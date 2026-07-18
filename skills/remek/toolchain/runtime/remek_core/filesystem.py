# ruff: noqa: D101, D102, D103
"""Filesystem."""

import hashlib
import os
import secrets
import stat
import unicodedata
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from .model import Error

MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_TREE_BYTES = 32 * 1024 * 1024
MAX_TREE_ENTRIES = 4096
MAX_DIRECTORY_ENTRIES = 1024
MAX_TREE_DEPTH = 32
ABSENT = "absent"
_TREE_DOMAIN = b"remek.filesystem-tree.v1\0"
_CACHE_NAMES = {"__pycache__", ".pytest_cache"}
_CACHE_SUFFIXES = {".pyc", ".pyo"}
_RESERVED_NAMES = {".remek-owner.json"}
_RESERVED_PREFIXES = (
    ".remek-stage-",
    ".remek-backup-",
    ".remek-rollback-",
    ".remek-artifact-",
)
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW


def is_private_name(value: str) -> bool:
    key = unicodedata.normalize("NFD", value).casefold()
    return key in _RESERVED_NAMES or any(marker in key for marker in _RESERVED_PREFIXES)


def _inside(path: Path, root: Path) -> bool:
    path_text = os.path.normcase(str(path))
    root_text = os.path.normcase(str(root))
    try:
        return os.path.commonpath((path_text, root_text)) == root_text
    except ValueError:
        return False


def paths_related(first: Path, second: Path) -> bool:
    return _inside(first, second) or _inside(second, first)


def _lstat(path: Path) -> os.stat_result | None:
    try:
        return path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise Error("filesystem.inspect", f"cannot inspect {path}: {exc}") from None


def entry_exists(path: Path) -> bool:
    return _lstat(path) is not None


def real_directory(path: Path) -> bool:
    info = _lstat(path)
    return info is not None and stat.S_ISDIR(info.st_mode)


def checked_root(path: Path) -> Path:
    selected = path.expanduser().absolute()
    try:
        candidate = selected.resolve(strict=True)
        info = candidate.lstat()
    except OSError as exc:
        raise Error("filesystem.root", f"cannot resolve root {selected}: {exc}") from None
    if not stat.S_ISDIR(info.st_mode):
        raise Error("filesystem.root", f"root must be one real directory: {candidate}")
    return candidate


def checked_path(root: Path, path: Path) -> Path:
    root = checked_root(root)
    candidate = (path if path.is_absolute() else root / path).absolute()
    try:
        relative = candidate.relative_to(root)
    except ValueError:
        raise Error("filesystem.escape", f"path escapes selected root: {candidate}") from None
    if not relative.parts or ".." in relative.parts:
        raise Error("filesystem.escape", f"path escapes selected root: {candidate}")
    portable_path(relative.as_posix())
    cursor = root
    for part in relative.parts[:-1]:
        cursor /= part
        try:
            info = cursor.lstat()
        except FileNotFoundError:
            break
        except OSError as exc:
            raise Error("filesystem.inspect", f"cannot inspect {cursor}: {exc}") from None
        if not stat.S_ISDIR(info.st_mode):
            raise Error("filesystem.ancestor", f"path ancestor is not a real directory: {cursor}")
    try:
        resolved_parent = candidate.parent.resolve(strict=False)
    except OSError as exc:
        raise Error(
            "filesystem.ancestor", f"cannot resolve path parent {candidate.parent}: {exc}"
        ) from None
    if not _inside(resolved_parent, root):
        raise Error("filesystem.escape", f"path resolves outside selected root: {candidate}")
    return candidate


def _validate_component(value: str) -> None:
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise Error("filesystem.path", "path contains invalid Unicode") from None
    if not encoded or len(encoded) > 255 or value in {".", ".."} or "\0" in value:
        raise Error("filesystem.path", f"invalid path component: {value!r}")
    for character in value:
        code = ord(character)
        if code < 0x20 or 0x7F <= code <= 0x9F or unicodedata.category(character) == "Cf":
            raise Error("filesystem.path", f"path contains a control character: {value!r}")


def portable_path(value: str, *, authored: bool = False) -> str:
    if not value or value.startswith("/") or value.endswith("/"):
        raise Error("filesystem.path", f"unsafe relative path: {value!r}")
    parts = value.split("/")
    normalized: list[str] = []
    for part in parts:
        _validate_component(part)
        key = unicodedata.normalize("NFD", part).casefold()
        normalized.append(key)
        if authored and is_private_name(key):
            raise Error("filesystem.reserved", f"authored path uses a remek marker: {value}")
        if authored and (key in _CACHE_NAMES or Path(key).suffix in _CACHE_SUFFIXES):
            raise Error(
                "filesystem.bytecode", f"authored path uses cache or bytecode content: {value}"
            )
    return "/".join(normalized)


@dataclass(frozen=True)
class FileIdentity:
    device: int
    inode: int
    mode: int
    size: int
    mtime_ns: int
    ctime_ns: int


@dataclass(frozen=True)
class RegularFile:
    data: bytes
    identity: FileIdentity


def _file_identity(info: os.stat_result) -> FileIdentity:
    return FileIdentity(
        info.st_dev,
        info.st_ino,
        stat.S_IMODE(info.st_mode),
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _read_descriptor(descriptor: int, path: object, limit: int) -> RegularFile:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise Error("filesystem.link", f"expected one unlinked regular file: {path}")
    chunks: list[bytes] = []
    remaining = limit + 1
    while remaining:
        try:
            chunk = os.read(descriptor, min(65536, remaining))
        except OSError as exc:
            raise Error("filesystem.read", f"cannot read {path}: {exc}") from None
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    data = b"".join(chunks)
    if len(data) > limit:
        raise Error("filesystem.limit", f"file exceeds {limit} bytes: {path}")
    after = os.fstat(descriptor)
    if (
        after.st_nlink != 1
        or _file_identity(before) != _file_identity(after)
        or len(data) != after.st_size
    ):
        raise Error("filesystem.unstable", f"file changed while reading: {path}")
    return RegularFile(data, _file_identity(after))


def _read_at(parent: int, name: str, path: object, limit: int) -> RegularFile:
    try:
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
    except OSError as exc:
        raise Error("filesystem.inspect", f"cannot inspect {path}: {exc}") from None
    if not stat.S_ISREG(before.st_mode):
        raise Error("filesystem.file", f"expected one regular file: {path}")
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        descriptor = os.open(name, flags, dir_fd=parent)
    except OSError as exc:
        raise Error("filesystem.open", f"cannot open {path}: {exc}") from None
    try:
        opened = os.fstat(descriptor)
        if _file_identity(before) != _file_identity(opened):
            raise Error("filesystem.unstable", f"file changed while opening: {path}")
        return _read_descriptor(descriptor, path, limit)
    finally:
        os.close(descriptor)


def read_regular(path: Path, *, limit: int = MAX_FILE_BYTES) -> RegularFile:
    selected = path.expanduser().absolute()
    parent = checked_root(selected.parent)
    descriptor = os.open(parent, _DIRECTORY_FLAGS)
    try:
        return _read_at(descriptor, selected.name, selected, limit)
    finally:
        os.close(descriptor)


@dataclass(frozen=True)
class TreeFile:
    path: str
    data: bytes
    mode: int


@dataclass(frozen=True)
class TreeDirectory:
    path: str
    mode: int = 0o755


@dataclass(frozen=True)
class Tree:
    root_mode: int
    directories: tuple[TreeDirectory, ...]
    files: tuple[TreeFile, ...]
    digest: str


@dataclass(frozen=True)
class DirectoryMember:
    name: str
    mode: int


def _mode(mode: int, path: str) -> None:
    if mode < 0 or mode > 0o777:
        raise Error("filesystem.mode", f"tree member has invalid mode: {path}")


def inventory_digest(
    root_mode: int,
    directories: list[tuple[str, int]],
    files: list[tuple[str, int, bytes]],
    *,
    domain: bytes = _TREE_DOMAIN,
) -> str:
    digest = hashlib.sha256(domain)

    def record(value: bytes) -> None:
        digest.update(len(value).to_bytes(8, "big"))
        digest.update(value)

    record(b"root")
    record(f"{root_mode:o}".encode())
    members = [(path, b"d", mode, b"") for path, mode in directories]
    members.extend((path, b"f", mode, content) for path, mode, content in files)
    for path, kind, mode, content in sorted(members):
        record(kind)
        record(path.encode("utf-8"))
        record(f"{mode:o}".encode())
        if content:
            record(content)
    return digest.hexdigest()


def _digest_tree(
    root_mode: int,
    directories: tuple[TreeDirectory, ...],
    files: tuple[TreeFile, ...],
    *,
    domain: bytes = _TREE_DOMAIN,
) -> str:
    return inventory_digest(
        root_mode,
        [(item.path, item.mode) for item in directories],
        [(item.path, item.mode, hashlib.sha256(item.data).digest()) for item in files],
        domain=domain,
    )


def tree_digest(tree: Tree, *, domain: bytes, exclude: frozenset[str] = frozenset()) -> str:
    directories = tuple(item for item in tree.directories if item.path not in exclude)
    files = tuple(item for item in tree.files if item.path not in exclude)
    return _digest_tree(tree.root_mode, directories, files, domain=domain)


def tree_from_entries(
    files: tuple[TreeFile, ...] | list[TreeFile],
    directories: tuple[TreeDirectory, ...] | list[TreeDirectory] = (),
    *,
    root_mode: int = 0o755,
) -> Tree:
    _mode(root_mode, ".")
    ordered_files = tuple(sorted(files, key=lambda item: item.path))
    ordered_directories = tuple(sorted(directories, key=lambda item: item.path))
    raw: dict[str, str] = {}
    portable: set[str] = set()
    total = 0
    for kind, members in (("directory", ordered_directories), ("file", ordered_files)):
        for item in members:
            key = portable_path(item.path)
            if len(item.path.split("/")) - (kind == "file") > MAX_TREE_DEPTH:
                raise Error("filesystem.depth", f"tree exceeds depth {MAX_TREE_DEPTH}: {item.path}")
            _mode(item.mode, item.path)
            if item.path in raw or key in portable:
                raise Error("filesystem.collision", f"tree has a portable collision: {item.path}")
            raw[item.path] = kind
            portable.add(key)
            if isinstance(item, TreeFile):
                if not isinstance(item.data, bytes) or len(item.data) > MAX_FILE_BYTES:
                    raise Error(
                        "filesystem.limit", f"tree member exceeds the file limit: {item.path}"
                    )
                total += len(item.data)
    for path in raw:
        parts = path.split("/")
        for index in range(1, len(parts)):
            ancestor = "/".join(parts[:index])
            if raw.get(ancestor) == "file":
                raise Error("filesystem.prefix", f"tree file conflicts with descendant: {ancestor}")
            if ancestor not in raw:
                raise Error("filesystem.parent", f"tree lacks directory entry: {ancestor}")
    if len(raw) > MAX_TREE_ENTRIES or total > MAX_TREE_BYTES:
        raise Error("filesystem.limit", "tree exceeds the bounded inventory")
    return Tree(
        root_mode,
        ordered_directories,
        ordered_files,
        _digest_tree(root_mode, ordered_directories, ordered_files),
    )


def git_mode(mode: int, *, directory: bool = False) -> int:
    return 0o755 if directory or mode & stat.S_IXUSR else 0o644


def git_tree(tree: Tree) -> Tree:
    return tree_from_entries(
        [TreeFile(item.path, item.data, git_mode(item.mode)) for item in tree.files],
        [TreeDirectory(item.path) for item in tree.directories],
    )


def _bounded_entries(
    descriptor: int,
    label: object,
    total: list[int],
) -> list[tuple[str, os.stat_result]]:
    retained: list[tuple[str, os.stat_result]] = []
    local = 0
    try:
        with os.scandir(descriptor) as iterator:
            for entry in iterator:
                local += 1
                total[0] += 1
                if local > MAX_DIRECTORY_ENTRIES or total[0] > MAX_TREE_ENTRIES:
                    raise Error("filesystem.limit", f"tree exceeds entry limits: {label}")
                try:
                    info = entry.stat(follow_symlinks=False)
                except OSError as exc:
                    raise Error(
                        "filesystem.inspect", f"cannot inspect {label}/{entry.name}: {exc}"
                    ) from None
                retained.append((entry.name, info))
    except OSError as exc:
        raise Error("filesystem.enumerate", f"cannot enumerate {label}: {exc}") from None
    retained.sort(key=lambda item: item[0])
    return retained


def _snapshot_descriptor(  # noqa: PLR0912
    descriptor: int,
    label: object,
    *,
    reject_bytecode: bool,
) -> Tree:
    root_info = os.fstat(descriptor)
    if not stat.S_ISDIR(root_info.st_mode):
        raise Error("filesystem.tree", f"expected one real directory tree: {label}")
    files: list[TreeFile] = []
    directories: list[TreeDirectory] = []
    total_entries = [0]
    total_bytes = 0
    pending: list[tuple[int, str, int]] = [(os.dup(descriptor), "", 0)]
    try:
        while pending:
            current, prefix, depth = pending.pop()
            try:
                entries = _bounded_entries(current, label, total_entries)
                for name, info in entries:
                    relative = f"{prefix}/{name}" if prefix else name
                    key = portable_path(name)
                    if reject_bytecode and (
                        key in _CACHE_NAMES or Path(key).suffix in _CACHE_SUFFIXES
                    ):
                        raise Error(
                            "filesystem.bytecode", f"runtime contains cache or bytecode: {relative}"
                        )
                    if stat.S_ISLNK(info.st_mode):
                        raise Error(
                            "filesystem.link", f"tree contains a link or reparse point: {relative}"
                        )
                    if stat.S_ISDIR(info.st_mode):
                        if depth + 1 > MAX_TREE_DEPTH:
                            raise Error(
                                "filesystem.depth",
                                f"tree exceeds depth {MAX_TREE_DEPTH}: {relative}",
                            )
                        child = os.open(
                            name,
                            _DIRECTORY_FLAGS,
                            dir_fd=current,
                        )
                        directories.append(TreeDirectory(relative, stat.S_IMODE(info.st_mode)))
                        pending.append((child, relative, depth + 1))
                    elif stat.S_ISREG(info.st_mode):
                        stable = _read_at(current, name, f"{label}/{relative}", MAX_FILE_BYTES)
                        total_bytes += len(stable.data)
                        if total_bytes > MAX_TREE_BYTES:
                            raise Error("filesystem.limit", f"tree exceeds byte limit: {label}")
                        files.append(TreeFile(relative, stable.data, stable.identity.mode))
                    else:
                        raise Error(
                            "filesystem.special", f"tree contains a special file: {relative}"
                        )
            finally:
                os.close(current)
    except BaseException:
        for current, _, _ in pending:
            os.close(current)
        raise
    return tree_from_entries(files, directories, root_mode=stat.S_IMODE(root_info.st_mode))


def snapshot_tree(path: Path, *, reject_bytecode: bool = False) -> Tree:
    try:
        info = path.lstat()
    except OSError as exc:
        raise Error("filesystem.inspect", f"cannot inspect tree {path}: {exc}") from None
    if not stat.S_ISDIR(info.st_mode):
        raise Error("filesystem.tree", f"expected one real directory tree: {path}")
    try:
        descriptor = os.open(path, _DIRECTORY_FLAGS)
    except OSError as exc:
        raise Error("filesystem.open", f"cannot open tree {path}: {exc}") from None
    try:
        opened = os.fstat(descriptor)
        if (
            info.st_dev,
            info.st_ino,
            stat.S_IMODE(info.st_mode),
            info.st_mtime_ns,
            info.st_ctime_ns,
        ) != (
            opened.st_dev,
            opened.st_ino,
            stat.S_IMODE(opened.st_mode),
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        ):
            raise Error("filesystem.unstable", f"tree changed while opening: {path}")
        first = _snapshot_descriptor(descriptor, path, reject_bytecode=reject_bytecode)
        second = _snapshot_descriptor(descriptor, path, reject_bytecode=reject_bytecode)
        final = os.fstat(descriptor)
        if first != second or (
            opened.st_dev,
            opened.st_ino,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        ) != (final.st_dev, final.st_ino, final.st_mtime_ns, final.st_ctime_ns):
            raise Error("filesystem.unstable", f"tree changed while reading: {path}")
        return second
    finally:
        os.close(descriptor)


def _directory_members(
    path: Path, failures: dict[str, Error] | None = None
) -> tuple[DirectoryMember, ...]:
    root = checked_root(path)
    descriptor = os.open(root, _DIRECTORY_FLAGS)
    try:
        entries = _bounded_entries(descriptor, root, [0])
        keys: dict[str, str] = {}
        result: list[DirectoryMember] = []
        for name, info in entries:
            result.append(DirectoryMember(name, info.st_mode))
            try:
                key = portable_path(name)
            except Error as exc:
                if failures is None:
                    raise
                failures[name] = exc
                continue
            prior = keys.get(key)
            if prior is not None:
                error = Error("filesystem.collision", f"directory has a portable collision: {name}")
                if failures is None:
                    raise error
                failures[prior] = error
                failures[name] = error
            else:
                keys[key] = name
        return tuple(result)
    finally:
        os.close(descriptor)


def directory_members(path: Path) -> tuple[DirectoryMember, ...]:
    return _directory_members(path)


def _file_fingerprint(data: bytes, mode: int) -> str:
    return f"file:{mode:o}:{hashlib.sha256(data).hexdigest()}"


def fingerprint(path: Path) -> str:
    info = _lstat(path)
    if info is None:
        return ABSENT
    if stat.S_ISLNK(info.st_mode):
        try:
            target = os.readlink(path)
        except OSError as exc:
            raise Error("filesystem.readlink", f"cannot read link {path}: {exc}") from None
        return f"link:{hashlib.sha256(os.fsencode(target)).hexdigest()}"
    if stat.S_ISREG(info.st_mode):
        stable = read_regular(path)
        return _file_fingerprint(stable.data, stable.identity.mode)
    if stat.S_ISDIR(info.st_mode):
        return f"tree:{snapshot_tree(path).digest}"
    raise Error("filesystem.special", f"unsupported filesystem object: {path}")


def _detect_posix_capabilities() -> bool:
    required = (
        os.open,
        os.stat,
        os.mkdir,
        os.unlink,
        os.rmdir,
        os.link,
        os.symlink,
        os.readlink,
    )
    if (
        os.name != "posix"
        or any(function not in os.supports_dir_fd for function in required)
        or os.stat not in os.supports_follow_symlinks
    ):
        return False
    descriptor = -1
    try:
        descriptor = os.open("/", _DIRECTORY_FLAGS)
        try:
            os.replace("", "", src_dir_fd=descriptor, dst_dir_fd=descriptor)
        except FileNotFoundError:
            return True
    except (NotImplementedError, OSError, TypeError):
        pass
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return False


_POSIX_CAPABILITIES = _detect_posix_capabilities()


def require_posix_capabilities() -> None:
    if not _POSIX_CAPABILITIES:
        raise Error("filesystem.capability", "required POSIX dir-fd operations unavailable")


class OpenedBoundary:
    def __init__(self, root: Path) -> None:
        require_posix_capabilities()
        self.root = checked_root(root)
        try:
            self.descriptor = os.open(self.root, _DIRECTORY_FLAGS)
        except OSError as exc:
            raise Error(
                "filesystem.boundary", f"cannot open mutation boundary {self.root}: {exc}"
            ) from None

    def close(self) -> None:
        if self.descriptor >= 0:
            descriptor = self.descriptor
            self.descriptor = -1
            with suppress(OSError):
                os.close(descriptor)

    def __enter__(self) -> "OpenedBoundary":
        return self

    def __exit__(self, _kind: object, _value: object, _traceback: object) -> None:
        self.close()

    def open_directory(self, relative: str = "") -> int:
        descriptor = os.dup(self.descriptor)
        try:
            for part in relative.split("/") if relative else ():
                child = os.open(
                    part,
                    _DIRECTORY_FLAGS,
                    dir_fd=descriptor,
                )
                os.close(descriptor)
                descriptor = child
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    def open_parent(self, relative: str) -> tuple[int, str]:
        portable_path(relative)
        parts = relative.split("/")
        descriptor = os.dup(self.descriptor)
        try:
            for part in parts[:-1]:
                child = os.open(part, _DIRECTORY_FLAGS, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            return descriptor, parts[-1]
        except BaseException as exc:
            with suppress(OSError):
                os.close(descriptor)
            if isinstance(exc, OSError):
                raise Error(
                    "filesystem.ancestor", f"cannot traverse {self.root / relative}: {exc}"
                ) from None
            raise


def _stat_at(parent: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise Error("filesystem.inspect", f"cannot inspect {name}: {exc}") from None


def fingerprint_at(parent: int, name: str) -> str:
    info = _stat_at(parent, name)
    if info is None:
        return ABSENT
    if stat.S_ISLNK(info.st_mode):
        try:
            target = os.readlink(name, dir_fd=parent)
        except OSError as exc:
            raise Error("filesystem.readlink", f"cannot read link {name}: {exc}") from None
        return f"link:{hashlib.sha256(os.fsencode(target)).hexdigest()}"
    if stat.S_ISREG(info.st_mode):
        stable = _read_at(parent, name, name, MAX_FILE_BYTES)
        return _file_fingerprint(stable.data, stable.identity.mode)
    if stat.S_ISDIR(info.st_mode):
        descriptor = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent)
        try:
            return f"tree:{_snapshot_descriptor(descriptor, name, reject_bytecode=False).digest}"
        finally:
            os.close(descriptor)
    raise Error("filesystem.special", f"unsupported filesystem object: {name}")


def write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    written = 0
    while written < len(view):
        count = os.write(descriptor, view[written:])
        if count <= 0:
            raise OSError("write made no progress")
        written += count


def write_file_at(parent: int, name: str, data: bytes, mode: int) -> tuple[int, int]:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = os.open(name, flags, 0o600, dir_fd=parent)
    opened: os.stat_result | None = None
    try:
        opened = os.fstat(descriptor)
        os.fchmod(descriptor, mode)
        write_all(descriptor, data)
        os.fsync(descriptor)
    except BaseException:
        if opened is None:
            with suppress(BaseException):
                opened = os.fstat(descriptor)
        with suppress(OSError):
            os.close(descriptor)
        if opened is not None:
            try:
                current = os.stat(name, dir_fd=parent, follow_symlinks=False)
                if (current.st_dev, current.st_ino) == (opened.st_dev, opened.st_ino):
                    os.unlink(name, dir_fd=parent)
            except OSError:
                pass
        raise
    os.close(descriptor)
    return opened.st_dev, opened.st_ino


def _mkdir_at(parent: int, name: str, mode: int) -> int:
    descriptor = -1
    try:
        os.mkdir(name, 0o700, dir_fd=parent)
        descriptor = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent)
        os.fchmod(descriptor, mode)
    except BaseException as exc:
        if descriptor >= 0:
            with suppress(OSError):
                os.close(descriptor)
        if not isinstance(exc, FileExistsError):
            with suppress(OSError):
                os.rmdir(name, dir_fd=parent)
        raise
    return descriptor


def write_tree_at(parent: int, name: str, tree: Tree) -> None:
    root = _mkdir_at(parent, name, tree.root_mode)
    descriptors: dict[str, int] = {"": root}
    built_directories: list[TreeDirectory] = []
    built_files: list[TreeFile] = []
    try:
        for directory in tree.directories:
            parent_path, _, child_name = directory.path.rpartition("/")
            descriptors[directory.path] = _mkdir_at(
                descriptors[parent_path], child_name, directory.mode
            )
            built_directories.append(directory)
        for item in tree.files:
            parent_path, _, child_name = item.path.rpartition("/")
            write_file_at(descriptors[parent_path], child_name, item.data, item.mode)
            built_files.append(item)
    except BaseException as exc:
        for descriptor in reversed(tuple(descriptors.values())):
            os.close(descriptor)
        try:
            partial = tree_from_entries(
                built_files,
                built_directories,
                root_mode=tree.root_mode,
            )
            remove_at(parent, name, f"tree:{partial.digest}")
        except (OSError, Error) as cleanup:
            raise Error(
                "filesystem.residue",
                f"partial tree remains at {name}: {cleanup}",
                changed=True,
            ) from exc
        raise
    for descriptor in reversed(tuple(descriptors.values())):
        os.close(descriptor)


def _remove_directory(parent: int, name: str) -> None:
    descriptor = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent)
    opened = os.fstat(descriptor)
    try:
        entries = _bounded_entries(descriptor, name, [0])
        for child, info in entries:
            if stat.S_ISDIR(info.st_mode):
                _remove_directory(descriptor, child)
            else:
                os.unlink(child, dir_fd=descriptor)
        current = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
            raise Error("filesystem.residue", f"directory identity changed: {name}")
    finally:
        os.close(descriptor)
    os.rmdir(name, dir_fd=parent)


def remove_at(parent: int, name: str, expected: str) -> None:
    current = fingerprint_at(parent, name)
    if current != expected:
        raise Error("filesystem.residue", f"refuse to remove changed object: {name}")
    info = _stat_at(parent, name)
    if info is None:
        return
    if stat.S_ISDIR(info.st_mode):
        _remove_directory(parent, name)
    else:
        os.unlink(name, dir_fd=parent)


def write_artifact(path: Path, data: bytes) -> Path:
    selected = path.expanduser().absolute()
    parent_path = checked_root(selected.parent)
    portable_path(selected.name)
    destination = parent_path / selected.name
    with OpenedBoundary(parent_path) as boundary:
        token = secrets.token_hex(8)
        suffix = hashlib.sha256(os.fsencode(selected.name)).hexdigest()[:12]
        stage = f".remek-artifact-{token}-{suffix}"
        identity: tuple[int, int] | None = None
        try:
            identity = write_file_at(boundary.descriptor, stage, data, 0o600)
            try:
                os.link(
                    stage,
                    selected.name,
                    src_dir_fd=boundary.descriptor,
                    dst_dir_fd=boundary.descriptor,
                    follow_symlinks=False,
                )
            except OSError as exc:
                installed = _stat_at(boundary.descriptor, selected.name)
                if installed is None or (installed.st_dev, installed.st_ino) != identity:
                    code = (
                        "artifact.exists"
                        if isinstance(exc, FileExistsError)
                        else "artifact.install"
                    )
                    message = (
                        f"artifact already exists: {destination}; not replaced; choose new output"
                        if code == "artifact.exists"
                        else f"cannot install operator artifact {destination}: {exc}"
                    )
                    raise Error(code, message) from None
        finally:
            try:
                info = _stat_at(boundary.descriptor, stage)
                if (
                    info is not None
                    and identity is not None
                    and (
                        info.st_dev,
                        info.st_ino,
                    )
                    == identity
                ):
                    os.unlink(stage, dir_fd=boundary.descriptor)
                elif info is not None:
                    raise OSError("stage identity is unknown or changed")
            except OSError as exc:
                raise Error(
                    "artifact.residue",
                    f"operator artifact stage remains beside {destination}: {exc}",
                    changed=True,
                ) from None
    return destination


def read_artifact(path: Path) -> RegularFile:
    selected = path.expanduser().absolute()
    parent_path = checked_root(selected.parent)
    portable_path(selected.name)
    descriptor = os.open(parent_path, _DIRECTORY_FLAGS)
    try:
        try:
            info = os.stat(selected.name, dir_fd=descriptor, follow_symlinks=False)
        except OSError as exc:
            raise Error(
                "artifact.inspect", f"cannot inspect operator artifact {selected}: {exc}"
            ) from None
        if not stat.S_ISREG(info.st_mode):
            raise Error("artifact.type", "operation plan must be one regular file")
        if info.st_nlink != 1:
            raise Error("artifact.links", "operation plan must have exactly one hard link")
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise Error("artifact.mode", "operation plan must be accessible only to its owner")
        if info.st_uid != os.geteuid():
            raise Error("artifact.owner", "operation plan must be owned by the effective user")
        return _read_at(descriptor, selected.name, selected, MAX_FILE_BYTES)
    finally:
        os.close(descriptor)

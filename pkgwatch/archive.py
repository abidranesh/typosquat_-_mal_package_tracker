"""Safe, in-memory reading of package archives (npm tarballs, sdists, wheels).

Nothing is ever written to disk and nothing from an archive is executed or imported.
Limits on file count and uncompressed size are enforced while reading, so a
decompression bomb is abandoned as soon as it crosses a limit.
"""

from __future__ import annotations

import io
import re
import tarfile
import zipfile
import zlib
from dataclasses import dataclass, field

from .config import Config

_DRIVE = re.compile(r"^[A-Za-z]:")


class ArchiveError(Exception):
    """Base class: the archive could not be read safely."""


class UnsafePath(ArchiveError):
    """An entry uses an absolute path or escapes the archive root (zip-slip)."""


class TooManyFiles(ArchiveError):
    """The archive holds more entries than allowed."""


class ArchiveTooLarge(ArchiveError):
    """The archive's uncompressed contents exceed the allowed size."""


class Malformed(ArchiveError):
    """The archive is corrupt or in an unsupported format."""


@dataclass
class ArchiveContents:
    """Files read from an archive. ``files`` holds at most ``max_file_bytes`` per file."""

    files: dict[str, bytes] = field(default_factory=dict)
    sizes: dict[str, int] = field(default_factory=dict)
    total_size: int = 0
    skipped_links: list[str] = field(default_factory=list)

    @property
    def file_count(self) -> int:
        return len(self.sizes)


@dataclass(frozen=True)
class Limits:
    max_files: int
    max_uncompressed_bytes: int
    max_file_bytes: int

    @classmethod
    def from_config(cls, config: Config) -> Limits:
        lim = config.limits
        return cls(
            int(lim["max_files"]), int(lim["max_uncompressed_bytes"]), int(lim["max_file_bytes"])
        )


def check_path(name: str) -> str:
    """Return a normalised relative path, or raise ``UnsafePath``."""
    if "\x00" in name:
        raise UnsafePath(f"NUL byte in entry name: {name!r}")
    normalised = name.replace("\\", "/")
    if normalised.startswith("/") or _DRIVE.match(normalised):
        raise UnsafePath(f"absolute path in archive: {name!r}")
    parts = [p for p in normalised.split("/") if p not in ("", ".")]
    if ".." in parts:
        raise UnsafePath(f"path traversal in archive: {name!r}")
    return "/".join(parts)


def _read_capped(stream: io.BufferedIOBase, remaining: int, keep: int) -> tuple[bytes, int]:
    """Read a member fully, keeping ``keep`` bytes; fail once ``remaining`` is exceeded."""
    kept = bytearray()
    size = 0
    while True:
        chunk = stream.read(65536)
        if not chunk:
            break
        size += len(chunk)
        if size > remaining:
            raise ArchiveTooLarge("uncompressed size limit exceeded")
        if len(kept) < keep:
            kept.extend(chunk[: keep - len(kept)])
    return bytes(kept), size


def _read_tar(data: bytes, limits: Limits) -> ArchiveContents:
    out = ArchiveContents()
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tar:
            count = 0
            for member in tar:
                count += 1
                if count > limits.max_files:
                    raise TooManyFiles(f"more than {limits.max_files} entries")
                path = check_path(member.name)
                if member.issym() or member.islnk():
                    target = member.linkname.replace("\\", "/")
                    if target.startswith("/") or ".." in target.split("/"):
                        raise UnsafePath(f"link escapes archive: {member.name!r} -> {target!r}")
                    out.skipped_links.append(path)
                    continue
                if not member.isfile():
                    continue
                if out.total_size + member.size > limits.max_uncompressed_bytes:
                    raise ArchiveTooLarge("uncompressed size limit exceeded")
                stream = tar.extractfile(member)
                if stream is None:
                    continue
                content, size = _read_capped(
                    stream, limits.max_uncompressed_bytes - out.total_size, limits.max_file_bytes
                )
                out.total_size += size
                out.files[path] = content
                out.sizes[path] = size
    except ArchiveError:
        raise
    except (tarfile.TarError, EOFError, OSError, zlib.error, ValueError) as exc:
        raise Malformed(f"unreadable tar archive: {exc}") from exc
    return out


def _read_zip(data: bytes, limits: Limits) -> ArchiveContents:
    out = ArchiveContents()
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            infos = zf.infolist()
            if len(infos) > limits.max_files:
                raise TooManyFiles(f"more than {limits.max_files} entries")
            for info in infos:
                path = check_path(info.filename)
                if info.is_dir():
                    continue
                if (info.external_attr >> 16) & 0o170000 == 0o120000:
                    out.skipped_links.append(path)
                    continue
                # Declared sizes can lie, so the real read below is capped as well.
                if out.total_size + info.file_size > limits.max_uncompressed_bytes:
                    raise ArchiveTooLarge("uncompressed size limit exceeded")
                with zf.open(info) as stream:
                    content, size = _read_capped(
                        stream,
                        limits.max_uncompressed_bytes - out.total_size,
                        limits.max_file_bytes,
                    )
                out.total_size += size
                out.files[path] = content
                out.sizes[path] = size
    except ArchiveError:
        raise
    except (zipfile.BadZipFile, EOFError, OSError, zlib.error, ValueError, RuntimeError) as exc:
        raise Malformed(f"unreadable zip archive: {exc}") from exc
    except NotImplementedError as exc:
        raise Malformed(f"unsupported zip feature: {exc}") from exc
    return out


def read_archive(data: bytes, filename: str, limits: Limits) -> ArchiveContents:
    """Read ``data`` as a tarball (``.tgz``/``.tar.*``) or zip (``.whl``/``.zip``/``.egg``)."""
    lower = filename.lower()
    if lower.endswith((".whl", ".zip", ".egg")) or data[:2] == b"PK":
        return _read_zip(data, limits)
    if (
        lower.endswith((".tgz", ".tar.gz", ".tar.bz2", ".tar.xz", ".tar"))
        or data[:2] == b"\x1f\x8b"
    ):
        return _read_tar(data, limits)
    raise Malformed(f"unsupported archive type: {filename!r}")

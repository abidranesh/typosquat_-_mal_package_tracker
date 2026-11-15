import io
import tarfile
import zipfile

import pytest

from pkgwatch.archive import (
    ArchiveTooLarge,
    Limits,
    Malformed,
    TooManyFiles,
    UnsafePath,
    check_path,
    read_archive,
)
from tests.helpers import make_tgz, make_zip

LIMITS = Limits(max_files=50, max_uncompressed_bytes=10_000, max_file_bytes=1_000)


def test_reads_tarball_in_memory():
    data = make_tgz({"package/package.json": '{"name":"x"}', "package/index.js": "x = 1"})
    contents = read_archive(data, "x-1.0.0.tgz", LIMITS)
    assert contents.files["package/index.js"] == b"x = 1"
    assert contents.file_count == 2 and contents.total_size == 17


def test_reads_wheel_as_zip():
    data = make_zip({"pkg/__init__.py": "VERSION = 1\n", "pkg-1.dist-info/METADATA": "Name: pkg"})
    contents = read_archive(data, "pkg-1-py3-none-any.whl", LIMITS)
    assert contents.files["pkg/__init__.py"] == b"VERSION = 1\n"


def test_detects_format_from_magic_bytes_when_extension_is_unknown():
    assert read_archive(make_zip({"a.py": "1"}), "blob", LIMITS).file_count == 1
    assert read_archive(make_tgz({"a.py": "1"}), "blob", LIMITS).file_count == 1


@pytest.mark.parametrize(
    "name",
    ["../evil.py", "package/../../evil.py", "/etc/passwd", "C:\\Windows\\x.dll", "a\\..\\..\\b"],
)
def test_zip_slip_entries_are_rejected_in_tar_and_zip(name):
    with pytest.raises(UnsafePath):
        read_archive(make_tgz({name: "x"}), "x.tgz", LIMITS)
    with pytest.raises(UnsafePath):
        read_archive(make_zip({name: "x"}), "x.zip", LIMITS)


def test_symlink_escaping_the_root_is_rejected_and_safe_links_are_skipped():
    with pytest.raises(UnsafePath):
        read_archive(make_tgz({"p/a": "x"}, links={"p/link": "../../etc/passwd"}), "x.tgz", LIMITS)
    with pytest.raises(UnsafePath):
        read_archive(make_tgz({}, links={"p/link": "/etc/passwd"}), "x.tgz", LIMITS)
    contents = read_archive(make_tgz({"p/a": "x"}, links={"p/link": "a"}), "x.tgz", LIMITS)
    assert contents.skipped_links == ["p/link"] and "p/link" not in contents.files


def test_too_many_files():
    files = {f"p/{i}.js": "x" for i in range(51)}
    with pytest.raises(TooManyFiles):
        read_archive(make_tgz(files), "x.tgz", LIMITS)
    with pytest.raises(TooManyFiles):
        read_archive(make_zip(files), "x.zip", LIMITS)


def test_uncompressed_size_limit_stops_a_decompression_bomb():
    bomb = {"p/zeros.bin": b"\x00" * 20_000}  # compresses to a few dozen bytes
    assert len(make_tgz(bomb)) < 500
    with pytest.raises(ArchiveTooLarge):
        read_archive(make_tgz(bomb), "x.tgz", LIMITS)
    with pytest.raises(ArchiveTooLarge):
        read_archive(make_zip(bomb), "x.zip", LIMITS)


def test_total_size_is_summed_across_files():
    files = {f"p/{i}.bin": b"\x01" * 3_000 for i in range(4)}
    with pytest.raises(ArchiveTooLarge):
        read_archive(make_tgz(files), "x.tgz", LIMITS)
    with pytest.raises(ArchiveTooLarge):
        read_archive(make_zip(files), "x.zip", LIMITS)


def test_zip_with_understated_size_is_still_capped():
    raw = make_zip({"p/big.bin": b"\x00" * 20_000})
    # Rewrite the declared uncompressed size so the headers lie about it.
    forged = raw.replace((20_000).to_bytes(4, "little"), (10).to_bytes(4, "little"))
    assert forged != raw
    with pytest.raises((ArchiveTooLarge, Malformed)):
        read_archive(forged, "x.zip", LIMITS)


def test_large_files_are_truncated_in_memory_but_sized_correctly():
    contents = read_archive(make_tgz({"p/big.js": "a" * 5_000}), "x.tgz", LIMITS)
    assert len(contents.files["p/big.js"]) == 1_000
    assert contents.sizes["p/big.js"] == 5_000


@pytest.mark.parametrize("name", ["x.tgz", "x.whl", "x.zip", "x.tar.gz"])
def test_malformed_archives_raise_malformed(name):
    with pytest.raises(Malformed):
        read_archive(b"this is not an archive at all", name, LIMITS)


def test_truncated_archives_raise_malformed():
    good_tar = make_tgz({"p/a.js": bytes(range(256)) * 20})
    with pytest.raises(Malformed):
        read_archive(good_tar[: len(good_tar) // 2], "x.tgz", LIMITS)
    good_zip = make_zip({"p/a.js": "x" * 2000})
    with pytest.raises(Malformed):
        read_archive(good_zip[:-30], "x.zip", LIMITS)


def test_unsupported_type_raises_malformed():
    with pytest.raises(Malformed, match="unsupported"):
        read_archive(b"\x00\x01\x02\x03", "x.rar", LIMITS)


def test_directories_and_special_members_are_ignored():
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        folder = tarfile.TarInfo("p/dir")
        folder.type = tarfile.DIRTYPE
        tar.addfile(folder)
        fifo = tarfile.TarInfo("p/fifo")
        fifo.type = tarfile.FIFOTYPE
        tar.addfile(fifo)
    assert read_archive(buffer.getvalue(), "x.tgz", LIMITS).file_count == 0
    zbuf = io.BytesIO()
    with zipfile.ZipFile(zbuf, "w") as zf:
        zf.writestr("p/dir/", "")
    assert read_archive(zbuf.getvalue(), "x.zip", LIMITS).file_count == 0


def test_zip_symlink_entries_are_skipped():
    zbuf = io.BytesIO()
    with zipfile.ZipFile(zbuf, "w") as zf:
        link = zipfile.ZipInfo("p/link")
        link.external_attr = 0o120777 << 16
        zf.writestr(link, "target")
    contents = read_archive(zbuf.getvalue(), "x.zip", LIMITS)
    assert contents.skipped_links == ["p/link"] and not contents.files


def test_check_path_normalises_and_rejects_nul():
    assert check_path("./package//index.js") == "package/index.js"
    with pytest.raises(UnsafePath):
        check_path("a\x00b")


def test_limits_come_from_config(config):
    limits = Limits.from_config(config)
    assert limits.max_files == 5000
    assert limits.max_uncompressed_bytes == 50 * 1024 * 1024
    assert config.limits["max_download_bytes"] == 10 * 1024 * 1024

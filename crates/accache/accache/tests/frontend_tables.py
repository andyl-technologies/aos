"""Verify every extracted compiler option against the pinned sccache source.

The frontend adapts surrounding parser types, but the GCC, Clang, and Rust
argument tables must retain every upstream entry. Formatting and comments are
ignored; macro calls and their arguments must remain identical.
"""

from pathlib import Path
import re
import sys
import tarfile


EXPECTED_ENTRIES = {"gcc": 86, "clang": 100, "rust": 37}
TABLE_START = re.compile(r"counted_array!\(\s*(?:pub\s+)?static\s+ARGS\b")


def option_table(source):
    match = TABLE_START.search(source)
    assert match is not None, "compiler option table is missing"
    end = source.find("]);", match.start())
    assert end >= 0, "compiler option table is unterminated"

    table = source[match.start():end + 3]
    without_comments = re.sub(r"//[^\n]*", "", table)
    normalized = re.sub(r"\s+", "", without_comments)
    count = normalized.count("flag!(") + normalized.count("take_arg!(")
    return normalized, count


def upstream_source(archive, compiler):
    suffix = f"/src/compiler/{compiler}.rs"
    members = [member for member in archive.getmembers()
               if member.isfile() and member.name.endswith(suffix)]
    assert len(members) == 1, (compiler, [member.name for member in members])
    source = archive.extractfile(members[0])
    assert source is not None, members[0].name
    return source.read().decode()


def main(tarball, frontend):
    with tarfile.open(tarball, "r:gz") as archive:
        for compiler, expected_count in EXPECTED_ENTRIES.items():
            upstream, upstream_count = option_table(upstream_source(archive, compiler))
            extracted, extracted_count = option_table(
                (frontend / "src/compiler" / f"{compiler}.rs").read_text())
            assert upstream_count == extracted_count == expected_count, (
                compiler, upstream_count, extracted_count, expected_count)
            assert upstream == extracted, f"{compiler} argument table differs from pinned sccache"
            print("PASS pinned frontend table", compiler, expected_count, flush=True)


if __name__ == "__main__":
    main(Path(sys.argv[1]), Path(sys.argv[2]))

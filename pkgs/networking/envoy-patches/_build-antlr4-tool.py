"""Compile the ANTLR tool and its Java dependencies from source archives."""

import argparse
import shutil
import stat
import subprocess
from pathlib import Path, PurePosixPath
from zipfile import ZipFile


OPAQUE_SUFFIXES = {
    ".a",
    ".bin",
    ".class",
    ".dll",
    ".dylib",
    ".exe",
    ".jar",
    ".o",
    ".so",
    ".wasm",
}
OPAQUE_SIGNATURES = (
    b"\x7fELF",
    b"\x00asm",
    b"!<arch>\n",
    b"\xca\xfe\xba\xbe",
    b"\xfe\xed\xfa\xce",
    b"\xfe\xed\xfa\xcf",
    b"\xce\xfa\xed\xfe",
    b"\xcf\xfa\xed\xfe",
    b"MZ",
)


def extract_source(archive_path: Path, destination: Path) -> None:
    with ZipFile(archive_path) as archive:
        for member in archive.infolist():
            path = PurePosixPath(member.filename)
            file_type = stat.S_IFMT(member.external_attr >> 16)
            if path.is_absolute() or ".." in path.parts or file_type == stat.S_IFLNK:
                raise ValueError(f"unsafe ANTLR source member: {member.filename}")
            if not member.is_dir() and path.suffix.lower() in OPAQUE_SUFFIXES:
                raise ValueError(f"opaque ANTLR source member: {member.filename}")
            if not member.is_dir():
                with archive.open(member) as contents:
                    if contents.read(8).startswith(OPAQUE_SIGNATURES):
                        raise ValueError(f"compiled ANTLR source member: {member.filename}")

        archive.extractall(destination)


def compile_sources(
    javac: Path,
    source: Path,
    classes: Path,
    dependencies: list[Path],
    excluded_names: set[str] | None = None,
) -> None:
    excluded_names = excluded_names or set()
    sources = sorted(
        path for path in source.rglob("*.java") if path.name not in excluded_names
    )
    if not sources:
        raise ValueError(f"no Java sources found in {source}")

    source_list = source.parent / f"{source.name}-sources.txt"
    source_list.write_text("\n".join(str(path) for path in sources) + "\n")

    command = [str(javac), "--release", "11", "-encoding", "UTF-8"]
    if dependencies:
        command.extend(["-cp", ":".join(str(path) for path in dependencies)])
    command.extend(["-d", str(classes), f"@{source_list}"])
    subprocess.run(command, check=True)


def copy_resource(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        if destination.read_bytes() != source.read_bytes():
            raise ValueError(f"conflicting ANTLR resource: {destination}")
        return

    shutil.copyfile(source, destination)


def assemble_jar(jar: Path, stage: Path, output: Path, roots: list[Path], icu: Path) -> None:
    for root in roots:
        for source in root.rglob("*"):
            if not source.is_file():
                continue

            relative = source.relative_to(root)
            if relative.parts[0] == "META-INF" or source.suffix == ".java":
                continue

            copy_resource(source, stage / relative)

    with ZipFile(icu) as archive:
        for member in archive.infolist():
            path = PurePosixPath(member.filename)
            if path.is_absolute() or ".." in path.parts:
                raise ValueError(f"unsafe source-built ICU member: {member.filename}")
            if member.is_dir() or path.parts[0] == "META-INF":
                continue

            destination = stage.joinpath(*path.parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            contents = archive.read(member)
            if destination.exists():
                if destination.read_bytes() != contents:
                    raise ValueError(f"conflicting ICU resource: {destination}")
            else:
                destination.write_bytes(contents)

    output.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            str(jar),
            "--create",
            "--file",
            str(output),
            "--no-manifest",
            "--date=1980-01-01T00:00:02Z",
            "-C",
            str(stage),
            ".",
        ],
        check=True,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    for name in (
        "out",
        "javac",
        "jar",
        "icu-jar",
        "antlr3",
        "stringtemplate",
        "treelayout",
        "antlr4-runtime",
        "antlr4-tool",
    ):
        parser.add_argument(f"--{name}", type=Path, required=True)
    args = parser.parse_args()

    work = Path.cwd() / "antlr4-source-build"
    work.mkdir()
    archives = {
        "antlr3": args.antlr3,
        "stringtemplate": args.stringtemplate,
        "treelayout": args.treelayout,
        "antlr4-runtime": args.antlr4_runtime,
        "antlr4-tool": args.antlr4_tool,
    }
    sources = {}
    classes = {}
    for name, archive in archives.items():
        sources[name] = work / f"{name}-source"
        classes[name] = work / f"{name}-classes"
        sources[name].mkdir()
        classes[name].mkdir()
        extract_source(archive, sources[name])

    # ANTLR 3's DOTTreeGenerator is unrelated to the ANTLR 4 tool. It alone
    # imports the older StringTemplate 3 and ANTLR 2 toolchain.
    compile_sources(
        args.javac,
        sources["antlr3"],
        classes["antlr3"],
        [],
        {"DOTTreeGenerator.java"},
    )
    compile_sources(args.javac, sources["stringtemplate"], classes["stringtemplate"], [classes["antlr3"]])
    compile_sources(args.javac, sources["treelayout"], classes["treelayout"], [])
    compile_sources(args.javac, sources["antlr4-runtime"], classes["antlr4-runtime"], [])
    compile_sources(
        args.javac,
        sources["antlr4-tool"],
        classes["antlr4-tool"],
        [
            classes["antlr3"],
            classes["stringtemplate"],
            classes["treelayout"],
            classes["antlr4-runtime"],
            args.icu_jar,
        ],
    )

    stage = work / "jar-contents"
    stage.mkdir()
    output = args.out / "share/java/envoy-antlr4-tool.jar"
    assemble_jar(args.jar, stage, output, [*classes.values(), *sources.values()], args.icu_jar)


if __name__ == "__main__":
    main()

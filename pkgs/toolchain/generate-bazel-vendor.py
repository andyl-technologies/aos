"""Generate Bazel's Maven BUILD file from its pinned lock and source-built JARs.

The normal mode requires every ordinary locked JAR. The explicit partial mode
exists for the Java bootstrap probe while native and optional Java artifacts
are still being built from source.
"""

import argparse
import json
import re
from pathlib import Path


def target_name(coordinate: str) -> str:
    """Return the Maven target spelling used by rules_jvm_external."""

    return re.sub(r"[^A-Za-z0-9]", "_", coordinate)


def jar_path(coordinate: str, version: str, classifier: str | None = None) -> Path:
    """Return a locked JAR's path below the Maven repository."""

    group, artifact = coordinate.split(":", 1)
    name = f"{artifact}-{version}"
    if classifier is not None:
        name += f"-{classifier}"
    return Path(group.replace(".", "/")) / artifact / version / f"{name}.jar"


def render_rule(name: str, path: Path, dependencies: list[str]) -> str:
    """Render the import and raw-file targets for one source-built JAR."""

    dependency_labels = ", ".join(json.dumps(f":{target_name(item)}") for item in dependencies)
    return "\n".join(
        (
            "java_import(",
            f"    name = {json.dumps(name)},",
            f"    jars = [{json.dumps(path.as_posix())}],",
            f"    deps = [{dependency_labels}],",
            '    visibility = ["//visibility:public"],',
            ")",
            "",
            "filegroup(",
            f"    name = {json.dumps(name + '_file')},",
            f"    srcs = [{json.dumps(path.as_posix())}],",
            '    visibility = ["//visibility:public"],',
            ")",
        )
    )


def generate(lock_file: Path, maven_root: Path, partial: bool) -> str:
    """Render BUILD.vendor, rejecting unavailable locked inputs by default."""

    lock = json.loads(lock_file.read_text())
    artifacts = lock["artifacts"]
    ordinary = {
        coordinate: jar_path(coordinate, metadata["version"])
        for coordinate, metadata in artifacts.items()
        if "jar" in metadata["shasums"]
    }
    classified = {
        f"{coordinate}:{classifier}": jar_path(coordinate, metadata["version"], classifier)
        for coordinate, metadata in artifacts.items()
        for classifier in metadata["shasums"]
        if classifier != "jar"
    }
    locked = ordinary | classified
    missing = sorted(
        coordinate for coordinate, path in locked.items() if not (maven_root / path).is_file()
    )
    if missing and not partial:
        raise ValueError("Missing source-built Maven JARs:\n" + "\n".join(missing))

    available = {
        coordinate: path for coordinate, path in locked.items() if coordinate not in missing
    }
    rules = ["# Generated from the pinned Maven lock and source-built JARs."]
    if missing:
        unit = "JAR" if len(missing) == 1 else "JARs"
        verb = "is" if len(missing) == 1 else "are"
        rules.append(f"# NOT FOR RELEASE: {len(missing)} locked {unit} {verb} absent.")

    for coordinate, path in sorted(available.items()):
        name = target_name(coordinate)
        dependencies = sorted(
            dependency
            for dependency in lock["dependencies"].get(coordinate, [])
            if dependency in available
        )
        rules.append(render_rule(name, path, dependencies))

        base_coordinate = ":".join(coordinate.split(":", 2)[:2])
        version = artifacts[base_coordinate]["version"]
        rules.append(
            "\n".join(
                (
                    "alias(",
                    f"    name = {json.dumps(name + '_' + target_name(version))},",
                    f"    actual = {json.dumps(':' + name)},",
                    '    visibility = ["//visibility:public"],',
                    ")",
                )
            )
        )

    source_files = ["BUILD.vendor"] + [path.as_posix() for path in sorted(available.values())]
    rules.append(
        "\n".join(
            (
                "filegroup(",
                '    name = "srcs",',
                "    srcs = [",
                *(f"        {json.dumps(path)}," for path in source_files),
                "    ],",
                '    visibility = ["//visibility:public"],',
                ")",
            )
        )
    )

    return "\n\n".join(rules) + "\n"


def main() -> None:
    """Parse paths and write BUILD.vendor after validating the locked inputs."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument("--maven-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--partial", action="store_true")
    arguments = parser.parse_args()

    contents = generate(arguments.lock, arguments.maven_root, arguments.partial)
    arguments.output.write_text(contents)


if __name__ == "__main__":
    main()

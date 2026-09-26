"""Recreate Bazel bootstrap resources from pinned Starlark sources."""

import argparse
import ast
import json
from pathlib import Path
from zipfile import ZIP_STORED, ZipFile, ZipInfo


RULES_DIRECTORY = Path("src/main/java/com/google/devtools/build/lib/bazel/rules")
WORKSPACE_BUILD_FILES = (
    RULES_DIRECTORY / "BUILD",
    RULES_DIRECTORY / "cpp/BUILD",
    RULES_DIRECTORY / "java/BUILD",
)
WORKSPACE_OUTPUTS = frozenset(
    {
        "coverage.WORKSPACE",
        "rules_license.WORKSPACE",
        "rules_suffix.WORKSPACE",
        "cc_configure.WORKSPACE",
        "jdk.WORKSPACE",
    }
)


def workspace_repositories(source_root: Path) -> dict:
    """Read the repository specifications from Bazel's Starlark source."""

    tree = ast.parse((source_root / "workspace_deps.bzl").read_text())
    assignments = (
        statement
        for statement in tree.body
        if isinstance(statement, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "WORKSPACE_REPOS"
            for target in statement.targets
        )
    )
    values = [ast.literal_eval(statement.value) for statement in assignments]
    if len(values) != 1 or not isinstance(values[0], dict):
        raise ValueError("Expected one WORKSPACE_REPOS dictionary")
    return values[0]


def workspace_rules(build_file: Path) -> list[dict]:
    """Extract literal gen_workspace_stanza calls from one Bazel BUILD file."""

    rules = []
    for statement in ast.parse(build_file.read_text()).body:
        if not isinstance(statement, ast.Expr) or not isinstance(statement.value, ast.Call):
            continue
        call = statement.value
        if not isinstance(call.func, ast.Name) or call.func.id != "gen_workspace_stanza":
            continue
        rules.append({keyword.arg: ast.literal_eval(keyword.value) for keyword in call.keywords})
    return rules


def repository_clause(repo: str, info: dict, rule: dict) -> str:
    """Render one repository declaration using Bazel's pinned rule attributes."""

    if rule.get("use_maybe"):
        clause = """
maybe(
    http_archive,
    name = "{repo}",
    sha256 = "{sha256}",
    strip_prefix = {strip_prefix},
    urls = {urls},
)
"""
    else:
        clause = rule.get("repo_clause") or """
http_archive(
    name = "{repo}",
    sha256 = "{sha256}",
    strip_prefix = {strip_prefix},
    urls = {urls},
)
"""

    return clause.format(
        repo=repo,
        sha256=info["sha256"],
        strip_prefix=json.dumps(info["strip_prefix"]) if info.get("strip_prefix") else "None",
        urls=json.dumps(info["urls"]),
    )


def stripped_lines(value: str) -> str:
    """Match Bazel's line trimming for preamble and postamble source text."""

    return "\n".join(line.strip() for line in value.strip().split("\n"))


def workspace_contents(build_file: Path, rule: dict, repositories: dict) -> str:
    """Render a WORKSPACE resource from its literal Starlark declaration."""

    stanzas = {
        "{" + repo + "}": repository_clause(repo, repositories[repo], rule)
        for repo in rule["repos"]
    }
    if template := rule.get("template"):
        contents = (build_file.parent / template).read_text()
        for marker, stanza in stanzas.items():
            if contents.count(marker) != 1:
                raise ValueError(f"Expected one {marker} in {template}")
            contents = contents.replace(marker, stanza)
        return contents

    return (
        stripped_lines(rule.get("preamble", ""))
        + "\n"
        + "".join(stanzas.values())
        + "\n"
        + stripped_lines(rule.get("postamble", ""))
        + "\n"
    )


def write_workspace_resources(source_root: Path) -> list[Path]:
    """Write the version's declared WORKSPACE resources into the source tree."""

    declarations = [
        (source_root / relative_build_file, rule)
        for relative_build_file in WORKSPACE_BUILD_FILES
        for rule in workspace_rules(source_root / relative_build_file)
    ]
    if not declarations:
        # Bazel 9 removed WORKSPACE support and declares no such resources.
        return []

    repositories = workspace_repositories(source_root)
    written = []
    declared = set()
    for build_file, rule in declarations:
        output_name = rule["out"]
        if output_name not in WORKSPACE_OUTPUTS:
            raise ValueError(f"Unknown Bazel bootstrap WORKSPACE resource: {output_name}")
        declared.add(output_name)

        output = build_file.parent / output_name
        if output.exists():
            raise FileExistsError(f"Generated Bazel resource already exists: {output}")
        output.write_text(workspace_contents(build_file, rule, repositories))
        written.append(output)

    if {path.name for path in written} != declared:
        raise ValueError("Bazel bootstrap WORKSPACE resource set is incomplete")
    return written


def write_builtins_zip(source_root: Path) -> Path:
    """Archive every checked-in builtins .bzl file with fixed ZIP metadata."""

    builtins_root = source_root / "src/main/starlark/builtins_bzl"
    output = source_root / RULES_DIRECTORY / "builtins_bzl.zip"
    if output.exists():
        raise FileExistsError(f"Generated Bazel resource already exists: {output}")

    sources = sorted(builtins_root.rglob("*.bzl"))
    if not sources:
        raise ValueError("No Bazel builtins .bzl sources found")

    with ZipFile(output, "w") as archive:
        for source in sources:
            relative = source.relative_to(builtins_root)
            contents = source.read_text(encoding="utf-8").encode("utf-8")
            entry = ZipInfo(f"builtins_bzl/{relative.as_posix()}", (1980, 1, 1, 0, 0, 0))
            entry.compress_type = ZIP_STORED
            entry.external_attr = 0o100644 << 16
            archive.writestr(entry, contents)
    return output


def main() -> None:
    """Generate the source-backed resources required by Bazel's Java runtime."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", required=True, type=Path)
    arguments = parser.parse_args()

    write_workspace_resources(arguments.source_root)
    write_builtins_zip(arguments.source_root)


if __name__ == "__main__":
    main()

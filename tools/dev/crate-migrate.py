"""Moves and renames workspace crates using the reviewed migration map.

Run with Python 3.11 or later. The default previews edits; --apply writes them.
--check validates mapped target manifests after migration; --report lists old
package mentions for manual classification. Executable names, protocol tags,
serialized values, and digest domains are deliberately excluded from blanket
replacement. Historical prose and package-name inventories need review.
"""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[2]
MAP_PATH = ROOT / "tools/dev/crate-migration.json"
ROWS = json.loads(MAP_PATH.read_text())["crates"]
NAMES = {row["old"]: row["new"] for row in ROWS}
PATHS = {row["source"]: row["target"] for row in ROWS}
SORTED_PATHS = sorted(PATHS, key=len, reverse=True)


def relocate(path):
    """Resolves a repository path through the reviewed directory mapping."""
    value = str(path)
    for old in SORTED_PATHS:
        if value == old or value.startswith(old + "/"):
            return Path(PATHS[old] + value[len(old):])
    return path


def source_path(text):
    """Updates explicit repository source paths without renaming binaries."""
    pattern = r"(?<![\w])(?:" + "|".join(map(re.escape, SORTED_PATHS)) + r")(?=/|$|[^\w/-])"
    return re.sub(pattern, lambda match: PATHS[match[0]], text)


def crate_root(path):
    for row in ROWS:
        parent = Path(row["source"])
        if path == parent or parent in path.parents:
            return parent
    return None


def relative_literals(text, old_path):
    """Rebases existing include/build paths as their source directories move."""
    owner = crate_root(old_path)
    if owner is None:
        return text

    def replacement(match):
        value = match[1]
        # Only path-shaped literals are eligible; JSON/domain strings stay intact.
        if not value.startswith("../"):
            return match[0]
        candidates = [old_path.parent, owner]
        for base in candidates:
            resolved = Path(os.path.normpath(base / value))
            if not (ROOT / resolved).exists():
                continue
            new_base = relocate(base)
            target = relocate(resolved)
            rebased = os.path.relpath(target, new_base)
            return '"' + rebased + '"'
        return match[0]

    return re.sub(r'"([^"\n]+)"', replacement, text)


def manifest(text, path):
    """Updates Cargo identities and paths while preserving declared targets."""
    parsed = tomllib.loads(text)
    owner = crate_root(path)
    section = ""
    output = []
    for line in text.splitlines(keepends=True):
        header = re.match(r"\s*(\[.*?\])", line)
        if header:
            section = header[1]
        if section == "[package]":
            line = re.sub(r'^(name\s*=\s*")([^"\n]+)(")', lambda m: m[1] + NAMES.get(m[2], m[2]) + m[3], line)
        if "dependencies" in section:
            line = re.sub(r"^(\s*)([\w-]+)(?=\s*[.=])", lambda m: m[1] + NAMES.get(m[2], m[2]), line)
            line = re.sub(r'\bpackage\s*=\s*"([^"]+)"', lambda m: 'package = "' + NAMES.get(m[1], m[1]) + '"', line)
            def dependency_path(match):
                base = path.parent
                old = Path(os.path.normpath(base / match[1]))
                target = relocate(old)
                return 'path = "' + os.path.relpath(target, relocate(base)) + '"'
            line = re.sub(r'\bpath\s*=\s*"([^"]+)"', dependency_path, line)
            # Cargo feature references must follow dependency keys.
        if section == "[features]":
            for old, new in NAMES.items():
                line = re.sub(r'(?<=dep:)' + re.escape(old) + r'(?=["/])', new, line)
                line = re.sub(r'(?<=["])' + re.escape(old) + r'(?=[?/])', new, line)
        if path == Path("crates/Cargo.toml") and section == "[workspace]":
            line = re.sub(r'"([^"\n]+)"', lambda m: '"' + str(relocate(Path("crates") / m[1])).removeprefix("crates/") + '"' if m[1] in NAMES else m[0], line)
        output.append(line)

    result = "".join(output)
    if owner and NAMES[owner.name] != owner.name and (ROOT / owner / "src/main.rs").exists():
        if not any(binary.get("path") == "src/main.rs" for binary in parsed.get("bin", [])):
            result += '\n# Keep the installed command stable when its Cargo package is renamed.\n[[bin]]\nname = "' + owner.name + '"\npath = "src/main.rs"\n'
    return source_path(result)


# Strings and comments are separate lexical regions. Import identifiers change
# only in code; arbitrary string values never receive crate-name replacement.
RUST_REGIONS = re.compile(r'//[^\n]*|/\*[\s\S]*?\*/|r(?P<hashes>\#*)"[\s\S]*?"(?P=hashes)|"(?:\\.|[^"\\])*"')
RUST_NAMES = {old.replace("-", "_"): new.replace("-", "_") for old, new in NAMES.items() if old != new}
RUST_NAMES.pop("aos", None)
RUST_NAMES.pop("crucible", None)
IDENTIFIERS = re.compile(r"\b(?:" + "|".join(map(re.escape, sorted(RUST_NAMES, key=len, reverse=True))) + r")\b")


def rust(text, path):
    def code(region):
        region = IDENTIFIERS.sub(lambda match: RUST_NAMES[match[0]], region)
        return re.sub(r"\bcrucible(?=\s*::)", "crucible_engine", region)

    output = []
    cursor = 0
    for match in RUST_REGIONS.finditer(text):
        output.append(code(text[cursor:match.start()]))
        region = match[0]
        if region.startswith(("//", "/*")):
            region = IDENTIFIERS.sub(lambda item: RUST_NAMES[item[0]], region)
            region = re.sub(r"\bcrucible(?=::)", "crucible_engine", region)
        output.append(region)
        cursor = match.end()
    output.append(code(text[cursor:]))
    return source_path(relative_literals("".join(output), path))


def commands(text):
    """Updates Cargo package selectors, never installed executable selectors."""
    for old, new in sorted(NAMES.items(), key=lambda item: len(item[0]), reverse=True):
        if old != new:
            text = re.sub(r"(?<=-p )" + re.escape(old) + r"(?=[\s\"'\\;]|$)", new, text)
            text = re.sub(r"(?<=--package )" + re.escape(old) + r"(?=[\s\"'\\;]|$)", new, text)
            text = re.sub(r"(?<=--features )" + re.escape(old) + r"(?=/)", new, text)
    return text


def lockfile(text):
    return re.sub(r'"([^"\n]+)"', lambda match: '"' + NAMES.get(match[1], match[1]) + '"', text)


def changes():
    tracked = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).decode().split("\0")
    for value in tracked:
        if not value:
            continue
        path = Path(value)
        if path.suffix not in {".rs", ".toml", ".nix", ".md", ".sh", ".bash", ".py", ".ts", ".tsx", ".json", ".yml", ".yaml", ".txt", ".lock"} and path.name not in {"justfile", "AGENTS.md", "aos-dev"}:
            continue
        if str(path).startswith("tests/crucible/fixtures/"):
            continue
        actual = ROOT / path
        if not actual.is_file() or actual.is_symlink():
            continue
        try:
            original = actual.read_text()
        except (UnicodeError, OSError):
            continue
        if path.name == "Cargo.toml":
            revised = manifest(original, path)
        elif path == Path("crates/Cargo.lock"):
            revised = lockfile(original)
        elif path.suffix == ".rs":
            revised = rust(original, path)
        else:
            revised = source_path(original)
        revised = commands(revised)
        if revised != original:
            yield path, revised


def check():
    errors = []
    for row in ROWS:
        path = ROOT / row["target"] / "Cargo.toml"
        # Follow-up merges legitimately remove a mapped package.
        if not path.exists():
            if (ROOT / row["source"]).exists():
                errors.append(f"unmigrated directory: {row['source']}")
            continue
        data = tomllib.loads(path.read_text())
        if data["package"]["name"] != row["new"]:
            errors.append(f"incorrect package name: {path}")
    workspace = tomllib.loads((ROOT / "crates/Cargo.toml").read_text())
    for member in workspace["workspace"]["members"]:
        if not (ROOT / "crates" / member / "Cargo.toml").exists():
            errors.append(f"missing workspace member: {member}")
    for error in errors:
        print(error, file=sys.stderr)
    return bool(errors)


def report():
    old = [name for name, new in NAMES.items() if name != new and name not in ("aos", "crucible")]
    subprocess.run(["rg", "--pcre2", "-n", "--glob", "!crate-migration.json", "--glob", "!crate-migrate.py", r"(?<![\w-])(?:" + "|".join(old) + r")(?![\w-])", "crates", "pkgs", "tests", "docs", "stdenv"], cwd=ROOT, check=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--apply", action="store_true")
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--report", action="store_true")
    args = parser.parse_args()
    if args.check:
        return check()
    if args.report:
        report()
        return 0
    if not all((ROOT / row["source"] / "Cargo.toml").exists() for row in ROWS):
        parser.error("the initial migration has already run or a source crate is missing; use --check or --report")
    edits = list(changes())
    for path, content in edits:
        print(f"edit {path}")
        if args.apply:
            (ROOT / path).write_text(content)
    # Stage every old crate first: crates/aos becomes a project parent and
    # cannot be moved directly into one of its own descendants.
    staging = ROOT / "crates/.migration-stage"
    if args.apply:
        staging.mkdir()
        for row in ROWS:
            (ROOT / row["source"]).rename(staging / row["old"])
    for row in ROWS:
        print(f"move {row['source']} -> {row['target']}")
        if args.apply:
            destination = ROOT / row["target"]
            destination.parent.mkdir(parents=True, exist_ok=True)
            (staging / row["old"]).rename(destination)
    if args.apply:
        staging.rmdir()
    print(f"{len(edits)} edited files; {len(ROWS)} crate moves")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

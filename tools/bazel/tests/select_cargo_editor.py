"""Aligns a temporary Cargo editor oracle with its compiled default targets."""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tomllib


def select(manifest, excluded, targets):
    """Omits disabled required-feature tests while retaining all other targets."""
    source = manifest.read_text()
    original = tomllib.loads(source)
    explicit = {test["name"]: test for test in original.get("test", [])}
    omitted = set(excluded) & explicit.keys()
    if not omitted:
        return {}, set()

    features = original.get("features", {})
    enabled = set()
    pending = list(features.get("default", []))
    while pending:
        feature = pending.pop()
        if feature in enabled:
            continue
        enabled.add(feature)
        pending.extend(features.get(feature, []))
    for name in omitted:
        required = explicit[name].get("required-features", [])
        if not required or all(feature in enabled for feature in required):
            raise ValueError(f"cannot omit a default-enabled Cargo editor test: {name}")

    # Cargo's editor model includes disabled explicit targets. Disable automatic
    # discovery before removing them, then spell out every remaining auto test.
    discovered = {
        target["name"]: {
            "name": target["name"],
            "path": Path(target["src_path"]).relative_to(manifest.parent.resolve()).as_posix(),
        }
        for target in targets if "test" in target["kind"]
    }
    if not explicit.keys() <= discovered.keys():
        raise ValueError("Cargo metadata omitted an explicitly declared editor test")
    selected = {**discovered, **explicit}
    selected = {name: test for name, test in selected.items() if name not in omitted}

    def keep_test(match):
        declaration = tomllib.loads(match[0])["test"][0]
        return "" if declaration["name"] in omitted else match[0]

    source = re.sub(r"(?ms)^\[\[test\]\]\s*\n.*?(?=^\[|\Z)", keep_test, source)
    package = re.search(r"(?ms)^\[package\]\s*\n.*?(?=^\[|\Z)", source)
    if package is None:
        raise ValueError("Cargo editor oracle has no unique package table")
    section = re.sub(r"(?m)^autotests\s*=.*\n", "", package[0])
    section = section.replace("[package]\n", "[package]\nautotests = false\n", 1)
    source = source[:package.start()] + section + source[package.end():]
    for name in sorted(selected.keys() - explicit.keys()):
        source += "\n[[test]]\n" + "\n".join(
            key + " = " + json.dumps(value) for key, value in selected[name].items()
        ) + "\n"

    expected = dict(original)
    expected["package"] = {**original["package"], "autotests": False}
    expected["test"] = list(selected.values())
    actual = tomllib.loads(source)
    actual_tests = {test["name"]: test for test in actual.pop("test", [])}
    expected.pop("test")
    if actual != expected or actual_tests != selected:
        raise ValueError("Cargo editor selection changed metadata beyond test discovery")
    manifest.write_text(source)
    return selected, omitted


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["source", "packages", "output"]:
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--exclude", action="append", required=True)
    parser.add_argument("--cargo", type=Path, required=True)
    parser.add_argument("--rustc", type=Path, required=True)
    options = parser.parse_args()
    source = options.source.resolve()
    def metadata():
        value = json.loads(subprocess.check_output([
            str(options.cargo), "metadata", "--offline", "--no-deps", "--format-version=1",
            "--manifest-path", str(source / "crates/Cargo.toml"),
        ], cwd=source, env=dict(os.environ, RUSTC=str(options.rustc)), text=True))
        return {Path(package["manifest_path"]): package for package in value["packages"]}

    packages = metadata()
    pending = set(options.exclude)
    report = {}
    for name, directory in json.loads(options.packages.read_text()).items():
        manifest = source / directory / "Cargo.toml"
        targets, omitted = select(manifest, set(options.exclude), packages[manifest]["targets"])
        pending -= omitted
        if omitted:
            report[name] = {"selected": targets, "omitted": sorted(omitted)}
    if pending:
        raise ValueError(f"excluded Cargo editor targets lack explicit declarations: {sorted(pending)}")
    after = metadata()
    for manifest, package in packages.items():
        # Explicit declarations can reorder Cargo's target list. Every target
        # record, including library/binary settings, must otherwise match.
        expected = [target for target in package["targets"]
                    if not ("test" in target["kind"] and target["name"] in options.exclude)]
        if sorted(map(json.dumps, after[manifest]["targets"])) != sorted(map(json.dumps, expected)):
            raise ValueError(f"Cargo editor selection changed another target: {manifest}")
    options.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()

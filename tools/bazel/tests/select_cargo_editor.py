"""Aligns a temporary Cargo editor oracle with its compiled configured targets."""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tomllib


def select(manifest, excluded, targets, *, kind="test", default_features=True):
    """Omits disabled required-feature targets while retaining other declarations."""
    if kind not in {"test", "bin"}:
        raise ValueError(f"unsupported Cargo editor target kind: {kind}")
    automatic = "autotests" if kind == "test" else "autobins"
    source = manifest.read_text()
    original = tomllib.loads(source)
    explicit = {target["name"]: target for target in original.get(kind, [])}
    omitted = set(excluded) & explicit.keys()
    if not omitted:
        return {}, set()

    features = original.get("features", {})
    enabled = set()
    pending = list(features.get("default", [])) if default_features else []
    while pending:
        feature = pending.pop()
        if feature in enabled:
            continue
        enabled.add(feature)
        pending.extend(features.get(feature, []))
    for name in omitted:
        required = explicit[name].get("required-features", [])
        if not required or all(feature in enabled for feature in required):
            raise ValueError(f"cannot omit a default-enabled Cargo editor {kind}: {name}")

    # Cargo's editor model includes disabled explicit targets. Disable automatic
    # discovery before removing them, then spell out every remaining automatic target.
    discovered = {
        target["name"]: {
            "name": target["name"],
            "path": Path(target["src_path"]).relative_to(manifest.parent.resolve()).as_posix(),
        }
        for target in targets if kind in target["kind"]
    }
    if not explicit.keys() <= discovered.keys():
        raise ValueError("Cargo metadata omitted an explicitly declared editor target")
    selected = {**discovered, **explicit}
    selected = {name: target for name, target in selected.items() if name not in omitted}

    def keep_target(match):
        declaration = tomllib.loads(match[0])[kind][0]
        return "" if declaration["name"] in omitted else match[0]

    source = re.sub(r"(?ms)^\[\[" + kind + r"\]\]\s*\n.*?(?=^\[|\Z)", keep_target, source)
    package = re.search(r"(?ms)^\[package\]\s*\n.*?(?=^\[|\Z)", source)
    if package is None:
        raise ValueError("Cargo editor oracle has no unique package table")
    section = re.sub(r"(?m)^" + automatic + r"\s*=.*\n", "", package[0])
    section = section.replace("[package]\n", "[package]\n" + automatic + " = false\n", 1)
    source = source[:package.start()] + section + source[package.end():]
    for name in sorted(selected.keys() - explicit.keys()):
        source += "\n[[" + kind + "]]\n" + "\n".join(
            key + " = " + json.dumps(value) for key, value in selected[name].items()
        ) + "\n"

    expected = dict(original)
    expected["package"] = {**original["package"], automatic: False}
    expected[kind] = list(selected.values())
    actual = tomllib.loads(source)
    actual_targets = {target["name"]: target for target in actual.pop(kind, [])}
    expected.pop(kind)
    if actual != expected or actual_targets != selected:
        raise ValueError("Cargo editor selection changed metadata beyond target discovery")
    manifest.write_text(source)
    return selected, omitted


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["source", "packages", "output"]:
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--exclude", action="append", default=[])
    parser.add_argument("--exclude-bin", action="append", default=[])
    parser.add_argument("--no-default-features", action="store_true")
    parser.add_argument("--cargo", type=Path, required=True)
    parser.add_argument("--rustc", type=Path, required=True)
    options = parser.parse_args()
    if not options.exclude and not options.exclude_bin:
        parser.error("at least one excluded test or binary is required")
    source = options.source.resolve()

    def metadata():
        value = json.loads(subprocess.check_output([
            str(options.cargo), "metadata", "--offline", "--no-deps", "--format-version=1",
            "--manifest-path", str(source / "crates/Cargo.toml"),
            *(["--no-default-features"] if options.no_default_features else []),
        ], cwd=source, env=dict(os.environ, RUSTC=str(options.rustc)), text=True))
        return {Path(package["manifest_path"]): package for package in value["packages"]}

    packages = metadata()
    exclusions = {"test": set(options.exclude), "bin": set(options.exclude_bin)}
    pending = {kind: set(names) for kind, names in exclusions.items()}
    report = {}
    for name, directory in json.loads(options.packages.read_text()).items():
        manifest = source / directory / "Cargo.toml"
        for kind, excluded in exclusions.items():
            targets, omitted = select(
                manifest, excluded, packages[manifest]["targets"],
                kind=kind, default_features=not options.no_default_features,
            )
            pending[kind] -= omitted
            if omitted:
                selection = {"selected": targets, "omitted": sorted(omitted)}
                if kind == "test":
                    report.setdefault(name, {}).update(selection)
                else:
                    report.setdefault(name, {})["bins"] = selection
    if any(pending.values()):
        raise ValueError(f"excluded Cargo editor targets lack explicit declarations: {pending}")
    after = metadata()
    for manifest, package in packages.items():
        # Explicit declarations can reorder Cargo's target list. Every target
        # record, including library/binary settings, must otherwise match.
        expected = [target for target in package["targets"]
                    if not any(kind in target["kind"] and target["name"] in names
                               for kind, names in exclusions.items())]
        if sorted(map(json.dumps, after[manifest]["targets"])) != sorted(map(json.dumps, expected)):
            raise ValueError(f"Cargo editor selection changed another target: {manifest}")
    options.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()

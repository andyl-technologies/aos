"""Checks a connected family's editor roots against its compiled feature graph."""

import argparse
import csv
import json
from pathlib import Path
import re


def diagnostics(path):
    """Normalizes analyzer locations while preserving every diagnostic and type."""
    result = []
    with path.open(newline="") as stream:
        for row in csv.reader(stream):
            if len(row) < 5:
                raise ValueError(f"invalid analyzer diagnostic: {row}")
            if row[0] != "synthetic":
                _, separator, relative = row[0].partition("/crates/")
                if not separator:
                    raise ValueError(f"analyzer diagnostic outside first-party sources: {row[0]}")
                row[0] = "crates/" + relative
            result.append(row)
    return sorted(result)


def analysis_statistics(log):
    """Retains incomplete inference counts instead of equating exit zero with parity."""
    result = {}
    for category in ["exprs", "pats"]:
        matches = re.findall(
            rf"{category}: (\d+), \?\?ty: (\d+) \(\d+%\), \?ty: (\d+) \(\d+%\)", log,
        )
        if len(matches) != 1:
            raise ValueError(f"missing unique analyzer statistics for {category}")
        total, unknown, partial = map(int, matches[0])
        if total == 0 or unknown + partial > total:
            raise ValueError(f"invalid analyzer statistics for {category}")
        result[category] = {"total": total, "unknown": unknown, "partial": partial}
    panics = re.findall(r"panics: (\d+)", log)
    if panics != ["0"]:
        raise ValueError(f"analyzer did not finish without panics: {panics}")
    result["panics"] = 0
    result["complete_inference"] = all(
        result[category]["unknown"] == result[category]["partial"] == 0
        for category in ["exprs", "pats"]
    )
    return result


def verify(project, inventory, packages, workspace):
    """Returns graph evidence after checking roots, features, and macro inputs."""
    expected = {}
    for directory in packages.values():
        prefix = f"//{directory}:"
        for target in inventory["configured_targets"]:
            if not target["label"].startswith(prefix):
                continue
            if target["kind"] not in {"rust_library", "rust_binary", "rust_test", "rust_proc_macro"}:
                continue
            root = target["crate_root"]
            # Unit tests may inherit their library's crate instead of declaring
            # a root. Names cannot identify roots: binaries and their libtests
            # both compile src/bin, and examples can use arbitrary rule names.
            if not root:
                continue
            if not root.startswith(directory + "/") or not (workspace / root).is_file():
                raise ValueError(f"compiled crate root is outside its package or missing: {root}")
            features = sorted(target["features"])
            if root in expected and expected[root] != features:
                raise ValueError(f"ambiguous compiled features for {root}")
            expected[root] = features

    actual = {}
    macros = []
    for crate in project["crates"]:
        root = Path(crate["root_module"])
        if not root.is_file():
            raise ValueError(f"editor root does not exist: {root}")
        if crate["is_proc_macro"]:
            macro = Path(crate["proc_macro_dylib_path"])
            if not macro.is_file():
                raise ValueError(f"editor proc macro does not exist: {macro}")
            macros.append(crate["display_name"])
        if not root.is_relative_to(workspace):
            continue
        relative = root.relative_to(workspace).as_posix()
        if not any(relative.startswith(directory + "/") for directory in packages.values()):
            continue
        features = sorted(
            cfg[len('feature="'):-1]
            for cfg in crate["cfg"] if cfg.startswith('feature="') and cfg.endswith('"')
        )
        if expected.get(relative) != features:
            raise ValueError(f"editor/compiled root or feature mismatch: {relative}: {features!r}")
        # A library can remain a dependency beside its separate libtest view.
        # Validate both configurations, then count only the workspace root.
        if not crate.get("is_workspace_member", True):
            continue
        if relative in actual:
            raise ValueError(f"duplicate editor root: {relative}")
        actual[relative] = features
    if actual != expected:
        raise ValueError(f"editor/compiled root or feature mismatch: {actual!r} != {expected!r}")
    if not expected:
        raise ValueError("no family editor roots were checked")
    if not Path(project["sysroot_src"], "core/src/lib.rs").is_file():
        raise ValueError("source-built Rust sysroot sources are missing")
    return {"roots": actual, "proc_macros": sorted(macros), "crate_count": len(project["crates"])}


def compare_analysis(bazel, cargo, packages, scope="whole-model"):
    """Compares diagnostics in the declared scope and retains inference counts."""
    if scope not in {"whole-model", "selected-packages"}:
        raise ValueError("unknown editor comparison scope")
    expected = cargo["diagnostics"]
    cargo_statistics = {key: value for key, value in cargo.items() if key != "diagnostics"}
    if bazel["analysis"].get("panics") != 0 or cargo_statistics.get("panics") != 0:
        raise ValueError("editor comparison requires both analyzers to finish without panics")
    report = {"analysis": bazel["analysis"], "roots": bazel["roots"]}
    if scope == "whole-model":
        if bazel["analysis"] != cargo_statistics:
            raise ValueError(f"Bazel/Cargo editor inference differs: {bazel['analysis']} != {cargo_statistics}")
    else:
        if not packages or not bazel["roots"]:
            raise ValueError("selected editor comparison requires configured package roots")
        # Cargo's analyzer also checks test bodies in local path dependencies,
        # even when they are excluded from workspace membership. Those bodies
        # have no corresponding libtest in this configured Bazel family.
        def selected(row):
            return any(row[0].startswith(path + "/") for path in packages.values())

        if any(not selected(row) for row in bazel["diagnostics"]):
            raise ValueError("Bazel editor analyzed diagnostics outside the selected family")
        report.update({
            "comparison_scope": sorted(packages.values()),
            "aggregate_statistics_comparable": False,
            "cargo_analysis": cargo_statistics,
            "unselected_cargo_diagnostics": [row for row in expected if row[0] != "synthetic" and not selected(row)],
            # Synthetic diagnostics have no source location, so they cannot be
            # assigned to the guest or its unselected path dependencies. Retain
            # them explicitly; any such Bazel diagnostic fails the scope check.
            "unattributed_cargo_diagnostics": [row for row in expected if row[0] == "synthetic"],
        })
        expected = [row for row in expected if selected(row)]
        # Separate library/libtest views can report the same source location
        # twice. Compare locations and inferred types while retaining every
        # raw occurrence; whole-model statistics and multiplicities differ.
        report["bazel_diagnostics"] = bazel["diagnostics"]
        report["cargo_selected_diagnostics"] = expected
        report["diagnostic_multiplicity_comparable"] = False
        actual = sorted(set(map(tuple, bazel["diagnostics"])))
        expected = sorted(set(map(tuple, expected)))
        if actual != expected:
            raise ValueError("Bazel/Cargo editor diagnostic locations or types differ")
        report["diagnostics"] = [list(row) for row in expected]
        return report
    if bazel["diagnostics"] != expected:
        raise ValueError("Bazel/Cargo editor diagnostic locations or types differ")
    report["diagnostics"] = expected
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["project", "inventory", "packages", "workspace", "output"]:
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--analysis-log", type=Path)
    parser.add_argument("--diagnostics", type=Path)
    options = parser.parse_args()
    report = verify(
        json.loads(options.project.read_text()), json.loads(options.inventory.read_text()),
        json.loads(options.packages.read_text()), options.workspace.resolve(),
    )
    if options.analysis_log:
        report["analysis"] = analysis_statistics(options.analysis_log.read_text())
    if options.diagnostics:
        report["diagnostics"] = diagnostics(options.diagnostics)
    options.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()

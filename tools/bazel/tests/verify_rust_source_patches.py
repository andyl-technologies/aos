"""Checks Rustix source provenance, probe decisions, and temporary-file cleanup."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


NATIVE_TARGETS = {"x86_64-unknown-linux-gnu": "x86_64", "aarch64-unknown-linux-gnu": "aarch64"}


def files(root):
    """Reads the complete immutable source tree, including license files."""
    return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in root.rglob("*") if path.is_file()}


def compile_program(rustc, source, output):
    subprocess.run([str(rustc), "--edition=2021", "--crate-name", "rustix_build_probe",
                    str(source / "build.rs"), "-o", str(output)], check=True)


def probe(program, source, rustc, target, output, features):
    """Runs with explicit target/cfg inputs and no ambient Cargo configuration."""
    output.mkdir()
    environment = {
        "PATH": os.environ["PATH"], "HOME": str(output), "RUSTC": str(rustc),
        "TARGET": target, "OUT_DIR": str(output), "CARGO_CFG_TARGET_ARCH": NATIVE_TARGETS[target],
        "CARGO_CFG_TARGET_ENV": "gnu", "CARGO_CFG_TARGET_OS": "linux",
        "CARGO_CFG_TARGET_POINTER_WIDTH": "64", "CARGO_CFG_TARGET_ENDIAN": "little",
        **features,
    }
    result = subprocess.run([str(program)], cwd=source, env=environment, capture_output=True, check=True)
    return {"stdout": result.stdout.decode(), "stderr": result.stderr.decode(),
            "files": files(output)}


def verify(options):
    before, after = files(options.baseline), files(options.patched)
    if before.keys() != after.keys():
        raise ValueError("patch provenance entered the compiled source repository")
    changed = sorted(name for name in before if before[name] != after[name])
    if changed != ["build.rs"]:
        raise ValueError("unexpected patched source changes: " + repr(changed))
    manifest = json.loads((options.provenance / "manifest.json").read_text())
    policy = json.loads(options.policy.read_text())["packages"]["rustix"]["1.1.4"]
    if (manifest["package"], manifest["version"], manifest["archive_sha256"]) != ("rustix", "1.1.4", policy["archive_sha256"]):
        raise ValueError("source patch provenance has the wrong archive identity")
    if len(manifest["patches"]) != len(policy["patches"]):
        raise ValueError("source patch provenance has a different patch count")
    for applied, expected in zip(manifest["patches"], policy["patches"]):
        if applied["origin"] != expected["path"] or applied["strip"] != expected["strip"]:
            raise ValueError("source patch provenance differs from the checked policy")
        digest = hashlib.sha256((options.provenance / applied["path"]).read_bytes()).hexdigest()
        if digest != applied["sha256"] or digest != expected["sha256"]:
            raise ValueError("retained source patch bytes differ from the policy")

    if options.target not in NATIVE_TARGETS:
        raise ValueError("unsupported native probe qualification target: " + options.target)
    with tempfile.TemporaryDirectory(prefix="rustix-probe-", dir=os.environ["TMPDIR"]) as temporary:
        scratch = Path(temporary)
        sources = {"baseline": options.baseline, "patched": options.patched, "upstream-fixed": options.upstream_fixed}
        programs = {}
        for name, source in sources.items():
            programs[name] = scratch / name
            compile_program(options.rustc, source, programs[name])
        profiles = {
            "native": (options.rustc, {"CARGO_FEATURE_STD": "1"}),
            "native-libc": (options.rustc, {"CARGO_FEATURE_STD": "1", "CARGO_FEATURE_USE_LIBC": "1"}),
            "native-no-std": (options.rustc, {}),
            "unsupported": (options.unsupported_rustc, {"CARGO_FEATURE_STD": "1"}),
        }
        reports = {}
        for name, (rustc, features) in profiles.items():
            records = {kind: probe(programs[kind], source, rustc, options.target,
                                   scratch / (name + "-" + kind), features)
                       for kind, source in sources.items()}
            if any(records["baseline"][field] != records["patched"][field] for field in ["stdout", "stderr"]):
                raise ValueError("probe decisions changed: " + name)
            if set(records["baseline"]["files"]) != {"rustix_test_can_compile"}:
                raise ValueError("baseline did not reproduce the retained probe artifact: " + name)
            if any(records[kind]["files"] for kind in ["patched", "upstream-fixed"]):
                raise ValueError("probe artifact survived cleanup: " + name)
            reports[name] = records
    return {"schema_version": 1, "target": options.target, "upstream_source_files": len(before), "changed_source_files": changed,
            "library_sources_and_licenses_identical": True, "patch_provenance": manifest,
            "probe_profiles": reports, "probe_decisions_unchanged": True,
            "patched_and_upstream_fixed_output_directories_empty": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["baseline", "patched", "provenance", "upstream-fixed", "policy", "rustc", "unsupported-rustc", "output"]:
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--target", required=True)
    options = parser.parse_args()
    options.output.mkdir(exist_ok=True)
    (options.output / "report.json").write_text(json.dumps(verify(options), indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()

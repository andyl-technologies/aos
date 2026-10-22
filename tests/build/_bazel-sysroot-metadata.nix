##! Qualifies immutable upstream-library metadata without a runtime Cargo driver.
{pkgs}: let
  toolchains = pkgs.aosBazelToolchains;
in
  pkgs.runCommand "aos-bazel-sysroot-metadata" {buildDeps = [pkgs.python3];} ''
    mkdir -p "$out"
    ${pkgs.python3}/bin/python3 - ${toolchains} "$out" <<'PYTHON'
    import hashlib
    import json
    from pathlib import Path
    import subprocess
    import sys

    toolchain, output = map(Path, sys.argv[1:])
    manifest = toolchain / "developer/rust-src/library/Cargo.toml"
    prefix = [str(toolchain / "bin/cargo"), "metadata", "--manifest-path", str(manifest), "--format-version", "1"]
    records = {}
    for target in ["x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu", "wasm32-unknown-unknown"]:
        command = prefix + ["--filter-platform", target, "-Zlockfile-path", "-Zunstable-options"]
        result = subprocess.run(command, capture_output=True, check=True, timeout=30)
        prepared = toolchain / "developer/sysroot-metadata" / (target + ".json")
        if result.stdout != prepared.read_bytes():
            raise ValueError("adapter did not return the exact prepared library graph")
        metadata = json.loads(result.stdout)
        names = {package["name"] for package in metadata["packages"]}
        if not {"core", "alloc", "std", "proc_macro"} <= names or not metadata["resolve"]["nodes"]:
            raise ValueError("incomplete standard-library metadata")
        for package in metadata["packages"]:
            if not Path(package["manifest_path"]).is_file():
                raise ValueError("standard-library metadata references an unavailable source")
        records[target] = {"sha256": hashlib.sha256(result.stdout).hexdigest(), "packages": sorted(names)}

    first_party = Path("Cargo.toml").resolve()
    first_party.write_text('[package]\nname = "rejected"\nversion = "0.1.0"\n')
    negative = [
        [str(toolchain / "bin/cargo"), "build"],
        [str(toolchain / "bin/cargo"), "metadata", "--manifest-path", str(first_party),
         "--format-version", "1", "--filter-platform", "x86_64-unknown-linux-gnu"],
        prefix + ["--filter-platform", "x86_64-unknown-linux-gnu", "--all-features"],
    ]
    for index, command in enumerate(negative):
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        (output / f"rejected-{index}.log").write_text(result.stdout + result.stderr)
        if result.returncode == 0:
            raise ValueError("adapter accepted first-party Cargo execution or an unsupported library configuration")
    (output / "metadata.json").write_text(json.dumps(records, indent=2, sort_keys=True) + "\n")
    PYTHON
  ''

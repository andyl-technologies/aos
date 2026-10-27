##! Compares the source-built upstream extractor with upstream Cargo fixtures.
{pkgs}: let
  helper = import ../../pkgs/build-support/_bazel/rust-helper.nix {pkgs = pkgs.buildPackages;};
  fixtures = "${pkgs.aosBazelModules.rules_rust}/cargo/private/cargo_toml_variable_extractor/testdata";
in
  pkgs.runCommand "aos-bazel-manifest-extractor-parity" {buildDeps = [pkgs.rust pkgs.python3];} ''
    cp -R ${fixtures} fixtures
    chmod -R u+w fixtures
    mkdir -p "$out"
    export CARGO_HOME="$TMPDIR/cargo" CARGO_TARGET_DIR="$TMPDIR/target" CARGO_NET_OFFLINE=true
    cp ${../../tools/bazel/metadata/export_rust_project.py} export_rust_project.py
    ${pkgs.python3}/bin/python3 - ${helper}/bin/cargo_toml_variable_extractor "$out" <<'PYTHON'
    import hashlib
    import json
    from pathlib import Path
    import subprocess
    import sys

    from export_rust_project import compiler_file_lines

    helper, output = Path(sys.argv[1]), Path(sys.argv[2])
    records = {}
    for name in ["empty", "standalone", "workspace/subcrate"]:
        manifest = Path("fixtures", name, "Cargo.toml").resolve()
        env_file = output / (name.replace("/", "-") + ".env")
        command = [str(helper), str(env_file), str(manifest)]
        if name.startswith("workspace/"):
            command.append(str(Path("fixtures/workspace/Cargo.toml").resolve()))
        subprocess.run(command, check=True, timeout=30)
        actual = "\n".join(compiler_file_lines(env_file)) + "\n"
        # These are unchanged upstream fixture programs, not first-party
        # compilation. They print the environment provided by Cargo itself.
        oracle = subprocess.run(["${pkgs.rust}/bin/cargo", "run", "--offline", "--quiet",
                                 "--manifest-path", str(manifest)],
                                check=True, capture_output=True, text=True, timeout=120)
        if actual != oracle.stdout:
            raise ValueError(f"upstream helper/Cargo environment differs for {name}: {actual!r} != {oracle.stdout!r}")
        records[name] = {"sha256": hashlib.sha256(actual.encode()).hexdigest(), "variables": 14}
    (output / "parity.json").write_text(json.dumps(records, indent=2, sort_keys=True) + "\n")
    PYTHON
  ''

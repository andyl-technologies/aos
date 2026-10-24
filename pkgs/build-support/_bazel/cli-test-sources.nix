##! Retains declared repository inputs consumed by CLI integration contracts.
{pkgs}: let
  source = import ../../tools/aos/_workspace-source.nix {
    inherit (pkgs) lib;
    includeIntegrationInputs = true;
  };
in
  pkgs.runCommand "aos-bazel-cli-test-sources" {buildDeps = [pkgs.python3];} ''
    mkdir -p "$out/source"
    ${pkgs.python3}/bin/python3 - "$out" <<'PYTHON'
    import hashlib
    import json
    from pathlib import Path
    import sys

    output = Path(sys.argv[1])
    files = {}
    source = Path("${source}")
    for path in sorted(source.rglob("*")):
        if path.is_symlink():
            raise ValueError("CLI repository inputs must contain regular files")
        if path.is_file():
            data = path.read_bytes()
            name = path.relative_to(source).as_posix()
            files[name] = {
                "sha256": hashlib.sha256(data).hexdigest(), "size": len(data),
                "executable": bool(path.stat().st_mode & 0o111),
            }
            # BUILD files are audit data. A suffix keeps them from creating
            # nested Bazel packages that would truncate the declared glob.
            target = output / "source" / (name + ".aos-source")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
    # Architecture checks consume Bazel's all-profile production graph through
    # this declared source tree. Cargo remains only an independent oracle.
    architecture_name = "build/bazel-architecture.json"
    if architecture_name in files:
        raise ValueError("generated architecture metadata conflicts with repository source")
    architecture = Path("${pkgs.aosBazelArchitecture}/architecture.json").read_bytes()
    files[architecture_name] = {
        "sha256": hashlib.sha256(architecture).hexdigest(), "size": len(architecture),
        "executable": False,
    }
    architecture_target = output / "source" / (architecture_name + ".aos-source")
    architecture_target.parent.mkdir(parents=True, exist_ok=True)
    architecture_target.write_bytes(architecture)
    if not {"MODULE.bazel", "default.nix", "crates/cli/aos-cli/src/lib.rs"}.issubset(files):
        raise ValueError("CLI repository inputs are incomplete")
    (output / "manifest.json").write_text(json.dumps({
        "schema_version": 1, "files": files,
    }, indent=2, sort_keys=True) + "\n")
    PYTHON
    cat > "$out/BUILD.bazel" <<'BUILD'
    exports_files(["manifest.json"], visibility = ["//visibility:public"])
    filegroup(name = "sources", srcs = glob(["source/**"]), visibility = ["//visibility:public"])
    BUILD
    touch "$out/REPO.bazel"
  ''

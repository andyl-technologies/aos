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
    if not files or "crates/aos/cli/aos-cli/src/lib.rs" not in files:
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

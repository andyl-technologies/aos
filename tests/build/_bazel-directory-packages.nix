##! Exercises generated tree aliases, export, digests and Nix installation.
{pkgs}: let
  workspace = pkgs.mkAosBazelWorkspace {
    root = ../..;
    sourceDirectories = ["tools/bazel"];
    analysisTargets = ["//tools/bazel/testing/package-tree:package"];
  };
  build = pkgs.mkAosBazelBuild {
    pname = "aos-bazel-directory-package-fixture";
    inherit workspace;
    targets = ["//tools/bazel/testing/package-tree:package"];
  };
  installed = pkgs.mkAosBazelPackage {
    pname = "directory-fixture";
    version = "1";
    inherit build;
    packageLabel = "//tools/bazel/testing/package-tree:package";
  };
in
  pkgs.runCommand "aos-bazel-directory-package-check" {buildDeps = [pkgs.python3];} ''
    mkdir -p "$out"
    ${pkgs.python3}/bin/python3 - ${installed} "$out/result.json" <<'PYTHON'
    import json
    from pathlib import Path
    import sys

    root, output = map(Path, sys.argv[1:])
    manifest = json.loads((root / "nix-support/bazel-package.json").read_text())
    expected = {"assets/nested/payload.txt": b"generated asset\n", "assets/version": b"1\n"}
    actual = {entry["destination"] for entry in manifest["artifacts"]}
    if actual != set(expected):
        raise ValueError("installed tree has an incomplete artifact inventory")
    # Nix canonicalizes installed data files to read-only store permissions.
    for name, content in expected.items():
        path = root / name
        if path.is_symlink() or path.read_bytes() != content or path.stat().st_mode & 0o777 != 0o444:
            raise ValueError("generated package tree changed bytes, modes or file kinds")
    output.write_text(json.dumps({"status": "PASS", "files": sorted(actual)}, sort_keys=True) + "\n")
    PYTHON
  ''

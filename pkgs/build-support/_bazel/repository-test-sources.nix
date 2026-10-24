##! Preserves the complete production text inspected by repository contract tests.
{
  pkgs,
  lib,
}: let
  repositoryRoot = ../../..;
  repositoryRootString = toString repositoryRoot;
  productionRoots = ["crates" "api" "modules" "pkgs" "systems" "stdenv" "lib"];
  excludedDirectories = [".git" ".worktrees" "target" "node_modules" "vendor" "tests" "examples"];
  sourceExtensions = [
    ".rs"
    ".proto"
    ".sql"
    ".nix"
    ".jq"
    ".js"
    ".jsx"
    ".ts"
    ".tsx"
    ".css"
    ".html"
    ".sh"
    ".toml"
    ".json"
    ".yaml"
    ".yml"
    ".c"
    ".h"
    ".cc"
    ".cpp"
    ".go"
    ".py"
    ".rb"
  ];
  includeSource = path: type: let
    pathString = toString path;
    relative = lib.removePrefix "${repositoryRootString}/" pathString;
    parts = lib.splitString "/" relative;
    inProductionRoot = builtins.elem (builtins.head parts) productionRoots;
    excluded = builtins.any (part: builtins.elem part excludedDirectories) parts;
    sourceFile = builtins.any (extension: lib.hasSuffix extension (baseNameOf path)) sourceExtensions;
  in
    pathString
    == repositoryRootString
    || (inProductionRoot && !excluded && (type == "directory" || (type == "regular" && sourceFile)))
    || (type == "regular" && builtins.elem relative ["MODULE.bazel" "default.nix" "flake.nix" "justfile"]);
  # Enumerate the checkout rather than the filtered store path: read-only Nix
  # evaluation can compute that path without first adding its files to the store.
  sourceFiles = directory: let
    entries = builtins.readDir directory;
  in
    lib.concatMap (name: let
      path = directory + "/${name}";
      type = entries.${name};
    in
      if !includeSource path type
      then []
      else if type == "directory"
      then sourceFiles path
      else lib.optional (type == "regular") (lib.removePrefix "${repositoryRootString}/" (toString path)))
    (builtins.attrNames entries);
  source = builtins.path {
    path = repositoryRoot;
    name = "aos-production-audit-source";
    filter = includeSource;
  };
in
  pkgs.mkDerivation {
    pname = "aos-bazel-repository-test-sources";
    version = "1";
    src = source;
    passthru.productionSourceFiles = sourceFiles repositoryRoot;
    buildDeps = [pkgs.python3];
    sharedBuildCache = false;
    dontStrip = true;
    dontPatchELF = true;
    dontNukeRefs = true;
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out"
          cp -R "$src" "$out/source"
          ${pkgs.python3}/bin/python3 - "$out" <<'PYTHON'
          import hashlib
          import json
          from pathlib import Path
          import sys

          output = Path(sys.argv[1])
          source = output / "source"
          files = {}
          for path in sorted(source.rglob("*")):
              if path.is_symlink():
                  raise ValueError("production audit source must contain regular files")
              if path.is_file():
                  data = path.read_bytes()
                  files[path.relative_to(source).as_posix()] = {
                      "sha256": hashlib.sha256(data).hexdigest(), "size": len(data),
                  }
          if not {"MODULE.bazel", "default.nix"}.issubset(files):
              raise ValueError("production audit source is incomplete")
          (output / "manifest.json").write_text(json.dumps({
              "schema_version": 1, "files": files,
          }, indent=2, sort_keys=True) + "\n")
          PYTHON
          cat > "$out/BUILD.bazel" <<'BUILD'
          exports_files(["manifest.json"], visibility = ["//visibility:public"])

          filegroup(
              name = "production_sources",
              srcs = glob(["source/**"]),
              visibility = ["//visibility:public"],
          )
          BUILD
          touch "$out/REPO.bazel"
        '';
      }
    ];
  }

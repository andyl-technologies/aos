# The selected kernel companion keeps the complete AOS build/bootstrap source
# in its original relative layout. Runtime journals and local outputs are not
# corresponding-source inputs. The operator supplies an immutable source tree.
{lib}: let
  repoRoot = ../../..;
  rootString = toString repoRoot;
  entries = [
    ".dockerignore"
    ".envrc"
    ".gitattributes"
    ".gitignore"
    "AGENTS.md"
    "CLAUDE.md"
    "CONTRIBUTING.md"
    "LICENSE"
    "LICENSES"
    "README.md"
    "aos-dev"
    "containers"
    "crates"
    "default.nix"
    "dev"
    "docs"
    "flake.lock"
    "flake.nix"
    "justfile"
    "lib"
    "modules"
    "pkgs"
    "qualification"
    "stdenv"
    "systems"
    "tests"
    "tools"
  ];
  excluded = [".git" ".crucible" "run-state" ".worktrees" "target" "result" "__pycache__"];
  characterization = "${rootString}/tests/fixtures/system-characterization-goldens";
in
  builtins.path {
    path = repoRoot;
    name = "aos-selected-kernel-build-source";
    filter = path: _type: let
      base = baseNameOf path;
      value = toString path;
    in
      !builtins.elem base excluded
      && builtins.match "core[.][0-9]+" base == null
      && !lib.hasPrefix characterization value
      && (value
        == rootString
        || builtins.any
        (entry: value == "${rootString}/${entry}" || lib.hasPrefix "${rootString}/${entry}/" value)
        entries);
  }

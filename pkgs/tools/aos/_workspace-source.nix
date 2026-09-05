{lib}: let
  repoRoot = ../../..;
  repoRootString = toString repoRoot;
in
  builtins.path {
    path = repoRoot;
    name = "aos-workspace-src";
    filter = path: type: let
      pathString = toString path;
      base = baseNameOf path;
      generatedDir =
        type
        == "directory"
        && (
          base
          == ".git"
          || base == ".direnv"
          || base == ".worktrees"
          || base == "result"
          || lib.hasPrefix "result-" base
          || base == "target"
          || lib.hasPrefix "target-" base
        );
    in
      !generatedDir
      && (
        pathString
        == repoRootString
        || lib.hasPrefix "${repoRootString}/crates" pathString
        || lib.hasPrefix "${repoRootString}/lib" pathString
        || lib.hasPrefix "${repoRootString}/modules" pathString
        || lib.hasPrefix "${repoRootString}/pkgs" pathString
        || lib.hasPrefix "${repoRootString}/qualification" pathString
        || lib.hasPrefix "${repoRootString}/stdenv" pathString
        || lib.hasPrefix "${repoRootString}/systems" pathString
        || pathString == "${repoRootString}/tests"
        || lib.hasPrefix "${repoRootString}/tests/fleet" pathString
        || lib.hasPrefix "${repoRootString}/tests/qualification" pathString
        || lib.hasPrefix "${repoRootString}/tests/vm" pathString
        || pathString == "${repoRootString}/default.nix"
        || pathString == "${repoRootString}/flake.nix"
        || pathString == "${repoRootString}/justfile"
        || pathString == "${repoRootString}/docs"
        || pathString == "${repoRootString}/docs/rfcs"
        || lib.hasPrefix "${repoRootString}/docs/rfcs/0012-hub-surface-topology" pathString
      );
  }

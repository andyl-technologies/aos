{lib}: let
  repoRoot = ../../..;
  repoRootString = toString repoRoot;
in
  builtins.path {
    path = repoRoot;
    name = "crucible-workspace-src";
    filter = path: _type: let
      pathString = toString path;
      base = baseNameOf path;
    in
      base != ".git"
      && base != "target"
      && base != "result"
      && (
        pathString == repoRootString
        || lib.hasPrefix "${repoRootString}/crates" pathString
        || lib.hasPrefix "${repoRootString}/docs" pathString
        || pathString == "${repoRootString}/pkgs"
        || pathString == "${repoRootString}/pkgs/tools"
        || lib.hasPrefix "${repoRootString}/pkgs/tools/crucible" pathString
        || pathString == "${repoRootString}/tests"
        || lib.hasPrefix "${repoRootString}/tests/crucible" pathString
      );
  }

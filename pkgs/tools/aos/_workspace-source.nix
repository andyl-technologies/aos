{
  lib,
  evaluatorFixtures ? false,
}: let
  repoRoot = ../../..;
  repoRootString = toString repoRoot;
in
  builtins.path {
    path = repoRoot;
    name =
      if evaluatorFixtures
      then "aos-evaluator-workspace-src"
      else "aos-workspace-src";
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
        || (
          evaluatorFixtures
          && (
            type
            == "directory"
            || lib.hasSuffix ".nix" pathString
            || lib.hasPrefix "${repoRootString}/fuzz/corpus/" pathString
          )
        )
      );
  }

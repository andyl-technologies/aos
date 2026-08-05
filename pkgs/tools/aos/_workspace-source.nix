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
        type == "directory"
        && (
          base == ".git"
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
        pathString == repoRootString
        || type == "directory"
        || lib.hasPrefix "${repoRootString}/crates/" pathString
        || lib.hasSuffix ".nix" pathString
        || lib.hasPrefix "${repoRootString}/fuzz/corpus/" pathString
      );
  }

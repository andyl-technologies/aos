##! Cargo-only Crucible workspace source.
{lib}: let
  repoRoot = ../../..;
  repoRootString = toString repoRoot;
in
  builtins.path {
    path = repoRoot;
    name = "crucible-cargo-src";
    filter = path: _type: let
      pathString = toString path;
      base = baseNameOf path;
    in
      base
      != ".git"
      && base != "target"
      && base != "result"
      && (
        pathString
        == repoRootString
        || pathString == "${repoRootString}/crates"
        || lib.hasPrefix "${repoRootString}/crates" pathString
      );
  }

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
      && pathString != "${repoRootString}/result"
      && (
        pathString
        == repoRootString
        || pathString == "${repoRootString}/crates"
        || lib.hasPrefix "${repoRootString}/crates" pathString
        || builtins.elem pathString [
          "${repoRootString}/tests"
          "${repoRootString}/tests/crucible"
          "${repoRootString}/tests/crucible/fixtures"
          "${repoRootString}/tests/crucible/fixtures/live-qemu-fuzz.family.toml"
        ]
      );
  }

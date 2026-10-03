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
      && base != ".crucible"
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
          "${repoRootString}/docs"
          "${repoRootString}/docs/rfcs"
          "${repoRootString}/docs/rfcs/0020-crucible-campaigns"
          "${repoRootString}/docs/rfcs/0020-crucible-campaigns/schema-registry.tsv"
          "${repoRootString}/docs/rfcs/0020-crucible-campaigns/11-implementation-plan.md"
        ]
      );
  }

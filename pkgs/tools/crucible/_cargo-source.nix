##! Cargo-only Crucible workspace source.
{lib}: let
  repoRoot = ../../..;
  repoRootString = toString repoRoot;
  daemonRunState = "${repoRootString}/crates/crucible/crucible-daemon/run-state";
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
      && pathString != daemonRunState
      && !lib.hasPrefix "${daemonRunState}/" pathString
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

##! Cargo-only Crucible workspace source.
{lib}: let
  isCargoBuildDirectory = import ../../build-support/_cargo-build-directory.nix;
  repoRoot = ../../..;
  repoRootString = toString repoRoot;
  daemonRunState = "${repoRootString}/crates/crucible/control/crucible-daemon/run-state";
in
  builtins.path {
    path = repoRoot;
    name = "crucible-cargo-src";
    filter = path: _type: let
      pathString = toString path;
      base = baseNameOf path;
      nodeContract = "${repoRootString}/docs/rfcs/0025-crucible-node-contract";
    in
      base
      != ".git"
      && base != ".crucible"
      # Local daemon journals must not perturb Cargo source identities.
      && base != "run-state"
      && !(base == "target" && isCargoBuildDirectory repoRoot path)
      && pathString != "${repoRootString}/result"
      && pathString != daemonRunState
      && !lib.hasPrefix "${daemonRunState}/" pathString
      && (
        pathString
        == repoRootString
        || pathString == "${repoRootString}/crates"
        || lib.hasPrefix "${repoRootString}/crates" pathString
        # The qualification catalogue embeds its normative RFC and wire vectors.
        || pathString == nodeContract
        || lib.hasPrefix "${nodeContract}/" pathString
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

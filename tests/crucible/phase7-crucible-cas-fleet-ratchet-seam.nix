{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.crucibleCasFleetRatchetSeam",
  taskIds ? ["T-PKG-23"],
  dependencies ? [],
}: let
  packagingDoc = builtins.readFile ../../docs/engineering/crucible/packaging.md;
  distributedExplorationDoc = builtins.readFile ../../docs/engineering/crucible/distributed-exploration.md;
  casSource = builtins.readFile ../../crates/crucible/crucible-store/src/lib.rs;
  casManifest = builtins.readFile ../../crates/crucible/crucible-store/Cargo.toml;
  defaultChecks = builtins.readFile ./default.nix;
  gateCiWiring = builtins.readFile ./phase7-crucible-gate-ci-wiring.nix;
  fleetStoreGate = builtins.readFile ./phase7-crucible-fleet-store.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  failures =
    failuresFor "docs/engineering/crucible/packaging.md" packagingDoc [
      {
        label = "fleet backend shares the seam";
        needle = "`SharedDagStore` as the fleet-visible backend of the same seam";
      }
    ]
    ++ failuresFor "docs/engineering/crucible/distributed-exploration.md" distributedExplorationDoc [
      {
        label = "same ratchet seam section";
        needle = "The fleet-visible content-addressed store is the **same seam**";
      }
      {
        label = "seam is documentation, not a dependency";
        needle = "documented text, not a";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-store/src/lib.rs" casSource [
      {
        label = "fleet-visible same seam docs";
        needle = "the fleet-visible backend for that same seam";
      }
      {
        label = "dependency-gated invalidation not second substrate";
        needle = "dependency-gated invalidation is\n//! not a second substrate";
      }
      {
        label = "SharedDagStore in seam";
        needle = "[`SharedDagStore`]";
      }
      {
        label = "InvalidationQuery evaluate in seam";
        needle = "[`InvalidationQuery::evaluate`]";
      }
      {
        label = "merge bar includes content-address";
        needle = "gate:content-address";
      }
      {
        label = "merge bar includes replay-oracle";
        needle = "gate:replay-oracle";
      }
      {
        label = "merge bar includes e2e";
        needle = "gate:e2e-determinism";
      }
      {
        label = "standalone no RFC dependency";
        needle = "no RFC-0007 dependency exists";
      }
    ]
    ++ forbiddenFor "crates/crucible/crucible-store/Cargo.toml" casManifest [
      {
        label = "ratchet dependency prefix";
        needle = "ratchet-";
      }
      {
        label = "aos-nix dependency prefix";
        needle = "aos-nix-";
      }
      {
        label = "exact ratchet dependency";
        needle = "ratchet =";
      }
      {
        label = "exact aos-nix dependency";
        needle = "aos-nix =";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase7 fleet ratchet seam check imported";
        needle = "crucibleCasFleetRatchetSeam = import ./phase7-crucible-cas-fleet-ratchet-seam.nix";
      }
      {
        label = "fleet equivalence raw gate waits for seam proof";
        needle = "dependencies = [phase2.gates.singleVmFingerprint.rawGate e2eDeterminism.rawGate phase7.crucibleFleetStore phase7.crucibleSharedDagStore phase7.crucibleFrontierLeases phase7.crucibleFourLayerDedup phase7.crucibleDeterminismGuardrail phase7.crucibleCasFleetRatchetSeam];";
      }
      {
        label = "fleet equivalence wrapper waits for seam proof";
        needle = "dependencies = [phase2.gates.singleVmFingerprint e2eDeterminism phase7.crucibleFleetStore phase7.crucibleSharedDagStore phase7.crucibleFrontierLeases phase7.crucibleFourLayerDedup phase7.crucibleDeterminismGuardrail phase7.crucibleCasFleetRatchetSeam];";
      }
    ]
    ++ failuresFor "tests/crucible/phase7-crucible-gate-ci-wiring.nix" gateCiWiring [
      {
        label = "CI wiring expects fleet seam proof";
        needle = "checks.crucible.phase7.crucibleCasFleetRatchetSeam";
      }
      {
        label = "CI wiring expects fleet equivalence seam dependency";
        needle = "dependencies = [phase2.gates.singleVmFingerprint.rawGate e2eDeterminism.rawGate phase7.crucibleFleetStore phase7.crucibleSharedDagStore phase7.crucibleFrontierLeases phase7.crucibleFourLayerDedup phase7.crucibleDeterminismGuardrail phase7.crucibleCasFleetRatchetSeam];";
      }
    ]
    ++ failuresFor "tests/crucible/phase7-crucible-fleet-store.nix" fleetStoreGate [
      {
        label = "fleet-store guard expects seam dependency";
        needle = "phase7.crucibleCasFleetRatchetSeam";
      }
    ];
in
  if failures != []
  then throw "crucible phase7 CAS fleet ratchet seam check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase7-cas-fleet-ratchet-seam";
      version = "0";
      src = null;

      buildDeps = [pkgs.coreutils] ++ dependencies;

      phases = [
        {
          name = "write-result";
          script = ''
            set -eu
            mkdir -p "$out"
            cat > "$out/result" <<RESULT
            PASS
            check=${attrPath}
            tasks=${builtins.concatStringsSep "," taskIds}
            seam=crucible_store::dag-store
            shared_seam=SharedDagStore+InvalidationQuery::evaluate
            interface=DagStore::put,DagStore::get,DagStore::has,SharedDagStore,InvalidationQuery::evaluate
            merge_plan=thin-adapter-behind-unchanged-interface
            merge_bar=gate:content-address,gate:replay-oracle,gate:e2e-determinism
            standalone_from_rfc_0007=true
            no_rfc_0007_dependency=true
            RESULT
          '';
        }
      ];
    }

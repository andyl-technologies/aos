{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.crucibleCasFleetRatchetSeam",
  taskIds ? ["T-PKG-23"],
  dependencies ? [],
}: let
  packagingDoc = builtins.readFile ../../docs/rfcs/0010-crucible/26-packaging-aos-integration.md;
  dceDoc = builtins.readFile ../../docs/rfcs/0010-crucible/35-distributed-continuous-exploration.md;
  casSource = builtins.readFile ../../crates/crucible-cas/src/lib.rs;
  casManifest = builtins.readFile ../../crates/crucible-cas/Cargo.toml;
  defaultChecks = builtins.readFile ./default.nix;
  gateCiWiring = builtins.readFile ./phase7-crucible-gate-ci-wiring.nix;
  fleetStoreGate = builtins.readFile ./phase7-crucible-fleet-store.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/26-packaging-aos-integration.md" packagingDoc [
      {
        label = "T-PKG-23 completion note";
        needle = "Completed by `checks.crucible.phase7.crucibleCasFleetRatchetSeam`";
      }
      {
        label = "PKG-45 same seam text";
        needle = "fleet-visible store + dependency-gated invalidation as the SAME seam";
      }
    ]
    ++ forbiddenFor "docs/rfcs/0010-crucible/26-packaging-aos-integration.md" packagingDoc [
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/35-distributed-continuous-exploration.md" dceDoc [
      {
        label = "DCE same ratchet seam section";
        needle = "The fleet-visible content-addressed store is the **same seam**";
      }
      {
        label = "DCE no RFC-0007 dependency";
        needle = "documented text, not a";
      }
    ]
    ++ failuresFor "crates/crucible-cas/src/lib.rs" casSource [
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
        label = "shared seam constant";
        needle = "pub const FUTURE_RATCHET_SHARED_SEAM";
      }
      {
        label = "seam interface constant";
        needle = "pub const FUTURE_RATCHET_SEAM_INTERFACE";
      }
      {
        label = "shared seam includes SharedDagStore";
        needle = "SharedDagStore+InvalidationQuery::evaluate";
      }
      {
        label = "seam interface includes put";
        needle = "DagStore::put";
      }
      {
        label = "seam interface includes get";
        needle = "DagStore::get";
      }
      {
        label = "seam interface includes has";
        needle = "DagStore::has";
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
    ++ forbiddenFor "crates/crucible-cas/Cargo.toml" casManifest [
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
            seam=crucible-cas::dag-store
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

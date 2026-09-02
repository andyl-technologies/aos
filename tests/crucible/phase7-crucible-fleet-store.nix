{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.crucibleFleetStore",
  taskIds ? ["T-PKG-21"],
  dependencies ? [],
}: let
  packagingDoc = builtins.readFile ../../docs/rfcs/0010-crucible/26-packaging-aos-integration.md;
  casSource =
    builtins.readFile ../../crates/crucible-cas/src/lib.rs
    + builtins.readFile ../../crates/crucible-cas/src/cas/tests.rs;
  fleetStoreProbe = builtins.readFile ../../crates/crucible-cas/src/bin/crucible-fleet-store.rs;
  fleetStorePackage = builtins.readFile ../../pkgs/tools/crucible-fleet-store.nix;
  rootDefault = builtins.readFile ../../default.nix;
  defaultChecks = builtins.readFile ./default.nix;
  gateCiWiring = builtins.readFile ./phase7-crucible-gate-ci-wiring.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/26-packaging-aos-integration.md" packagingDoc [
      {
        label = "T-PKG-21 completion note";
        needle = "Completed by `checks.crucible.phase7.crucibleFleetStore`";
      }
      {
        label = "fleet store package name";
        needle = "`pkgs.crucible-fleet-store`";
      }
      {
        label = "distributed fleet surface name";
        needle = "`checks.fleet.crucible-distributed-continuous-exploration`";
      }
    ]
    ++ forbiddenFor "docs/rfcs/0010-crucible/26-packaging-aos-integration.md" packagingDoc [
    ]
    ++ failuresFor "crates/crucible-cas/src/lib.rs" casSource [
      {
        label = "shared store public type";
        needle = "pub struct SharedDagStore";
      }
      {
        label = "shared store dag implementation";
        needle = "impl DagStore for SharedDagStore";
      }
      {
        label = "shared store atomic publish";
        needle = "fs::hard_link(&temp_path, &path)";
      }
      {
        label = "shared store exclusive temp creation";
        needle = ".create_new(true)";
      }
      {
        label = "shared store idempotent publish conflict";
        needle = "io::ErrorKind::AlreadyExists";
      }
      {
        label = "shared store mismatch protection";
        needle = "CasError::ContentMismatch";
      }
      {
        label = "shared store identity test";
        needle = "shared_store_identity_is_location_independent";
      }
      {
        label = "shared store concurrent put test";
        needle = "shared_store_concurrent_put_is_idempotent";
      }
      {
        label = "shared store temp collision test";
        needle = "shared_store_temp_creation_skips_existing_collision";
      }
    ]
    ++ failuresFor "crates/crucible-cas/src/bin/crucible-fleet-store.rs" fleetStoreProbe [
      {
        label = "fleet store binary name";
        needle = "crucible-fleet-store";
      }
      {
        label = "probe command";
        needle = "\"probe\"";
      }
      {
        label = "probe actual concurrent put proof";
        needle = "prove_concurrent_put_idempotent";
      }
      {
        label = "probe concurrent writer count";
        needle = "const CONCURRENT_WRITERS: usize = 16;";
      }
      {
        label = "shared store backend";
        needle = "SharedDagStore";
      }
      {
        label = "DagStore interface output";
        needle = "interface=DagStore::put,DagStore::get,DagStore::has";
      }
      {
        label = "shared backend output";
        needle = "backend=SharedDagStore";
      }
      {
        label = "concurrent put output";
        needle = "concurrent_put=idempotent";
      }
      {
        label = "concurrent writer output";
        needle = "concurrent_writers={CONCURRENT_WRITERS}";
      }
      {
        label = "single object output";
        needle = "object_file_count={object_file_count}";
      }
    ]
    ++ failuresFor "pkgs/tools/crucible-fleet-store.nix" fleetStorePackage [
      {
        label = "AOS package name";
        needle = ''pname = "crucible-fleet-store";'';
      }
      {
        label = "Cargo package builder";
        needle = "mkCargoPackage";
      }
      {
        label = "vendored Cargo dependencies";
        needle = "fetchCargoVendor";
      }
      {
        label = "crucible-cas binary build";
        needle = ''cargoFlags = "-p crucible-cas --bin crucible-fleet-store";'';
      }
      {
        label = "crucible-cas package tests";
        needle = ''cargoTestFlags = "-p crucible-cas";'';
      }
      {
        label = "explicit AOS grep dependency";
        needle = "[buildPackages.grep]";
      }
      {
        label = "source build marker";
        needle = "aos_from_source=true";
      }
      {
        label = "fleet visibility marker";
        needle = "fleet_visible=true";
      }
      {
        label = "DCE shared store task marker";
        needle = "dce_task=T-DCE-1";
      }
    ]
    ++ forbiddenFor "pkgs/tools/crucible-fleet-store.nix" fleetStorePackage [
      {
        label = "host tool pattern";
        needle = "hostTools";
      }
      {
        label = "nixpkgs import";
        needle = "<nixpkgs>";
      }
      {
        label = "env shebang";
        needle = "/usr/bin/env";
      }
      {
        label = "host shell path";
        needle = "/bin/sh";
      }
      {
        label = "host bash path";
        needle = "/bin/bash";
      }
    ]
    ++ failuresFor "default.nix" rootDefault [
      {
        label = "fleet store check surface";
        needle = "crucible-distributed-continuous-exploration = let";
      }
      {
        label = "fleet store package input";
        needle = "fleetStore = pkgs.crucible-fleet-store;";
      }
      {
        label = "explorer package input";
        needle = "explorer = pkgs.crucible;";
      }
      {
        label = "source check input";
        needle = "fleetStoreGate = crucibleChecks.phase7.crucibleFleetStore;";
      }
      {
        label = "fleet store probe";
        needle = ''"''${fleetStore}/bin/crucible-fleet-store" probe "$probe_root"'';
      }
      {
        label = "shared DagStore source check input";
        needle = "sharedDagStoreGate = crucibleChecks.phase7.crucibleSharedDagStore;";
      }
      {
        label = "distributed search marker";
        needle = "distributed_search_surface=enabled";
      }
      {
        label = "continuous campaign marker";
        needle = "continuous_campaign_surface=enabled";
      }
      {
        label = "TCG-only marker";
        needle = "tcg_only=true";
      }
      {
        label = "no required system features marker";
        needle = "required_system_features=none";
      }
      {
        label = "no KVM marker";
        needle = "kvm_required=false";
      }
    ]
    ++ forbiddenFor "default.nix" rootDefault [
      {
        label = "KVM requirement on T-PKG-21 fleet surface";
        needle = ''requiredSystemFeatures = [ "kvm" ]'';
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase7 fleet store check imported";
        needle = "crucibleFleetStore = import ./phase7-crucible-fleet-store.nix";
      }
      {
        label = "phase7 shared DagStore check imported";
        needle = "crucibleSharedDagStore = import ./phase7-crucible-shared-dag-store.nix";
      }
      {
        label = "phase7 frontier leases check imported";
        needle = "crucibleFrontierLeases = import ./phase7-crucible-frontier-leases.nix";
      }
      {
        label = "fleet equivalence raw gate waits for fleet store package";
        needle = "dependencies = [phase2.gates.singleVmFingerprint.rawGate e2eDeterminism.rawGate phase7.crucibleFleetStore phase7.crucibleSharedDagStore phase7.crucibleFrontierLeases phase7.crucibleFourLayerDedup phase7.crucibleDeterminismGuardrail phase7.crucibleCasFleetRatchetSeam];";
      }
      {
        label = "fleet equivalence wrapper waits for fleet store package";
        needle = "dependencies = [phase2.gates.singleVmFingerprint e2eDeterminism phase7.crucibleFleetStore phase7.crucibleSharedDagStore phase7.crucibleFrontierLeases phase7.crucibleFourLayerDedup phase7.crucibleDeterminismGuardrail phase7.crucibleCasFleetRatchetSeam];";
      }
    ]
    ++ failuresFor "tests/crucible/phase7-crucible-gate-ci-wiring.nix" gateCiWiring [
      {
        label = "CI wiring expects distributed fleet surface";
        needle = "checks.fleet.crucible-distributed-continuous-exploration";
      }
      {
        label = "CI wiring expects fleet store package";
        needle = "pkgs.crucible-fleet-store";
      }
      {
        label = "CI wiring expects shared DagStore proof";
        needle = "checks.crucible.phase7.crucibleSharedDagStore";
      }
      {
        label = "CI wiring expects frontier lease proof";
        needle = "checks.crucible.phase7.crucibleFrontierLeases";
      }
      {
        label = "CI wiring expects TCG-only fleet store";
        needle = "tcg_only=true";
      }
    ];
in
  if failures != []
  then throw "crucible phase7 fleet store check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase7-fleet-store";
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
            package=pkgs.crucible-fleet-store
            fleet_check_surface=checks.fleet.crucible-distributed-continuous-exploration
            dag_store_backend=SharedDagStore
            explorer_closure=pkgs.crucible
            distributed_search_surface=enabled
            continuous_campaign_surface=enabled
            tcg_only=true
            required_system_features=none
            kvm_required=false
            RESULT
          '';
        }
      ];
    }

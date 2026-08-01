{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.crucibleSharedDagStore",
  taskIds ? ["T-DCE-1"],
  dependencies ? [],
}: let
  dceDoc = builtins.readFile ../../docs/rfcs/0010-crucible/35-distributed-continuous-exploration.md;
  casSource =
    builtins.readFile ../../crates/crucible-cas/src/lib.rs
    + builtins.readFile ../../crates/crucible-cas/src/cas/tests.rs;
  fleetStoreProbe = builtins.readFile ../../crates/crucible-cas/src/bin/crucible-fleet-store.rs;
  fleetStorePackage = builtins.readFile ../../pkgs/tools/crucible-fleet-store.nix;
  rootDefault = builtins.readFile ../../default.nix;
  defaultChecks = builtins.readFile ./default.nix;
  gateCiWiring = builtins.readFile ./phase7-crucible-gate-ci-wiring.nix;
  fleetStoreGate = builtins.readFile ./phase7-crucible-fleet-store.nix;
  fleetStore = pkgs.crucible-fleet-store;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  fleetEquivalenceRawDependency = "dependencies = [phase2.gates.singleVmFingerprint.rawGate e2eDeterminism.rawGate phase7.crucibleFleetStore phase7.crucibleSharedDagStore phase7.crucibleFrontierLeases phase7.crucibleFourLayerDedup phase7.crucibleDeterminismGuardrail phase7.crucibleCasFleetRatchetSeam];";
  fleetEquivalenceWrapperDependency = "dependencies = [phase2.gates.singleVmFingerprint e2eDeterminism phase7.crucibleFleetStore phase7.crucibleSharedDagStore phase7.crucibleFrontierLeases phase7.crucibleFourLayerDedup phase7.crucibleDeterminismGuardrail phase7.crucibleCasFleetRatchetSeam];";

  failures =
    failuresFor "docs/rfcs/0010-crucible/35-distributed-continuous-exploration.md" dceDoc [
      {
        label = "T-DCE-1 completion note";
        needle = "Completed by `checks.crucible.phase7.crucibleSharedDagStore`";
      }
      {
        label = "DCE-3 shared backend invariant";
        needle = "share a single content-addressed `DagStore` backend";
      }
      {
        label = "DCE-4 idempotent concurrent put invariant";
        needle = "idempotent, convergent\n  concurrent `put`";
      }
    ]
    ++ forbiddenFor "docs/rfcs/0010-crucible/35-distributed-continuous-exploration.md" dceDoc [
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
        label = "shared store hard-link publish";
        needle = "fs::hard_link(&temp_path, &path)";
      }
      {
        label = "shared store exclusive temp creation";
        needle = ".create_new(true)";
      }
      {
        label = "shared store already-exists convergence";
        needle = "io::ErrorKind::AlreadyExists";
      }
      {
        label = "shared store content mismatch guard";
        needle = "CasError::ContentMismatch";
      }
      {
        label = "location-independent identity test";
        needle = "shared_store_identity_is_location_independent";
      }
      {
        label = "concurrent put test";
        needle = "shared_store_concurrent_put_is_idempotent";
      }
    ]
    ++ failuresFor "crates/crucible-cas/src/bin/crucible-fleet-store.rs" fleetStoreProbe [
      {
        label = "probe location identity function";
        needle = "prove_location_independent_identity";
      }
      {
        label = "probe concurrent put function";
        needle = "prove_concurrent_put_idempotent";
      }
      {
        label = "probe concurrent writer count";
        needle = "const CONCURRENT_WRITERS: usize = 16;";
      }
      {
        label = "probe spawns concurrent writers";
        needle = "thread::spawn";
      }
      {
        label = "probe start barrier";
        needle = "Barrier::new(CONCURRENT_WRITERS)";
      }
      {
        label = "probe waits at barrier";
        needle = "start.wait();";
      }
      {
        label = "probe validates one shared object";
        needle = "object_file_count != 1";
      }
      {
        label = "probe reports root count";
        needle = "location_independent_roots=2";
      }
      {
        label = "probe reports writer count";
        needle = "concurrent_writers={CONCURRENT_WRITERS}";
      }
      {
        label = "probe reports object count";
        needle = "object_file_count={object_file_count}";
      }
    ]
    ++ failuresFor "pkgs/tools/crucible-fleet-store.nix" fleetStorePackage [
      {
        label = "package validates root count";
        needle = "grep -q '^location_independent_roots=2$'";
      }
      {
        label = "package validates writer count";
        needle = "grep -q '^concurrent_writers=16$'";
      }
      {
        label = "package validates object count";
        needle = "grep -q '^object_file_count=1$'";
      }
      {
        label = "package records DCE task";
        needle = "dce_task=T-DCE-1";
      }
      {
        label = "package records shared store proof";
        needle = "shared_dag_store_proof=location-independent-identity,idempotent-concurrent-put";
      }
    ]
    ++ failuresFor "default.nix" rootDefault [
      {
        label = "distributed wrapper consumes shared DagStore gate";
        needle = "sharedDagStoreGate = crucibleChecks.phase7.crucibleSharedDagStore;";
      }
      {
        label = "distributed wrapper checks shared DagStore result";
        needle = ''shared_dag_store_result="''${sharedDagStoreGate}/result"'';
      }
      {
        label = "distributed wrapper records shared DagStore source check";
        needle = "source_check=checks.crucible.phase7.crucibleSharedDagStore";
      }
      {
        label = "distributed wrapper records package check";
        needle = "package_check=checks.crucible.phase7.crucibleFleetStore";
      }
      {
        label = "distributed wrapper records shared backend";
        needle = "shared_store_backend=SharedDagStore";
      }
      {
        label = "distributed wrapper records writer count";
        needle = "concurrent_writers=16";
      }
      {
        label = "distributed wrapper records object count";
        needle = "object_file_count=1";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase7 shared DagStore check imported";
        needle = "crucibleSharedDagStore = import ./phase7-crucible-shared-dag-store.nix";
      }
      {
        label = "fleet equivalence raw gate waits for shared DagStore proof";
        needle = fleetEquivalenceRawDependency;
      }
      {
        label = "fleet equivalence wrapper waits for shared DagStore proof";
        needle = fleetEquivalenceWrapperDependency;
      }
    ]
    ++ failuresFor "tests/crucible/phase7-crucible-gate-ci-wiring.nix" gateCiWiring [
      {
        label = "CI wiring expects shared DagStore check";
        needle = "checks.crucible.phase7.crucibleSharedDagStore";
      }
      {
        label = "CI wiring expects shared DagStore raw dependency";
        needle = fleetEquivalenceRawDependency;
      }
      {
        label = "CI wiring expects shared DagStore wrapper dependency";
        needle = fleetEquivalenceWrapperDependency;
      }
    ]
    ++ failuresFor "tests/crucible/phase7-crucible-fleet-store.nix" fleetStoreGate [
      {
        label = "fleet-store guard expects shared DagStore gate";
        needle = "phase7.crucibleSharedDagStore";
      }
    ];
in
  if failures != []
  then throw "crucible phase7 shared DagStore check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase7-shared-dag-store";
      version = "0";
      src = null;

      buildDeps = [pkgs.coreutils pkgs.grep fleetStore] ++ dependencies;

      phases = [
        {
          name = "probe-shared-dag-store";
          script = ''
            set -eu
            probe_root="$TMPDIR/crucible-shared-dag-store"
            "${fleetStore}/bin/crucible-fleet-store" probe "$probe_root" > "$TMPDIR/crucible-shared-dag-store.probe"
            grep -q '^backend=SharedDagStore$' "$TMPDIR/crucible-shared-dag-store.probe"
            grep -q '^interface=DagStore::put,DagStore::get,DagStore::has$' "$TMPDIR/crucible-shared-dag-store.probe"
            grep -q '^location_independent_identity=true$' "$TMPDIR/crucible-shared-dag-store.probe"
            grep -q '^location_independent_roots=2$' "$TMPDIR/crucible-shared-dag-store.probe"
            grep -q '^concurrent_put=idempotent$' "$TMPDIR/crucible-shared-dag-store.probe"
            grep -q '^concurrent_writers=16$' "$TMPDIR/crucible-shared-dag-store.probe"
            grep -q '^object_file_count=1$' "$TMPDIR/crucible-shared-dag-store.probe"

            mkdir -p "$out"
            cat > "$out/result" <<RESULT
            PASS
            check=${attrPath}
            tasks=${builtins.concatStringsSep "," taskIds}
            fleet_store_component=${fleetStore}
            runtime_probe=crucible-fleet-store probe
            shared_store_backend=SharedDagStore
            interface=DagStore::put,DagStore::get,DagStore::has
            location_independent_identity=true
            location_independent_roots=2
            concurrent_put=idempotent
            concurrent_writers=16
            object_file_count=1
            gate_dependency=checks.crucible.phase7.gates.fleetEquivalence
            RESULT
          '';
        }
      ];
    }

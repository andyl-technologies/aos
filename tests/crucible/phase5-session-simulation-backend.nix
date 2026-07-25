{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.sessionSimulationBackend",
  taskIds ? [],
  openTaskIds ? ["T-SESS-11"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  backendLib = builtins.readFile ../../crates/crucible/src/backend.rs;
  crucibleShmemLib =
    builtins.readFile ../../crates/crucible-shmem/src/lib.rs
    + builtins.readFile ../../crates/crucible-shmem/src/shmem/frame_node.rs
    + builtins.readFile ../../crates/crucible-shmem/src/shmem/region.rs
    + builtins.readFile ../../crates/crucible-shmem/src/shmem/ring_coverage.rs;
  crucibleLib = builtins.readFile ../../crates/crucible/src/lib.rs;
  simBackendLib = builtins.readFile ../../crates/crucible/src/sim_backend.rs;
  qemuNodeLib = builtins.readFile ../../crates/crucible-qemu/src/node.rs;
  sessionDoc = builtins.readFile ../../docs/rfcs/0010-crucible/20-session-control-plane.md;
  planDoc = builtins.readFile ../../docs/rfcs/0010-crucible/32-implementation-plan.md;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;
  openTaskList = builtins.concatStringsSep "," openTaskIds;

  hasInfix = needle: haystack: let
    needleLen = builtins.stringLength needle;
    haystackLen = builtins.stringLength haystack;
    maxStart = haystackLen - needleLen;
    indexes =
      if needleLen == 0
      then [0]
      else if maxStart < 0
      then []
      else builtins.genList (index: index) (maxStart + 1);
  in
    builtins.any (index:
      builtins.substring index needleLen haystack == needle)
    indexes;

  failuresFor = fileLabel: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (!(hasInfix requirement.needle content)) [
          "${fileLabel}: missing ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;

  failures =
    failuresFor "docs/rfcs/0010-crucible/20-session-control-plane.md" sessionDoc [
      {
        label = "T-SESS-11 remains open";
        needle = "- [ ] **T-SESS-11**";
      }
      {
        label = "T-SESS-11 partial-evidence note";
        needle = "Partial evidence under `checks.crucible.phase5.sessionSimulationBackend`";
      }
      {
        label = "synchronous SimulationBackend sketch";
        needle = "pub trait SimulationBackend {";
      }
      {
        label = "actor-owned non-Send backend sketch";
        needle = "no `Send` bound is required";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "phase5 simulation backend status note";
        needle = "`T-SESS-11` has partial evidence through `checks.crucible.phase5.sessionSimulationBackend`";
      }
    ]
    ++ failuresFor "crates/crucible/src/backend.rs" backendLib [
      {
        label = "simulation backend trait";
        needle = "pub trait SimulationBackend";
      }
      {
        label = "scheduler-supplied step method";
        needle = "fn step_to(&mut self, ceiling: VirtualTime) -> Result<StepObservation, BackendError>;";
      }
      {
        label = "scheduler-boundary apply method";
        needle = "fn apply(&mut self, effect: &BackendEffect, at: VirtualTime) -> Result<(), BackendError>;";
      }
      {
        label = "backend snapshot method";
        needle = "fn snapshot(&mut self) -> Result<BackendSnapshot, BackendError>;";
      }
      {
        label = "backend restore method";
        needle = "fn restore(&mut self, snapshot: &BackendSnapshot) -> Result<(), BackendError>;";
      }
      {
        label = "scheduler-mirrored now method";
        needle = "fn now(&self) -> VirtualTime;";
      }
      {
        label = "node fingerprint method";
        needle = "fn fingerprint(&mut self, node: NodeId) -> Result<FingerprintSample, BackendError>;";
      }
      {
        label = "backend shutdown method";
        needle = "fn shutdown(&mut self) -> Result<(), BackendError>;";
      }
      {
        label = "step observation type";
        needle = "pub struct StepObservation";
      }
      {
        label = "backend effect type";
        needle = "pub enum BackendEffect";
      }
      {
        label = "backend snapshot type";
        needle = "pub struct BackendSnapshot";
      }
      {
        label = "fingerprint sample type";
        needle = "pub struct FingerprintSample";
      }
      {
        label = "mock simulation backend";
        needle = "pub struct MockSimulationBackend";
      }
      {
        label = "mock simulation backend implementation";
        needle = "impl SimulationBackend for MockSimulationBackend";
      }
      {
        label = "object-safe mock dispatch test";
        needle = "simulation_backend_trait_is_object_safe_and_scheduler_timed";
      }
      {
        label = "scheduler timing rejection test";
        needle = "mock_simulation_backend_rejects_backend_owned_time_regression";
      }
    ]
    ++ failuresFor "crates/crucible-shmem/src/lib.rs" crucibleShmemLib [
      {
        label = "region header clone for model snapshots";
        needle = "impl Clone for RegionHeader";
      }
      {
        label = "region allocation clone for SimDouble snapshots";
        needle = "impl Clone for RegionAllocation";
      }
      {
        label = "ring header clone for model snapshots";
        needle = "impl Clone for RingHeader";
      }
      {
        label = "node slot clone for model snapshots";
        needle = "impl Clone for NodeSlot";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" crucibleLib [
      {
        label = "public backend effect export";
        needle = "BackendEffect";
      }
      {
        label = "public backend snapshot export";
        needle = "BackendSnapshot";
      }
      {
        label = "public fingerprint sample export";
        needle = "FingerprintSample";
      }
      {
        label = "public mock backend export";
        needle = "MockSimulationBackend";
      }
      {
        label = "public simulation trait export";
        needle = "SimulationBackend";
      }
      {
        label = "public step observation export";
        needle = "StepObservation";
      }
    ]
    ++ failuresFor "crates/crucible/src/sim_backend.rs" simBackendLib [
      {
        label = "SimBackend implementation";
        needle = "impl SimulationBackend for SimBackend";
      }
      {
        label = "SimDouble implementation";
        needle = "impl SimulationBackend for SimDouble";
      }
      {
        label = "full SimDouble snapshot cache";
        needle = "snapshots: BTreeMap<ContentHash, SimDoubleSnapshotState>";
      }
      {
        label = "SimDouble snapshot state";
        needle = "struct SimDoubleSnapshotState";
      }
      {
        label = "SimDouble full-state restore";
        needle = "fn restore_snapshot_state(&mut self, state: &SimDoubleSnapshotState)";
      }
      {
        label = "scheduler send authorizer rejection for trait stepping";
        needle = "struct RejectingSimulationBackendSends;";
      }
      {
        label = "trait stepping cannot authorize cross-node sends";
        needle = "lacks scheduler send authorization";
      }
      {
        label = "SimDouble scheduler-time effect guard";
        needle = "sim double backend effect at";
      }
      {
        label = "SimBackend trait test";
        needle = "sim_backend_satisfies_simulation_backend_trait";
      }
      {
        label = "SimDouble trait test";
        needle = "sim_double_satisfies_simulation_backend_trait";
      }
      {
        label = "SimDouble unauthorized outbound test";
        needle = "sim_double_simulation_backend_rejects_outbound_without_scheduler_authorization";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/node.rs" qemuNodeLib [
      {
        label = "QEMU implementation";
        needle = "impl SimulationBackend for QemuNode";
      }
      {
        label = "QEMU observed virtual time mirror";
        needle = "last_observed_time: VirtualTime";
      }
      {
        label = "QEMU snapshot stamps virtual time mirror";
        needle = "checkpoint.virtual_time = self.last_observed_time";
      }
      {
        label = "QEMU restore resets virtual time mirror";
        needle = "self.last_observed_time = checkpoint.virtual_time";
      }
      {
        label = "QEMU scheduler-time effect guard";
        needle = "qemu backend effect at";
      }
      {
        label = "QEMU advance outcome time mirror";
        needle = "virtual_time_from_advance_outcome";
      }
      {
        label = "QEMU trait test";
        needle = "qemu_node_satisfies_simulation_backend_trait";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase5 exposes session simulation backend check";
        needle = "sessionSimulationBackend = import ./phase5-session-simulation-backend.nix";
      }
      {
        label = "phase5 simulation backend attr path";
        needle = ''attrPath = "checks.crucible.phase5.sessionSimulationBackend"'';
      }
      {
        label = "phase5 simulation backend open task id";
        needle = ''openTaskIds = ["T-SESS-11"]'';
      }
      {
        label = "phase5 simulation backend depends on lock-free observation";
        needle = "dependencies = [phase5.sessionLockFreeObservation]";
      }
    ];
in
  if failures != []
  then throw "crucible phase5 session-simulation-backend check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase5-session-simulation-backend";
      version = "0";
      src = crucibleSrc;

      buildDeps =
        [
          pkgs.coreutils
          pkgs.rust
          pkgs.sed
        ]
        ++ dependencies;

      phases = [
        {
          name = "unpack";
          script = ''
            cp -R "$src" source
            chmod -R u+w source
            cd source
          '';
        }
        {
          name = "configure";
          script = ''
            export CARGO_HOME="$TMPDIR/cargo"
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            mkdir -p "$CARGO_HOME" .cargo
            if [ -f "${cargoDeps}/.cargo/config.toml" ]; then
              sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
                > .cargo/config.toml
            else
              printf '[source.crates-io]\nreplace-with = "vendored-sources"\n\n[source.vendored-sources]\ndirectory = "${cargoDeps}"\n\n' \
                > .cargo/config.toml
            fi
          '';
        }
        {
          name = "run-session-simulation-backend";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-session-simulation-backend-target" \
              -p crucible \
              --features test-double \
              simulation_backend \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-session-simulation-backend-target" \
              -p crucible-qemu \
              --lib \
              qemu_node_satisfies_simulation_backend_trait \
              -- --test-threads=1
          '';
        }
        {
          name = "write-result";
          script = ''
            set -eu
            mkdir -p "$out"
            cat > "$out/result" <<'RESULT'
            PASS
            check=${attrPath}
            tasks=${taskList}
            open_tasks=${openTaskList}
            status=partial
            component=crucible-session
            backend_trait=SimulationBackend
            timing_source=scheduler
            implementations=mock,sim-backend,sim-double,qemu-node
            RESULT
          '';
        }
      ];
    }

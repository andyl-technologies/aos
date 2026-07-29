{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase3.schedulerAllVcpusIdle",
  taskIds ? ["T-SCHED-30"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  libSource = builtins.readFile ../../crates/crucible/src/lib.rs;
  focusedTest = builtins.readFile ../../crates/crucible/tests/scheduler_all_vcpus_idle.rs;
  schedulingDoc = builtins.readFile ../../docs/rfcs/0010-crucible/08-scheduling.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;



  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/08-scheduling.md" schedulingDoc [
      {
        label = "T-SCHED-30 checked off";
        needle = "- [x] **T-SCHED-30**";
      }
      {
        label = "T-SCHED-30 completion note";
        needle = "Completed by `checks.crucible.phase3.schedulerAllVcpusIdle`";
      }
      {
        label = "all-vCPUs-idle note";
        needle = "all vCPUs are halted, timer-free, and input-free";
      }
      {
        label = "exact vCPU coverage note";
        needle = "exact contiguous coverage of every vCPU in `0..N`";
      }
      {
        label = "minimum vCPU deadline note";
        needle = "minimum per-vCPU deadline";
      }
      {
        label = "node-level projection note";
        needle = "one scheduler node candidate";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "vCPU idle state type";
        needle = "pub struct SchedulerVcpuIdleState";
      }
      {
        label = "node vCPU snapshot type";
        needle = "pub struct SchedulerNodeVcpuIdleSnapshot";
      }
      {
        label = "scenario snapshot queue";
        needle = "pub vcpu_idle_snapshots: Vec<SchedulerNodeVcpuIdleSnapshot>";
      }
      {
        label = "scenario snapshot builder";
        needle = "with_vcpu_idle_snapshot";
      }
      {
        label = "scenario material includes snapshots";
        needle = "vcpu_idle_snapshots={}";
      }
      {
        label = "scenario material includes vCPU count";
        needle = "vcpu_count={}";
      }
      {
        label = "snapshot validates all vCPUs";
        needle = "must cover all";
      }
      {
        label = "snapshot validates contiguous vCPUs";
        needle = "contiguous vCPUs";
      }
      {
        label = "RR policy count cross-check";
        needle = "does not match RR policy";
      }
      {
        label = "active vCPU blocker";
        needle = "ActiveVcpu";
      }
      {
        label = "pending vCPU timer blocker";
        needle = "PendingVcpuTimer";
      }
      {
        label = "pending vCPU input blocker";
        needle = "PendingVcpuInput";
      }
      {
        label = "effective activity helper";
        needle = "effective_node_activity";
      }
      {
        label = "effective exact-local helper";
        needle = "effective_exact_local_event";
      }
      {
        label = "earliest vCPU deadline helper";
        needle = "earliest_vcpu_deadline";
      }
      {
        label = "due vCPU timer clearing";
        needle = "state.next_deadline = None";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "vCPU idle state exported";
        needle = "SchedulerVcpuIdleState";
      }
      {
        label = "node vCPU snapshot exported";
        needle = "SchedulerNodeVcpuIdleSnapshot";
      }
    ]
    ++ failuresFor "crates/crucible/tests/scheduler_all_vcpus_idle.rs" focusedTest [
      {
        label = "focused all-vCPUs-idle test";
        needle = "all-vCPUs-idle quiescence";
      }
      {
        label = "terminal quiescence test";
        needle = "all_vcpus_halted_without_timer_or_input_are_quiescent";
      }
      {
        label = "active vCPU blocker test";
        needle = "active_vcpu_prevents_idle_and_uses_one_node_level_projection";
      }
      {
        label = "pending input blocker test";
        needle = "pending_vcpu_input_prevents_idle_even_when_all_vcpus_are_halted";
      }
      {
        label = "minimum deadline test";
        needle = "node_idle_wake_uses_minimum_vcpu_deadline_and_clears_due_timer";
      }
      {
        label = "liveness drain test";
        needle = "liveness_drains_all_vcpu_deadlines_before_terminal_quiescence";
      }
      {
        label = "validation test";
        needle = "vcpu_idle_snapshot_rejects_duplicate_vcpu_indices";
      }
      {
        label = "missing coverage validation test";
        needle = "vcpu_idle_snapshot_rejects_missing_vcpu_coverage";
      }
      {
        label = "RR policy mismatch validation test";
        needle = "vcpu_idle_snapshot_count_must_match_rr_subdivision_policy";
      }
      {
        label = "identity test";
        needle = "vcpu_idle_snapshot_participates_in_configuration_identity";
      }
      {
        label = "node-level publication assertion";
        needle = "scheduler.run_ceiling_publications().len(), 1";
      }
      {
        label = "minimum deadline assertion";
        needle = "SimInstant { nanos: 7 }";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/scheduler_all_vcpus_idle.rs" focusedTest [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
      {
        label = "pending placeholder";
        needle = "todo!";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase3 exposes scheduler all-vCPUs-idle check";
        needle = "schedulerAllVcpusIdle = import ./phase3-scheduler-all-vcpus-idle.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase3 scheduler all-vCPUs-idle check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase3-scheduler-all-vcpus-idle";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
        pkgs.coreutils
        pkgs.rust
        pkgs.sed
      ];

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
          name = "run-scheduler-all-vcpus-idle";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-scheduler-all-vcpus-idle-target" \
              -p crucible \
              --test scheduler_all_vcpus_idle \
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
            component=crucible-scheduler
            gate=gate:scheduler-liveness,gate:single-vm-fingerprint
            all_vcpus_idle_quiescence=true
            node_level_idle_wake_projection=true
            RESULT
          '';
        }
      ];
    }

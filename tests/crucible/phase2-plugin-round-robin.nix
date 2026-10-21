{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuPluginRoundRobin",
  taskIds ? [],
  openTaskIds ? ["T-PLUG-24"],
}: let
  inherit (import ./_test-gate.nix {inherit pkgs lib;}) mkCrucibleTestGate;

  pluginLib = builtins.readFile ../../crates/crucible-qemu-plugin/src/lib.rs;
  pluginRoundRobin = builtins.readFile ../../crates/crucible-qemu-plugin/src/round_robin.rs;
  pluginDeadline = builtins.readFile ../../crates/crucible-qemu-plugin/src/deadline.rs;
  pluginIdleLoop = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-qemu-plugin/src/idle_loop.rs;
  };
  pluginSpec = builtins.readFile ../../docs/rfcs/0010-crucible/12-qemu-plugin.md;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;
  openTaskList = builtins.concatStringsSep "," openTaskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/12-qemu-plugin.md" pluginSpec [
      {
        label = "single-threaded RR TCG obligation";
        needle = "single-threaded round-robin TCG";
      }
      {
        label = "fixed RR quantum wording";
        needle = "fixed, content-addressed `rr_switch_quantum`";
      }
      {
        label = "fixed ascending rotation wording";
        needle = "fixed ascending rotation";
      }
      {
        label = "all halted predicate wording";
        needle = "only when every vCPU is halted";
      }
      {
        label = "minimum over vCPUs wording";
        needle = "minimum over all vCPUs";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/lib.rs" pluginLib [
      {
        label = "round-robin module exported";
        needle = "pub mod round_robin;";
      }
      {
        label = "round-robin API re-exported";
        needle = "RoundRobinRunState";
      }
      {
        label = "round-robin module map";
        needle = "`round_robin` owns fixed-quantum vCPU rotation and per-vCPU halt tracking";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/round_robin.rs" pluginRoundRobin [
      {
        label = "validated RR config";
        needle = "pub struct RoundRobinConfig";
      }
      {
        label = "fixed quantum API";
        needle = "pub const fn rr_switch_quantum";
      }
      {
        label = "ascending next-vCPU API";
        needle = "pub const fn next_vcpu";
      }
      {
        label = "RUN cursor";
        needle = "pub struct RoundRobinRunState";
      }
      {
        label = "quantum retirement";
        needle = "pub fn retire";
      }
      {
        label = "halted current vCPU skip";
        needle = "pub fn advance_past_halted_current";
      }
      {
        label = "wrong vCPU fail-loud error";
        needle = "WrongCurrentVcpu";
      }
      {
        label = "quantum overrun fail-loud error";
        needle = "QuantumOverrun";
      }
      {
        label = "vCPU count mismatch fail-loud error";
        needle = "VcpuCountMismatch";
      }
      {
        label = "per-vCPU halt tracker";
        needle = "pub struct VcpuHaltTracker";
      }
      {
        label = "halt transition API";
        needle = "pub fn mark_halted";
      }
      {
        label = "resume/preemption transition API";
        needle = "pub fn mark_running";
      }
      {
        label = "next runnable vCPU scan";
        needle = "pub fn next_running_after";
      }
      {
        label = "all halted predicate";
        needle = "pub fn all_halted";
      }
      {
        label = "all halted wake plan API";
        needle = "pub fn compute_all_halted_idle_wake_plan";
      }
      {
        label = "deadline reducer use";
        needle = "aggregate_multi_vcpu_deadline";
      }
      {
        label = "idle wake plan reuse";
        needle = "compute_idle_wake_plan";
      }
      {
        label = "fixed quantum rotation test";
        needle = "round_robin_run_uses_fixed_quantum_and_ascending_rotation";
      }
      {
        label = "wrong vCPU and overrun test";
        needle = "round_robin_rejects_wrong_vcpu_and_quantum_overrun";
      }
      {
        label = "halted current vCPU skip test";
        needle = "halted_current_vcpu_yields_to_next_running_vcpu_without_node_idle";
      }
      {
        label = "halt tracker test";
        needle = "vcpu_halt_tracker_requires_every_vcpu_before_node_idle";
      }
      {
        label = "all-halted min deadline test";
        needle = "all_halted_idle_wake_uses_minimum_per_vcpu_deadline";
      }
      {
        label = "complete deadline validation test";
        needle = "all_halted_idle_wake_validates_complete_deadline_reports";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/deadline.rs" pluginDeadline [
      {
        label = "per-vCPU deadline report";
        needle = "pub struct PerVcpuDeadlineReport";
      }
      {
        label = "multi-vCPU minimum reducer";
        needle = "pub fn aggregate_multi_vcpu_deadline";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/idle_loop module" pluginIdleLoop [
      {
        label = "shared idle wake planner";
        needle = "pub fn compute_idle_wake_plan";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes plugin round-robin check";
        needle = "qemuPluginRoundRobin = import ./phase2-plugin-round-robin.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase2 plugin round-robin check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    mkCrucibleTestGate {
      pname = "crucible-phase2-plugin-round-robin";

      buildDeps = [
        pkgs.sed
      ];

      phases = [
        {
          name = "run-plugin-round-robin";
          script = ''
            set -eu

            # Every required test must be listed exactly once by the plugin's
            # test targets, and all of them run in one exact libtest
            # invocation that reports exactly that many passes.
            crucible-exact-tests -p crucible-qemu-plugin -- --test-threads=1 \
              round_robin::tests::round_robin_run_uses_fixed_quantum_and_ascending_rotation \
              round_robin::tests::round_robin_rejects_wrong_vcpu_and_quantum_overrun \
              round_robin::tests::halted_current_vcpu_yields_to_next_running_vcpu_without_node_idle \
              round_robin::tests::vcpu_halt_tracker_requires_every_vcpu_before_node_idle \
              round_robin::tests::all_halted_idle_wake_uses_minimum_per_vcpu_deadline \
              round_robin::tests::all_halted_idle_wake_validates_complete_deadline_reports
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
            rr_switch_quantum=fixed-retired-instructions
            vcpu_rotation=fixed-ascending
            halt_tracking=per-vcpu-all-halted
            idle_wake_icount=min-armed-vcpu-deadline
            RESULT
          '';
        }
      ];
    }

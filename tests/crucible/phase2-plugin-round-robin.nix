{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuPluginRoundRobin",
  taskIds ? ["T-PLUG-24"],
  openTaskIds ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

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
    pkgs.mkDerivation {
      pname = "crucible-phase2-plugin-round-robin";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
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
          name = "run-plugin-round-robin";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi

            target_dir="$TMPDIR/crucible-plugin-round-robin-target"
            run_exact_test() {
              filter="$1"
              expected="$2"
              list_file="$TMPDIR/test-list"
              output_file="$TMPDIR/test-output"

              cargo test \
                --frozen \
                --offline \
                --target-dir "$target_dir" \
                --manifest-path crates/Cargo.toml \
                -p crucible-qemu-plugin \
                "$filter" \
                -- --list > "$list_file"
              if [ "$(grep -Fx "$expected: test" "$list_file" | wc -l | tr -d ' ')" != 1 ]; then
                echo "expected exactly one listed test: $expected" >&2
                cat "$list_file" >&2
                exit 1
              fi

              cargo test \
                --frozen \
                --offline \
                --target-dir "$target_dir" \
                --manifest-path crates/Cargo.toml \
                -p crucible-qemu-plugin \
                "$filter" \
                -- --exact --test-threads=1 > "$output_file"
              if ! grep -q 'test result: ok. 1 passed;' "$output_file"; then
                echo "expected exactly one passed test: $expected" >&2
                cat "$output_file" >&2
                exit 1
              fi
            }

            run_exact_test \
              round_robin::tests::round_robin_run_uses_fixed_quantum_and_ascending_rotation \
              round_robin::tests::round_robin_run_uses_fixed_quantum_and_ascending_rotation
            run_exact_test \
              round_robin::tests::round_robin_rejects_wrong_vcpu_and_quantum_overrun \
              round_robin::tests::round_robin_rejects_wrong_vcpu_and_quantum_overrun
            run_exact_test \
              round_robin::tests::halted_current_vcpu_yields_to_next_running_vcpu_without_node_idle \
              round_robin::tests::halted_current_vcpu_yields_to_next_running_vcpu_without_node_idle
            run_exact_test \
              round_robin::tests::vcpu_halt_tracker_requires_every_vcpu_before_node_idle \
              round_robin::tests::vcpu_halt_tracker_requires_every_vcpu_before_node_idle
            run_exact_test \
              round_robin::tests::all_halted_idle_wake_uses_minimum_per_vcpu_deadline \
              round_robin::tests::all_halted_idle_wake_uses_minimum_per_vcpu_deadline
            run_exact_test \
              round_robin::tests::all_halted_idle_wake_validates_complete_deadline_reports \
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
            rr_switch_quantum=fixed-node-icount
            vcpu_rotation=fixed-ascending
            halt_tracking=per-vcpu-all-halted
            idle_wake_icount=min-armed-vcpu-deadline
            RESULT
          '';
        }
      ];
    }

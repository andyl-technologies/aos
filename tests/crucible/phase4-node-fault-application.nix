{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.nodeFaultApplication",
  taskIds ? ["T-FAULT-7"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-6Ig56XHLaW8Ow70BXh/oVSblxDoU4dkK5XqZJmd2RUw=";
  };

  nodeFault = builtins.readFile ../../crates/crucible/src/node_fault.rs;
  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  libSource = builtins.readFile ../../crates/crucible/src/lib.rs;
  faultTest = builtins.readFile ../../crates/crucible/tests/node_fault_application.rs;
  faultDoc = builtins.readFile ../../docs/rfcs/0010-crucible/17-fault-injection.md;
  defaultChecks = builtins.readFile ./default.nix;

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

  forbiddenFor = fileLabel: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (hasInfix requirement.needle content) [
          "${fileLabel}: forbidden ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/17-fault-injection.md" faultDoc [
      {
        label = "T-FAULT-7 checked off";
        needle = "- [x] **T-FAULT-7**";
      }
      {
        label = "T-FAULT-7 completion note";
        needle = "Completed by `checks.crucible.phase4.nodeFaultApplication`";
      }
    ]
    ++ failuresFor "crates/crucible/src/node_fault.rs" nodeFault [
      {
        label = "timing fault state";
        needle = "pub struct NodeTimingFaults";
      }
      {
        label = "anchored slowdown counter";
        needle = "pub anchor_counter: NodeCounter";
      }
      {
        label = "anchored slowdown time";
        needle = "pub anchor_time: SimInstant";
      }
      {
        label = "faulted VM projection";
        needle = "pub fn faulted_virtual_time";
      }
      {
        label = "slowed ceiling inverse";
        needle = "pub fn counter_for_faulted_virtual_time_ceil";
      }
      {
        label = "guest visible projection";
        needle = "guest_visible_time";
      }
      {
        label = "integer slowdown denominator";
        needle = "FaultSlowdownFactorBasisPoints::ONE.basis_points()";
      }
      {
        label = "combined node timing lowering";
        needle = "pub fn node_timing_faults_from_combined_node";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "runtime node timing state";
        needle = "timing_faults: NodeTimingFaults";
      }
      {
        label = "scheduler node timing application method";
        needle = "pub fn apply_combined_node_timing_faults";
      }
      {
        label = "scheduler bridge function";
        needle = "pub fn apply_combined_node_timing_faults_to_scheduler";
      }
      {
        label = "guest-visible clock read";
        needle = "pub fn guest_visible_time_for_node";
      }
      {
        label = "fault-aware current time";
        needle = "fn node_current_time";
      }
      {
        label = "fault-aware run ceiling inverse";
        needle = "fn node_counter_for_time_ceil";
      }
      {
        label = "fault-aware frontier";
        needle = ".faulted_virtual_time(node.counter, shift)?";
      }
      {
        label = "fault-aware concurrent completion";
        needle = "key = min_instant(key, preemption.virtual_time)";
      }
      {
        label = "preemption application virtual time";
        needle = "pub virtual_time: SimInstant";
      }
      {
        label = "fault-aware I/O completion stamp";
        needle = "let instant = self.vm_delivery_time_for_icount(";
      }
      {
        label = "fault-aware device fault decisions";
        needle = "fn project_device_decisions_for_vm_time";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "node fault module";
        needle = "pub mod node_fault";
      }
      {
        label = "timing state export";
        needle = "NodeTimingFaults";
      }
      {
        label = "timing projection export";
        needle = "NodeTimingProjection";
      }
      {
        label = "scheduler timing application export";
        needle = "apply_combined_node_timing_faults_to_scheduler";
      }
    ]
    ++ failuresFor "crates/crucible/tests/node_fault_application.rs" faultTest [
      {
        label = "anchored slow projection test";
        needle = "slow_projection_anchors_at_activation_without_rewinding_time";
      }
      {
        label = "scheduler slow run ceiling test";
        needle = "slow_fault_stretches_scheduler_run_ceiling_without_changing_counters";
      }
      {
        label = "clock-skew scheduler-axis test";
        needle = "clock_skew_offsets_guest_time_without_moving_scheduler_axis";
      }
      {
        label = "slowed preemption event time test";
        needle = "slowed_preemption_event_time_uses_faulted_virtual_projection";
      }
      {
        label = "slowed I/O completion event key test";
        needle = "slowed_device_completion_event_key_uses_faulted_virtual_projection";
      }
      {
        label = "bridge function covered";
        needle = "apply_combined_node_timing_faults_to_scheduler";
      }
      {
        label = "slow ceiling assertion";
        needle = "ceiling.max_advance_icount, 30";
      }
      {
        label = "clock skew ceiling assertion";
        needle = "ceiling.max_advance_icount, 50";
      }
      {
        label = "preemption event-log timestamp assertion";
        needle = "VirtualTime { ticks: 15 }";
      }
      {
        label = "I/O completion event-key timestamp assertion";
        needle = "VirtualTime { ticks: 514 }";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 node fault application import";
        needle = "nodeFaultApplication = import ./phase4-node-fault-application.nix";
      }
      {
        label = "phase4 node fault application attr path";
        needle = "attrPath = \"checks.crucible.phase4.nodeFaultApplication\"";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/node_fault_application.rs" faultTest [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
      {
        label = "unfinished todo";
        needle = "todo!";
      }
      {
        label = "unfinished unimplemented";
        needle = "unimplemented!";
      }
    ];
in
  if failures != []
  then throw "crucible phase4 node-fault-application check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-node-fault-application";
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
          name = "run-node-fault-application";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-node-fault-application-target" \
              -p crucible \
              --test node_fault_application \
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
            slow=anchored-counter-to-virtual-time
            clock_skew=guest-visible-only
            RESULT
          '';
        }
      ];
    }

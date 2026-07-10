{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.nodeCrashApplication",
  taskIds ? ["T-FAULT-8"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-6Ig56XHLaW8Ow70BXh/oVSblxDoU4dkK5XqZJmd2RUw=";
  };

  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  libSource = builtins.readFile ../../crates/crucible/src/lib.rs;
  deviceSubnode = builtins.readFile ../../crates/crucible/src/device_subnode.rs;
  deviceInflight = builtins.readFile ../../crates/crucible-device/src/inflight.rs;
  deviceCore = builtins.readFile ../../crates/crucible-device/src/subnode.rs;
  crashTest = builtins.readFile ../../crates/crucible/tests/node_crash_application.rs;
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
        label = "T-FAULT-8 checked off";
        needle = "- [x] **T-FAULT-8**";
      }
      {
        label = "T-FAULT-8 completion note";
        needle = "Completed by `checks.crucible.phase4.nodeCrashApplication`";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "crash application record";
        needle = "pub struct SchedulerNodeCrashApplication";
      }
      {
        label = "restart application record";
        needle = "pub struct SchedulerNodeRestartApplication";
      }
      {
        label = "discarded event record";
        needle = "pub struct SchedulerDiscardedEvent";
      }
      {
        label = "discarded I/O record";
        needle = "pub struct SchedulerDiscardedIoCompletion";
      }
      {
        label = "checkpoint anchor record";
        needle = "pub struct SchedulerNodeCheckpoint";
      }
      {
        label = "runtime crash state";
        needle = "crash: Option<RuntimeNodeCrashState>";
      }
      {
        label = "runtime stay-down state";
        needle = "stopped_crash: Option<RuntimeNodeStoppedState>";
      }
      {
        label = "apply crash API";
        needle = "pub fn apply_node_crash";
      }
      {
        label = "checkpoint recording API";
        needle = "pub fn record_node_checkpoint";
      }
      {
        label = "heal crash API";
        needle = "pub fn heal_node_crash";
      }
      {
        label = "explicit stopped restart API";
        needle = "pub fn restart_stopped_node";
      }
      {
        label = "combined crash bridge";
        needle = "pub fn apply_combined_node_crash_to_scheduler";
      }
      {
        label = "crashed frontier skip";
        needle = "if node.crash.is_some()";
      }
      {
        label = "pending event discard";
        needle = "fn discard_pending_events_for_node";
      }
      {
        label = "device completion discard";
        needle = "fn discard_device_completions_for_node";
      }
      {
        label = "down edge suppression";
        needle = "fn suppress_down_edges";
      }
      {
        label = "latest suppressed edge retention";
        needle = "fn upsert_edge_by_endpoint";
      }
      {
        label = "suppressed edge recompute lookup";
        needle = "fn suppressed_down_edge_exists";
      }
      {
        label = "stay-down restart policy";
        needle = "RestartPolicy::StayDown";
      }
    ]
    ++ failuresFor "crates/crucible/src/device_subnode.rs" deviceSubnode [
      {
        label = "scheduler sub-node discard";
        needle = "pub fn discard_in_flight";
      }
      {
        label = "device core discard call";
        needle = "self.device.discard_inflight()";
      }
    ]
    ++ failuresFor "crates/crucible-device/src/inflight.rs" deviceInflight [
      {
        label = "raw in-flight drain";
        needle = "pub fn drain_all";
      }
    ]
    ++ failuresFor "crates/crucible-device/src/subnode.rs" deviceCore [
      {
        label = "device core in-flight discard";
        needle = "pub fn discard_inflight";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "crash application export";
        needle = "SchedulerNodeCrashApplication";
      }
      {
        label = "restart application export";
        needle = "SchedulerNodeRestartApplication";
      }
      {
        label = "discard event export";
        needle = "SchedulerDiscardedEvent";
      }
      {
        label = "discard I/O export";
        needle = "SchedulerDiscardedIoCompletion";
      }
      {
        label = "checkpoint export";
        needle = "SchedulerNodeCheckpoint";
      }
      {
        label = "crash bridge export";
        needle = "apply_combined_node_crash_to_scheduler";
      }
    ]
    ++ failuresFor "crates/crucible/tests/node_crash_application.rs" crashTest [
      {
        label = "crash discard peer progress test";
        needle = "crash_discards_events_io_and_edges_without_constraining_peer";
      }
      {
        label = "ready-point restart test";
        needle = "from_ready_point_restart_reboots_at_current_frontier_and_restores_edges";
      }
      {
        label = "checkpoint restart test";
        needle = "from_last_checkpoint_restart_resumes_recorded_checkpoint_not_crash_counter";
      }
      {
        label = "stay-down restart test";
        needle = "stay_down_heal_consumes_crash_and_waits_for_explicit_restart";
      }
      {
        label = "unrelated work survival test";
        needle = "crash_preserves_unrelated_events_and_device_completions";
      }
      {
        label = "topology update while down test";
        needle = "topology_updates_while_node_is_down_are_restored_on_restart";
      }
      {
        label = "netlink recompute while down test";
        needle = "netlink_latency_recompute_updates_suppressed_down_edge";
      }
      {
        label = "topology removal while down test";
        needle = "topology_removal_while_node_is_down_is_not_restored_on_restart";
      }
      {
        label = "only-node frozen frontier test";
        needle = "crash_of_only_node_keeps_frontier_at_frozen_crash_time";
      }
      {
        label = "run-twice replay trace test";
        needle = "crash_replay_trace_is_identical_across_independent_runs";
      }
      {
        label = "combined crash bridge covered";
        needle = "apply_combined_node_crash_to_scheduler";
      }
      {
        label = "discarded frame class assertion";
        needle = "ScheduledEventResolveClass::FrameDelivery";
      }
      {
        label = "checkpoint API covered";
        needle = "record_node_checkpoint";
      }
      {
        label = "full I/O discard key assertion";
        needle = "source_node: 1";
      }
      {
        label = "peer progress assertion";
        needle = "outcome.frontier.ticks, 40";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 node crash application import";
        needle = "nodeCrashApplication = import ./phase4-node-crash-application.nix";
      }
      {
        label = "phase4 node crash application attr path";
        needle = "attrPath = \"checks.crucible.phase4.nodeCrashApplication\"";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/node_crash_application.rs" crashTest [
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
  then throw "crucible phase4 node-crash-application check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-node-crash-application";
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
          name = "run-node-crash-application";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-node-crash-application-target" \
              -p crucible \
              --test node_crash_application \
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
            crash=discard-events-and-io
            restart=ready-point-checkpoint-stay-down
            RESULT
          '';
        }
      ];
    }

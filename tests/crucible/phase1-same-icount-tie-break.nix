{
  pkgs,
  lib,
}: let
  phase0S4 = import ./phase0-s4.nix {inherit pkgs;};

  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  engineTest = builtins.readFile ../../crates/crucible/tests/same_icount_tie_break.rs;
  shmemTest = builtins.readFile ../../crates/crucible-shmem/tests/icount_stamped_injection.rs;
  determinismContract = builtins.readFile ../../docs/rfcs/0010-crucible/04-determinism-contract.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;



  failures =
    failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "scheduled event key";
        needle = "pub struct ScheduledEventKey";
      }
      {
        label = "delivery virtual time field";
        needle = "pub timeline: SharedTimelineKey";
      }
      {
        label = "consumer node tie-break field";
        needle = "pub node: SchedulerNodeId";
      }
      {
        label = "producer node tie-break field";
        needle = "pub producer: SchedulerNodeId";
      }
      {
        label = "producer-local sequence field";
        needle = "pub sequence: u64";
      }
      {
        label = "scheduled-event order implementation";
        needle = "impl Ord for ScheduledEventKey";
      }
      {
        label = "scheduled-event order starts with timeline virtual time";
        needle = "self.timeline\n            .virtual_time";
      }
      {
        label = "scheduled-event order uses consumer node";
        needle = "self.timeline.node";
      }
      {
        label = "scheduled-event order preserves producer tie-break";
        needle = "self.producer.cmp(&other.producer)";
      }
      {
        label = "scheduled-event order resolves by sequence last";
        needle = "self.timeline.sequence";
      }
      {
        label = "canonical event ordering helper";
        needle = "pub fn ordered_scheduled_events";
      }
      {
        label = "scheduler helper compares canonical key";
        needle = "left.key.cmp(&right.key)";
      }
      {
        label = "unit test rejects arrival order";
        needle = "scheduled_events_resolve_by_key_not_arrival_order";
      }
    ]
    ++ failuresFor "crates/crucible/tests/same_icount_tie_break.rs" engineTest [
      {
        label = "same-icount public API test";
        needle = "same_icount_inputs_resolve_by_virtual_time_consumer_producer_sequence";
      }
      {
        label = "arrival reversal public API test";
        needle = "same_icount_inputs_keep_order_when_arrival_order_reverses";
      }
      {
        label = "public helper used by test";
        needle = "ordered_scheduled_events";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/same_icount_tie_break.rs" engineTest [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
    ]
    ++ failuresFor "crates/crucible-shmem/tests/icount_stamped_injection.rs" shmemTest [
      {
        label = "consumer-side same-icount tie-break";
        needle = "same_icount_frames_resolve_by_source_node_then_sequence";
      }
      {
        label = "consumer-side canonical order helper";
        needle = "deliverable_frames_at";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/04-determinism-contract.md" determinismContract [
      {
        label = "T-DET-13 checklist complete";
        needle = "- [x] **T-DET-13**";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes same-icount tie-break check";
        needle = "sameIcountTieBreak = import ./phase1-same-icount-tie-break.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 same-icount tie-break check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-same-icount-tie-break";
      version = "0";
      src = null;

      buildDeps = [
        pkgs.coreutils
        pkgs.grep
      ];

      phases = [
        {
          name = "record-same-icount-tie-break";
          script = ''
            set -eu
            s4_result="${phase0S4}/result"

            grep -q '^PASS$' "$s4_result"
            grep -q '^tie_break_key=delivery_icount_src_node_seq$' "$s4_result"
            grep -q '^injection_order_match=true$' "$s4_result"
            grep -q '^arrival_order_negative_control_failed=true$' "$s4_result"

            mkdir -p "$out"
            cat > "$out/result" <<'RESULT'
            PASS
            check=checks.crucible.phase1.sameIcountTieBreak
            tasks=T-DET-13
            engine_order=virtual_time,consumer_node,producer_node,sequence
            shmem_projection=delivery_icount,src_node,seq
            arrival_order_visible=false
            phase0_evidence=checks.crucible.phase0.s4ShmemVisibility
            RESULT
          '';
        }
      ];
    }

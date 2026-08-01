{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase3.schedulerEventOrder",
  taskIds ? ["T-SCHED-8"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  model = import ./_crucible-model-source.nix {inherit lib;};
  canonical = builtins.readFile ../../crates/crucible/src/model/canonical.rs;
  libSource = builtins.readFile ../../crates/crucible/src/lib.rs;
  eventOrderTest = builtins.readFile ../../crates/crucible/tests/scheduler_event_order.rs;
  schedulingDoc = builtins.readFile ../../docs/rfcs/0010-crucible/08-scheduling.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/08-scheduling.md" schedulingDoc [
      {
        label = "T-SCHED-8 completion note";
        needle = "Completed by `checks.crucible.phase3.schedulerEventOrder`";
      }
      {
        label = "four-field total-order key";
        needle = "(virtual_time, consumer node_id, producer node_id, sequence)";
      }
      {
        label = "four key fields";
        needle = "The four key fields, precisely:";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "full scheduled-event key doc";
        needle = "(virtual_time, consumer node, producer node, sequence)";
      }
      {
        label = "scheduled-event key allocator";
        needle = "pub fn next_scheduled_event_key";
      }
      {
        label = "sequence overflow error";
        needle = "scheduled event sequence overflow";
      }
      {
        label = "consumer tie-break accessor";
        needle = "pub fn consumer(&self) -> &SchedulerNodeId";
      }
      {
        label = "producer tie-break accessor";
        needle = "pub fn producer(&self) -> &SchedulerNodeId";
      }
      {
        label = "sequence tie-break accessor";
        needle = "pub fn sequence(&self) -> u64";
      }
      {
        label = "runtime scheduler carries event sequences";
        needle = "event_sequences: EventSequenceState";
      }
      {
        label = "runtime event allocator uses saved state";
        needle = "&mut self.event_sequences";
      }
      {
        label = "delivery decision records event virtual time";
        needle = "virtual_time: event.key.virtual_time()";
      }
      {
        label = "delivery decision records consumer identity";
        needle = "consumer: event.key.consumer().clone()";
      }
      {
        label = "delivery decision records producer identity";
        needle = "producer: event.key.producer().clone()";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "scheduler node identity in model";
        needle = "pub struct SchedulerNodeId";
      }
      {
        label = "scheduler node kind in model";
        needle = "pub enum SchedulingNodeKind";
      }
      {
        label = "delivery event virtual time";
        needle = "pub virtual_time: VirtualTime";
      }
      {
        label = "delivery event consumer";
        needle = "pub consumer: SchedulerNodeId";
      }
      {
        label = "delivery event producer";
        needle = "pub producer: SchedulerNodeId";
      }
      {
        label = "event sequence key";
        needle = "pub struct EventSequenceKey";
      }
      {
        label = "event sequence state";
        needle = "pub struct EventSequenceState";
      }
      {
        label = "scheduler carries event sequences";
        needle = "pub event_sequences: EventSequenceState";
      }
      {
        label = "per-pair sequence getter";
        needle = "pub fn next_sequence(&self, producer: &SchedulerNodeId, consumer: &SchedulerNodeId) -> u64";
      }
      {
        label = "per-pair sequence setter";
        needle = "producer: SchedulerNodeId";
      }
      {
        label = "symmetry includes producer sequence node";
        needle = "nodes.insert(sequence.producer.node.clone())";
      }
      {
        label = "symmetry includes consumer sequence node";
        needle = "nodes.insert(sequence.consumer.node.clone())";
      }
      {
        label = "symmetry prints event sequences";
        needle = "scheduler.event_sequences={}";
      }
      {
        label = "binary delivery event consumer identity";
        needle = "write_scheduler_node_id_binary(&event.consumer";
      }
      {
        label = "text delivery event consumer identity";
        needle = "{prefix}.event.consumer={}";
      }
    ]
    ++ failuresFor "crates/crucible/src/model/canonical.rs" canonical [
      {
        label = "canonical sequence state writer";
        needle = "fn write_event_sequence_state";
      }
      {
        label = "canonical scheduler sequence state call";
        needle = "write_event_sequence_state(hasher, &state.event_sequences)";
      }
      {
        label = "canonical producer identity";
        needle = "write_scheduler_node_id(hasher, &key.producer)";
      }
      {
        label = "canonical consumer identity";
        needle = "write_scheduler_node_id(hasher, &key.consumer)";
      }
      {
        label = "canonical delivery event consumer identity";
        needle = "write_scheduler_node_id(hasher, &key.consumer)";
      }
      {
        label = "canonical delivery event producer identity";
        needle = "write_scheduler_node_id(hasher, &key.producer)";
      }
      {
        label = "canonical next sequence value";
        needle = "hasher.write_u64(*next)";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "event sequence key export";
        needle = "EventSequenceKey";
      }
      {
        label = "event sequence state export";
        needle = "EventSequenceState";
      }
      {
        label = "scheduled-event key allocator export";
        needle = "next_scheduled_event_key";
      }
    ]
    ++ failuresFor "crates/crucible/tests/scheduler_event_order.rs" eventOrderTest [
      {
        label = "tuple ordering test";
        needle = "scheduled_event_keys_order_by_virtual_consumer_producer_sequence";
      }
      {
        label = "per-pair allocation test";
        needle = "next_scheduled_event_key_allocates_per_producer_consumer_sequence";
      }
      {
        label = "scheduler node kind independence test";
        needle = "next_scheduled_event_key_keeps_scheduler_node_kinds_independent";
      }
      {
        label = "overflow test";
        needle = "next_scheduled_event_key_rejects_sequence_overflow";
      }
      {
        label = "saved state hash test";
        needle = "event_sequence_state_is_carried_in_materialized_scheduler_state_hash";
      }
      {
        label = "runtime saved-state allocation test";
        needle = "single_scheduler_allocates_control_event_keys_from_saved_sequence_state";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/scheduler_event_order.rs" eventOrderTest [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase3 exposes scheduler event-order check";
        needle = "schedulerEventOrder = import ./phase3-scheduler-event-order.nix";
      }
    ]
    ++ forbiddenFor "docs/rfcs/0010-crucible/08-scheduling.md" schedulingDoc [
      {
        label = "stale three-field event order";
        needle = "(virtual_time, node_id, sequence)";
      }
    ];
in
  if failures != []
  then throw "crucible phase3 scheduler event-order check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase3-scheduler-event-order";
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
          name = "run-scheduler-event-order";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-scheduler-event-order-target" \
              -p crucible \
              --test scheduler_event_order \
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
            event_order=virtual-consumer-producer-sequence
            sequence_state=saved-producer-consumer-counters
            materialized_state=event-sequence-sensitive
            RESULT
          '';
        }
      ];
    }

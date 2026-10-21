{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase3.schedulerResolve",
  taskIds ? ["T-SCHED-16"],
}: let
  inherit (import ./_test-gate.nix {inherit pkgs lib;}) mkCrucibleTestGate;

  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  libSource = builtins.readFile ../../crates/crucible/src/lib.rs;
  resolveTest = builtins.readFile ../../crates/crucible/tests/scheduler_resolve.rs;
  schedulingDoc = builtins.readFile ../../docs/rfcs/0010-crucible/08-scheduling.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/08-scheduling.md" schedulingDoc [
      {
        label = "T-SCHED-16 completion note";
        needle = "Completed by `checks.crucible.phase3.schedulerResolve`";
      }
      {
        label = "RESOLVE requirement";
        needle = "Implement RESOLVE";
      }
      {
        label = "transport independence requirement";
        needle = "transport-timing-independent";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "resolve class enum";
        needle = "pub enum ScheduledEventResolveClass";
      }
      {
        label = "frame delivery class";
        needle = "FrameDelivery";
      }
      {
        label = "resolve class helper";
        needle = "pub fn scheduled_event_resolve_class";
      }
      {
        label = "delivery time helper";
        needle = "pub fn scheduled_event_delivery_time";
      }
      {
        label = "due resolver helper";
        needle = "pub fn resolve_due_scheduled_events";
      }
      {
        label = "consumer filter";
        needle = "event.key.consumer() == consumer";
      }
      {
        label = "exact frontier due predicate";
        needle = "delivery_time == advanced_to";
      }
      {
        label = "canonical resolve order";
        needle = "ordered_scheduled_events(&resolved)";
      }
      {
        label = "backend target validation";
        needle = "input.node != event.key.consumer().node";
      }
      {
        label = "I/O exact delivery validation";
        needle = "exact_local_event_from_scheduled_event(event.key.consumer(), event, shift)?";
      }
      {
        label = "quantum uses due resolver";
        needle = "resolve_due_scheduled_events(\n            &mut self.pending_events";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "resolve class export";
        needle = "ScheduledEventResolveClass";
      }
      {
        label = "due resolver export";
        needle = "resolve_due_scheduled_events";
      }
      {
        label = "delivery time export";
        needle = "scheduled_event_delivery_time";
      }
      {
        label = "resolve class helper export";
        needle = "scheduled_event_resolve_class";
      }
    ]
    ++ failuresFor "crates/crucible/tests/scheduler_resolve.rs" resolveTest [
      {
        label = "mixed class quantum test";
        needle = "resolve_quantum_processes_frame_and_io_at_exact_delivery_icount_in_total_order";
      }
      {
        label = "transport order test";
        needle = "resolve_due_events_are_independent_of_pending_transport_order";
      }
      {
        label = "backend target validation test";
        needle = "resolve_rejects_backend_input_with_mismatched_payload_target";
      }
      {
        label = "future event boundary test";
        needle = "resolve_leaves_future_backend_input_unvalidated_until_due";
      }
      {
        label = "I/O delivery validation test";
        needle = "resolve_rejects_io_completion_with_non_exact_delivery_icount";
      }
      {
        label = "frame delivery assertion";
        needle = "ScheduledEventResolveClass::FrameDelivery";
      }
      {
        label = "I/O completion assertion";
        needle = "ScheduledEventResolveClass::IoCompletion";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase3 exposes scheduler resolve check";
        needle = "schedulerResolve = import ./phase3-scheduler-resolve.nix";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/scheduler_resolve.rs" resolveTest [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
      {
        label = "pending placeholder";
        needle = "todo!";
      }
      {
        label = "wall-clock dependency";
        needle = "std::time";
      }
      {
        label = "sleep dependency";
        needle = "sleep(";
      }
    ];
in
  if failures != []
  then throw "crucible phase3 scheduler resolve check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    mkCrucibleTestGate {
      pname = "crucible-phase3-scheduler-resolve";

      buildDeps = [
        pkgs.coreutils
        pkgs.sed
      ];

      phases = [
        {
          name = "run-scheduler-resolve";
          script = ''
            set -eu
            cd crates
            crucible-cargo test \
              -p crucible \
              --test scheduler_resolve \
              -- --test-threads=1
            crucible-cargo test \
              -p crucible \
              --test scheduler_exact_local_event \
              -- --test-threads=1
            crucible-cargo test \
              -p crucible \
              --features test-double \
              --test gate_scheduler_liveness \
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
            resolve=due-events-total-order
            visibility=exact-delivery-icount
            payloads=frame-io-fault
            transport_order_dependency=false
            RESULT
          '';
        }
      ];
    }

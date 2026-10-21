{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase3.schedulerRendezvous",
  taskIds ? ["T-SCHED-7"],
}: let
  inherit (import ./_test-gate.nix {inherit pkgs lib;}) mkCrucibleTestGate;

  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  libSource = builtins.readFile ../../crates/crucible/src/lib.rs;
  rendezvousTest = builtins.readFile ../../crates/crucible/tests/scheduler_rendezvous.rs;
  livenessTest = builtins.readFile ../../crates/crucible/tests/gate_scheduler_liveness.rs;
  # Bounded ceilings (RFC-0010 SCHED-12) must not move guest events: a costed
  # double proves it for the scheduler, and the live flight's partition probe
  # proves it on the production QEMU path.
  frequencyTest = builtins.readFile ../../crates/crucible/tests/scheduler_frequency_independence.rs;
  partitionProbe = builtins.readFile ../../crates/crucible-qemu/examples/crucible-qemu-production-plugin-flight/partition_probe.rs;
  schedulingDoc = builtins.readFile ../../docs/rfcs/0010-crucible/08-scheduling.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/08-scheduling.md" schedulingDoc [
      {
        label = "T-SCHED-7 completion note";
        needle = "Completed by `checks.crucible.phase3.schedulerRendezvous`";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "rendezvous policy type";
        needle = "pub struct SchedulerRendezvous";
      }
      {
        label = "fixed rendezvous constructor";
        needle = "pub fn every";
      }
      {
        label = "zero rendezvous rejection";
        needle = "scheduler rendezvous interval must be nonzero";
      }
      {
        label = "rendezvous cap helper";
        needle = "pub fn rendezvous_cap_for";
      }
      {
        label = "scenario stores rendezvous";
        needle = "pub rendezvous: SchedulerRendezvous";
      }
      {
        label = "pick computes one shared rendezvous cap";
        needle = "let rendezvous_cap = self.shared_rendezvous_cap()";
      }
      {
        label = "empty quantum no decision";
        needle = "if selected_candidates.is_empty()";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "rendezvous export";
        needle = "SchedulerRendezvous";
      }
      {
        label = "rendezvous cap export";
        needle = "rendezvous_cap_for";
      }
    ]
    ++ failuresFor "crates/crucible/tests/scheduler_rendezvous.rs" rendezvousTest [
      {
        label = "cap boundary test";
        needle = "rendezvous_cap_uses_next_shared_boundary";
      }
      {
        label = "frontier-based shared cap test";
        needle = "rendezvous_shared_cap_is_frontier_based_not_node_local";
      }
      {
        label = "zero interval test";
        needle = "rendezvous_rejects_zero_interval";
      }
      {
        label = "no empty decision test";
        needle = "single_scheduler_rendezvous_caps_without_decision_or_idle";
      }
      {
        label = "empty rendezvous RNG cursor test";
        needle = "empty_rendezvous_quantum_does_not_advance_decision_rng_cursor";
      }
      {
        label = "frequency independence test";
        needle = "rendezvous_frequency_does_not_change_delivery_order_or_configuration";
      }
      {
        label = "configuration equality assertion";
        needle = "fast_report.final_configuration";
      }
      {
        label = "delivery-order equality assertion";
        needle = "delivery_order_decisions(&fast_report)";
      }
      {
        label = "exact delivery virtual-time assertion";
        needle = "vec![(12, vec![77])]";
      }
    ]
    ++ failuresFor "crates/crucible/tests/scheduler_frequency_independence.rs" frequencyTest [
      {
        label = "costed bounded-ceiling trajectory test";
        needle = "bounded_ceilings_leave_every_guest_event_independent_of_the_schedule";
      }
      {
        label = "legacy ceiling credit negative control";
        needle = "legacy_ceiling_credit_is_detected_as_schedule_dependent";
      }
      {
        label = "seeded ceiling schedule property";
        needle = "seeded_random_ceiling_schedules_match_the_unconstrained_baseline";
      }
      {
        label = "topology swap exact only for affected nodes";
        needle = "a_link_fault_is_an_exact_event_only_for_the_nodes_whose_link_it_changes";
      }
      {
        label = "exact topology swap schedule independence";
        needle = "an_exact_topology_swap_is_independent_of_the_ceiling_schedule";
      }
      {
        label = "settlement below an exact topology swap refused";
        needle = "settling_below_an_exact_topology_swap_is_refused";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/examples/crucible-qemu-production-plugin-flight/partition_probe.rs" partitionProbe [
      {
        label = "production alternating rendezvous bounds";
        needle = "PartitionSchedule::AlternatingRendezvous";
      }
      {
        label = "production seeded odd-picosecond bounds";
        needle = "PartitionSchedule::SeededOdd";
      }
      {
        label = "production frequency-independence evidence";
        needle = "bound_frequency_independent=true";
      }
    ]
    ++ failuresFor "crates/crucible/tests/gate_scheduler_liveness.rs" livenessTest [
      {
        label = "liveness no per-quantum decision assumption";
        needle = "recorded decisions without canonical event-log entries";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/scheduler_rendezvous.rs" rendezvousTest [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase3 exposes scheduler rendezvous check";
        needle = "schedulerRendezvous = import ./phase3-scheduler-rendezvous.nix";
      }
      {
        label = "phase4 exposes the production bounded-ceiling flight";
        needle = "schedulerBoundFrequencyQemuVm = phase7.productionRustPluginFlight.rawGate.partitionDiagnostic;";
      }
    ];
in
  if failures != []
  then throw "crucible phase3 scheduler rendezvous check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    mkCrucibleTestGate {
      pname = "crucible-phase3-scheduler-rendezvous";

      buildDeps = [
        pkgs.coreutils
        pkgs.sed
      ];

      phases = [
        {
          name = "run-scheduler-rendezvous";
          script = ''
            set -eu
            cd crates
            crucible-cargo test \
              -p crucible \
              --test scheduler_rendezvous \
              --test scheduler_frequency_independence \
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
            rendezvous=exact-shared-horizon-cap
            ordering_exactness=frequency-independent
            empty_rendezvous_quantum=no-canonical-decision
            bounded_ceilings=guest-trajectory-frequency-independent
            topology_swap=exact-event-for-affected-nodes-only
            production_path=checks.crucible.phase4.schedulerBoundFrequencyQemuVm
            RESULT
          '';
        }
      ];
    }

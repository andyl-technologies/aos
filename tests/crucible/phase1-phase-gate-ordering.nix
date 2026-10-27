{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.phaseGateOrdering",
  taskIds ? ["T-HARN-26"],
}: let
  inherit (import ./_test-gate.nix {inherit pkgs lib;}) mkCrucibleTestGate;

  phasePlanRust = builtins.readFile ../../crates/crucible/crucible-test-support/src/phase_plan.rs;
  phasePlanTest = builtins.readFile ../../crates/crucible/crucible-test-support/tests/phase_plan.rs;
  gateCatalog = builtins.readFile ../../docs/rfcs/0010-crucible/24-determinism-harness-testing.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "crates/crucible/crucible-test-support/src/phase_plan.rs" phasePlanRust [
      {
        label = "ordered phase gate data";
        needle = "pub const PHASE_GATE_ORDER";
      }
      {
        label = "layer-gate precedence data";
        needle = "pub const LAYER_GATE_PRECEDENCES";
      }
      {
        label = "green-before-advance enforcement";
        needle = "pub fn green_before_advance_failures";
      }
      {
        label = "layer-gate precedence enforcement";
        needle = "pub fn layer_gate_precedence_failures";
      }
      {
        label = "terminal acceptance lookup";
        needle = "pub fn terminal_acceptance_gate";
      }
      {
        label = "SimDouble availability phase";
        needle = "pub const SIM_DOUBLE_AVAILABLE_PHASE: PhasePlanPhase = PhasePlanPhase::Phase1";
      }
      {
        label = "terminal Phase 7 signal-fault target";
        needle = "checks.crucible.phase7.gates.signalFaultSystem";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-test-support/tests/phase_plan.rs" phasePlanTest [
      {
        label = "RFC Section 13 parity test";
        needle = "phase_gate_plan_matches_rfc_section_13_and_nix_wiring";
      }
      {
        label = "green-before-advance test";
        needle = "green_before_advance_requires_every_prior_phase_gate";
      }
      {
        label = "terminal signal-fault test";
        needle = "terminal_signal_fault_occurrence_remains_in_phase7_acceptance_set";
      }
      {
        label = "SimDouble ordering test";
        needle = "sim_double_is_available_before_dependent_gate_occurrences";
      }
      {
        label = "HARN-3 layer precedence test";
        needle = "layer_gate_precedences_keep_lower_layer_checks_first";
      }
      {
        label = "negative invariant regression test";
        needle = "phase_plan_invariants_reject_synthetic_drift";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/24-determinism-harness-testing.md" gateCatalog [
      {
        label = "green-before-advance requirement";
        needle = "green-before-advance";
      }
      {
        label = "terminal Phase 7 signal-fault requirement";
        needle = "`gate:signal-fault-system` terminal";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "green-before-advance wrapper";
        needle = "greenBeforeAdvance = {";
      }
      {
        label = "green-before-advance wrapper uses AOS bash";
        needle = ''builder = "''${pkgs.bash}/bin/bash";'';
      }
      {
        label = "green-before-advance wrapper gate input";
        needle = "GATE = gate;";
      }
      {
        label = "green-before-advance wrapper uses AOS coreutils";
        needle = ''PATH = "''${pkgs.coreutils}/bin";'';
      }
      {
        label = "green-before-advance raw gate passthru";
        needle = "rawGate = gate;";
      }
      {
        label = "raw gate dependency injection";
        needle = "dependencies = [replayOracle.rawGate phase1.simDouble];";
      }
      {
        label = "recursive phase graph";
        needle = "in rec {";
      }
      {
        label = "Phase 1 waits for Phase 0";
        needle = "dependencies = [phase0.gates.blockers phase0.gates.harnessLint.rawGate];";
      }
      {
        label = "SimDouble gate dependency";
        needle = "dependencies = [contentAddress.rawGate phase1.simDouble];";
      }
      {
        label = "Phase 2 waits for Phase 1 terminal gate";
        needle = "phase1.gates.divergenceBisect";
      }
      {
        label = "Phase 5 waits for Phase 4 e2e";
        needle = "dependencies = [phase4.gates.e2eDeterminism.rawGate];";
      }
      {
        label = "Phase 7 waits for Phase 6";
        needle = "dependencies = [phase2.qemuCheckpointDeltaFlight phase6.gates.replayOracle.rawGate phase6.basicBlockCoverage.rawGate phase7.";
      }
      {
        label = "phase-gate-ordering check import";
        needle = "phaseGateOrdering = import ./phase1-phase-gate-ordering.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 phase-gate-ordering check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    mkCrucibleTestGate {
      pname = "crucible-phase1-phase-gate-ordering";

      buildDeps = [
        pkgs.coreutils
        pkgs.sed
      ];

      phases = [
        {
          name = "run-phase-gate-ordering";
          script = ''
            set -eu
            cd crates
            crucible-cargo test \
              -p crucible-test-support \
              --test phase_plan \
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
            tasks=${builtins.concatStringsSep "," taskIds}
            rust_test=crucible_test_support::phase_plan
            phase_gate_ordering=green-before-advance
            terminal_gate=gate:signal-fault-system
            sim_double_available=phase1
            RESULT
          '';
        }
      ];
    }

{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.phaseGateOrdering",
  taskIds ? ["T-HARN-26"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  phasePlanRust = builtins.readFile ../../crates/crucible-harness/src/phase_plan.rs;
  phasePlanTest = builtins.readFile ../../crates/crucible-harness/tests/phase_plan.rs;
  gateCatalog = builtins.readFile ../../docs/rfcs/0010-crucible/24-determinism-harness-testing.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;


  failures =
    failuresFor "crates/crucible-harness/src/phase_plan.rs" phasePlanRust [
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
        label = "terminal Phase 7 e2e target";
        needle = "checks.crucible.phase7.gates.e2eDeterminism";
      }
    ]
    ++ failuresFor "crates/crucible-harness/tests/phase_plan.rs" phasePlanTest [
      {
        label = "RFC Section 13 parity test";
        needle = "phase_gate_plan_matches_rfc_section_13_and_nix_wiring";
      }
      {
        label = "green-before-advance test";
        needle = "green_before_advance_requires_every_prior_phase_gate";
      }
      {
        label = "terminal e2e test";
        needle = "terminal_e2e_occurrence_remains_in_phase7_acceptance_set";
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
        label = "T-HARN-26 checklist complete";
        needle = "- [x] **T-HARN-26**";
      }
      {
        label = "green-before-advance requirement";
        needle = "green-before-advance";
      }
      {
        label = "terminal Phase 7 e2e requirement";
        needle = "`gate:e2e-determinism` terminal";
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
        needle = "dependencies = [phase6.gates.replayOracle.rawGate phase6.basicBlockCoverage.rawGate phase7.";
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
    pkgs.mkDerivation {
      pname = "crucible-phase1-phase-gate-ordering";
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
          name = "run-phase-gate-ordering";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-phase-gate-ordering-target" \
              -p crucible-harness \
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
            rust_test=crucible-harness::phase_plan
            phase_gate_ordering=green-before-advance
            terminal_gate=gate:e2e-determinism
            sim_double_available=phase1
            RESULT
          '';
        }
      ];
    }

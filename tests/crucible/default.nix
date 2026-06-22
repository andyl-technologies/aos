{
  pkgs,
  lib,
}: let
  redGate = import ./red-gate-placeholder.nix {inherit pkgs;};
in {
  phase0 = {
    gates = {
      blockers = import ./phase0-blockers.nix {
        inherit pkgs;
        attrPath = "checks.crucible.phase0.gates.blockers";
        blockers = [
          (import ./phase0-s1.nix {inherit pkgs lib;})
          (import ./phase0-s2.nix {inherit pkgs lib;})
          (import ./phase0-s4.nix {inherit pkgs;})
          (import ./phase0-s3.nix {inherit pkgs lib;})
          (import ./phase0-s11.nix {inherit pkgs lib;})
        ];
      };
      harnessLint = import ./phase1-harness-lint.nix {
        inherit pkgs lib;
        attrPath = "checks.crucible.phase0.gates.harnessLint";
      };
    };
    s1Fingerprint = import ./phase0-s1.nix {inherit pkgs lib;};
    s2HltBusyPoll = import ./phase0-s2.nix {inherit pkgs lib;};
    s3SavevmLoadvm = import ./phase0-s3.nix {inherit pkgs lib;};
    s4ShmemVisibility = import ./phase0-s4.nix {inherit pkgs;};
    s5VirtualMemory = import ./phase0-s5.nix {inherit pkgs lib;};
    s6KaslrAslr = import ./phase0-s6.nix {inherit pkgs lib;};
    s7DeadlineCeiling = import ./phase0-s7.nix {inherit pkgs lib;};
    s9QemuBuildIdentity = import ./phase0-s9.nix {inherit pkgs lib;};
    s10Aarch64Doorbell = import ./phase0-s10.nix {inherit pkgs;};
    s11MultiVcpuFingerprint = import ./phase0-s11.nix {inherit pkgs lib;};
    s12PreemptionDecision = import ./phase0-s12.nix {inherit pkgs;};
    s13RrSwitchQuantumFallback = import ./phase0-s13.nix {inherit pkgs;};
    s14GdbstubFallback = import ./phase0-s14.nix {inherit pkgs;};
    abiDrift = import ./phase0-abi-drift.nix {inherit pkgs;};
    coverageOverhead = import ./phase0-coverage.nix {inherit pkgs lib;};
    futexStress = import ./phase0-futex-stress.nix {inherit pkgs;};
    lifecycle = import ./phase0-lifecycle.nix {inherit pkgs lib;};
    multiVmParallelism = import ./phase0-parallelism.nix {inherit pkgs;};
    riskRegisterGate = import ./phase0-risk-register.nix {inherit pkgs;};
    searchTreeGrowth = import ./phase0-search-tree.nix {inherit pkgs;};
  };
  phase1 = {
    aosWorkspaceBuild = import ./phase1-aos-workspace-build.nix {inherit pkgs lib;};
    contractAIsolation = import ./phase1-contract-a-isolation.nix {inherit pkgs lib;};
    controlPlaneBoundary = import ./phase1-control-plane-boundary.nix {inherit pkgs lib;};
    crateArtifactTypes = import ./phase1-crate-artifact-types.nix {inherit pkgs lib;};
    crateFeaturePowerset = import ./phase1-crate-feature-powerset.nix {inherit pkgs lib;};
    crateLayerGraph = import ./phase1-crate-layer-graph.nix {inherit pkgs lib;};
    crateSpecIndex = import ./phase1-crate-spec-index.nix {inherit pkgs lib;};
    crateUnsafeFence = import ./phase1-crate-unsafe-fence.nix {inherit pkgs lib;};
    concurrencyAbiOracleStandards = import ./phase1-concurrency-abi-oracle-standards.nix {inherit pkgs lib;};
    decisionRecording = import ./phase1-decision-recording.nix {inherit pkgs lib;};
    decisionRng = import ./phase1-decision-rng.nix {inherit pkgs lib;};
    determinismCoreCoverage = import ./phase1-determinism-core-coverage.nix {inherit pkgs lib;};
    deterministicLaunch = import ./phase1-deterministic-launch.nix {inherit pkgs lib;};
    determinismReview = import ./phase1-determinism-review.nix {inherit pkgs lib;};
    documentationHygiene = import ./phase1-documentation-hygiene.nix {inherit pkgs lib;};
    engineeringHygiene = import ./phase1-engineering-hygiene.nix {inherit pkgs lib;};
    executionFingerprintDefinition = import ./phase1-execution-fingerprint-definition.nix {inherit pkgs lib;};
    gateTargetMapping = import ./phase1-gate-target-mapping.nix {inherit pkgs lib;};
    guestEntropyLaunch = import ./phase1-guest-entropy-launch.nix {inherit pkgs lib;};
    harnessComponents = import ./phase1-harness-components.nix {inherit pkgs lib;};
    icountStampedInjection = import ./phase1-icount-stamped-injection.nix {inherit pkgs lib;};
    icountNoRealtime = import ./phase1-icount-no-realtime.nix {inherit pkgs lib;};
    kaslrAslrDefault = import ./phase1-kaslr-aslr-default.nix {inherit pkgs lib;};
    layer0Determinism = import ./phase1-layer0-determinism.nix {inherit pkgs lib;};
    layer1Injection = import ./phase1-layer1-injection.nix {inherit pkgs lib;};
    lookaheadGate = import ./phase1-lookahead-gate.nix {inherit pkgs lib;};
    noWarpWithPlugin = import ./phase1-no-warp-with-plugin.nix {inherit pkgs lib;};
    qemuDeterministicEntropy = import ./phase1-qemu-deterministic-entropy.nix {inherit pkgs lib;};
    phaseGateWiring = import ./phase1-phase-gate-wiring.nix {inherit pkgs lib;};
    rfcConsistency = import ./phase1-rfc-consistency.nix {inherit pkgs lib;};
    rustdocBar = import ./phase1-rustdoc-bar.nix {inherit pkgs lib;};
    sameIcountTieBreak = import ./phase1-same-icount-tie-break.nix {inherit pkgs lib;};
    singleVmFingerprint = import ./phase1-single-vm-fingerprint-gate.nix {inherit pkgs lib;};
    singleSchedulerBoundary = import ./phase1-single-scheduler-boundary.nix {inherit pkgs lib;};
    standaloneDependencies = import ./phase1-standalone-dependencies.nix {inherit pkgs lib;};
    testingStandards = import ./phase1-testing-standards.nix {inherit pkgs lib;};
    gates = {
      harnessLint = import ./phase1-harness-lint.nix {
        inherit pkgs lib;
        attrPath = "checks.crucible.phase1.gates.harnessLint";
      };
      layer0Determinism = import ./phase1-layer0-determinism.nix {
        inherit pkgs lib;
        attrPath = "checks.crucible.phase1.gates.layer0Determinism";
        taskIds = [
          "T-PLAN-3"
          "T-HARN-5"
          "T-DET-1"
          "T-DET-2"
          "T-DET-3"
          "T-DET-4"
          "T-DET-5"
          "T-DET-6"
          "T-DET-7"
          "T-DET-8"
          "T-DET-9"
          "T-DET-10"
        ];
      };
      contentAddress = import ./phase1-content-address.nix {
        inherit pkgs lib;
        attrPath = "checks.crucible.phase1.gates.contentAddress";
        taskIds = ["T-PLAN-3" "T-HARN-11"];
      };
      replayOracle = import ./phase1-replay-oracle.nix {
        inherit pkgs lib;
        attrPath = "checks.crucible.phase1.gates.replayOracle";
        taskIds = [
          "T-PLAN-3"
          "T-DET-18"
          "T-HARN-12"
          "T-EXEC-4"
        ];
      };
      singleVmFingerprint = import ./phase1-single-vm-fingerprint-gate.nix {
        inherit pkgs lib;
        attrPath = "checks.crucible.phase1.gates.singleVmFingerprint";
        taskIds = ["T-PLAN-3" "T-HARN-7" "T-DET-8" "T-DET-9"];
      };
      divergenceBisect = redGate {
        attrPath = "checks.crucible.phase1.gates.divergenceBisect";
        gateName = "gate:divergence-bisect";
        owner = "crucible-harness";
        phase = "phase1";
        taskIds = ["T-PLAN-3" "T-HARN-10"];
        reason = "divergence bisection gate is intentionally pending";
      };
    };
  };
  phase2 = {
    gates = {
      abiConformance = redGate {
        attrPath = "checks.crucible.phase2.gates.abiConformance";
        gateName = "gate:abi-conformance";
        owner = "crucible-harness";
        phase = "phase2";
        taskIds = ["T-PLAN-3" "T-HARN-17"];
        reason = "ABI conformance gate is intentionally pending";
      };
      qemuInert = redGate {
        attrPath = "checks.crucible.phase2.gates.qemuInert";
        gateName = "gate:qemu-inert";
        owner = "crucible-qemu";
        phase = "phase2";
        taskIds = ["T-PLAN-3" "T-HARN-21"];
        reason = "QEMU inertness gate is intentionally pending";
      };
      patchMicrotests = redGate {
        attrPath = "checks.crucible.phase2.gates.patchMicrotests";
        gateName = "gate:patch-microtests";
        owner = "crucible-qemu-plugin";
        phase = "phase2";
        taskIds = ["T-PLAN-3" "T-HARN-20"];
        reason = "QEMU patch micro-test gate is intentionally pending";
      };
      singleVmFingerprint = redGate {
        attrPath = "checks.crucible.phase2.gates.singleVmFingerprint";
        gateName = "gate:single-vm-fingerprint";
        owner = "crucible-qemu";
        phase = "phase2";
        taskIds = ["T-PLAN-3" "T-HARN-7"];
        reason = "single-VM fingerprint gate is intentionally pending";
      };
      anyGuest = redGate {
        attrPath = "checks.crucible.phase2.gates.anyGuest";
        gateName = "gate:any-guest";
        owner = "crucible-qemu";
        phase = "phase2";
        taskIds = ["T-PLAN-3" "T-HARN-16"];
        reason = "any-guest gate is intentionally pending";
      };
    };
  };
  phase3 = {
    gates = {
      layer1Injection = import ./phase1-layer1-injection.nix {
        inherit pkgs lib;
        attrPath = "checks.crucible.phase3.gates.layer1Injection";
        taskIds = ["T-PLAN-3" "T-HARN-8" "T-DET-11" "T-DET-12" "T-DET-13" "T-DET-14"];
      };
      schedulerLiveness = redGate {
        attrPath = "checks.crucible.phase3.gates.schedulerLiveness";
        gateName = "gate:scheduler-liveness";
        owner = "crucible";
        phase = "phase3";
        taskIds = ["T-PLAN-3" "T-HARN-14"];
        reason = "scheduler liveness gate is intentionally pending";
      };
      adversarialDeterminism = redGate {
        attrPath = "checks.crucible.phase3.gates.adversarialDeterminism";
        gateName = "gate:adversarial-determinism";
        owner = "crucible-harness";
        phase = "phase3";
        taskIds = ["T-PLAN-3" "T-CRATE-8" "T-HARN-22"];
        reason = "two-VM adversarial determinism gate is intentionally pending";
      };
    };
  };
  phase4 = {
    gates = {
      replayOracle = redGate {
        attrPath = "checks.crucible.phase4.gates.replayOracle";
        gateName = "gate:replay-oracle";
        owner = "crucible";
        phase = "phase4";
        taskIds = ["T-PLAN-3" "T-HARN-12"];
        reason = "full replay oracle gate is intentionally pending";
      };
      e2eDeterminism = redGate {
        attrPath = "checks.crucible.phase4.gates.e2eDeterminism";
        gateName = "gate:e2e-determinism";
        owner = "crucible-harness";
        phase = "phase4";
        taskIds = ["T-PLAN-3" "T-HARN-23"];
        reason = "mock-backend end-to-end determinism gate is intentionally pending";
      };
    };
  };
  phase5 = {
    gates = {
      controlResponsive = redGate {
        attrPath = "checks.crucible.phase5.gates.controlResponsive";
        gateName = "gate:control-responsive";
        owner = "crucible-session";
        phase = "phase5";
        taskIds = ["T-PLAN-3" "T-HARN-15"];
        reason = "control-plane responsiveness gate is intentionally pending";
      };
    };
  };
  phase6 = {
    gates = {
      replayOracle = redGate {
        attrPath = "checks.crucible.phase6.gates.replayOracle";
        gateName = "gate:replay-oracle";
        owner = "crucible";
        phase = "phase6";
        taskIds = ["T-PLAN-3" "T-HARN-12" "T-HARN-13"];
        reason = "search-time replay oracle gate is intentionally pending";
      };
    };
  };
  phase7 = {
    gates = {
      perfBench = redGate {
        attrPath = "checks.crucible.phase7.gates.perfBench";
        gateName = "gate:perf-bench";
        owner = "crucible-harness";
        phase = "phase7";
        taskIds = ["T-PLAN-3" "T-PERF-1"];
        reason = "performance benchmark gate is intentionally pending";
      };
      e2eDeterminism = redGate {
        attrPath = "checks.crucible.phase7.gates.e2eDeterminism";
        gateName = "gate:e2e-determinism";
        owner = "crucible-harness";
        phase = "phase7";
        taskIds = ["T-PLAN-3" "T-HARN-23"];
        reason = "acceptance end-to-end determinism gate is intentionally pending";
      };
      fleetEquivalence = redGate {
        attrPath = "checks.crucible.phase7.gates.fleetEquivalence";
        gateName = "gate:fleet-equivalence";
        owner = "crucible-harness";
        phase = "phase7";
        taskIds = ["T-PLAN-3" "T-DCE-7"];
        reason = "fleet equivalence gate is intentionally pending";
      };
      campaignContinuity = redGate {
        attrPath = "checks.crucible.phase7.gates.campaignContinuity";
        gateName = "gate:campaign-continuity";
        owner = "crucible-harness";
        phase = "phase7";
        taskIds = ["T-PLAN-3" "T-DCE-9"];
        reason = "campaign continuity gate is intentionally pending";
      };
    };
  };
}

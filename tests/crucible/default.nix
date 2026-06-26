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
    adversarialHostFixture = import ./phase1-adversarial-host-fixture.nix {inherit pkgs lib;};
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
    clockDeadline = import ./phase1-clock-deadline.nix {inherit pkgs lib;};
    blockRtcRead = import ./phase1-block-rtc-read.nix {inherit pkgs lib;};
    documentationHygiene = import ./phase1-documentation-hygiene.nix {inherit pkgs lib;};
    engineeringHygiene = import ./phase1-engineering-hygiene.nix {inherit pkgs lib;};
    executionBake = import ./phase1-execution-bake.nix {inherit pkgs lib;};
    executionCacheEviction = import ./phase1-execution-cache-eviction.nix {inherit pkgs lib;};
    executionDecisionTaxonomy = import ./phase1-execution-decision-taxonomy.nix {inherit pkgs lib;};
    executionEngineStateMachine = import ./phase1-execution-engine-state-machine.nix {inherit pkgs lib;};
    executionGraphOperations = import ./phase1-execution-graph-operations.nix {inherit pkgs lib;};
    executionInstantiate = import ./phase1-execution-instantiate.nix {inherit pkgs lib;};
    executionLiveSnapshot = import ./phase1-execution-live-snapshot.nix {inherit pkgs lib;};
    executionModelCore = import ./phase1-execution-model-core.nix {inherit pkgs lib;};
    executionNodeBlobRef = import ./phase1-execution-node-blob-ref.nix {inherit pkgs lib;};
    executionReadyPoint = import ./phase1-execution-ready-point.nix {inherit pkgs lib;};
    executionResumeFingerprint = import ./phase1-execution-resume-fingerprint.nix {inherit pkgs lib;};
    executionStartResumeFork = import ./phase1-execution-start-resume-fork.nix {inherit pkgs lib;};
    executionStepPurity = import ./phase1-execution-step-purity.nix {inherit pkgs lib;};
    executionFingerprintDefinition = import ./phase1-execution-fingerprint-definition.nix {inherit pkgs lib;};
    fixedIcountShift = import ./phase1-fixed-icount-shift.nix {inherit pkgs lib;};
    gateCatalog = import ./phase1-gate-catalog.nix {inherit pkgs lib;};
    gateTargetMapping = import ./phase1-gate-target-mapping.nix {inherit pkgs lib;};
    guestNonModification = import ./phase1-guest-non-modification.nix {inherit pkgs lib;};
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
    qemuDeterministicGetrandom = import ./phase1-qemu-deterministic-getrandom.nix {inherit pkgs lib;};
    qemuMultiVcpuLaunch = import ./phase2-qemu-multi-vcpu-launch.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase1.qemuMultiVcpuLaunch";
      taskIds = ["T-DET-29" "T-DET-30"];
    };
    qemuPluginPreemption = import ./phase2-plugin-preemption.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase1.qemuPluginPreemption";
      taskIds = ["T-DET-30"];
    };
    qemuPluginAppRandomDoorbell = import ./phase2-plugin-app-random-doorbell.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase1.qemuPluginAppRandomDoorbell";
      taskIds = ["T-DET-31"];
    };
    qemuNetDeterministic = import ./phase1-qemu-net-deterministic.nix {inherit pkgs lib;};
    qemuNetTxCallback = import ./phase1-qemu-net-tx-callback.nix {inherit pkgs lib;};
    qemuDoorbellNoPatch = import ./phase1-qemu-doorbell-no-patch.nix {inherit pkgs lib;};
    qemuDiagnosticPatchesDevOnly = import ./phase1-qemu-diagnostic-patches-dev-only.nix {inherit pkgs lib;};
    qemuSimCorrectness = import ./phase1-qemu-sim-correctness.nix {inherit pkgs lib;};
    qemuSimBatchTcgExec = import ./phase1-qemu-sim-batch-tcg-exec.nix {inherit pkgs lib;};
    qemuBlockShmem = import ./phase1-qemu-block-shmem.nix {inherit pkgs lib;};
    qemuNinePShmem = import ./phase1-qemu-9p-shmem.nix {inherit pkgs lib;};
    pluginTimeAdvance = import ./phase1-plugin-time-advance.nix {inherit pkgs lib;};
    pluginRuntimeApis = import ./phase1-plugin-runtime-apis.nix {inherit pkgs lib;};
    rrFingerprintHelpers = import ./phase1-rr-fingerprint-helpers.nix {inherit pkgs lib;};
    phaseGateWiring = import ./phase1-phase-gate-wiring.nix {inherit pkgs lib;};
    rfcConsistency = import ./phase1-rfc-consistency.nix {inherit pkgs lib;};
    rustdocBar = import ./phase1-rustdoc-bar.nix {inherit pkgs lib;};
    sameIcountTieBreak = import ./phase1-same-icount-tie-break.nix {inherit pkgs lib;};
    simDouble = import ./phase1-sim-double.nix {inherit pkgs lib;};
    singleVmFingerprint = import ./phase1-single-vm-fingerprint-gate.nix {inherit pkgs lib;};
    singleSchedulerBoundary = import ./phase1-single-scheduler-boundary.nix {inherit pkgs lib;};
    standaloneDependencies = import ./phase1-standalone-dependencies.nix {inherit pkgs lib;};
    testingStandards = import ./phase1-testing-standards.nix {inherit pkgs lib;};
    timeClockSkew = import ./phase1-time-clock-skew.nix {inherit pkgs lib;};
    timeContractADeterminism = import ./phase1-time-contract-a-determinism.nix {inherit pkgs lib;};
    timeMultiVcpuAggregateClock = import ./phase1-time-multi-vcpu-aggregate-clock.nix {inherit pkgs lib;};
    timeNoRealtimeWarp = import ./phase1-time-no-realtime-warp.nix {inherit pkgs lib;};
    timeAdvanceCeiling = import ./phase1-time-advance-ceiling.nix {inherit pkgs lib;};
    timeSharedTimeline = import ./phase1-time-shared-timeline.nix {inherit pkgs lib;};
    timeVocabulary = import ./phase1-time-vocabulary.nix {inherit pkgs lib;};
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
          "T-DET-28"
          "T-DET-29"
          "T-DET-30"
          "T-DET-31"
          "T-DET-8"
          "T-DET-9"
          "T-DET-10"
          "T-TIME-8"
          "T-TIME-9"
        ];
      };
      contentAddress = import ./phase1-content-address.nix {
        inherit pkgs lib;
        attrPath = "checks.crucible.phase1.gates.contentAddress";
        taskIds = ["T-PLAN-3" "T-HARN-11" "T-TEMP-1" "T-TEMP-2" "T-TEMP-3" "T-TEMP-6"];
      };
      replayOracle = import ./phase1-replay-oracle.nix {
        inherit pkgs lib;
        attrPath = "checks.crucible.phase1.gates.replayOracle";
        taskIds = [
          "T-PLAN-3"
          "T-DET-18"
          "T-DET-21"
          "T-DET-27"
          "T-HARN-12"
          "T-EXEC-4"
          "T-EXEC-11"
          "T-TEMP-3"
          "T-TEMP-4"
          "T-TEMP-5"
        ];
      };
      singleVmFingerprint = import ./phase1-single-vm-fingerprint-gate.nix {
        inherit pkgs lib;
        attrPath = "checks.crucible.phase1.gates.singleVmFingerprint";
        taskIds = ["T-PLAN-3" "T-HARN-6" "T-HARN-7" "T-DET-8" "T-DET-9" "T-TIME-8" "T-TIME-9" "T-EXEC-17" "T-EXEC-18"];
      };
      divergenceBisect = import ./phase1-divergence-bisect.nix {
        inherit pkgs lib;
        attrPath = "checks.crucible.phase1.gates.divergenceBisect";
        taskIds = [
          "T-PLAN-3"
          "T-DET-20"
          "T-HARN-9"
          "T-HARN-10"
          "T-EXEC-12"
        ];
      };
    };
  };
  phase2 = {
    protocolFrameFormat = import ./phase2-protocol-frame-format.nix {inherit pkgs lib;};
    protocolCodec = import ./phase2-protocol-codec.nix {inherit pkgs lib;};
    protocolDescriptorHandover = import ./phase2-protocol-descriptor-handover.nix {inherit pkgs lib;};
    protocolHandshake = import ./phase2-protocol-handshake.nix {inherit pkgs lib;};
    protocolSetupCompletion = import ./phase2-protocol-setup-completion.nix {inherit pkgs lib;};
    protocolLifecycle = import ./phase2-protocol-lifecycle.nix {inherit pkgs lib;};
    protocolShutdownEscalation = import ./phase2-protocol-shutdown-escalation.nix {inherit pkgs lib;};
    protocolSetupFailure = import ./phase2-protocol-setup-failure.nix {inherit pkgs lib;};
    protocolGoldenVectors = import ./phase2-protocol-golden-vectors.nix {inherit pkgs lib;};
    protocolCodecFuzz = import ./phase2-protocol-codec-fuzz.nix {inherit pkgs lib;};
    protocolInertness = import ./phase2-protocol-inertness.nix {inherit pkgs lib;};
    qemuPluginAbiScaffold = import ./phase2-plugin-abi-scaffold.nix {inherit pkgs lib;};
    qemuPluginArgs = import ./phase2-plugin-args.nix {inherit pkgs lib;};
    qemuPluginRegistrationOrder = import ./phase2-plugin-registration-order.nix {inherit pkgs lib;};
    qemuPluginTimeControl = import ./phase2-plugin-time-control.nix {inherit pkgs lib;};
    qemuPluginIdleLoop = import ./phase2-plugin-idle-loop.nix {inherit pkgs lib;};
    qemuPluginDeadlineIntrospection = import ./phase2-plugin-deadline-introspection.nix {inherit pkgs lib;};
    qemuPluginSynchronousIdleAdvance = import ./phase2-plugin-synchronous-idle-advance.nix {inherit pkgs lib;};
    qemuPluginInboundFrames = import ./phase2-plugin-inbound-frames.nix {inherit pkgs lib;};
    qemuPluginDeviceIoFreeze = import ./phase2-plugin-device-io-freeze.nix {inherit pkgs lib;};
    qemuPluginNetworkTx = import ./phase2-plugin-network-tx.nix {inherit pkgs lib;};
    qemuPluginNetworkRx = import ./phase2-plugin-network-rx.nix {inherit pkgs lib;};
    qemuPluginBlockIo = import ./phase2-plugin-block-io.nix {inherit pkgs lib;};
    qemuPluginNinePIo = import ./phase2-plugin-9p-io.nix {inherit pkgs lib;};
    qemuPluginWhiteboxDoorbell = import ./phase2-plugin-whitebox-doorbell.nix {inherit pkgs lib;};
    qemuPluginAppRandomDoorbell = import ./phase2-plugin-app-random-doorbell.nix {inherit pkgs lib;};
    qemuPluginCoverage = import ./phase2-plugin-coverage.nix {inherit pkgs lib;};
    qemuPluginHandshake = import ./phase2-plugin-handshake.nix {inherit pkgs lib;};
    qemuPluginSetupCompletion = import ./phase2-plugin-setup-completion.nix {inherit pkgs lib;};
    qemuPluginBootBarrier = import ./phase2-plugin-boot-barrier.nix {inherit pkgs lib;};
    qemuPluginTeardown = import ./phase2-plugin-teardown.nix {inherit pkgs lib;};
    qemuPluginShmemOrdering = import ./phase2-plugin-shmem-ordering.nix {inherit pkgs lib;};
    qemuPluginUnsafeBoundary = import ./phase2-plugin-unsafe-boundary.nix {inherit pkgs lib;};
    qemuPluginFailLoud = import ./phase2-plugin-fail-loud.nix {inherit pkgs lib;};
    qemuPluginQemuInert = import ./phase2-plugin-qemu-inert.nix {inherit pkgs lib;};
    qemuPluginRoundRobin = import ./phase2-plugin-round-robin.nix {inherit pkgs lib;};
    qemuPluginPreemption = import ./phase2-plugin-preemption.nix {inherit pkgs lib;};
    qemuPluginVcpuIntrospection = import ./phase2-plugin-vcpu-introspection.nix {inherit pkgs lib;};
    qemuAsyncDriver = import ./phase2-qemu-async-driver.nix {inherit pkgs lib;};
    qemuCrashDetection = import ./phase2-qemu-crash-detection.nix {inherit pkgs lib;};
    qemuDeterminismBoundary = import ./phase2-qemu-determinism-boundary.nix {inherit pkgs lib;};
    qemuLaunchBuilder = import ./phase2-qemu-launch-builder.nix {inherit pkgs lib;};
    qemuMultiVcpuLaunch = import ./phase2-qemu-multi-vcpu-launch.nix {inherit pkgs lib;};
    qemuPatchSeries = import ./phase2-qemu-patch-series.nix {inherit pkgs lib;};
    qemuPatchRegeneration = import ./phase2-qemu-patch-regeneration.nix {inherit pkgs lib;};
    qemuRrQuantumIcount = import ./phase2-qemu-rr-quantum-icount.nix {inherit pkgs lib;};
    qemuLaunchValidation = import ./phase2-qemu-launch-validation.nix {inherit pkgs lib;};
    qemuNodeWrapper = import ./phase2-qemu-node-wrapper.nix {inherit pkgs lib;};
    qemuQmpClient = import ./phase2-qemu-qmp-client.nix {inherit pkgs lib;};
    qemuInjectionContract = import ./phase2-qemu-injection-contract.nix {inherit pkgs lib;};
    qemuQuantumShmem = import ./phase2-qemu-quantum-shmem.nix {inherit pkgs lib;};
    qemuRealization = import ./phase2-qemu-realization.nix {inherit pkgs lib;};
    qemuSavevmFallback = import ./phase2-qemu-savevm-fallback.nix {inherit pkgs lib;};
    qemuNvcpuFingerprint = import ./phase2-qemu-nvcpu-fingerprint.nix {inherit pkgs lib;};
    qemuShutdownEscalation = import ./phase2-qemu-shutdown-escalation.nix {inherit pkgs lib;};
    qemuSingleVmFingerprint = import ./phase2-qemu-single-vm-fingerprint.nix {inherit pkgs lib;};
    qemuSpawnFdPassing = import ./phase2-qemu-spawn-fd-passing.nix {inherit pkgs lib;};
    anyGuest = import ./phase2-any-guest.nix {inherit pkgs lib;};
    shmemRegionLayout = import ./phase2-shmem-region-layout.nix {inherit pkgs lib;};
    shmemGeneratedHeader = import ./phase2-shmem-generated-header.nix {inherit pkgs lib;};
    shmemAbiConformance = import ./phase2-shmem-abi-conformance.nix {inherit pkgs lib;};
    spscConcurrency = import ./phase2-spsc-concurrency.nix {inherit pkgs lib;};
    shmemSpscAbiConformance = import ./phase2-shmem-spsc-abi-conformance.nix {inherit pkgs lib;};
    shmemSnapshotRestore = import ./phase2-shmem-snapshot-restore.nix {inherit pkgs lib;};
    shmemHandoffFutex = import ./phase2-shmem-handoff-futex.nix {inherit pkgs lib;};
    shmemControlFlags = import ./phase2-shmem-control-flags.nix {inherit pkgs lib;};
    shmemMultiVcpuNodeSlot = import ./phase2-shmem-multi-vcpu-node-slot.nix {inherit pkgs lib;};
    shmemDeliverability = import ./phase2-shmem-deliverability.nix {inherit pkgs lib;};
    abiConformance = import ./phase2-abi-conformance.nix {inherit pkgs lib;};
    gates = let
      patchMicrotestsCheck = import ./phase2-patch-microtests.nix {
        inherit pkgs lib;
        attrPath = "checks.crucible.phase2.gates.patchMicrotests";
        taskIds = ["T-PLAN-3" "T-HARN-20" "T-PATCH-2" "T-PATCH-20" "T-PATCH-21"];
      };
    in {
      abiConformance = import ./phase2-abi-conformance.nix {
        inherit pkgs lib;
        attrPath = "checks.crucible.phase2.gates.abiConformance";
        taskIds = ["T-PLAN-3" "T-HARN-17" "T-API-11" "T-API-12"];
      };
      qemuInert = import ./phase2-qemu-inert.nix {
        inherit pkgs lib;
        attrPath = "checks.crucible.phase2.gates.qemuInert";
        taskIds = ["T-PLAN-3" "T-HARN-21" "T-PATCH-3"];
        patchMicrotests = patchMicrotestsCheck;
      };
      patchMicrotests = patchMicrotestsCheck;
      singleVmFingerprint = import ./phase1-single-vm-fingerprint-gate.nix {
        inherit pkgs lib;
        attrPath = "checks.crucible.phase2.gates.singleVmFingerprint";
        taskIds = ["T-PLAN-3" "T-HARN-7"];
      };
      anyGuest = import ./phase2-any-guest.nix {
        inherit pkgs lib;
        attrPath = "checks.crucible.phase2.gates.anyGuest";
        taskIds = ["T-PLAN-3" "T-DET-22" "T-HARN-16"];
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
      schedulerLiveness = import ./phase3-scheduler-liveness.nix {
        inherit pkgs lib;
        attrPath = "checks.crucible.phase3.gates.schedulerLiveness";
        taskIds = ["T-PLAN-3" "T-HARN-14"];
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
      e2eDeterminism = import ./phase4-e2e-determinism.nix {
        inherit pkgs lib;
        attrPath = "checks.crucible.phase4.gates.e2eDeterminism";
        taskIds = ["T-PLAN-3" "T-DET-26"];
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

{
  pkgs,
  lib,
}: let
  redGate = import ./red-gate-placeholder.nix {inherit pkgs;};
  greenBeforeAdvance = {
    attrPath,
    gate,
    dependencies,
  }: let
    gateSlug = builtins.replaceStrings [":" "." "/"] ["-" "-" "-"] attrPath;
  in
    (builtins.derivation {
      name = "crucible-green-before-advance-${gateSlug}-0";
      inherit (lib) system;
      builder = "${pkgs.bash}/bin/bash";
      args = [
        "-c"
        ''
          set -eu
          : "$GATE"
          : "$DEPENDENCY_PATHS"
          mkdir -p "$out"
          {
            printf 'PASS\n'
            printf 'green_before_advance=%s\n' "$ATTR_PATH"
            printf 'green_before_advance_dependency_count=%s\n' "$DEPENDENCY_COUNT"
          } > "$out/result"
        ''
      ];
      PATH = "${pkgs.coreutils}/bin";
      ATTR_PATH = attrPath;
      DEPENDENCY_COUNT = toString (builtins.length dependencies);
      DEPENDENCY_PATHS = builtins.concatStringsSep ":" dependencies;
      GATE = gate;
    })
    // {
      rawGate = gate;
      passthru.rawGate = gate;
    };
  redBeforeAdvance = {
    attrPath,
    gate,
    dependencies,
    phase,
    reason,
    taskIds,
    gateName ? "gate:single-vm-fingerprint",
    owner ? "crucible-qemu",
  }: let
    blocker = redGate {
      inherit attrPath phase reason taskIds;
      inherit gateName owner;
      dependencies = [gate] ++ dependencies;
    };
  in
    blocker
    // {
      rawGate = gate;
      passthru.rawGate = gate;
    };
in rec {
  phase0 = {
    gates = rec {
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
      harnessLint = greenBeforeAdvance {
        attrPath = "checks.crucible.phase0.gates.harnessLint";
        # lint needle: harnessLint = import ./phase1-harness-lint.nix
        gate = import ./phase1-harness-lint.nix {
          inherit pkgs lib;
          attrPath = "checks.crucible.phase0.gates.harnessLint";
          dependencies = [blockers];
        };
        dependencies = [blockers];
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
    s10Aarch64Doorbell = import ./phase0-s10.nix {inherit pkgs lib;};
    aarch64S1S6 = import ./phase0-aarch64-s1-s6.nix {inherit pkgs lib;};
    s11MultiVcpuFingerprint = import ./phase0-s11.nix {inherit pkgs lib;};
    s12PreemptionDecision = import ./phase0-s12.nix {inherit pkgs;};
    s13RrSwitchQuantumFallback = import ./phase0-s13.nix {inherit pkgs lib;};
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
    hostObservableSchedule = import ./phase1-host-observable-schedule.nix {inherit pkgs lib;};
    icountStampedInjection = import ./phase1-icount-stamped-injection.nix {inherit pkgs lib;};
    icountNoRealtime = import ./phase1-icount-no-realtime.nix {inherit pkgs lib;};
    kaslrAslrDefault = import ./phase1-kaslr-aslr-default.nix {inherit pkgs lib;};
    layer0Determinism = import ./phase1-layer0-determinism.nix {inherit pkgs lib;};
    layer1Injection = import ./phase1-layer1-injection.nix {inherit pkgs lib;};
    lookaheadGate = import ./phase1-lookahead-gate.nix {inherit pkgs lib;};
    noWarpWithPlugin = import ./phase1-no-warp-with-plugin.nix {inherit pkgs lib;};
    detRngDelivery = import ./phase1-qemu-det-rng-delivery.nix {inherit pkgs lib;};
    detVirtioIoeventfd = import ./phase1-qemu-det-virtio-ioeventfd.nix {inherit pkgs lib;};
    qemuDeterministicEntropy = import ./phase1-qemu-deterministic-entropy.nix {inherit pkgs lib;};
    qemuDeterministicGetrandom = import ./phase1-qemu-deterministic-getrandom.nix {inherit pkgs lib;};
    qemuMultiVcpuLaunch = import ./phase2-qemu-multi-vcpu-launch.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase1.qemuMultiVcpuLaunch";
      taskIds = ["T-DET-29"];
      openTaskIds = [];
    };
    qemuPluginPreemption = import ./phase2-plugin-preemption.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase1.qemuPluginPreemption";
      taskIds = ["T-PLUG-25"];
      openTaskIds = [];
    };
    qemuPluginAppRandomDoorbell = import ./phase2-plugin-app-random-doorbell.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase1.qemuPluginAppRandomDoorbell";
      taskIds = [];
      openTaskIds = [];
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
    phaseGateOrdering = import ./phase1-phase-gate-ordering.nix {inherit pkgs lib;};
    phaseGateWiring = import ./phase1-phase-gate-wiring.nix {inherit pkgs lib;};
    rfcConsistency = import ./phase1-rfc-consistency.nix {inherit pkgs lib;};
    rustdocBar = import ./phase1-rustdoc-bar.nix {inherit pkgs lib;};
    sameIcountTieBreak = import ./phase1-same-icount-tie-break.nix {inherit pkgs lib;};
    simDouble = import ./phase1-sim-double.nix {inherit pkgs lib;};
    singleVmFingerprint = import ./phase1-single-vm-fingerprint-gate.nix {inherit pkgs lib;};
    singleSchedulerBoundary = import ./phase1-single-scheduler-boundary.nix {inherit pkgs lib;};
    spatialComponentAddressing = import ./phase1-spatial-component-addressing.nix {inherit pkgs lib;};
    spatialLayerOrthogonality = import ./phase1-spatial-layer-orthogonality.nix {inherit pkgs lib;};
    spatialLinkTransport = import ./phase1-spatial-link-transport.nix {inherit pkgs lib;};
    spatialLogicalTopology = import ./phase1-spatial-logical-topology.nix {inherit pkgs lib;};
    spatialMembershipFaults = import ./phase1-spatial-membership-faults.nix {inherit pkgs lib;};
    spatialCanonicalization = import ./phase1-spatial-canonicalization.nix {inherit pkgs lib;};
    spatialNodeLaunchInputs = import ./phase1-spatial-node-launch-inputs.nix {inherit pkgs lib;};
    spatialPlanComponent = import ./phase1-spatial-plan-component.nix {inherit pkgs lib;};
    spatialPlanValidation = import ./phase1-spatial-plan-validation.nix {inherit pkgs lib;};
    spatialPropertiesComponent = import ./phase1-spatial-properties-component.nix {inherit pkgs lib;};
    spatialReproductionArtifact = import ./phase1-spatial-reproduction-artifact.nix {inherit pkgs lib;};
    spatialScenarioFamily = import ./phase1-spatial-scenario-family.nix {inherit pkgs lib;};
    spatialScenarioBuilder = import ./phase1-spatial-scenario-builder.nix {inherit pkgs lib;};
    spatialScenarioDefValue = import ./phase1-spatial-scenario-def-value.nix {inherit pkgs lib;};
    spatialSeedComponent = import ./phase1-spatial-seed-component.nix {inherit pkgs lib;};
    spatialSerializableForm = import ./phase1-spatial-serializable-form.nix {inherit pkgs lib;};
    spatialStaticTopology = import ./phase1-spatial-static-topology.nix {inherit pkgs lib;};
    spatialValidationPass = import ./phase1-spatial-validation-pass.nix {inherit pkgs lib;};
    spatialWorldTopology = import ./phase1-spatial-world-topology.nix {inherit pkgs lib;};
    standaloneDependencies = import ./phase1-standalone-dependencies.nix {inherit pkgs lib;};
    testingStandards = import ./phase1-testing-standards.nix {inherit pkgs lib;};
    timeClockSkew = import ./phase1-time-clock-skew.nix {inherit pkgs lib;};
    timeContractADeterminism = import ./phase1-time-contract-a-determinism.nix {inherit pkgs lib;};
    timeMultiVcpuAggregateClock = import ./phase1-time-multi-vcpu-aggregate-clock.nix {inherit pkgs lib;};
    timeNoRealtimeWarp = import ./phase1-time-no-realtime-warp.nix {inherit pkgs lib;};
    timeAdvanceCeiling = import ./phase1-time-advance-ceiling.nix {inherit pkgs lib;};
    timeSharedTimeline = import ./phase1-time-shared-timeline.nix {inherit pkgs lib;};
    timeVocabulary = import ./phase1-time-vocabulary.nix {inherit pkgs lib;};
    gates = rec {
      harnessLint = greenBeforeAdvance {
        attrPath = "checks.crucible.phase1.gates.harnessLint";
        # lint needle: harnessLint = import ./phase1-harness-lint.nix
        gate = import ./phase1-harness-lint.nix {
          inherit pkgs lib;
          attrPath = "checks.crucible.phase1.gates.harnessLint";
          dependencies = [phase0.gates.blockers phase0.gates.harnessLint.rawGate];
        };
        dependencies = [phase0.gates.blockers phase0.gates.harnessLint];
      };
      hostObservableSchedule = greenBeforeAdvance {
        attrPath = "checks.crucible.phase1.gates.hostObservableSchedule";
        # lint needle: hostObservableSchedule = import ./phase1-host-observable-schedule.nix
        gate = import ./phase1-host-observable-schedule.nix {
          inherit pkgs lib;
          attrPath = "checks.crucible.phase1.gates.hostObservableSchedule";
          taskIds = ["T-HARN-4"];
          dependencies = [harnessLint.rawGate];
        };
        dependencies = [harnessLint];
      };
      layer0Determinism = greenBeforeAdvance {
        attrPath = "checks.crucible.phase1.gates.layer0Determinism";
        # lint needle: layer0Determinism = import ./phase1-layer0-determinism.nix
        gate = import ./phase1-layer0-determinism.nix {
          inherit pkgs lib;
          attrPath = "checks.crucible.phase1.gates.layer0Determinism";
          dependencies = [harnessLint.rawGate];
          taskIds = [
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
            "T-DET-8"
            "T-DET-9"
            "T-DET-10"
            "T-TIME-9"
          ];
          openTaskIds = [];
        };
        dependencies = [harnessLint];
      };
      contentAddress = greenBeforeAdvance {
        attrPath = "checks.crucible.phase1.gates.contentAddress";
        # lint needle: contentAddress = import ./phase1-content-address.nix
        gate = import ./phase1-content-address.nix {
          inherit pkgs lib;
          attrPath = "checks.crucible.phase1.gates.contentAddress";
          taskIds = ["T-ASRT-17" "T-HARN-11" "T-PAT-4" "T-TEMP-1" "T-TEMP-2" "T-TEMP-3" "T-TEMP-6" "T-TEMP-8" "T-TEMP-9" "T-TEMP-10" "T-TEMP-11"];
          dependencies = [layer0Determinism.rawGate];
        };
        dependencies = [layer0Determinism];
      };
      replayOracle = greenBeforeAdvance {
        attrPath = "checks.crucible.phase1.gates.replayOracle";
        # lint needle: replayOracle = import ./phase1-replay-oracle.nix
        gate = import ./phase1-replay-oracle.nix {
          inherit pkgs lib;
          attrPath = "checks.crucible.phase1.gates.replayOracle";
          dependencies = [contentAddress.rawGate phase1.simDouble];
          taskIds = [
            "T-DET-18"
            "T-DET-21"
            "T-DET-27"
            "T-HARN-12"
            "T-HARN-13"
            "T-EXEC-4"
            "T-EXEC-11"
            "T-PAT-4"
            "T-TEMP-3"
            "T-TEMP-4"
            "T-TEMP-5"
            "T-TEMP-7"
            "T-TEMP-9"
            "T-TEMP-11"
          ];
        };
        dependencies = [contentAddress phase1.simDouble];
      };
      singleVmFingerprint = greenBeforeAdvance {
        attrPath = "checks.crucible.phase1.gates.singleVmFingerprint";
        # lint needle: singleVmFingerprint = import ./phase1-single-vm-fingerprint-gate.nix
        gate = import ./phase1-single-vm-fingerprint-gate.nix {
          inherit pkgs lib;
          attrPath = "checks.crucible.phase1.gates.singleVmFingerprint";
          taskIds = ["T-ASRT-18" "T-DET-9" "T-EXEC-17" "T-EXEC-18" "T-PAT-9"];
          dependencies = [replayOracle.rawGate phase1.simDouble];
        };
        dependencies = [replayOracle phase1.simDouble];
      };
      divergenceBisect = greenBeforeAdvance {
        attrPath = "checks.crucible.phase1.gates.divergenceBisect";
        # lint needle: divergenceBisect = import ./phase1-divergence-bisect.nix
        gate = import ./phase1-divergence-bisect.nix {
          inherit pkgs lib;
          attrPath = "checks.crucible.phase1.gates.divergenceBisect";
          dependencies = [singleVmFingerprint.rawGate phase1.simDouble];
          taskIds = [
            "T-DET-20"
            "T-HARN-9"
            "T-HARN-10"
            "T-HARN-13"
            "T-EXEC-12"
          ];
        };
        dependencies = [singleVmFingerprint phase1.simDouble];
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
    qemuDeviceCompletionAdvance = import ./phase2-qemu-device-completion-advance.nix {inherit pkgs lib;};
    qemu9pSyncKick = import ./phase2-qemu-9p-sync-kick.nix {inherit pkgs lib;};
    qemuWhiteboxGuestWrite = import ./phase2-qemu-whitebox-guest-write.nix {inherit pkgs lib;};
    qemuPatchRegeneration = import ./phase2-qemu-patch-regeneration.nix {inherit pkgs lib;};
    qemuRawStateExport = import ./phase2-qemu-raw-state-export.nix {inherit pkgs lib;};
    qemuRrQuantumIcount = import ./phase2-qemu-rr-quantum-icount.nix {inherit pkgs lib;};
    qemuDetIpi = import ./phase2-qemu-det-ipi.nix {inherit pkgs lib;};
    qemuVcpuIntrospect = import ./phase2-qemu-vcpu-introspect.nix {inherit pkgs lib;};
    qemuPreemptionInject = import ./phase2-qemu-preemption-inject.nix {inherit pkgs lib;};
    qemuLaunchValidation = import ./phase2-qemu-launch-validation.nix {inherit pkgs lib;};
    qemuNodeFactory = import ./phase2-qemu-node-factory.nix {inherit pkgs lib;};
    qemuNodeWrapper = import ./phase2-qemu-node-wrapper.nix {inherit pkgs lib;};
    qemuQmpClient = import ./phase2-qemu-qmp-client.nix {inherit pkgs lib;};
    qemuInjectionContract = import ./phase2-qemu-injection-contract.nix {inherit pkgs lib;};
    qemuQuantumShmem = import ./phase2-qemu-quantum-shmem.nix {inherit pkgs lib;};
    qemuRealization = import ./phase2-qemu-realization.nix {inherit pkgs lib;};
    qemuSavevmFallback = import ./phase2-qemu-savevm-fallback.nix {inherit pkgs lib;};
    qemuNvcpuFingerprint = import ./phase2-qemu-nvcpu-fingerprint.nix {inherit pkgs lib;};
    qemuLiveGenesisExecutor = import ./phase2-qemu-live-genesis-executor.nix {inherit pkgs lib;};
    qemuLivePluginInstall = import ./phase2-qemu-live-plugin-install.nix {inherit pkgs lib;};
    qemuLiveWhiteboxDoorbell = import ./phase2-qemu-live-whitebox-doorbell.nix {inherit pkgs lib;};
    qemuLiveBlockRealization = import ./phase2-qemu-live-block-realization.nix {inherit pkgs lib;};
    qemuLiveNodeStep = import ./phase2-qemu-live-node-step.nix {inherit pkgs lib;};
    qemuLiveBlockIo = import ./phase2-qemu-live-block-io.nix {inherit pkgs lib;};
    qemuLive9pIo = import ./phase2-qemu-live-9p-io.nix {inherit pkgs lib;};
    qemuLiveNetworkIo = import ./phase2-qemu-live-network-io.nix {inherit pkgs lib;};
    qemuLivePluginQuantum = import ./phase2-qemu-live-plugin-quantum.nix {inherit pkgs lib;};
    qemuLivePluginQuantumSmp = import ./phase2-qemu-live-plugin-quantum-smp.nix {inherit pkgs lib;};
    qemuLivePluginPreemption = import ./phase2-qemu-live-plugin-preemption.nix {inherit pkgs lib;};
    qemuLivePluginFingerprint = import ./phase2-qemu-live-plugin-fingerprint.nix {inherit pkgs lib;};
    qemuLivePluginFingerprintSmp = import ./phase2-qemu-live-plugin-fingerprint-smp.nix {inherit pkgs lib;};
    qemuLiveTerminalHorizon = import ./phase2-qemu-live-terminal-horizon.nix {inherit pkgs lib;};
    qemuLiveTerminalTargets = import ./phase2-qemu-live-terminal-targets.nix {inherit pkgs lib;};
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
    gates = rec {
      abiConformance = greenBeforeAdvance {
        attrPath = "checks.crucible.phase2.gates.abiConformance";
        # lint needle: abiConformance = import ./phase2-abi-conformance.nix
        gate = import ./phase2-abi-conformance.nix {
          inherit pkgs lib;
          attrPath = "checks.crucible.phase2.gates.abiConformance";
          taskIds = ["T-HARN-17" "T-API-11" "T-API-12" "T-PAT-8"];
          dependencies = [
            phase1.gates.harnessLint.rawGate
            phase1.gates.layer0Determinism.rawGate
            phase1.gates.contentAddress.rawGate
            phase1.gates.replayOracle.rawGate
            phase1.gates.singleVmFingerprint.rawGate
            phase1.gates.divergenceBisect.rawGate
          ];
        };
        dependencies = [
          phase1.gates.harnessLint
          phase1.gates.layer0Determinism
          phase1.gates.contentAddress
          phase1.gates.replayOracle
          phase1.gates.singleVmFingerprint
          phase1.gates.divergenceBisect
        ];
      };
      layer1Injection = greenBeforeAdvance {
        attrPath = "checks.crucible.phase2.gates.layer1Injection";
        # lint needle: layer1Injection = import ./phase1-layer1-injection.nix
        gate = import ./phase1-layer1-injection.nix {
          inherit pkgs lib;
          attrPath = "checks.crucible.phase2.gates.layer1Injection";
          taskIds = ["T-HARN-8" "T-DET-11" "T-DET-12" "T-DET-13" "T-DET-14"];
          dependencies = [abiConformance.rawGate];
        };
        dependencies = [abiConformance];
      };
      patchMicrotests = greenBeforeAdvance {
        attrPath = "checks.crucible.phase2.gates.patchMicrotests";
        # lint needle: patchMicrotests = import ./phase2-patch-microtests.nix
        gate = import ./phase2-patch-microtests.nix {
          inherit pkgs lib;
          attrPath = "checks.crucible.phase2.gates.patchMicrotests";
          taskIds = ["T-PKG-4" "T-HARN-20" "T-PATCH-2" "T-PATCH-20" "T-PATCH-21" "T-PATCH-22" "T-PATCH-23" "T-PATCH-24"];
          openTaskIds = [];
          dependencies = [layer1Injection.rawGate];
        };
        dependencies = [layer1Injection];
      };
      qemuInert = greenBeforeAdvance {
        attrPath = "checks.crucible.phase2.gates.qemuInert";
        # lint needle: qemuInert = import ./phase2-qemu-inert.nix
        gate = import ./phase2-qemu-inert.nix {
          inherit pkgs lib;
          attrPath = "checks.crucible.phase2.gates.qemuInert";
          taskIds = ["T-DET-23" "T-HARN-21" "T-PATCH-3"];
          openTaskIds = [];
          patchMicrotests = patchMicrotests.rawGate;
          dependencies = [patchMicrotests.rawGate];
        };
        dependencies = [patchMicrotests];
      };
      singleVmFingerprint = greenBeforeAdvance {
        attrPath = "checks.crucible.phase2.gates.singleVmFingerprint";
        # lint needle: singleVmFingerprint = import ./phase1-single-vm-fingerprint-gate.nix
        # Canonical ordering dependency is qemu-inert only (the phase4
        # channel-wiring gate pins `qemuInert -> singleVmFingerprint -> anyGuest`);
        # the certifying evidence gates ride on the outer greenBeforeAdvance
        # dependencies, where they are still forced to build. Certified by the
        # live Rust-plugin fingerprint authority (phase2.qemuLivePluginFingerprint)
        # in addition to the diagnostic C-trace importer
        # (phase2.qemuSingleVmFingerprint): T-DET-8, T-HARN-7, T-QEMU-11,
        # T-QEMU-16, T-TIME-8.
        gate = import ./phase1-single-vm-fingerprint-gate.nix {
          inherit pkgs lib;
          attrPath = "checks.crucible.phase2.gates.singleVmFingerprint";
          taskIds = [];
          dependencies = [qemuInert.rawGate];
        };
        dependencies = [qemuInert phase2.qemuSingleVmFingerprint phase2.qemuLivePluginFingerprint];
      };
      anyGuest = greenBeforeAdvance {
        attrPath = "checks.crucible.phase2.gates.anyGuest";
        # lint needle: anyGuest = import ./phase2-any-guest.nix
        gate = import ./phase2-any-guest.nix {
          inherit pkgs lib;
          attrPath = "checks.crucible.phase2.gates.anyGuest";
          taskIds = ["T-DET-22" "T-HARN-16"];
          dependencies = [singleVmFingerprint.rawGate];
        };
        dependencies = [singleVmFingerprint];
      };
    };
  };
  phase3 = {
    schedulerActor = import ./phase3-scheduler-actor.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase3.schedulerActor";
      taskIds = ["T-SCHED-1"];
    };
    schedulerLookahead = import ./phase3-scheduler-lookahead.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase3.schedulerLookahead";
      taskIds = ["T-SCHED-2"];
    };
    schedulerConservativePdes = import ./phase3-scheduler-conservative-pdes.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase3.schedulerConservativePdes";
      taskIds = ["T-SCHED-3"];
    };
    schedulerHorizon = import ./phase3-scheduler-horizon.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase3.schedulerHorizon";
      taskIds = ["T-SCHED-5"];
    };
    schedulerExactLocalEvent = import ./phase3-scheduler-exact-local-event.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase3.schedulerExactLocalEvent";
      taskIds = ["T-SCHED-6"];
    };
    schedulerRendezvous = import ./phase3-scheduler-rendezvous.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase3.schedulerRendezvous";
      taskIds = ["T-SCHED-7"];
    };
    schedulerEventOrder = import ./phase3-scheduler-event-order.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase3.schedulerEventOrder";
      taskIds = ["T-SCHED-8"];
    };
    schedulerOrderingLint = import ./phase3-scheduler-ordering-lint.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase3.schedulerOrderingLint";
      taskIds = ["T-SCHED-9"];
    };
    schedulerLinkLatencyFloor = import ./phase3-scheduler-link-latency-floor.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase3.schedulerLinkLatencyFloor";
      taskIds = ["T-SCHED-10"];
    };
    schedulerQuiescence = import ./phase3-scheduler-quiescence.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase3.schedulerQuiescence";
      taskIds = ["T-SCHED-11"];
    };
    schedulerQuantumLoop = import ./phase3-scheduler-quantum-loop.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase3.schedulerQuantumLoop";
      taskIds = ["T-SCHED-12"];
    };
    schedulerEffectiveHorizon = import ./phase3-scheduler-effective-horizon.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase3.schedulerEffectiveHorizon";
      taskIds = ["T-SCHED-13"];
    };
    schedulerRunCeiling = import ./phase3-scheduler-run-ceiling.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase3.schedulerRunCeiling";
      taskIds = ["T-SCHED-14"];
    };
    schedulerIdleFastForward = import ./phase3-scheduler-idle-fast-forward.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase3.schedulerIdleFastForward";
      taskIds = ["T-SCHED-15"];
    };
    schedulerResolve = import ./phase3-scheduler-resolve.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase3.schedulerResolve";
      taskIds = ["T-SCHED-16"];
    };
    schedulerResolveRng = import ./phase3-scheduler-resolve-rng.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase3.schedulerResolveRng";
      taskIds = ["T-SCHED-17"];
    };
    schedulerLateDelivery = import ./phase3-scheduler-late-delivery.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase3.schedulerLateDelivery";
      taskIds = ["T-SCHED-18"];
    };
    schedulerEmitStep = import ./phase3-scheduler-emit-step.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase3.schedulerEmitStep";
      taskIds = ["T-SCHED-19"];
    };
    schedulerQuantumPattern = import ./phase3-scheduler-quantum-pattern.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase3.schedulerQuantumPattern";
      taskIds = ["T-PAT-2"];
    };
    schedulerIcountCeiling = import ./phase3-scheduler-icount-ceiling.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase3.schedulerIcountCeiling";
      taskIds = ["T-SCHED-20"];
    };
    schedulerWakeOrdering = import ./phase3-scheduler-wake-ordering.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase3.schedulerWakeOrdering";
      taskIds = ["T-SCHED-21"];
    };
    schedulerTopologyChange = import ./phase3-scheduler-topology-change.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase3.schedulerTopologyChange";
      taskIds = ["T-SCHED-22"];
    };
    schedulerPartitionHeal = import ./phase3-scheduler-partition-heal.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase3.schedulerPartitionHeal";
      taskIds = ["T-SCHED-23"];
    };
    schedulerTopologyRendezvous = import ./phase3-scheduler-topology-rendezvous.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase3.schedulerTopologyRendezvous";
      taskIds = ["T-SCHED-24"];
    };
    schedulerConcurrency = import ./phase3-scheduler-concurrency.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase3.schedulerConcurrency";
      taskIds = ["T-SCHED-25"];
    };
    schedulerRendezvousPurpose = import ./phase3-scheduler-rendezvous-purpose.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase3.schedulerRendezvousPurpose";
      taskIds = ["T-SCHED-26"];
    };
    schedulerControlResponsive = import ./phase3-scheduler-control-responsive.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase3.schedulerControlResponsive";
      taskIds = ["T-SCHED-27"];
    };
    schedulerRrSubdivision = import ./phase3-scheduler-rr-subdivision.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase3.schedulerRrSubdivision";
      taskIds = ["T-SCHED-28"];
    };
    schedulerPreemptionResolve = import ./phase3-scheduler-preemption-resolve.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase3.schedulerPreemptionResolve";
      taskIds = ["T-SCHED-29"];
    };
    schedulerAllVcpusIdle = import ./phase3-scheduler-all-vcpus-idle.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase3.schedulerAllVcpusIdle";
      taskIds = ["T-SCHED-30"];
    };
    blockWireAbi = import ./phase3-block-wire-abi.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase3.blockWireAbi";
      taskIds = ["T-IO-3"];
    };
    blockCowOverlayPattern = import ./phase3-block-cow-overlay-pattern.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase3.blockCowOverlayPattern";
      taskIds = ["T-IO-2" "T-IO-5" "T-PAT-7"];
    };
    gates = rec {
      layer1Injection = greenBeforeAdvance {
        attrPath = "checks.crucible.phase3.gates.layer1Injection";
        # lint needle: layer1Injection = import ./phase1-layer1-injection.nix
        gate = import ./phase1-layer1-injection.nix {
          inherit pkgs lib;
          attrPath = "checks.crucible.phase3.gates.layer1Injection";
          taskIds = ["T-HARN-8" "T-DET-11" "T-DET-12" "T-DET-13" "T-DET-14"];
          dependencies = [phase2.gates.anyGuest.rawGate];
        };
        dependencies = [phase2.gates.anyGuest];
      };
      schedulerLiveness = greenBeforeAdvance {
        attrPath = "checks.crucible.phase3.gates.schedulerLiveness";
        # lint needle: schedulerLiveness = import ./phase3-scheduler-liveness.nix
        gate = import ./phase3-scheduler-liveness.nix {
          inherit pkgs lib;
          attrPath = "checks.crucible.phase3.gates.schedulerLiveness";
          taskIds = ["T-HARN-14" "T-SCHED-4"];
          dependencies = [layer1Injection.rawGate];
        };
        dependencies = [layer1Injection];
      };
      adversarialDeterminism = greenBeforeAdvance {
        attrPath = "checks.crucible.phase3.gates.adversarialDeterminism";
        # lint needle: adversarialDeterminism = import ./phase3-adversarial-determinism.nix
        gate = import ./phase3-adversarial-determinism.nix {
          inherit pkgs lib;
          attrPath = "checks.crucible.phase3.gates.adversarialDeterminism";
          taskIds = ["T-HARN-22"];
          dependencies = [schedulerLiveness.rawGate];
        };
        dependencies = [schedulerLiveness];
      };
    };
  };
  phase4 = {
    eventGraphControlFlow = import ./phase4-event-graph-control-flow.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.eventGraphControlFlow";
      taskIds = ["T-TRIG-1"];
    };
    sharedConditionVocabulary = import ./phase4-shared-condition-vocabulary.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.sharedConditionVocabulary";
      taskIds = ["T-TRIG-2"];
    };
    timeConditionLeaves = import ./phase4-time-condition-leaves.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.timeConditionLeaves";
      taskIds = ["T-TRIG-3"];
    };
    observableConditionLeaves = import ./phase4-observable-condition-leaves.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.observableConditionLeaves";
      taskIds = ["T-TRIG-4"];
    };
    coverageConditionLeaf = import ./phase4-coverage-condition-leaf.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.coverageConditionLeaf";
      taskIds = ["T-TRIG-5"];
    };
    memoryConditionLeaf = import ./phase4-memory-condition-leaf.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.memoryConditionLeaf";
      taskIds = ["T-TRIG-6"];
    };
    assertionQuiescenceLeaves = import ./phase4-assertion-quiescence-leaves.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.assertionQuiescenceLeaves";
      taskIds = ["T-TRIG-7"];
    };
    guestMarkerLeaf = import ./phase4-guest-marker-leaf.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.guestMarkerLeaf";
      taskIds = ["T-TRIG-8"];
    };
    compoundConditionCombinators = import ./phase4-compound-condition-combinators.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.compoundConditionCombinators";
      taskIds = ["T-TRIG-9"];
    };
    deterministicConditionEvaluation = import ./phase4-deterministic-condition-evaluation.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.deterministicConditionEvaluation";
      taskIds = ["T-TRIG-10"];
    };
    triggerFiringCausalLog = import ./phase4-trigger-firing-causal-log.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.triggerFiringCausalLog";
      taskIds = ["T-TRIG-11"];
    };
    triggerActionApplication = import ./phase4-trigger-action-application.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.triggerActionApplication";
      taskIds = ["T-TRIG-12"];
    };
    triggerNodeScheduling = import ./phase4-trigger-node-scheduling.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.triggerNodeScheduling";
      taskIds = ["T-TRIG-13"];
    };
    triggerRelativeTimers = import ./phase4-trigger-relative-timers.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.triggerRelativeTimers";
      taskIds = ["T-TRIG-14"];
    };
    triggerGraphValidator = import ./phase4-trigger-graph-validator.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.triggerGraphValidator";
      taskIds = ["T-TRIG-15"];
    };
    triggerPlanLowering = import ./phase4-trigger-plan-lowering.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.triggerPlanLowering";
      taskIds = ["T-TRIG-16"];
    };
    triggerVerdictComposition = import ./phase4-trigger-verdict-composition.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.triggerVerdictComposition";
      taskIds = ["T-TRIG-17"];
    };
    eventGraphSerialization = import ./phase4-event-graph-serialization.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.eventGraphSerialization";
      taskIds = ["T-TRIG-18"];
    };
    blackBoxFirstGuarantee = import ./phase4-black-box-first-guarantee.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.blackBoxFirstGuarantee";
      taskIds = ["T-TRIG-19"];
    };
    faultTaxonomy = import ./phase4-fault-taxonomy.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.faultTaxonomy";
      taskIds = ["T-FAULT-1"];
    };
    faultModelRule = import ./phase4-fault-model-rule.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.faultModelRule";
      taskIds = ["T-FAULT-2"];
    };
    faultDecisionRng = import ./phase4-fault-decision-rng.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.faultDecisionRng";
      taskIds = ["T-FAULT-3"];
    };
    faultIntegerRates = import ./phase4-fault-integer-rates.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.faultIntegerRates";
      taskIds = ["T-FAULT-4"];
    };
    faultCombination = import ./phase4-fault-combination.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.faultCombination";
      taskIds = ["T-FAULT-5"];
    };
    networkFaultApplication = import ./phase4-network-fault-application.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.networkFaultApplication";
      taskIds = ["T-FAULT-6"];
    };
    nodeFaultApplication = import ./phase4-node-fault-application.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.nodeFaultApplication";
      taskIds = ["T-FAULT-7"];
    };
    nodeCrashApplication = import ./phase4-node-crash-application.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.nodeCrashApplication";
      taskIds = ["T-FAULT-8"];
    };
    ioFaultApplication = import ./phase4-io-fault-application.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.ioFaultApplication";
      taskIds = ["T-FAULT-9"];
    };
    faultPlan = import ./phase4-fault-plan.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.faultPlan";
      taskIds = ["T-FAULT-10"];
    };
    imperativeFaultControl = import ./phase4-imperative-fault-control.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.imperativeFaultControl";
      taskIds = ["T-FAULT-11"];
    };
    faultTagState = import ./phase4-fault-tag-state.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.faultTagState";
      taskIds = ["T-FAULT-12"];
    };
    activeFaultTable = import ./phase4-active-fault-table.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.activeFaultTable";
      taskIds = ["T-FAULT-13"];
    };
    randomFaultConfig = import ./phase4-random-fault-config.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.randomFaultConfig";
      taskIds = ["T-FAULT-14"];
    };
    faultDeterminismGate = import ./phase4-fault-determinism-gate.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.faultDeterminismGate";
      taskIds = ["T-FAULT-15"];
    };
    faultTestDoubleGate = import ./phase4-fault-test-double-gate.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.faultTestDoubleGate";
      taskIds = ["T-FAULT-16"];
    };
    propertyVocabulary = import ./phase4-property-vocabulary.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.propertyVocabulary";
      taskIds = ["T-ASRT-1"];
    };
    propertyFingerprintNeutrality = import ./phase4-property-fingerprint-neutrality.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.propertyFingerprintNeutrality";
      taskIds = ["T-ASRT-2"];
    };
    propertyConfiguration = import ./phase4-property-configuration.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.propertyConfiguration";
      taskIds = ["T-ASRT-3"];
    };
    observedStateMaterialization = import ./phase4-observed-state-materialization.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.observedStateMaterialization";
      taskIds = ["T-ASRT-4"];
    };
    hostSideAssertions = import ./phase4-host-side-assertions.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.hostSideAssertions";
      taskIds = ["T-ASRT-5"];
    };
    guestMarkerAssertions = import ./phase4-guest-marker-assertions.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.guestMarkerAssertions";
      taskIds = ["T-ASRT-6"];
    };
    offlineAssertionChecker = import ./phase4-offline-assertion-checker.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.offlineAssertionChecker";
      taskIds = ["T-ASRT-7"];
    };
    assertionLogFold = import ./phase4-assertion-log-fold.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.assertionLogFold";
      taskIds = ["T-ASRT-8"];
    };
    formalTraceExport = import ./phase4-formal-trace-export.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.formalTraceExport";
      taskIds = ["T-ASRT-9"];
    };
    assertionEvaluationTiming = import ./phase4-assertion-evaluation-timing.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.assertionEvaluationTiming";
      taskIds = ["T-ASRT-10"];
    };
    assertionEvaluationOrder = import ./phase4-assertion-evaluation-order.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.assertionEvaluationOrder";
      taskIds = ["T-ASRT-11"];
    };
    assertionLifecycle = import ./phase4-assertion-lifecycle.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.assertionLifecycle";
      taskIds = ["T-ASRT-12"];
    };
    assertionDeterminismNonPerturbation = import ./phase4-assertion-determinism-nonperturbation.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.assertionDeterminismNonPerturbation";
      taskIds = ["T-ASRT-13"];
    };
    assertionViolationRecords = import ./phase4-assertion-violation-records.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.assertionViolationRecords";
      taskIds = ["T-ASRT-14"];
    };
    assertionViolationReproduction = import ./phase4-assertion-violation-reproduction.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.assertionViolationReproduction";
      taskIds = ["T-ASRT-15"];
    };
    assertionProximityGradient = import ./phase4-assertion-proximity-gradient.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.assertionProximityGradient";
      taskIds = ["T-ASRT-18"];
    };
    eventLogUnified = import ./phase4-event-log-unified.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.eventLogUnified";
      taskIds = ["T-OBS-1"];
    };
    eventLogSchema = import ./phase4-event-log-schema.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.eventLogSchema";
      taskIds = ["T-OBS-2"];
    };
    eventLogPayload = import ./phase4-event-log-payload.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.eventLogPayload";
      taskIds = ["T-OBS-3"];
    };
    eventLogClassCatalog = import ./phase4-event-log-class-catalog.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.eventLogClassCatalog";
      taskIds = ["T-OBS-4"];
    };
    eventLogContentAddress = import ./phase4-event-log-content-address.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.eventLogContentAddress";
      taskIds = ["T-OBS-5"];
    };
    eventLogDeterminism = import ./phase4-event-log-determinism.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.eventLogDeterminism";
      taskIds = ["T-OBS-6"];
    };
    eventLogAssertionFold = import ./phase4-event-log-assertion-fold.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.eventLogAssertionFold";
      taskIds = ["T-OBS-7"];
    };
    eventLogDivergenceBisect = import ./phase4-event-log-divergence-bisect.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.eventLogDivergenceBisect";
      taskIds = ["T-OBS-8"];
    };
    eventLogCoverage = import ./phase4-event-log-coverage.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.eventLogCoverage";
      taskIds = ["T-OBS-9"];
    };
    eventLogReproductionArtifact = import ./phase4-event-log-reproduction-artifact.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.eventLogReproductionArtifact";
      taskIds = ["T-OBS-10"];
    };
    eventLogControlPlaneStreaming = import ./phase4-event-log-control-plane-streaming.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.eventLogControlPlaneStreaming";
      taskIds = ["T-OBS-11"];
    };
    eventLogTracingBridge = import ./phase4-event-log-tracing-bridge.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.eventLogTracingBridge";
      taskIds = ["T-OBS-12"];
    };
    eventKindCatalogFreeze = import ./phase4-event-kind-catalog-freeze.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.eventKindCatalogFreeze";
      taskIds = ["T-OBS-13"];
    };
    eventLogAssertionProximity = import ./phase4-event-log-assertion-proximity.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.eventLogAssertionProximity";
      taskIds = ["T-OBS-14"];
    };
    guestHostBlackBoxSurface = import ./phase4-guest-host-black-box-surface.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.guestHostBlackBoxSurface";
      taskIds = ["T-GHC-1"];
    };
    guestHostOsAgnostic = import ./phase4-guest-host-os-agnostic.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.guestHostOsAgnostic";
      taskIds = ["T-GHC-2"];
    };
    guestHostReadiness = import ./phase4-guest-host-readiness.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.guestHostReadiness";
      taskIds = ["T-GHC-3"];
    };
    guestHostDoorbell = import ./phase4-guest-host-doorbell.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.guestHostDoorbell";
      taskIds = ["T-GHC-4"];
      openTaskIds = [];
    };
    guestHostDoorbellAbi = import ./phase4-guest-host-doorbell-abi.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.guestHostDoorbellAbi";
      taskIds = ["T-GHC-5"];
    };
    guestHostDoorbellCollisionInertness = import ./phase4-guest-host-doorbell-collision-inertness.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.guestHostDoorbellCollisionInertness";
      taskIds = ["T-GHC-6"];
      openTaskIds = [];
    };
    guestHostDoorbellFrame = import ./phase4-guest-host-doorbell-frame.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.guestHostDoorbellFrame";
      taskIds = ["T-GHC-7"];
    };
    guestHostMarkerVocabulary = import ./phase4-guest-host-marker-vocabulary.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.guestHostMarkerVocabulary";
      taskIds = ["T-GHC-8"];
    };
    guestHostMarkerObservability = import ./phase4-guest-host-marker-observability.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.guestHostMarkerObservability";
      taskIds = ["T-GHC-9"];
      openTaskIds = [];
    };
    guestHostEmitter = import ./phase4-guest-host-emitter.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.guestHostEmitter";
      taskIds = ["T-GHC-10"];
    };
    guestHostEmitterAbsence = import ./phase4-guest-host-emitter-absence.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.guestHostEmitterAbsence";
      taskIds = ["T-GHC-11"];
    };
    guestHostChannelDeterminism = import ./phase4-guest-host-channel-determinism.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.guestHostChannelDeterminism";
      taskIds = [];
      openTaskIds = ["T-GHC-12"];
    };
    guestHostVirtualMemorySpike = import ./phase4-guest-host-virtual-memory-spike.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.guestHostVirtualMemorySpike";
      taskIds = ["T-GHC-13"];
      phase0S5 = phase0.s5VirtualMemory;
    };
    guestHostDecoderHardening = import ./phase4-guest-host-decoder-hardening.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.guestHostDecoderHardening";
      taskIds = ["T-GHC-14"];
    };
    guestHostChannelGateWiring = import ./phase4-guest-host-channel-gate-wiring.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.guestHostChannelGateWiring";
      taskIds = ["T-GHC-15"];
      openTaskIds = [];
      qemuLiveWhiteboxDoorbell = phase2.qemuLiveWhiteboxDoorbell;
      qemuWhiteboxGuestWrite = phase2.qemuWhiteboxGuestWrite;
    };
    guestHostAppRandomDoorbell = import ./phase4-guest-host-app-random-doorbell.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.guestHostAppRandomDoorbell";
      taskIds = [];
      openTaskIds = ["T-GHC-16"];
      phase0S5 = phase0.s5VirtualMemory;
    };
    guestHostAppRandomCap = import ./phase4-guest-host-app-random-cap.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.guestHostAppRandomCap";
      taskIds = ["T-GHC-17"];
    };
    workloadModel = import ./phase4-workload-model.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.workloadModel";
      taskIds = ["T-WL-1"];
    };
    workloadEntropyBoundary = import ./phase4-workload-entropy-boundary.nix {
      inherit pkgs lib;
      phase1GuestEntropyLaunch = phase1.guestEntropyLaunch;
      attrPath = "checks.crucible.phase4.workloadEntropyBoundary";
      taskIds = ["T-WL-2"];
    };
    workloadSeed = import ./phase4-workload-seed.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.workloadSeed";
      taskIds = ["T-WL-3"];
    };
    workloadLoadPatterns = import ./phase4-workload-load-patterns.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.workloadLoadPatterns";
      taskIds = ["T-WL-4"];
    };
    workloadVirtualTimeShapes = import ./phase4-workload-virtual-time-shapes.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.workloadVirtualTimeShapes";
      taskIds = ["T-WL-5"];
    };
    workloadParameterization = import ./phase4-workload-parameterization.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase4.workloadParameterization";
      taskIds = ["T-WL-6"];
    };
    gates = rec {
      replayOracle = greenBeforeAdvance {
        attrPath = "checks.crucible.phase4.gates.replayOracle";
        # lint needle: replayOracle = import ./phase4-event-graph-replay-oracle.nix
        gate = import ./phase4-event-graph-replay-oracle.nix {
          inherit pkgs lib;
          attrPath = "checks.crucible.phase4.gates.replayOracle";
          taskIds = ["T-TRIG-20" "T-ASRT-16" "T-ASRT-18"];
          dependencies = [phase3.gates.adversarialDeterminism.rawGate];
        };
        dependencies = [phase3.gates.adversarialDeterminism];
      };
      e2eDeterminism = redBeforeAdvance {
        attrPath = "checks.crucible.phase4.gates.e2eDeterminism";
        # lint needle: e2eDeterminism = import ./phase4-e2e-determinism.nix
        gate = import ./phase4-e2e-determinism.nix {
          inherit pkgs lib;
          attrPath = "checks.crucible.phase4.gates.e2eDeterminism";
          taskIds = ["T-DET-26" "T-ASRT-16"];
          dependencies = [replayOracle.rawGate phase1.simDouble];
        };
        dependencies = [replayOracle phase1.simDouble];
        phase = "phase4";
        reason = "the remaining white-box channel work requires crash-control, network, and multi-node production evidence";
        taskIds = ["T-GHC-6" "T-GHC-12" "T-GHC-15" "T-GHC-16"];
      };
    };
  };
  phase5 = {
    sessionActor = import ./phase5-session-actor.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase5.sessionActor";
      taskIds = ["T-SESS-1"];
    };
    sessionLifecycle = import ./phase5-session-lifecycle.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase5.sessionLifecycle";
      taskIds = ["T-SESS-3"];
      dependencies = [phase3.gates.schedulerLiveness.rawGate];
    };
    sessionCommandSet = import ./phase5-session-command-set.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase5.sessionCommandSet";
      taskIds = ["T-SESS-4"];
      dependencies = [phase5.sessionLifecycle];
    };
    sessionStepModes = import ./phase5-session-step-modes.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase5.sessionStepModes";
      taskIds = ["T-SESS-5"];
      dependencies = [phase5.sessionCommandSet];
    };
    sessionBoundaryControl = import ./phase5-session-boundary-control.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase5.sessionBoundaryControl";
      taskIds = ["T-SESS-6"];
      dependencies = [phase5.sessionStepModes];
    };
    sessionBreakpoints = import ./phase5-session-breakpoints.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase5.sessionBreakpoints";
      taskIds = ["T-SESS-7"];
      openTaskIds = [];
      dependencies = [phase5.sessionBoundaryControl];
    };
    sessionSaveResumeFork = import ./phase5-session-save-resume-fork.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase5.sessionSaveResumeFork";
      taskIds = ["T-SESS-8"];
      dependencies = [phase5.sessionBreakpoints];
    };
    sessionControlDeterminism = import ./phase5-session-control-determinism.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase5.sessionControlDeterminism";
      taskIds = ["T-SESS-9"];
      dependencies = [phase5.sessionSaveResumeFork];
    };
    sessionLockFreeObservation = import ./phase5-session-lock-free-observation.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase5.sessionLockFreeObservation";
      taskIds = ["T-SESS-10"];
      dependencies = [phase5.sessionControlDeterminism];
    };
    sessionSimulationBackend = import ./phase5-session-simulation-backend.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase5.sessionSimulationBackend";
      taskIds = ["T-SESS-11"];
      openTaskIds = [];
      dependencies = [phase5.sessionLockFreeObservation];
    };
    cliSkeleton = import ./phase5-cli-skeleton.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase5.cliSkeleton";
      taskIds = ["T-CLI-1"];
    };
    gates = {
      controlResponsive = greenBeforeAdvance {
        attrPath = "checks.crucible.phase5.gates.controlResponsive";
        # lint needle: controlResponsive = import ./phase5-control-responsive.nix
        gate = import ./phase5-control-responsive.nix {
          inherit pkgs lib;
          attrPath = "checks.crucible.phase5.gates.controlResponsive";
          taskIds = ["T-HARN-15"];
          dependencies = [phase4.gates.e2eDeterminism.rawGate];
        };
        dependencies = [phase4.gates.e2eDeterminism];
      };
    };
    sessionSimDoubleSuite = import ./phase5-session-sim-double-suite.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase5.sessionSimDoubleSuite";
      taskIds = ["T-SESS-12" "T-PAT-6"];
      openTaskIds = [];
      dependencies = [
        phase5.sessionSimulationBackend
        phase3.gates.schedulerLiveness.rawGate
        phase5.gates.controlResponsive.rawGate
      ];
    };
    sessionDebugTimeTravel = import ./phase5-session-debug-time-travel.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase5.sessionDebugTimeTravel";
      taskIds = ["T-SESS-13"];
      dependencies = [
        phase5.sessionSimDoubleSuite
        phase5.gates.controlResponsive.rawGate
      ];
    };
    apiControlClient = import ./phase5-api-control-client.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase5.apiControlClient";
      taskIds = ["T-API-1"];
      dependencies = [
        phase5.sessionDebugTimeTravel
        phase2.gates.abiConformance.rawGate
        phase5.gates.controlResponsive.rawGate
      ];
    };
    apiSessionCommandMapping = import ./phase5-api-session-command-mapping.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase5.apiSessionCommandMapping";
      taskIds = ["T-API-2"];
      dependencies = [
        phase5.apiControlClient
        phase5.sessionCommandSet
        phase2.gates.abiConformance.rawGate
        phase5.gates.controlResponsive.rawGate
      ];
    };
    apiLifecycleUnary = import ./phase5-api-lifecycle-unary.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase5.apiLifecycleUnary";
      taskIds = ["T-API-3"];
      dependencies = [
        phase5.apiSessionCommandMapping
        phase5.sessionLifecycle
        phase5.sessionCommandSet
        phase2.gates.abiConformance.rawGate
        phase5.gates.controlResponsive.rawGate
      ];
    };
    apiStreamingEquivalence = import ./phase5-api-streaming-equivalence.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase5.apiStreamingEquivalence";
      taskIds = ["T-API-4"];
      dependencies = [
        phase5.apiLifecycleUnary
        phase5.apiSessionCommandMapping
        phase5.sessionLifecycle
        phase5.sessionCommandSet
        phase2.gates.abiConformance.rawGate
        phase5.gates.controlResponsive.rawGate
      ];
    };
    apiOpenSetPayload = import ./phase5-api-open-set-payload.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase5.apiOpenSetPayload";
      taskIds = ["T-API-5"];
      dependencies = [
        phase5.apiStreamingEquivalence
        phase5.apiLifecycleUnary
        phase5.apiSessionCommandMapping
        phase5.sessionLifecycle
        phase5.sessionCommandSet
        phase2.gates.abiConformance.rawGate
        phase5.gates.controlResponsive.rawGate
      ];
    };
    apiStreamingCursor = import ./phase5-api-streaming-cursor.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase5.apiStreamingCursor";
      taskIds = ["T-API-6"];
      dependencies = [
        phase5.apiOpenSetPayload
        phase5.apiStreamingEquivalence
        phase5.apiLifecycleUnary
        phase5.sessionLifecycle
        phase5.sessionCommandSet
        phase2.gates.abiConformance.rawGate
        phase5.gates.controlResponsive.rawGate
      ];
    };
    apiStateUpdateStream = import ./phase5-api-state-update-stream.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase5.apiStateUpdateStream";
      taskIds = ["T-API-7"];
      dependencies = [
        phase5.apiStreamingCursor
        phase5.apiOpenSetPayload
        phase5.apiStreamingEquivalence
        phase5.apiLifecycleUnary
        phase5.sessionLifecycle
        phase5.sessionCommandSet
        phase2.gates.abiConformance.rawGate
        phase5.gates.controlResponsive.rawGate
      ];
    };
    apiEpochGuards = import ./phase5-api-epoch-guards.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase5.apiEpochGuards";
      taskIds = ["T-API-8"];
      dependencies = [
        phase5.apiStateUpdateStream
        phase5.apiStreamingCursor
        phase5.apiOpenSetPayload
        phase5.apiStreamingEquivalence
        phase5.apiLifecycleUnary
        phase5.sessionLifecycle
        phase5.sessionCommandSet
        phase2.gates.abiConformance.rawGate
        phase5.gates.controlResponsive.rawGate
      ];
    };
    apiReproductionContext = import ./phase5-api-reproduction-context.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase5.apiReproductionContext";
      taskIds = ["T-API-9"];
      dependencies = [
        phase5.apiEpochGuards
        phase5.apiStateUpdateStream
        phase5.apiStreamingCursor
        phase5.apiOpenSetPayload
        phase5.apiStreamingEquivalence
        phase5.apiLifecycleUnary
        phase5.sessionControlDeterminism
        phase5.sessionLockFreeObservation
        phase5.sessionLifecycle
        phase5.sessionCommandSet
        phase2.gates.abiConformance.rawGate
        phase5.gates.controlResponsive.rawGate
      ];
    };
    apiCommandStatusTaxonomy = import ./phase5-api-command-status-taxonomy.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase5.apiCommandStatusTaxonomy";
      taskIds = ["T-API-10"];
      dependencies = [
        phase5.apiReproductionContext
        phase5.apiEpochGuards
        phase5.apiStateUpdateStream
        phase5.apiStreamingCursor
        phase5.apiOpenSetPayload
        phase5.apiStreamingEquivalence
        phase5.apiLifecycleUnary
        phase5.sessionControlDeterminism
        phase5.sessionLockFreeObservation
        phase5.sessionLifecycle
        phase5.sessionCommandSet
        phase2.gates.abiConformance.rawGate
        phase5.gates.controlResponsive.rawGate
      ];
    };
    apiReferenceClientConformance = import ./phase5-api-reference-client-conformance.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase5.apiReferenceClientConformance";
      taskIds = ["T-API-13"];
      dependencies = [
        phase5.apiCommandStatusTaxonomy
        phase5.apiReproductionContext
        phase5.apiEpochGuards
        phase5.apiStateUpdateStream
        phase5.apiStreamingCursor
        phase5.apiOpenSetPayload
        phase5.apiStreamingEquivalence
        phase5.apiLifecycleUnary
        phase5.sessionSimulationBackend
        phase5.sessionControlDeterminism
        phase5.sessionLockFreeObservation
        phase5.sessionLifecycle
        phase5.sessionCommandSet
        phase2.gates.abiConformance.rawGate
        phase5.gates.controlResponsive.rawGate
      ];
    };
    apiNondeterminism = import ./phase5-api-nondeterminism.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase5.apiNondeterminism";
      taskIds = ["T-API-14"];
      dependencies = [
        phase5.apiReferenceClientConformance
        phase5.apiCommandStatusTaxonomy
        phase5.apiReproductionContext
        phase5.apiEpochGuards
        phase5.apiStateUpdateStream
        phase5.apiStreamingCursor
        phase5.apiOpenSetPayload
        phase5.apiStreamingEquivalence
        phase5.apiLifecycleUnary
        phase5.sessionControlDeterminism
        phase5.sessionLockFreeObservation
        phase5.sessionLifecycle
        phase5.sessionCommandSet
        phase2.gates.abiConformance.rawGate
        phase4.gates.replayOracle.rawGate
        phase5.gates.controlResponsive.rawGate
      ];
    };
    cliThinWrapper = import ./phase5-cli-thin-wrapper.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase5.cliThinWrapper";
      taskIds = ["T-CLI-2"];
      dependencies = [
        phase5.cliSkeleton
        phase5.apiNondeterminism
        phase5.apiReferenceClientConformance
        phase5.sessionDebugTimeTravel
        phase5.sessionSaveResumeFork
        phase5.sessionCommandSet
        phase5.sessionLockFreeObservation
        phase5.gates.controlResponsive.rawGate
      ];
    };
    cliBackendSelection = import ./phase5-cli-backend-selection.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase5.cliBackendSelection";
      taskIds = ["T-CLI-3"];
      openTaskIds = [];
      dependencies = [
        phase5.cliThinWrapper
        phase5.apiNondeterminism
        phase5.apiReferenceClientConformance
        phase5.sessionSimulationBackend
        phase5.gates.controlResponsive.rawGate
      ];
    };
    cliDeterminismErgonomics = import ./phase5-cli-determinism-ergonomics.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase5.cliDeterminismErgonomics";
      taskIds = ["T-CLI-4"];
      dependencies = [
        phase5.cliBackendSelection
        phase4.gates.replayOracle.rawGate
        phase4.gates.e2eDeterminism.rawGate
        phase5.gates.controlResponsive.rawGate
      ];
    };
    cliHermeticDiscovery = import ./phase5-cli-hermetic-discovery.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase5.cliHermeticDiscovery";
      taskIds = ["T-CLI-5"];
      dependencies = [
        phase5.cliDeterminismErgonomics
        phase4.gates.replayOracle.rawGate
        phase4.gates.e2eDeterminism.rawGate
        phase5.gates.controlResponsive.rawGate
      ];
    };
    cliRunWorkflow = import ./phase5-cli-run-workflow.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase5.cliRunWorkflow";
      taskIds = ["T-CLI-6"];
      openTaskIds = [];
      dependencies = [
        phase5.cliHermeticDiscovery
        phase4.gates.replayOracle.rawGate
        phase4.gates.e2eDeterminism.rawGate
        phase5.gates.controlResponsive.rawGate
      ];
    };
    cliSaveWorkflow = import ./phase5-cli-save-workflow.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase5.cliSaveWorkflow";
      taskIds = ["T-CLI-9"];
      openTaskIds = [];
      dependencies = [
        phase5.cliRunWorkflow
        phase4.gates.replayOracle.rawGate
        phase5.gates.controlResponsive.rawGate
      ];
    };
    cliResumeWorkflow = import ./phase5-cli-resume-workflow.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase5.cliResumeWorkflow";
      taskIds = ["T-CLI-10"];
      openTaskIds = [];
      dependencies = [
        phase5.cliSaveWorkflow
        phase5.sessionSaveResumeFork
        phase5.gates.controlResponsive.rawGate
      ];
    };
    cliForkWorkflow = import ./phase5-cli-fork-workflow.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase5.cliForkWorkflow";
      taskIds = ["T-CLI-11"];
      openTaskIds = [];
      dependencies = [
        phase5.cliSaveWorkflow
        phase5.cliResumeWorkflow
        phase5.sessionSaveResumeFork
        phase5.gates.controlResponsive.rawGate
      ];
    };
    cliVerifyWorkflow = import ./phase5-cli-verify-workflow.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase5.cliVerifyWorkflow";
      taskIds = ["T-CLI-7"];
      openTaskIds = [];
      dependencies = [
        phase5.cliRunWorkflow
        phase4.gates.e2eDeterminism.rawGate
        phase5.gates.controlResponsive.rawGate
      ];
    };
    cliSelftest = import ./phase5-cli-selftest.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase5.cliSelftest";
      taskIds = ["T-CLI-8"];
      openTaskIds = [];
      dependencies = [
        phase5.cliRunWorkflow
        phase4.gates.replayOracle.rawGate
        phase5.gates.controlResponsive.rawGate
      ];
    };
    cliReplayCheck = import ./phase5-cli-replay-check.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase5.cliReplayCheck";
      taskIds = ["T-CLI-12"];
      openTaskIds = [];
      dependencies = [
        phase5.cliRunWorkflow
        phase4.gates.replayOracle.rawGate
        phase4.gates.e2eDeterminism.rawGate
      ];
    };
    cliSearchFuzzWorkflow = import ./phase5-cli-search-fuzz-workflow.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase5.cliSearchFuzzWorkflow";
      taskIds = ["T-CLI-13"];
      openTaskIds = [];
      dependencies = [
        phase5.cliRunWorkflow
        phase5.cliForkWorkflow
        phase5.cliReplayCheck
        phase6.stateSpaceSearch
        phase6.coverageGuidedFuzzing
        phase4.gates.replayOracle.rawGate
        phase4.gates.e2eDeterminism.rawGate
      ];
    };
    cliTriageWorkflow = import ./phase5-cli-triage-workflow.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase5.cliTriageWorkflow";
      taskIds = ["T-CLI-17"];
      dependencies = [
        phase5.cliSearchFuzzWorkflow
        phase6.triageThinDriver
        phase6.triageCliSurface
      ];
    };
    cliServeReadOnly = import ./phase5-cli-serve-read-only.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase5.cliServeReadOnly";
      taskIds = ["T-CLI-14"];
      openTaskIds = [];
      dependencies = [
        phase5.cliRunWorkflow
        phase5.cliThinWrapper
        phase5.gates.controlResponsive.rawGate
      ];
    };
    cliServeMaxSessions = import ./phase5-cli-serve-max-sessions.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase5.cliServeMaxSessions";
      taskIds = ["T-CLI-14"];
      openTaskIds = [];
      dependencies = [
        phase5.cliServeReadOnly
        phase5.cliRunWorkflow
        phase5.gates.controlResponsive.rawGate
      ];
    };
    cliServeMultiClient = import ./phase5-cli-serve-multi-client.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase5.cliServeMultiClient";
      taskIds = ["T-CLI-14"];
      openTaskIds = [];
      dependencies = [
        phase5.cliServeReadOnly
        phase5.cliServeMaxSessions
        phase5.gates.controlResponsive.rawGate
      ];
    };
    cliServeShutdown = import ./phase5-cli-serve-shutdown.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase5.cliServeShutdown";
      taskIds = ["T-CLI-14"];
      openTaskIds = [];
      dependencies = [
        phase5.cliServeReadOnly
        phase5.cliServeMaxSessions
        phase5.cliServeMultiClient
      ];
    };
    cliExitMachineReadable = import ./phase5-cli-exit-machine-readable.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase5.cliExitMachineReadable";
      taskIds = ["T-CLI-15"];
      openTaskIds = [];
      dependencies = [
        phase5.cliRunWorkflow
        phase5.cliServeShutdown
        phase5.cliDeterminismErgonomics
        phase5.gates.controlResponsive.rawGate
      ];
    };
    cliCompletionsHelp = import ./phase5-cli-completions-help.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase5.cliCompletionsHelp";
      taskIds = ["T-CLI-16"];
      openTaskIds = [];
      dependencies = [
        phase5.cliRunWorkflow
        phase5.cliThinWrapper
        phase5.gates.controlResponsive.rawGate
      ];
    };
  };
  phase6 = {
    advancedDependencyLadder = greenBeforeAdvance {
      attrPath = "checks.crucible.phase6.advancedDependencyLadder";
      gate = import ./phase6-advanced-dependency-ladder.nix {
        inherit pkgs lib;
        attrPath = "checks.crucible.phase6.advancedDependencyLadder";
        taskIds = ["T-ADV-1"];
        dependencies = [
          phase2.gates.singleVmFingerprint.rawGate
          phase4.gates.replayOracle.rawGate
          phase4.gates.e2eDeterminism.rawGate
          phase5.gates.controlResponsive.rawGate
        ];
      };
      dependencies = [
        phase2.gates.singleVmFingerprint
        phase4.gates.replayOracle
        phase4.gates.e2eDeterminism
        phase5.gates.controlResponsive
      ];
    };
    explorationLifecycle = greenBeforeAdvance {
      attrPath = "checks.crucible.phase6.explorationLifecycle";
      gate = import ./phase6-exploration-lifecycle.nix {
        inherit pkgs lib;
        attrPath = "checks.crucible.phase6.explorationLifecycle";
        taskIds = ["T-ADV-2"];
        dependencies = [
          phase5.gates.controlResponsive.rawGate
          phase6.advancedDependencyLadder.rawGate
        ];
      };
      dependencies = [
        phase5.gates.controlResponsive
        phase6.advancedDependencyLadder
      ];
    };
    restoreStrategies = greenBeforeAdvance {
      attrPath = "checks.crucible.phase6.restoreStrategies";
      gate = import ./phase6-restore-strategies.nix {
        inherit pkgs lib;
        attrPath = "checks.crucible.phase6.restoreStrategies";
        taskIds = ["T-ADV-5"];
        dependencies = [
          phase4.gates.replayOracle.rawGate
          phase4.gates.e2eDeterminism.rawGate
          phase6.advancedDependencyLadder.rawGate
        ];
      };
      dependencies = [
        phase4.gates.replayOracle
        phase4.gates.e2eDeterminism
        phase6.advancedDependencyLadder
      ];
    };
    savevmCompleteness = greenBeforeAdvance {
      attrPath = "checks.crucible.phase6.savevmCompleteness";
      gate = import ./phase6-savevm-completeness.nix {
        inherit pkgs lib;
        attrPath = "checks.crucible.phase6.savevmCompleteness";
        taskIds = ["T-ADV-6"];
        dependencies = [
          phase4.gates.replayOracle.rawGate
          phase4.gates.e2eDeterminism.rawGate
          phase6.restoreStrategies.rawGate
        ];
      };
      dependencies = [
        phase4.gates.replayOracle
        phase4.gates.e2eDeterminism
        phase6.restoreStrategies
      ];
    };
    explorationFork = greenBeforeAdvance {
      attrPath = "checks.crucible.phase6.explorationFork";
      gate = import ./phase6-exploration-fork.nix {
        inherit pkgs lib;
        attrPath = "checks.crucible.phase6.explorationFork";
        taskIds = ["T-ADV-3"];
        dependencies = [
          phase4.gates.replayOracle.rawGate
          phase4.gates.e2eDeterminism.rawGate
          phase6.explorationLifecycle.rawGate
          phase6.savevmCompleteness.rawGate
        ];
      };
      dependencies = [
        phase4.gates.replayOracle
        phase4.gates.e2eDeterminism
        phase6.explorationLifecycle
        phase6.savevmCompleteness
      ];
    };
    stateSpaceSearch = greenBeforeAdvance {
      attrPath = "checks.crucible.phase6.stateSpaceSearch";
      gate = import ./phase6-state-space-search.nix {
        inherit pkgs lib;
        attrPath = "checks.crucible.phase6.stateSpaceSearch";
        taskIds = ["T-ADV-7"];
        dependencies = [
          phase4.gates.replayOracle.rawGate
          phase4.gates.e2eDeterminism.rawGate
          phase6.restoreStrategies.rawGate
          phase6.savevmCompleteness.rawGate
          phase6.gates.replayOracle.rawGate
        ];
      };
      dependencies = [
        phase4.gates.replayOracle
        phase4.gates.e2eDeterminism
        phase6.restoreStrategies
        phase6.savevmCompleteness
        phase6.gates.replayOracle
      ];
    };
    searchStrategies = greenBeforeAdvance {
      attrPath = "checks.crucible.phase6.searchStrategies";
      gate = import ./phase6-search-strategies.nix {
        inherit pkgs lib;
        attrPath = "checks.crucible.phase6.searchStrategies";
        taskIds = ["T-ADV-8"];
        dependencies = [
          phase4.gates.replayOracle.rawGate
          phase4.gates.e2eDeterminism.rawGate
          phase6.stateSpaceSearch.rawGate
          phase6.gates.replayOracle.rawGate
        ];
      };
      dependencies = [
        phase4.gates.replayOracle
        phase4.gates.e2eDeterminism
        phase6.stateSpaceSearch
        phase6.gates.replayOracle
      ];
    };
    searchReductions = greenBeforeAdvance {
      attrPath = "checks.crucible.phase6.searchReductions";
      gate = import ./phase6-search-reductions.nix {
        inherit pkgs lib;
        attrPath = "checks.crucible.phase6.searchReductions";
        taskIds = ["T-ADV-9"];
        dependencies = [
          phase4.gates.replayOracle.rawGate
          phase4.gates.e2eDeterminism.rawGate
          phase6.stateSpaceSearch.rawGate
          phase6.searchStrategies.rawGate
          phase6.gates.replayOracle.rawGate
        ];
      };
      dependencies = [
        phase4.gates.replayOracle
        phase4.gates.e2eDeterminism
        phase6.stateSpaceSearch
        phase6.searchStrategies
        phase6.gates.replayOracle
      ];
    };
    preemptionBranching = greenBeforeAdvance {
      attrPath = "checks.crucible.phase6.preemptionBranching";
      gate = import ./phase6-guided-adaptive-exploration.nix {
        inherit pkgs lib;
        attrPath = "checks.crucible.phase6.preemptionBranching";
        taskIds = ["T-ADV-20"];
        openTaskIds = [];
        gateName = "gate:preemption-branching";
        dependencies = [
          phase4.gates.replayOracle.rawGate
          phase4.gates.e2eDeterminism.rawGate
          phase6.searchReductions.rawGate
        ];
      };
      dependencies = [
        phase4.gates.replayOracle
        phase4.gates.e2eDeterminism
        phase6.searchReductions
      ];
    };
    appRandomBranching = greenBeforeAdvance {
      attrPath = "checks.crucible.phase6.appRandomBranching";
      gate = import ./phase6-guided-adaptive-exploration.nix {
        inherit pkgs lib;
        attrPath = "checks.crucible.phase6.appRandomBranching";
        taskIds = ["T-ADV-21"];
        openTaskIds = [];
        gateName = "gate:app-random-branching";
        dependencies = [
          phase4.gates.replayOracle.rawGate
          phase4.gates.e2eDeterminism.rawGate
          phase6.preemptionBranching.rawGate
        ];
      };
      dependencies = [
        phase4.gates.replayOracle
        phase4.gates.e2eDeterminism
        phase6.preemptionBranching
      ];
    };
    basicBlockCoverage = greenBeforeAdvance {
      attrPath = "checks.crucible.phase6.basicBlockCoverage";
      gate = import ./phase6-basic-block-coverage.nix {
        inherit pkgs lib;
        attrPath = "checks.crucible.phase6.basicBlockCoverage";
        taskIds = ["T-ADV-10" "T-PLUG-15" "T-PERF-15"];
        openTaskIds = [];
        dependencies = [
          phase2.gates.singleVmFingerprint.rawGate
          phase2.gates.anyGuest.rawGate
          phase2.qemuPluginCoverage
          phase4.gates.e2eDeterminism.rawGate
          phase4.eventLogCoverage
          phase6.stateSpaceSearch.rawGate
          phase6.searchReductions.rawGate
        ];
      };
      dependencies = [
        phase2.gates.singleVmFingerprint
        phase2.gates.anyGuest
        phase2.qemuPluginCoverage
        phase4.gates.e2eDeterminism
        phase4.eventLogCoverage
        phase6.stateSpaceSearch
        phase6.searchReductions
      ];
    };
    coverageFeedback = greenBeforeAdvance {
      attrPath = "checks.crucible.phase6.coverageFeedback";
      gate = import ./phase6-coverage-feedback.nix {
        inherit pkgs lib;
        attrPath = "checks.crucible.phase6.coverageFeedback";
        taskIds = ["T-ADV-11"];
        dependencies = [
          phase2.gates.singleVmFingerprint.rawGate
          phase1.gates.contentAddress.rawGate
          phase4.gates.e2eDeterminism.rawGate
          phase4.eventLogCoverage
          phase6.searchStrategies.rawGate
          phase6.basicBlockCoverage.rawGate
        ];
      };
      dependencies = [
        phase2.gates.singleVmFingerprint
        phase1.gates.contentAddress
        phase4.gates.e2eDeterminism
        phase4.eventLogCoverage
        phase6.searchStrategies
        phase6.basicBlockCoverage
      ];
    };
    guidanceSignals = greenBeforeAdvance {
      attrPath = "checks.crucible.phase6.guidanceSignals";
      gate = import ./phase6-guided-adaptive-exploration.nix {
        inherit pkgs lib;
        attrPath = "checks.crucible.phase6.guidanceSignals";
        taskIds = ["T-ADV-17"];
        gateName = "gate:guidance-signals";
        dependencies = [
          phase4.gates.replayOracle.rawGate
          phase4.gates.e2eDeterminism.rawGate
          phase6.searchStrategies.rawGate
          phase6.coverageFeedback.rawGate
        ];
      };
      dependencies = [
        phase4.gates.replayOracle
        phase4.gates.e2eDeterminism
        phase6.searchStrategies
        phase6.coverageFeedback
      ];
    };
    adaptiveStrategies = greenBeforeAdvance {
      attrPath = "checks.crucible.phase6.adaptiveStrategies";
      gate = import ./phase6-guided-adaptive-exploration.nix {
        inherit pkgs lib;
        attrPath = "checks.crucible.phase6.adaptiveStrategies";
        taskIds = ["T-ADV-18"];
        gateName = "gate:adaptive-strategies";
        dependencies = [
          phase4.gates.replayOracle.rawGate
          phase4.gates.e2eDeterminism.rawGate
          phase6.guidanceSignals.rawGate
        ];
      };
      dependencies = [
        phase4.gates.replayOracle
        phase4.gates.e2eDeterminism
        phase6.guidanceSignals
      ];
    };
    guidanceDeterminismLint = greenBeforeAdvance {
      attrPath = "checks.crucible.phase6.guidanceDeterminismLint";
      gate = import ./phase6-guided-adaptive-exploration.nix {
        inherit pkgs lib;
        attrPath = "checks.crucible.phase6.guidanceDeterminismLint";
        taskIds = ["T-ADV-19"];
        gateName = "gate:guidance-determinism-lint";
        dependencies = [
          phase4.gates.replayOracle.rawGate
          phase4.gates.e2eDeterminism.rawGate
          phase6.adaptiveStrategies.rawGate
        ];
      };
      dependencies = [
        phase4.gates.replayOracle
        phase4.gates.e2eDeterminism
        phase6.adaptiveStrategies
      ];
    };
    coverageGuidedFuzzing = greenBeforeAdvance {
      attrPath = "checks.crucible.phase6.coverageGuidedFuzzing";
      gate = import ./phase6-coverage-guided-fuzzing.nix {
        inherit pkgs lib;
        attrPath = "checks.crucible.phase6.coverageGuidedFuzzing";
        taskIds = ["T-ADV-12"];
        dependencies = [
          phase1.gates.contentAddress.rawGate
          phase4.gates.replayOracle.rawGate
          phase4.gates.e2eDeterminism.rawGate
          phase6.stateSpaceSearch.rawGate
          phase6.searchStrategies.rawGate
          phase6.basicBlockCoverage.rawGate
          phase6.coverageFeedback.rawGate
          phase6.guidanceDeterminismLint.rawGate
          phase6.appRandomBranching.rawGate
        ];
      };
      dependencies = [
        phase1.gates.contentAddress
        phase4.gates.replayOracle
        phase4.gates.e2eDeterminism
        phase6.stateSpaceSearch
        phase6.searchStrategies
        phase6.basicBlockCoverage
        phase6.coverageFeedback
        phase6.guidanceDeterminismLint
        phase6.appRandomBranching
      ];
    };
    coverageGuidedCorpus = greenBeforeAdvance {
      attrPath = "checks.crucible.phase6.coverageGuidedCorpus";
      gate = import ./phase6-coverage-guided-corpus.nix {
        inherit pkgs lib;
        attrPath = "checks.crucible.phase6.coverageGuidedCorpus";
        taskIds = ["T-ADV-13"];
        dependencies = [
          phase1.gates.contentAddress.rawGate
          phase4.gates.replayOracle.rawGate
          phase4.gates.e2eDeterminism.rawGate
          phase6.coverageGuidedFuzzing.rawGate
        ];
      };
      dependencies = [
        phase1.gates.contentAddress
        phase4.gates.replayOracle
        phase4.gates.e2eDeterminism
        phase6.coverageGuidedFuzzing
      ];
    };
    reproductionArtifacts = greenBeforeAdvance {
      attrPath = "checks.crucible.phase6.reproductionArtifacts";
      gate = import ./phase6-reproduction-artifacts.nix {
        inherit pkgs lib;
        attrPath = "checks.crucible.phase6.reproductionArtifacts";
        taskIds = ["T-ADV-14"];
        dependencies = [
          phase1.gates.contentAddress.rawGate
          phase4.gates.replayOracle.rawGate
          phase4.gates.e2eDeterminism.rawGate
          phase6.coverageGuidedCorpus.rawGate
        ];
      };
      dependencies = [
        phase1.gates.contentAddress
        phase4.gates.replayOracle
        phase4.gates.e2eDeterminism
        phase6.coverageGuidedCorpus
      ];
    };
    minimization = greenBeforeAdvance {
      attrPath = "checks.crucible.phase6.minimization";
      gate = import ./phase6-minimization.nix {
        inherit pkgs lib;
        attrPath = "checks.crucible.phase6.minimization";
        taskIds = ["T-ADV-15"];
        dependencies = [
          phase1.gates.contentAddress.rawGate
          phase4.gates.replayOracle.rawGate
          phase4.gates.e2eDeterminism.rawGate
          phase6.reproductionArtifacts.rawGate
        ];
      };
      dependencies = [
        phase1.gates.contentAddress
        phase4.gates.replayOracle
        phase4.gates.e2eDeterminism
        phase6.reproductionArtifacts
      ];
    };
    failureSignature = greenBeforeAdvance {
      attrPath = "checks.crucible.phase6.failureSignature";
      gate = import ./phase6-failure-signature.nix {
        inherit pkgs lib;
        attrPath = "checks.crucible.phase6.failureSignature";
        taskIds = ["T-TRI-1"];
        dependencies = [
          phase1.gates.contentAddress.rawGate
          phase4.gates.replayOracle.rawGate
          phase4.gates.e2eDeterminism.rawGate
          phase4.assertionViolationRecords
          phase4.assertionViolationReproduction
          phase4.eventLogUnified
          phase6.reproductionArtifacts.rawGate
          phase6.minimization.rawGate
        ];
      };
      dependencies = [
        phase1.gates.contentAddress
        phase4.gates.replayOracle
        phase4.gates.e2eDeterminism
        phase4.assertionViolationRecords
        phase4.assertionViolationReproduction
        phase4.eventLogUnified
        phase6.reproductionArtifacts
        phase6.minimization
      ];
    };
    failureNormalization = greenBeforeAdvance {
      attrPath = "checks.crucible.phase6.failureNormalization";
      gate = import ./phase6-failure-normalization.nix {
        inherit pkgs lib;
        attrPath = "checks.crucible.phase6.failureNormalization";
        taskIds = ["T-TRI-2"];
        dependencies = [
          phase6.failureSignature.rawGate
          phase1.gates.contentAddress.rawGate
          phase4.gates.replayOracle.rawGate
          phase4.gates.e2eDeterminism.rawGate
          phase6.minimization.rawGate
        ];
      };
      dependencies = [
        phase6.failureSignature
        phase1.gates.contentAddress
        phase4.gates.replayOracle
        phase4.gates.e2eDeterminism
        phase6.minimization
      ];
    };
    signaturePolicy = greenBeforeAdvance {
      attrPath = "checks.crucible.phase6.signaturePolicy";
      gate = import ./phase6-signature-policy.nix {
        inherit pkgs lib;
        attrPath = "checks.crucible.phase6.signaturePolicy";
        taskIds = ["T-TRI-3"];
        dependencies = [
          phase6.failureNormalization.rawGate
          phase1.gates.contentAddress.rawGate
        ];
      };
      dependencies = [
        phase6.failureNormalization
        phase1.gates.contentAddress
      ];
    };
    failureClustering = greenBeforeAdvance {
      attrPath = "checks.crucible.phase6.failureClustering";
      gate = import ./phase6-failure-clustering.nix {
        inherit pkgs lib;
        attrPath = "checks.crucible.phase6.failureClustering";
        taskIds = ["T-TRI-4"];
        dependencies = [
          phase6.signaturePolicy.rawGate
          phase1.gates.contentAddress.rawGate
          phase4.gates.e2eDeterminism.rawGate
        ];
      };
      dependencies = [
        phase6.signaturePolicy
        phase1.gates.contentAddress
        phase4.gates.e2eDeterminism
      ];
    };
    signaturePreservingMinimization = greenBeforeAdvance {
      attrPath = "checks.crucible.phase6.signaturePreservingMinimization";
      gate = import ./phase6-signature-preserving-minimization.nix {
        inherit pkgs lib;
        attrPath = "checks.crucible.phase6.signaturePreservingMinimization";
        taskIds = ["T-TRI-5"];
        dependencies = [
          phase6.failureClustering.rawGate
          phase6.minimization.rawGate
          phase1.gates.contentAddress.rawGate
          phase4.gates.replayOracle.rawGate
        ];
      };
      dependencies = [
        phase6.failureClustering
        phase6.minimization
        phase1.gates.contentAddress
        phase4.gates.replayOracle
      ];
    };
    perClusterReports = greenBeforeAdvance {
      attrPath = "checks.crucible.phase6.perClusterReports";
      gate = import ./phase6-per-cluster-reports.nix {
        inherit pkgs lib;
        attrPath = "checks.crucible.phase6.perClusterReports";
        taskIds = ["T-TRI-6"];
        dependencies = [
          phase6.signaturePreservingMinimization.rawGate
          phase6.failureClustering.rawGate
          phase1.gates.contentAddress.rawGate
          phase4.gates.e2eDeterminism.rawGate
        ];
      };
      dependencies = [
        phase6.signaturePreservingMinimization
        phase6.failureClustering
        phase1.gates.contentAddress
        phase4.gates.e2eDeterminism
      ];
    };
    triageThinDriver = greenBeforeAdvance {
      attrPath = "checks.crucible.phase6.triageThinDriver";
      gate = import ./phase6-triage-thin-driver.nix {
        inherit pkgs lib;
        attrPath = "checks.crucible.phase6.triageThinDriver";
        taskIds = ["T-TRI-7"];
        dependencies = [
          phase6.perClusterReports.rawGate
          phase6.signaturePreservingMinimization.rawGate
          phase6.failureClustering.rawGate
          phase1.gates.contentAddress.rawGate
          phase4.gates.e2eDeterminism.rawGate
        ];
      };
      dependencies = [
        phase6.perClusterReports
        phase6.signaturePreservingMinimization
        phase6.failureClustering
        phase1.gates.contentAddress
        phase4.gates.e2eDeterminism
      ];
    };
    triageCliSurface = greenBeforeAdvance {
      attrPath = "checks.crucible.phase6.triageCliSurface";
      gate = import ./phase6-triage-cli-surface.nix {
        inherit pkgs lib;
        attrPath = "checks.crucible.phase6.triageCliSurface";
        taskIds = ["T-TRI-8"];
        dependencies = [
          phase5.cliSkeleton
          phase6.triageThinDriver.rawGate
        ];
      };
      dependencies = [
        phase5.cliSkeleton
        phase6.triageThinDriver
      ];
    };
    unifyingView = greenBeforeAdvance {
      attrPath = "checks.crucible.phase6.unifyingView";
      gate = import ./phase6-unifying-view.nix {
        inherit pkgs lib;
        attrPath = "checks.crucible.phase6.unifyingView";
        taskIds = ["T-ADV-16"];
        dependencies = [
          phase2.gates.singleVmFingerprint.rawGate
          phase4.gates.replayOracle.rawGate
          phase4.gates.e2eDeterminism.rawGate
          phase6.minimization.rawGate
        ];
      };
      dependencies = [
        phase2.gates.singleVmFingerprint
        phase4.gates.replayOracle
        phase4.gates.e2eDeterminism
        phase6.minimization
      ];
    };
    debugAttach = greenBeforeAdvance {
      attrPath = "checks.crucible.phase6.debugAttach";
      gate = import ./phase6-debug-attach.nix {
        inherit pkgs lib;
        attrPath = "checks.crucible.phase6.debugAttach";
        taskIds = ["T-DBG-1"];
        openTaskIds = [];
        dependencies = [
          phase4.gates.replayOracle.rawGate
          phase4.gates.e2eDeterminism.rawGate
          phase6.unifyingView.rawGate
        ];
      };
      dependencies = [
        phase4.gates.replayOracle
        phase4.gates.e2eDeterminism
        phase6.unifyingView
      ];
    };
    readOnlyDebugInspection = greenBeforeAdvance {
      attrPath = "checks.crucible.phase6.readOnlyDebugInspection";
      gate = import ./phase6-read-only-debug-inspection.nix {
        inherit pkgs lib;
        attrPath = "checks.crucible.phase6.readOnlyDebugInspection";
        taskIds = ["T-DBG-2"];
        openTaskIds = [];
        dependencies = [
          phase4.gates.replayOracle.rawGate
          phase4.gates.e2eDeterminism.rawGate
          phase6.debugAttach.rawGate
        ];
      };
      dependencies = [
        phase4.gates.replayOracle
        phase4.gates.e2eDeterminism
        phase6.debugAttach
      ];
    };
    canonicalDebugBreakpoint = greenBeforeAdvance {
      attrPath = "checks.crucible.phase6.canonicalDebugBreakpoint";
      gate = import ./phase6-canonical-debug-breakpoint.nix {
        inherit pkgs lib;
        attrPath = "checks.crucible.phase6.canonicalDebugBreakpoint";
        taskIds = ["T-DBG-3"];
        openTaskIds = [];
        dependencies = [
          phase1.layer0Determinism
          phase4.gates.replayOracle.rawGate
          phase4.gates.e2eDeterminism.rawGate
          phase6.readOnlyDebugInspection.rawGate
        ];
      };
      dependencies = [
        phase1.layer0Determinism
        phase4.gates.replayOracle
        phase4.gates.e2eDeterminism
        phase6.readOnlyDebugInspection
      ];
    };
    debugTimeTravel = greenBeforeAdvance {
      attrPath = "checks.crucible.phase6.debugTimeTravel";
      gate = import ./phase6-debug-time-travel.nix {
        inherit pkgs lib;
        attrPath = "checks.crucible.phase6.debugTimeTravel";
        taskIds = ["T-DBG-4"];
        dependencies = [
          phase4.gates.replayOracle.rawGate
          phase4.gates.e2eDeterminism.rawGate
          phase6.canonicalDebugBreakpoint.rawGate
        ];
      };
      dependencies = [
        phase4.gates.replayOracle
        phase4.gates.e2eDeterminism
        phase6.canonicalDebugBreakpoint
      ];
    };
    debugScopedTimeTravel = greenBeforeAdvance {
      attrPath = "checks.crucible.phase6.debugScopedTimeTravel";
      gate = import ./phase6-debug-scoped-time-travel.nix {
        inherit pkgs lib;
        attrPath = "checks.crucible.phase6.debugScopedTimeTravel";
        taskIds = ["T-DBG-5"];
        dependencies = [
          phase4.gates.replayOracle.rawGate
          phase4.gates.e2eDeterminism.rawGate
          phase6.debugTimeTravel.rawGate
        ];
      };
      dependencies = [
        phase4.gates.replayOracle
        phase4.gates.e2eDeterminism
        phase6.debugTimeTravel
      ];
    };
    debugNonCanonicalBranch = greenBeforeAdvance {
      attrPath = "checks.crucible.phase6.debugNonCanonicalBranch";
      gate = import ./phase6-debug-non-canonical-branch.nix {
        inherit pkgs lib;
        attrPath = "checks.crucible.phase6.debugNonCanonicalBranch";
        taskIds = ["T-DBG-6"];
        dependencies = [
          phase4.gates.replayOracle.rawGate
          phase4.gates.e2eDeterminism.rawGate
          phase6.debugScopedTimeTravel.rawGate
        ];
      };
      dependencies = [
        phase4.gates.replayOracle
        phase4.gates.e2eDeterminism
        phase6.debugScopedTimeTravel
      ];
    };
    debugTargetResolver = greenBeforeAdvance {
      attrPath = "checks.crucible.phase6.debugTargetResolver";
      gate = import ./phase6-debug-target-resolver.nix {
        inherit pkgs lib;
        attrPath = "checks.crucible.phase6.debugTargetResolver";
        taskIds = ["T-DBG-7"];
        dependencies = [
          phase1.gates.divergenceBisect.rawGate
          phase4.gates.replayOracle.rawGate
          phase5.gates.controlResponsive.rawGate
          phase6.debugNonCanonicalBranch.rawGate
        ];
      };
      dependencies = [
        phase1.gates.divergenceBisect
        phase4.gates.replayOracle
        phase5.gates.controlResponsive
        phase6.debugNonCanonicalBranch
      ];
    };
    debugCliSurface = greenBeforeAdvance {
      attrPath = "checks.crucible.phase6.debugCliSurface";
      gate = import ./phase6-debug-cli-surface.nix {
        inherit pkgs lib;
        attrPath = "checks.crucible.phase6.debugCliSurface";
        taskIds = ["T-DBG-8" "T-CLI-18"];
        openTaskIds = [];
        dependencies = [
          phase1.gates.layer0Determinism.rawGate
          phase4.gates.replayOracle.rawGate
          phase4.gates.e2eDeterminism.rawGate
          phase5.gates.controlResponsive.rawGate
          phase6.debugScopedTimeTravel.rawGate
          phase6.debugNonCanonicalBranch.rawGate
          phase6.debugTargetResolver.rawGate
        ];
      };
      dependencies = [
        phase1.gates.layer0Determinism
        phase4.gates.replayOracle
        phase4.gates.e2eDeterminism
        phase5.gates.controlResponsive
        phase6.debugScopedTimeTravel
        phase6.debugNonCanonicalBranch
        phase6.debugTargetResolver
      ];
    };
    gates = {
      replayOracle = greenBeforeAdvance {
        attrPath = "checks.crucible.phase6.gates.replayOracle";
        gate = import ./phase6-fork-replay-oracle.nix {
          inherit pkgs lib;
          attrPath = "checks.crucible.phase6.gates.replayOracle";
          taskIds = ["T-ADV-4"];
          dependencies = [
            phase4.gates.replayOracle.rawGate
            phase4.gates.e2eDeterminism.rawGate
            phase6.explorationFork.rawGate
            phase6.restoreStrategies.rawGate
          ];
        };
        dependencies = [
          phase4.gates.replayOracle
          phase4.gates.e2eDeterminism
          phase6.explorationFork
          phase6.restoreStrategies
        ];
      };
    };
  };
  phase7 = {
    cruciblePackageInventory = import ./phase7-crucible-package-inventory.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase7.cruciblePackageInventory";
      taskIds = ["T-PKG-1"];
    };
    crucibleQemuPackage = import ./phase7-crucible-qemu-package.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase7.crucibleQemuPackage";
      taskIds = ["T-PKG-2"];
    };
    packageFeatureLedger = import ./phase7-package-feature-ledger.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase7.packageFeatureLedger";
      taskIds = ["T-PKG-2"];
    };
    pythonBootstrapClosure = import ./phase7-python-bootstrap-closure.nix {
      inherit pkgs;
      attrPath = "checks.crucible.phase7.pythonBootstrapClosure";
      taskIds = ["T-PKG-2"];
    };
    crucibleQemuPluginPackage = import ./phase7-crucible-qemu-plugin-package.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase7.crucibleQemuPluginPackage";
      taskIds = ["T-PKG-7"];
    };
    cruciblePackageHermeticDiscovery = import ./phase7-crucible-package-hermetic-discovery.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase7.cruciblePackageHermeticDiscovery";
      taskIds = ["T-PKG-9"];
    };
    cruciblePackageAbiVersioning = import ./phase7-crucible-package-abi-versioning.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase7.cruciblePackageAbiVersioning";
      taskIds = ["T-PKG-10"];
    };
    cruciblePackageAbiConformance = import ./phase7-crucible-package-abi-conformance.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase7.cruciblePackageAbiConformance";
      taskIds = ["T-PKG-11"];
      rawAbiGate = phase2.abiConformance;
      gatedAbiGate = phase2.gates.abiConformance;
    };
    crucibleLinuxKernel = import ./phase7-crucible-linux-kernel.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase7.crucibleLinuxKernel";
      taskIds = ["T-PKG-12"];
      linuxCrucible = pkgs.linux-crucible;
      anyGuestGate = phase2.gates.anyGuest;
    };
    crucibleFixtures = import ./phase7-crucible-fixtures.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase7.crucibleFixtures";
      taskIds = ["T-PKG-13"];
      crucibleFixtures = pkgs.crucible-fixtures;
      anyGuestGate = phase2.gates.anyGuest.rawGate;
    };
    crucibleGateCiWiring = import ./phase7-crucible-gate-ci-wiring.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase7.crucibleGateCiWiring";
      taskIds = ["T-PKG-14"];
      openTaskIds = [];
    };
    crucibleCas = import ./phase7-crucible-cas.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase7.crucibleCas";
      taskIds = ["T-PKG-17"];
    };
    crucibleCasRatchetSeam = import ./phase7-crucible-cas-ratchet-seam.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase7.crucibleCasRatchetSeam";
      taskIds = ["T-PKG-18"];
    };
    crucibleCasFleetRatchetSeam = import ./phase7-crucible-cas-fleet-ratchet-seam.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase7.crucibleCasFleetRatchetSeam";
      taskIds = ["T-PKG-23"];
    };
    crucibleFleetStore = import ./phase7-crucible-fleet-store.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase7.crucibleFleetStore";
      taskIds = ["T-PKG-21"];
    };
    crucibleSharedDagStore = import ./phase7-crucible-shared-dag-store.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase7.crucibleSharedDagStore";
      taskIds = ["T-DCE-1"];
    };
    crucibleFrontierLeases = import ./phase7-crucible-frontier-leases.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase7.crucibleFrontierLeases";
      taskIds = ["T-DCE-2"];
    };
    crucibleFourLayerDedup = import ./phase7-crucible-four-layer-dedup.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase7.crucibleFourLayerDedup";
      taskIds = ["T-DCE-3"];
    };
    crucibleCampaignManifest = import ./phase7-crucible-campaign-manifest.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase7.crucibleCampaignManifest";
      taskIds = ["T-DCE-4"];
    };
    crucibleCampaignSeeding = import ./phase7-crucible-campaign-seeding.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase7.crucibleCampaignSeeding";
      taskIds = ["T-DCE-5"];
    };
    crucibleCampaignStorageBounding = import ./phase7-crucible-campaign-storage-bounding.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase7.crucibleCampaignStorageBounding";
      taskIds = ["T-DCE-6"];
    };
    crucibleDeterminismGuardrail = import ./phase7-crucible-determinism-guardrail.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase7.crucibleDeterminismGuardrail";
      taskIds = ["T-DCE-7"];
    };
    crucibleCampaignProvenance = import ./phase7-crucible-campaign-provenance.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase7.crucibleCampaignProvenance";
      taskIds = ["T-PKG-22"];
    };
    cruciblePackagingConformance = import ./phase7-crucible-packaging-conformance.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase7.cruciblePackagingConformance";
      taskIds = ["T-PKG-16"];
      patchMicrotestsGate = import ./phase2-patch-microtests.nix {
        inherit pkgs lib;
        attrPath = "checks.crucible.phase2.gates.patchMicrotests";
        taskIds = ["T-PKG-4" "T-HARN-20" "T-PATCH-2" "T-PATCH-20" "T-PATCH-21" "T-PATCH-22" "T-PATCH-23" "T-PATCH-24"];
        openTaskIds = [];
      };
    };
    crucibleReleaseManifest = import ./phase7-crucible-release-manifest.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase7.crucibleReleaseManifest";
      taskIds = ["T-PKG-19"];
    };
    crucibleWorkspacePackage = import ./phase7-crucible-workspace-package.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase7.crucibleWorkspacePackage";
      taskIds = ["T-PKG-8"];
    };
    happyPathExample = import ./phase7-happy-path-example.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase7.happyPathExample";
      taskIds = ["T-EX-1"];
    };
    partitionRecoveryExample = import ./phase7-partition-recovery-example.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase7.partitionRecoveryExample";
      taskIds = ["T-EX-2"];
    };
    crashRestartExample = import ./phase7-crash-restart-example.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase7.crashRestartExample";
      taskIds = ["T-EX-3"];
    };
    faultCampaignExample = import ./phase7-fault-campaign-example.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase7.faultCampaignExample";
      taskIds = ["T-EX-4"];
    };
    adversarialExampleVerify = import ./phase7-adversarial-example-verify.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase7.adversarialExampleVerify";
      taskIds = ["T-EX-5"];
    };
    reproductionArtifactFormat = import ./phase7-reproduction-artifact-format.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase7.reproductionArtifactFormat";
      taskIds = ["T-HARN-24"];
    };
    reproductionProvenanceTriple = import ./phase7-reproduction-provenance-triple.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase7.reproductionProvenanceTriple";
      taskIds = ["T-PKG-20"];
    };
    machineIndependentReproduction = import ./phase7-machine-independent-reproduction.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase7.machineIndependentReproduction";
      taskIds = ["T-HARN-25"];
    };
    crucibleDceIntegration = import ./phase7-crucible-dce-integration.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase7.crucibleDceIntegration";
      taskIds = ["T-DCE-10"];
      dependencies = [
        phase7.crucibleCasFleetRatchetSeam
        phase7.crucibleFleetStore
        phase7.crucibleGateCiWiring
      ];
    };
    qemuHostParallel = import ./phase7-qemu-host-parallel.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase7.qemuHostParallel";
      taskIds = ["T-PERF-29"];
      dependencies = [
        phase1.gates.singleVmFingerprint.rawGate
        phase2.qemuLiveNodeStep
        phase3.gates.adversarialDeterminism.rawGate
      ];
    };
    fingerprintDigestOffload = import ./phase7-fingerprint-digest-offload.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase7.fingerprintDigestOffload";
      taskIds = ["T-PERF-30"];
      liveFingerprint = phase2.qemuLivePluginFingerprint;
      fingerprintHelpers = phase1.rrFingerprintHelpers;
      dependencies = [
        phase1.gates.singleVmFingerprint.rawGate
        phase2.qemuLivePluginFingerprint
      ];
    };
    deviceHostWorkOverlap = import ./phase7-device-host-work-overlap.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase7.deviceHostWorkOverlap";
      taskIds = ["T-PERF-31"];
      liveBlockIo = phase2.qemuLiveBlockIo;
      dependencies = [phase2.qemuLiveBlockIo];
    };
    gates = rec {
      perfBench = greenBeforeAdvance {
        attrPath = "checks.crucible.phase7.gates.perfBench";
        # lint needle: perfBench = import ./phase7-perf-bench.nix
        gate = import ./phase7-perf-bench.nix {
          inherit pkgs lib;
          attrPath = "checks.crucible.phase7.gates.perfBench";
          taskIds = [
            "T-PERF-1"
            "T-PERF-2"
            "T-PERF-3"
            "T-PERF-4"
            "T-PERF-5"
            "T-PERF-6"
            "T-PERF-7"
            "T-PERF-8"
            "T-PERF-9"
            "T-PERF-10"
            "T-PERF-11"
            "T-PERF-12"
            "T-PERF-13"
            "T-PERF-14"
            "T-PERF-15"
            "T-PERF-16"
            "T-PERF-17"
            "T-PERF-18"
            "T-PERF-19"
            "T-PERF-20"
            "T-PERF-21"
            "T-PERF-22"
            "T-PERF-23"
            "T-PERF-24"
            "T-PERF-25"
            "T-PERF-26"
            "T-PERF-27"
            "T-PERF-28"
            "T-PERF-29"
            "T-PERF-30"
            "T-PERF-31"
          ];
          openTaskIds = [
            "T-PERF-32"
            "T-PERF-33"
            "T-PERF-34"
          ];
          hostParallelism = phase7.qemuHostParallel;
          fingerprintOffload = phase7.fingerprintDigestOffload;
          deviceWorkOverlap = phase7.deviceHostWorkOverlap;
          dependencies = [phase6.gates.replayOracle.rawGate phase6.basicBlockCoverage.rawGate phase7.qemuHostParallel phase7.fingerprintDigestOffload phase7.deviceHostWorkOverlap];
        };
        dependencies = [phase6.gates.replayOracle phase6.basicBlockCoverage phase7.qemuHostParallel phase7.fingerprintDigestOffload phase7.deviceHostWorkOverlap];
      };
      e2eDeterminism = greenBeforeAdvance {
        attrPath = "checks.crucible.phase7.gates.e2eDeterminism";
        # lint needle: e2eDeterminism = import ./phase7-e2e-determinism.nix
        gate = import ./phase7-e2e-determinism.nix {
          inherit pkgs lib;
          attrPath = "checks.crucible.phase7.gates.e2eDeterminism";
          taskIds = ["T-HARN-23"];
          openTaskIds = [];
          dependencies = [perfBench.rawGate phase7.crucibleLinuxKernel phase7.crucibleFixtures phase7.crucibleGateCiWiring phase7.crucibleReleaseManifest phase7.reproductionProvenanceTriple];
        };
        dependencies = [perfBench phase7.crucibleLinuxKernel phase7.crucibleFixtures phase7.crucibleGateCiWiring phase7.crucibleReleaseManifest phase7.reproductionProvenanceTriple];
      };
      fleetEquivalence = greenBeforeAdvance {
        attrPath = "checks.crucible.phase7.gates.fleetEquivalence";
        gate = import ./phase7-crucible-fleet-equivalence.nix {
          inherit pkgs lib;
          attrPath = "checks.crucible.phase7.gates.fleetEquivalence";
          taskIds = ["T-DCE-8"];
          dependencies = [phase2.gates.singleVmFingerprint.rawGate e2eDeterminism.rawGate phase7.crucibleFleetStore phase7.crucibleSharedDagStore phase7.crucibleFrontierLeases phase7.crucibleFourLayerDedup phase7.crucibleDeterminismGuardrail phase7.crucibleCasFleetRatchetSeam];
        };
        dependencies = [phase2.gates.singleVmFingerprint e2eDeterminism phase7.crucibleFleetStore phase7.crucibleSharedDagStore phase7.crucibleFrontierLeases phase7.crucibleFourLayerDedup phase7.crucibleDeterminismGuardrail phase7.crucibleCasFleetRatchetSeam];
      };
      campaignContinuity = greenBeforeAdvance {
        attrPath = "checks.crucible.phase7.gates.campaignContinuity";
        gate = import ./phase7-crucible-campaign-continuity.nix {
          inherit pkgs lib;
          attrPath = "checks.crucible.phase7.gates.campaignContinuity";
          taskIds = ["T-DCE-9"];
          dependencies = [fleetEquivalence.rawGate phase7.crucibleCampaignManifest phase7.crucibleCampaignSeeding phase7.crucibleCampaignStorageBounding phase7.crucibleCampaignProvenance];
        };
        dependencies = [fleetEquivalence phase7.crucibleCampaignManifest phase7.crucibleCampaignSeeding phase7.crucibleCampaignStorageBounding phase7.crucibleCampaignProvenance];
      };
    };
  };
}

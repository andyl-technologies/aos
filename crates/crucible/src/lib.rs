//! `crucible` owns the pure engine type spine.
//!
//! Spec index: RFC-0010 files 05, 06, 07, 08, 17, 18, 19.
//!
//! This L3 crate defines the RFC-0010 execution-model vocabulary shared by the
//! scheduler, temporal graph, checkpoint cache, fault engine, assertions, event
//! log, uniform I/O sub-node lifecycle, block overlay model, and VM backend
//! adapters. The crate remains a safe reduction island: it declares the backend
//! trait and core model signatures, while concrete VM drivers and
//! driver-specific details live outside the engine crate.
//!
//! Module map: [`model`] owns the content-addressed execution vocabulary,
//! [`decision`] owns seeded decision recording, [`device`] bridges the
//! `crucible-device` I/O sub-nodes into the determinism RNG and the device half
//! of `MaterializedState`, [`device_subnode`] holds the L1 I/O devices as
//! scheduling sub-nodes that drive the scheduler horizon and RESOLVE delivery,
//! [`example_corpus`] owns the built-in worked-example scenario corpus,
//! [`node_fault`] owns VM timing projection for slow and clock-skew faults,
//! [`backend`] owns the VM backend boundary, [`event_catalog`] owns the versioned
//! event-kind catalog, [`scheduler`] owns the quantum-loop boundary, [`trigger`]
//! owns event-graph control flow, [`tracing_bridge`] owns opt-in host diagnostic
//! mirroring to `tracing`, and `sim_backend` provides the gated in-process test
//! double.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod backend;
pub mod decision;
pub mod device;
pub mod device_subnode;
pub mod event_catalog;
pub mod example_corpus;
pub mod model;
pub mod node_fault;
pub mod scheduler;
#[cfg(feature = "test-double")]
mod sim_backend;
pub mod tracing_bridge;
pub mod trigger;

pub use backend::{
    AdvanceOutcome, Backend, BackendEffect, BackendError, BackendInput, BackendSnapshot,
    ExecutionFingerprint, ExecutionHorizon, FingerprintSample, GdbAttachInfo, GdbListen,
    MockSimulationBackend, MockSimulationBackendState, SimulationBackend, StepObservation,
};
pub use decision::{DecisionRecordError, DecisionRecorder};
pub use device::{
    LinkEmitDecisionRecord, NetworkFaultApplication, NetworkLinkDirection,
    apply_combined_block_faults_to_subnode, apply_combined_block_faults_to_subnode_and_state,
    apply_combined_network_faults, apply_combined_network_faults_to_link,
    apply_combined_network_faults_to_scheduler, apply_combined_ninep_faults_to_subnode,
    apply_combined_ninep_faults_to_subnode_and_state, block_faults_from_combined_block,
    device_overlay, device_rng, device_stream_id, emit_link_frame_with_recorded_faults,
    heal_combined_network_faults_to_scheduler, io_fault_id, io_fault_state,
    link_faults_from_combined_network, network_partition_change, network_partition_removed_edges,
    ninep_faults_from_combined_ninep, record_device_fault, with_active_io_faults,
};
pub use device_subnode::{DeviceDelivery, DeviceSchedulingSubNode};
pub use event_catalog::{
    EVENT_KIND_CATALOG_VERSION, EventKindCatalogDependency, EventKindCatalogEntry,
    event_kind_catalog, event_kind_catalog_canonical_bytes, event_kind_catalog_canonical_material,
    event_kind_catalog_class, event_kind_catalog_dependency_map, event_kind_catalog_entry,
};
pub use example_corpus::{
    BUILT_IN_EXAMPLE_CORPUS_VERSION, CRASH_RESTART_SCENARIO_NAME,
    EXAMPLE_CORPUS_REQUIRES_GUEST_COMPONENTS, EXAMPLE_CORPUS_WHITE_BOX_REQUIRED,
    ExampleCorpusError, ExampleScenarioFixture, ExampleScenarioRunOutcome,
    ExampleScenarioRunReport, ExampleScenarioVerifyReport, FAULT_CAMPAIGN_FAMILY_NAME,
    FaultCampaignExampleReport, HAPPY_PATH_SCENARIO_NAME, PARTITION_RECOVERY_SCENARIO_NAME,
    built_in_example_corpus, crash_restart_scenario, fault_campaign_family, happy_path_scenario,
    partition_recovery_scenario, run_example_scenario, run_fault_campaign_example,
    run_fault_campaign_example_default, verify_crash_restart_default_runs,
    verify_example_scenario_runs, verify_happy_path_default_runs,
    verify_partition_recovery_default_runs,
};
pub use model::{
    APPLICATION_TRAFFIC_ORIGINATES_IN_GUEST, ActiveFaultTable, ActiveNetworkEdgeDirection,
    ActiveNetworkEdgeKey, AdaptiveStrategyArm, AdaptiveStrategyConfig, AdaptiveStrategyCredit,
    AdaptiveStrategyReward, AdaptiveStrategyRun, AdaptiveStrategySelection, AppRandomBranchConfig,
    AppRandomBranchRun, AppRandomDecision, AppRandomDrawSite, AssertionDef, AssertionId,
    AssertionPhase, AssertionProximityGuidanceSignal, BlockFault, Checkpoint, CheckpointKind,
    CheckpointMeta, ChoiceTag, ClockDriftRate, CodePoint, CombinedBlockFaults,
    CombinedDuplicateFault, CombinedFaults, CombinedIoCorruptionFault,
    CombinedNetworkCorruptionFault, CombinedNetworkFaults, CombinedNinePFailureFault,
    CombinedNinePFaults, CombinedNodeFaults, CombinedPartitionFault, Configuration,
    ContentAddressedBlobRef, ContentHash, ControlFaultAction, ControlFaultDecision,
    CoverageGuidanceSignal, CoverageGuidedCorpus, CoverageGuidedCorpusAdmission,
    CoverageGuidedCorpusAdmissionDecision, CoverageGuidedCorpusConfig, CoverageGuidedCorpusEntry,
    CoverageGuidedCorpusEntryOrigin, CoverageGuidedCorpusError, CoverageGuidedCorpusRun,
    CoverageGuidedFuzzConfig, CoverageGuidedFuzzIteration, CoverageGuidedFuzzRun,
    CoverageGuidedFuzzThroughputReport, CoverageGuidedFuzzThroughputTarget, CowDeltaKind,
    CowDeltaRef, CowSharingStats, DEFAULT_APP_RANDOM_DRAW_CAP,
    DEFAULT_COVERAGE_GUIDED_FUZZ_THROUGHPUT_TARGET, DagStore, DagStoreError,
    DagStoreReproductionArtifact, DebugAttachChannelKind, DebugAttachChannelSet, DebugAttachReport,
    DebugAttachRequest, DebugBreakpointClientKind, DebugBreakpointMechanism, DebugBreakpointReport,
    DebugBreakpointRequest, DebugBreakpointTarget, DebugCheckpointCadenceReport,
    DebugCheckpointCadenceRequest, DebugCheckpointStride, DebugCliSurfaceContract, DebugCoordinate,
    DebugDivergenceCoordinate, DebugFailureFooterCommand, DebugGdbEndpoint, DebugGdbstubChannel,
    DebugGdbstubStepPolicy, DebugGotoReport, DebugGotoRequest, DebugGuestEdit, DebugGuestEditKind,
    DebugMultiVcpuPolicy, DebugNonCanonicalBranch, DebugNonCanonicalBranchAction,
    DebugNonCanonicalBranchReport, DebugNonCanonicalBranchRequest, DebugNonCanonicalBranchTrigger,
    DebugNonCanonicalForkMarker, DebugNonCanonicalLiveStatus, DebugOperatorControlKind,
    DebugPerNodeGotoReport, DebugPerNodeTimeTravelReport, DebugPerNodeTimeTravelRequest,
    DebugReadMutationBoundaryPolicy, DebugReadOnlyCheckpointFootprint,
    DebugReadOnlyInspectionFootprint, DebugReadOnlyInspectionKind, DebugReadOnlyInspectionReport,
    DebugReadOnlyInspectionRequest, DebugReplayOracleBisectionRequest, DebugReverseContinueMatch,
    DebugReverseContinueReport, DebugReverseContinueRequest, DebugReverseLatencyPolicy,
    DebugReverseStepGrain, DebugReverseStepReport, DebugReverseStepRequest,
    DebugSymbolResolutionPolicy, DebugTargetResolverReport, DebugTargetResolverRequest,
    DebugTargetSelector, DebugWholeWorldTarget, DebugWholeWorldTimeTravelReport,
    DebugWholeWorldTimeTravelRequest, Decision, DecisionRngState, DeliveryOrderDecision, DeviceId,
    DeviceOverlayDelta, DeviceRngState, EngineError, EventId, EventKey, EventLogOffset,
    EventSequenceKey, EventSequenceState, FailureCausalCone, FailureCluster, FailureClusterFinding,
    FailureClusterMember, FailureClusterReport, FailureClusterReportCausalStep,
    FailureClusterReportDivergence, FailureClusterReportFailure, FailureClusterReportFormat,
    FailureClusterReportReproduction, FailureClusterReportSet, FailureClusteringResult,
    FailureCoverageClass, FailureFindingsLedger, FailureFirstFailingPoint, FailureKind,
    FailurePropertyKey, FailurePropertyViolationRecord, FailureRecordedEventLog, FailureSignature,
    FailureSignatureKey, FailureSignatureNormalization,
    FailureSignaturePreservingMinimizationResult, FailureSignaturePreservingMinimizationRun,
    FailureSymmetryCanonicalizer, FailureTriageChangedCluster, FailureTriageResult,
    FailureTriageResultDiff, FailureTriageResultIdentity, FailureTriageSignatureCheckRecord,
    FailureTriageSignatureMismatch, FailureTriageSignatureSelfCheck,
    FailureTriageSignatureSelfCheckInput, FailureTriageStoredArtifact, FamilyParams, FamilySpace,
    Fault, FaultBandwidthBitsPerSecond, FaultCaps, FaultDecision, FaultDensity, FaultDensityRange,
    FaultDuration, FaultId, FaultPlan, FaultPlanEntry, FaultRateBasisPoints,
    FaultSlowdownFactorBasisPoints, FaultState, FaultTag, FaultWeights, FindingDiscoveryPath,
    FindingReproductionArtifact, FindingReproductionArtifactError, FleetEquivalenceDivergence,
    FleetEquivalenceReport, FleetFindingSetEntry, FleetWorkClaim, FleetWorkStealingConfig,
    FleetWorkStealingSearchRun, FramePredicate, FrontierChild, FrontierCoveredChild,
    FrontierReductionPolicy, FrontierReductionReason, FrontierReductionReport, GenesisCheckpoint,
    GuestWorkloadBinary, GuestWorkloadConfigTreeDelivery, GuestWorkloadConfigTreeRef,
    GuestWorkloadLoadPatternFixture, GuestWorkloadParameterKey, GuestWorkloadPattern,
    GuestWorkloadScalarParameter, GuestWorkloadSeed, GuestWorkloadSpikeMode,
    GuestWorkloadTimeSource, GuidanceDeterminismLintReport, GuidanceScore, GuidanceSignal,
    GuidanceSignalComposition, GuidanceSignalInput, GuidanceSignalKind, GuidanceSignalWeight,
    Icount, IoEventKind, IoFailureMode, IrqVector, LinkDef, LinkId, LinkLossProbability,
    LocalCheckpointClosureIndex, LocalDagStore, MIN_LINK_LATENCY, MarkerId, MaterializationPolicy,
    MaterializationTrigger, MaterializedState, MemPlace, MembershipFault, MemoryCmp,
    MemoryDagStore, MemoryWidth, MinimizationAttempt, MinimizationConfig, MinimizationRun,
    NetworkCorruptionFault, NetworkFault, NinePErrno, NinePFault, NodeBlobRef, NodeClockSkew,
    NodeCounter, NodeFault, NodeId, NodeLifecycle, NodeTemplate, NoveltyRarityGuidanceSignal,
    OverrideDecision, PROPERTY_QUANTIFIER_COUNT, PROPERTY_SCHEMA_DOMAIN, PROPERTY_SCHEMA_VERSION,
    PartialOrderIndependenceProof, PartialOrderReductionKey, PartialOrderReductionPolicy,
    PartitionDirection, PendingFrame, PinnedConfiguration, PinnedScenario, Plan, PlanEntry,
    Predicate, PreemptionBranchConfig, PreemptionBranchRun, PreemptionDecision, PreemptionKind,
    Properties, Property, PropertyKind, RandomFaultConfig, ReachabilityExpectation,
    ReachableDisposition, ReadyPoint, RegexProgram, ReplayOracleCheck, ReproductionArtifact,
    ReproductionEventLogArtifact, ReproductionEventLogReplay, ReproductionReplay, RestartPolicy,
    RngDecision, RngStreamId, RngStreamPosition, RuntimeState, SavevmCompletenessHedge,
    ScenarioBuilder, ScenarioDef, ScenarioDefForm, ScenarioFamily, Schedule, ScheduleError,
    SchedulerNodeId, SchedulerState, SchedulingNodeKind, SchedulingPoint, SearchBudget,
    SearchDiscoveredFailure, SearchExpansion, SearchFailureOracle, SearchFrontierChoice,
    SearchFrontierChoices, SearchReplayOracleBisectionRequest, SearchReplayOracleSamplingConfig,
    SearchReplayOracleSamplingReport, SearchRetainedLogAssertionEvidence,
    SearchRetainedLogPredicateResolutions, SearchStrategy, Seed, SeedSpace, SeededRngStream,
    SeverityBounds, Shift, SignaturePolicy, SignaturePolicyLevel, SimDuration, SimInstant,
    SimOffset, State, SymmetryClassId, SymmetryReductionClasses, SymmetryReductionKey,
    TemporalGraph, TemporalGraphFork, TemporalGraphGcReport, TemporalGraphGcRoots,
    TemporalGraphReferenceCounts, TemporalGraphRuntime, TemporalGraphSampledSearchRun,
    TemporalGraphSave, TemporalGraphSearch, TemporalGraphSearchRun, TemporalGraphStoreError,
    TemporalGraphStoreKeys, TimeConversionError, TimerId, TimerRegistry, TimerState, TopologyShape,
    TopologySizeRange, UnifiedGraphOperationEvidence, UnifiedGraphOperationKind,
    UnifiedGraphOperationReport, VcpuId, VirtualInstant, VirtualTime, VmArchitecture,
    VmSnapshotRef, WORKLOAD_CONFIG_TREE_DETERMINISTIC_QIDS,
    WORKLOAD_CONFIG_TREE_SCENARIO_PARAMETER, WORKLOAD_CONFIG_TREE_SORTED_ENUMERATION,
    WORKLOAD_CONFIG_TREES_ARE_READ_ONLY, WORKLOAD_ENGINE_ROLE,
    WORKLOAD_HOST_WALL_CLOCK_LOAD_SHAPES_ALLOWED, WORKLOAD_LOAD_PATTERN_BLACK_BOX_CONFIG_SUFFICES,
    WORKLOAD_LOAD_PATTERN_REQUIRES_WHITE_BOX, WORKLOAD_LOAD_PATTERN_SCENARIO_PARAMETER,
    WORKLOAD_PARAMETER_HOST_RUNTIME_POKES_ALLOWED, WORKLOAD_PARAMETERS_ARE_SCENARIO_CONFIG,
    WORKLOAD_SCENARIO_PARAMETER, WORKLOAD_SEED_BLACK_BOX_CONFIG_SUFFICES,
    WORKLOAD_SEED_REQUIRES_WHITE_BOX, WORKLOAD_SEED_SCENARIO_PARAMETER,
    WORKLOAD_SPIKE_MODE_SCENARIO_PARAMETER, WORKLOAD_TIME_SOURCE_SCENARIO_PARAMETER,
    WORKLOAD_TIME_VARIATION_REQUIRES_VIRTUAL_TIME, WhiteBoxPolicy, WorkloadEngineRole, World,
    WorldLookaheadEdge, WorldNode, WorldStaticTopology, WorldWorkloadConfigTree,
    app_random_branch_decisions, bake, instantiate, lint_guidance_determinism_source,
    preemption_branch_decisions, reduce, run_adaptive_strategy_selection, step, try_step,
};
pub use node_fault::{
    NodeTimingFaults, NodeTimingProjection, node_timing_faults_from_combined_node,
    project_node_timing,
};
#[cfg(feature = "test-double")]
pub use scheduler::SchedulerRunCeilingHandoffError;
#[cfg(feature = "test-double")]
/// Shared-memory ABI version used by the engine's in-process double.
pub const SHMEM_ABI_VERSION: u32 = crucible_shmem::ABI_VERSION;
pub use scheduler::{
    AssertionRunVerdict, AssertionVerdictFailure, BackendQuantumLoop, ComposedRunVerdict,
    ComposedRunVerdictFailure, ConcurrentQuantumLoop, ConservativeAdvanceAuthorization,
    ControlOperation, ControlOperationKind, EventAttributeValue, EventClass,
    EventDiagnosticPayload, EventLevel, EventLog, EventLogAssertionProximityProjection,
    EventLogAssertionProximityProjectionEntry, EventLogCausalDivergencePoint,
    EventLogCausalProjection, EventLogCausalProjectionEntry, EventLogCoverageFeedback,
    EventLogCoverageFeedbackConsumer, EventLogCoverageObservation, EventLogCoverageProjection,
    EventLogCoverageProjectionEntry, EventLogDeterminismComparison, EventLogDeterminismMismatch,
    EventLogIcountStamp, EventLogTime, EventPayload, EventSource, ExactLocalEvent, IoCompletion,
    LogEntry, NetworkLookahead, NodeTimelineProjection, QuantumLoop, QuantumOutcome,
    QuantumRequest, SCHEDULER_CONTROL_RESPONSE_BOUND_QUANTA, ScheduledEvent, ScheduledEventKey,
    ScheduledEventPayload, ScheduledEventResolveClass, SchedulerActor, SchedulerActorError,
    SchedulerActorHandle, SchedulerActorReply, SchedulerActorStateSnapshot,
    SchedulerConcurrentQuantumOutcome, SchedulerConcurrentRunCandidate, SchedulerConcurrentRunSet,
    SchedulerControlApplication, SchedulerDiscardedEvent, SchedulerDiscardedIoCompletion,
    SchedulerEffectiveClock, SchedulerEffectiveClockSource, SchedulerError,
    SchedulerEvaluationBoundaryKind, SchedulerEventLogAppend, SchedulerEventLogClass,
    SchedulerEventLogEntry, SchedulerEventLogPayload, SchedulerHorizon, SchedulerHorizonLimit,
    SchedulerHorizonSource, SchedulerLivenessError, SchedulerLivenessReport,
    SchedulerLivenessScenario, SchedulerLookaheadEdge, SchedulerLookaheadEdgeEndpoint,
    SchedulerLookaheadGraph, SchedulerNodeActivity, SchedulerNodeCheckpoint,
    SchedulerNodeCrashApplication, SchedulerNodeRestartApplication, SchedulerNodeVcpuIdleSnapshot,
    SchedulerPreemptionApplication, SchedulerQuiescence, SchedulerQuiescenceBlocker,
    SchedulerRendezvous, SchedulerRendezvousNode, SchedulerRendezvousPurpose,
    SchedulerRendezvousRecord, SchedulerResolveDecisionRecord, SchedulerResolveFaultChoice,
    SchedulerRunCeilingPublication, SchedulerRunSubdivisionPolicy, SchedulerRunSubdivisionRecord,
    SchedulerRunSubdivisionSlice, SchedulerScenarioNode, SchedulerSendAuthorization,
    SchedulerSendAuthorizer, SchedulerTerminal, SchedulerTopologyChange,
    SchedulerTopologyChangeApplication, SchedulerTopologyChangeEffect,
    SchedulerTopologyChangeTrigger, SchedulerTopologyLookaheadUpdate, SchedulerVcpuIdleState,
    SharedTimeline, SharedTimelineKey, SingleScheduler, TriggerActionApplication,
    TriggerActionState, TriggerDiagnosticRecord, TriggerLabelRecord, TriggerVerdict,
    UnresolvedCrossNodeDependency, apply_combined_node_crash_to_scheduler,
    apply_combined_node_timing_faults_to_scheduler, assertion_proximity_fingerprint_from_event_log,
    authorize_conservative_advance, check_scheduler_liveness, compare_event_log_determinism,
    coverage_fingerprint_from_event_log, event_log_assertion_proximity_projection,
    event_log_causal_projection, event_log_coverage_projection,
    exact_local_event_from_io_completion, exact_local_event_from_scheduled_event,
    exact_local_event_from_timer_deadline_ns, horizon_from_exact_local_event,
    horizon_from_network_lookahead, lookahead_for_node, network_horizon_from_lookahead,
    next_exact_local_event, next_scheduled_event_key, ordered_scheduled_events,
    ordered_timeline_keys, rendezvous_cap_for, resolve_due_scheduled_events,
    resolve_probabilistic_decisions, scheduled_event_delivery_time, scheduled_event_resolve_class,
    scheduler_rr_run_subdivision, unresolved_cross_node_dependencies,
};
#[cfg(feature = "test-double")]
pub use sim_backend::{
    SimBackend, SimBackendState, SimDeliveredFrame, SimDouble, SimDoubleConfig,
    SimDoubleControlEvent, SimDoubleError, SimDoubleHostScheduleEvent, SimInstructionScript,
    SimInstructionStep, SimOutboundFrame,
};
pub use tracing_bridge::{TracingBridge, TracingBridgeConfig};
#[cfg(feature = "test-double")]
pub use trigger::observable_event_from_whitebox_marker_payload;
pub use trigger::{
    Action, AssertionQuantifierKind, AssertionViolationArtifactReplay,
    AssertionViolationBisectionRequest, AssertionViolationDivergence,
    AssertionViolationReplayError, AssertionViolationReplayReport, BLACK_BOX_OBSERVATION_CONTRACTS,
    BLACK_BOX_OBSERVATION_KIND_COUNT, BLACK_BOX_OBSERVATION_KINDS, BasicBlockCoverageConfig,
    BasicBlockCoverageConsumer, BasicBlockCoverageError, BasicBlockCoverageMode,
    BasicBlockCoverageRegistrationPlan, BlackBoxHostOracle, BlackBoxObservationContract,
    BlackBoxObservationKind, BlackBoxObservationSource, Condition, ConditionEvaluation,
    ConditionEvaluationError, ConditionEvaluationPass, ConditionEvaluator, ConditionEventLogPrefix,
    ConditionLeaf, ConditionLeafOracle, ConsumedBasicBlockCoverage,
    DEFAULT_BASIC_BLOCK_COVERAGE_MAP_ENTRIES, Event, EventEvaluationKind, EventEvaluationPoint,
    EventFiring, EventFirings, EventGraph, EventGraphBuilder, EventGraphError,
    EventGraphEventBuilder, EventGraphState, ExternalFormalTraceExport,
    ExternalFormalTraceExporter, FirePolicy, GuestAssertionDetail, GuestAssertionKind,
    GuestAssertionMarker, HostAssertionEvaluator, HostAssertionHarnessLint,
    HostAssertionHarnessLintError, HostAssertionHarnessLintViolation, HostAssertionLifecycle,
    HostAssertionOracle, HostAssertionOutcome, HostAssertionOutcomeKind, HostAssertionPredicate,
    HostAssertionProximity, HostAssertionReport, HostAssertionViolation, LintedHostAssertionOracle,
    LogLevel, LoweredPlanEventGraph, ObservableEvent, ObservableEventPayload, ObservedFaultFact,
    ObservedOrderingFact, ObservedState, OfflineAssertionCheckError, OfflineAssertionChecker,
    PropertyLifecycleState, ReadyPointResolution, ReadyPointResolutionError,
    ReadyPointResolutionKind, RecordedAssertionLog, ResolvedCodePoint, ResolvedMemPlace,
    SearchScheduleNamedPredicateKey, SearchScheduleNamedPredicateTruths, TcgExecBasicBlock,
    basic_block_coverage_map_index, check_assertion_violation_reproduction,
    check_assertion_violation_reproduction_with_oracles, lint_host_assertion_harness_source,
    resolve_ready_point,
};

#[cfg(any(debug_assertions, feature = "test-support"))]
#[doc(hidden)]
pub mod test_support {
    //! Debug-build helpers for integration tests.

    use crate::{
        ConditionEvaluationError, ConditionEventLogPrefix, ContentHash, EventPayload,
        HostAssertionPredicate, Icount, LintedHostAssertionOracle, NodeId, ObservableEvent,
        SchedulerEvaluationBoundaryKind, SchedulerEventLogClass, SchedulerEventLogEntry,
        SchedulerEventLogPayload, VirtualTime,
    };

    /// Wraps a host assertion predicate for tests that inspect evaluator behavior.
    ///
    /// This helper is debug-only and intentionally bypasses production harness
    /// linting so integration tests can record evaluator call order.
    #[must_use]
    pub fn unchecked_host_assertion_oracle_for_test<O>(oracle: O) -> LintedHostAssertionOracle<O>
    where
        O: HostAssertionPredicate,
    {
        crate::trigger::unchecked_host_assertion_oracle_for_test(oracle)
    }

    /// Builds a scheduler observable event-log entry for integration tests.
    #[must_use]
    pub fn condition_observation_entry_for_test(
        sequence: u64,
        event: &ObservableEvent,
    ) -> SchedulerEventLogEntry {
        SchedulerEventLogEntry::observable(sequence, event.at(), event.payload().clone())
    }

    /// Builds a scheduler evaluation-boundary entry for integration tests.
    #[must_use]
    pub fn condition_boundary_entry_for_test(
        sequence: u64,
        at: VirtualTime,
        kind: SchedulerEvaluationBoundaryKind,
    ) -> SchedulerEventLogEntry {
        SchedulerEventLogEntry::evaluation_boundary(sequence, at, kind)
    }

    /// Builds a scheduler event-log entry carrying a typed payload for integration tests.
    #[must_use]
    pub fn condition_payload_entry_for_test(
        sequence: u64,
        at: VirtualTime,
        payload: SchedulerEventLogPayload,
    ) -> SchedulerEventLogEntry {
        SchedulerEventLogEntry::with_payload_for_test(sequence, at, payload)
    }

    /// Builds a scheduler event-log entry with a caller-supplied open payload for tests.
    #[must_use]
    pub fn condition_open_payload_entry_for_test(
        sequence: u64,
        at: VirtualTime,
        class: SchedulerEventLogClass,
        event_payload: EventPayload,
        payload: SchedulerEventLogPayload,
    ) -> SchedulerEventLogEntry {
        SchedulerEventLogEntry::with_open_payload_for_test(
            sequence,
            at,
            class,
            event_payload,
            payload,
        )
    }

    /// Returns a test entry with an intentionally replaced content hash.
    #[must_use]
    pub fn condition_entry_with_content_hash_for_test(
        entry: SchedulerEventLogEntry,
        content_hash: ContentHash,
    ) -> SchedulerEventLogEntry {
        entry.with_content_hash_for_test(content_hash)
    }

    /// Replaces an entry's icount stamp while keeping its content hash consistent.
    #[must_use]
    pub fn condition_entry_with_icount_stamp_for_test(
        entry: SchedulerEventLogEntry,
        node: Option<NodeId>,
        icount: Icount,
    ) -> SchedulerEventLogEntry {
        let mut time = entry.time().clone();
        time.icount = crate::scheduler::EventLogIcountStamp { node, icount };
        entry.with_time_for_test(time)
    }

    /// Builds a checked condition prefix from scheduler entries for integration tests.
    ///
    /// # Errors
    ///
    /// Returns [`ConditionEvaluationError`] when the supplied entries do not form
    /// a checked scheduler prefix.
    pub fn condition_prefix_from_scheduler_entries_for_test(
        entries: Vec<SchedulerEventLogEntry>,
    ) -> Result<ConditionEventLogPrefix, ConditionEvaluationError> {
        ConditionEventLogPrefix::from_scheduler_event_log_entries(entries)
    }

    /// Builds a checked quantum-boundary condition prefix for integration tests.
    ///
    /// # Panics
    ///
    /// Panics when the synthetic scheduler boundary entry does not form a valid
    /// prefix.
    #[must_use]
    pub fn condition_prefix_at_quantum_boundary_for_test(ticks: u64) -> ConditionEventLogPrefix {
        let at = VirtualTime { ticks };
        match ConditionEventLogPrefix::from_scheduler_event_log_entries(vec![
            condition_boundary_entry_for_test(0, at, SchedulerEvaluationBoundaryKind::Quantum),
        ]) {
            Ok(prefix) => prefix,
            Err(error) => {
                panic!("test scheduler boundary entry should form a checked prefix: {error}")
            }
        }
    }

    /// Builds a checked condition prefix from observable events for integration tests.
    ///
    /// # Errors
    ///
    /// Returns [`ConditionEvaluationError`] when the generated entries do not
    /// form a checked scheduler prefix.
    pub fn condition_prefix_from_observable_events_for_test(
        ticks: u64,
        events: Vec<ObservableEvent>,
    ) -> Result<ConditionEventLogPrefix, ConditionEvaluationError> {
        let mut indexed_events = events.iter().enumerate().collect::<Vec<_>>();
        indexed_events.sort_by_key(|(index, event)| (event.at().ticks, *index));
        let mut entries = indexed_events
            .iter()
            .enumerate()
            .map(|(sequence, (_, event))| {
                condition_observation_entry_for_test(
                    u64::try_from(sequence).unwrap_or(u64::MAX),
                    event,
                )
            })
            .collect::<Vec<_>>();
        entries.push(condition_boundary_entry_for_test(
            u64::try_from(entries.len()).unwrap_or(u64::MAX),
            VirtualTime { ticks },
            SchedulerEvaluationBoundaryKind::Quantum,
        ));
        ConditionEventLogPrefix::from_scheduler_event_log_entries(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn step_appends_decision_without_mutating_parent() {
        let config = Configuration::genesis(ScenarioDef::from_canonical_material(
            "crucible.test.step",
            "scenario=stub",
        ));
        let decision = Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name("root"),
            value: 42,
        });

        let child = step(&config, decision.clone());

        assert!(config.schedule.is_empty());
        assert_eq!(child.schedule.decisions(), &[decision]);
    }

    #[test]
    fn step_is_pure_temporal_graph_edge_constructor() {
        for seed in 0..64 {
            let parent = Configuration {
                def: generated_scenario(seed),
                schedule: generated_schedule(seed, 4),
            };
            let original_parent = parent.clone();
            let decision = generated_decision(seed, 64);

            let child = step(&parent, decision.clone());

            assert_eq!(parent, original_parent);
            assert_eq!(child.def, parent.def);
            assert_ne!(child, parent);
            assert_eq!(child.schedule.len(), parent.schedule.len() + 1);
            assert_eq!(
                child.schedule.prefix(parent.schedule.len()),
                Ok(parent.schedule.clone())
            );
            assert_eq!(child.schedule.decisions().last(), Some(&decision));
            assert_eq!(child.id(), child.content_hash());
        }
    }

    #[test]
    fn schedule_prefix_bounds_are_checked() {
        let schedule = Schedule::empty().appended(Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name("root"),
            value: 1,
        }));

        let prefix = schedule.prefix(1);
        assert!(prefix.is_ok());
        assert_eq!(prefix.as_ref().map(Schedule::len), Ok(1));
        let error = match schedule.prefix(2) {
            Ok(_) => panic!("prefix beyond schedule length should fail"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            ScheduleError::PrefixTooLong {
                requested: 2,
                available: 1,
            }
        ));
        assert_eq!(
            error.to_string(),
            "schedule prefix length 2 exceeds available length 1"
        );
    }

    #[test]
    fn time_vocabulary_converts_icount_and_virtual_instants_exactly() {
        let shift = match Shift::new(4) {
            Ok(shift) => shift,
            Err(error) => panic!("valid shift should construct: {error}"),
        };
        let icount = Icount { retired: 17 };
        let instant = match icount.to_virtual(shift) {
            Ok(instant) => instant,
            Err(error) => panic!("valid icount conversion should succeed: {error}"),
        };
        let unaligned = VirtualInstant { nanos: 275 };

        assert_eq!(instant, VirtualInstant { nanos: 272 });
        assert_eq!(instant.to_icount_floor(shift), Ok(icount));
        assert_eq!(instant.to_icount_ceil(shift), Ok(icount));
        assert_eq!(unaligned.to_icount_floor(shift), Ok(Icount { retired: 17 }));
        assert_eq!(unaligned.to_icount_ceil(shift), Ok(Icount { retired: 18 }));
        let alias: SimInstant = instant;
        assert_eq!(alias, instant);
    }

    #[test]
    fn time_vocabulary_keeps_duration_and_offset_distinct() {
        let earlier = VirtualInstant { nanos: 40 };
        let later = VirtualInstant { nanos: 100 };
        let duration = SimDuration { nanos: 25 };

        assert_eq!(later.duration_since(earlier), SimDuration { nanos: 60 });
        assert_eq!(earlier.duration_since(later), SimDuration { nanos: 0 });
        assert_eq!(earlier + duration, VirtualInstant { nanos: 65 });
        assert_eq!(
            duration + SimDuration { nanos: 5 },
            SimDuration { nanos: 30 }
        );
        assert_eq!(duration * 3, SimDuration { nanos: 75 });
        assert_eq!(
            VirtualInstant { nanos: 10 }.with_skew(SimOffset { nanos: -15 }),
            VirtualInstant::EPOCH
        );
        assert_eq!(
            VirtualInstant { nanos: 10 }.with_skew(SimOffset { nanos: 15 }),
            VirtualInstant { nanos: 25 }
        );
    }

    #[test]
    fn time_vocabulary_rejects_invalid_shift_and_virtual_time_overflow() {
        let invalid = Shift { bits: 64 };
        let valid = Shift { bits: 63 };

        assert_eq!(
            Shift::new(64),
            Err(TimeConversionError::InvalidShift { shift: invalid })
        );
        assert_eq!(
            Icount { retired: 1 }.to_virtual(invalid),
            Err(TimeConversionError::InvalidShift { shift: invalid })
        );
        assert_eq!(
            Icount { retired: 2 }.to_virtual(valid),
            Err(TimeConversionError::VirtualTimeOverflow {
                icount: Icount { retired: 2 },
                shift: valid,
            })
        );
    }

    #[test]
    fn clock_skew_applies_fixed_point_drift_to_guest_reads_only() {
        let scheduler_time = VirtualInstant { nanos: 100 };
        let skew = NodeClockSkew {
            offset: SimOffset { nanos: -10 },
            drift_rate: drift_rate(3, 2),
        };

        assert_eq!(
            skew.guest_visible_time(scheduler_time),
            Ok(VirtualInstant { nanos: 140 })
        );
        assert_eq!(scheduler_time, VirtualInstant { nanos: 100 });
        assert_eq!(
            NodeClockSkew::PERFECT.guest_visible_time(scheduler_time),
            Ok(scheduler_time)
        );
    }

    #[test]
    fn clock_skew_uses_floor_rounding_without_floating_point() {
        let skew = NodeClockSkew {
            offset: SimOffset { nanos: 0 },
            drift_rate: drift_rate(3, 2),
        };

        assert_eq!(
            skew.guest_visible_time(VirtualInstant { nanos: 5 }),
            Ok(VirtualInstant { nanos: 7 })
        );
        assert_eq!(
            NodeClockSkew {
                offset: SimOffset { nanos: -20 },
                drift_rate: drift_rate(1, 3),
            }
            .guest_visible_time(VirtualInstant { nanos: 9 }),
            Ok(VirtualInstant::EPOCH)
        );
    }

    #[test]
    fn clock_skew_rejects_invalid_drift_rate_and_overflow() {
        let invalid = ClockDriftRate {
            numerator: 1,
            denominator: 0,
        };
        let overflowing = ClockDriftRate {
            numerator: u64::MAX,
            denominator: 1,
        };

        assert_eq!(
            ClockDriftRate::new(1, 0),
            Err(TimeConversionError::InvalidDriftRate {
                drift_rate: invalid,
            })
        );
        assert_eq!(
            invalid.apply_floor(VirtualInstant { nanos: 1 }),
            Err(TimeConversionError::InvalidDriftRate {
                drift_rate: invalid,
            })
        );
        assert_eq!(
            overflowing.apply_floor(VirtualInstant { nanos: 2 }),
            Err(TimeConversionError::GuestVisibleTimeOverflow {
                virtual_time: VirtualInstant { nanos: 2 },
                drift_rate: overflowing,
            })
        );
        assert_eq!(
            NodeClockSkew {
                offset: SimOffset { nanos: 1 },
                drift_rate: ClockDriftRate::ONE,
            }
            .guest_visible_time(VirtualInstant { nanos: u64::MAX }),
            Err(TimeConversionError::GuestVisibleTimeOffsetOverflow {
                virtual_time: VirtualInstant { nanos: u64::MAX },
                offset: SimOffset { nanos: 1 },
            })
        );
        assert_eq!(
            NodeClockSkew {
                offset: SimOffset { nanos: 1 },
                drift_rate: invalid,
            }
            .scenario_hash_material(),
            Err(TimeConversionError::InvalidDriftRate {
                drift_rate: invalid,
            })
        );
    }

    #[test]
    fn clock_skew_hash_material_omits_perfect_clock_and_records_overrides() {
        let base = "scenario=clock-skew\nnode=a";
        let perfect_material = material_with_skew(base, NodeClockSkew::default());
        let explicit_perfect_material = material_with_skew(base, NodeClockSkew::PERFECT);
        let equivalent_perfect_material = material_with_skew(
            base,
            NodeClockSkew {
                offset: SimOffset { nanos: 0 },
                drift_rate: drift_rate(2, 2),
            },
        );
        let skewed = NodeClockSkew {
            offset: SimOffset { nanos: 50 },
            drift_rate: drift_rate(1001, 1000),
        };
        let skewed_material = material_with_skew(base, skewed);

        assert_eq!(NodeClockSkew::PERFECT.scenario_hash_material(), Ok(None));
        assert_eq!(perfect_material, base);
        assert_eq!(explicit_perfect_material, base);
        assert_eq!(equivalent_perfect_material, base);
        assert!(skewed_material.contains("clock_skew_offset_ns=50"));
        assert!(skewed_material.contains("clock_drift_rate=1001/1000"));
        assert!(skewed_material.contains("clock_drift_rounding=floor"));
        assert!(skewed_material.contains("clock_skew_applies_to=guest-visible-only"));
        assert!(skewed_material.contains("clock_skew_scheduling_axis=unskewed-icount-derived"));
        assert_ne!(
            ScenarioDef::from_canonical_material("crucible.test.clock-skew", &perfect_material)
                .id(),
            ScenarioDef::from_canonical_material("crucible.test.clock-skew", &skewed_material).id(),
        );
    }

    #[test]
    fn canonical_material_builds_stable_scenario_identity() {
        let first =
            ScenarioDef::from_canonical_material("crucible.test.scenario", "field=a\nvalue=1");
        let second =
            ScenarioDef::from_canonical_material("crucible.test.scenario", "field=a\nvalue=1");
        let changed_material =
            ScenarioDef::from_canonical_material("crucible.test.scenario", "field=a\nvalue=2");
        let changed_domain =
            ScenarioDef::from_canonical_material("crucible.test.other", "field=a\nvalue=1");

        assert_eq!(first, second);
        assert_ne!(first.id(), changed_material.id());
        assert_ne!(first.id(), changed_domain.id());
    }

    #[test]
    fn scenario_def_form_is_immutable_pure_four_tuple_value() {
        let blob_ref = |label: &str| {
            ContentAddressedBlobRef::from_hash(ContentHash::from_canonical_material(
                "crucible.test.scenario-def-value.blob",
                label,
            ))
        };
        let world = world_from_nodes_and_links(
            vec![
                WorldNode {
                    kernel: Some(blob_ref("kernel-a")),
                    root_image: Some(blob_ref("root-a")),
                    initrd: Some(blob_ref("initrd-a")),
                    ..ready_node(
                        "a",
                        ReadyPoint::FixedIcount {
                            icount: Icount { retired: 11 },
                        },
                    )
                },
                ready_node(
                    "b",
                    ReadyPoint::FixedIcount {
                        icount: Icount { retired: 13 },
                    },
                ),
            ],
            vec![transport_link("a", "b", 10, 1, 0, Some(1_000_000))],
        );
        let plan = Plan::from_entries_for_world(
            &world,
            vec![
                PlanEntry::Activate {
                    at: VirtualTime { ticks: 5 },
                    tag: tag("crash-b"),
                    fault: MembershipFault::Crash {
                        node: node_id("b"),
                        restart: RestartPolicy::StayDown,
                    },
                },
                PlanEntry::Heal {
                    at: VirtualTime { ticks: 9 },
                    tag: tag("crash-b"),
                },
            ],
        )
        .unwrap_or_else(|error| panic!("plan should be valid: {error}"));
        let properties = Properties::from_assertions_for_world(
            &world,
            vec![assertion(
                "a-alive",
                "node a remains alive",
                Property::Always {
                    predicate: named_predicate("node_alive", &["a"]),
                },
            )],
        )
        .unwrap_or_else(|error| panic!("properties should be valid: {error}"));
        let seed = Seed::from_u64(0x0010_0001);
        let form = ScenarioDefForm::from_components(&world, &plan, &properties, seed)
            .unwrap_or_else(|error| panic!("scenario form should be valid: {error}"));
        let scenario = form.scenario_def();

        assert_eq!(form.world(), &world);
        assert_eq!(form.plan(), &plan);
        assert_eq!(form.properties(), &properties);
        assert_eq!(form.seed(), seed);
        assert_eq!(form.id(), scenario.id());
        assert_eq!(scenario.seed(), seed);

        for case in 0..8 {
            let seed = Seed::from_u64(case);
            let left = ScenarioDefForm::from_components(&world, &plan, &properties, seed)
                .unwrap_or_else(|error| panic!("left scenario form should be valid: {error}"));
            let right = ScenarioDefForm::from_components(&world, &plan, &properties, seed)
                .unwrap_or_else(|error| panic!("right scenario form should be valid: {error}"));
            assert_eq!(left, right);
            assert_eq!(left.id(), right.id());
            assert_eq!(left.scenario_def(), right.scenario_def());
            assert_eq!(left.canonical_bytes(), right.canonical_bytes());
        }

        let original_id = form.id();
        let changed_world = world_from_nodes_and_links(
            vec![WorldNode {
                kernel: Some(blob_ref("kernel-b")),
                ..ready_node(
                    "a",
                    ReadyPoint::FixedIcount {
                        icount: Icount { retired: 11 },
                    },
                )
            }],
            Vec::new(),
        );
        let changed_plan = Plan::from_entries_for_world(
            &world,
            vec![PlanEntry::Activate {
                at: VirtualTime { ticks: 5 },
                tag: tag("isolate-a"),
                fault: MembershipFault::Isolate { node: node_id("a") },
            }],
        )
        .unwrap_or_else(|error| panic!("changed plan should be valid: {error}"));
        let changed_properties = Properties::from_assertions_for_world(
            &world,
            vec![assertion(
                "b-alive",
                "node b remains alive",
                Property::Always {
                    predicate: named_predicate("node_alive", &["b"]),
                },
            )],
        )
        .unwrap_or_else(|error| panic!("changed properties should be valid: {error}"));

        assert_eq!(form.id(), original_id);
        assert_eq!(form.world(), &world);
        assert_ne!(
            ScenarioDefForm::from_components(
                &changed_world,
                &Plan::empty(),
                &Properties::empty(),
                seed
            )
            .unwrap_or_else(|error| panic!("changed-world form should be valid: {error}"))
            .id(),
            original_id
        );
        assert_ne!(
            ScenarioDefForm::from_components(&world, &changed_plan, &properties, seed)
                .unwrap_or_else(|error| panic!("changed-plan form should be valid: {error}"))
                .id(),
            original_id
        );
        assert_ne!(
            ScenarioDefForm::from_components(&world, &plan, &changed_properties, seed)
                .unwrap_or_else(|error| panic!("changed-properties form should be valid: {error}"))
                .id(),
            original_id
        );
        assert_ne!(
            ScenarioDefForm::from_components(&world, &plan, &properties, Seed::from_u64(2))
                .unwrap_or_else(|error| panic!("changed-seed form should be valid: {error}"))
                .id(),
            original_id
        );
        assert!(matches!(
            ContentAddressedBlobRef::parse("kernel", "/nix/store/not-a-content-ref"),
            Err(EngineError::ScenarioImageReferenceNotContentAddressed { field, .. })
                if field == "kernel"
        ));
    }

    #[test]
    fn scenario_layers_stay_structurally_orthogonal() {
        let partition_entry = PlanEntry::Activate {
            at: VirtualTime { ticks: 7 },
            tag: tag("split-a-b"),
            fault: MembershipFault::Partition {
                endpoint_a: node_id("a"),
                endpoint_b: node_id("b"),
                direction: PartitionDirection::Bidirectional,
            },
        };
        let property_assertion = assertion(
            "a-reachable",
            "node a remains reachable",
            Property::Always {
                predicate: named_predicate("node_alive", &["a"]),
            },
        );
        let world = world_from_nodes_and_links(
            two_ready_nodes(),
            vec![transport_link("a", "b", 10, 1, 0, Some(1_000_000))],
        );
        let plan = Plan::from_entries_for_world(&world, vec![partition_entry.clone()])
            .unwrap_or_else(|error| panic!("plan should be valid: {error}"));
        let properties =
            Properties::from_assertions_for_world(&world, vec![property_assertion.clone()])
                .unwrap_or_else(|error| panic!("properties should be valid: {error}"));
        let seed = Seed::from_u64(0x0010_0002);
        let form = ScenarioDefForm::from_components(&world, &plan, &properties, seed)
            .unwrap_or_else(|error| panic!("scenario form should be valid: {error}"));
        let built = ScenarioBuilder::new()
            .node("a", NodeTemplate::fixed_icount(Icount { retired: 1 }))
            .node("b", NodeTemplate::fixed_icount(Icount { retired: 2 }))
            .link_with_transport(
                "a",
                "b",
                SimDuration { nanos: 10 },
                SimDuration { nanos: 1 },
                LinkLossProbability::ZERO,
                Some(1_000_000),
            )
            .plan_entry(partition_entry.clone())
            .property(property_assertion.clone())
            .seed(seed)
            .build()
            .unwrap_or_else(|error| panic!("builder scenario should be valid: {error}"));

        assert_eq!(built, form.scenario_def());

        let other_seed_form =
            ScenarioDefForm::from_components(&world, &plan, &properties, Seed::from_u64(99))
                .unwrap_or_else(|error| panic!("other-seed form should be valid: {error}"));
        assert_eq!(other_seed_form.world().id(), form.world().id());
        assert_eq!(
            other_seed_form.plan().content_hash(),
            form.plan().content_hash()
        );
        assert_eq!(
            other_seed_form.properties().content_hash(),
            form.properties().content_hash()
        );
        assert_ne!(other_seed_form.id(), form.id());

        let changed_plan = Plan::from_entries_for_world(
            &world,
            vec![PlanEntry::Activate {
                at: VirtualTime { ticks: 7 },
                tag: tag("crash-b"),
                fault: MembershipFault::Crash {
                    node: node_id("b"),
                    restart: RestartPolicy::StayDown,
                },
            }],
        )
        .unwrap_or_else(|error| panic!("changed plan should be valid: {error}"));
        let changed_plan_form =
            ScenarioDefForm::from_components(&world, &changed_plan, &properties, seed)
                .unwrap_or_else(|error| panic!("changed-plan form should be valid: {error}"));
        assert_eq!(changed_plan_form.world().id(), form.world().id());
        assert_eq!(
            changed_plan_form.properties().content_hash(),
            form.properties().content_hash()
        );
        assert_ne!(
            changed_plan_form.plan().content_hash(),
            form.plan().content_hash()
        );
        assert_ne!(changed_plan_form.id(), form.id());

        let changed_properties = Properties::from_assertions_for_world(
            &world,
            vec![assertion(
                "b-reachable",
                "node b remains reachable",
                Property::Always {
                    predicate: named_predicate("node_alive", &["b"]),
                },
            )],
        )
        .unwrap_or_else(|error| panic!("changed properties should be valid: {error}"));
        let changed_properties_form =
            ScenarioDefForm::from_components(&world, &plan, &changed_properties, seed)
                .unwrap_or_else(|error| panic!("changed-properties form should be valid: {error}"));
        assert_eq!(changed_properties_form.world().id(), form.world().id());
        assert_eq!(
            changed_properties_form.plan().content_hash(),
            form.plan().content_hash()
        );
        assert_ne!(
            changed_properties_form.properties().content_hash(),
            form.properties().content_hash()
        );
        assert_ne!(changed_properties_form.id(), form.id());

        let toml = form
            .to_canonical_toml()
            .unwrap_or_else(|error| panic!("scenario form should serialize: {error}"));
        assert!(toml.contains("[[world.link]]"));
        assert!(toml.contains("[[plan.entry]]"));
        assert!(toml.contains("[[properties.assertion]]"));
        assert!(toml.contains("seed = \"0x"));
        assert!(!toml.contains("boot_event"));
        assert!(!toml.contains("entrypoint"));

        let missing_link_fault = ScenarioBuilder::new()
            .node("a", NodeTemplate::fixed_icount(Icount { retired: 1 }))
            .node("b", NodeTemplate::fixed_icount(Icount { retired: 2 }))
            .plan_entry(partition_entry)
            .build();
        assert!(matches!(
            missing_link_fault,
            Err(EngineError::PlanFaultUnknownLink { .. })
        ));

        let assertion_cannot_declare_node = ScenarioBuilder::new()
            .node("a", NodeTemplate::fixed_icount(Icount { retired: 1 }))
            .property(assertion(
                "missing-node",
                "properties cannot declare topology",
                Property::Always {
                    predicate: named_predicate("node_alive", &["missing"]),
                },
            ))
            .build();
        assert!(matches!(
            assertion_cannot_declare_node,
            Err(EngineError::PropertyPredicateUnknownNode { .. })
        ));

        let link_cannot_declare_missing_node = ScenarioBuilder::new()
            .node("a", NodeTemplate::fixed_icount(Icount { retired: 1 }))
            .link("a", "missing")
            .build();
        assert!(matches!(
            link_cannot_declare_missing_node,
            Err(EngineError::WorldLinkUnknownNode { .. })
        ));
    }

    #[test]
    fn spatial_components_have_independent_content_addresses_and_cross_reuse() {
        let seed = Seed::from_u64(0x0010_0003);
        let world = world_from_nodes_and_links(
            two_ready_nodes(),
            vec![transport_link("a", "b", 10, 1, 0, Some(1_000_000))],
        );
        let compatible_world = world_from_nodes_and_links(
            vec![
                ready_node(
                    "a",
                    ReadyPoint::FixedIcount {
                        icount: Icount { retired: 11 },
                    },
                ),
                ready_node(
                    "b",
                    ReadyPoint::FixedIcount {
                        icount: Icount { retired: 12 },
                    },
                ),
            ],
            vec![transport_link("a", "b", 20, 2, 0, Some(2_000_000))],
        );
        let plan_entry = PlanEntry::Activate {
            at: VirtualTime { ticks: 3 },
            tag: tag("split-a-b"),
            fault: MembershipFault::Partition {
                endpoint_a: node_id("b"),
                endpoint_b: node_id("a"),
                direction: PartitionDirection::Bidirectional,
            },
        };
        let plan = Plan::from_entries_for_world(&world, vec![plan_entry.clone()])
            .unwrap_or_else(|error| panic!("plan should be valid: {error}"));
        let plan_reused = Plan::from_entries_for_world(&compatible_world, plan.entries().to_vec())
            .unwrap_or_else(|error| panic!("plan should reuse across compatible world: {error}"));
        let properties = Properties::from_assertions_for_world(
            &world,
            vec![assertion(
                "a-alive",
                "node a remains alive",
                Property::Always {
                    predicate: named_predicate("node_alive", &["a"]),
                },
            )],
        )
        .unwrap_or_else(|error| panic!("properties should be valid: {error}"));
        let properties_reused = Properties::from_assertions_for_world(
            &compatible_world,
            properties.assertions().to_vec(),
        )
        .unwrap_or_else(|error| panic!("properties should reuse across compatible world: {error}"));

        let world_material = String::from_utf8(world.canonical_bytes())
            .unwrap_or_else(|error| panic!("world material should be utf8: {error}"));
        let plan_material = String::from_utf8(plan.canonical_bytes())
            .unwrap_or_else(|error| panic!("plan material should be utf8: {error}"));
        let properties_material = String::from_utf8(properties.canonical_bytes())
            .unwrap_or_else(|error| panic!("properties material should be utf8: {error}"));
        assert_eq!(
            world.id(),
            ContentHash::from_canonical_material("crucible.model.world.v1", &world_material)
        );
        assert_eq!(
            plan.content_hash(),
            ContentHash::from_canonical_material("crucible.model.plan.v1", &plan_material)
        );
        assert_eq!(
            properties.content_hash(),
            ContentHash::from_canonical_material(
                "crucible.model.properties.v1",
                &properties_material
            )
        );
        assert_ne!(world.id(), compatible_world.id());
        assert_eq!(plan.content_hash(), plan_reused.content_hash());
        assert_eq!(properties.content_hash(), properties_reused.content_hash());

        let form = ScenarioDefForm::from_components(&world, &plan, &properties, seed)
            .unwrap_or_else(|error| panic!("scenario form should be valid: {error}"));
        let reused_world_form = ScenarioDefForm::from_components(
            &world,
            &Plan::empty(),
            &Properties::empty(),
            Seed::from_u64(0x0010_0004),
        )
        .unwrap_or_else(|error| panic!("same-world scenario should be valid: {error}"));
        assert_eq!(form.world().id(), reused_world_form.world().id());
        assert_ne!(form.id(), reused_world_form.id());

        let reused_plan_properties_form = ScenarioDefForm::from_components(
            &compatible_world,
            &plan_reused,
            &properties_reused,
            seed,
        )
        .unwrap_or_else(|error| panic!("reused plan/properties scenario should be valid: {error}"));
        assert_ne!(form.world().id(), reused_plan_properties_form.world().id());
        assert_eq!(
            form.plan().content_hash(),
            reused_plan_properties_form.plan().content_hash()
        );
        assert_eq!(
            form.properties().content_hash(),
            reused_plan_properties_form.properties().content_hash()
        );
        assert_ne!(form.id(), reused_plan_properties_form.id());

        let changed_plan = Plan::from_entries_for_world(
            &world,
            vec![PlanEntry::Activate {
                at: VirtualTime { ticks: 3 },
                tag: tag("crash-b"),
                fault: MembershipFault::Crash {
                    node: node_id("b"),
                    restart: RestartPolicy::StayDown,
                },
            }],
        )
        .unwrap_or_else(|error| panic!("changed plan should be valid: {error}"));
        let changed_plan_form =
            ScenarioDefForm::from_components(&world, &changed_plan, &properties, seed)
                .unwrap_or_else(|error| panic!("changed-plan scenario should be valid: {error}"));
        assert_eq!(form.world().id(), changed_plan_form.world().id());
        assert_ne!(form.plan().content_hash(), changed_plan.content_hash());
        assert_ne!(form.id(), changed_plan_form.id());

        let changed_properties = Properties::from_assertions_for_world(
            &world,
            vec![assertion(
                "b-alive",
                "node b remains alive",
                Property::Always {
                    predicate: named_predicate("node_alive", &["b"]),
                },
            )],
        )
        .unwrap_or_else(|error| panic!("changed properties should be valid: {error}"));
        let changed_properties_form =
            ScenarioDefForm::from_components(&world, &plan, &changed_properties, seed)
                .unwrap_or_else(|error| {
                    panic!("changed-properties scenario should be valid: {error}")
                });
        assert_eq!(form.world().id(), changed_properties_form.world().id());
        assert_ne!(
            form.properties().content_hash(),
            changed_properties.content_hash()
        );
        assert_ne!(form.id(), changed_properties_form.id());
    }

    #[test]
    fn world_node_launch_inputs_are_portable_and_identity_bearing() {
        let blob_ref = |label: &str| {
            ContentAddressedBlobRef::from_hash(ContentHash::from_canonical_material(
                "crucible.test.node-launch-inputs.blob",
                label,
            ))
        };
        let kernel = blob_ref("kernel");
        let root_image = blob_ref("root-image");
        let initrd = blob_ref("initrd");
        let ready_point = ReadyPoint::FixedIcount {
            icount: Icount { retired: 77 },
        };
        let cmdline = "console=ttyS0 root=/dev/vda ro";
        let base_node = WorldNode {
            id: node_id("vm"),
            arch: VmArchitecture::Aarch64,
            memory_mib: 2048,
            cmdline: cmdline.to_owned(),
            ready_point: ready_point.clone(),
            white_box: WhiteBoxPolicy::Enabled,
            smp_vcpus: 2,
            icount_shift: 1,
            kernel: Some(kernel),
            root_image: Some(root_image),
            initrd: Some(initrd),
        };
        let base_world = world_from_nodes(vec![base_node.clone()]);
        let base_scenario = base_world.scenario_def();
        let template_scenario = ScenarioBuilder::new()
            .node(
                "vm",
                NodeTemplate::fixed_icount(Icount { retired: 77 })
                    .arch(VmArchitecture::Aarch64)
                    .memory_mib(2048)
                    .cmdline(cmdline)
                    .white_box(WhiteBoxPolicy::Enabled)
                    .smp_vcpus(2)
                    .icount_shift(1)
                    .kernel(kernel)
                    .root_image(root_image)
                    .initrd(initrd),
            )
            .build()
            .unwrap_or_else(|error| panic!("template scenario should be valid: {error}"));
        let material = String::from_utf8(base_world.canonical_bytes())
            .unwrap_or_else(|error| panic!("world material should be utf8: {error}"));
        let toml = base_world
            .to_canonical_toml()
            .unwrap_or_else(|error| panic!("world TOML should serialize: {error}"));
        let host_path_toml = toml.replacen(&kernel.to_uri(), "/nix/store/kernel", 1);
        let round_trip_binary = World::from_compact_binary(&base_world.to_compact_binary())
            .unwrap_or_else(|error| panic!("world binary should parse: {error}"));

        assert_eq!(template_scenario, base_scenario);
        assert_eq!(
            base_world.id(),
            ContentHash::from_canonical_material("crucible.model.world.v1", &material)
        );
        assert_eq!(base_world.nodes().len(), 1);
        assert_eq!(base_world.nodes()[0].arch, VmArchitecture::Aarch64);
        assert_eq!(base_world.nodes()[0].memory_mib, 2048);
        assert_eq!(base_world.nodes()[0].cmdline, cmdline);
        assert_eq!(base_world.nodes()[0].ready_point, ready_point);
        assert_eq!(base_world.nodes()[0].white_box, WhiteBoxPolicy::Enabled);
        assert_eq!(base_world.nodes()[0].smp_vcpus, 2);
        assert_eq!(base_world.nodes()[0].icount_shift, 1);
        assert_eq!(base_world.nodes()[0].kernel, Some(kernel));
        assert_eq!(base_world.nodes()[0].root_image, Some(root_image));
        assert_eq!(base_world.nodes()[0].initrd, Some(initrd));
        assert_eq!(
            World::from_canonical_toml(&toml)
                .unwrap_or_else(|error| panic!("world TOML should parse: {error}")),
            base_world
        );
        assert_eq!(round_trip_binary, base_world);
        assert!(toml.contains("arch = \"aarch64\""));
        assert!(toml.contains("memory_mib = 2048"));
        assert!(toml.contains("cmdline = \"console=ttyS0 root=/dev/vda ro\""));
        assert!(material.contains("arch=aarch64"));
        assert!(material.contains("memory_mib=2048"));
        assert!(material.contains(&format!("cmdline_len={}", cmdline.len())));
        assert!(material.contains("cmdline=console=ttyS0 root=/dev/vda ro"));

        let assert_identity_changes = |label: &str, node: WorldNode| {
            let changed_world = world_from_nodes(vec![node]);
            assert_ne!(base_world.id(), changed_world.id(), "{label}");
            assert_ne!(
                base_scenario.id(),
                changed_world.scenario_def().id(),
                "{label}"
            );
        };
        assert_identity_changes(
            "architecture must affect identity",
            WorldNode {
                arch: VmArchitecture::X86_64,
                ..base_node.clone()
            },
        );
        assert_identity_changes(
            "memory size must affect identity",
            WorldNode {
                memory_mib: 4096,
                ..base_node.clone()
            },
        );
        assert_identity_changes(
            "kernel command line must affect identity",
            WorldNode {
                cmdline: format!("{cmdline} quiet"),
                ..base_node.clone()
            },
        );
        assert_identity_changes(
            "kernel blob must affect identity",
            WorldNode {
                kernel: Some(blob_ref("kernel-v2")),
                ..base_node.clone()
            },
        );
        assert_identity_changes(
            "root image blob must affect identity",
            WorldNode {
                root_image: Some(blob_ref("root-image-v2")),
                ..base_node.clone()
            },
        );
        assert_identity_changes(
            "initrd blob must affect identity",
            WorldNode {
                initrd: Some(blob_ref("initrd-v2")),
                ..base_node.clone()
            },
        );
        assert_identity_changes(
            "fixed vCPU count must affect identity",
            WorldNode {
                smp_vcpus: 3,
                ..base_node.clone()
            },
        );
        assert_identity_changes(
            "fixed icount shift must affect identity",
            WorldNode {
                icount_shift: 2,
                ..base_node.clone()
            },
        );
        assert_identity_changes(
            "ready point must affect identity",
            WorldNode {
                ready_point: ReadyPoint::ConsoleMarker {
                    marker: String::from("ready"),
                },
                ..base_node.clone()
            },
        );
        assert_identity_changes(
            "white-box opt-in must affect identity",
            WorldNode {
                white_box: WhiteBoxPolicy::Disabled,
                ..base_node.clone()
            },
        );

        assert!(matches!(
            World::from_nodes(vec![WorldNode {
                memory_mib: 0,
                ..base_node
            }]),
            Err(EngineError::WorldNodeMemoryMibZero { node }) if node == node_id("vm")
        ));
        assert!(matches!(
            ContentAddressedBlobRef::parse("kernel", "/nix/store/kernel"),
            Err(EngineError::ScenarioImageReferenceNotContentAddressed { field, value })
                if field == "kernel" && value == "/nix/store/kernel"
        ));
        assert!(matches!(
            World::from_canonical_toml(&host_path_toml),
            Err(EngineError::ScenarioImageReferenceNotContentAddressed { field, value })
                if field == "kernel" && value == "/nix/store/kernel"
        ));
    }

    #[test]
    fn configuration_id_is_content_addressed_by_def_and_schedule() {
        let scenario =
            ScenarioDef::from_canonical_material("crucible.test.configuration", "node=a\nseed=1");
        let same_scenario =
            ScenarioDef::from_canonical_material("crucible.test.configuration", "node=a\nseed=1");
        let base_schedule = Schedule::empty().appended(Decision::RngDraw(RngDecision {
            stream: RngStreamId::for_node("node-a/faults"),
            value: 7,
        }));
        let same = Configuration {
            def: same_scenario,
            schedule: base_schedule.clone(),
        };
        let changed_schedule = Configuration {
            def: scenario.clone(),
            schedule: base_schedule.appended(Decision::FaultFires(FaultDecision {
                at: VirtualTime { ticks: 1 },
                fault: FaultId {
                    name: String::from("link-drop"),
                },
                fired: true,
            })),
        };
        let base = Configuration {
            def: scenario,
            schedule: same.schedule.clone(),
        };

        assert_eq!(base, same);
        assert_eq!(base.id(), same.id());
        assert_eq!(base.id(), base.content_hash());
        assert_ne!(base.schedule, changed_schedule.schedule);
        assert_ne!(base.id(), changed_schedule.id());
    }

    #[test]
    fn configuration_id_property_covers_generated_def_schedule_pairs() {
        let mut checked_cases = 0;

        for seed in 0..64 {
            let def = generated_scenario(seed);
            let schedule = generated_schedule(seed, 6);
            let base = Configuration {
                def: def.clone(),
                schedule: schedule.clone(),
            };
            let same = Configuration {
                def: generated_scenario(seed),
                schedule: schedule.clone(),
            };
            let changed_schedule = Configuration {
                def: def.clone(),
                schedule: schedule.appended(generated_decision(seed, 99)),
            };
            let same_length_changed_schedule = Configuration {
                def: def.clone(),
                schedule: generated_schedule(seed + 10_000, 6),
            };
            let reordered_schedule = Configuration {
                def: def.clone(),
                schedule: swap_first_two_decisions(&base.schedule),
            };
            let changed_def = Configuration {
                def: generated_scenario(seed + 1_000),
                schedule: base.schedule.clone(),
            };

            assert_eq!(base, same);
            assert_eq!(base.id(), same.id());
            assert_eq!(base.id(), base.content_hash());
            assert_ne!(base.schedule, changed_schedule.schedule);
            assert_ne!(base.id(), changed_schedule.id());
            assert_eq!(
                base.schedule.len(),
                same_length_changed_schedule.schedule.len()
            );
            assert_ne!(base.schedule, same_length_changed_schedule.schedule);
            assert_ne!(base.id(), same_length_changed_schedule.id());
            assert_eq!(base.schedule.len(), reordered_schedule.schedule.len());
            assert_ne!(base.schedule, reordered_schedule.schedule);
            assert_ne!(base.id(), reordered_schedule.id());
            assert_ne!(base.def, changed_def.def);
            assert_ne!(base.id(), changed_def.id());

            checked_cases += 1;
        }

        assert_eq!(checked_cases, 64);
    }

    #[test]
    fn reduce_is_pure_over_scenario_and_schedule() {
        let scenario =
            ScenarioDef::from_canonical_material("crucible.test.reduce", "node=a\nseed=1");
        let other_scenario =
            ScenarioDef::from_canonical_material("crucible.test.reduce", "node=a\nseed=2");
        let first_decision = Decision::RngDraw(RngDecision {
            stream: RngStreamId::for_node("node-a/faults"),
            value: 7,
        });
        let second_decision = Decision::FaultFires(FaultDecision {
            at: VirtualTime { ticks: 10 },
            fault: FaultId {
                name: String::from("link-drop"),
            },
            fired: true,
        });
        let schedule = Schedule::empty()
            .appended(first_decision.clone())
            .appended(second_decision.clone());
        let reordered = Schedule::empty()
            .appended(second_decision)
            .appended(first_decision);

        let first = reduce(&scenario, &schedule);
        let second = reduce(&scenario, &schedule);
        let changed_scenario = reduce(&other_scenario, &schedule);
        let changed_order = reduce(&scenario, &reordered);

        assert_eq!(first, second);
        assert_ne!(first, changed_scenario);
        assert_ne!(first, changed_order);
    }

    #[test]
    fn reduce_is_prefix_closed_by_schedule_hash() {
        let scenario =
            ScenarioDef::from_canonical_material("crucible.test.reduce", "node=a\nseed=prefix");
        let root = Configuration::genesis(scenario.clone());
        let child = step(
            &root,
            Decision::DeliveryOrder(DeliveryOrderDecision {
                at: VirtualTime { ticks: 4 },
                order: vec![event_key(4, 1), event_key(4, 2)],
            }),
        );
        let grandchild = step(
            &child,
            Decision::AppRandom(AppRandomDecision {
                node: NodeId {
                    name: String::from("node-a"),
                },
                stream: RngStreamId::for_node("app/request"),
                request_id: 3,
                width: 16,
                value: 0xace,
            }),
        );
        let child_prefix = match grandchild.schedule.prefix(1) {
            Ok(prefix) => prefix,
            Err(error) => panic!("valid prefix should not fail: {error}"),
        };
        let root_reduced = reduce(&scenario, &root.schedule);
        let child_reduced = reduce(&scenario, &child.schedule);
        let child_prefix_reduced = reduce(&scenario, &child_prefix);
        let grandchild_reduced = reduce(&scenario, &grandchild.schedule);

        assert_eq!(child.schedule, child_prefix);
        assert_eq!(child_reduced, child_prefix_reduced);
        assert_ne!(root_reduced, child_reduced);
        assert_ne!(child_reduced, grandchild_reduced);
        assert_ne!(root.content_hash(), child.content_hash());
        assert_ne!(child.content_hash(), grandchild.content_hash());
        assert_ne!(
            child.schedule.content_hash(),
            grandchild.schedule.content_hash()
        );
    }

    #[test]
    fn resume_continue_matches_uninterrupted_run_by_fingerprint() {
        let scenario = generated_scenario(0x500);
        let mut uninterrupted = DecisionRecorder::new(Configuration::genesis(scenario.clone()));
        for index in 0..8 {
            record_representative_decision(&mut uninterrupted, index);
        }
        let uninterrupted = uninterrupted.into_configuration();

        let mut prefix = DecisionRecorder::new(Configuration::genesis(scenario));
        for index in 0..4 {
            record_representative_decision(&mut prefix, index);
        }
        let prefix = prefix.into_configuration();
        let prefix_len = prefix.schedule.len();
        let mut resumed = DecisionRecorder::new(prefix.clone());
        for index in 4..8 {
            record_representative_decision(&mut resumed, index);
        }
        let resumed = resumed.into_configuration();

        assert_eq!(
            uninterrupted.schedule.prefix(prefix_len),
            Ok(prefix.schedule.clone())
        );
        assert_ne!(
            configuration_execution_fingerprint(&prefix),
            configuration_execution_fingerprint(&uninterrupted)
        );
        assert_eq!(uninterrupted, resumed);
        assert_eq!(
            configuration_execution_fingerprint(&uninterrupted),
            configuration_execution_fingerprint(&resumed)
        );
    }

    #[test]
    fn instantiate_loads_exact_snapshot_without_genesis() {
        let scenario = generated_scenario(41);
        let config = Configuration {
            def: scenario,
            schedule: generated_schedule(41, 3),
        };
        let graph = match TemporalGraph::empty()
            .with_cached_snapshot(&config, fat_checkpoint_for(&config))
        {
            Ok(graph) => graph,
            Err(error) => panic!("valid exact snapshot should register: {error}"),
        };

        let runtime = match instantiate(&graph, &config) {
            Ok(runtime) => runtime,
            Err(error) => panic!("exact snapshot should instantiate without genesis: {error}"),
        };

        assert_eq!(runtime.configuration, config.id());
        assert_eq!(runtime.id, reduced_state_id(&config));
    }

    #[test]
    fn instantiate_replays_from_nearest_cached_ancestor() {
        let scenario = generated_scenario(43);
        let config = Configuration {
            def: scenario.clone(),
            schedule: generated_schedule(43, 5),
        };
        let near_ancestor = Configuration {
            def: scenario.clone(),
            schedule: match config.schedule.prefix(3) {
                Ok(schedule) => schedule,
                Err(error) => panic!("valid ancestor prefix should construct: {error}"),
            },
        };
        let far_ancestor = Configuration {
            def: scenario,
            schedule: match config.schedule.prefix(1) {
                Ok(schedule) => schedule,
                Err(error) => panic!("valid ancestor prefix should construct: {error}"),
            },
        };
        let graph = match TemporalGraph::empty()
            .with_cached_snapshot(&far_ancestor, fat_checkpoint_for(&far_ancestor))
            .and_then(|graph| {
                graph.with_cached_snapshot(&near_ancestor, fat_checkpoint_for(&near_ancestor))
            }) {
            Ok(graph) => graph,
            Err(error) => panic!("valid ancestor snapshots should register: {error}"),
        };

        let selected_ancestor = match graph.nearest_cached_ancestor(&config) {
            Ok(Some(ancestor)) => ancestor,
            Ok(None) => panic!("nearest cached ancestor should exist"),
            Err(error) => panic!("ancestor lookup should succeed: {error}"),
        };
        let runtime = match instantiate(&graph, &config) {
            Ok(runtime) => runtime,
            Err(error) => panic!("ancestor replay should instantiate: {error}"),
        };

        assert_eq!(selected_ancestor, near_ancestor);
        assert_eq!(runtime.configuration, config.id());
        assert_eq!(runtime.id, reduced_state_id(&config));
    }

    #[test]
    fn instantiate_loads_baked_genesis_for_genesis() {
        let scenario = generated_scenario(47);
        let genesis = Configuration::genesis(scenario.clone());
        let graph = match TemporalGraph::empty()
            .with_baked_genesis(&scenario, genesis_checkpoint_for(&genesis))
        {
            Ok(graph) => graph,
            Err(error) => panic!("valid baked genesis should register: {error}"),
        };

        let runtime = match instantiate(&graph, &genesis) {
            Ok(runtime) => runtime,
            Err(error) => panic!("baked genesis should instantiate genesis: {error}"),
        };

        assert_eq!(runtime.configuration, genesis.id());
        assert_eq!(runtime.id, reduced_state_id(&genesis));
    }

    #[test]
    fn instantiate_replays_from_baked_genesis_for_uncached_descendant() {
        let scenario = generated_scenario(53);
        let genesis = Configuration::genesis(scenario.clone());
        let config = Configuration {
            def: scenario.clone(),
            schedule: generated_schedule(53, 4),
        };
        let graph = match TemporalGraph::empty()
            .with_baked_genesis(&scenario, genesis_checkpoint_for(&genesis))
        {
            Ok(graph) => graph,
            Err(error) => panic!("valid baked genesis should register: {error}"),
        };

        let runtime = match instantiate(&graph, &config) {
            Ok(runtime) => runtime,
            Err(error) => panic!("baked-genesis replay should instantiate descendant: {error}"),
        };

        assert_eq!(runtime.configuration, config.id());
        assert_eq!(runtime.id, reduced_state_id(&config));
    }

    #[test]
    fn temporal_graph_save_materializes_fat_checkpoint_keyed_by_configuration() {
        let scenario = generated_scenario(75);
        let genesis = Configuration::genesis(scenario.clone());
        let config = Configuration {
            def: scenario.clone(),
            schedule: generated_schedule(75, 2),
        };
        let mut graph = match TemporalGraph::empty()
            .with_baked_genesis(&scenario, genesis_checkpoint_for(&genesis))
        {
            Ok(graph) => graph,
            Err(error) => panic!("valid baked genesis should register: {error}"),
        };

        let checkpoint = match graph.save_checkpoint(&config) {
            Ok(checkpoint) => checkpoint,
            Err(error) => panic!("save should materialize through instantiate: {error}"),
        };
        let saved_again = match graph.save_checkpoint(&config) {
            Ok(checkpoint) => checkpoint,
            Err(error) => panic!("duplicate save should reuse checkpoint: {error}"),
        };

        assert_eq!(checkpoint, saved_again);
        assert_eq!(checkpoint.configuration, config.id());
        assert_eq!(checkpoint.kind, CheckpointKind::Fat);
        assert_eq!(graph.cached_snapshot(&config), Some(&checkpoint));
        assert_eq!(graph.cached_snapshot_count(), 1);
        assert!(matches!(
            graph.checkpoint_node(config.id()),
            Some(source) if source.kind == CheckpointKind::Thin && source.state.is_none()
        ));
        assert!(graph.contains_configuration(&config));
        assert_eq!(
            instantiate(&graph, &config).map(|runtime| runtime.id),
            Ok(reduced_state_id(&config))
        );
    }

    #[test]
    fn compact_checkpoint_decode_rejects_inconsistent_outer_shape() {
        let config = Configuration::genesis(generated_scenario(87));
        let valid = fat_checkpoint_for(&config);

        let mut fat_without_state = valid.clone();
        fat_without_state.state = None;
        assert!(matches!(
            Checkpoint::from_compact_binary(&fat_without_state.to_compact_binary()),
            Err(EngineError::ScenarioSerialization { reason })
                if reason == "fat checkpoint is missing materialized state"
        ));

        let mut thin_with_state = Checkpoint::new(config.id(), config.id(), CheckpointKind::Thin);
        thin_with_state.state = valid.state.clone();
        assert!(matches!(
            Checkpoint::from_compact_binary(&thin_with_state.to_compact_binary()),
            Err(EngineError::ScenarioSerialization { reason })
                if reason == "thin checkpoint carries materialized state"
        ));

        let mut identity_mismatch = valid;
        identity_mismatch.id = ContentHash::from_canonical_material(
            "crucible.test.invalid-checkpoint",
            "identity-mismatch",
        );
        assert!(matches!(
            Checkpoint::from_compact_binary(&identity_mismatch.to_compact_binary()),
            Err(EngineError::ScenarioSerialization { reason })
                if reason == "checkpoint id does not match configuration id"
        ));
    }

    #[test]
    fn temporal_graph_materialized_cache_keeps_thin_checkpoint_source_of_truth() {
        let scenario = generated_scenario(76);
        let genesis = Configuration::genesis(scenario.clone());
        let config = Configuration {
            def: scenario.clone(),
            schedule: generated_schedule(76, 3),
        };
        let mut graph = match TemporalGraph::empty()
            .with_baked_genesis(&scenario, genesis_checkpoint_for(&genesis))
        {
            Ok(graph) => graph,
            Err(error) => panic!("valid baked genesis should register: {error}"),
        };

        let thin = match graph.record_thin_checkpoint(&config) {
            Ok(checkpoint) => checkpoint,
            Err(error) => panic!("thin checkpoint should record: {error}"),
        };
        let fat = match graph.materialize_checkpoint(&config) {
            Ok(checkpoint) => checkpoint,
            Err(error) => panic!("hot checkpoint should materialize: {error}"),
        };
        let source = match graph.checkpoint_node(config.id()) {
            Some(checkpoint) => checkpoint,
            None => panic!("source checkpoint should remain recorded"),
        };

        assert_eq!(thin.id, config.id());
        assert_eq!(thin.kind, CheckpointKind::Thin);
        assert!(thin.state.is_none());
        assert_eq!(fat.id, thin.id);
        assert_eq!(fat.kind, CheckpointKind::Fat);
        assert!(fat.state.is_some());
        assert_eq!(source, &thin);
        assert_eq!(graph.cached_snapshot(&config), Some(&fat));
    }

    #[test]
    fn temporal_graph_evicts_fat_checkpoint_back_to_thin_without_state_change() {
        let scenario = generated_scenario(80);
        let genesis = Configuration::genesis(scenario.clone());
        let config = Configuration {
            def: scenario.clone(),
            schedule: generated_schedule(80, 3),
        };
        let mut graph = match TemporalGraph::empty()
            .with_baked_genesis(&scenario, genesis_checkpoint_for(&genesis))
        {
            Ok(graph) => graph,
            Err(error) => panic!("valid baked genesis should register: {error}"),
        };
        let fat = match graph.materialize_checkpoint(&config) {
            Ok(checkpoint) => checkpoint,
            Err(error) => panic!("checkpoint should materialize: {error}"),
        };
        let exact_runtime = match instantiate(&graph, &config) {
            Ok(runtime) => runtime,
            Err(error) => panic!("exact cached checkpoint should instantiate: {error}"),
        };

        let thin = match graph.evict_fat_checkpoint_to_thin(&config) {
            Ok(checkpoint) => checkpoint,
            Err(error) => panic!("fat checkpoint should evict to thin: {error}"),
        };
        let replay_runtime = match instantiate(&graph, &config) {
            Ok(runtime) => runtime,
            Err(error) => panic!("thin checkpoint should replay from ancestor: {error}"),
        };

        assert_eq!(fat.id, thin.id);
        assert_eq!(thin.kind, CheckpointKind::Thin);
        assert!(thin.state.is_none());
        assert!(graph.cached_snapshot(&config).is_none());
        assert_eq!(graph.cached_snapshot_count(), 0);
        assert_eq!(exact_runtime, replay_runtime);
    }

    #[test]
    fn temporal_graph_gc_cache_collection_preserves_replay_oracle_path() {
        let scenario = generated_scenario(84);
        let genesis = Configuration::genesis(scenario.clone());
        let config = Configuration {
            def: scenario.clone(),
            schedule: generated_schedule(84, 3),
        };
        let mut graph = match TemporalGraph::empty()
            .with_baked_genesis(&scenario, genesis_checkpoint_for(&genesis))
        {
            Ok(graph) => graph,
            Err(error) => panic!("valid baked genesis should register: {error}"),
        };
        let fat = match graph.materialize_checkpoint(&config) {
            Ok(checkpoint) => checkpoint,
            Err(error) => panic!("checkpoint should materialize before cache GC: {error}"),
        };
        let before_check = match graph.replay_checkpoint(&config, &fat) {
            Ok(check) => check,
            Err(error) => panic!("fat snapshot should match thin derivation before GC: {error}"),
        };

        let thin = match graph.collect_cached_snapshot(&config) {
            Ok(Some(checkpoint)) => checkpoint,
            Ok(None) => panic!("fat cache entry should exist before collection"),
            Err(error) => panic!("fat cache collection should succeed: {error}"),
        };
        let replay_runtime = match instantiate(&graph, &config) {
            Ok(runtime) => runtime,
            Err(error) => {
                panic!("thin derivation should remain realizable after cache GC: {error}")
            }
        };
        let after_check = match graph.replay_checkpoint(&config, &fat) {
            Ok(check) => check,
            Err(error) => {
                panic!("fat snapshot should still match thin derivation after GC: {error}")
            }
        };

        assert_eq!(thin.kind, CheckpointKind::Thin);
        assert!(thin.state.is_none());
        assert!(graph.cached_snapshot(&config).is_none());
        assert_eq!(before_check, after_check);
        assert_eq!(replay_runtime.configuration, config.id());
        assert_eq!(replay_runtime.id, reduced_state_id(&config));
    }

    #[test]
    fn temporal_graph_materialization_policy_keeps_cold_or_over_budget_nodes_thin() {
        let scenario = generated_scenario(81);
        let genesis = Configuration::genesis(scenario.clone());
        let first = Configuration {
            def: scenario.clone(),
            schedule: generated_schedule(81, 1),
        };
        let cold = Configuration {
            def: scenario.clone(),
            schedule: generated_schedule(82, 1),
        };
        let over_budget = Configuration {
            def: scenario.clone(),
            schedule: generated_schedule(83, 1),
        };
        let mut graph = match TemporalGraph::empty()
            .with_baked_genesis(&scenario, genesis_checkpoint_for(&genesis))
        {
            Ok(graph) => graph,
            Err(error) => panic!("valid baked genesis should register: {error}"),
        };
        let policy = MaterializationPolicy::with_budget(1);

        let hot = match graph.materialize_hot_checkpoint(
            &first,
            policy,
            MaterializationTrigger::RepeatedForkSource,
        ) {
            Ok(checkpoint) => checkpoint,
            Err(error) => panic!("first hot checkpoint should materialize: {error}"),
        };
        let cold_checkpoint =
            match graph.materialize_hot_checkpoint(&cold, policy, MaterializationTrigger::Cold) {
                Ok(checkpoint) => checkpoint,
                Err(error) => panic!("cold checkpoint should remain thin: {error}"),
            };
        let over_budget_checkpoint = match graph.materialize_hot_checkpoint(
            &over_budget,
            policy,
            MaterializationTrigger::SharedReplayPath,
        ) {
            Ok(checkpoint) => checkpoint,
            Err(error) => panic!("over-budget hot checkpoint should remain thin: {error}"),
        };

        assert_eq!(hot.kind, CheckpointKind::Fat);
        assert_eq!(graph.cached_snapshot_count(), 1);
        assert_eq!(cold_checkpoint.kind, CheckpointKind::Thin);
        assert_eq!(over_budget_checkpoint.kind, CheckpointKind::Thin);
        assert!(graph.cached_snapshot(&cold).is_none());
        assert!(graph.cached_snapshot(&over_budget).is_none());

        match graph.evict_fat_checkpoint_to_thin(&first) {
            Ok(checkpoint) => assert_eq!(checkpoint.kind, CheckpointKind::Thin),
            Err(error) => panic!("eviction should free the materialization budget: {error}"),
        }
        let interactive = match graph.materialize_hot_checkpoint(
            &over_budget,
            policy,
            MaterializationTrigger::InteractiveTarget,
        ) {
            Ok(checkpoint) => checkpoint,
            Err(error) => panic!("interactive target should materialize after eviction: {error}"),
        };

        assert_eq!(interactive.kind, CheckpointKind::Fat);
        assert_eq!(graph.cached_snapshot(&over_budget), Some(&interactive));
        assert_eq!(graph.cached_snapshot_count(), 1);
    }

    #[test]
    fn temporal_graph_savevm_hedge_keeps_unreliable_device_checkpoint_thin() {
        let scenario = generated_scenario(85);
        let genesis = Configuration::genesis(scenario.clone());
        let config = Configuration {
            def: scenario.clone(),
            schedule: generated_schedule(85, 2),
        };
        let device = device_id("block0");
        let checkpoint = fat_checkpoint_with_device_overlay(&config, device.clone());
        let hedge = SavevmCompletenessHedge::with_unreliable_devices([device.clone()]);
        let mut hedged_graph = match TemporalGraph::empty()
            .with_baked_genesis(&scenario, genesis_checkpoint_for(&genesis))
        {
            Ok(graph) => graph,
            Err(error) => panic!("valid baked genesis should register: {error}"),
        };

        let allowed = match hedged_graph.cache_snapshot_with_savevm_hedge(
            &config,
            checkpoint.clone(),
            &SavevmCompletenessHedge::verified(),
        ) {
            Ok(checkpoint) => checkpoint,
            Err(error) => panic!("verified device snapshot should cache as fat: {error}"),
        };
        assert_eq!(hedged_graph.cached_snapshot(&config), Some(&allowed));

        let thin = match hedged_graph.cache_snapshot_with_savevm_hedge(
            &config,
            checkpoint.clone(),
            &hedge,
        ) {
            Ok(checkpoint) => checkpoint,
            Err(error) => panic!("unreliable device snapshot should fall back to thin: {error}"),
        };
        let runtime = match instantiate(&hedged_graph, &config) {
            Ok(runtime) => runtime,
            Err(error) => panic!("thin fallback should replay to the target: {error}"),
        };

        assert!(SavevmCompletenessHedge::verified().allows_checkpoint(&checkpoint));
        assert!(!hedge.allows_checkpoint(&checkpoint));
        assert!(hedge.unreliable_devices().contains(&device));
        assert_eq!(allowed.kind, CheckpointKind::Fat);
        assert_eq!(thin.kind, CheckpointKind::Thin);
        assert!(thin.state.is_none());
        assert!(hedged_graph.cached_snapshot(&config).is_none());
        assert_eq!(hedged_graph.cached_snapshot_count(), 0);
        assert_eq!(runtime.configuration, config.id());
        assert_eq!(runtime.id, reduced_state_id(&config));
    }

    #[test]
    fn temporal_graph_savevm_full_s3_fallback_evicts_hot_checkpoint_to_thin() {
        let scenario = generated_scenario(86);
        let genesis = Configuration::genesis(scenario.clone());
        let config = Configuration {
            def: scenario.clone(),
            schedule: generated_schedule(86, 2),
        };
        let mut graph = match TemporalGraph::empty()
            .with_baked_genesis(&scenario, genesis_checkpoint_for(&genesis))
        {
            Ok(graph) => graph,
            Err(error) => panic!("valid baked genesis should register: {error}"),
        };
        let fat = match graph.materialize_checkpoint(&config) {
            Ok(checkpoint) => checkpoint,
            Err(error) => panic!("checkpoint should materialize before fallback: {error}"),
        };
        let exact_runtime = match instantiate(&graph, &config) {
            Ok(runtime) => runtime,
            Err(error) => panic!("exact snapshot should instantiate before fallback: {error}"),
        };
        let hedge = SavevmCompletenessHedge::thin_replay_until_full_s3();
        let policy = MaterializationPolicy::with_budget(8);

        let thin = match graph.materialize_hot_checkpoint_with_savevm_hedge(
            &config,
            policy,
            MaterializationTrigger::InteractiveTarget,
            &hedge,
        ) {
            Ok(checkpoint) => checkpoint,
            Err(error) => panic!("fallback should evict hot checkpoint to thin: {error}"),
        };
        let replay_runtime = match instantiate(&graph, &config) {
            Ok(runtime) => runtime,
            Err(error) => panic!("thin fallback should replay after eviction: {error}"),
        };

        assert!(!hedge.fat_snapshot_default());
        assert!(hedge.unreliable_devices().is_empty());
        assert_eq!(fat.kind, CheckpointKind::Fat);
        assert_eq!(thin.id, fat.id);
        assert_eq!(thin.kind, CheckpointKind::Thin);
        assert!(thin.state.is_none());
        assert!(graph.cached_snapshot(&config).is_none());
        assert_eq!(graph.cached_snapshot_count(), 0);
        assert_eq!(exact_runtime, replay_runtime);
    }

    #[test]
    fn temporal_graph_replay_checkpoint_is_on_demand_replay_oracle() {
        let scenario = generated_scenario(77);
        let genesis = Configuration::genesis(scenario.clone());
        let config = Configuration {
            def: scenario.clone(),
            schedule: generated_schedule(77, 3),
        };
        let mut graph = match TemporalGraph::empty()
            .with_baked_genesis(&scenario, genesis_checkpoint_for(&genesis))
        {
            Ok(graph) => graph,
            Err(error) => panic!("valid baked genesis should register: {error}"),
        };
        let checkpoint = match graph.save_checkpoint(&config) {
            Ok(checkpoint) => checkpoint,
            Err(error) => panic!("save should materialize checkpoint: {error}"),
        };

        let check = match graph.replay_checkpoint(&config, &checkpoint) {
            Ok(check) => check,
            Err(error) => panic!("fat checkpoint should match thin replay: {error}"),
        };
        let genesis_checkpoint = match graph.save_checkpoint(&genesis) {
            Ok(checkpoint) => checkpoint,
            Err(error) => panic!("genesis save should reuse baked checkpoint: {error}"),
        };
        let genesis_check = match graph.replay_checkpoint(&genesis, &genesis_checkpoint) {
            Ok(check) => check,
            Err(error) => panic!("baked genesis should match thin replay: {error}"),
        };
        let mut corrupted = checkpoint.clone();
        corrupted.id = ContentHash::from_canonical_material(
            "crucible.test.fat-checkpoint.corrupt",
            "wrong-runtime",
        );
        let mismatch = match graph.replay_checkpoint(&config, &corrupted) {
            Ok(_) => panic!("corrupt fat checkpoint should fail replay oracle"),
            Err(error) => error,
        };

        assert_eq!(check.configuration, config.id());
        assert_eq!(check.fat_checkpoint, checkpoint.id);
        assert_eq!(check.thin_checkpoint, checkpoint.id);
        assert_eq!(genesis_check.configuration, genesis.id());
        assert_eq!(genesis_check.fat_checkpoint, genesis_checkpoint.id);
        assert_eq!(genesis_check.thin_checkpoint, genesis_checkpoint.id);
        assert!(matches!(
            mismatch,
            EngineError::CheckpointIdentityMismatch { checkpoint, .. } if checkpoint == corrupted.id
        ));
    }

    #[test]
    fn temporal_graph_replay_checkpoint_rejects_materialized_payload_drift() {
        let node = node_id("node");
        let world = world_from_nodes(vec![WorldNode {
            id: node.clone(),
            arch: NodeTemplate::DEFAULT_ARCH,
            memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
            cmdline: String::new(),
            ready_point: ReadyPoint::FixedIcount {
                icount: Icount { retired: 10 },
            },
            white_box: WhiteBoxPolicy::Disabled,
            smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
            icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
            kernel: None,
            root_image: None,
            initrd: None,
        }]);
        let scenario = world.scenario_def();
        let genesis = Configuration::genesis(scenario.clone());
        let config = step(&genesis, generated_decision(84, 0));
        let baked = match bake(&world) {
            Ok(genesis) => genesis,
            Err(error) => panic!("world bake should produce a genesis checkpoint: {error}"),
        };
        let mut graph = match TemporalGraph::empty().with_baked_genesis(&scenario, baked) {
            Ok(graph) => graph,
            Err(error) => panic!("valid baked genesis should register: {error}"),
        };
        let checkpoint = match graph.materialize_checkpoint(&config) {
            Ok(checkpoint) => checkpoint,
            Err(error) => panic!("checkpoint should materialize through thin replay: {error}"),
        };
        let mut corrupted = checkpoint.clone();
        corrupted.node_blobs.insert(
            node,
            NodeBlobRef::baked(ContentHash::from_canonical_material(
                "crucible.test.materialized-payload-drift",
                "wrong-vm-blob",
            )),
        );
        corrupted.state = Some(MaterializedState::from_checkpoint_parts(
            &corrupted.node_icounts,
            &corrupted.node_blobs,
        ));
        let expected_state = checkpoint
            .state
            .as_ref()
            .map(|state| state.id)
            .unwrap_or_else(|| panic!("valid materialized checkpoint should carry state"));
        let actual_state = corrupted
            .state
            .as_ref()
            .map(|state| state.id)
            .unwrap_or_else(|| panic!("corrupted checkpoint should carry recomputed state"));

        let error = match graph.replay_checkpoint(&config, &corrupted) {
            Ok(_) => panic!("payload drift should fail replay-oracle validation"),
            Err(error) => error,
        };

        assert_eq!(corrupted.id, checkpoint.id);
        assert_eq!(corrupted.configuration, checkpoint.configuration);
        assert_eq!(corrupted.parent, checkpoint.parent);
        assert_eq!(corrupted.schedule_delta, checkpoint.schedule_delta);
        assert_ne!(actual_state, expected_state);
        assert!(matches!(
            error,
            EngineError::ReplayOracleMismatch {
                checkpoint: corrupt_id,
                expected,
                actual,
            } if corrupt_id == corrupted.id
                && expected == expected_state
                && actual == actual_state
        ));
    }

    #[test]
    fn temporal_graph_replay_oracle_rejects_cached_snapshot_to_thin() {
        let node = node_id("node");
        let world = world_from_nodes(vec![WorldNode {
            id: node.clone(),
            arch: NodeTemplate::DEFAULT_ARCH,
            memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
            cmdline: String::new(),
            ready_point: ReadyPoint::FixedIcount {
                icount: Icount { retired: 12 },
            },
            white_box: WhiteBoxPolicy::Disabled,
            smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
            icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
            kernel: None,
            root_image: None,
            initrd: None,
        }]);
        let scenario = world.scenario_def();
        let genesis = Configuration::genesis(scenario.clone());
        let config = step(&genesis, generated_decision(87, 0));
        let baked = match bake(&world) {
            Ok(genesis) => genesis,
            Err(error) => panic!("world bake should produce a genesis checkpoint: {error}"),
        };
        let mut source = match TemporalGraph::empty().with_baked_genesis(&scenario, baked.clone()) {
            Ok(graph) => graph,
            Err(error) => panic!("valid baked genesis should register: {error}"),
        };
        let checkpoint = match source.materialize_checkpoint(&config) {
            Ok(checkpoint) => checkpoint,
            Err(error) => panic!("checkpoint should materialize through thin replay: {error}"),
        };
        let checks = match source.validate_cached_snapshots_with_replay_oracle() {
            Ok(checks) => checks,
            Err(error) => panic!("valid cache should pass replay-oracle admission: {error}"),
        };
        let mut corrupted = checkpoint.clone();
        corrupted.node_blobs.insert(
            node,
            NodeBlobRef::baked(ContentHash::from_canonical_material(
                "crucible.test.cached-replay-oracle",
                "wrong-cached-vm-blob",
            )),
        );
        corrupted.state = Some(MaterializedState::from_checkpoint_parts(
            &corrupted.node_icounts,
            &corrupted.node_blobs,
        ));
        let expected_state = checkpoint
            .state
            .as_ref()
            .map(|state| state.id)
            .unwrap_or_else(|| panic!("valid materialized checkpoint should carry state"));
        let actual_state = corrupted
            .state
            .as_ref()
            .map(|state| state.id)
            .unwrap_or_else(|| panic!("corrupted checkpoint should carry recomputed state"));
        let corrupted_for_validation = corrupted.clone();
        let mut graph = match TemporalGraph::empty().with_baked_genesis(&scenario, baked.clone()) {
            Ok(graph) => graph,
            Err(error) => panic!("valid baked genesis should register: {error}"),
        };
        if let Err(error) = graph.cache_snapshot(&config, corrupted) {
            panic!("corrupt-but-loadable cache should insert before oracle admission: {error}");
        }

        let load_error = match instantiate(&graph, &config) {
            Ok(_) => panic!("public exact-cache instantiate should reject corrupt fat snapshot"),
            Err(error) => error,
        };
        let error = match graph.materialize_checkpoint(&config) {
            Ok(_) => panic!("corrupt cached snapshot should fail replay-oracle admission"),
            Err(error) => error,
        };
        let thin = match graph.checkpoint_node(config.id()) {
            Some(checkpoint) => checkpoint,
            None => panic!("replay-oracle rejection should keep the thin checkpoint node"),
        };
        let runtime = match instantiate(&graph, &config) {
            Ok(runtime) => runtime,
            Err(error) => {
                panic!("thin derivation should remain realizable after rejection: {error}")
            }
        };
        let mut validation_graph = match TemporalGraph::empty().with_baked_genesis(&scenario, baked)
        {
            Ok(graph) => graph,
            Err(error) => panic!("valid baked genesis should register: {error}"),
        };
        if let Err(error) = validation_graph.cache_snapshot(&config, corrupted_for_validation) {
            panic!(
                "corrupt-but-loadable cache should insert before whole-cache validation: {error}"
            );
        }
        let validation_error = match validation_graph.validate_cached_snapshots_with_replay_oracle()
        {
            Ok(_) => panic!("whole-cache replay-oracle validation should reject corrupt cache"),
            Err(error) => error,
        };

        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].configuration, config.id());
        assert!(matches!(
            load_error,
            EngineError::ReplayOracleMismatch {
                checkpoint: corrupt_id,
                expected,
                actual,
            } if corrupt_id == checkpoint.id
                && expected == expected_state
                && actual == actual_state
        ));
        assert!(matches!(
            error,
            EngineError::ReplayOracleMismatch {
                checkpoint: corrupt_id,
                expected,
                actual,
            } if corrupt_id == checkpoint.id
                && expected == expected_state
                && actual == actual_state
        ));
        assert!(matches!(
            validation_error,
            EngineError::ReplayOracleMismatch {
                checkpoint: corrupt_id,
                expected,
                actual,
            } if corrupt_id == checkpoint.id
                && expected == expected_state
                && actual == actual_state
        ));
        assert!(graph.cached_snapshot(&config).is_none());
        assert!(validation_graph.cached_snapshot(&config).is_none());
        assert_eq!(thin.kind, CheckpointKind::Thin);
        assert!(thin.state.is_none());
        assert_eq!(runtime.configuration, config.id());
        assert_eq!(runtime.id, reduced_state_id(&config));
    }

    #[test]
    fn temporal_graph_replay_oracle_admits_cached_ancestors_before_target() {
        let node = node_id("node");
        let world = world_from_nodes(vec![WorldNode {
            id: node.clone(),
            arch: NodeTemplate::DEFAULT_ARCH,
            memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
            cmdline: String::new(),
            ready_point: ReadyPoint::FixedIcount {
                icount: Icount { retired: 13 },
            },
            white_box: WhiteBoxPolicy::Disabled,
            smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
            icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
            kernel: None,
            root_image: None,
            initrd: None,
        }]);
        let scenario = world.scenario_def();
        let genesis = Configuration::genesis(scenario.clone());
        let ancestor = step(&genesis, generated_decision(88, 0));
        let target = step(&ancestor, generated_decision(88, 1));
        let baked = match bake(&world) {
            Ok(genesis) => genesis,
            Err(error) => panic!("world bake should produce a genesis checkpoint: {error}"),
        };
        let mut source = match TemporalGraph::empty().with_baked_genesis(&scenario, baked.clone()) {
            Ok(graph) => graph,
            Err(error) => panic!("valid baked genesis should register: {error}"),
        };
        let ancestor_checkpoint = match source.materialize_checkpoint(&ancestor) {
            Ok(checkpoint) => checkpoint,
            Err(error) => panic!("ancestor checkpoint should materialize: {error}"),
        };
        let corrupt_ancestor =
            corrupt_checkpoint_node_blob(&ancestor_checkpoint, &node, "wrong-ancestor-vm-blob");
        let mut unsafe_replay_graph = TemporalGraph::empty();
        if let Err(error) = unsafe_replay_graph.cache_snapshot(&ancestor, corrupt_ancestor.clone())
        {
            panic!("corrupt-but-loadable ancestor cache should insert: {error}");
        }
        let corrupt_runtime = match instantiate(&unsafe_replay_graph, &target) {
            Ok(runtime) => runtime,
            Err(error) => panic!("target setup should replay from corrupt ancestor: {error}"),
        };
        let corrupt_target = match Checkpoint::from_recorded_configuration(
            &target,
            Some(&ancestor),
            VirtualTime::default(),
            corrupt_runtime.node_icounts,
            CheckpointKind::Fat,
            corrupt_runtime.node_blobs,
        ) {
            Ok(checkpoint) => checkpoint,
            Err(error) => panic!("corrupt target checkpoint should remain loadable: {error}"),
        };
        let expected_state = ancestor_checkpoint
            .state
            .as_ref()
            .map(|state| state.id)
            .unwrap_or_else(|| panic!("valid ancestor checkpoint should carry state"));
        let actual_state = corrupt_ancestor
            .state
            .as_ref()
            .map(|state| state.id)
            .unwrap_or_else(|| panic!("corrupted ancestor checkpoint should carry state"));
        let mut graph = match TemporalGraph::empty().with_baked_genesis(&scenario, baked) {
            Ok(graph) => graph,
            Err(error) => panic!("valid baked genesis should register: {error}"),
        };
        if let Err(error) = graph.cache_snapshot(&ancestor, corrupt_ancestor) {
            panic!("corrupt-but-loadable ancestor cache should insert before admission: {error}");
        }
        if let Err(error) = graph.cache_snapshot(&target, corrupt_target) {
            panic!("corrupt-but-loadable target cache should insert before admission: {error}");
        }

        let error = match graph.materialize_checkpoint(&target) {
            Ok(_) => {
                panic!("cached target should not validate against an unadmitted corrupt ancestor")
            }
            Err(error) => error,
        };

        assert!(matches!(
            error,
            EngineError::ReplayOracleMismatch {
                checkpoint: corrupt_id,
                expected,
                actual,
            } if corrupt_id == ancestor_checkpoint.id
                && expected == expected_state
                && actual == actual_state
        ));
        assert!(graph.cached_snapshot(&ancestor).is_none());
        assert!(graph.cached_snapshot(&target).is_none());
        assert!(matches!(
            graph.checkpoint_node(ancestor.id()),
            Some(checkpoint) if checkpoint.kind == CheckpointKind::Thin && checkpoint.state.is_none()
        ));
        assert!(matches!(
            graph.checkpoint_node(target.id()),
            Some(checkpoint) if checkpoint.kind == CheckpointKind::Thin && checkpoint.state.is_none()
        ));
    }

    #[test]
    fn temporal_graph_replay_checkpoint_ignores_exact_target_snapshot() {
        let scenario = generated_scenario(78);
        let genesis = Configuration::genesis(scenario.clone());
        let config = Configuration {
            def: scenario.clone(),
            schedule: generated_schedule(78, 2),
        };
        let mut materializer = match TemporalGraph::empty()
            .with_baked_genesis(&scenario, genesis_checkpoint_for(&genesis))
        {
            Ok(graph) => graph,
            Err(error) => panic!("valid baked genesis should register: {error}"),
        };
        let checkpoint = match materializer.save_checkpoint(&config) {
            Ok(checkpoint) => checkpoint,
            Err(error) => panic!("save should materialize checkpoint: {error}"),
        };
        let graph = match TemporalGraph::empty().with_cached_snapshot(&config, checkpoint.clone()) {
            Ok(graph) => graph,
            Err(error) => panic!("valid exact target snapshot should register: {error}"),
        };

        let error = match graph.replay_checkpoint(&config, &checkpoint) {
            Ok(_) => panic!("replay oracle should not load the exact target snapshot"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            EngineError::MissingBakedGenesis { scenario: missing } if missing == scenario.id()
        ));
    }

    #[test]
    fn temporal_graph_checkpoint_resume_resolves_cached_snapshot_without_thin_node() {
        let scenario = generated_scenario(178);
        let genesis = Configuration::genesis(scenario.clone());
        let config = Configuration {
            def: scenario.clone(),
            schedule: generated_schedule(178, 2),
        };
        let mut materializer = match TemporalGraph::empty()
            .with_baked_genesis(&scenario, genesis_checkpoint_for(&genesis))
        {
            Ok(graph) => graph,
            Err(error) => panic!("valid baked genesis should register: {error}"),
        };
        let checkpoint = match materializer.save_checkpoint(&config) {
            Ok(checkpoint) => checkpoint,
            Err(error) => panic!("save should materialize checkpoint: {error}"),
        };
        let mut graph = match TemporalGraph::empty().with_cached_snapshot(&config, checkpoint) {
            Ok(graph) => graph,
            Err(error) => panic!("valid cached snapshot should register: {error}"),
        };

        assert!(graph.checkpoint_node(config.id()).is_none());
        assert_eq!(graph.checkpoint_configuration(config.id()), Some(&config));
        let resumed = match graph.resume_checkpoint(config.id()) {
            Ok(runtime) => runtime,
            Err(error) => panic!("cached snapshot checkpoint should resume: {error}"),
        };
        assert_eq!(resumed.configuration, config.id());
        assert_eq!(resumed.runtime.configuration, config.id());
    }

    #[test]
    fn temporal_graph_frontier_enumeration_deduplicates_by_configuration_id() {
        let scenario = generated_scenario(79);
        let frontier = Configuration::genesis(scenario.clone());
        let duplicate = generated_decision(79, 0);
        let distinct = generated_decision(79, 1);
        let mut graph = match TemporalGraph::empty()
            .with_baked_genesis(&scenario, genesis_checkpoint_for(&frontier))
        {
            Ok(graph) => graph,
            Err(error) => panic!("valid baked genesis should register: {error}"),
        };

        let first = graph.enumerate_frontier(
            &frontier,
            vec![duplicate.clone(), duplicate, distinct.clone()],
        );
        let first = match first {
            Ok(children) => children,
            Err(error) => panic!("first frontier enumeration should record children: {error}"),
        };
        let second =
            match graph.enumerate_frontier(&frontier, vec![generated_decision(79, 0), distinct]) {
                Ok(children) => children,
                Err(error) => panic!("second frontier enumeration should reuse children: {error}"),
            };

        assert_eq!(first.len(), 2);
        assert!(first.iter().all(|child| !child.already_recorded));
        assert_eq!(second.len(), 2);
        assert!(second.iter().all(|child| child.already_recorded));
        assert_eq!(graph.recorded_configuration_count(), 3);
        assert_eq!(graph.checkpoint_node_count(), 3);
        assert!(graph.contains_configuration(&frontier));
        for child in first {
            assert!(graph.contains_configuration(&child.configuration));
            assert_eq!(child.configuration.def, frontier.def);
            assert_eq!(
                child.configuration.schedule.len(),
                frontier.schedule.len() + 1
            );
        }
    }

    #[test]
    fn bake_content_addresses_world_as_shared_fat_genesis_checkpoint() {
        let world = generated_world(71);
        let same_world = generated_world(71);
        let other_world = generated_world(72);
        let def = world.scenario_def();
        let genesis = Configuration::genesis(def.clone());

        let baked = match bake(&world) {
            Ok(genesis) => genesis,
            Err(error) => panic!("world bake should produce a genesis checkpoint: {error}"),
        };
        let baked_again = match bake(&same_world) {
            Ok(genesis) => genesis,
            Err(error) => panic!("same world bake should be deterministic: {error}"),
        };
        let other_baked = match bake(&other_world) {
            Ok(genesis) => genesis,
            Err(error) => panic!("other world bake should produce a checkpoint: {error}"),
        };

        assert_eq!(world, same_world);
        assert_eq!(world.scenario_def(), same_world.scenario_def());
        assert_eq!(baked, baked_again);
        assert_ne!(baked.checkpoint.id, other_baked.checkpoint.id);
        assert_ne!(def, other_world.scenario_def());
        assert_eq!(baked.checkpoint.configuration, genesis.id());
        assert_eq!(baked.checkpoint.kind, CheckpointKind::Fat);
    }

    #[test]
    fn baked_world_genesis_instantiates_as_first_resume() {
        let world = generated_world(73);
        let def = world.scenario_def();
        let genesis = Configuration::genesis(def.clone());
        let baked = match bake(&world) {
            Ok(genesis) => genesis,
            Err(error) => panic!("world bake should produce a genesis checkpoint: {error}"),
        };
        let graph = match TemporalGraph::empty().with_baked_genesis(&def, baked) {
            Ok(graph) => graph,
            Err(error) => panic!("baked world genesis should register: {error}"),
        };

        let runtime = match instantiate(&graph, &genesis) {
            Ok(runtime) => runtime,
            Err(error) => panic!("baked world genesis should instantiate by load: {error}"),
        };

        assert_eq!(runtime.configuration, genesis.id());
        assert_eq!(runtime.id, reduced_state_id(&genesis));
    }

    #[test]
    fn world_ready_point_policies_are_hashed_canonically() {
        let fixed = ready_node(
            "a",
            ReadyPoint::FixedIcount {
                icount: Icount { retired: 42 },
            },
        );
        let idle = ready_node(
            "b",
            ReadyPoint::NetworkIdle {
                window: SimDuration { nanos: 1_000 },
            },
        );
        let console = ready_node(
            "c",
            ReadyPoint::ConsoleMarker {
                marker: String::from("crucible-ready"),
            },
        );
        let agent = WorldNode {
            id: node_id("d"),
            arch: NodeTemplate::DEFAULT_ARCH,
            memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
            cmdline: String::new(),
            ready_point: ReadyPoint::AgentSignal,
            white_box: WhiteBoxPolicy::Enabled,
            smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
            icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
            kernel: None,
            root_image: None,
            initrd: None,
        };

        let canonical = world_from_nodes_and_links(
            vec![fixed.clone(), idle.clone(), console.clone(), agent.clone()],
            vec![link("a", "b")],
        );
        let reordered =
            world_from_nodes_and_links(vec![agent, console, idle, fixed], vec![link("a", "b")]);
        let changed = world_from_nodes(vec![ready_node(
            "a",
            ReadyPoint::FixedIcount {
                icount: Icount { retired: 43 },
            },
        )]);
        let baked = match bake(&canonical) {
            Ok(genesis) => genesis,
            Err(error) => panic!("canonical ready-point world should bake: {error}"),
        };
        let baked_again = match bake(&reordered) {
            Ok(genesis) => genesis,
            Err(error) => panic!("reordered ready-point world should bake: {error}"),
        };
        let manually_reordered = match World::from_recorded_parts(
            canonical.id,
            canonical.nodes().iter().rev().cloned().collect(),
            canonical.links().iter().rev().cloned().collect(),
        ) {
            Ok(world) => world,
            Err(error) => panic!("manually reordered ready-point world should be valid: {error}"),
        };
        let manually_baked = match bake(&manually_reordered) {
            Ok(genesis) => genesis,
            Err(error) => panic!("manually reordered ready-point world should bake: {error}"),
        };

        assert_eq!(canonical.nodes().len(), 4);
        assert_eq!(canonical.id, reordered.id);
        assert_eq!(canonical.nodes(), reordered.nodes());
        assert_eq!(canonical.scenario_def(), manually_reordered.scenario_def());
        assert_eq!(baked, baked_again);
        assert_eq!(baked, manually_baked);
        assert_ne!(canonical.id, changed.id);
        assert_ne!(
            baked.checkpoint.id,
            match bake(&changed) {
                Ok(genesis) => genesis.checkpoint.id,
                Err(error) => panic!("changed ready-point world should bake: {error}"),
            }
        );
    }

    #[test]
    fn world_topology_hashes_nodes_and_links_canonically() {
        let node_a = ready_node(
            "a",
            ReadyPoint::FixedIcount {
                icount: Icount { retired: 1 },
            },
        );
        let node_b = ready_node(
            "b",
            ReadyPoint::FixedIcount {
                icount: Icount { retired: 2 },
            },
        );

        let canonical =
            world_from_nodes_and_links(vec![node_a.clone(), node_b.clone()], vec![link("a", "b")]);
        let reordered =
            world_from_nodes_and_links(vec![node_b.clone(), node_a.clone()], vec![link("b", "a")]);
        let without_link = world_from_nodes(vec![node_b, node_a]);
        let baked = match bake(&canonical) {
            Ok(genesis) => genesis,
            Err(error) => panic!("canonical linked world should bake: {error}"),
        };
        let baked_again = match bake(&reordered) {
            Ok(genesis) => genesis,
            Err(error) => panic!("reordered linked world should bake: {error}"),
        };
        let unlinked_baked = match bake(&without_link) {
            Ok(genesis) => genesis,
            Err(error) => panic!("unlinked world should bake: {error}"),
        };

        assert_eq!(canonical.id, reordered.id);
        assert_eq!(canonical.nodes(), reordered.nodes());
        assert_eq!(canonical.links(), reordered.links());
        assert_eq!(canonical.links(), [link("a", "b")].as_slice());
        assert_eq!(canonical.scenario_def(), reordered.scenario_def());
        assert_eq!(baked, baked_again);
        assert_ne!(canonical.id, without_link.id);
        assert_ne!(canonical.scenario_def(), without_link.scenario_def());
        assert_ne!(baked.checkpoint.id, unlinked_baked.checkpoint.id);
    }

    #[test]
    fn world_topology_rejects_invalid_links() {
        let nodes = vec![
            ready_node(
                "a",
                ReadyPoint::FixedIcount {
                    icount: Icount { retired: 1 },
                },
            ),
            ready_node(
                "b",
                ReadyPoint::FixedIcount {
                    icount: Icount { retired: 2 },
                },
            ),
        ];
        let duplicate_node = World::from_nodes_and_links(
            vec![
                ready_node(
                    "dup",
                    ReadyPoint::FixedIcount {
                        icount: Icount { retired: 1 },
                    },
                ),
                ready_node(
                    "dup",
                    ReadyPoint::FixedIcount {
                        icount: Icount { retired: 2 },
                    },
                ),
            ],
            Vec::new(),
        );
        let duplicate =
            World::from_nodes_and_links(nodes.clone(), vec![link("a", "b"), link("b", "a")]);
        let unknown = World::from_nodes_and_links(nodes, vec![link("a", "missing")]);
        let self_loop = LinkDef::new(node_id("a"), node_id("a"));

        assert!(matches!(
            duplicate_node,
            Err(EngineError::DuplicateWorldNodeId { .. })
        ));
        assert!(matches!(
            duplicate,
            Err(EngineError::DuplicateWorldLink { .. })
        ));
        assert!(matches!(
            unknown,
            Err(EngineError::WorldLinkUnknownNode { node, .. }) if node == node_id("missing")
        ));
        assert!(matches!(
            self_loop,
            Err(EngineError::WorldLinkSelfLoop { node }) if node == node_id("a")
        ));
    }

    #[test]
    fn world_link_transport_material_affects_world_identity() {
        let nodes = two_ready_nodes();
        let base = world_from_nodes_and_links(
            nodes.clone(),
            vec![transport_link("a", "b", 5, 1, 250_000, Some(1_000_000))],
        );
        let reordered = world_from_nodes_and_links(
            nodes.clone().into_iter().rev().collect(),
            vec![transport_link("b", "a", 5, 1, 250_000, Some(1_000_000))],
        );
        let changed_latency = world_from_nodes_and_links(
            nodes.clone(),
            vec![transport_link("a", "b", 6, 1, 250_000, Some(1_000_000))],
        );
        let changed_jitter = world_from_nodes_and_links(
            nodes.clone(),
            vec![transport_link("a", "b", 5, 2, 250_000, Some(1_000_000))],
        );
        let changed_loss = world_from_nodes_and_links(
            nodes.clone(),
            vec![transport_link("a", "b", 5, 1, 250_001, Some(1_000_000))],
        );
        let changed_bandwidth = world_from_nodes_and_links(
            nodes,
            vec![transport_link("a", "b", 5, 1, 250_000, Some(2_000_000))],
        );
        let base_baked = match bake(&base) {
            Ok(genesis) => genesis,
            Err(error) => panic!("base transport world should bake: {error}"),
        };
        let changed_latency_baked = match bake(&changed_latency) {
            Ok(genesis) => genesis,
            Err(error) => panic!("changed-latency transport world should bake: {error}"),
        };

        assert_eq!(base.id, reordered.id);
        assert_eq!(base.links(), reordered.links());
        assert_eq!(base.links()[0].latency(), SimDuration { nanos: 5 });
        assert_eq!(base.links()[0].jitter(), SimDuration { nanos: 1 });
        assert_eq!(base.links()[0].loss().millionths(), 250_000);
        assert_eq!(base.links()[0].bandwidth_bps(), Some(1_000_000));
        assert_ne!(base.id, changed_latency.id);
        assert_ne!(base.id, changed_jitter.id);
        assert_ne!(base.id, changed_loss.id);
        assert_ne!(base.id, changed_bandwidth.id);
        assert_eq!(base.scenario_def(), reordered.scenario_def());
        assert_ne!(base.scenario_def(), changed_latency.scenario_def());
        assert_ne!(
            base_baked.checkpoint.id,
            changed_latency_baked.checkpoint.id
        );
    }

    #[test]
    fn world_link_transport_rejects_invalid_floor_and_loss() {
        let below_floor = LinkDef::with_transport(
            node_id("a"),
            node_id("b"),
            SimDuration { nanos: 0 },
            SimDuration { nanos: 0 },
            LinkLossProbability::ZERO,
            None,
        );
        let jitter_below_floor = LinkDef::with_transport(
            node_id("a"),
            node_id("b"),
            SimDuration { nanos: 5 },
            SimDuration { nanos: 5 },
            LinkLossProbability::ZERO,
            None,
        );
        let loss_out_of_range = LinkLossProbability::from_millionths(1_000_001);
        let duplicate_endpoint_pair = World::from_nodes_and_links(
            two_ready_nodes(),
            vec![
                transport_link("a", "b", 5, 1, 0, None),
                transport_link("b", "a", 6, 1, 0, None),
            ],
        );

        assert_eq!(MIN_LINK_LATENCY, SimDuration { nanos: 1 });
        assert_eq!(
            LinkLossProbability::ONE.millionths(),
            LinkLossProbability::from_millionths(1_000_000)
                .map(|loss| loss.millionths())
                .unwrap_or_default()
        );
        assert!(matches!(
            below_floor,
            Err(EngineError::WorldLinkLatencyBelowFloor { latency, minimum, .. })
                if latency == SimDuration { nanos: 0 } && minimum == MIN_LINK_LATENCY
        ));
        assert!(matches!(
            jitter_below_floor,
            Err(EngineError::WorldLinkJitterBelowLatencyFloor {
                latency,
                jitter,
                minimum,
                ..
            }) if latency == SimDuration { nanos: 5 }
                && jitter == SimDuration { nanos: 5 }
                && minimum == MIN_LINK_LATENCY
        ));
        assert!(matches!(
            loss_out_of_range,
            Err(EngineError::LinkLossProbabilityOutOfRange {
                millionths: 1_000_001,
                maximum: 1_000_000,
            })
        ));
        assert!(matches!(
            duplicate_endpoint_pair,
            Err(EngineError::DuplicateWorldLink { .. })
        ));
    }

    #[test]
    fn scheduler_link_latency_floor_rejects_subfloor_before_hashing_and_enters_world_material() {
        let below_floor = LinkDef::with_transport(
            node_id("a"),
            node_id("b"),
            SimDuration { nanos: 0 },
            SimDuration::default(),
            LinkLossProbability::ZERO,
            None,
        );
        let jitter_below_floor = LinkDef::with_transport(
            node_id("a"),
            node_id("b"),
            SimDuration { nanos: 5 },
            SimDuration { nanos: 5 },
            LinkLossProbability::ZERO,
            None,
        );
        let floor_world = world_from_nodes_and_links(two_ready_nodes(), vec![link("a", "b")]);
        let material = String::from_utf8(floor_world.canonical_bytes())
            .unwrap_or_else(|error| panic!("world material should be utf8: {error}"));
        let toml = floor_world
            .to_canonical_toml()
            .unwrap_or_else(|error| panic!("world TOML should serialize: {error}"));
        let subfloor_toml = toml.replace("latency_nanos = 1", "latency_nanos = 0");
        let parsed_subfloor = World::from_canonical_toml(&subfloor_toml);
        let raised_latency_world = world_from_nodes_and_links(
            two_ready_nodes(),
            vec![transport_link("a", "b", 2, 0, 0, None)],
        );

        assert_eq!(MIN_LINK_LATENCY, SimDuration { nanos: 1 });
        assert!(matches!(
            below_floor,
            Err(EngineError::WorldLinkLatencyBelowFloor { latency, minimum, .. })
                if latency == SimDuration { nanos: 0 } && minimum == MIN_LINK_LATENCY
        ));
        assert!(matches!(
            jitter_below_floor,
            Err(EngineError::WorldLinkJitterBelowLatencyFloor {
                latency,
                jitter,
                minimum,
                ..
            }) if latency == SimDuration { nanos: 5 }
                && jitter == SimDuration { nanos: 5 }
                && minimum == MIN_LINK_LATENCY
        ));
        assert!(matches!(
            parsed_subfloor,
            Err(EngineError::WorldLinkLatencyBelowFloor { latency, minimum, .. })
                if latency == SimDuration { nanos: 0 } && minimum == MIN_LINK_LATENCY
        ));
        assert!(material.contains("min_link_latency_ns=1"));
        assert_eq!(
            floor_world.id(),
            ContentHash::from_canonical_material("crucible.model.world.v1", &material)
        );
        assert_ne!(floor_world.id(), raised_latency_world.id());
        assert_ne!(
            floor_world.scenario_def().id(),
            raised_latency_world.scenario_def().id()
        );
        assert_eq!(
            floor_world.static_topology().lookahead_graph[0].minimum_latency,
            MIN_LINK_LATENCY
        );
    }

    #[test]
    fn world_static_topology_is_derived_from_world_only() {
        let world = world_from_nodes_and_links(
            two_ready_nodes(),
            vec![transport_link("b", "a", 10, 2, 0, None)],
        );
        let reordered = world_from_nodes_and_links(
            two_ready_nodes().into_iter().rev().collect(),
            vec![transport_link("a", "b", 10, 2, 0, None)],
        );
        let changed_latency = world_from_nodes_and_links(
            two_ready_nodes(),
            vec![transport_link("a", "b", 11, 2, 0, None)],
        );
        let genesis = Configuration::genesis(world.scenario_def());
        let scheduled = Configuration {
            def: genesis.def.clone(),
            schedule: genesis.schedule.appended(generated_decision(93, 0)),
        };

        let topology = world.static_topology();

        assert_eq!(genesis.def, scheduled.def);
        assert_ne!(genesis.schedule, scheduled.schedule);
        assert_eq!(topology, reordered.static_topology());
        assert_eq!(topology.participants, vec![node_id("a"), node_id("b")]);
        assert_eq!(
            topology.rng_streams,
            vec![
                RngStreamId::for_link(
                    "link_endpoint_a_len=1\nlink_endpoint_a=a\nlink_endpoint_b_len=1\nlink_endpoint_b=b",
                ),
                RngStreamId::for_node("a"),
                RngStreamId::for_node("b"),
            ]
        );
        assert_eq!(
            topology.lookahead_graph,
            vec![
                WorldLookaheadEdge {
                    from: node_id("a"),
                    to: node_id("b"),
                    minimum_latency: SimDuration { nanos: 8 },
                },
                WorldLookaheadEdge {
                    from: node_id("b"),
                    to: node_id("a"),
                    minimum_latency: SimDuration { nanos: 8 },
                },
            ]
        );
        assert_eq!(topology.bake_nodes, vec![node_id("a"), node_id("b")]);
        assert_ne!(
            topology.lookahead_graph,
            changed_latency.static_topology().lookahead_graph
        );
    }

    #[test]
    fn world_static_topology_link_rng_streams_are_collision_free() {
        let world = world_from_nodes_and_links(
            vec![
                ready_node(
                    "a",
                    ReadyPoint::FixedIcount {
                        icount: Icount { retired: 1 },
                    },
                ),
                ready_node(
                    "b--c",
                    ReadyPoint::FixedIcount {
                        icount: Icount { retired: 2 },
                    },
                ),
                ready_node(
                    "a--b",
                    ReadyPoint::FixedIcount {
                        icount: Icount { retired: 3 },
                    },
                ),
                ready_node(
                    "c",
                    ReadyPoint::FixedIcount {
                        icount: Icount { retired: 4 },
                    },
                ),
            ],
            vec![link("a", "b--c"), link("a--b", "c")],
        );

        let link_streams = world
            .static_topology()
            .rng_streams
            .into_iter()
            .filter(|stream| stream.domain == crucible_sim::DECISION_RNG_LINK_STREAM_DOMAIN)
            .collect::<Vec<_>>();

        assert_eq!(
            link_streams,
            vec![
                RngStreamId::for_link(
                    "link_endpoint_a_len=1\nlink_endpoint_a=a\nlink_endpoint_b_len=4\nlink_endpoint_b=b--c",
                ),
                RngStreamId::for_link(
                    "link_endpoint_a_len=4\nlink_endpoint_a=a--b\nlink_endpoint_b_len=1\nlink_endpoint_b=c",
                ),
            ]
        );
    }

    #[test]
    fn membership_plan_faults_layer_over_static_world_topology() {
        let world = world_from_nodes_and_links(
            vec![
                ready_node(
                    "a",
                    ReadyPoint::FixedIcount {
                        icount: Icount { retired: 1 },
                    },
                ),
                ready_node(
                    "b",
                    ReadyPoint::FixedIcount {
                        icount: Icount { retired: 2 },
                    },
                ),
                ready_node(
                    "c",
                    ReadyPoint::FixedIcount {
                        icount: Icount { retired: 3 },
                    },
                ),
            ],
            vec![link("a", "b"), link("b", "c")],
        );
        let topology = world.static_topology();
        let plan = match Plan::from_entries_for_world(
            &world,
            vec![
                PlanEntry::Activate {
                    at: VirtualTime { ticks: 0 },
                    tag: tag("joining-c"),
                    fault: MembershipFault::NotYetJoined { node: node_id("c") },
                },
                PlanEntry::Heal {
                    at: VirtualTime { ticks: 10 },
                    tag: tag("joining-c"),
                },
                PlanEntry::Activate {
                    at: VirtualTime { ticks: 20 },
                    tag: tag("crash-a"),
                    fault: MembershipFault::Crash {
                        node: node_id("a"),
                        restart: RestartPolicy::FromReadyPoint,
                    },
                },
                PlanEntry::Heal {
                    at: VirtualTime { ticks: 30 },
                    tag: tag("crash-a"),
                },
                PlanEntry::Activate {
                    at: VirtualTime { ticks: 40 },
                    tag: tag("split-ab"),
                    fault: MembershipFault::Partition {
                        endpoint_a: node_id("a"),
                        endpoint_b: node_id("b"),
                        direction: PartitionDirection::Bidirectional,
                    },
                },
                PlanEntry::Activate {
                    at: VirtualTime { ticks: 50 },
                    tag: tag("isolate-b"),
                    fault: MembershipFault::Isolate { node: node_id("b") },
                },
            ],
        ) {
            Ok(plan) => plan,
            Err(error) => panic!("membership plan should reference declared topology: {error}"),
        };

        assert_eq!(plan.entries().len(), 6);
        assert_eq!(world.static_topology(), topology);
        assert_eq!(
            topology.participants,
            vec![node_id("a"), node_id("b"), node_id("c")]
        );
        assert_eq!(topology.bake_nodes, topology.participants);
        assert!(matches!(
            &plan.entries()[0],
            PlanEntry::Activate {
                fault: MembershipFault::NotYetJoined { node },
                ..
            } if *node == node_id("c")
        ));
    }

    #[test]
    fn membership_plan_rejects_dynamic_or_undeclared_topology_targets() {
        let world = world_from_nodes_and_links(
            vec![
                ready_node(
                    "a",
                    ReadyPoint::FixedIcount {
                        icount: Icount { retired: 1 },
                    },
                ),
                ready_node(
                    "b",
                    ReadyPoint::FixedIcount {
                        icount: Icount { retired: 2 },
                    },
                ),
                ready_node(
                    "c",
                    ReadyPoint::FixedIcount {
                        icount: Icount { retired: 3 },
                    },
                ),
            ],
            vec![link("a", "b")],
        );

        let unknown_node = Plan::from_entries_for_world(
            &world,
            vec![PlanEntry::Activate {
                at: VirtualTime { ticks: 0 },
                tag: tag("crash-missing"),
                fault: MembershipFault::Crash {
                    node: node_id("missing"),
                    restart: RestartPolicy::StayDown,
                },
            }],
        );
        let unknown_link = Plan::from_entries_for_world(
            &world,
            vec![PlanEntry::Activate {
                at: VirtualTime { ticks: 0 },
                tag: tag("split-ac"),
                fault: MembershipFault::Partition {
                    endpoint_a: node_id("a"),
                    endpoint_b: node_id("c"),
                    direction: PartitionDirection::EndpointAToEndpointB,
                },
            }],
        );
        let unknown_heal = Plan::from_entries_for_world(
            &world,
            vec![PlanEntry::Heal {
                at: VirtualTime { ticks: 0 },
                tag: tag("missing"),
            }],
        );
        let heal_before_activate = Plan::from_entries_for_world(
            &world,
            vec![
                PlanEntry::Heal {
                    at: VirtualTime { ticks: 5 },
                    tag: tag("late-join"),
                },
                PlanEntry::Activate {
                    at: VirtualTime { ticks: 10 },
                    tag: tag("late-join"),
                    fault: MembershipFault::NotYetJoined { node: node_id("c") },
                },
            ],
        );
        let not_yet_joined_after_start = Plan::from_entries_for_world(
            &world,
            vec![PlanEntry::Activate {
                at: VirtualTime { ticks: 10 },
                tag: tag("late-hold"),
                fault: MembershipFault::NotYetJoined { node: node_id("c") },
            }],
        );
        let replaced_tag_heals_after_first_activation = Plan::from_entries_for_world(
            &world,
            vec![
                PlanEntry::Activate {
                    at: VirtualTime { ticks: 10 },
                    tag: tag("replaceable"),
                    fault: MembershipFault::Crash {
                        node: node_id("a"),
                        restart: RestartPolicy::StayDown,
                    },
                },
                PlanEntry::Heal {
                    at: VirtualTime { ticks: 20 },
                    tag: tag("replaceable"),
                },
                PlanEntry::Activate {
                    at: VirtualTime { ticks: 30 },
                    tag: tag("replaceable"),
                    fault: MembershipFault::Crash {
                        node: node_id("b"),
                        restart: RestartPolicy::StayDown,
                    },
                },
            ],
        );

        assert!(matches!(
            unknown_node,
            Err(EngineError::PlanFaultUnknownNode { node }) if node == node_id("missing")
        ));
        assert!(matches!(
            unknown_link,
            Err(EngineError::PlanFaultUnknownLink {
                endpoint_a,
                endpoint_b,
            }) if endpoint_a == node_id("a") && endpoint_b == node_id("c")
        ));
        assert!(matches!(
            unknown_heal,
            Err(EngineError::PlanHealUnknownTag { tag }) if tag == self::tag("missing")
        ));
        assert!(matches!(
            heal_before_activate,
            Err(EngineError::PlanHealBeforeActivate {
                tag,
                activate_at,
                heal_at,
            }) if tag == self::tag("late-join")
                && activate_at.ticks == 10
                && heal_at.ticks == 5
        ));
        assert!(matches!(
            not_yet_joined_after_start,
            Err(EngineError::PlanNotYetJoinedAfterStart { node, at })
                if node == node_id("c") && at.ticks == 10
        ));
        assert!(replaced_tag_heals_after_first_activation.is_ok());
    }

    #[test]
    fn plan_validation_reports_precise_fault_heal_and_time_errors() {
        let world = world_from_nodes_and_links(
            vec![
                ready_node(
                    "a",
                    ReadyPoint::FixedIcount {
                        icount: Icount { retired: 1 },
                    },
                ),
                ready_node(
                    "b",
                    ReadyPoint::FixedIcount {
                        icount: Icount { retired: 2 },
                    },
                ),
                ready_node(
                    "c",
                    ReadyPoint::FixedIcount {
                        icount: Icount { retired: 3 },
                    },
                ),
            ],
            vec![link("a", "b")],
        );

        let unknown_crash_target = Plan::from_entries_for_world(
            &world,
            vec![PlanEntry::Activate {
                at: VirtualTime { ticks: 5 },
                tag: tag("crash-missing"),
                fault: MembershipFault::Crash {
                    node: node_id("missing"),
                    restart: RestartPolicy::FromReadyPoint,
                },
            }],
        );
        let unknown_isolate_target = Plan::from_entries_for_world(
            &world,
            vec![PlanEntry::Activate {
                at: VirtualTime { ticks: 6 },
                tag: tag("isolate-missing"),
                fault: MembershipFault::Isolate {
                    node: node_id("missing-isolate"),
                },
            }],
        );
        let unknown_partition_link = Plan::from_entries_for_world(
            &world,
            vec![PlanEntry::Activate {
                at: VirtualTime { ticks: 7 },
                tag: tag("split-bc"),
                fault: MembershipFault::Partition {
                    endpoint_a: node_id("b"),
                    endpoint_b: node_id("c"),
                    direction: PartitionDirection::EndpointBToEndpointA,
                },
            }],
        );
        let unknown_heal_tag = Plan::from_entries_for_world(
            &world,
            vec![PlanEntry::Heal {
                at: VirtualTime { ticks: 8 },
                tag: tag("never-activated"),
            }],
        );
        let heal_before_activate = Plan::from_entries_for_world(
            &world,
            vec![
                PlanEntry::Activate {
                    at: VirtualTime { ticks: 20 },
                    tag: tag("split-ab"),
                    fault: MembershipFault::Partition {
                        endpoint_a: node_id("a"),
                        endpoint_b: node_id("b"),
                        direction: PartitionDirection::Bidirectional,
                    },
                },
                PlanEntry::Heal {
                    at: VirtualTime { ticks: 10 },
                    tag: tag("split-ab"),
                },
            ],
        );
        let not_yet_joined_after_start = Plan::from_entries_for_world(
            &world,
            vec![PlanEntry::Activate {
                at: VirtualTime { ticks: 1 },
                tag: tag("late-hold"),
                fault: MembershipFault::NotYetJoined { node: node_id("c") },
            }],
        );
        let start_time_not_yet_joined = Plan::from_entries_for_world(
            &world,
            vec![PlanEntry::Activate {
                at: VirtualTime::default(),
                tag: tag("initial-hold"),
                fault: MembershipFault::NotYetJoined { node: node_id("c") },
            }],
        );
        let direction_a_to_b = Plan::from_entries_for_world(
            &world,
            vec![PlanEntry::Activate {
                at: VirtualTime { ticks: 30 },
                tag: tag("one-way-split"),
                fault: MembershipFault::Partition {
                    endpoint_a: node_id("a"),
                    endpoint_b: node_id("b"),
                    direction: PartitionDirection::EndpointAToEndpointB,
                },
            }],
        );
        let direction_b_to_a = Plan::from_entries_for_world(
            &world,
            vec![PlanEntry::Activate {
                at: VirtualTime { ticks: 30 },
                tag: tag("one-way-split"),
                fault: MembershipFault::Partition {
                    endpoint_a: node_id("b"),
                    endpoint_b: node_id("a"),
                    direction: PartitionDirection::EndpointBToEndpointA,
                },
            }],
        );
        let negative_time_toml = r#"
id = "blake3:0000000000000000000000000000000000000000000000000000000000000000"

[[entry]]
kind = "activate"
at_ticks = -1
tag = "negative-time"

[entry.fault]
kind = "crash"
node = "a"
restart = "stay_down"
"#;
        let unknown_direction_toml = r#"
id = "blake3:0000000000000000000000000000000000000000000000000000000000000000"

[[entry]]
kind = "activate"
at_ticks = 0
tag = "bad-direction"

[entry.fault]
kind = "partition"
endpoint_a = "a"
endpoint_b = "b"
direction = "sideways"
"#;
        let unsupported_fault_param_toml = r#"
id = "blake3:0000000000000000000000000000000000000000000000000000000000000000"

[[entry]]
kind = "activate"
at_ticks = 0
tag = "unsupported-rate"

[entry.fault]
kind = "crash"
node = "a"
restart = "stay_down"
rate = 1.5
"#;
        let negative_time = Plan::from_canonical_toml_for_world(&world, negative_time_toml);
        let unknown_direction = Plan::from_canonical_toml_for_world(&world, unknown_direction_toml);
        let unsupported_fault_param =
            Plan::from_canonical_toml_for_world(&world, unsupported_fault_param_toml);
        let valid_scenario_plan = Plan::from_entries_for_world(
            &world,
            vec![PlanEntry::Activate {
                at: VirtualTime::default(),
                tag: tag("scenario-crash"),
                fault: MembershipFault::Crash {
                    node: node_id("a"),
                    restart: RestartPolicy::StayDown,
                },
            }],
        )
        .unwrap_or_else(|error| panic!("scenario plan should be valid: {error}"));
        let valid_scenario_form = ScenarioDefForm::from_components(
            &world,
            &valid_scenario_plan,
            &Properties::empty(),
            Seed::from_u64(0x0010_0020),
        )
        .unwrap_or_else(|error| panic!("scenario form should be valid: {error}"));
        let scenario_negative_time_toml = valid_scenario_form
            .to_canonical_toml()
            .unwrap_or_else(|error| panic!("scenario TOML should serialize: {error}"))
            .replace("at_ticks = 0", "at_ticks = -2");
        let scenario_negative_time =
            ScenarioDefForm::from_canonical_toml(&scenario_negative_time_toml);

        assert!(matches!(
            unknown_crash_target,
            Err(EngineError::PlanFaultUnknownNode { node })
                if node == node_id("missing")
        ));
        assert!(matches!(
            unknown_isolate_target,
            Err(EngineError::PlanFaultUnknownNode { node })
                if node == node_id("missing-isolate")
        ));
        assert!(matches!(
            unknown_partition_link,
            Err(EngineError::PlanFaultUnknownLink {
                endpoint_a,
                endpoint_b,
            }) if endpoint_a == node_id("b") && endpoint_b == node_id("c")
        ));
        assert!(matches!(
            unknown_heal_tag,
            Err(EngineError::PlanHealUnknownTag { tag })
                if tag == self::tag("never-activated")
        ));
        assert!(matches!(
            heal_before_activate,
            Err(EngineError::PlanHealBeforeActivate {
                tag,
                activate_at,
                heal_at,
            }) if tag == self::tag("split-ab")
                && activate_at.ticks == 20
                && heal_at.ticks == 10
        ));
        assert!(matches!(
            not_yet_joined_after_start,
            Err(EngineError::PlanNotYetJoinedAfterStart { node, at })
                if node == node_id("c") && at.ticks == 1
        ));
        assert!(matches!(
            negative_time,
            Err(EngineError::PlanNegativeTime { entry, at_ticks })
                if entry == 0 && at_ticks == -1
        ));
        assert!(matches!(
            unknown_direction,
            Err(EngineError::PlanFaultUnknownDirection { entry, direction })
                if entry == 0 && direction == "sideways"
        ));
        assert!(matches!(
            unsupported_fault_param,
            Err(EngineError::PlanFaultUnsupportedParam { entry, field })
                if entry == 0 && field == "rate"
        ));
        assert!(matches!(
            scenario_negative_time,
            Err(EngineError::PlanNegativeTime { entry, at_ticks })
                if entry == 0 && at_ticks == -2
        ));

        let start_time_not_yet_joined =
            start_time_not_yet_joined.unwrap_or_else(|error| panic!("{error}"));
        let direction_a_to_b = direction_a_to_b.unwrap_or_else(|error| panic!("{error}"));
        let direction_b_to_a = direction_b_to_a.unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(start_time_not_yet_joined.entries().len(), 1);
        assert_eq!(
            direction_a_to_b.entries(),
            direction_b_to_a.entries(),
            "equivalent one-way partitions should canonicalize to the same fault params",
        );
        assert_eq!(
            direction_a_to_b.content_hash(),
            direction_b_to_a.content_hash()
        );
    }

    #[test]
    fn scenario_def_form_rejects_well_formedness_matrix_before_hashing() {
        let world = world_from_nodes_and_links(
            vec![
                ready_node(
                    "a",
                    ReadyPoint::FixedIcount {
                        icount: Icount { retired: 1 },
                    },
                ),
                ready_node(
                    "b",
                    ReadyPoint::FixedIcount {
                        icount: Icount { retired: 2 },
                    },
                ),
                ready_node(
                    "c",
                    ReadyPoint::FixedIcount {
                        icount: Icount { retired: 3 },
                    },
                ),
            ],
            vec![link("a", "b")],
        );
        let changed_vcpu_world = world_from_nodes_and_links(
            vec![
                WorldNode {
                    smp_vcpus: 2,
                    ..ready_node(
                        "a",
                        ReadyPoint::FixedIcount {
                            icount: Icount { retired: 1 },
                        },
                    )
                },
                ready_node(
                    "b",
                    ReadyPoint::FixedIcount {
                        icount: Icount { retired: 2 },
                    },
                ),
                ready_node(
                    "c",
                    ReadyPoint::FixedIcount {
                        icount: Icount { retired: 3 },
                    },
                ),
            ],
            vec![link("a", "b")],
        );
        let changed_shift_world = world_from_nodes_and_links(
            vec![
                WorldNode {
                    icount_shift: 1,
                    ..ready_node(
                        "a",
                        ReadyPoint::FixedIcount {
                            icount: Icount { retired: 1 },
                        },
                    )
                },
                ready_node(
                    "b",
                    ReadyPoint::FixedIcount {
                        icount: Icount { retired: 2 },
                    },
                ),
                ready_node(
                    "c",
                    ReadyPoint::FixedIcount {
                        icount: Icount { retired: 3 },
                    },
                ),
            ],
            vec![link("a", "b")],
        );
        let duplicate_node_ids = World::from_nodes(vec![
            ready_node(
                "dup",
                ReadyPoint::FixedIcount {
                    icount: Icount { retired: 1 },
                },
            ),
            ready_node(
                "dup",
                ReadyPoint::FixedIcount {
                    icount: Icount { retired: 2 },
                },
            ),
        ]);
        let unknown_link_endpoint = World::from_nodes_and_links(
            vec![ready_node(
                "a",
                ReadyPoint::FixedIcount {
                    icount: Icount { retired: 1 },
                },
            )],
            vec![link("a", "missing")],
        );
        let latency_below_floor = LinkDef::with_transport(
            node_id("a"),
            node_id("b"),
            SimDuration { nanos: 0 },
            SimDuration::default(),
            LinkLossProbability::ZERO,
            None,
        );
        let jitter_below_floor = LinkDef::with_transport(
            node_id("a"),
            node_id("b"),
            SimDuration { nanos: 5 },
            SimDuration { nanos: 5 },
            LinkLossProbability::ZERO,
            None,
        );
        let loss_out_of_range = LinkLossProbability::from_millionths(1_000_001);
        let plan_unknown_node = Plan::from_entries_for_world(
            &world,
            vec![PlanEntry::Activate {
                at: VirtualTime::default(),
                tag: tag("missing-node"),
                fault: MembershipFault::Crash {
                    node: node_id("missing"),
                    restart: RestartPolicy::StayDown,
                },
            }],
        );
        let plan_unknown_link = Plan::from_entries_for_world(
            &world,
            vec![PlanEntry::Activate {
                at: VirtualTime::default(),
                tag: tag("missing-link"),
                fault: MembershipFault::Partition {
                    endpoint_a: node_id("b"),
                    endpoint_b: node_id("c"),
                    direction: PartitionDirection::Bidirectional,
                },
            }],
        );
        let unsupported_fault_param_toml = r#"
id = "blake3:0000000000000000000000000000000000000000000000000000000000000000"

[[entry]]
kind = "activate"
at_ticks = 0
tag = "unsupported-window"

[entry.fault]
kind = "crash"
node = "a"
restart = "stay_down"
window = 10
"#;
        let unsupported_fault_param =
            Plan::from_canonical_toml_for_world(&world, unsupported_fault_param_toml);
        let unknown_direction_toml = r#"
id = "blake3:0000000000000000000000000000000000000000000000000000000000000000"

[[entry]]
kind = "activate"
at_ticks = 0
tag = "bad-direction"

[entry.fault]
kind = "partition"
endpoint_a = "a"
endpoint_b = "b"
direction = "sideways"
"#;
        let unknown_direction = Plan::from_canonical_toml_for_world(&world, unknown_direction_toml);
        let unknown_heal_tag = Plan::from_entries_for_world(
            &world,
            vec![PlanEntry::Heal {
                at: VirtualTime { ticks: 10 },
                tag: tag("never-activated"),
            }],
        );
        let negative_plan_time_toml = r#"
id = "blake3:0000000000000000000000000000000000000000000000000000000000000000"

[[entry]]
kind = "heal"
at_ticks = -5
tag = "negative-time"
"#;
        let negative_plan_time =
            Plan::from_canonical_toml_for_world(&world, negative_plan_time_toml);
        let unknown_property_ref = Properties::from_assertions_for_world(
            &world,
            vec![assertion(
                "missing",
                "missing property node",
                Property::Always {
                    predicate: named_predicate("node_alive", &["missing"]),
                },
            )],
        );
        let empty_property_compound = Properties::from_assertions_for_world(
            &world,
            vec![assertion(
                "empty",
                "empty all-of",
                Property::Always {
                    predicate: Predicate::AllOf {
                        predicates: Vec::new(),
                    },
                },
            )],
        );
        let white_box_ready_point_without_opt_in = World::from_nodes(vec![WorldNode {
            id: node_id("agent"),
            arch: NodeTemplate::DEFAULT_ARCH,
            memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
            cmdline: String::new(),
            ready_point: ReadyPoint::AgentSignal,
            white_box: WhiteBoxPolicy::Disabled,
            smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
            icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
            kernel: None,
            root_image: None,
            initrd: None,
        }]);
        let zero_vcpu_count = World::from_nodes(vec![WorldNode {
            id: node_id("zero-vcpu"),
            arch: NodeTemplate::DEFAULT_ARCH,
            memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
            cmdline: String::new(),
            ready_point: ReadyPoint::FixedIcount {
                icount: Icount { retired: 1 },
            },
            white_box: WhiteBoxPolicy::Disabled,
            smp_vcpus: 0,
            icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
            kernel: None,
            root_image: None,
            initrd: None,
        }]);
        let icount_shift_too_large = World::from_nodes(vec![WorldNode {
            id: node_id("bad-shift"),
            arch: NodeTemplate::DEFAULT_ARCH,
            memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
            cmdline: String::new(),
            ready_point: ReadyPoint::FixedIcount {
                icount: Icount { retired: 1 },
            },
            white_box: WhiteBoxPolicy::Disabled,
            smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
            icount_shift: 63,
            kernel: None,
            root_image: None,
            initrd: None,
        }]);
        let valid_plan = Plan::from_entries_for_world(
            &world,
            vec![PlanEntry::Activate {
                at: VirtualTime::default(),
                tag: tag("valid-crash"),
                fault: MembershipFault::Crash {
                    node: node_id("a"),
                    restart: RestartPolicy::StayDown,
                },
            }],
        )
        .unwrap_or_else(|error| panic!("valid plan should build: {error}"));
        let valid_form = ScenarioDefForm::from_components(
            &world,
            &valid_plan,
            &Properties::empty(),
            Seed::from_u64(0x0010_0021),
        )
        .unwrap_or_else(|error| panic!("valid scenario form should build: {error}"));
        let scenario_negative_plan_time = ScenarioDefForm::from_canonical_toml(
            &valid_form
                .to_canonical_toml()
                .unwrap_or_else(|error| panic!("valid scenario should serialize: {error}"))
                .replace("at_ticks = 0", "at_ticks = -7"),
        );

        assert!(matches!(
            duplicate_node_ids,
            Err(EngineError::DuplicateWorldNodeId { node }) if node == node_id("dup")
        ));
        assert!(matches!(
            unknown_link_endpoint,
            Err(EngineError::WorldLinkUnknownNode { node, .. })
                if node == node_id("missing")
        ));
        assert!(matches!(
            latency_below_floor,
            Err(EngineError::WorldLinkLatencyBelowFloor { latency, minimum, .. })
                if latency == SimDuration { nanos: 0 } && minimum == MIN_LINK_LATENCY
        ));
        assert!(matches!(
            jitter_below_floor,
            Err(EngineError::WorldLinkJitterBelowLatencyFloor {
                latency,
                jitter,
                minimum,
                ..
            }) if latency == SimDuration { nanos: 5 }
                && jitter == SimDuration { nanos: 5 }
                && minimum == MIN_LINK_LATENCY
        ));
        assert!(matches!(
            loss_out_of_range,
            Err(EngineError::LinkLossProbabilityOutOfRange {
                millionths,
                maximum,
            }) if millionths == 1_000_001 && maximum == 1_000_000
        ));
        assert!(matches!(
            plan_unknown_node,
            Err(EngineError::PlanFaultUnknownNode { node })
                if node == node_id("missing")
        ));
        assert!(matches!(
            plan_unknown_link,
            Err(EngineError::PlanFaultUnknownLink {
                endpoint_a,
                endpoint_b,
            }) if endpoint_a == node_id("b") && endpoint_b == node_id("c")
        ));
        assert!(matches!(
            unsupported_fault_param,
            Err(EngineError::PlanFaultUnsupportedParam { entry, field })
                if entry == 0 && field == "window"
        ));
        assert!(matches!(
            unknown_direction,
            Err(EngineError::PlanFaultUnknownDirection { entry, direction })
                if entry == 0 && direction == "sideways"
        ));
        assert!(matches!(
            unknown_heal_tag,
            Err(EngineError::PlanHealUnknownTag { tag })
                if tag == self::tag("never-activated")
        ));
        assert!(matches!(
            negative_plan_time,
            Err(EngineError::PlanNegativeTime { entry, at_ticks })
                if entry == 0 && at_ticks == -5
        ));
        assert!(matches!(
            unknown_property_ref,
            Err(EngineError::PropertyPredicateUnknownNode { node })
                if node == node_id("missing")
        ));
        assert!(matches!(
            empty_property_compound,
            Err(EngineError::PropertyPredicateEmptyCompound { kind }) if kind == "all-of"
        ));
        assert!(matches!(
            white_box_ready_point_without_opt_in,
            Err(EngineError::WhiteBoxReadyPointWithoutOptIn { node })
                if node == node_id("agent")
        ));
        assert!(matches!(
            zero_vcpu_count,
            Err(EngineError::WorldNodeSmpVcpuCountZero { node })
                if node == node_id("zero-vcpu")
        ));
        assert!(matches!(
            icount_shift_too_large,
            Err(EngineError::WorldNodeIcountShiftTooLarge {
                node,
                shift,
                maximum,
            }) if node == node_id("bad-shift") && shift == 63 && maximum == 62
        ));
        assert!(matches!(
            scenario_negative_plan_time,
            Err(EngineError::PlanNegativeTime { entry, at_ticks })
                if entry == 0 && at_ticks == -7
        ));
        assert_eq!(valid_form.id(), valid_form.scenario_def().id());
        assert_ne!(world.id(), changed_vcpu_world.id());
        assert_ne!(world.id(), changed_shift_world.id());
        assert_ne!(world.scenario_def(), changed_vcpu_world.scenario_def());
        assert_ne!(world.scenario_def(), changed_shift_world.scenario_def());
    }

    #[test]
    fn plan_content_address_is_orthogonal_and_canonical() {
        let world = world_from_nodes_and_links(
            two_ready_nodes(),
            vec![transport_link("a", "b", 10, 1, 0, None)],
        );
        let changed_world = world_from_nodes_and_links(
            vec![
                ready_node(
                    "a",
                    ReadyPoint::FixedIcount {
                        icount: Icount { retired: 11 },
                    },
                ),
                ready_node(
                    "b",
                    ReadyPoint::FixedIcount {
                        icount: Icount { retired: 12 },
                    },
                ),
            ],
            vec![transport_link("a", "b", 20, 1, 0, None)],
        );
        let incompatible_world = world_from_nodes_and_links(two_ready_nodes(), Vec::new());
        let authored_order = vec![
            PlanEntry::Heal {
                at: VirtualTime { ticks: 40 },
                tag: tag("split"),
            },
            PlanEntry::Activate {
                at: VirtualTime { ticks: 10 },
                tag: tag("split"),
                fault: MembershipFault::Partition {
                    endpoint_a: node_id("b"),
                    endpoint_b: node_id("a"),
                    direction: PartitionDirection::Bidirectional,
                },
            },
            PlanEntry::Activate {
                at: VirtualTime { ticks: 20 },
                tag: tag("crash-b"),
                fault: MembershipFault::Crash {
                    node: node_id("b"),
                    restart: RestartPolicy::FromLastCheckpoint,
                },
            },
        ];
        let canonical_order = vec![
            PlanEntry::Activate {
                at: VirtualTime { ticks: 10 },
                tag: tag("split"),
                fault: MembershipFault::Partition {
                    endpoint_a: node_id("a"),
                    endpoint_b: node_id("b"),
                    direction: PartitionDirection::Bidirectional,
                },
            },
            PlanEntry::Activate {
                at: VirtualTime { ticks: 20 },
                tag: tag("crash-b"),
                fault: MembershipFault::Crash {
                    node: node_id("b"),
                    restart: RestartPolicy::FromLastCheckpoint,
                },
            },
            PlanEntry::Heal {
                at: VirtualTime { ticks: 40 },
                tag: tag("split"),
            },
        ];

        let plan = match Plan::from_entries_for_world(&world, authored_order) {
            Ok(plan) => plan,
            Err(error) => panic!("authored-order plan should be valid: {error}"),
        };
        let same_plan = match Plan::from_entries_for_world(&world, canonical_order) {
            Ok(plan) => plan,
            Err(error) => panic!("canonical-order plan should be valid: {error}"),
        };
        let same_plan_changed_world =
            match Plan::from_entries_for_world(&changed_world, same_plan.entries().to_vec()) {
                Ok(plan) => plan,
                Err(error) => panic!("same plan should apply to compatible world: {error}"),
            };
        let changed_plan = match Plan::from_entries_for_world(
            &world,
            vec![PlanEntry::Activate {
                at: VirtualTime { ticks: 11 },
                tag: tag("split"),
                fault: MembershipFault::Partition {
                    endpoint_a: node_id("a"),
                    endpoint_b: node_id("b"),
                    direction: PartitionDirection::Bidirectional,
                },
            }],
        ) {
            Ok(plan) => plan,
            Err(error) => panic!("changed plan should be valid: {error}"),
        };
        let empty_plan = Plan::empty();

        assert_eq!(plan.content_hash(), same_plan.content_hash());
        assert_eq!(plan.entries(), same_plan.entries());
        assert_eq!(plan.content_hash(), same_plan_changed_world.content_hash());
        assert_ne!(plan.content_hash(), changed_plan.content_hash());
        assert_eq!(
            world.scenario_def(),
            world
                .scenario_def_with_plan(&empty_plan)
                .unwrap_or_else(|error| panic!("empty plan should compose: {error}"))
        );
        assert_eq!(
            world
                .scenario_def_with_plan(&plan)
                .unwrap_or_else(|error| panic!("plan should compose: {error}")),
            world
                .scenario_def_with_plan(&same_plan)
                .unwrap_or_else(|error| panic!("same plan should compose: {error}"))
        );
        assert_ne!(
            world.scenario_def(),
            world
                .scenario_def_with_plan(&plan)
                .unwrap_or_else(|error| panic!("plan should affect scenario identity: {error}"))
        );
        assert_ne!(
            world
                .scenario_def_with_plan(&plan)
                .unwrap_or_else(|error| panic!("plan should compose: {error}")),
            changed_world
                .scenario_def_with_plan(&same_plan_changed_world)
                .unwrap_or_else(|error| panic!(
                    "same plan should compose with compatible world: {error}"
                ))
        );
        assert!(matches!(
            incompatible_world.scenario_def_with_plan(&plan),
            Err(EngineError::PlanFaultUnknownLink {
                endpoint_a,
                endpoint_b,
            }) if endpoint_a == node_id("a") && endpoint_b == node_id("b")
        ));
    }

    #[test]
    fn properties_content_address_is_orthogonal_and_validated() {
        let mut world_nodes = two_ready_nodes();
        world_nodes[0].white_box = WhiteBoxPolicy::Enabled;
        let world =
            world_from_nodes_and_links(world_nodes, vec![transport_link("a", "b", 10, 1, 0, None)]);
        let mut changed_world_nodes = vec![
            ready_node(
                "a",
                ReadyPoint::FixedIcount {
                    icount: Icount { retired: 11 },
                },
            ),
            ready_node(
                "b",
                ReadyPoint::FixedIcount {
                    icount: Icount { retired: 12 },
                },
            ),
        ];
        changed_world_nodes[0].white_box = WhiteBoxPolicy::Enabled;
        let changed_world = world_from_nodes_and_links(
            changed_world_nodes,
            vec![transport_link("a", "b", 20, 1, 0, None)],
        );
        let incompatible_world = world_from_nodes_and_links(
            vec![ready_node(
                "a",
                ReadyPoint::FixedIcount {
                    icount: Icount { retired: 1 },
                },
            )],
            Vec::new(),
        );
        let authored_order = vec![
            assertion(
                "settles",
                "replicas settle to the same state",
                Property::AfterQuiescence {
                    predicate: named_predicate("replicas_equal", &["b", "a"]),
                },
            ),
            assertion(
                "alive",
                "nodes remain alive",
                Property::Always {
                    predicate: Predicate::AllOf {
                        predicates: vec![
                            named_predicate("node_alive", &["b"]),
                            named_predicate("node_alive", &["a"]),
                        ],
                    },
                },
            ),
            assertion(
                "commit-reached",
                "commit marker was reached",
                Property::Reachable {
                    predicate: Predicate::GuestMarker {
                        marker: marker_id("commit"),
                    },
                    expectation: ReachabilityExpectation::Reachable {
                        on_unreached: ReachableDisposition::Warn,
                    },
                },
            ),
        ];
        let canonical_order = vec![
            assertion(
                "alive",
                "nodes remain alive",
                Property::Always {
                    predicate: Predicate::AllOf {
                        predicates: vec![
                            named_predicate("node_alive", &["a"]),
                            named_predicate("node_alive", &["b"]),
                        ],
                    },
                },
            ),
            assertion(
                "commit-reached",
                "commit marker was reached",
                Property::Reachable {
                    predicate: Predicate::GuestMarker {
                        marker: marker_id("commit"),
                    },
                    expectation: ReachabilityExpectation::Reachable {
                        on_unreached: ReachableDisposition::Warn,
                    },
                },
            ),
            assertion(
                "settles",
                "replicas settle to the same state",
                Property::AfterQuiescence {
                    predicate: named_predicate("replicas_equal", &["b", "a"]),
                },
            ),
        ];

        let properties = match Properties::from_assertions_for_world(&world, authored_order) {
            Ok(properties) => properties,
            Err(error) => panic!("authored-order properties should be valid: {error}"),
        };
        let same_properties = match Properties::from_assertions_for_world(&world, canonical_order) {
            Ok(properties) => properties,
            Err(error) => panic!("canonical-order properties should be valid: {error}"),
        };
        let same_properties_changed_world = match Properties::from_assertions_for_world(
            &changed_world,
            same_properties.assertions().to_vec(),
        ) {
            Ok(properties) => properties,
            Err(error) => panic!("same properties should apply to compatible world: {error}"),
        };
        let changed_properties = match Properties::from_assertions_for_world(
            &world,
            vec![assertion(
                "alive",
                "node b remains alive",
                Property::Always {
                    predicate: named_predicate("node_alive", &["b"]),
                },
            )],
        ) {
            Ok(properties) => properties,
            Err(error) => panic!("changed properties should be valid: {error}"),
        };
        let unknown_node = Properties::from_assertions_for_world(
            &world,
            vec![assertion(
                "missing",
                "missing node is invalid",
                Property::Always {
                    predicate: named_predicate("node_alive", &["missing"]),
                },
            )],
        );
        let duplicate_id = Properties::from_assertions_for_world(
            &world,
            vec![
                assertion(
                    "dup",
                    "first",
                    Property::Always {
                        predicate: named_predicate("node_alive", &["a"]),
                    },
                ),
                assertion(
                    "dup",
                    "second",
                    Property::Sometimes {
                        predicate: named_predicate("node_alive", &["b"]),
                    },
                ),
            ],
        );
        let empty_compound = Properties::from_assertions_for_world(
            &world,
            vec![assertion(
                "empty",
                "empty all-of is invalid",
                Property::Always {
                    predicate: Predicate::AllOf {
                        predicates: Vec::new(),
                    },
                },
            )],
        );
        let empty_plan = Plan::empty();
        let empty_properties = Properties::empty();
        let partition_plan = match Plan::from_entries_for_world(
            &world,
            vec![PlanEntry::Activate {
                at: VirtualTime { ticks: 10 },
                tag: tag("split"),
                fault: MembershipFault::Partition {
                    endpoint_a: node_id("a"),
                    endpoint_b: node_id("b"),
                    direction: PartitionDirection::Bidirectional,
                },
            }],
        ) {
            Ok(plan) => plan,
            Err(error) => panic!("partition plan should be valid: {error}"),
        };
        let mut no_link_world_nodes = two_ready_nodes();
        no_link_world_nodes[0].white_box = WhiteBoxPolicy::Enabled;
        let no_link_world = world_from_nodes_and_links(no_link_world_nodes, Vec::new());

        assert_eq!(properties.content_hash(), same_properties.content_hash());
        assert_eq!(properties.assertions(), same_properties.assertions());
        assert_eq!(
            properties.content_hash(),
            same_properties_changed_world.content_hash()
        );
        assert_ne!(properties.content_hash(), changed_properties.content_hash());
        assert_eq!(
            world.scenario_def(),
            world
                .scenario_def_with_plan_and_properties(&empty_plan, &empty_properties)
                .unwrap_or_else(|error| panic!(
                    "empty plan and properties should compose: {error}"
                ))
        );
        assert_eq!(
            world
                .scenario_def_with_plan(&empty_plan)
                .unwrap_or_else(|error| panic!("empty plan should compose: {error}")),
            world
                .scenario_def_with_plan_and_properties(&empty_plan, &empty_properties)
                .unwrap_or_else(|error| panic!(
                    "empty properties should preserve plan-only scenario: {error}"
                ))
        );
        assert_ne!(
            world
                .scenario_def_with_plan(&empty_plan)
                .unwrap_or_else(|error| panic!("empty plan should compose: {error}")),
            world
                .scenario_def_with_plan_and_properties(&empty_plan, &properties)
                .unwrap_or_else(|error| panic!(
                    "properties should affect scenario identity: {error}"
                ))
        );
        assert_ne!(
            world
                .scenario_def_with_plan_and_properties(&empty_plan, &properties)
                .unwrap_or_else(|error| panic!("properties should compose: {error}")),
            changed_world
                .scenario_def_with_plan_and_properties(&empty_plan, &same_properties_changed_world)
                .unwrap_or_else(|error| panic!(
                    "same properties should compose with compatible world: {error}"
                ))
        );
        assert!(matches!(
            incompatible_world.scenario_def_with_plan_and_properties(&empty_plan, &properties),
            Err(EngineError::PropertyPredicateUnknownNode { node }) if node == node_id("b")
        ));
        assert!(matches!(
            no_link_world.scenario_def_with_plan_and_properties(&partition_plan, &properties),
            Err(EngineError::PlanFaultUnknownLink {
                endpoint_a,
                endpoint_b,
            }) if endpoint_a == node_id("a") && endpoint_b == node_id("b")
        ));
        assert!(matches!(
            unknown_node,
            Err(EngineError::PropertyPredicateUnknownNode { node })
                if node == node_id("missing")
        ));
        assert!(matches!(
            duplicate_id,
            Err(EngineError::PropertyDuplicateAssertionId { id }) if id == assertion_id("dup")
        ));
        assert!(matches!(
            empty_compound,
            Err(EngineError::PropertyPredicateEmptyCompound { kind }) if kind == "all-of"
        ));
    }

    #[test]
    fn scenario_builder_keeps_authoring_layers_structurally_orthogonal() {
        let seed = Seed::from_u64(0x0010_0015);
        let plan_entry = PlanEntry::Activate {
            at: VirtualTime { ticks: 3 },
            tag: tag("split"),
            fault: MembershipFault::Partition {
                endpoint_a: node_id("a"),
                endpoint_b: node_id("b"),
                direction: PartitionDirection::Bidirectional,
            },
        };
        let property = assertion(
            "both-alive",
            "both nodes stay alive",
            Property::Always {
                predicate: Predicate::AllOf {
                    predicates: vec![
                        named_predicate("node_alive", &["b"]),
                        named_predicate("node_alive", &["a"]),
                    ],
                },
            },
        );

        let scenario = ScenarioBuilder::new()
            .node(
                "a",
                NodeTemplate::fixed_icount(Icount { retired: 11 })
                    .white_box(WhiteBoxPolicy::Disabled),
            )
            .node_like("b", "a")
            .link_with_transport(
                "b",
                "a",
                SimDuration { nanos: 10 },
                SimDuration { nanos: 1 },
                LinkLossProbability::ZERO,
                Some(1_000_000),
            )
            .plan_entry(plan_entry.clone())
            .property(property.clone())
            .seed(seed)
            .build()
            .unwrap_or_else(|error| panic!("builder-authored scenario should be valid: {error}"));
        let manual_world = world_from_nodes_and_links(
            vec![
                ready_node(
                    "a",
                    ReadyPoint::FixedIcount {
                        icount: Icount { retired: 11 },
                    },
                ),
                ready_node(
                    "b",
                    ReadyPoint::FixedIcount {
                        icount: Icount { retired: 11 },
                    },
                ),
            ],
            vec![transport_link("a", "b", 10, 1, 0, Some(1_000_000))],
        );
        let manual_plan = Plan::from_entries_for_world(&manual_world, vec![plan_entry])
            .unwrap_or_else(|error| panic!("manual plan should be valid: {error}"));
        let manual_properties =
            Properties::from_assertions_for_world(&manual_world, vec![property])
                .unwrap_or_else(|error| panic!("manual properties should be valid: {error}"));
        let manual_scenario = manual_world
            .scenario_def_with_plan_properties_and_seed(&manual_plan, &manual_properties, seed)
            .unwrap_or_else(|error| panic!("manual scenario composition should be valid: {error}"));
        let reused_world_scenario = ScenarioBuilder::new()
            .world(&manual_world)
            .seed(seed)
            .build()
            .unwrap_or_else(|error| panic!("world-template scenario should be valid: {error}"));
        let complete_layer_scenario = ScenarioBuilder::new()
            .world(&manual_world)
            .plan(manual_plan.clone())
            .properties(manual_properties.clone())
            .seed(seed)
            .build()
            .unwrap_or_else(|error| panic!("complete-layer scenario should be valid: {error}"));
        let templated_world_scenario = ScenarioBuilder::new()
            .node("fixed", NodeTemplate::fixed_icount(Icount { retired: 5 }))
            .node(
                "idle",
                NodeTemplate::network_idle(SimDuration { nanos: 1_000 }),
            )
            .node("console", NodeTemplate::console_marker("ready"))
            .node("agent", NodeTemplate::agent_signal())
            .link("fixed", "idle")
            .link_def(link("agent", "console"))
            .seed(seed)
            .build()
            .unwrap_or_else(|error| panic!("templated world scenario should be valid: {error}"));
        let templated_world = world_from_nodes_and_links(
            vec![
                ready_node(
                    "fixed",
                    ReadyPoint::FixedIcount {
                        icount: Icount { retired: 5 },
                    },
                ),
                ready_node(
                    "idle",
                    ReadyPoint::NetworkIdle {
                        window: SimDuration { nanos: 1_000 },
                    },
                ),
                ready_node(
                    "console",
                    ReadyPoint::ConsoleMarker {
                        marker: String::from("ready"),
                    },
                ),
                WorldNode {
                    id: node_id("agent"),
                    arch: NodeTemplate::DEFAULT_ARCH,
                    memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
                    cmdline: String::new(),
                    ready_point: ReadyPoint::AgentSignal,
                    white_box: WhiteBoxPolicy::Enabled,
                    smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
                    icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
                    kernel: None,
                    root_image: None,
                    initrd: None,
                },
            ],
            vec![link("idle", "fixed"), link("console", "agent")],
        );

        assert_eq!(scenario, manual_scenario);
        assert_eq!(complete_layer_scenario, manual_scenario);
        assert_eq!(
            templated_world_scenario,
            templated_world.scenario_def_with_seed(seed)
        );
        assert_eq!(
            reused_world_scenario,
            manual_world.scenario_def_with_seed(seed)
        );
        assert!(matches!(
            ScenarioBuilder::new().node_like("copy", "missing").build(),
            Err(EngineError::ScenarioBuilderUnknownNodeTemplate { node, template })
                if node == node_id("copy") && template == node_id("missing")
        ));
        assert!(matches!(
            ScenarioBuilder::new()
                .node("a", NodeTemplate::fixed_icount(Icount { retired: 1 }))
                .node("b", NodeTemplate::fixed_icount(Icount { retired: 2 }))
                .plan_entry(PlanEntry::Activate {
                    at: VirtualTime { ticks: 1 },
                    tag: tag("split"),
                    fault: MembershipFault::Partition {
                        endpoint_a: node_id("a"),
                        endpoint_b: node_id("b"),
                        direction: PartitionDirection::Bidirectional,
                    },
                })
                .build(),
            Err(EngineError::PlanFaultUnknownLink {
                endpoint_a,
                endpoint_b,
            }) if endpoint_a == node_id("a") && endpoint_b == node_id("b")
        ));
        assert!(matches!(
            ScenarioBuilder::new()
                .node("a", NodeTemplate::fixed_icount(Icount { retired: 1 }))
                .property(assertion(
                    "missing",
                    "missing node should be rejected",
                    Property::Always {
                        predicate: named_predicate("node_alive", &["b"]),
                    },
                ))
                .build(),
            Err(EngineError::PropertyPredicateUnknownNode { node }) if node == node_id("b")
        ));
        assert!(matches!(
            ScenarioBuilder::new()
                .node("agent", NodeTemplate::new(ReadyPoint::AgentSignal))
                .build(),
            Err(EngineError::WhiteBoxReadyPointWithoutOptIn { node })
                if node == node_id("agent")
        ));
    }

    #[test]
    fn serializable_scenario_form_round_trips_and_rejects_host_paths() {
        let kernel_ref = ContentAddressedBlobRef::from_hash(ContentHash::from_canonical_material(
            "crucible.test.blob",
            "kernel",
        ));
        let root_image_ref = ContentAddressedBlobRef::from_hash(
            ContentHash::from_canonical_material("crucible.test.blob", "root-image"),
        );
        let initrd_ref = ContentAddressedBlobRef::from_hash(ContentHash::from_canonical_material(
            "crucible.test.blob",
            "initrd",
        ));
        let world = world_from_nodes_and_links(
            vec![
                WorldNode {
                    id: node_id("a"),
                    arch: NodeTemplate::DEFAULT_ARCH,
                    memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
                    cmdline: String::new(),
                    ready_point: ReadyPoint::FixedIcount {
                        icount: Icount { retired: 11 },
                    },
                    white_box: WhiteBoxPolicy::Disabled,
                    smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
                    icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
                    kernel: Some(kernel_ref),
                    root_image: Some(root_image_ref),
                    initrd: Some(initrd_ref),
                },
                ready_node(
                    "b",
                    ReadyPoint::ConsoleMarker {
                        marker: String::from("ready"),
                    },
                ),
            ],
            vec![transport_link("b", "a", 10, 1, 0, Some(1_000_000))],
        );
        let world_without_image_refs = world_from_nodes_and_links(
            vec![
                ready_node(
                    "a",
                    ReadyPoint::FixedIcount {
                        icount: Icount { retired: 11 },
                    },
                ),
                ready_node(
                    "b",
                    ReadyPoint::ConsoleMarker {
                        marker: String::from("ready"),
                    },
                ),
            ],
            vec![transport_link("b", "a", 10, 1, 0, Some(1_000_000))],
        );
        let plan = Plan::from_entries_for_world(
            &world,
            vec![
                PlanEntry::Activate {
                    at: VirtualTime { ticks: 10 },
                    tag: tag("split"),
                    fault: MembershipFault::Partition {
                        endpoint_a: node_id("b"),
                        endpoint_b: node_id("a"),
                        direction: PartitionDirection::Bidirectional,
                    },
                },
                PlanEntry::Heal {
                    at: VirtualTime { ticks: 40 },
                    tag: tag("split"),
                },
            ],
        )
        .unwrap_or_else(|error| panic!("serialized-form plan should be valid: {error}"));
        let properties = Properties::from_assertions_for_world(
            &world,
            vec![assertion(
                "safety",
                "replicas never diverge",
                Property::Reachable {
                    predicate: Predicate::Once {
                        predicate: Box::new(Predicate::AllOf {
                            predicates: vec![
                                named_predicate("node_alive", &["a"]),
                                Predicate::Not {
                                    predicate: Box::new(named_predicate("node_alive", &["b"])),
                                },
                            ],
                        }),
                    },
                    expectation: ReachabilityExpectation::Reachable {
                        on_unreached: ReachableDisposition::Fail,
                    },
                },
            )],
        )
        .unwrap_or_else(|error| panic!("serialized-form properties should be valid: {error}"));
        let seed = Seed::from_u64(0x0010_0016);
        let form = ScenarioDefForm::from_components(&world, &plan, &properties, seed)
            .unwrap_or_else(|error| panic!("scenario form should validate: {error}"));
        let scenario = world
            .scenario_def_with_plan_properties_and_seed(&plan, &properties, seed)
            .unwrap_or_else(|error| panic!("manual scenario should validate: {error}"));
        let toml = form
            .to_canonical_toml()
            .unwrap_or_else(|error| panic!("scenario form TOML should serialize: {error}"));
        let binary = form.to_compact_binary();
        let parsed_toml = ScenarioDefForm::from_canonical_toml(&toml)
            .unwrap_or_else(|error| panic!("scenario form TOML should parse: {error}"));
        let parsed_binary = ScenarioDefForm::from_compact_binary(&binary)
            .unwrap_or_else(|error| panic!("scenario form binary should parse: {error}"));
        let world_toml = world
            .to_canonical_toml()
            .unwrap_or_else(|error| panic!("world TOML should serialize: {error}"));
        let plan_toml = plan
            .to_canonical_toml()
            .unwrap_or_else(|error| panic!("plan TOML should serialize: {error}"));
        let properties_toml = properties
            .to_canonical_toml()
            .unwrap_or_else(|error| panic!("properties TOML should serialize: {error}"));
        let seed_toml = seed
            .to_canonical_toml()
            .unwrap_or_else(|error| panic!("seed TOML should serialize: {error}"));
        let blob_hash = kernel_ref.hash();
        let blob_uri = kernel_ref.to_uri();
        let blob = ContentAddressedBlobRef::parse("kernel", &blob_uri)
            .unwrap_or_else(|error| panic!("blob ref should parse: {error}"));
        let wrong_hash =
            ContentHash::from_canonical_material("crucible.test.scenario-form", "wrong");
        let wrong_id_toml = toml.replacen(
            &format!("id = \"blake3:{}\"", form.id().to_hex()),
            &format!("id = \"blake3:{}\"", wrong_hash.to_hex()),
            1,
        );
        let empty_world = World::from_nodes_and_links(Vec::new(), Vec::new())
            .unwrap_or_else(|error| panic!("empty world should serialize: {error}"));
        let empty_world_toml = empty_world
            .to_canonical_toml()
            .unwrap_or_else(|error| panic!("empty world TOML should serialize: {error}"));
        let wrong_empty_world_toml = empty_world_toml.replacen(
            &format!("id = \"blake3:{}\"", empty_world.id().to_hex()),
            &format!("id = \"blake3:{}\"", wrong_hash.to_hex()),
            1,
        );
        let mut host_path_toml = toml.clone();
        host_path_toml.push_str("\nkernel=\"/nix/store/not-a-content-ref/bzImage\"\n");

        assert_eq!(form.scenario_def(), scenario);
        assert_eq!(parsed_toml, form);
        assert_eq!(parsed_binary, form);
        assert_eq!(parsed_toml.canonical_bytes(), form.canonical_bytes());
        assert_eq!(parsed_binary.canonical_bytes(), form.canonical_bytes());
        assert_ne!(form.canonical_bytes(), binary);
        assert_ne!(world_without_image_refs.id(), world.id());
        assert!(toml.contains(&format!("kernel = \"{}\"", kernel_ref.to_uri())));
        assert!(toml.contains(&format!("root_image = \"{}\"", root_image_ref.to_uri())));
        assert!(toml.contains(&format!("initrd = \"{}\"", initrd_ref.to_uri())));
        assert_eq!(
            World::from_canonical_toml(&world_toml)
                .unwrap_or_else(|error| panic!("world TOML should parse: {error}")),
            world
        );
        assert_eq!(
            World::from_compact_binary(&world.to_compact_binary())
                .unwrap_or_else(|error| panic!("world binary should parse: {error}")),
            world
        );
        assert_eq!(
            Plan::from_canonical_toml_for_world(&world, &plan_toml)
                .unwrap_or_else(|error| panic!("plan TOML should parse: {error}")),
            plan
        );
        assert_eq!(
            Plan::from_compact_binary_for_world(&world, &plan.to_compact_binary())
                .unwrap_or_else(|error| panic!("plan binary should parse: {error}")),
            plan
        );
        assert_eq!(
            Properties::from_canonical_toml_for_world(&world, &properties_toml)
                .unwrap_or_else(|error| panic!("properties TOML should parse: {error}")),
            properties
        );
        assert_eq!(
            Properties::from_compact_binary_for_world(&world, &properties.to_compact_binary())
                .unwrap_or_else(|error| panic!("properties binary should parse: {error}")),
            properties
        );
        assert_eq!(
            Seed::from_canonical_toml(&seed_toml)
                .unwrap_or_else(|error| panic!("seed TOML should parse: {error}")),
            seed
        );
        assert_eq!(
            Seed::from_compact_binary(&seed.to_compact_binary())
                .unwrap_or_else(|error| panic!("seed binary should parse: {error}")),
            seed
        );
        assert_eq!(blob.hash(), blob_hash);
        assert_eq!(blob.to_uri(), blob_uri);
        assert!(matches!(
            ContentAddressedBlobRef::parse("kernel", "/nix/store/kernel"),
            Err(EngineError::ScenarioImageReferenceNotContentAddressed { field, value })
                if field == "kernel" && value == "/nix/store/kernel"
        ));
        assert!(matches!(
            ScenarioDefForm::from_canonical_toml(&wrong_id_toml),
            Err(EngineError::ScenarioSerializedIdMismatch { component, .. })
                if component == "scenario"
        ));
        assert!(matches!(
            World::from_canonical_toml(&wrong_empty_world_toml),
            Err(EngineError::ScenarioSerializedIdMismatch { component, .. })
                if component == "world"
        ));
        assert!(matches!(
            ScenarioDefForm::from_canonical_toml(&host_path_toml),
            Err(EngineError::ScenarioImageReferenceNotContentAddressed { field, .. })
                if field == "kernel"
        ));
    }

    #[test]
    fn scenario_family_pins_concrete_validated_instances() {
        let seed_a = Seed::from_u64(0x0010_0017);
        let seed_b = Seed::from_u64(0x0010_0018);
        let zero_density = FaultDensity::ZERO;
        let half_density = FaultDensity::from_millionths(500_000)
            .unwrap_or_else(|error| panic!("half density should be valid: {error}"));
        let space = FamilySpace::new(
            SeedSpace::explicit(vec![seed_b, seed_a])
                .unwrap_or_else(|error| panic!("explicit seed space should be valid: {error}")),
            FaultDensityRange::new(zero_density, half_density)
                .unwrap_or_else(|error| panic!("density range should be valid: {error}")),
            TopologySizeRange::new(3, 4)
                .unwrap_or_else(|error| panic!("topology size range should be valid: {error}")),
            vec![
                TopologyShape::Star,
                TopologyShape::Ring,
                TopologyShape::Mesh,
                TopologyShape::Random,
            ],
        )
        .unwrap_or_else(|error| panic!("family space should be valid: {error}"));
        let tiny_space = FamilySpace::new(
            SeedSpace::explicit(vec![seed_a, seed_b])
                .unwrap_or_else(|error| panic!("tiny seed space should be valid: {error}")),
            FaultDensityRange::new(
                zero_density,
                FaultDensity::from_millionths(1).unwrap_or_else(|error| {
                    panic!("one-millionth density should be valid: {error}")
                }),
            )
            .unwrap_or_else(|error| panic!("tiny density range should be valid: {error}")),
            TopologySizeRange::new(1, 2).unwrap_or_else(|error| {
                panic!("tiny topology size range should be valid: {error}")
            }),
            vec![TopologyShape::Ring, TopologyShape::Star],
        )
        .unwrap_or_else(|error| panic!("tiny family space should be valid: {error}"));
        let generated_seeds = SeedSpace::generated(Seed::from_u64(0xfeed), 2)
            .unwrap_or_else(|error| panic!("generated seed space should be valid: {error}"));
        let family = ScenarioFamily::new(space, NodeTemplate::fixed_icount(Icount { retired: 17 }))
            .property(assertion(
                "node-zero-live",
                "first generated node remains addressable",
                Property::Sometimes {
                    predicate: named_predicate("node_alive", &["node-0"]),
                },
            ));
        let params = FamilyParams {
            seed: seed_a,
            fault_density: half_density,
            topology_size: 4,
            topology_shape: TopologyShape::Ring,
        };
        let pinned = family
            .instantiate(params)
            .unwrap_or_else(|error| panic!("family params should instantiate: {error}"));
        let repeated = family
            .instantiate(params)
            .unwrap_or_else(|error| panic!("same family params should instantiate: {error}"));
        let zero_faults = family
            .instantiate(FamilyParams {
                fault_density: zero_density,
                ..params
            })
            .unwrap_or_else(|error| {
                panic!("zero-density family params should instantiate: {error}")
            });
        let other_seed = family
            .instantiate(FamilyParams {
                seed: seed_b,
                ..params
            })
            .unwrap_or_else(|error| panic!("other seed family params should instantiate: {error}"));
        let smaller_topology = family
            .instantiate(FamilyParams {
                topology_size: 3,
                ..params
            })
            .unwrap_or_else(|error| panic!("smaller topology should instantiate: {error}"));
        let star_topology = family
            .instantiate(FamilyParams {
                topology_shape: TopologyShape::Star,
                ..params
            })
            .unwrap_or_else(|error| panic!("star topology should instantiate: {error}"));
        let mesh_topology = family
            .instantiate(FamilyParams {
                topology_shape: TopologyShape::Mesh,
                ..params
            })
            .unwrap_or_else(|error| panic!("mesh topology should instantiate: {error}"));
        let random_zero_faults = family
            .instantiate(FamilyParams {
                fault_density: zero_density,
                topology_shape: TopologyShape::Random,
                ..params
            })
            .unwrap_or_else(|error| {
                panic!("random zero-density topology should instantiate: {error}")
            });
        let random_half_faults = family
            .instantiate(FamilyParams {
                topology_shape: TopologyShape::Random,
                ..params
            })
            .unwrap_or_else(|error| {
                panic!("random half-density topology should instantiate: {error}")
            });
        let sampled = family
            .instantiate_sample(0)
            .unwrap_or_else(|error| panic!("sampled family params should instantiate: {error}"));
        let sampled_again = family
            .instantiate_sample(0)
            .unwrap_or_else(|error| panic!("same sample should instantiate: {error}"));
        let generated_seed_0 = generated_seeds
            .seed_at(0)
            .unwrap_or_else(|error| panic!("generated seed 0 should exist: {error}"));
        let generated_seed_1 = generated_seeds
            .seed_at(1)
            .unwrap_or_else(|error| panic!("generated seed 1 should exist: {error}"));
        let out_of_space = family.instantiate(FamilyParams {
            topology_size: 5,
            ..params
        });
        let bad_density = FaultDensity::from_millionths(1_000_001);
        let pinned_form = pinned.clone().into_form();
        let pinned_genesis = pinned.genesis_configuration();
        let round_tripped_pinned_form = ScenarioDefForm::from_canonical_toml(
            &pinned_genesis
                .scenario_form()
                .to_canonical_toml()
                .unwrap_or_else(|error| panic!("pinned form TOML should serialize: {error}")),
        )
        .unwrap_or_else(|error| panic!("pinned form TOML should parse: {error}"));
        let tiny_total = tiny_space
            .cardinality()
            .unwrap_or_else(|error| panic!("tiny space cardinality should compute: {error}"));
        let mut tiny_samples = std::collections::BTreeSet::new();
        for index in 0..tiny_total {
            tiny_samples.insert(
                tiny_space
                    .sample(index)
                    .unwrap_or_else(|error| panic!("tiny sample {index} should exist: {error}")),
            );
        }
        let exhausted_tiny_sample = tiny_space.sample(tiny_total);

        assert_eq!(pinned, repeated);
        assert_eq!(pinned.params(), params);
        assert_eq!(pinned.form().seed(), params.seed);
        assert_eq!(pinned.form().world().nodes().len(), 4);
        assert_eq!(pinned.form().world().links().len(), 4);
        assert_eq!(pinned.form().properties().assertions().len(), 1);
        assert_eq!(pinned.form().plan().entries().len(), 8);
        assert_eq!(
            pinned
                .form()
                .plan()
                .entries()
                .iter()
                .filter(|entry| matches!(entry, PlanEntry::Activate { .. }))
                .count(),
            4
        );
        assert_eq!(pinned_form, pinned.form().clone());
        assert_eq!(pinned_genesis.configuration().def, pinned.scenario_def());
        assert_eq!(pinned_genesis.scenario_form(), pinned.form());
        assert_eq!(round_tripped_pinned_form, pinned.form().clone());
        assert!(zero_faults.form().plan().entries().is_empty());
        assert_ne!(zero_faults.id(), pinned.id());
        assert_ne!(other_seed.id(), pinned.id());
        assert_eq!(smaller_topology.form().world().nodes().len(), 3);
        assert_eq!(smaller_topology.form().world().links().len(), 3);
        assert_ne!(smaller_topology.id(), pinned.id());
        assert_eq!(star_topology.form().world().links().len(), 3);
        assert_ne!(star_topology.id(), pinned.id());
        assert_eq!(mesh_topology.form().world().links().len(), 6);
        assert_ne!(mesh_topology.id(), pinned.id());
        assert_eq!(
            random_zero_faults.form().world(),
            random_half_faults.form().world()
        );
        assert!(random_zero_faults.form().plan().entries().is_empty());
        assert!(!random_half_faults.form().plan().entries().is_empty());
        assert_ne!(random_zero_faults.id(), random_half_faults.id());
        assert_eq!(sampled, sampled_again);
        assert!(family.space().contains(sampled.params()));
        assert_eq!(tiny_total, 16);
        assert_eq!(tiny_samples.len(), tiny_total as usize);
        assert!(matches!(
            exhausted_tiny_sample,
            Err(EngineError::ScenarioFamilyParameterOutOfSpace { parameter })
                if parameter == "sample_index"
        ));
        assert_ne!(generated_seed_0, generated_seed_1);
        assert!(matches!(
            out_of_space,
            Err(EngineError::ScenarioFamilyParameterOutOfSpace { parameter })
                if parameter == "topology_size"
        ));
        assert!(matches!(
            bad_density,
            Err(EngineError::FaultDensityOutOfRange { millionths, maximum })
                if millionths == 1_000_001 && maximum == 1_000_000
        ));
    }

    #[test]
    fn reproduction_artifact_is_self_contained_and_replay_checked() {
        let seed = Seed::from_u64(0x0010_0018);
        let density = FaultDensity::from_millionths(250_000)
            .unwrap_or_else(|error| panic!("density should be valid: {error}"));
        let space = FamilySpace::new(
            SeedSpace::explicit(vec![seed])
                .unwrap_or_else(|error| panic!("seed space should be valid: {error}")),
            FaultDensityRange::new(density, density)
                .unwrap_or_else(|error| panic!("density range should be valid: {error}")),
            TopologySizeRange::new(3, 3)
                .unwrap_or_else(|error| panic!("topology size range should be valid: {error}")),
            vec![TopologyShape::Ring],
        )
        .unwrap_or_else(|error| panic!("family space should be valid: {error}"));
        let family = ScenarioFamily::new(space, NodeTemplate::fixed_icount(Icount { retired: 24 }));
        let pinned = family
            .instantiate_sample(0)
            .unwrap_or_else(|error| panic!("sample should instantiate: {error}"));
        let pinned_genesis = pinned.genesis_configuration();
        let fault_name = pinned
            .form()
            .plan()
            .entries()
            .iter()
            .find_map(|entry| match entry {
                PlanEntry::Activate { tag, .. } => Some(tag.name.clone()),
                PlanEntry::Heal { .. } => None,
            })
            .unwrap_or_else(|| "family-fault-0".to_owned());
        let schedule = Schedule::empty()
            .appended(Decision::DeliveryOrder(DeliveryOrderDecision {
                at: VirtualTime { ticks: 1 },
                order: vec![event_key(1, 1), event_key(1, 2)],
            }))
            .appended(Decision::FaultFires(FaultDecision {
                at: VirtualTime { ticks: 2 },
                fault: FaultId { name: fault_name },
                fired: true,
            }))
            .appended(Decision::RngDraw(RngDecision {
                stream: RngStreamId::for_node("node-0"),
                value: 0x0010_0018,
            }))
            .appended(Decision::Override(OverrideDecision {
                point: SchedulingPoint {
                    key: "node-0/fault-choice".to_owned(),
                },
                choice: ChoiceTag {
                    name: "fire".to_owned(),
                },
            }))
            .appended(Decision::Preemption(PreemptionDecision {
                node: node_id("node-0"),
                at: Icount { retired: 32 },
                kind: PreemptionKind::VcpuSwitch {
                    from_vcpu: VcpuId { index: 0 },
                    to_vcpu: VcpuId { index: 1 },
                },
            }))
            .appended(Decision::Preemption(PreemptionDecision {
                node: node_id("node-1"),
                at: Icount { retired: 48 },
                kind: PreemptionKind::InterruptAt {
                    target_vcpu: VcpuId { index: 0 },
                    irq: IrqVector { vector: 32 },
                },
            }))
            .appended(Decision::AppRandom(AppRandomDecision {
                node: node_id("node-2"),
                stream: RngStreamId::for_node("node-2"),
                request_id: 7,
                width: 64,
                value: 0xfeed_beef,
            }));
        let schedule_binary = schedule.to_compact_binary();
        let parsed_schedule = Schedule::from_compact_binary(&schedule_binary)
            .unwrap_or_else(|error| panic!("schedule binary should parse: {error}"));
        let artifact = ReproductionArtifact::capture(pinned.form(), &schedule)
            .unwrap_or_else(|error| panic!("artifact capture should reduce: {error}"));
        let replay = artifact
            .replay()
            .unwrap_or_else(|error| panic!("artifact should replay: {error}"));
        let expected_state = replay.state;
        let artifact_bytes = artifact.to_compact_binary();
        let decoded_artifact = ReproductionArtifact::from_compact_binary(&artifact_bytes)
            .unwrap_or_else(|error| panic!("artifact binary should parse: {error}"));
        let reduced_state = reduce(&artifact.scenario_def(), artifact.schedule())
            .unwrap_or_else(|error| panic!("artifact schedule should reduce: {error}"))
            .id;
        let scenario_toml = artifact
            .scenario_form()
            .to_canonical_toml()
            .unwrap_or_else(|error| panic!("scenario TOML should serialize: {error}"));
        let round_tripped_scenario = ScenarioDefForm::from_canonical_toml(&scenario_toml)
            .unwrap_or_else(|error| panic!("scenario TOML should parse: {error}"));
        let offline_replay_artifact =
            ReproductionArtifact::from_recorded_parts(round_tripped_scenario, parsed_schedule);
        let pinned_genesis_artifact =
            ReproductionArtifact::from_pinned_configuration(&pinned_genesis)
                .unwrap_or_else(|error| panic!("pinned genesis should capture: {error}"));
        let checkpoint_configuration = Configuration {
            def: artifact.scenario_def(),
            schedule: artifact.schedule().clone(),
        };
        let genesis_configuration = pinned_genesis.configuration().clone();
        let checkpoint = Checkpoint::from_recorded_configuration(
            &checkpoint_configuration,
            Some(&genesis_configuration),
            VirtualTime { ticks: 7 },
            std::collections::BTreeMap::new(),
            CheckpointKind::Fat,
            std::collections::BTreeMap::new(),
        )
        .unwrap_or_else(|error| panic!("checkpoint should record: {error}"));
        let checkpoint_binary = checkpoint.to_compact_binary();
        let decoded_checkpoint = Checkpoint::from_compact_binary(&checkpoint_binary)
            .unwrap_or_else(|error| panic!("checkpoint binary should parse: {error}"));
        let drifted_schedule = artifact.schedule().appended(Decision::RngDraw(RngDecision {
            stream: RngStreamId::for_node("node-1"),
            value: 99,
        }));
        let drifted_state = reduce(&artifact.scenario_def(), &drifted_schedule)
            .unwrap_or_else(|error| panic!("drifted schedule should reduce: {error}"))
            .id;
        let schedule_drift_artifact = ReproductionArtifact::from_recorded_parts(
            artifact.scenario_form().clone(),
            drifted_schedule,
        );
        let wrong_state = ContentHash::from_canonical_material(
            "crucible.test.reproduction-artifact",
            "wrong-recorded-state",
        );

        assert_eq!(artifact.seed(), artifact.scenario_def().seed());
        assert_eq!(artifact.scenario_form(), pinned.form());
        assert_eq!(artifact.schedule(), &schedule);
        assert_eq!(reduced_state, replay.state);
        assert_eq!(
            artifact.id(),
            ContentHash::from_bytes(&artifact.canonical_bytes())
        );
        assert_eq!(artifact.to_compact_binary(), artifact.canonical_bytes());
        assert_eq!(replay.artifact, artifact.id());
        assert_eq!(replay.scenario, artifact.scenario_def().id());
        assert_eq!(replay.schedule, artifact.schedule().content_hash());
        assert_eq!(replay.state, expected_state);
        assert_eq!(decoded_artifact, artifact);
        assert_eq!(
            decoded_artifact
                .verify_replay(expected_state)
                .unwrap_or_else(|error| panic!("decoded replay should verify: {error}")),
            replay
        );
        assert_eq!(offline_replay_artifact.id(), artifact.id());
        assert_eq!(
            offline_replay_artifact.canonical_bytes(),
            artifact.canonical_bytes()
        );
        assert_eq!(
            offline_replay_artifact
                .replay()
                .unwrap_or_else(|error| panic!("offline replay should verify: {error}")),
            replay
        );
        assert_eq!(decoded_checkpoint, checkpoint);
        assert_eq!(
            decoded_checkpoint.to_compact_binary(),
            checkpoint.to_compact_binary()
        );
        assert_eq!(pinned_genesis_artifact.scenario_form(), pinned.form());
        assert!(pinned_genesis_artifact.schedule().is_empty());
        assert_ne!(schedule_drift_artifact.id(), artifact.id());
        assert!(matches!(
            schedule_drift_artifact.verify_replay(expected_state),
            Err(EngineError::ReproductionArtifactReplayMismatch {
                artifact: replayed_artifact,
                expected,
                actual,
            }) if replayed_artifact == schedule_drift_artifact.id()
                && expected == expected_state
                && actual == drifted_state
        ));
        assert!(matches!(
            artifact.verify_replay(wrong_state),
            Err(EngineError::ReproductionArtifactReplayMismatch {
                artifact: replayed_artifact,
                expected,
                actual,
            }) if replayed_artifact == artifact.id()
                && expected == wrong_state
                && actual == expected_state
        ));
    }

    #[test]
    fn canonicalization_hashes_meaning_not_authoring_spelling() {
        let kernel = ContentAddressedBlobRef::from_hash(ContentHash::from_canonical_material(
            "crucible.test.canonicalization.blob",
            "kernel",
        ));
        let root_image = ContentAddressedBlobRef::from_hash(ContentHash::from_canonical_material(
            "crucible.test.canonicalization.blob",
            "root-image",
        ));
        let initrd = ContentAddressedBlobRef::from_hash(ContentHash::from_canonical_material(
            "crucible.test.canonicalization.blob",
            "initrd",
        ));
        let changed_kernel =
            ContentAddressedBlobRef::from_hash(ContentHash::from_canonical_material(
                "crucible.test.canonicalization.blob",
                "changed-kernel",
            ));
        let node_a = WorldNode {
            id: node_id("a"),
            arch: NodeTemplate::DEFAULT_ARCH,
            memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
            cmdline: String::new(),
            ready_point: ReadyPoint::FixedIcount {
                icount: Icount { retired: 1 },
            },
            white_box: WhiteBoxPolicy::Disabled,
            smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
            icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
            kernel: Some(kernel),
            root_image: Some(root_image),
            initrd: Some(initrd),
        };
        let node_b = WorldNode {
            id: node_id("b"),
            arch: NodeTemplate::DEFAULT_ARCH,
            memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
            cmdline: String::new(),
            ready_point: ReadyPoint::NetworkIdle {
                window: SimDuration { nanos: 12 },
            },
            white_box: WhiteBoxPolicy::Disabled,
            smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
            icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
            kernel: None,
            root_image: Some(root_image),
            initrd: None,
        };
        let node_c = WorldNode {
            id: node_id("c"),
            arch: NodeTemplate::DEFAULT_ARCH,
            memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
            cmdline: String::new(),
            ready_point: ReadyPoint::ConsoleMarker {
                marker: "ready".to_owned(),
            },
            white_box: WhiteBoxPolicy::Disabled,
            smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
            icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
            kernel: Some(kernel),
            root_image: None,
            initrd: Some(initrd),
        };
        let authored_world = world_from_nodes_and_links(
            vec![node_c.clone(), node_a.clone(), node_b.clone()],
            vec![
                transport_link("c", "b", 50, 5, 125_000, Some(1_000_000)),
                transport_link("b", "a", 10, 1, 0, None),
            ],
        );
        let canonical_world = world_from_nodes_and_links(
            vec![node_a.clone(), node_b.clone(), node_c.clone()],
            vec![
                transport_link("a", "b", 10, 1, 0, None),
                transport_link("b", "c", 50, 5, 125_000, Some(1_000_000)),
            ],
        );
        let changed_loss_world = world_from_nodes_and_links(
            vec![node_a.clone(), node_b.clone(), node_c.clone()],
            vec![
                transport_link("a", "b", 10, 1, 0, None),
                transport_link("b", "c", 50, 5, 125_001, Some(1_000_000)),
            ],
        );
        let changed_ref_world = world_from_nodes_and_links(
            vec![
                WorldNode {
                    kernel: Some(changed_kernel),
                    ..node_a.clone()
                },
                node_b.clone(),
                node_c.clone(),
            ],
            canonical_world.links().to_vec(),
        );
        let changed_icount_world = world_from_nodes_and_links(
            vec![
                WorldNode {
                    ready_point: ReadyPoint::FixedIcount {
                        icount: Icount { retired: 2 },
                    },
                    ..node_a.clone()
                },
                node_b.clone(),
                node_c.clone(),
            ],
            canonical_world.links().to_vec(),
        );
        let changed_duration_world = world_from_nodes_and_links(
            vec![
                node_a.clone(),
                WorldNode {
                    ready_point: ReadyPoint::NetworkIdle {
                        window: SimDuration { nanos: 13 },
                    },
                    ..node_b.clone()
                },
                node_c.clone(),
            ],
            canonical_world.links().to_vec(),
        );
        let changed_bandwidth_world = world_from_nodes_and_links(
            vec![node_a.clone(), node_b.clone(), node_c.clone()],
            vec![
                transport_link("a", "b", 10, 1, 0, None),
                transport_link("b", "c", 50, 5, 125_000, Some(2_000_000)),
            ],
        );
        let authored_plan = Plan::from_entries_for_world(
            &authored_world,
            vec![
                PlanEntry::Heal {
                    at: VirtualTime { ticks: 40 },
                    tag: tag("split"),
                },
                PlanEntry::Activate {
                    at: VirtualTime { ticks: 20 },
                    tag: tag("crash-c"),
                    fault: MembershipFault::Crash {
                        node: node_id("c"),
                        restart: RestartPolicy::FromReadyPoint,
                    },
                },
                PlanEntry::Activate {
                    at: VirtualTime { ticks: 10 },
                    tag: tag("split"),
                    fault: MembershipFault::Partition {
                        endpoint_a: node_id("c"),
                        endpoint_b: node_id("b"),
                        direction: PartitionDirection::EndpointBToEndpointA,
                    },
                },
            ],
        )
        .unwrap_or_else(|error| panic!("authored plan should be valid: {error}"));
        let canonical_plan = Plan::from_entries_for_world(
            &canonical_world,
            vec![
                PlanEntry::Activate {
                    at: VirtualTime { ticks: 10 },
                    tag: tag("split"),
                    fault: MembershipFault::Partition {
                        endpoint_a: node_id("b"),
                        endpoint_b: node_id("c"),
                        direction: PartitionDirection::EndpointAToEndpointB,
                    },
                },
                PlanEntry::Activate {
                    at: VirtualTime { ticks: 20 },
                    tag: tag("crash-c"),
                    fault: MembershipFault::Crash {
                        node: node_id("c"),
                        restart: RestartPolicy::FromReadyPoint,
                    },
                },
                PlanEntry::Heal {
                    at: VirtualTime { ticks: 40 },
                    tag: tag("split"),
                },
            ],
        )
        .unwrap_or_else(|error| panic!("canonical plan should be valid: {error}"));
        let changed_time_plan = Plan::from_entries_for_world(
            &canonical_world,
            vec![
                PlanEntry::Activate {
                    at: VirtualTime { ticks: 11 },
                    tag: tag("split"),
                    fault: MembershipFault::Partition {
                        endpoint_a: node_id("b"),
                        endpoint_b: node_id("c"),
                        direction: PartitionDirection::EndpointAToEndpointB,
                    },
                },
                PlanEntry::Activate {
                    at: VirtualTime { ticks: 20 },
                    tag: tag("crash-c"),
                    fault: MembershipFault::Crash {
                        node: node_id("c"),
                        restart: RestartPolicy::FromReadyPoint,
                    },
                },
                PlanEntry::Heal {
                    at: VirtualTime { ticks: 40 },
                    tag: tag("split"),
                },
            ],
        )
        .unwrap_or_else(|error| panic!("changed-time plan should be valid: {error}"));
        let changed_tag_plan = Plan::from_entries_for_world(
            &canonical_world,
            vec![
                PlanEntry::Activate {
                    at: VirtualTime { ticks: 10 },
                    tag: tag("split-alt"),
                    fault: MembershipFault::Partition {
                        endpoint_a: node_id("b"),
                        endpoint_b: node_id("c"),
                        direction: PartitionDirection::EndpointAToEndpointB,
                    },
                },
                PlanEntry::Activate {
                    at: VirtualTime { ticks: 20 },
                    tag: tag("crash-c"),
                    fault: MembershipFault::Crash {
                        node: node_id("c"),
                        restart: RestartPolicy::FromReadyPoint,
                    },
                },
                PlanEntry::Heal {
                    at: VirtualTime { ticks: 40 },
                    tag: tag("split-alt"),
                },
            ],
        )
        .unwrap_or_else(|error| panic!("changed-tag plan should be valid: {error}"));
        let changed_fault_plan = Plan::from_entries_for_world(
            &canonical_world,
            vec![
                PlanEntry::Activate {
                    at: VirtualTime { ticks: 10 },
                    tag: tag("split"),
                    fault: MembershipFault::Partition {
                        endpoint_a: node_id("b"),
                        endpoint_b: node_id("c"),
                        direction: PartitionDirection::Bidirectional,
                    },
                },
                PlanEntry::Activate {
                    at: VirtualTime { ticks: 20 },
                    tag: tag("crash-c"),
                    fault: MembershipFault::Crash {
                        node: node_id("c"),
                        restart: RestartPolicy::FromReadyPoint,
                    },
                },
                PlanEntry::Heal {
                    at: VirtualTime { ticks: 40 },
                    tag: tag("split"),
                },
            ],
        )
        .unwrap_or_else(|error| panic!("changed-fault plan should be valid: {error}"));
        let authored_properties = Properties::from_assertions_for_world(
            &authored_world,
            vec![
                assertion(
                    "settles",
                    "replicas settle",
                    Property::AfterQuiescence {
                        predicate: named_predicate("replicas_equal", &["b", "c"]),
                    },
                ),
                assertion(
                    "alive",
                    "nodes remain alive",
                    Property::Always {
                        predicate: Predicate::AllOf {
                            predicates: vec![
                                named_predicate("node_alive", &["c"]),
                                named_predicate("node_alive", &["a"]),
                            ],
                        },
                    },
                ),
            ],
        )
        .unwrap_or_else(|error| panic!("authored properties should be valid: {error}"));
        let canonical_properties = Properties::from_assertions_for_world(
            &canonical_world,
            vec![
                assertion(
                    "alive",
                    "nodes remain alive",
                    Property::Always {
                        predicate: Predicate::AllOf {
                            predicates: vec![
                                named_predicate("node_alive", &["a"]),
                                named_predicate("node_alive", &["c"]),
                            ],
                        },
                    },
                ),
                assertion(
                    "settles",
                    "replicas settle",
                    Property::AfterQuiescence {
                        predicate: named_predicate("replicas_equal", &["b", "c"]),
                    },
                ),
            ],
        )
        .unwrap_or_else(|error| panic!("canonical properties should be valid: {error}"));
        let changed_message_properties = Properties::from_assertions_for_world(
            &canonical_world,
            vec![
                assertion(
                    "alive",
                    "nodes stay alive",
                    Property::Always {
                        predicate: Predicate::AllOf {
                            predicates: vec![
                                named_predicate("node_alive", &["a"]),
                                named_predicate("node_alive", &["c"]),
                            ],
                        },
                    },
                ),
                assertion(
                    "settles",
                    "replicas settle",
                    Property::AfterQuiescence {
                        predicate: named_predicate("replicas_equal", &["b", "c"]),
                    },
                ),
            ],
        )
        .unwrap_or_else(|error| panic!("changed-message properties should be valid: {error}"));
        let changed_predicate_properties = Properties::from_assertions_for_world(
            &canonical_world,
            vec![
                assertion(
                    "alive",
                    "nodes remain alive",
                    Property::Always {
                        predicate: named_predicate("node_alive", &["a"]),
                    },
                ),
                assertion(
                    "settles",
                    "replicas settle",
                    Property::AfterQuiescence {
                        predicate: named_predicate("replicas_equal", &["b", "c"]),
                    },
                ),
            ],
        )
        .unwrap_or_else(|error| panic!("changed-predicate properties should be valid: {error}"));
        let seed = Seed::from_u64(0x0010_0019);
        let authored_form = ScenarioDefForm::from_components(
            &authored_world,
            &authored_plan,
            &authored_properties,
            seed,
        )
        .unwrap_or_else(|error| panic!("authored form should be valid: {error}"));
        let canonical_form = ScenarioDefForm::from_components(
            &canonical_world,
            &canonical_plan,
            &canonical_properties,
            seed,
        )
        .unwrap_or_else(|error| panic!("canonical form should be valid: {error}"));
        let other_seed_form = ScenarioDefForm::from_components(
            &canonical_world,
            &canonical_plan,
            &canonical_properties,
            Seed::from_u64(0x0010_0020),
        )
        .unwrap_or_else(|error| panic!("other-seed form should be valid: {error}"));
        let loss = LinkLossProbability::from_millionths(125_000)
            .unwrap_or_else(|error| panic!("fixed loss should be valid: {error}"));
        let density = FaultDensity::from_millionths(125_000)
            .unwrap_or_else(|error| panic!("fixed density should be valid: {error}"));
        let density_family = ScenarioFamily::new(
            FamilySpace::new(
                SeedSpace::explicit(vec![seed])
                    .unwrap_or_else(|error| panic!("density seed space should be valid: {error}")),
                FaultDensityRange::new(FaultDensity::ZERO, density)
                    .unwrap_or_else(|error| panic!("density range should be valid: {error}")),
                TopologySizeRange::new(4, 4).unwrap_or_else(|error| {
                    panic!("density topology range should be valid: {error}")
                }),
                vec![TopologyShape::Ring],
            )
            .unwrap_or_else(|error| panic!("density family space should be valid: {error}")),
            NodeTemplate::fixed_icount(Icount { retired: 8 }),
        );
        let zero_density_instance = density_family
            .instantiate(FamilyParams {
                seed,
                fault_density: FaultDensity::ZERO,
                topology_size: 4,
                topology_shape: TopologyShape::Ring,
            })
            .unwrap_or_else(|error| panic!("zero-density family should instantiate: {error}"));
        let fixed_density_instance = density_family
            .instantiate(FamilyParams {
                seed,
                fault_density: density,
                topology_size: 4,
                topology_shape: TopologyShape::Ring,
            })
            .unwrap_or_else(|error| panic!("fixed-density family should instantiate: {error}"));

        assert_eq!(loss.millionths(), 125_000);
        assert_eq!(density.millionths(), 125_000);
        assert_eq!(
            authored_world.id().to_hex(),
            "2f107a46c69f789cd0fa04ed4bca6e7c1d780594789e2167a80bf0dfe3bc21c3"
        );
        assert_eq!(
            ContentHash::from_bytes(&authored_world.canonical_bytes()).to_hex(),
            "ccd11b842c868487bd1417fba149d40afe0fb75e012217552da9999a2d081c00"
        );
        assert_eq!(
            ContentHash::from_bytes(&authored_world.to_compact_binary()).to_hex(),
            "d6b383bba7293f4ed649f2f2cded1d57a6117077fdbaeb29a3f9b989a5533c3b"
        );
        assert_eq!(
            authored_plan.content_hash().to_hex(),
            "f9e1e5c40ecbfce8d62e71476b59f2f207e6457ae947647c1e44ab1ad86f2e3a"
        );
        assert_eq!(
            ContentHash::from_bytes(&authored_plan.canonical_bytes()).to_hex(),
            "a8c0faf32016e717da4e1cf3e8ac99ce59ca80262a363fbf23b714aa5e604579"
        );
        assert_eq!(
            ContentHash::from_bytes(&authored_plan.to_compact_binary()).to_hex(),
            "28392e5c96b6e782ade455ceb679c1511d584a41a7b273afdd04a442480ae346"
        );
        assert_eq!(
            authored_properties.content_hash().to_hex(),
            "b20bc725db83e5943ed694b56a51b3b5d099734c9185a466ac6135f1b9ceff13"
        );
        assert_eq!(
            ContentHash::from_bytes(&authored_properties.canonical_bytes()).to_hex(),
            "9bc626347b695dea6dc28e300f95a2b7770af8717b681c02185d2bf3fcef6306"
        );
        assert_eq!(
            ContentHash::from_bytes(&authored_properties.to_compact_binary()).to_hex(),
            "068432cc28bbd3c94320ad87fda5794710c5fecc065ba81a003c2f6c98766e2a"
        );
        assert_eq!(
            authored_form.id().to_hex(),
            "e13a8e94a43857719319c913ba7036109d033e47263411799a8baee73a50ea94"
        );
        assert_eq!(
            ContentHash::from_bytes(&authored_form.canonical_bytes()).to_hex(),
            "d74fc071677d443ee8263436ab9279169085b3e1e121815b902b53339b0f4bb0"
        );
        assert_eq!(
            ContentHash::from_bytes(&authored_form.to_compact_binary()).to_hex(),
            "455912b3f3ad4878d8d40af3b41b75179d3ad06b7038081d2ed8993b42fa2a44"
        );
        assert_eq!(authored_world.id(), canonical_world.id());
        assert_eq!(authored_world.nodes(), canonical_world.nodes());
        assert_eq!(authored_world.links(), canonical_world.links());
        assert!(
            authored_world
                .to_compact_binary()
                .starts_with(b"crucible.world.v1\0")
        );
        assert!(
            authored_plan
                .to_compact_binary()
                .starts_with(b"crucible.plan.v1\0")
        );
        assert!(
            authored_properties
                .to_compact_binary()
                .starts_with(b"crucible.properties.v1\0")
        );
        assert!(
            authored_form
                .to_compact_binary()
                .starts_with(b"crucible.scenario-def-form.v1\0")
        );
        assert_eq!(
            authored_world.canonical_bytes(),
            canonical_world.canonical_bytes()
        );
        assert_eq!(
            authored_world.to_compact_binary(),
            canonical_world.to_compact_binary()
        );
        assert_eq!(
            authored_world
                .to_canonical_toml()
                .unwrap_or_else(|error| panic!("world TOML should serialize: {error}")),
            canonical_world
                .to_canonical_toml()
                .unwrap_or_else(|error| panic!("canonical world TOML should serialize: {error}"))
        );
        assert_ne!(authored_world.id(), changed_loss_world.id());
        assert_ne!(authored_world.id(), changed_ref_world.id());
        assert_ne!(authored_world.id(), changed_icount_world.id());
        assert_ne!(authored_world.id(), changed_duration_world.id());
        assert_ne!(authored_world.id(), changed_bandwidth_world.id());
        assert_eq!(authored_plan.content_hash(), canonical_plan.content_hash());
        assert_eq!(authored_plan.entries(), canonical_plan.entries());
        assert_eq!(
            authored_plan.canonical_bytes(),
            canonical_plan.canonical_bytes()
        );
        assert_eq!(
            authored_plan.to_compact_binary(),
            canonical_plan.to_compact_binary()
        );
        assert_eq!(
            authored_plan
                .to_canonical_toml()
                .unwrap_or_else(|error| panic!("plan TOML should serialize: {error}")),
            canonical_plan
                .to_canonical_toml()
                .unwrap_or_else(|error| panic!("canonical plan TOML should serialize: {error}"))
        );
        assert_ne!(
            authored_plan.content_hash(),
            changed_time_plan.content_hash()
        );
        assert_ne!(
            authored_plan.content_hash(),
            changed_tag_plan.content_hash()
        );
        assert_ne!(
            authored_plan.content_hash(),
            changed_fault_plan.content_hash()
        );
        assert_eq!(
            authored_properties.content_hash(),
            canonical_properties.content_hash()
        );
        assert_eq!(
            authored_properties.assertions(),
            canonical_properties.assertions()
        );
        assert_eq!(
            authored_properties.canonical_bytes(),
            canonical_properties.canonical_bytes()
        );
        assert_eq!(
            authored_properties.to_compact_binary(),
            canonical_properties.to_compact_binary()
        );
        assert_eq!(
            authored_properties
                .to_canonical_toml()
                .unwrap_or_else(|error| panic!("properties TOML should serialize: {error}")),
            canonical_properties
                .to_canonical_toml()
                .unwrap_or_else(|error| {
                    panic!("canonical properties TOML should serialize: {error}")
                })
        );
        assert_ne!(
            authored_properties.content_hash(),
            changed_message_properties.content_hash()
        );
        assert_ne!(
            authored_properties.content_hash(),
            changed_predicate_properties.content_hash()
        );
        assert_eq!(authored_form.id(), canonical_form.id());
        assert_eq!(authored_form.scenario_def(), canonical_form.scenario_def());
        assert_eq!(
            authored_form.canonical_bytes(),
            canonical_form.canonical_bytes()
        );
        assert_eq!(
            authored_form.to_compact_binary(),
            canonical_form.to_compact_binary()
        );
        assert_eq!(
            authored_form
                .to_canonical_toml()
                .unwrap_or_else(|error| panic!("scenario TOML should serialize: {error}")),
            canonical_form.to_canonical_toml().unwrap_or_else(|error| {
                panic!("canonical scenario TOML should serialize: {error}")
            })
        );
        assert_ne!(authored_form.id(), other_seed_form.id());
        assert_eq!(
            zero_density_instance.form().world(),
            fixed_density_instance.form().world()
        );
        assert_ne!(
            zero_density_instance.form().plan().content_hash(),
            fixed_density_instance.form().plan().content_hash()
        );
        assert_ne!(zero_density_instance.id(), fixed_density_instance.id());
    }

    #[test]
    fn seed_is_scenario_identity_and_name_hashed_stream_root() {
        let world = world_from_nodes_and_links(
            two_ready_nodes(),
            vec![transport_link("a", "b", 10, 1, 0, None)],
        );
        let expanded_world = world_from_nodes_and_links(
            vec![
                ready_node(
                    "a",
                    ReadyPoint::FixedIcount {
                        icount: Icount { retired: 1 },
                    },
                ),
                ready_node(
                    "b",
                    ReadyPoint::FixedIcount {
                        icount: Icount { retired: 2 },
                    },
                ),
                ready_node(
                    "c",
                    ReadyPoint::FixedIcount {
                        icount: Icount { retired: 3 },
                    },
                ),
            ],
            vec![transport_link("a", "b", 10, 1, 0, None)],
        );
        let seed = Seed::from_u64(42);
        let other_seed = Seed::from_u64(43);
        let mut tail_changed_bytes = seed.bytes();
        tail_changed_bytes[31] = 1;
        let tail_changed_seed = Seed::from_bytes(tail_changed_bytes);
        let empty_plan = Plan::empty();
        let empty_properties = Properties::empty();
        let node_stream = RngStreamId::for_node("a");
        let link_stream = RngStreamId::for_link("a");
        let generic_seeded = ScenarioDef::from_canonical_material_with_seed(
            "crucible.test.seeded-scenario",
            "world=opaque",
            seed,
        );
        let generic_other_seed = ScenarioDef::from_canonical_material_with_seed(
            "crucible.test.seeded-scenario",
            "world=opaque",
            other_seed,
        );
        let world_streams = seeded_stream_map(world.seeded_rng_streams(seed));
        let expanded_streams = seeded_stream_map(expanded_world.seeded_rng_streams(seed));
        let mut world_node_draws = seed.fork_stream(&node_stream);
        let mut expanded_node_draws = seed.fork_stream(&node_stream);
        let mut seeded_recorder =
            DecisionRecorder::new(Configuration::genesis(world.scenario_def_with_seed(seed)));
        let mut expected_recorder_stream = seed.fork_stream(&node_stream);

        assert_eq!(
            world.scenario_def(),
            world.scenario_def_with_seed(Seed::default())
        );
        assert_eq!(
            world
                .scenario_def_with_plan_and_properties(&empty_plan, &empty_properties)
                .unwrap_or_else(|error| panic!(
                    "default-seed empty components should compose: {error}"
                )),
            world
                .scenario_def_with_plan_properties_and_seed(
                    &empty_plan,
                    &empty_properties,
                    Seed::default(),
                )
                .unwrap_or_else(|error| panic!("explicit default seed should compose: {error}"))
        );
        assert_ne!(world.scenario_def(), world.scenario_def_with_seed(seed));
        assert_ne!(
            world.scenario_def_with_seed(seed),
            world.scenario_def_with_seed(other_seed)
        );
        assert_ne!(generic_seeded.id(), generic_other_seed.id());
        assert_ne!(generic_seeded.seed(), generic_other_seed.seed());
        assert_ne!(
            Configuration::genesis(generic_seeded.clone()).id(),
            Configuration::genesis(generic_other_seed.clone()).id()
        );
        assert_ne!(
            reduce(&generic_seeded, &Schedule::empty())
                .unwrap_or_else(|error| panic!("seeded reduce should succeed: {error}"))
                .id,
            reduce(&generic_other_seed, &Schedule::empty())
                .unwrap_or_else(|error| panic!("other seeded reduce should succeed: {error}"))
                .id
        );
        assert_ne!(
            seed.stream_seed(&node_stream),
            other_seed.stream_seed(&node_stream)
        );
        assert_ne!(
            seed.stream_seed(&node_stream),
            tail_changed_seed.stream_seed(&node_stream)
        );
        for index in 0..32 {
            let mut bytes = seed.bytes();
            bytes[index] ^= 0x80;
            let changed_seed = Seed::from_bytes(bytes);
            assert_ne!(
                seed.stream_seed(&node_stream),
                changed_seed.stream_seed(&node_stream),
                "byte {index} should contribute to stream derivation"
            );
        }
        assert_ne!(
            seed.stream_seed(&node_stream),
            seed.stream_seed(&link_stream)
        );
        assert_eq!(
            seed.stream_seed(&node_stream),
            seed.fork_stream(&node_stream).seed()
        );
        assert_eq!(world_node_draws.next_u64(), expanded_node_draws.next_u64());
        assert_eq!(
            seeded_recorder.draw_u64(node_stream.clone()),
            expected_recorder_stream.next_u64()
        );

        for stream in world.static_topology().rng_streams {
            assert_eq!(
                world_streams.get(&stream),
                expanded_streams.get(&stream),
                "stream seed should be stable for existing stream {stream:?}"
            );
        }
        assert!(expanded_streams.contains_key(&RngStreamId::for_node("c")));
    }

    #[cfg(feature = "test-double")]
    #[test]
    fn world_logical_topology_ignores_physical_transport_layout() {
        let compact_layout = shmem_layout(2, 16, 3);
        let expanded_layout = shmem_layout(2, 64, 3);
        let world = world_from_nodes_and_links(
            two_ready_nodes(),
            vec![transport_link("a", "b", 5, 1, 0, None)],
        );
        let compact_world = world_with_physical_layout_id(&world, compact_layout, 4096);
        let expanded_world = world_with_physical_layout_id(&world, expanded_layout, 65_536);
        let compact_baked = match bake(&compact_world) {
            Ok(genesis) => genesis,
            Err(error) => panic!("compact-layout world should bake: {error}"),
        };
        let expanded_baked = match bake(&expanded_world) {
            Ok(genesis) => genesis,
            Err(error) => panic!("expanded-layout world should bake: {error}"),
        };

        assert_ne!(compact_layout, expanded_layout);
        assert_ne!(
            compact_layout.queue_capacity,
            expanded_layout.queue_capacity
        );
        assert_ne!(compact_layout.region_size, expanded_layout.region_size);
        assert_ne!(compact_world.id, expanded_world.id);
        assert_eq!(compact_world.nodes(), expanded_world.nodes());
        assert_eq!(compact_world.links(), expanded_world.links());
        assert_eq!(
            compact_world.static_topology(),
            expanded_world.static_topology()
        );
        assert_eq!(compact_world.scenario_def(), expanded_world.scenario_def());
        assert_eq!(compact_baked.checkpoint.id, expanded_baked.checkpoint.id);
    }

    #[test]
    fn world_ready_point_rejects_agent_signal_without_white_box_opt_in() {
        let invalid = World::from_nodes(vec![WorldNode {
            id: node_id("agent"),
            arch: NodeTemplate::DEFAULT_ARCH,
            memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
            cmdline: String::new(),
            ready_point: ReadyPoint::AgentSignal,
            white_box: WhiteBoxPolicy::Disabled,
            smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
            icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
            kernel: None,
            root_image: None,
            initrd: None,
        }]);
        let duplicate = World::from_nodes(vec![
            ready_node(
                "dup",
                ReadyPoint::FixedIcount {
                    icount: Icount { retired: 1 },
                },
            ),
            ready_node(
                "dup",
                ReadyPoint::NetworkIdle {
                    window: SimDuration { nanos: 10 },
                },
            ),
        ]);
        let valid = World::from_nodes(vec![WorldNode {
            id: node_id("agent"),
            arch: NodeTemplate::DEFAULT_ARCH,
            memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
            cmdline: String::new(),
            ready_point: ReadyPoint::AgentSignal,
            white_box: WhiteBoxPolicy::Enabled,
            smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
            icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
            kernel: None,
            root_image: None,
            initrd: None,
        }]);

        assert!(matches!(
            invalid,
            Err(EngineError::WhiteBoxReadyPointWithoutOptIn { .. })
        ));
        assert!(matches!(
            duplicate,
            Err(EngineError::DuplicateWorldNodeId { .. })
        ));
        assert!(valid.is_ok());
    }

    #[test]
    fn bake_is_content_identical_for_each_ready_point_policy() {
        let policies = vec![
            (
                ReadyPoint::FixedIcount {
                    icount: Icount { retired: 10 },
                },
                WhiteBoxPolicy::Disabled,
            ),
            (
                ReadyPoint::NetworkIdle {
                    window: SimDuration { nanos: 250 },
                },
                WhiteBoxPolicy::Disabled,
            ),
            (
                ReadyPoint::ConsoleMarker {
                    marker: String::from("ready"),
                },
                WhiteBoxPolicy::Disabled,
            ),
            (ReadyPoint::AgentSignal, WhiteBoxPolicy::Enabled),
        ];

        for (index, (ready_point, white_box)) in policies.into_iter().enumerate() {
            let node_name = format!("node-{index}");
            let node = WorldNode {
                id: node_id(&node_name),
                arch: NodeTemplate::DEFAULT_ARCH,
                memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
                cmdline: String::new(),
                ready_point,
                white_box,
                smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
                icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
                kernel: None,
                root_image: None,
                initrd: None,
            };
            let world = if matches!(&node.ready_point, ReadyPoint::NetworkIdle { .. }) {
                let peer_name = format!("peer-{index}");
                world_from_nodes_and_links(
                    vec![
                        node,
                        ready_node(
                            &peer_name,
                            ReadyPoint::FixedIcount {
                                icount: Icount { retired: 1 },
                            },
                        ),
                    ],
                    vec![link(&node_name, &peer_name)],
                )
            } else {
                world_from_nodes(vec![node])
            };
            let first = match bake(&world) {
                Ok(genesis) => genesis,
                Err(error) => panic!("ready-point policy should bake: {error}"),
            };
            let second = match bake(&world) {
                Ok(genesis) => genesis,
                Err(error) => panic!("ready-point policy should bake again: {error}"),
            };

            assert_eq!(first, second);
            assert_eq!(first.checkpoint.kind, CheckpointKind::Fat);
            assert_eq!(
                first.checkpoint.configuration,
                Configuration::genesis(world.scenario_def()).id()
            );
        }
    }

    #[test]
    fn ready_point_policy_material_affects_baked_genesis() {
        let cases = vec![
            (
                "fixed-icount target",
                WorldNode {
                    id: node_id("node"),
                    arch: NodeTemplate::DEFAULT_ARCH,
                    memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
                    cmdline: String::new(),
                    ready_point: ReadyPoint::FixedIcount {
                        icount: Icount { retired: 10 },
                    },
                    white_box: WhiteBoxPolicy::Disabled,
                    smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
                    icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
                    kernel: None,
                    root_image: None,
                    initrd: None,
                },
                WorldNode {
                    id: node_id("node"),
                    arch: NodeTemplate::DEFAULT_ARCH,
                    memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
                    cmdline: String::new(),
                    ready_point: ReadyPoint::FixedIcount {
                        icount: Icount { retired: 11 },
                    },
                    white_box: WhiteBoxPolicy::Disabled,
                    smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
                    icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
                    kernel: None,
                    root_image: None,
                    initrd: None,
                },
            ),
            (
                "network-idle window",
                WorldNode {
                    id: node_id("node"),
                    arch: NodeTemplate::DEFAULT_ARCH,
                    memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
                    cmdline: String::new(),
                    ready_point: ReadyPoint::NetworkIdle {
                        window: SimDuration { nanos: 250 },
                    },
                    white_box: WhiteBoxPolicy::Disabled,
                    smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
                    icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
                    kernel: None,
                    root_image: None,
                    initrd: None,
                },
                WorldNode {
                    id: node_id("node"),
                    arch: NodeTemplate::DEFAULT_ARCH,
                    memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
                    cmdline: String::new(),
                    ready_point: ReadyPoint::NetworkIdle {
                        window: SimDuration { nanos: 251 },
                    },
                    white_box: WhiteBoxPolicy::Disabled,
                    smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
                    icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
                    kernel: None,
                    root_image: None,
                    initrd: None,
                },
            ),
            (
                "console marker",
                WorldNode {
                    id: node_id("node"),
                    arch: NodeTemplate::DEFAULT_ARCH,
                    memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
                    cmdline: String::new(),
                    ready_point: ReadyPoint::ConsoleMarker {
                        marker: String::from("ready"),
                    },
                    white_box: WhiteBoxPolicy::Disabled,
                    smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
                    icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
                    kernel: None,
                    root_image: None,
                    initrd: None,
                },
                WorldNode {
                    id: node_id("node"),
                    arch: NodeTemplate::DEFAULT_ARCH,
                    memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
                    cmdline: String::new(),
                    ready_point: ReadyPoint::ConsoleMarker {
                        marker: String::from("ready-v2"),
                    },
                    white_box: WhiteBoxPolicy::Disabled,
                    smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
                    icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
                    kernel: None,
                    root_image: None,
                    initrd: None,
                },
            ),
            (
                "agent-signal variant",
                WorldNode {
                    id: node_id("node"),
                    arch: NodeTemplate::DEFAULT_ARCH,
                    memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
                    cmdline: String::new(),
                    ready_point: ReadyPoint::AgentSignal,
                    white_box: WhiteBoxPolicy::Enabled,
                    smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
                    icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
                    kernel: None,
                    root_image: None,
                    initrd: None,
                },
                WorldNode {
                    id: node_id("node"),
                    arch: NodeTemplate::DEFAULT_ARCH,
                    memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
                    cmdline: String::new(),
                    ready_point: ReadyPoint::ConsoleMarker {
                        marker: String::from("agent-ready"),
                    },
                    white_box: WhiteBoxPolicy::Enabled,
                    smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
                    icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
                    kernel: None,
                    root_image: None,
                    initrd: None,
                },
            ),
            (
                "white-box policy",
                WorldNode {
                    id: node_id("node"),
                    arch: NodeTemplate::DEFAULT_ARCH,
                    memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
                    cmdline: String::new(),
                    ready_point: ReadyPoint::FixedIcount {
                        icount: Icount { retired: 10 },
                    },
                    white_box: WhiteBoxPolicy::Disabled,
                    smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
                    icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
                    kernel: None,
                    root_image: None,
                    initrd: None,
                },
                WorldNode {
                    id: node_id("node"),
                    arch: NodeTemplate::DEFAULT_ARCH,
                    memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
                    cmdline: String::new(),
                    ready_point: ReadyPoint::FixedIcount {
                        icount: Icount { retired: 10 },
                    },
                    white_box: WhiteBoxPolicy::Enabled,
                    smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
                    icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
                    kernel: None,
                    root_image: None,
                    initrd: None,
                },
            ),
        ];

        for (label, base_node, changed_node) in cases {
            let uses_network_idle =
                matches!(&base_node.ready_point, ReadyPoint::NetworkIdle { .. })
                    || matches!(&changed_node.ready_point, ReadyPoint::NetworkIdle { .. });
            let base = if uses_network_idle {
                world_from_nodes_and_links(
                    vec![
                        base_node,
                        ready_node(
                            "peer",
                            ReadyPoint::FixedIcount {
                                icount: Icount { retired: 1 },
                            },
                        ),
                    ],
                    vec![link("node", "peer")],
                )
            } else {
                world_from_nodes(vec![base_node])
            };
            let changed = if uses_network_idle {
                world_from_nodes_and_links(
                    vec![
                        changed_node,
                        ready_node(
                            "peer",
                            ReadyPoint::FixedIcount {
                                icount: Icount { retired: 1 },
                            },
                        ),
                    ],
                    vec![link("node", "peer")],
                )
            } else {
                world_from_nodes(vec![changed_node])
            };
            let base_baked = match bake(&base) {
                Ok(genesis) => genesis,
                Err(error) => panic!("{label} base world should bake: {error}"),
            };
            let changed_baked = match bake(&changed) {
                Ok(genesis) => genesis,
                Err(error) => panic!("{label} changed world should bake: {error}"),
            };

            assert_ne!(base.id, changed.id, "{label}");
            assert_ne!(
                base_baked.checkpoint.id, changed_baked.checkpoint.id,
                "{label}"
            );
        }
    }

    #[test]
    fn baked_genesis_records_node_blob_refs_uniformly() {
        let node = ready_node(
            "node",
            ReadyPoint::FixedIcount {
                icount: Icount { retired: 64 },
            },
        );
        let world = world_from_nodes(vec![node.clone()]);
        let baked = match bake(&world) {
            Ok(genesis) => genesis,
            Err(error) => panic!("world with ready-point node should bake: {error}"),
        };
        let Some(blob) = baked.checkpoint.node_blob(&node.id) else {
            panic!("baked genesis should carry a blob ref for the node");
        };

        assert_eq!(baked.checkpoint.node_blobs.len(), 1);
        assert!(matches!(blob, NodeBlobRef::Baked(_)));
        assert_eq!(
            Some(blob),
            baked.checkpoint.node_blobs.get(&node_id("node"))
        );
    }

    #[test]
    fn node_blob_refs_are_uniform_for_baked_and_cow_delta_state() {
        let node = node_id("node");
        let baked_blob = ContentHash::from_canonical_material("crucible.test.node-blob", "baked");
        let delta = ContentHash::from_canonical_material("crucible.test.node-blob", "delta");
        let resolved = ContentHash::from_canonical_material("crucible.test.node-blob", "resolved");
        let cow_blob = NodeBlobRef::cow_delta(baked_blob, delta, resolved);
        let materialized_blob = NodeBlobRef::baked(resolved);
        let genesis = Configuration::genesis(generated_scenario(71));
        let descendant = Configuration {
            def: genesis.def.clone(),
            schedule: generated_schedule(71, 1),
        };
        let genesis_checkpoint = Checkpoint::with_node_blobs(
            ContentHash::from_canonical_material("crucible.test.checkpoint", "genesis"),
            genesis.id(),
            CheckpointKind::Fat,
            std::collections::BTreeMap::from([(node.clone(), NodeBlobRef::baked(baked_blob))]),
        );
        let descendant_checkpoint = Checkpoint::with_node_blobs(
            ContentHash::from_canonical_material("crucible.test.checkpoint", "descendant"),
            descendant.id(),
            CheckpointKind::Fat,
            std::collections::BTreeMap::from([(node.clone(), cow_blob.clone())]),
        );

        assert!(matches!(
            genesis_checkpoint.node_blob(&node),
            Some(NodeBlobRef::Baked(_))
        ));
        assert!(matches!(
            descendant_checkpoint.node_blob(&node),
            Some(NodeBlobRef::CowDelta { resolved: hash, .. }) if *hash == resolved
        ));
        assert_eq!(
            descendant_checkpoint
                .node_blob(&node)
                .map(NodeBlobRef::content_hash),
            Some(materialized_blob.content_hash())
        );
    }

    #[test]
    fn instantiate_requires_baked_genesis_when_no_cached_path() {
        let scenario = generated_scenario(59);
        let config = Configuration {
            def: scenario,
            schedule: generated_schedule(59, 2),
        };

        let error = match instantiate(&TemporalGraph::empty(), &config) {
            Ok(_) => panic!("uncached path without baked genesis should fail"),
            Err(error) => error,
        };

        assert!(matches!(error, EngineError::MissingBakedGenesis { .. }));
        assert_eq!(
            error.to_string(),
            "missing baked genesis checkpoint for scenario"
        );
    }

    #[test]
    fn temporal_graph_rejects_mismatched_or_thin_cached_snapshots() {
        let scenario = generated_scenario(61);
        let config = Configuration {
            def: scenario.clone(),
            schedule: generated_schedule(61, 2),
        };
        let other = Configuration::genesis(scenario);
        let mismatched = Checkpoint::new(config.id(), other.id(), CheckpointKind::Fat);
        let thin = Checkpoint::new(config.id(), config.id(), CheckpointKind::Thin);
        let valid = fat_checkpoint_for(&config);
        let mut wrong_scenario = valid.clone();
        wrong_scenario.scenario_ref = generated_scenario(62).id();
        let mut wrong_parent = valid.clone();
        wrong_parent.parent = None;
        let mut wrong_delta = valid.clone();
        wrong_delta.schedule_delta = Schedule::empty();

        let mismatch_error = match TemporalGraph::empty().with_cached_snapshot(&config, mismatched)
        {
            Ok(_) => panic!("mismatched snapshot should be rejected"),
            Err(error) => error,
        };
        let thin_error = match TemporalGraph::empty().with_cached_snapshot(&config, thin) {
            Ok(_) => panic!("thin snapshot should be rejected"),
            Err(error) => error,
        };
        let scenario_error =
            match TemporalGraph::empty().with_cached_snapshot(&config, wrong_scenario) {
                Ok(_) => panic!("scenario-ref mismatch should be rejected"),
                Err(error) => error,
            };
        let parent_error = match TemporalGraph::empty().with_cached_snapshot(&config, wrong_parent)
        {
            Ok(_) => panic!("parent mismatch should be rejected"),
            Err(error) => error,
        };
        let delta_error = match TemporalGraph::empty().with_cached_snapshot(&config, wrong_delta) {
            Ok(_) => panic!("schedule-delta mismatch should be rejected"),
            Err(error) => error,
        };

        assert!(matches!(
            mismatch_error,
            EngineError::CheckpointConfigurationMismatch { .. }
        ));
        assert!(matches!(
            thin_error,
            EngineError::CheckpointNotLoadable {
                kind: CheckpointKind::Thin,
                ..
            }
        ));
        assert!(matches!(
            scenario_error,
            EngineError::CheckpointTopologyMismatch {
                reason: "scenario-ref-mismatch",
                ..
            }
        ));
        assert!(matches!(
            parent_error,
            EngineError::CheckpointTopologyMismatch {
                reason: "parent-mismatch",
                ..
            }
        ));
        assert!(matches!(
            delta_error,
            EngineError::CheckpointTopologyMismatch {
                reason: "schedule-delta-mismatch",
                ..
            }
        ));
    }

    #[test]
    fn temporal_graph_rejects_plain_cached_genesis_snapshot() {
        let scenario = generated_scenario(63);
        let genesis = Configuration::genesis(scenario);

        let error = match TemporalGraph::empty()
            .with_cached_snapshot(&genesis, fat_checkpoint_for(&genesis))
        {
            Ok(_) => panic!("genesis snapshot should be registered through baked genesis"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            EngineError::GenesisSnapshotMustBeBaked { .. }
        ));
        assert_eq!(
            error.to_string(),
            "genesis snapshots must be registered as baked genesis checkpoints"
        );
    }

    #[test]
    fn temporal_graph_rejects_mismatched_or_thin_baked_genesis() {
        let scenario = generated_scenario(67);
        let genesis = Configuration::genesis(scenario.clone());
        let descendant = Configuration {
            def: scenario.clone(),
            schedule: generated_schedule(67, 1),
        };
        let mismatched = GenesisCheckpoint {
            checkpoint: fat_checkpoint_for(&descendant),
        };
        let thin = GenesisCheckpoint {
            checkpoint: Checkpoint::new(genesis.id(), genesis.id(), CheckpointKind::Thin),
        };

        let mismatch_error = match TemporalGraph::empty().with_baked_genesis(&scenario, mismatched)
        {
            Ok(_) => panic!("mismatched baked genesis should be rejected"),
            Err(error) => error,
        };
        let thin_error = match TemporalGraph::empty().with_baked_genesis(&scenario, thin) {
            Ok(_) => panic!("thin baked genesis should be rejected"),
            Err(error) => error,
        };

        assert!(matches!(
            mismatch_error,
            EngineError::CheckpointConfigurationMismatch { .. }
        ));
        assert!(matches!(
            thin_error,
            EngineError::CheckpointNotLoadable {
                kind: CheckpointKind::Thin,
                ..
            }
        ));
    }

    #[test]
    fn backend_trait_is_object_safe() {
        struct StubBackend;

        impl Backend for StubBackend {
            fn advance_to_horizon(
                &mut self,
                _horizon: ExecutionHorizon,
            ) -> Result<AdvanceOutcome, BackendError> {
                Ok(AdvanceOutcome::ReachedHorizon)
            }

            fn fingerprint(&mut self) -> Result<ExecutionFingerprint, BackendError> {
                Ok(ExecutionFingerprint {
                    hash: ContentHash::default(),
                })
            }

            fn deliver_input(&mut self, _input: BackendInput) -> Result<(), BackendError> {
                Ok(())
            }

            fn snapshot(&mut self) -> Result<Checkpoint, BackendError> {
                Ok(Checkpoint::new(
                    ContentHash::default(),
                    ContentHash::default(),
                    CheckpointKind::Fat,
                ))
            }

            fn restore(&mut self, _checkpoint: &Checkpoint) -> Result<(), BackendError> {
                Ok(())
            }

            fn shutdown(&mut self) -> Result<(), BackendError> {
                Ok(())
            }
        }

        let mut backend = StubBackend;
        let object: &mut dyn Backend = &mut backend;
        let advanced = object.advance_to_horizon(ExecutionHorizon {
            icount: Icount { retired: 10 },
        });

        assert_eq!(advanced, Ok(AdvanceOutcome::ReachedHorizon));
    }

    #[test]
    fn engine_and_backend_errors_render_all_variants_deterministically() {
        let engine = EngineError::NotImplemented {
            operation: "instantiate",
        };
        let checkpoint_not_loadable = EngineError::CheckpointNotLoadable {
            checkpoint: ContentHash::default(),
            kind: CheckpointKind::Thin,
        };
        let checkpoint_mismatch = EngineError::CheckpointConfigurationMismatch {
            checkpoint: ContentHash::default(),
            expected: ContentHash::default(),
            actual: ContentHash::default(),
        };
        let missing_genesis = EngineError::MissingBakedGenesis {
            scenario: ContentHash::default(),
        };
        let genesis_must_be_baked = EngineError::GenesisSnapshotMustBeBaked {
            configuration: ContentHash::default(),
        };
        let runtime_mismatch = EngineError::RuntimeConfigurationMismatch {
            runtime: ContentHash::default(),
            expected: ContentHash::default(),
            actual: ContentHash::default(),
        };
        let replay_target_mismatch = EngineError::ReplayTargetMismatch {
            expected: ContentHash::default(),
            actual: ContentHash::default(),
        };
        let replay_oracle_mismatch = EngineError::ReplayOracleMismatch {
            checkpoint: ContentHash::default(),
            expected: ContentHash::default(),
            actual: ContentHash::default(),
        };
        let schedule_prefix = EngineError::SchedulePrefix(ScheduleError::PrefixTooLong {
            requested: 3,
            available: 2,
        });
        let backend_not_implemented = BackendError::NotImplemented {
            operation: "snapshot",
        };
        let backend_rejected = BackendError::Rejected {
            message: String::from("stable rejection"),
        };

        assert_eq!(engine.to_string(), "instantiate is not implemented yet");
        assert_eq!(
            checkpoint_not_loadable.to_string(),
            "checkpoint is not loadable because it is thin"
        );
        assert_eq!(
            checkpoint_mismatch.to_string(),
            "checkpoint configuration does not match requested configuration"
        );
        assert_eq!(
            missing_genesis.to_string(),
            "missing baked genesis checkpoint for scenario"
        );
        assert_eq!(
            genesis_must_be_baked.to_string(),
            "genesis snapshots must be registered as baked genesis checkpoints"
        );
        assert_eq!(
            runtime_mismatch.to_string(),
            "runtime configuration does not match replay start configuration"
        );
        assert_eq!(
            replay_target_mismatch.to_string(),
            "replayed suffix did not produce requested configuration"
        );
        assert_eq!(
            replay_oracle_mismatch.to_string(),
            "replay oracle mismatch between fat checkpoint and thin derivation"
        );
        assert_eq!(
            schedule_prefix.to_string(),
            "schedule prefix failed: schedule prefix length 3 exceeds available length 2"
        );
        assert_eq!(
            backend_not_implemented.to_string(),
            "backend operation snapshot is not implemented yet"
        );
        assert_eq!(backend_rejected.to_string(), "stable rejection");
    }

    fn generated_scenario(seed: u64) -> ScenarioDef {
        ScenarioDef::from_canonical_material_with_seed(
            "crucible.test.configuration.generated",
            &format!("node=a\nseed={seed}\nimage=generated-{seed:04}"),
            Seed::from_u64(seed),
        )
    }

    fn generated_world(seed: u64) -> World {
        World::from_content_hash(ContentHash::from_canonical_material(
            "crucible.test.world.generated",
            &format!("nodes=a,b\nlinks=a-b\nseed={seed}"),
        ))
    }

    fn world_from_nodes(nodes: Vec<WorldNode>) -> World {
        match World::from_nodes(nodes) {
            Ok(world) => world,
            Err(error) => panic!("test world should be valid: {error}"),
        }
    }

    fn world_from_nodes_and_links(nodes: Vec<WorldNode>, links: Vec<LinkDef>) -> World {
        match World::from_nodes_and_links(nodes, links) {
            Ok(world) => world,
            Err(error) => panic!("test world topology should be valid: {error}"),
        }
    }

    fn two_ready_nodes() -> Vec<WorldNode> {
        vec![
            ready_node(
                "a",
                ReadyPoint::FixedIcount {
                    icount: Icount { retired: 1 },
                },
            ),
            ready_node(
                "b",
                ReadyPoint::FixedIcount {
                    icount: Icount { retired: 2 },
                },
            ),
        ]
    }

    #[cfg(feature = "test-double")]
    fn shmem_layout(
        vm_node_count: u32,
        queue_capacity: u32,
        icount_shift: u32,
    ) -> crucible_shmem::RegionLayout {
        match crucible_shmem::RegionLayout::for_config(crucible_shmem::RegionConfig::new(
            vm_node_count,
            queue_capacity,
            icount_shift,
        )) {
            Ok(layout) => layout,
            Err(error) => panic!("shmem region layout should be valid: {error}"),
        }
    }

    #[cfg(feature = "test-double")]
    fn world_with_physical_layout_id(
        world: &World,
        layout: crucible_shmem::RegionLayout,
        host_page_size: u64,
    ) -> World {
        match World::from_recorded_parts(
            ContentHash::from_canonical_material(
                "crucible.test.physical-transport-layout",
                &format!(
                    "vm_node_count={}\nnode_count={}\nqueue_capacity={}\nring_count={}\nnode_slots_off={}\nring_hdr_off={}\nring_data_off={}\nentry_stride={}\nregion_size={}\nicount_shift={}\nhost_page_size={}",
                    layout.vm_node_count,
                    layout.node_count,
                    layout.queue_capacity,
                    layout.ring_count,
                    layout.node_slots_off,
                    layout.ring_hdr_off,
                    layout.ring_data_off,
                    layout.entry_stride,
                    layout.region_size,
                    layout.icount_shift,
                    host_page_size
                ),
            ),
            world.nodes().to_vec(),
            world.links().to_vec(),
        ) {
            Ok(world) => world,
            Err(error) => panic!("physical-layout-id world should remain valid: {error}"),
        }
    }

    fn ready_node(name: &str, ready_point: ReadyPoint) -> WorldNode {
        WorldNode {
            id: node_id(name),
            arch: NodeTemplate::DEFAULT_ARCH,
            memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
            cmdline: String::new(),
            ready_point,
            white_box: WhiteBoxPolicy::Disabled,
            smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
            icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
            kernel: None,
            root_image: None,
            initrd: None,
        }
    }

    fn link(left: &str, right: &str) -> LinkDef {
        match LinkDef::new(node_id(left), node_id(right)) {
            Ok(link) => link,
            Err(error) => panic!("test link should be valid: {error}"),
        }
    }

    fn transport_link(
        left: &str,
        right: &str,
        latency_ns: u64,
        jitter_ns: u64,
        loss_millionths: u32,
        bandwidth_bps: Option<u64>,
    ) -> LinkDef {
        let loss = match LinkLossProbability::from_millionths(loss_millionths) {
            Ok(loss) => loss,
            Err(error) => panic!("test loss probability should be valid: {error}"),
        };
        match LinkDef::with_transport(
            node_id(left),
            node_id(right),
            SimDuration { nanos: latency_ns },
            SimDuration { nanos: jitter_ns },
            loss,
            bandwidth_bps,
        ) {
            Ok(link) => link,
            Err(error) => panic!("test transport link should be valid: {error}"),
        }
    }

    fn node_id(name: &str) -> NodeId {
        NodeId {
            name: name.to_owned(),
        }
    }

    fn tag(name: &str) -> FaultTag {
        FaultTag::from_name(name)
    }

    fn assertion_id(name: &str) -> AssertionId {
        AssertionId::from_name(name)
    }

    fn marker_id(name: &str) -> MarkerId {
        MarkerId::from_name(name)
    }

    fn named_predicate(name: &str, nodes: &[&str]) -> Predicate {
        Predicate::Named {
            name: name.to_owned(),
            nodes: nodes.iter().map(|node| node_id(node)).collect(),
        }
    }

    fn assertion(name: &str, message: &str, property: Property) -> AssertionDef {
        AssertionDef {
            id: assertion_id(name),
            message: message.to_owned(),
            property,
        }
    }

    fn seeded_stream_map(
        streams: Vec<SeededRngStream>,
    ) -> std::collections::BTreeMap<RngStreamId, u64> {
        streams
            .into_iter()
            .map(|stream| (stream.stream, stream.seed))
            .collect()
    }

    fn device_id(name: &str) -> DeviceId {
        DeviceId {
            name: name.to_owned(),
        }
    }

    fn generated_schedule(seed: u64, len: u64) -> Schedule {
        let mut schedule = Schedule::empty();
        for index in 0..len {
            schedule = schedule.appended(generated_decision(seed, index));
        }
        schedule
    }

    fn drift_rate(numerator: u64, denominator: u64) -> ClockDriftRate {
        match ClockDriftRate::new(numerator, denominator) {
            Ok(rate) => rate,
            Err(error) => panic!("test drift rate should be valid: {error}"),
        }
    }

    fn material_with_skew(base: &str, skew: NodeClockSkew) -> String {
        match skew.scenario_hash_material() {
            Ok(Some(skew_material)) => format!("{base}\n{skew_material}"),
            Ok(None) => base.to_owned(),
            Err(error) => panic!("test clock skew material should be valid: {error}"),
        }
    }

    fn swap_first_two_decisions(schedule: &Schedule) -> Schedule {
        let decisions = schedule.decisions();
        let mut swapped = Schedule::empty();

        if decisions.len() < 2 {
            return schedule.clone();
        }

        swapped = swapped.appended(decisions[1].clone());
        swapped = swapped.appended(decisions[0].clone());
        for decision in &decisions[2..] {
            swapped = swapped.appended(decision.clone());
        }

        swapped
    }

    fn record_representative_decision(recorder: &mut DecisionRecorder, index: u64) {
        match index % 3 {
            0 => {
                let _ = recorder.draw_u64(RngStreamId::for_node(format!("node-a/faults/{index}")));
            }
            1 => {
                let _ = recorder.decide_fault_basis_points(
                    VirtualTime { ticks: index + 1 },
                    FaultId {
                        name: format!("link-a-b/drop-{index}"),
                    },
                    RngStreamId::for_node("node-b/faults"),
                    FaultRateBasisPoints::from_basis_points(5_000)
                        .unwrap_or_else(|error| panic!("test rate should be valid: {error}")),
                );
            }
            _ => {
                let served = recorder.serve_app_random(
                    NodeId {
                        name: String::from("node-a"),
                    },
                    RngStreamId::for_node("node-a/app-random"),
                    16,
                );
                assert!(served.is_ok());
            }
        }
    }

    fn configuration_execution_fingerprint(configuration: &Configuration) -> ExecutionFingerprint {
        let state = match reduce(&configuration.def, &configuration.schedule) {
            Ok(state) => state,
            Err(error) => panic!("pure configuration fingerprint should reduce: {error}"),
        };
        ExecutionFingerprint { hash: state.id }
    }

    fn reduced_state_id(configuration: &Configuration) -> ContentHash {
        match reduce(&configuration.def, &configuration.schedule) {
            Ok(state) => state.id,
            Err(error) => panic!("pure reduced state should construct: {error}"),
        }
    }

    fn corrupt_checkpoint_node_blob(
        checkpoint: &Checkpoint,
        node: &NodeId,
        label: &str,
    ) -> Checkpoint {
        let mut corrupted = checkpoint.clone();
        corrupted.node_blobs.insert(
            node.clone(),
            NodeBlobRef::baked(ContentHash::from_canonical_material(
                "crucible.test.corrupt-checkpoint-node-blob",
                label,
            )),
        );
        corrupted.state = Some(MaterializedState::from_checkpoint_parts(
            &corrupted.node_icounts,
            &corrupted.node_blobs,
        ));
        corrupted
    }

    fn fat_checkpoint_for(configuration: &Configuration) -> Checkpoint {
        let parent = if configuration.is_genesis() {
            None
        } else {
            let schedule = match configuration
                .schedule
                .prefix(configuration.schedule.len().saturating_sub(1))
            {
                Ok(schedule) => schedule,
                Err(error) => panic!("test schedule prefix should build: {error}"),
            };
            Some(Configuration {
                def: configuration.def.clone(),
                schedule,
            })
        };
        match Checkpoint::from_recorded_configuration(
            configuration,
            parent.as_ref(),
            VirtualTime::default(),
            std::collections::BTreeMap::new(),
            CheckpointKind::Fat,
            std::collections::BTreeMap::new(),
        ) {
            Ok(checkpoint) => checkpoint,
            Err(error) => panic!("test checkpoint should be recorded-shaped: {error}"),
        }
    }

    fn fat_checkpoint_with_device_overlay(
        configuration: &Configuration,
        device: DeviceId,
    ) -> Checkpoint {
        let mut checkpoint = fat_checkpoint_for(configuration);
        checkpoint.state = Some(MaterializedState::from_components(
            std::collections::BTreeMap::new(),
            std::collections::BTreeMap::from([(device.clone(), device_overlay(&device.name))]),
            SchedulerState::empty(),
            DecisionRngState::empty(),
            EventLogOffset::default(),
        ));
        checkpoint
    }

    fn device_overlay(label: &str) -> DeviceOverlayDelta {
        let parent =
            ContentHash::from_canonical_material("crucible.test.device-overlay.parent", label);
        let delta =
            ContentHash::from_canonical_material("crucible.test.device-overlay.delta", label);
        let resolved =
            ContentHash::from_canonical_material("crucible.test.device-overlay.resolved", label);
        DeviceOverlayDelta::new(parent, delta, resolved, DeviceRngState::empty())
    }

    fn genesis_checkpoint_for(configuration: &Configuration) -> GenesisCheckpoint {
        GenesisCheckpoint {
            checkpoint: fat_checkpoint_for(configuration),
        }
    }

    fn event_key(virtual_time: u64, sequence: u64) -> EventKey {
        EventKey::new(
            VirtualTime {
                ticks: virtual_time,
            },
            scheduler_node("consumer"),
            scheduler_node("producer"),
            sequence,
        )
    }

    fn scheduler_node(name: &str) -> SchedulerNodeId {
        SchedulerNodeId {
            node: NodeId {
                name: name.to_owned(),
            },
            kind: SchedulingNodeKind::Vm,
        }
    }

    fn generated_decision(seed: u64, index: u64) -> Decision {
        match (seed + index) % 6 {
            0 => Decision::DeliveryOrder(DeliveryOrderDecision {
                at: VirtualTime {
                    ticks: seed + index,
                },
                order: vec![
                    event_key(seed + index, index),
                    event_key(seed + index, index + 1),
                ],
            }),
            1 => Decision::FaultFires(FaultDecision {
                at: VirtualTime {
                    ticks: seed.saturating_mul(2) + index,
                },
                fault: FaultId {
                    name: format!("fault-{seed}-{index}"),
                },
                fired: index.is_multiple_of(2),
            }),
            2 => Decision::RngDraw(RngDecision {
                stream: RngStreamId::for_node(format!("node-{seed}/stream-{index}")),
                value: seed.rotate_left((index % 31) as u32) ^ index,
            }),
            3 => Decision::Override(OverrideDecision {
                point: SchedulingPoint {
                    key: format!("point-{seed}-{index}"),
                },
                choice: ChoiceTag {
                    name: format!("choice-{index}"),
                },
            }),
            4 => Decision::Preemption(PreemptionDecision {
                node: NodeId {
                    name: format!("node-{seed}"),
                },
                at: Icount {
                    retired: seed + index + 1,
                },
                kind: PreemptionKind::VcpuSwitch {
                    from_vcpu: VcpuId { index: 0 },
                    to_vcpu: VcpuId { index: 1 },
                },
            }),
            _ => Decision::AppRandom(AppRandomDecision {
                node: NodeId {
                    name: format!("node-{seed}"),
                },
                stream: RngStreamId::for_node(format!("app-random-{index}")),
                request_id: index,
                width: 32,
                value: seed.wrapping_mul(0x9e37_79b9) ^ index,
            }),
        }
    }
}

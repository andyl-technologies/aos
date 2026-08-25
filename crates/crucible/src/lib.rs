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
//! [`node_time`] owns backend-counter to scheduler-time rebasing,
//! [`backend`] owns the VM backend boundary, [`event_catalog`] owns the versioned
//! event-kind catalog, [`scheduler`] owns the quantum-loop boundary, [`trigger`]
//! owns event-graph control flow, [`tracing_bridge`] owns opt-in host diagnostic
//! mirroring to `tracing`, `local_backend` provides the production local
//! backend, and `sim_backend` provides the feature-gated in-process QEMU test
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
mod local_backend;
pub mod model;
pub mod node_time;
pub mod scheduler;
#[cfg(feature = "test-double")]
mod sim_backend;
pub mod tracing_bridge;
pub mod trigger;

/// Portable canonical campaign vocabulary owned by `crucible-campaign`.
pub use crucible_campaign as campaign;

pub use backend::{
    AdvanceOutcome, Backend, BackendEffect, BackendError, BackendInput,
    BackendNetworkCompletedFaultPhase, BackendNetworkFaultContinuation, BackendNetworkFaultCursor,
    BackendNetworkFaultCursorError, BackendNetworkOutput, BackendNetworkOutputCodecError,
    BackendNetworkPreservedAvailability, BackendNetworkRoute, BackendSnapshot,
    ExecutionFingerprint, ExecutionHorizon, FingerprintSample, GdbAttachInfo, GdbListen,
    MockSimulationBackend, MockSimulationBackendState, SimulationBackend, StepObservation,
    deterministic_node_mac, deterministic_node_mac_string,
};
pub use crucible_device::{ResolvedNetworkFrameEffects, ResolvedNetworkFrameEffectsError};
pub use decision::{
    AppRandomSelectable, AppRandomSelectableError, DecisionRecordError, DecisionRecorder,
    app_random_stream_belongs_to_node, validate_app_random_model_selection,
};
pub use device::{LinkEmitDecisionRecord, NetworkLinkDirection, device_overlay, device_stream_id};
pub use device_subnode::{
    DEFAULT_WORLD_IO_INBOX_CAPACITY, DEFAULT_WORLD_IO_OUTBOX_CAPACITY, DeviceDelivery,
    DeviceSchedulingSubNode, DeviceSchedulingSubNodeCheckpoint,
    DeviceSchedulingSubNodeCheckpointError, DeviceSubNodeBindingError, WorldIoInstantiationError,
    WorldIoInstantiationLayout, WorldIoLayoutError, WorldIoLayoutPolicy, WorldIoRuntimeLayout,
    instantiate_world_io_sub_nodes,
};
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
pub use local_backend::{SimBackend, SimBackendState};
pub use model::{
    ADAPTIVE_UCB_SCORE_ONE_MICRO, APPLICATION_TRAFFIC_ORIGINATES_IN_GUEST, AdaptiveCampaignConfig,
    AdaptiveCampaignRun, AdaptiveCampaignSelection, AdaptiveStrategyArm, AdaptiveStrategyConfig,
    AdaptiveStrategyCredit, AdaptiveStrategyReward, AdaptiveStrategyRun, AdaptiveStrategySelection,
    AppRandomBranchConfig, AppRandomBranchError, AppRandomBranchRun, AppRandomDecision,
    AppRandomDrawSite, AppRandomSampleBudget, AssertionDef, AssertionId, AssertionPhase,
    AssertionProximityGuidanceSignal, Checkpoint, CheckpointKind, CheckpointMeta, ChoiceTag,
    CodePoint, Configuration, ContentAddressedBlobRef, ContentHash, CoverageGuidanceSignal,
    CoverageGuidedCorpus, CoverageGuidedCorpusAdmission, CoverageGuidedCorpusAdmissionDecision,
    CoverageGuidedCorpusConfig, CoverageGuidedCorpusEntry, CoverageGuidedCorpusEntryOrigin,
    CoverageGuidedCorpusError, CoverageGuidedCorpusRun, CoverageGuidedFuzzConfig,
    CoverageGuidedFuzzIteration, CoverageGuidedFuzzRun, CoverageGuidedFuzzThroughputReport,
    CoverageGuidedFuzzThroughputTarget, CowDeltaKind, CowDeltaRef, CowSharingStats,
    DEFAULT_ADAPTIVE_UCB_EXPLORATION_WEIGHT_MICROS, DEFAULT_APP_RANDOM_DRAW_CAP,
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
    DebugReadOnlyInspectionRequest, DebugReplayOracleBisectionRequest, DebugRetiredWorldCleanup,
    DebugReverseContinueMatch, DebugReverseContinueReport, DebugReverseContinueRequest,
    DebugReverseLatencyPolicy, DebugReverseStepGrain, DebugReverseStepReport,
    DebugReverseStepRequest, DebugRuntimeRepositionReport, DebugRuntimeRepositionRequest,
    DebugSymbolResolutionPolicy, DebugTargetResolverReport, DebugTargetResolverRequest,
    DebugTargetSelector, DebugWholeWorldTarget, DebugWholeWorldTimeTravelReport,
    DebugWholeWorldTimeTravelRequest, Decision, DecisionRngState, DeliveryOrderDecision, DeviceId,
    DeviceOverlayDelta, DeviceRngState, EngineError, EventId, EventKey, EventLogOffset,
    EventSequenceKey, EventSequenceState, FailureCausalCone, FailureCluster, FailureClusterFinding,
    FailureClusterMember, FailureClusterReport, FailureClusterReportCausalStep,
    FailureClusterReportDivergence, FailureClusterReportFailure, FailureClusterReportFormat,
    FailureClusterReportReproduction, FailureClusterReportSet, FailureClusteringResult,
    FailureCoverageClass, FailureFindingsLedger, FailureFirstFailingPoint, FailureKind,
    FailureMinimizationDisposition, FailurePropertyKey, FailurePropertyViolationRecord,
    FailureRecordedEventLog, FailureSignature, FailureSignatureKey, FailureSignatureNormalization,
    FailureSignaturePreservingMinimizationResult, FailureSignaturePreservingMinimizationRun,
    FailureSymmetryCanonicalizer, FailureTimeoutBudgetKind, FailureTimeoutRecord,
    FailureTriageChangedCluster, FailureTriageResult, FailureTriageResultDiff,
    FailureTriageResultIdentity, FailureTriageSignatureCheckRecord, FailureTriageSignatureMismatch,
    FailureTriageSignatureSelfCheck, FailureTriageSignatureSelfCheckInput,
    FailureTriageStoredArtifact, FamilyParams, FamilySpace, FaultSignalPlan, FindingDiscoveryPath,
    FindingReproductionArtifact, FindingReproductionArtifactError, FleetEquivalenceDivergence,
    FleetEquivalenceReport, FleetFindingSetEntry, FleetWorkClaim, FleetWorkStealingConfig,
    FleetWorkStealingSearchRun, FramePredicate, FrontierChild, FrontierCoveredChild,
    FrontierReductionPolicy, FrontierReductionReason, FrontierReductionReport, GenesisCheckpoint,
    GuestWorkloadBinary, GuestWorkloadConfigTreeDelivery, GuestWorkloadConfigTreeRef,
    GuestWorkloadLoadPatternFixture, GuestWorkloadParameterKey, GuestWorkloadPattern,
    GuestWorkloadScalarParameter, GuestWorkloadSeed, GuestWorkloadSpikeMode,
    GuestWorkloadTimeSource, GuidanceDeterminismLintReport, GuidanceObservation,
    GuidanceRarityTable, GuidanceScore, GuidanceSearchConfig, GuidanceSearchState, GuidanceSignal,
    GuidanceSignalComposition, GuidanceSignalInput, GuidanceSignalKind, GuidanceSignalWeight,
    Icount, IoEventKind, IrqVector, LinkDef, LinkId, LinkLossProbability,
    LocalCheckpointClosureIndex, LocalDagStore, MAX_APP_RANDOM_SAMPLES_PER_DRAW,
    MAX_MINIMIZATION_CANDIDATE_WORK_BYTES, MAX_MINIMIZATION_CANDIDATES, MIN_LINK_LATENCY, MarkerId,
    MaterializationPolicy, MaterializationTrigger, MaterializedSearchMutation,
    MaterializedSearchPlan, MaterializedState, MemPlace, MemoryCmp, MemoryDagStore, MemoryWidth,
    MinimizationAttempt, MinimizationConfig, MinimizationRun, NetworkLinkPendingFrame,
    NetworkLinkRuntimeCursor, NodeBlobRef, NodeCounter, NodeId, NodeLifecycle, NodeTemplate,
    NoveltyRarityGuidanceSignal, OverrideDecision, PROPERTY_QUANTIFIER_COUNT,
    PROPERTY_SCHEMA_DOMAIN, PROPERTY_SCHEMA_VERSION, PartialOrderIndependenceProof,
    PartialOrderReductionKey, PartialOrderReductionPolicy, PendingFrame, PinnedConfiguration,
    PinnedScenario, Plan, Predicate, PreemptionBranchConfig, PreemptionBranchRun,
    PreemptionDecision, PreemptionKind, Properties, Property, PropertyKind,
    ReachabilityExpectation, ReachableDisposition, ReadyPoint, RegexProgram, ReplayOracleCheck,
    ReproductionArtifact, ReproductionEventLogArtifact, ReproductionEventLogReplay,
    ReproductionReplay, ResolvedFaultTarget, RngDecision, RngStreamId, RngStreamPosition,
    RuntimeState, ScenarioBuilder, ScenarioDef, ScenarioDefForm, ScenarioFamily,
    ScenarioSelectableLimits, ScenarioSelectables, Schedule, ScheduleError, SchedulerNodeId,
    SchedulerState, SchedulingNodeKind, SchedulingPoint, SearchBudget, SearchDiscoveredFailure,
    SearchExpansion, SearchFailureOracle, SearchFrontierChoice, SearchFrontierChoices,
    SearchReplayOracleBisectionRequest, SearchReplayOracleSamplingConfig,
    SearchReplayOracleSamplingReport, SearchRetainedLogAssertionEvidence,
    SearchRetainedLogPredicateResolutions, SearchRuntimeFrontier, SearchStrategy, Seed, SeedSpace,
    SeededRngStream, SelectionDecision, Shift, SignaturePolicy, SignaturePolicyLevel, SimDuration,
    SimInstant, SimOffset, State, SymmetryClassId, SymmetryReductionClasses, SymmetryReductionKey,
    TargetSelector, TemporalGraph, TemporalGraphFork, TemporalGraphGcReport, TemporalGraphGcRoots,
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
    WorldBlockLatency, WorldDeviceKind, WorldIoCoreConfig, WorldIoNode, WorldIoNodeKind,
    WorldLookaheadEdge, WorldNinePLatency, WorldNode, WorldNodeDef, WorldStaticTopology,
    WorldWorkloadConfigTree, app_random_branch_decisions, bake, instantiate,
    lint_guidance_determinism_source, materialize_search_plans, preemption_branch_decisions,
    reduce, run_adaptive_strategy_selection, step, try_step,
};
pub use node_time::{NodeTimeMapping, NodeTimeProjection};
#[cfg(feature = "test-double")]
pub use scheduler::SchedulerRunCeilingHandoffError;
/// Shared-memory ABI version used by Crucible backends and artifacts.
pub const SHMEM_ABI_VERSION: u32 = include!("../../crucible-shmem/src/abi_version.in");
pub use scheduler::{
    AssertionRunVerdict, AssertionVerdictFailure, BackendNetworkOutputInterceptor,
    BackendNetworkSettlement, BackendQuantumLoop, CheckpointTerminalCause, ComposedRunVerdict,
    ComposedRunVerdictFailure, ConcurrentQuantumLoop, ConservativeAdvanceAuthorization,
    ControlOperation, ControlOperationKind, EventAttributeValue, EventClass,
    EventDiagnosticPayload, EventLevel, EventLog, EventLogAssertionProximityProjection,
    EventLogAssertionProximityProjectionEntry, EventLogCausalDivergencePoint,
    EventLogCausalProjection, EventLogCausalProjectionEntry, EventLogCoverageFeedback,
    EventLogCoverageFeedbackConsumer, EventLogCoverageObservation, EventLogCoverageProjection,
    EventLogCoverageProjectionEntry, EventLogDeterminismComparison, EventLogDeterminismMismatch,
    EventLogIcountStamp, EventLogTime, EventPayload, EventSource, ExactLocalEvent, IoCompletion,
    LogEntry, MAX_SINGLE_SCHEDULER_CHECKPOINT_BYTES, NetworkDroppedFrameEvidence,
    NetworkInFlightDropEvidence, NetworkLookahead, NodeTimelineProjection,
    NoopBackendNetworkOutputInterceptor, QuantumLoop, QuantumOutcome, QuantumRequest,
    QuantumTerminalVerdict, SCHEDULER_CONTROL_RESPONSE_BOUND_QUANTA, ScheduledEvent,
    ScheduledEventKey, ScheduledEventPayload, ScheduledEventResolveClass, SchedulerActor,
    SchedulerActorError, SchedulerActorHandle, SchedulerActorReply, SchedulerActorStateSnapshot,
    SchedulerConcurrentQuantumOutcome, SchedulerConcurrentRunCandidate, SchedulerConcurrentRunSet,
    SchedulerControlApplication, SchedulerEffectiveClock, SchedulerEffectiveClockSource,
    SchedulerError, SchedulerEvaluationBoundaryKind, SchedulerEventLogAppend,
    SchedulerEventLogClass, SchedulerEventLogEntry, SchedulerEventLogPayload, SchedulerHorizon,
    SchedulerHorizonLimit, SchedulerHorizonSource, SchedulerLivenessError, SchedulerLivenessReport,
    SchedulerLivenessScenario, SchedulerLookaheadEdge, SchedulerLookaheadEdgeEndpoint,
    SchedulerLookaheadGraph, SchedulerNetworkCheckpoint, SchedulerNetworkCheckpointCodecError,
    SchedulerNetworkLinkCheckpoint, SchedulerNodeActivity, SchedulerNodeCheckpoint,
    SchedulerNodeVcpuIdleSnapshot, SchedulerOperationalFailureClass,
    SchedulerPreemptionApplication, SchedulerQuiescence, SchedulerQuiescenceBlocker,
    SchedulerRendezvous, SchedulerRendezvousNode, SchedulerRendezvousPurpose,
    SchedulerRendezvousRecord, SchedulerRunCeilingPublication, SchedulerRunSubdivisionPolicy,
    SchedulerRunSubdivisionRecord, SchedulerRunSubdivisionSlice, SchedulerScenarioNode,
    SchedulerSendAuthorization, SchedulerSendAuthorizer, SchedulerTerminal,
    SchedulerTopologyChange, SchedulerTopologyChangeApplication, SchedulerTopologyChangeEffect,
    SchedulerTopologyChangeTrigger, SchedulerTopologyLookaheadUpdate, SchedulerVcpuIdleState,
    SchedulerWorldInstantiationError, SharedTimeline, SharedTimelineKey, SingleScheduler,
    SingleSchedulerCheckpoint, SingleSchedulerCheckpointError, TriggerActionApplication,
    TriggerActionState, TriggerDiagnosticRecord, TriggerLabelRecord, TriggerVerdict,
    UnresolvedCrossNodeDependency, WorldNetworkLinkRuntime,
    assertion_proximity_fingerprint_from_event_log, authorize_conservative_advance,
    check_scheduler_liveness, compare_event_log_determinism, coverage_fingerprint_from_event_log,
    event_log_assertion_proximity_projection, event_log_causal_projection,
    event_log_coverage_projection, exact_local_event_from_io_completion,
    exact_local_event_from_scheduled_event, exact_local_event_from_timer_deadline_ns,
    horizon_from_exact_local_event, horizon_from_network_lookahead,
    is_supported_live_world_network_override, live_world_network_override_matches_world,
    live_world_network_override_point_prefixes, lookahead_for_node, network_horizon_from_lookahead,
    next_exact_local_event, next_scheduled_event_key, ordered_scheduled_events,
    ordered_timeline_keys, rendezvous_cap_for, resolve_due_scheduled_events,
    scheduled_event_delivery_time, scheduled_event_resolve_class, scheduler_rr_run_subdivision,
    unresolved_cross_node_dependencies,
};
#[cfg(feature = "test-double")]
pub use sim_backend::{
    SimDeliveredFrame, SimDouble, SimDoubleConfig, SimDoubleControlEvent, SimDoubleError,
    SimDoubleHostScheduleEvent, SimInstructionScript, SimInstructionStep, SimOutboundFrame,
    sim_double_host_schedule_canonical_bytes,
};
pub use tracing_bridge::{TracingBridge, TracingBridgeConfig};
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
    GuestAssertionMarker, GuestMeasurementEvent, GuestMeasurementRational, GuestMeasurementValue,
    GuestSemanticMarkerDetail, HostAssertionCheckpointError, HostAssertionEvaluator,
    HostAssertionEvaluatorCheckpoint, HostAssertionHarnessLint, HostAssertionHarnessLintError,
    HostAssertionHarnessLintViolation, HostAssertionLifecycle, HostAssertionOracle,
    HostAssertionOutcome, HostAssertionOutcomeKind, HostAssertionPredicate, HostAssertionProximity,
    HostAssertionReport, HostAssertionViolation, LintedHostAssertionOracle, LogLevel,
    LoweredPlanEventGraph, ObservableEvent, ObservableEventPayload, ObservedOrderingFact,
    ObservedState, OfflineAssertionCheckError, OfflineAssertionChecker, PropertyLifecycleState,
    ReadyPointResolution, ReadyPointResolutionError, ReadyPointResolutionKind,
    RecordedAssertionLog, ResolvedCodePoint, ResolvedMemPlace, SearchScheduleNamedPredicateKey,
    SearchScheduleNamedPredicateTruths, TcgExecBasicBlock, basic_block_coverage_map_index,
    check_assertion_violation_reproduction, check_assertion_violation_reproduction_with_oracles,
    lint_host_assertion_harness_source, observable_event_from_whitebox_marker_payload,
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
#[path = "tests.rs"]
mod tests;

//! `crucible-session` owns the live session actor.
//!
//! Spec index: RFC-0010 files 20.
//!
//! This L4 crate will drive one live runtime state, accept control requests at quantum boundaries, and expose the session semantics specified by RFC-0010 file 20. It contains no raw QEMU or shared-memory access.
//!
//! Module map: the crate root owns [`SessionDriver`], [`Engine`], and [`SessionActor`]; [`validation`] owns replay and validation DAG adapters.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

/// Engine vocabulary exposed through the session boundary for control-plane clients.
pub mod engine {
    pub use crucible::{
        Action, AssertionDef, AssertionId, AssertionPhase, AssertionQuantifierKind,
        BlackBoxHostOracle, CRASH_RESTART_SCENARIO_NAME, Checkpoint, CheckpointKind, ChoiceTag,
        CodePoint, ConditionEventLogPrefix, Configuration, ContentAddressedBlobRef, ContentHash,
        CoverageGuidedCorpusConfig, CoverageGuidedCorpusRun, CoverageGuidedFuzzConfig,
        CoverageGuidedFuzzRun, DagStore, DagStoreError, DebugCheckpointStride,
        DebugCliSurfaceContract, DebugCoordinate, DebugFailureFooterCommand, DebugGdbEndpoint,
        DebugReverseStepGrain, Decision, DeliveryOrderDecision, EngineError, EventAttributeValue,
        EventDiagnosticPayload, EventId, EventLevel, EventLog, EventLogCoverageFeedback,
        EventLogCoverageObservation, EventLogIcountStamp, EventLogOffset, EventLogTime,
        EventPayload, EventSource, ExampleCorpusError, ExampleScenarioVerifyReport,
        ExecutionFingerprint, FAULT_CAMPAIGN_FAMILY_NAME, FailureCluster, FailureClusterFinding,
        FailureClusterReport, FailureClusterReportFailure, FailureClusterReportFormat,
        FailureClusterReportSet, FailureClusteringResult, FailureFindingsLedger, FailureKind,
        FailureMinimizationDisposition, FailurePropertyViolationRecord, FailureRecordedEventLog,
        FailureSignature, FailureSignatureNormalization,
        FailureSignaturePreservingMinimizationResult, FailureSignaturePreservingMinimizationRun,
        FailureTimeoutBudgetKind, FailureTimeoutRecord, FailureTriageResult,
        FailureTriageSignatureSelfCheck, FailureTriageSignatureSelfCheckInput,
        FailureTriageStoredArtifact, FamilySpace, FindingDiscoveryPath,
        FindingReproductionArtifact, FingerprintSample, GenesisCheckpoint,
        HAPPY_PATH_SCENARIO_NAME, HostAssertionEvaluator, HostAssertionOutcomeKind,
        HostAssertionViolation, Icount, LocalDagStore, MarkerId, MaterializationPolicy,
        MaterializationTrigger, MaterializedState, MemPlace, MemoryCmp, MemoryDagStore,
        MemoryWidth, MinimizationConfig, MinimizationRun, NodeId, NodeTemplate, ObservableEvent,
        OverrideDecision, PARTITION_RECOVERY_SCENARIO_NAME, Plan, Predicate, Properties, Property,
        QuantumLoop, QuantumOutcome, QuantumRequest, ReadyPoint, RecordedAssertionLog,
        ReplayOracleCheck, ReproductionArtifact, ResolvedCodePoint, ResolvedMemPlace, RngDecision,
        RngStreamId, SHMEM_ABI_VERSION, ScenarioDef, ScenarioDefForm, ScenarioFamily, Schedule,
        SchedulerError, SchedulerEvaluationBoundaryKind, SchedulerEventLogClass,
        SchedulerEventLogEntry, SchedulerEventLogPayload, SchedulerQuiescence, SchedulingPoint,
        SearchBudget, SearchDiscoveredFailure, SearchExpansion, SearchFailureOracle,
        SearchFrontierChoices, SearchReplayOracleSamplingConfig, SearchReplayOracleSamplingReport,
        SearchRetainedLogAssertionEvidence, SearchRuntimeFrontier, SearchScheduleNamedPredicateKey,
        SearchScheduleNamedPredicateTruths, SearchStrategy, Seed, SeedSpace, SignaturePolicy,
        SignaturePolicyLevel, SimBackend, SimDuration, SimulationBackend, TemporalGraph,
        TemporalGraphSampledSearchRun, TemporalGraphSearchRun, TemporalGraphStoreError,
        TopologyShape, TopologySizeRange, UnifiedGraphOperationEvidence, UnifiedGraphOperationKind,
        UnifiedGraphOperationReport, VirtualTime, VmArchitecture, WhiteBoxPolicy, World, WorldNode,
        bake, built_in_example_corpus, crash_restart_scenario, fault_campaign_family,
        happy_path_scenario, partition_recovery_scenario, run_fault_campaign_example, try_step,
        verify_example_scenario_runs,
    };
}

/// Session-owned replay and validation DAG adapters.
pub mod validation;

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crucible::{
    Action, BackendError, Checkpoint, CodePoint, Condition, ConditionEvaluationError,
    ConditionEvaluationPass, ConditionEventLogPrefix, ConditionLeaf, ConditionLeafOracle,
    Configuration, ContentHash, ControlOperation, ControlOperationKind, DagStore,
    DebugAttachReport, DebugAttachRequest, DebugCoordinate, DebugGdbEndpoint, DebugGotoReport,
    DebugGotoRequest, DebugNonCanonicalBranchAction, DebugNonCanonicalBranchReport,
    DebugNonCanonicalBranchRequest, DebugReverseContinueReport, DebugReverseContinueRequest,
    DebugReverseStepGrain, DebugReverseStepReport, DebugReverseStepRequest,
    DebugRuntimeRepositionRequest, Decision, EngineError, FingerprintSample, GdbListen, MemPlace,
    NodeId, ObservableEventPayload, QuantumLoop, QuantumOutcome, QuantumRequest,
    QuantumTerminalVerdict, ResolvedCodePoint, ResolvedMemPlace, RuntimeState, Schedule,
    ScheduledEventPayload, SchedulerError, SchedulerEvaluationBoundaryKind, SchedulerEventLogClass,
    SchedulerEventLogEntry, SchedulerEventLogPayload, SchedulerLivenessScenario,
    SchedulerQuiescence, SchedulerWorldInstantiationError, SimDuration, SingleScheduler,
    TemporalGraph, VirtualTime, WhiteBoxPolicy, World, WorldIoLayoutPolicy,
};
use crucible_protocol::guest_introspection::{
    GUEST_INTROSPECTION_FEATURE_CHANNEL_ID, GuestIntrospectionFailureCode,
    GuestIntrospectionFeatures, GuestIntrospectionMessage, GuestIntrospectionRecord,
};
use thiserror::Error;
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TryRecvError;
use tokio::sync::oneshot;

#[path = "session/actor.rs"]
mod session_actor;
#[path = "session/breakpoint_metadata.rs"]
mod session_breakpoint_metadata;
#[path = "session/commands.rs"]
mod session_commands;
#[path = "session/core.rs"]
mod session_core;
#[path = "session/debug_coordinator.rs"]
mod session_debug_coordinator;
#[path = "session/engine.rs"]
mod session_engine;
#[path = "session/exploration.rs"]
mod session_exploration;
#[path = "session/exploration/support.rs"]
mod session_exploration_support;
#[path = "session/streams.rs"]
mod session_streams;

pub use session_actor::*;
pub use session_breakpoint_metadata::*;
pub use session_commands::*;
pub use session_core::*;
pub use session_debug_coordinator::*;
pub use session_engine::*;
pub use session_exploration::*;
use session_exploration_support::*;
pub use session_streams::*;

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#[allow(clippy::expect_used)]
mod tests;

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
        AssertionId, AssertionPhase, AssertionQuantifierKind, BlackBoxHostOracle,
        CRASH_RESTART_SCENARIO_NAME, Checkpoint, CheckpointKind, ChoiceTag,
        ConditionEventLogPrefix, Configuration, ContentAddressedBlobRef, ContentHash,
        CoverageGuidedCorpusConfig, CoverageGuidedCorpusRun, CoverageGuidedFuzzConfig,
        CoverageGuidedFuzzRun, DagStore, DagStoreError, DebugCheckpointStride,
        DebugCliSurfaceContract, DebugCoordinate, DebugFailureFooterCommand, DebugGdbEndpoint,
        DebugReverseStepGrain, Decision, DeliveryOrderDecision, EngineError, EventAttributeValue,
        EventDiagnosticPayload, EventLevel, EventLogOffset, ExampleCorpusError,
        ExampleScenarioVerifyReport, ExecutionFingerprint, FAULT_CAMPAIGN_FAMILY_NAME,
        FailureClusterFinding, FailureClusterReport, FailureClusterReportFailure,
        FailureClusterReportFormat, FailureClusterReportSet, FailureClusteringResult,
        FailureFindingsLedger, FailurePropertyViolationRecord, FailureRecordedEventLog,
        FailureSignature, FailureSignatureNormalization,
        FailureSignaturePreservingMinimizationResult, FailureSignaturePreservingMinimizationRun,
        FailureTriageResult, FailureTriageSignatureSelfCheck, FailureTriageSignatureSelfCheckInput,
        FailureTriageStoredArtifact, FamilySpace, FaultDensity, FaultDensityRange, FaultTag,
        FindingDiscoveryPath, FindingReproductionArtifact, FingerprintSample, GenesisCheckpoint,
        HAPPY_PATH_SCENARIO_NAME, HostAssertionEvaluator, HostAssertionOutcomeKind,
        HostAssertionViolation, Icount, LocalDagStore, MarkerId, MaterializationPolicy,
        MaterializationTrigger, MemoryDagStore, MinimizationConfig, MinimizationRun, NodeId,
        NodeTemplate, OverrideDecision, PARTITION_RECOVERY_SCENARIO_NAME, Predicate, QuantumLoop,
        QuantumOutcome, QuantumRequest, ReadyPoint, RecordedAssertionLog, ReplayOracleCheck,
        ReproductionArtifact, RngDecision, RngStreamId, SHMEM_ABI_VERSION, ScenarioDef,
        ScenarioDefForm, ScenarioFamily, Schedule, SchedulerError, SchedulerEventLogEntry,
        SchedulerQuiescence, SchedulingPoint, SearchBudget, SearchDiscoveredFailure,
        SearchFailureOracle, SearchReplayOracleSamplingConfig, SearchReplayOracleSamplingReport,
        SearchRetainedLogAssertionEvidence, SearchScheduleNamedPredicateKey,
        SearchScheduleNamedPredicateTruths, SearchStrategy, Seed, SeedSpace, SignaturePolicy,
        SignaturePolicyLevel, SimBackend, SimDuration, SimulationBackend, TemporalGraph,
        TemporalGraphSampledSearchRun, TemporalGraphStoreError, TopologyShape, TopologySizeRange,
        UnifiedGraphOperationEvidence, UnifiedGraphOperationKind, UnifiedGraphOperationReport,
        VirtualTime, VmArchitecture, WhiteBoxPolicy, World, built_in_example_corpus,
        crash_restart_scenario, fault_campaign_family, happy_path_scenario,
        partition_recovery_scenario, run_fault_campaign_example, try_step,
        verify_example_scenario_runs,
    };
}

/// Session-owned replay and validation DAG adapters.
pub mod validation;

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crucible::{
    Action, BackendError, Checkpoint, Condition, ConditionEvaluationError, ConditionEvaluationPass,
    ConditionEventLogPrefix, ConditionLeaf, ConditionLeafOracle, Configuration, ContentHash,
    ControlOperation, ControlOperationKind, DagStore, DebugAttachReport, DebugAttachRequest,
    DebugGotoReport, DebugGotoRequest, DebugNonCanonicalBranchReport,
    DebugNonCanonicalBranchRequest, DebugReverseContinueReport, DebugReverseContinueRequest,
    DebugReverseStepGrain, DebugReverseStepReport, DebugReverseStepRequest, Decision, EngineError,
    Fault, FaultTag, FingerprintSample, GdbListen, NodeId, ObservableEventPayload, QuantumLoop,
    QuantumOutcome, QuantumRequest, RuntimeState, Schedule, ScheduledEventPayload, SchedulerError,
    SchedulerEvaluationBoundaryKind, SchedulerEventLogClass, SchedulerEventLogEntry,
    SchedulerEventLogPayload, SchedulerLivenessScenario, SchedulerQuiescence,
    SchedulerWorldInstantiationError, SimDuration, SingleScheduler, TemporalGraph, VirtualTime,
    WhiteBoxPolicy, World, WorldIoLayoutPolicy,
};
use thiserror::Error;
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TryRecvError;
use tokio::sync::oneshot;

include!("session/core.rs");
include!("session/commands.rs");
include!("session/exploration.rs");
include!("session/streams.rs");
include!("session/engine.rs");
include!("session/actor.rs");

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#[allow(clippy::expect_used)]
mod tests;

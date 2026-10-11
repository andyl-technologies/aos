//! Closed boundary-transcript data, independently of replay authority.
//!
//! The canonical JSON envelope has this shape:
//!
//! ```text
//! {"schema_version":1,"origin":{...},"limits":{...},"records":[...]}
//! ```
//!
//! Every interaction retains its complete request and response bytes. Content
//! references bind those bytes; they do not authorize replay or physical effects.

use crucible_node_contract::{ContentRef, Id, Position, Repeatability, U64};
use serde::{Deserialize, Serialize};

use crate::node_contract::{NodeRoute, SavedRuntimeActivation};
use crate::node_scheduling::InputPayload;

/// Declares finite raw-capture reservations before an external operation begins.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TranscriptLimits {
    /// Bounds the complete ordered interaction count, including control actions.
    pub maximum_records: U64,
    /// Reserves the largest complete request, response and evidence interaction.
    pub maximum_record_bytes: U64,
    /// Bounds all retained raw bytes and envelope metadata together.
    pub maximum_total_bytes: U64,
}

/// Retains actual observed provenance independently of a fresh replay realization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TranscriptOrigin {
    /// Identifies the actual source attempt, rather than its planned scenario.
    pub attempt: Id,
    /// Retains the complete original durable world activation and owner roster.
    pub activation: SavedRuntimeActivation,
    /// Retains the actual source participant and its authoritative incarnations.
    pub route: NodeRoute,
    /// Binds complete initialization, implementation and selected model identity.
    pub source_binding: ContentRef,
    /// Retains complete scenario, input, fault, clock and ordering preconditions.
    ///
    /// These are readable raw objects, not substitute labels or hash-only input.
    pub context: Vec<InputPayload>,
    /// Preserves the source world's admitted influence and nondeterminism taint.
    pub repeatability: Repeatability,
}

/// Identifies a recorded interaction that may affect later boundary responses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TranscriptAction {
    /// Observes the original complete producer inventory at a stopped boundary.
    Observe,
    /// Transfers one original complete frozen input cut into adapter custody.
    StageInput,
    /// Submits one immutable original execution or administrative permission.
    Begin,
    /// Retains the original terminal result; operational pending polls are omitted.
    Complete,
    /// Closes the original quantized window without issuing a replacement run.
    CloseWindow,
    /// Requests cancellation of the original operation without promising rollback.
    Cancel,
    /// Acknowledges actual output publication and its original custody identity.
    Acknowledge,
}

/// Retains original physical uncertainty separately from assigned logical time.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PhysicalTimingUncertainty {
    /// The recorded boundary supplies no qualified physical event-time interval.
    Unbounded,
    /// The original observer qualified a finite physical time interval.
    ObservedInterval {
        /// Original earliest possible observed time in source-clock nanoseconds.
        earliest_ns: U64,
        /// Original latest possible observed time in the same source clock.
        latest_ns: U64,
        /// Retains the actual clock and measurement qualification evidence.
        evidence: ContentRef,
    },
}

/// Retains one original request under complete request and context preconditions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TranscriptRequest {
    /// Selects the recorded semantic or custody action.
    pub action: TranscriptAction,
    /// Retains the original operation or staging identity without ordinal matching.
    pub identity: Id,
    /// Retains the original reached boundary before the request.
    pub boundary: Position,
    /// Binds the exact complete original request bytes and media type.
    pub content: ContentRef,
    /// Retains the complete original request bytes needed for divergence checks.
    pub bytes: Vec<u8>,
    /// Binds the original complete relevant context object inventory.
    pub context: ContentRef,
}

/// Retains one complete source interaction without claiming simulated computation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TranscriptRecord {
    /// Orders all source interactions contiguously without loss or wrapping.
    pub sequence: U64,
    /// Retains the actual request, its raw payload and its applicability context.
    pub request: TranscriptRequest,
    /// Binds the exact original response bytes and media type.
    pub response: ContentRef,
    /// Retains complete raw response bytes required to reconstruct future inputs.
    pub response_bytes: Vec<u8>,
    /// Retains original receipt, payload, consumption and dependency proof bytes.
    pub evidence: Vec<InputPayload>,
    /// Preserves assigned original response boundaries and phases in order.
    pub assigned_positions: Vec<Position>,
    /// Preserves original uncertainty without manufacturing exact physical time.
    pub physical_uncertainty: PhysicalTimingUncertainty,
}

/// Contains complete raw interactions within one explicitly bounded source prefix.
///
/// Decoding this data is not installed qualification. Replay requires verified
/// original source custody, exact applicability, and the separate adapter seal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundaryTranscript {
    /// Selects the closed boundary-transcript format edition.
    #[serde(deserialize_with = "crucible_node_contract::deserialize_version")]
    pub schema_version: u16,
    /// Retains the actual source attempt and its complete relevant provenance.
    pub origin: TranscriptOrigin,
    /// Retains the reservations admitted before source execution began.
    pub limits: TranscriptLimits,
    /// Retains the complete contiguous original interaction prefix.
    pub records: Vec<TranscriptRecord>,
}

/// Describes original semantic identities without conveying dispatch authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayRequestMetadata {
    /// Names the original action, independently of operational pending polls.
    pub action: TranscriptAction,
    /// Names the original operation or input-staging request.
    pub identity: Id,
    /// Retains exact original timing permission when the request carries one.
    pub operation: Option<crate::node_contract::OperationRequest>,
    /// Names the original immutable input batch, when present.
    pub input_batch: Option<Id>,
    /// Retains the original staging operation, when present.
    pub input_stage: Option<Id>,
    /// Retains the original complete exclusive input cut, when present.
    pub input_cut: Option<Position>,
}

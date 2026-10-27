//! Bounded replay evaluation and exact aggregation for scenario measurements.
//!
//! The evaluator consumes authenticated scheduler entries plus already-
//! normalized typed samples. Guest protocol decoding and model-owned sample
//! projection remain separate producers; neither can bypass the scenario's
//! immutable measurement contracts.

use super::*;
use std::borrow::Borrow;

mod boundary;
mod ownership;
mod validation;

pub use validation::validate_measurement_event_log;
use validation::{
    boundary_node_count, event_for_sequence, validate_and_index_samples, validate_terminal_state,
};

use boundary::evaluate_window;

/// Maximum normalized metric samples accepted by one evaluation.
pub const MAX_MEASUREMENT_RUNTIME_SAMPLES: usize = 1_000_000;
/// Maximum aggregate canonical bytes across normalized runtime samples.
pub const MAX_MEASUREMENT_RUNTIME_SAMPLE_BYTES: usize = 64 * 1024 * 1024;
/// Maximum definition-by-event visits accepted by one evaluation.
pub const MAX_MEASUREMENT_EVENT_VISITS: usize = 4_000_000;
/// Maximum model-metric-by-event visits accepted by sample projection.
pub const MAX_MODEL_MEASUREMENT_EVENT_VISITS: usize = 4_000_000;
/// Maximum canonical scheduler entries accepted by one evaluation.
pub const MAX_MEASUREMENT_EVENT_ENTRIES: usize = 1_000_000;
/// Maximum terminal per-node counters accepted by one evaluation.
pub const MAX_MEASUREMENT_TERMINAL_NODES: usize = 65_536;
/// Maximum canonical bytes in one complete measurement evaluation.
///
/// The bound matches the campaign evaluation-payload ceiling so every valid
/// evaluation can be retained without a second, narrower profile.
pub const MAX_MEASUREMENT_EVALUATION_BYTES: usize = 32 * 1024 * 1024;

/// One canonical exact rational represented as a reduced signed magnitude.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReducedRational {
    negative: bool,
    numerator: u128,
    denominator: u128,
}

impl ReducedRational {
    /// Builds and reduces one exact rational.
    ///
    /// # Errors
    ///
    /// Returns [`MeasurementEvaluationError::ZeroDenominator`] when
    /// `denominator` is zero.
    pub fn new(
        negative: bool,
        numerator: u128,
        denominator: u128,
    ) -> Result<Self, MeasurementEvaluationError> {
        if denominator == 0 {
            return Err(MeasurementEvaluationError::ZeroDenominator);
        }
        if numerator == 0 {
            return Ok(Self {
                negative: false,
                numerator: 0,
                denominator: 1,
            });
        }
        let divisor = greatest_common_divisor(numerator, denominator);
        Ok(Self {
            negative,
            numerator: numerator / divisor,
            denominator: denominator / divisor,
        })
    }

    /// Builds an exact rational from one signed integer.
    #[must_use]
    pub const fn from_signed(value: i64) -> Self {
        Self {
            negative: value.is_negative(),
            numerator: value.unsigned_abs() as u128,
            denominator: 1,
        }
    }

    /// Builds an exact rational from one unsigned integer.
    #[must_use]
    pub const fn from_unsigned(value: u64) -> Self {
        Self {
            negative: false,
            numerator: value as u128,
            denominator: 1,
        }
    }

    /// Returns whether this nonzero rational is negative.
    #[must_use]
    pub const fn is_negative(self) -> bool {
        self.negative
    }

    /// Returns the reduced unsigned numerator magnitude.
    #[must_use]
    pub const fn numerator(self) -> u128 {
        self.numerator
    }

    /// Returns the positive reduced denominator.
    #[must_use]
    pub const fn denominator(self) -> u128 {
        self.denominator
    }

    fn checked_add(self, right: Self) -> Result<Self, MeasurementEvaluationError> {
        let common = greatest_common_divisor(self.denominator, right.denominator);
        let left_scale = right.denominator / common;
        let right_scale = self.denominator / common;
        let left = self
            .numerator
            .checked_mul(left_scale)
            .ok_or(MeasurementEvaluationError::ArithmeticOverflow)?;
        let right_scaled = right
            .numerator
            .checked_mul(right_scale)
            .ok_or(MeasurementEvaluationError::ArithmeticOverflow)?;
        let denominator = self
            .denominator
            .checked_mul(left_scale)
            .ok_or(MeasurementEvaluationError::ArithmeticOverflow)?;

        let (negative, numerator) = if self.negative == right.negative {
            (
                self.negative,
                left.checked_add(right_scaled)
                    .ok_or(MeasurementEvaluationError::ArithmeticOverflow)?,
            )
        } else if left >= right_scaled {
            (self.negative, left - right_scaled)
        } else {
            (right.negative, right_scaled - left)
        };
        Self::new(negative, numerator, denominator)
    }

    fn checked_sub(self, right: Self) -> Result<Self, MeasurementEvaluationError> {
        let negated = if right.numerator == 0 {
            right
        } else {
            Self {
                negative: !right.negative,
                ..right
            }
        };
        self.checked_add(negated)
    }

    fn checked_divide_by(self, divisor: u64) -> Result<Self, MeasurementEvaluationError> {
        if divisor == 0 {
            return Err(MeasurementEvaluationError::ZeroDenominator);
        }
        let denominator = self
            .denominator
            .checked_mul(u128::from(divisor))
            .ok_or(MeasurementEvaluationError::ArithmeticOverflow)?;
        Self::new(self.negative, self.numerator, denominator)
    }

    fn checked_cmp(self, right: Self) -> Result<std::cmp::Ordering, MeasurementEvaluationError> {
        if self.negative != right.negative {
            return Ok(if self.negative {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Greater
            });
        }
        let common = greatest_common_divisor(self.denominator, right.denominator);
        let left = self
            .numerator
            .checked_mul(right.denominator / common)
            .ok_or(MeasurementEvaluationError::ArithmeticOverflow)?;
        let right = right
            .numerator
            .checked_mul(self.denominator / common)
            .ok_or(MeasurementEvaluationError::ArithmeticOverflow)?;
        let ordering = left.cmp(&right);
        Ok(if self.negative {
            ordering.reverse()
        } else {
            ordering
        })
    }
}

/// One normalized typed metric sample admitted by a scenario definition.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum MeasurementSampleValue {
    /// Signed 64-bit integer.
    Signed(i64),
    /// Unsigned 64-bit integer.
    Unsigned(u64),
    /// Exact reduced rational.
    Rational(ReducedRational),
    /// Boolean value.
    Boolean(bool),
    /// One canonical enumerated identifier.
    Enumerated(String),
    /// Bounded signed integer vector.
    SignedVector(Vec<i64>),
    /// Bounded unsigned integer vector.
    UnsignedVector(Vec<u64>),
}

/// One exact aggregate recomputed from retained samples.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum MeasurementAggregateValue {
    /// Signed integer aggregate.
    Signed(i64),
    /// Unsigned integer aggregate.
    Unsigned(u64),
    /// Exact reduced-rational aggregate.
    Rational(ReducedRational),
    /// Boolean aggregate.
    Boolean(bool),
    /// Enumerated aggregate.
    Enumerated(String),
    /// Signed-vector aggregate.
    SignedVector(Vec<i64>),
    /// Unsigned-vector aggregate.
    UnsignedVector(Vec<u64>),
    /// Inclusive declared bins followed by the greater-than-final-bound bin.
    Histogram(Vec<u64>),
}

impl From<MeasurementSampleValue> for MeasurementAggregateValue {
    fn from(value: MeasurementSampleValue) -> Self {
        match value {
            MeasurementSampleValue::Signed(value) => Self::Signed(value),
            MeasurementSampleValue::Unsigned(value) => Self::Unsigned(value),
            MeasurementSampleValue::Rational(value) => Self::Rational(value),
            MeasurementSampleValue::Boolean(value) => Self::Boolean(value),
            MeasurementSampleValue::Enumerated(value) => Self::Enumerated(value),
            MeasurementSampleValue::SignedVector(value) => Self::SignedVector(value),
            MeasurementSampleValue::UnsignedVector(value) => Self::UnsignedVector(value),
        }
    }
}

/// One typed sample attached to an exact scheduler event.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct MeasurementRuntimeSample {
    sequence: u64,
    measurement: MeasurementId,
    metric: MetricId,
    value: MeasurementSampleValue,
}

impl MeasurementRuntimeSample {
    /// Builds one normalized sample at an exact scheduler sequence.
    #[must_use]
    pub const fn new(
        sequence: u64,
        measurement: MeasurementId,
        metric: MetricId,
        value: MeasurementSampleValue,
    ) -> Self {
        Self {
            sequence,
            measurement,
            metric,
            value,
        }
    }

    /// Returns the scheduler sequence carrying this sample.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the scenario measurement identity.
    #[must_use]
    pub const fn measurement(&self) -> &MeasurementId {
        &self.measurement
    }

    /// Returns the metric identity within the measurement.
    #[must_use]
    pub const fn metric(&self) -> &MetricId {
        &self.metric
    }

    /// Returns the exact normalized value.
    #[must_use]
    pub const fn value(&self) -> &MeasurementSampleValue {
        &self.value
    }
}

impl Borrow<MeasurementSampleValue> for MeasurementRuntimeSample {
    fn borrow(&self) -> &MeasurementSampleValue {
        &self.value
    }
}

/// Terminal modeled state used to resolve stateful boundaries after the log.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct MeasurementTerminalState {
    /// Canonical scenario-ready coordinate, when the replay prefix reached it.
    pub scenario_ready_at: Option<VirtualTime>,
    /// Final modeled virtual-time coordinate.
    pub at: VirtualTime,
    /// Final per-node retired-instruction counters.
    pub node_icounts: BTreeMap<NodeId, Icount>,
    /// Whether the scheduler supplied canonical terminal quiescence evidence.
    pub scheduler_quiescent: bool,
}

/// One scheduler-ordered event participating in boundary satisfaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct MeasurementBoundaryEvent {
    sequence: u64,
    content_hash: ContentHash,
}

impl MeasurementBoundaryEvent {
    /// Returns the exact scheduler sequence.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the authenticated scheduler-entry content hash.
    #[must_use]
    pub const fn content_hash(&self) -> ContentHash {
        self.content_hash
    }
}

/// Exact evidence proving one boundary or timeout became satisfied.
#[derive(Debug, PartialEq, Eq, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct MeasurementBoundaryEvidence {
    sequence: Option<u64>,
    at: VirtualTime,
    events: Vec<MeasurementBoundaryEvent>,
    cohort: Vec<NodeId>,
}

impl MeasurementBoundaryEvidence {
    /// Returns the completing event sequence, or `None` for a synthetic
    /// genesis/terminal coordinate.
    #[must_use]
    pub const fn sequence(&self) -> Option<u64> {
        self.sequence
    }

    /// Returns the modeled coordinate at which the boundary completed.
    #[must_use]
    pub const fn at(&self) -> VirtualTime {
        self.at
    }

    /// Returns the exact canonical event hashes satisfying this boundary.
    #[must_use]
    pub fn events(&self) -> &[MeasurementBoundaryEvent] {
        &self.events
    }

    /// Returns the exact cohort members selected in canonical event order.
    #[must_use]
    pub fn cohort(&self) -> &[NodeId] {
        &self.cohort
    }
}

/// Final modeled state of one declared measurement window.
#[derive(Debug, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MeasurementWindowOutcome {
    /// The begin boundary never became true.
    NotStarted,
    /// The window opened but neither its end nor timeout became true.
    Open {
        /// Exact begin-boundary evidence.
        begin: MeasurementBoundaryEvidence,
    },
    /// The declared end boundary completed.
    Completed {
        /// Exact begin-boundary evidence.
        begin: MeasurementBoundaryEvidence,
        /// Exact end-boundary evidence.
        end: MeasurementBoundaryEvidence,
    },
    /// The declared modeled timeout completed before the end boundary.
    TimedOut {
        /// Exact begin-boundary evidence.
        begin: MeasurementBoundaryEvidence,
        /// Exact timeout evidence.
        timeout: MeasurementBoundaryEvidence,
    },
}

impl MeasurementWindowOutcome {
    fn includes_entry(&self, entry: &SchedulerEventLogEntry) -> bool {
        let begin = match self {
            Self::NotStarted => return false,
            Self::Open { begin } | Self::Completed { begin, .. } | Self::TimedOut { begin, .. } => {
                begin
            }
        };
        let end = match self {
            Self::Completed { end, .. } => Some(end),
            Self::TimedOut { timeout, .. } => Some(timeout),
            Self::NotStarted | Self::Open { .. } => None,
        };

        let after_begin = entry.at() > begin.at
            || (entry.at() == begin.at
                && begin
                    .sequence
                    .is_none_or(|sequence| entry.sequence() >= sequence));
        let before_end = end.is_none_or(|end| {
            entry.at() < end.at
                || (entry.at() == end.at
                    && end
                        .sequence
                        .is_none_or(|sequence| entry.sequence() <= sequence))
        });
        after_begin && before_end
    }
}

/// Exact samples and recomputed aggregate for one metric.
#[derive(Debug, PartialEq, Eq, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct MeasurementMetricOutcome {
    samples: Vec<MeasurementRuntimeSample>,
    aggregate: MeasurementAggregateValue,
    evidence: Vec<ContentHash>,
}

impl MeasurementMetricOutcome {
    /// Returns samples in canonical scheduler order.
    #[must_use]
    pub fn samples(&self) -> &[MeasurementRuntimeSample] {
        &self.samples
    }

    /// Returns the recomputed exact aggregate.
    #[must_use]
    pub const fn aggregate(&self) -> &MeasurementAggregateValue {
        &self.aggregate
    }

    /// Returns the event hash corresponding to every sample.
    #[must_use]
    pub fn evidence(&self) -> &[ContentHash] {
        &self.evidence
    }
}

/// Replay result for one declared measurement.
#[derive(Debug, PartialEq, Eq, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct MeasurementOutcome {
    window: MeasurementWindowOutcome,
    metrics: BTreeMap<MetricId, MeasurementMetricOutcome>,
}

impl MeasurementOutcome {
    /// Returns the final window state and exact satisfying evidence.
    #[must_use]
    pub const fn window(&self) -> &MeasurementWindowOutcome {
        &self.window
    }

    /// Returns metric outcomes in canonical metric-ID order.
    #[must_use]
    pub const fn metrics(&self) -> &BTreeMap<MetricId, MeasurementMetricOutcome> {
        &self.metrics
    }
}

/// Complete bounded evaluation keyed by canonical measurement identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeasurementEvaluation {
    body: std::sync::Arc<OwnedEvaluation>,
}

#[derive(Debug, PartialEq, Eq)]
struct OwnedEvaluation {
    definitions: ContentHash,
    outcomes: BTreeMap<MeasurementId, MeasurementOutcome>,
    id: ContentHash,
    canonical: Vec<u8>,
    input_custody: crate::owned_decode::DecodeCustody,
    custody: crate::owned_decode::DecodeCustody,
}

impl MeasurementEvaluation {
    /// Returns the exact scenario measurement-definition component.
    #[must_use]
    pub fn definitions(&self) -> ContentHash {
        self.body.definitions
    }

    /// Returns outcomes in canonical measurement-ID order.
    #[must_use]
    pub fn outcomes(&self) -> &BTreeMap<MeasurementId, MeasurementOutcome> {
        &self.body.outcomes
    }

    /// Returns the content address of this complete canonical evaluation.
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        self.body.id
    }

    /// Returns the exact language-neutral evaluation body.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.body.canonical
    }

    fn new(
        definitions: ContentHash,
        outcomes: BTreeMap<MeasurementId, MeasurementOutcome>,
        input_custody: crate::owned_decode::DecodeCustody,
    ) -> Result<Self, MeasurementEvaluationError> {
        let length = preflight_evaluation_bytes(definitions, &outcomes)?;
        let canonical = canonical_evaluation_json(definitions, &outcomes, length)?;
        let id = ContentHash::from_canonical_hex_bytes(
            "crucible.model.measurement-evaluation.v2",
            &canonical,
        );
        let custody = crate::owned_decode::require_current_custody()
            .map_err(MeasurementEvaluationError::OriginalAdmission)?;
        ownership::charge_shared_body::<OwnedEvaluation>()?;
        Ok(Self {
            body: std::sync::Arc::new(OwnedEvaluation {
                definitions,
                outcomes,
                id,
                canonical,
                input_custody,
                custody,
            }),
        })
    }
}

/// Stable failure while replaying or aggregating scenario measurements.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum MeasurementEvaluationError {
    /// A canonical event identity refused its original rendering or metadata admission.
    #[error("measurement event identity failed: {source}")]
    CanonicalIdentity {
        /// Original typed canonical rendering failure.
        source: std::sync::Arc<crate::EngineError>,
        /// Keeps the admitted error envelope alive through its last reader.
        custody: crate::owned_decode::DecodeCustody,
    },
    /// The original metadata account refused event identity verification.
    #[error(transparent)]
    OriginalAdmission(crate::owned_decode::DecodeAdmissionError),
    /// Input exceeded one deterministic work or collection bound.
    #[error("measurement evaluation limit `{limit}` exceeded")]
    LimitExceeded {
        /// Stable bound name.
        limit: &'static str,
    },
    /// A scheduler entry failed its canonical content-hash check.
    #[error("measurement event-log entry {sequence} has an invalid content hash")]
    InvalidEventHash {
        /// Rejected sequence.
        sequence: u64,
    },
    /// Scheduler entries were not strictly dense and increasing.
    #[error("measurement event-log sequence {actual} did not follow {previous}")]
    NonDenseEventLog {
        /// Previous accepted sequence.
        previous: u64,
        /// Rejected sequence.
        actual: u64,
    },
    /// A sample names a sequence absent from the supplied event log.
    #[error("measurement sample references absent event sequence {sequence}")]
    UnknownSampleSequence {
        /// Missing sequence.
        sequence: u64,
    },
    /// A sample names an undeclared measurement or metric.
    #[error("measurement sample references unknown {kind} `{id}`")]
    UnknownSampleTarget {
        /// Missing namespace.
        kind: &'static str,
        /// Missing ID.
        id: String,
        /// Keeps the original diagnostic allocation alive.
        custody: crate::owned_decode::DecodeCustody,
    },
    /// More than one value was supplied for a metric at one event.
    #[error("duplicate sample for measurement `{measurement}` metric `{metric}` at {sequence}")]
    DuplicateSample {
        /// Measurement ID.
        measurement: MeasurementId,
        /// Metric ID.
        metric: MetricId,
        /// Keeps the original diagnostic allocation alive.
        custody: crate::owned_decode::DecodeCustody,
        /// Event sequence.
        sequence: u64,
    },
    /// A normalized value violates its declared metric type.
    #[error("sample type does not match measurement `{measurement}` metric `{metric}`")]
    SampleTypeMismatch {
        /// Measurement ID.
        measurement: MeasurementId,
        /// Metric ID.
        metric: MetricId,
        /// Keeps the original diagnostic allocation alive.
        custody: crate::owned_decode::DecodeCustody,
    },
    /// An exact arithmetic operation exceeded its closed representation.
    #[error("measurement exact arithmetic overflowed")]
    ArithmeticOverflow,
    /// A rational denominator was zero.
    #[error("measurement rational denominator must be nonzero")]
    ZeroDenominator,
    /// An aggregation requires at least one sample.
    #[error("measurement aggregation `{aggregation}` requires at least one sample")]
    EmptySamples {
        /// Stable aggregation name.
        aggregation: &'static str,
    },
    /// A canonical evaluation body could not be encoded.
    #[error("measurement evaluation canonical encoding failed: {reason}")]
    CanonicalEncoding {
        /// Stable serialization detail.
        reason: String,
        /// Keeps the original diagnostic allocation alive.
        custody: crate::owned_decode::DecodeCustody,
    },
    /// Supplied retained bytes differ from exact replay output.
    #[error("retained measurement evaluation does not match exact replay")]
    ReplayMismatch,
    /// The terminal coordinate precedes retained scheduler evidence.
    #[error("measurement terminal coordinate precedes event sequence {sequence}")]
    TerminalBeforeEvent {
        /// Last event whose coordinate exceeds the terminal coordinate.
        sequence: u64,
    },
    /// A terminal per-node icount regressed behind retained evidence.
    #[error("measurement terminal icount regressed for node `{node:?}`")]
    TerminalIcountRegression {
        /// Node whose terminal counter regressed.
        node: NodeId,
        /// Keeps the original diagnostic allocation alive.
        custody: crate::owned_decode::DecodeCustody,
    },
    /// A model-source event had an invalid authority or required typed field.
    #[error("measurement model source found invalid `{kind}` event at sequence {sequence}")]
    InvalidModelSourceEvent {
        /// Exact scheduler sequence carrying the malformed event.
        sequence: u64,
        /// Stable scheduler event kind.
        kind: &'static str,
    },
}

impl From<crate::EngineError> for MeasurementEvaluationError {
    fn from(source: crate::EngineError) -> Self {
        match source {
            crate::EngineError::ArtifactDecodeAdmission { source } => {
                Self::OriginalAdmission(source)
            }
            source => {
                let custody = match crate::owned_decode::require_current_custody() {
                    Ok(custody) => custody,
                    Err(error) => return Self::OriginalAdmission(error),
                };
                let bytes = (std::mem::size_of::<crate::EngineError>()
                    + 2 * std::mem::size_of::<usize>()) as u64;
                if let Err(error) = crate::owned_decode::charge_bytes(bytes) {
                    return Self::OriginalAdmission(error);
                }
                Self::CanonicalIdentity {
                    source: std::sync::Arc::new(source),
                    custody,
                }
            }
        }
    }
}

/// Model-owned samples retaining the original producer allocation account.
#[derive(Debug, PartialEq, Eq)]
pub struct MeasurementModelSamples {
    samples: Vec<MeasurementRuntimeSample>,
    custody: crate::owned_decode::DecodeCustody,
}

impl std::ops::Deref for MeasurementModelSamples {
    type Target = [MeasurementRuntimeSample];

    fn deref(&self) -> &Self::Target {
        &self.samples
    }
}

impl MeasurementModelSamples {
    /// Transfers samples and their original credit into an owning evaluator.
    ///
    /// The receiver keeps the custody through the final sample destructor.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        Vec<MeasurementRuntimeSample>,
        crate::owned_decode::DecodeCustody,
    ) {
        (self.samples, self.custody)
    }
}

/// Derives model-owned metric samples from an authenticated scheduler log.
///
/// One sample is emitted for each matching event and metric contract. Virtual
/// time and scheduler-event metrics sample every entry; node icounts sample
/// entries stamped for the declared node; modeled event, network-drop, and
/// storage-completion metrics sample their exact typed event classes. Guest
/// metrics remain the responsibility of the guest protocol adapter.
///
/// # Errors
///
/// Returns [`MeasurementEvaluationError`] when the log is unauthenticated or
/// non-dense, a model-source event lacks a required typed attribute, or the
/// deterministic visit, sample-count, or sample-byte bound is exceeded.
pub fn derive_model_measurement_samples(
    definitions: &MeasurementDefinitions,
    entries: &[SchedulerEventLogEntry],
) -> Result<MeasurementModelSamples, MeasurementEvaluationError> {
    let output = crate::owned_decode::require_current_child_budget()
        .map_err(MeasurementEvaluationError::OriginalAdmission)?;
    let _scope = output.enter();
    let mut samples = Vec::new();
    append_model_measurement_samples(definitions, entries, &mut samples)?;
    output
        .check()
        .map_err(MeasurementEvaluationError::OriginalAdmission)?;
    Ok(MeasurementModelSamples {
        samples,
        custody: output.custody(),
    })
}

/// Appends model-owned samples to an independently normalized sample stream.
///
/// This is the bounded mixed-source path: the runtime sample-count and byte
/// limits apply to the existing guest samples plus newly derived model samples,
/// and no second model-sample vector is allocated. The caller retains the
/// active original account through the last reader of the appended samples.
///
/// # Errors
///
/// Returns the same errors as [`derive_model_measurement_samples`], including
/// when `samples` already exceeds the runtime sample bound or the combined
/// stream exceeds a count or byte limit.
pub fn append_model_measurement_samples(
    definitions: &MeasurementDefinitions,
    entries: &[SchedulerEventLogEntry],
    samples: &mut Vec<MeasurementRuntimeSample>,
) -> Result<(), MeasurementEvaluationError> {
    validate_measurement_event_log(entries)?;
    if samples.len() > MAX_MEASUREMENT_RUNTIME_SAMPLES {
        return Err(MeasurementEvaluationError::LimitExceeded {
            limit: "measurement-runtime-samples",
        });
    }

    let model_metric_count = definitions
        .definitions()
        .iter()
        .flat_map(|definition| &definition.metrics)
        .filter(|metric| metric.source != MetricSource::Guest)
        .count();
    let visits = model_metric_count.checked_mul(entries.len()).ok_or(
        MeasurementEvaluationError::LimitExceeded {
            limit: "model-measurement-event-visits",
        },
    )?;
    if visits > MAX_MODEL_MEASUREMENT_EVENT_VISITS {
        return Err(MeasurementEvaluationError::LimitExceeded {
            limit: "model-measurement-event-visits",
        });
    }

    let mut sample_bytes = preflight_runtime_sample_bytes(samples)?;
    for (measurement, metric) in definitions.definitions().iter().flat_map(|definition| {
        definition
            .metrics
            .iter()
            .filter(|metric| metric.source != MetricSource::Guest)
            .map(move |metric| (&definition.id, metric))
    }) {
        for entry in entries {
            let Some(value) = model_sample_value(metric, entry)? else {
                continue;
            };
            if samples.len() == MAX_MEASUREMENT_RUNTIME_SAMPLES {
                return Err(MeasurementEvaluationError::LimitExceeded {
                    limit: "measurement-runtime-samples",
                });
            }
            let sample = MeasurementRuntimeSample::new(
                entry.sequence(),
                ownership::copy_measurement(measurement)?,
                ownership::copy_metric(&metric.id)?,
                value,
            );
            let separator = usize::from(!samples.is_empty());
            let encoded_sample_bytes = encoded_runtime_sample_len(&sample)?;
            sample_bytes = sample_bytes
                .checked_add(separator)
                .and_then(|length| length.checked_add(encoded_sample_bytes))
                .ok_or(MeasurementEvaluationError::LimitExceeded {
                    limit: "measurement-runtime-sample-bytes",
                })?;
            if sample_bytes > MAX_MEASUREMENT_RUNTIME_SAMPLE_BYTES {
                return Err(MeasurementEvaluationError::LimitExceeded {
                    limit: "measurement-runtime-sample-bytes",
                });
            }
            ownership::reserve(samples, 1)?;
            samples.push(sample);
        }
    }
    Ok(())
}

fn model_sample_value(
    metric: &MetricDefinition,
    entry: &SchedulerEventLogEntry,
) -> Result<Option<MeasurementSampleValue>, MeasurementEvaluationError> {
    let payload = entry.event_payload();
    let value = match &metric.source {
        MetricSource::Guest => None,
        MetricSource::VirtualTime => Some(entry.at().ticks),
        MetricSource::NodeIcount { node } => entry
            .time()
            .stamp
            .node
            .as_ref()
            .filter(|stamped| *stamped == node)
            .and_then(|_node| entry.time().stamp.retired.map(|count| count.retired)),
        MetricSource::ModeledEventCount { event } if payload.kind() == "trigger_fired" => {
            let observed = payload.event("event").ok_or(
                MeasurementEvaluationError::InvalidModelSourceEvent {
                    sequence: entry.sequence(),
                    kind: "trigger_fired",
                },
            )?;
            if !matches!(entry.source(), EventSource::Engine)
                && !matches!(
                    entry.source(),
                    EventSource::Scenario { event } if event == observed
                )
            {
                return Err(MeasurementEvaluationError::InvalidModelSourceEvent {
                    sequence: entry.sequence(),
                    kind: "trigger_fired",
                });
            }
            (observed == event).then_some(1)
        }
        MetricSource::ModeledEventCount { .. } => None,
        MetricSource::NetworkModeledDropCount { link } if payload.kind() == "message_dropped" => {
            let observed = payload.string("link").ok_or(
                MeasurementEvaluationError::InvalidModelSourceEvent {
                    sequence: entry.sequence(),
                    kind: "message_dropped",
                },
            )?;
            if !matches!(
                entry.source(),
                EventSource::Engine | EventSource::Node { .. }
            ) {
                return Err(MeasurementEvaluationError::InvalidModelSourceEvent {
                    sequence: entry.sequence(),
                    kind: "message_dropped",
                });
            }
            link.as_ref()
                .is_none_or(|expected| expected.name == observed)
                .then_some(1)
        }
        MetricSource::NetworkModeledDropCount { .. } => None,
        MetricSource::StorageCompletionCount { node } if payload.kind() == "io_completion" => {
            let observed = payload.node("node").ok_or(
                MeasurementEvaluationError::InvalidModelSourceEvent {
                    sequence: entry.sequence(),
                    kind: "io_completion",
                },
            )?;
            if !matches!(entry.source(), EventSource::Engine)
                && !matches!(
                    entry.source(),
                    EventSource::Node { node } if node == observed
                )
            {
                return Err(MeasurementEvaluationError::InvalidModelSourceEvent {
                    sequence: entry.sequence(),
                    kind: "io_completion",
                });
            }
            (observed == node).then_some(1)
        }
        MetricSource::StorageCompletionCount { .. } => None,
        MetricSource::SchedulerEventCount => Some(1),
    };
    Ok(value.map(MeasurementSampleValue::Unsigned))
}

/// Replays measurement boundaries and recomputes every declared aggregate.
///
/// Samples are admitted only when their event sequence lies inclusively between
/// the selected begin and end/timeout events. End-boundary satisfaction wins
/// when an end and timeout become true on the same scheduler entry.
///
/// # Errors
///
/// Returns [`MeasurementEvaluationError`] for unauthenticated or non-dense
/// event logs, unknown/duplicate/mistyped samples, exceeded deterministic work
/// bounds, or exact-arithmetic failure.
pub fn evaluate_measurements(
    definitions: &MeasurementDefinitions,
    entries: &[SchedulerEventLogEntry],
    samples: Vec<MeasurementRuntimeSample>,
    terminal: &MeasurementTerminalState,
) -> Result<MeasurementEvaluation, MeasurementEvaluationError> {
    let input_custody = crate::owned_decode::require_current_custody()
        .map_err(MeasurementEvaluationError::OriginalAdmission)?;
    let output = crate::owned_decode::require_current_child_budget()
        .map_err(MeasurementEvaluationError::OriginalAdmission)?;
    let _output_scope = output.enter();
    validate_measurement_event_log(entries)?;
    validate_terminal_state(entries, terminal)?;
    if samples.len() > MAX_MEASUREMENT_RUNTIME_SAMPLES {
        return Err(MeasurementEvaluationError::LimitExceeded {
            limit: "measurement-runtime-samples",
        });
    }
    preflight_runtime_sample_bytes(&samples)?;
    let boundary_nodes =
        definitions
            .definitions()
            .iter()
            .try_fold(0_usize, |total, definition| {
                let begin = boundary_node_count(&definition.begin)?;
                let end = boundary_node_count(&definition.end)?;
                total
                    .checked_add(begin)
                    .and_then(|total| total.checked_add(end))
                    .ok_or(MeasurementEvaluationError::LimitExceeded {
                        limit: "measurement-event-visits",
                    })
            })?;
    let visits = boundary_nodes
        .checked_mul(entries.len().saturating_add(1))
        .ok_or(MeasurementEvaluationError::LimitExceeded {
            limit: "measurement-event-visits",
        })?;
    if visits > MAX_MEASUREMENT_EVENT_VISITS {
        return Err(MeasurementEvaluationError::LimitExceeded {
            limit: "measurement-event-visits",
        });
    }
    let mut samples = validate_and_index_samples(definitions, entries, samples)?;
    let mut outcomes = BTreeMap::new();
    for definition in definitions.definitions() {
        let window = evaluate_window(definition, entries, terminal)?;
        let mut metrics = BTreeMap::new();
        for metric in &definition.metrics {
            let mut retained = samples
                .remove(&(&definition.id, &metric.id))
                .unwrap_or_default();
            retained.retain(|sample| {
                event_for_sequence(entries, sample.sequence)
                    .is_some_and(|entry| window.includes_entry(entry))
            });
            let aggregate = aggregate_metric_samples(metric, &retained)?;
            let mut evidence = Vec::new();
            ownership::reserve(&mut evidence, retained.len())?;
            for sample in &retained {
                evidence.push(
                    event_for_sequence(entries, sample.sequence)
                        .map(SchedulerEventLogEntry::content_hash)
                        .ok_or(MeasurementEvaluationError::UnknownSampleSequence {
                            sequence: sample.sequence,
                        })?,
                );
            }
            ownership::tree_entry::<MetricId, MeasurementMetricOutcome>()?;
            metrics.insert(
                ownership::copy_metric(&metric.id)?,
                MeasurementMetricOutcome {
                    samples: retained,
                    aggregate,
                    evidence,
                },
            );
        }
        ownership::tree_entry::<MeasurementId, MeasurementOutcome>()?;
        outcomes.insert(
            ownership::copy_measurement(&definition.id)?,
            MeasurementOutcome { window, metrics },
        );
    }
    MeasurementEvaluation::new(definitions.content_hash(), outcomes, input_custody)
}

/// Recomputes and authenticates one retained canonical evaluation body.
///
/// # Errors
///
/// Returns the same failures as [`evaluate_measurements`] or
/// [`MeasurementEvaluationError::ReplayMismatch`] when `retained` is not the
/// exact canonical body produced by replay.
pub fn verify_measurement_evaluation(
    definitions: &MeasurementDefinitions,
    entries: &[SchedulerEventLogEntry],
    samples: Vec<MeasurementRuntimeSample>,
    terminal: &MeasurementTerminalState,
    retained: &[u8],
) -> Result<MeasurementEvaluation, MeasurementEvaluationError> {
    let evaluation = evaluate_measurements(definitions, entries, samples, terminal)?;
    if evaluation.canonical_bytes() != retained {
        return Err(MeasurementEvaluationError::ReplayMismatch);
    }
    Ok(evaluation)
}

// Recomputes one aggregate only after the full evaluator has authenticated the
// metric declaration and normalized every sample against its declared type.
fn aggregate_metric_samples<S: Borrow<MeasurementSampleValue>>(
    definition: &MetricDefinition,
    samples: &[S],
) -> Result<MeasurementAggregateValue, MeasurementEvaluationError> {
    match &definition.aggregation {
        Aggregation::Count => Ok(MeasurementAggregateValue::Unsigned(
            u64::try_from(samples.len())
                .map_err(|_| MeasurementEvaluationError::ArithmeticOverflow)?,
        )),
        Aggregation::Sum => aggregate_sum(&definition.value_type, samples),
        Aggregation::Min => aggregate_extreme(samples, std::cmp::Ordering::Less),
        Aggregation::Max => aggregate_extreme(samples, std::cmp::Ordering::Greater),
        Aggregation::ExactMean => aggregate_mean(samples),
        Aggregation::Histogram { upper_bounds } => aggregate_histogram(samples, upper_bounds),
        Aggregation::First => {
            ownership::aggregate_copy(samples.first().map(Borrow::borrow), "first")
        }
        Aggregation::Last => ownership::aggregate_copy(samples.last().map(Borrow::borrow), "last"),
        Aggregation::EventDelta => aggregate_delta(samples),
    }
}

#[derive(serde::Serialize)]
struct MeasurementEvaluationBody<'a> {
    definitions: ContentHash,
    measurement: &'a BTreeMap<MeasurementId, MeasurementOutcome>,
}

fn canonical_evaluation_json(
    definitions: ContentHash,
    outcomes: &BTreeMap<MeasurementId, MeasurementOutcome>,
    length: usize,
) -> Result<Vec<u8>, MeasurementEvaluationError> {
    let mut bytes = Vec::new();
    ownership::reserve(&mut bytes, length)?;
    bytes.resize(length, 0);
    let mut output = bytes.as_mut_slice();
    serde_json::to_writer(
        &mut output,
        &MeasurementEvaluationBody {
            definitions,
            measurement: outcomes,
        },
    )
    .map_err(|error| ownership::encoding_error(&error))?;
    if !output.is_empty() {
        return Err(MeasurementEvaluationError::ReplayMismatch);
    }
    Ok(bytes)
}

fn preflight_runtime_sample_bytes(
    samples: &[MeasurementRuntimeSample],
) -> Result<usize, MeasurementEvaluationError> {
    let mut counter = BoundedJsonByteCounter {
        length: 0,
        maximum: MAX_MEASUREMENT_RUNTIME_SAMPLE_BYTES,
        exceeded: false,
    };
    let encoded = serde_json::to_writer(&mut counter, samples);
    if counter.exceeded {
        return Err(MeasurementEvaluationError::LimitExceeded {
            limit: "measurement-runtime-sample-bytes",
        });
    }
    encoded.map_err(|error| ownership::encoding_error(&error))?;
    Ok(counter.length)
}

fn encoded_runtime_sample_len(
    sample: &MeasurementRuntimeSample,
) -> Result<usize, MeasurementEvaluationError> {
    let mut counter = BoundedJsonByteCounter {
        length: 0,
        maximum: MAX_MEASUREMENT_RUNTIME_SAMPLE_BYTES,
        exceeded: false,
    };
    let encoded = serde_json::to_writer(&mut counter, sample);
    if counter.exceeded {
        return Err(MeasurementEvaluationError::LimitExceeded {
            limit: "measurement-runtime-sample-bytes",
        });
    }
    encoded.map_err(|error| ownership::encoding_error(&error))?;
    Ok(counter.length)
}

fn preflight_evaluation_bytes(
    definitions: ContentHash,
    outcomes: &BTreeMap<MeasurementId, MeasurementOutcome>,
) -> Result<usize, MeasurementEvaluationError> {
    let mut counter = BoundedJsonByteCounter {
        length: 0,
        maximum: MAX_MEASUREMENT_EVALUATION_BYTES,
        exceeded: false,
    };
    let encoded = serde_json::to_writer(
        &mut counter,
        &MeasurementEvaluationBody {
            definitions,
            measurement: outcomes,
        },
    );
    if counter.exceeded {
        return Err(MeasurementEvaluationError::LimitExceeded {
            limit: "measurement-evaluation-bytes",
        });
    }
    encoded.map_err(|error| ownership::encoding_error(&error))?;
    Ok(counter.length)
}

struct BoundedJsonByteCounter {
    length: usize,
    maximum: usize,
    exceeded: bool,
}

impl io::Write for BoundedJsonByteCounter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.length = match self.length.checked_add(bytes.len()) {
            Some(length) => length,
            None => {
                self.exceeded = true;
                return Err(io::Error::other(
                    "measurement evaluation byte count overflowed",
                ));
            }
        };
        if self.length > self.maximum {
            self.exceeded = true;
            return Err(io::Error::other(
                "measurement evaluation byte limit exceeded",
            ));
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn greatest_common_divisor(mut left: u128, mut right: u128) -> u128 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left
}

fn aggregate_sum<S: Borrow<MeasurementSampleValue>>(
    value_type: &MetricValueType,
    samples: &[S],
) -> Result<MeasurementAggregateValue, MeasurementEvaluationError> {
    match value_type {
        MetricValueType::SignedInteger => samples
            .iter()
            .try_fold(0_i64, |total, sample| match sample.borrow() {
                MeasurementSampleValue::Signed(value) => total
                    .checked_add(*value)
                    .ok_or(MeasurementEvaluationError::ArithmeticOverflow),
                _ => Err(MeasurementEvaluationError::ArithmeticOverflow),
            })
            .map(MeasurementAggregateValue::Signed),
        MetricValueType::UnsignedInteger => samples
            .iter()
            .try_fold(0_u64, |total, sample| match sample.borrow() {
                MeasurementSampleValue::Unsigned(value) => total
                    .checked_add(*value)
                    .ok_or(MeasurementEvaluationError::ArithmeticOverflow),
                _ => Err(MeasurementEvaluationError::ArithmeticOverflow),
            })
            .map(MeasurementAggregateValue::Unsigned),
        MetricValueType::ReducedRational => samples
            .iter()
            .try_fold(
                ReducedRational::from_unsigned(0),
                |total, sample| match sample.borrow() {
                    MeasurementSampleValue::Rational(value) => total.checked_add(*value),
                    _ => Err(MeasurementEvaluationError::ArithmeticOverflow),
                },
            )
            .map(MeasurementAggregateValue::Rational),
        MetricValueType::Boolean
        | MetricValueType::Enumerated { .. }
        | MetricValueType::IntegerVector { .. } => {
            Err(MeasurementEvaluationError::ArithmeticOverflow)
        }
    }
}

fn aggregate_extreme<S: Borrow<MeasurementSampleValue>>(
    samples: &[S],
    desired: std::cmp::Ordering,
) -> Result<MeasurementAggregateValue, MeasurementEvaluationError> {
    let mut selected =
        samples
            .first()
            .map(Borrow::borrow)
            .ok_or(MeasurementEvaluationError::EmptySamples {
                aggregation: if desired == std::cmp::Ordering::Less {
                    "min"
                } else {
                    "max"
                },
            })?;
    for sample in &samples[1..] {
        let ordering = compare_samples(sample.borrow(), selected)?;
        if ordering == desired {
            selected = sample.borrow();
        }
    }
    Ok(ownership::copy_value(selected)?.into())
}

fn compare_samples(
    left: &MeasurementSampleValue,
    right: &MeasurementSampleValue,
) -> Result<std::cmp::Ordering, MeasurementEvaluationError> {
    match (left, right) {
        (MeasurementSampleValue::Signed(left), MeasurementSampleValue::Signed(right)) => {
            Ok(left.cmp(right))
        }
        (MeasurementSampleValue::Unsigned(left), MeasurementSampleValue::Unsigned(right)) => {
            Ok(left.cmp(right))
        }
        (MeasurementSampleValue::Rational(left), MeasurementSampleValue::Rational(right)) => {
            left.checked_cmp(*right)
        }
        (MeasurementSampleValue::Boolean(left), MeasurementSampleValue::Boolean(right)) => {
            Ok(left.cmp(right))
        }
        _ => Err(MeasurementEvaluationError::ArithmeticOverflow),
    }
}

fn aggregate_mean<S: Borrow<MeasurementSampleValue>>(
    samples: &[S],
) -> Result<MeasurementAggregateValue, MeasurementEvaluationError> {
    if samples.is_empty() {
        return Err(MeasurementEvaluationError::EmptySamples {
            aggregation: "exact_mean",
        });
    }
    let total = samples
        .iter()
        .try_fold(ReducedRational::from_unsigned(0), |total, sample| {
            let value = match sample.borrow() {
                MeasurementSampleValue::Signed(value) => ReducedRational::from_signed(*value),
                MeasurementSampleValue::Unsigned(value) => ReducedRational::from_unsigned(*value),
                MeasurementSampleValue::Rational(value) => *value,
                _ => return Err(MeasurementEvaluationError::ArithmeticOverflow),
            };
            total.checked_add(value)
        })?;
    total
        .checked_divide_by(
            u64::try_from(samples.len())
                .map_err(|_| MeasurementEvaluationError::ArithmeticOverflow)?,
        )
        .map(MeasurementAggregateValue::Rational)
}

fn aggregate_histogram<S: Borrow<MeasurementSampleValue>>(
    samples: &[S],
    upper_bounds: &[i64],
) -> Result<MeasurementAggregateValue, MeasurementEvaluationError> {
    let count = upper_bounds
        .len()
        .checked_add(1)
        .ok_or(MeasurementEvaluationError::ArithmeticOverflow)?;
    let mut bins = Vec::new();
    ownership::reserve(&mut bins, count)?;
    bins.resize(count, 0_u64);
    for sample in samples {
        let bin = match sample.borrow() {
            MeasurementSampleValue::Signed(value) => {
                upper_bounds.partition_point(|bound| *bound < *value)
            }
            MeasurementSampleValue::Unsigned(value) => upper_bounds.partition_point(|bound| {
                bound.is_negative() || u64::try_from(*bound).is_ok_and(|bound| bound < *value)
            }),
            _ => return Err(MeasurementEvaluationError::ArithmeticOverflow),
        };
        bins[bin] = bins[bin]
            .checked_add(1)
            .ok_or(MeasurementEvaluationError::ArithmeticOverflow)?;
    }
    Ok(MeasurementAggregateValue::Histogram(bins))
}

fn aggregate_delta<S: Borrow<MeasurementSampleValue>>(
    samples: &[S],
) -> Result<MeasurementAggregateValue, MeasurementEvaluationError> {
    let first = samples
        .first()
        .ok_or(MeasurementEvaluationError::EmptySamples {
            aggregation: "event_delta",
        })?;
    let last = samples
        .last()
        .ok_or(MeasurementEvaluationError::EmptySamples {
            aggregation: "event_delta",
        })?;
    match (first.borrow(), last.borrow()) {
        (MeasurementSampleValue::Signed(first), MeasurementSampleValue::Signed(last)) => last
            .checked_sub(*first)
            .map(MeasurementAggregateValue::Signed)
            .ok_or(MeasurementEvaluationError::ArithmeticOverflow),
        (MeasurementSampleValue::Unsigned(first), MeasurementSampleValue::Unsigned(last)) => last
            .checked_sub(*first)
            .map(MeasurementAggregateValue::Unsigned)
            .ok_or(MeasurementEvaluationError::ArithmeticOverflow),
        (MeasurementSampleValue::Rational(first), MeasurementSampleValue::Rational(last)) => last
            .checked_sub(*first)
            .map(MeasurementAggregateValue::Rational),
        _ => Err(MeasurementEvaluationError::ArithmeticOverflow),
    }
}

#[cfg(test)]
mod tests;

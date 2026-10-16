//! Bounded replay evaluation and exact aggregation for scenario measurements.
//!
//! The evaluator consumes authenticated scheduler entries plus already-
//! normalized typed samples. Guest protocol decoding and model-owned sample
//! projection remain separate producers; neither can bypass the scenario's
//! immutable measurement contracts.

use super::*;

mod boundary;
mod fold;
mod replay;

pub use replay::{MeasurementReplay, ModelSampleProjector};

/// Maximum scheduler entries accepted by the slice-based entry points.
///
/// [`MeasurementReplay`] streams entries and has no entry bound; this bound
/// applies only where a caller already holds the complete log in memory.
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
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
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
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
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
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
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

/// Admitted sample count and recomputed aggregate for one metric.
///
/// The aggregate is absent only when the window did not complete and admitted
/// no sample for an aggregation that is undefined on an empty window. A
/// completed window always carries its aggregate. The samples themselves are
/// a pure function of the replayed log and are not retained (RFC-0020
/// CMEAS-23).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct MeasurementMetricOutcome {
    samples: u64,
    aggregate: Option<MeasurementAggregateValue>,
}

impl MeasurementMetricOutcome {
    /// Returns how many samples the window admitted.
    #[must_use]
    pub const fn samples(&self) -> u64 {
        self.samples
    }

    /// Returns the recomputed exact aggregate.
    ///
    /// Returns `None` when an uncommitted window admitted no sample for a
    /// first, last, min, max, exact-mean, or event-delta aggregation.
    #[must_use]
    pub const fn aggregate(&self) -> Option<&MeasurementAggregateValue> {
        self.aggregate.as_ref()
    }
}

/// Replay result for one declared measurement.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
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
    definitions: ContentHash,
    outcomes: BTreeMap<MeasurementId, MeasurementOutcome>,
    id: ContentHash,
    canonical: Vec<u8>,
}

impl MeasurementEvaluation {
    /// Returns the exact scenario measurement-definition component.
    #[must_use]
    pub const fn definitions(&self) -> ContentHash {
        self.definitions
    }

    /// Returns outcomes in canonical measurement-ID order.
    #[must_use]
    pub const fn outcomes(&self) -> &BTreeMap<MeasurementId, MeasurementOutcome> {
        &self.outcomes
    }

    /// Returns the content address of this complete canonical evaluation.
    #[must_use]
    pub const fn content_hash(&self) -> ContentHash {
        self.id
    }

    /// Returns the exact language-neutral evaluation body.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }

    fn new(
        definitions: ContentHash,
        outcomes: BTreeMap<MeasurementId, MeasurementOutcome>,
    ) -> Result<Self, MeasurementEvaluationError> {
        preflight_evaluation_bytes(definitions, &outcomes)?;
        let canonical = canonical_evaluation_json(definitions, &outcomes)?;
        let id = ContentHash::from_canonical_hex_bytes(
            "crucible.model.measurement-evaluation.v3",
            &canonical,
        );
        Ok(Self {
            definitions,
            outcomes,
            id,
            canonical,
        })
    }
}

/// Stable failure while replaying or aggregating scenario measurements.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum MeasurementEvaluationError {
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
    },
    /// More than one value was supplied for a metric at one event.
    #[error("duplicate sample for measurement `{measurement}` metric `{metric}` at {sequence}")]
    DuplicateSample {
        /// Measurement ID.
        measurement: MeasurementId,
        /// Metric ID.
        metric: MetricId,
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
/// Returns [`MeasurementEvaluationError`] when the log is unauthenticated,
/// non-dense, or longer than [`MAX_MEASUREMENT_EVENT_ENTRIES`], or a
/// model-source event lacks a required typed attribute.
pub fn derive_model_measurement_samples(
    definitions: &MeasurementDefinitions,
    entries: &[SchedulerEventLogEntry],
) -> Result<Vec<MeasurementRuntimeSample>, MeasurementEvaluationError> {
    let mut samples = Vec::new();
    append_model_measurement_samples(definitions, entries, &mut samples)?;
    Ok(samples)
}

/// Appends model-owned samples to an independently normalized sample stream.
///
/// This slice path materializes every sample; it serves callers that already
/// hold a bounded log in memory. Streaming callers feed
/// [`ModelSampleProjector`] output straight into a [`MeasurementReplay`].
///
/// # Errors
///
/// Returns the same errors as [`derive_model_measurement_samples`].
pub fn append_model_measurement_samples(
    definitions: &MeasurementDefinitions,
    entries: &[SchedulerEventLogEntry],
    samples: &mut Vec<MeasurementRuntimeSample>,
) -> Result<(), MeasurementEvaluationError> {
    validate_measurement_event_log(entries)?;
    let projector = ModelSampleProjector::new(definitions);
    for entry in entries {
        projector.project(entry, samples)?;
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
    validate_measurement_event_log(entries)?;

    let mut by_sequence = BTreeMap::<u64, Vec<MeasurementRuntimeSample>>::new();
    for sample in samples {
        by_sequence.entry(sample.sequence).or_default().push(sample);
    }
    let mut replay = MeasurementReplay::new(definitions, terminal)?;
    for entry in entries {
        let carried = by_sequence.remove(&entry.sequence()).unwrap_or_default();
        replay.observe(entry, carried)?;
    }
    if let Some(sequence) = by_sequence.keys().next() {
        return Err(MeasurementEvaluationError::UnknownSampleSequence {
            sequence: *sequence,
        });
    }
    replay.finish()
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

/// Aggregates a complete sample list through the same fold replay uses.
#[cfg(test)]
fn aggregate_metric_samples(
    definition: &MetricDefinition,
    samples: &[MeasurementSampleValue],
) -> Result<MeasurementAggregateValue, MeasurementEvaluationError> {
    let mut fold = fold::MetricFold::new(definition);
    for sample in samples {
        fold.observe(sample);
    }
    fold.aggregate()
}

#[derive(serde::Serialize)]
struct MeasurementEvaluationBody<'a> {
    definitions: ContentHash,
    measurement: &'a BTreeMap<MeasurementId, MeasurementOutcome>,
}

fn canonical_evaluation_json(
    definitions: ContentHash,
    outcomes: &BTreeMap<MeasurementId, MeasurementOutcome>,
) -> Result<Vec<u8>, MeasurementEvaluationError> {
    serde_json::to_vec(&MeasurementEvaluationBody {
        definitions,
        measurement: outcomes,
    })
    .map_err(|error| MeasurementEvaluationError::CanonicalEncoding {
        reason: error.to_string(),
    })
}

fn preflight_evaluation_bytes(
    definitions: ContentHash,
    outcomes: &BTreeMap<MeasurementId, MeasurementOutcome>,
) -> Result<(), MeasurementEvaluationError> {
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
    encoded.map_err(|error| MeasurementEvaluationError::CanonicalEncoding {
        reason: error.to_string(),
    })
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

/// Validates the bounded authenticated scheduler log used by measurement replay.
///
/// Semantic adapters call this before interpreting or copying typed payloads so
/// forged and non-dense entries cannot enter producer-specific normalization.
///
/// # Errors
///
/// Returns [`MeasurementEvaluationError`] when the entry count exceeds its
/// deterministic bound, an entry hash is invalid, or sequences are not dense.
pub fn validate_measurement_event_log(
    entries: &[SchedulerEventLogEntry],
) -> Result<(), MeasurementEvaluationError> {
    if entries.len() > MAX_MEASUREMENT_EVENT_ENTRIES {
        return Err(MeasurementEvaluationError::LimitExceeded {
            limit: "measurement-event-entries",
        });
    }
    let mut previous: Option<u64> = None;
    for entry in entries {
        if !entry.has_valid_content_hash() {
            return Err(MeasurementEvaluationError::InvalidEventHash {
                sequence: entry.sequence(),
            });
        }
        if let Some(previous) = previous {
            let expected =
                previous
                    .checked_add(1)
                    .ok_or(MeasurementEvaluationError::NonDenseEventLog {
                        previous,
                        actual: entry.sequence(),
                    })?;
            if entry.sequence() != expected {
                return Err(MeasurementEvaluationError::NonDenseEventLog {
                    previous,
                    actual: entry.sequence(),
                });
            }
        }
        previous = Some(entry.sequence());
    }
    Ok(())
}

fn sample_matches_type(value: &MeasurementSampleValue, kind: &MetricValueType) -> bool {
    match (value, kind) {
        (MeasurementSampleValue::Signed(_), MetricValueType::SignedInteger)
        | (MeasurementSampleValue::Unsigned(_), MetricValueType::UnsignedInteger)
        | (MeasurementSampleValue::Rational(_), MetricValueType::ReducedRational)
        | (MeasurementSampleValue::Boolean(_), MetricValueType::Boolean) => true,
        (MeasurementSampleValue::Enumerated(value), MetricValueType::Enumerated { variants }) => {
            variants.binary_search(value).is_ok()
        }
        (
            MeasurementSampleValue::SignedVector(values),
            MetricValueType::IntegerVector {
                signed: true,
                maximum_elements,
            },
        ) => usize::try_from(*maximum_elements).is_ok_and(|maximum| values.len() <= maximum),
        (
            MeasurementSampleValue::UnsignedVector(values),
            MetricValueType::IntegerVector {
                signed: false,
                maximum_elements,
            },
        ) => usize::try_from(*maximum_elements).is_ok_and(|maximum| values.len() <= maximum),
        _ => false,
    }
}

#[cfg(test)]
mod tests;

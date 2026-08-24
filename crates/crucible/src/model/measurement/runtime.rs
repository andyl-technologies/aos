//! Bounded replay evaluation and exact aggregation for scenario measurements.
//!
//! The evaluator consumes authenticated scheduler entries plus already-
//! normalized typed samples. Guest protocol decoding and model-owned sample
//! projection remain separate producers; neither can bypass the scenario's
//! immutable measurement contracts.

use super::*;

mod boundary;

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
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
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
            "crucible.model.measurement-evaluation.v1",
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
/// Returns [`MeasurementEvaluationError`] when the log is unauthenticated or
/// non-dense, a model-source event lacks a required typed attribute, or the
/// deterministic visit, sample-count, or sample-byte bound is exceeded.
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
/// This is the bounded mixed-source path: the runtime sample-count and byte
/// limits apply to the existing guest samples plus newly derived model samples,
/// and no second model-sample vector is allocated.
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
    validate_event_log(entries)?;
    if samples.len() > MAX_MEASUREMENT_RUNTIME_SAMPLES {
        return Err(MeasurementEvaluationError::LimitExceeded {
            limit: "measurement-runtime-samples",
        });
    }

    let model_metrics = definitions
        .definitions()
        .iter()
        .flat_map(|definition| {
            definition
                .metrics
                .iter()
                .filter(|metric| metric.source != MetricSource::Guest)
                .map(move |metric| (&definition.id, metric))
        })
        .collect::<Vec<_>>();
    let visits = model_metrics.len().checked_mul(entries.len()).ok_or(
        MeasurementEvaluationError::LimitExceeded {
            limit: "model-measurement-event-visits",
        },
    )?;
    if visits > MAX_MODEL_MEASUREMENT_EVENT_VISITS {
        return Err(MeasurementEvaluationError::LimitExceeded {
            limit: "model-measurement-event-visits",
        });
    }

    let remaining = MAX_MEASUREMENT_RUNTIME_SAMPLES
        .checked_sub(samples.len())
        .ok_or(MeasurementEvaluationError::LimitExceeded {
            limit: "measurement-runtime-samples",
        })?;
    samples.reserve(visits.min(remaining).min(4_096));
    let mut sample_bytes = preflight_runtime_sample_bytes(samples)?;
    for (measurement, metric) in model_metrics {
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
                measurement.clone(),
                metric.id.clone(),
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
            .icount
            .node
            .as_ref()
            .filter(|stamped| *stamped == node)
            .map(|_node| entry.time().icount.icount.retired),
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
    validate_event_log(entries)?;
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
    let samples = validate_and_index_samples(definitions, entries, samples)?;
    let mut outcomes = BTreeMap::new();
    for definition in definitions.definitions() {
        let window = evaluate_window(definition, entries, terminal)?;
        let mut metrics = BTreeMap::new();
        for metric in &definition.metrics {
            let retained = samples
                .get(&(definition.id.clone(), metric.id.clone()))
                .into_iter()
                .flatten()
                .filter(|sample| {
                    event_for_sequence(entries, sample.sequence)
                        .is_some_and(|entry| window.includes_entry(entry))
                })
                .cloned()
                .collect::<Vec<_>>();
            let aggregate = aggregate_metric_samples(
                metric,
                &retained
                    .iter()
                    .map(|sample| sample.value.clone())
                    .collect::<Vec<_>>(),
            )?;
            let evidence = retained
                .iter()
                .map(|sample| {
                    event_for_sequence(entries, sample.sequence)
                        .map(SchedulerEventLogEntry::content_hash)
                        .ok_or(MeasurementEvaluationError::UnknownSampleSequence {
                            sequence: sample.sequence,
                        })
                })
                .collect::<Result<Vec<_>, _>>()?;
            metrics.insert(
                metric.id.clone(),
                MeasurementMetricOutcome {
                    samples: retained,
                    aggregate,
                    evidence,
                },
            );
        }
        outcomes.insert(
            definition.id.clone(),
            MeasurementOutcome { window, metrics },
        );
    }
    MeasurementEvaluation::new(definitions.content_hash(), outcomes)
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
fn aggregate_metric_samples(
    definition: &MetricDefinition,
    samples: &[MeasurementSampleValue],
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
        Aggregation::First => samples.first().cloned().map(Into::into).ok_or(
            MeasurementEvaluationError::EmptySamples {
                aggregation: "first",
            },
        ),
        Aggregation::Last => samples.last().cloned().map(Into::into).ok_or(
            MeasurementEvaluationError::EmptySamples {
                aggregation: "last",
            },
        ),
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
) -> Result<Vec<u8>, MeasurementEvaluationError> {
    serde_json::to_vec(&MeasurementEvaluationBody {
        definitions,
        measurement: outcomes,
    })
    .map_err(|error| MeasurementEvaluationError::CanonicalEncoding {
        reason: error.to_string(),
    })
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
    encoded.map_err(|error| MeasurementEvaluationError::CanonicalEncoding {
        reason: error.to_string(),
    })?;
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
    encoded.map_err(|error| MeasurementEvaluationError::CanonicalEncoding {
        reason: error.to_string(),
    })?;
    Ok(counter.length)
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

fn validate_event_log(
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

fn validate_terminal_state(
    entries: &[SchedulerEventLogEntry],
    terminal: &MeasurementTerminalState,
) -> Result<(), MeasurementEvaluationError> {
    if terminal.node_icounts.len() > MAX_MEASUREMENT_TERMINAL_NODES {
        return Err(MeasurementEvaluationError::LimitExceeded {
            limit: "measurement-terminal-nodes",
        });
    }
    for entry in entries {
        if entry.at() > terminal.at {
            return Err(MeasurementEvaluationError::TerminalBeforeEvent {
                sequence: entry.sequence(),
            });
        }
        if let Some(node) = &entry.time().icount.node
            && terminal
                .node_icounts
                .get(node)
                .is_some_and(|terminal| terminal.retired < entry.time().icount.icount.retired)
        {
            return Err(MeasurementEvaluationError::TerminalIcountRegression {
                node: node.clone(),
            });
        }
    }
    if terminal
        .scenario_ready_at
        .is_some_and(|ready| ready > terminal.at)
    {
        return Err(MeasurementEvaluationError::TerminalBeforeEvent {
            sequence: entries.last().map_or(0, SchedulerEventLogEntry::sequence),
        });
    }
    Ok(())
}

fn boundary_node_count(selector: &BoundarySelector) -> Result<usize, MeasurementEvaluationError> {
    let children = match selector {
        BoundarySelector::All { selectors } | BoundarySelector::Any { selectors } => selectors,
        _ => return Ok(1),
    };
    children.iter().try_fold(1_usize, |total, child| {
        total.checked_add(boundary_node_count(child)?).ok_or(
            MeasurementEvaluationError::LimitExceeded {
                limit: "measurement-event-visits",
            },
        )
    })
}

type SampleIndex = BTreeMap<(MeasurementId, MetricId), Vec<MeasurementRuntimeSample>>;

fn validate_and_index_samples(
    definitions: &MeasurementDefinitions,
    entries: &[SchedulerEventLogEntry],
    mut samples: Vec<MeasurementRuntimeSample>,
) -> Result<SampleIndex, MeasurementEvaluationError> {
    samples.sort_by(|left, right| {
        (left.sequence, &left.measurement, &left.metric).cmp(&(
            right.sequence,
            &right.measurement,
            &right.metric,
        ))
    });
    let definitions_by_id = definitions
        .definitions()
        .iter()
        .map(|definition| (&definition.id, definition))
        .collect::<BTreeMap<_, _>>();
    let mut indexed = BTreeMap::<_, Vec<_>>::new();
    let mut previous: Option<(u64, &MeasurementId, &MetricId)> = None;
    for sample in &samples {
        if event_for_sequence(entries, sample.sequence).is_none() {
            return Err(MeasurementEvaluationError::UnknownSampleSequence {
                sequence: sample.sequence,
            });
        }
        if previous
            .as_ref()
            .is_some_and(|(sequence, measurement, metric)| {
                *sequence == sample.sequence
                    && *measurement == &sample.measurement
                    && *metric == &sample.metric
            })
        {
            return Err(MeasurementEvaluationError::DuplicateSample {
                measurement: sample.measurement.clone(),
                metric: sample.metric.clone(),
                sequence: sample.sequence,
            });
        }
        let definition = definitions_by_id.get(&sample.measurement).ok_or_else(|| {
            MeasurementEvaluationError::UnknownSampleTarget {
                kind: "measurement",
                id: sample.measurement.as_str().to_owned(),
            }
        })?;
        let metric = definition
            .metrics
            .iter()
            .find(|metric| metric.id == sample.metric)
            .ok_or_else(|| MeasurementEvaluationError::UnknownSampleTarget {
                kind: "metric",
                id: sample.metric.as_str().to_owned(),
            })?;
        if !sample_matches_type(&sample.value, &metric.value_type) {
            return Err(MeasurementEvaluationError::SampleTypeMismatch {
                measurement: sample.measurement.clone(),
                metric: sample.metric.clone(),
            });
        }
        previous = Some((sample.sequence, &sample.measurement, &sample.metric));
    }
    for sample in samples {
        indexed
            .entry((sample.measurement.clone(), sample.metric.clone()))
            .or_default()
            .push(sample);
    }
    Ok(indexed)
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

fn event_for_sequence(
    entries: &[SchedulerEventLogEntry],
    sequence: u64,
) -> Option<&SchedulerEventLogEntry> {
    let first = entries.first()?.sequence();
    let index = sequence
        .checked_sub(first)
        .and_then(|value| usize::try_from(value).ok())?;
    entries
        .get(index)
        .filter(|entry| entry.sequence() == sequence)
}

fn aggregate_sum(
    value_type: &MetricValueType,
    samples: &[MeasurementSampleValue],
) -> Result<MeasurementAggregateValue, MeasurementEvaluationError> {
    match value_type {
        MetricValueType::SignedInteger => samples
            .iter()
            .try_fold(0_i64, |total, sample| match sample {
                MeasurementSampleValue::Signed(value) => total
                    .checked_add(*value)
                    .ok_or(MeasurementEvaluationError::ArithmeticOverflow),
                _ => Err(MeasurementEvaluationError::ArithmeticOverflow),
            })
            .map(MeasurementAggregateValue::Signed),
        MetricValueType::UnsignedInteger => samples
            .iter()
            .try_fold(0_u64, |total, sample| match sample {
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
                |total, sample| match sample {
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

fn aggregate_extreme(
    samples: &[MeasurementSampleValue],
    desired: std::cmp::Ordering,
) -> Result<MeasurementAggregateValue, MeasurementEvaluationError> {
    let mut selected =
        samples
            .first()
            .cloned()
            .ok_or(MeasurementEvaluationError::EmptySamples {
                aggregation: if desired == std::cmp::Ordering::Less {
                    "min"
                } else {
                    "max"
                },
            })?;
    for sample in &samples[1..] {
        let ordering = compare_samples(sample, &selected)?;
        if ordering == desired {
            selected = sample.clone();
        }
    }
    Ok(selected.into())
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

fn aggregate_mean(
    samples: &[MeasurementSampleValue],
) -> Result<MeasurementAggregateValue, MeasurementEvaluationError> {
    if samples.is_empty() {
        return Err(MeasurementEvaluationError::EmptySamples {
            aggregation: "exact_mean",
        });
    }
    let total = samples
        .iter()
        .try_fold(ReducedRational::from_unsigned(0), |total, sample| {
            let value = match sample {
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

fn aggregate_histogram(
    samples: &[MeasurementSampleValue],
    upper_bounds: &[i64],
) -> Result<MeasurementAggregateValue, MeasurementEvaluationError> {
    let mut bins = vec![0_u64; upper_bounds.len().saturating_add(1)];
    for sample in samples {
        let bin = match sample {
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

fn aggregate_delta(
    samples: &[MeasurementSampleValue],
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
    match (first, last) {
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

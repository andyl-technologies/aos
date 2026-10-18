//! Typed authentication and concrete indexing of measurement replay inputs.

use super::*;

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
        if !entry
            .has_valid_content_hash()
            .map_err(MeasurementEvaluationError::from)?
        {
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

pub(super) fn validate_terminal_state(
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
        if let Some(node) = &entry.time().stamp.node
            && terminal
                .node_icounts
                .get(node)
                .zip(entry.time().stamp.retired)
                .is_some_and(|(terminal, observed)| terminal.retired < observed.retired)
        {
            return Err(MeasurementEvaluationError::TerminalIcountRegression {
                node: ownership::copy_node(node)?,
                custody: crate::owned_decode::require_current_custody()
                    .map_err(MeasurementEvaluationError::OriginalAdmission)?,
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

pub(super) fn boundary_node_count(
    selector: &BoundarySelector,
) -> Result<usize, MeasurementEvaluationError> {
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

type SampleIndex<'a> = BTreeMap<(&'a MeasurementId, &'a MetricId), Vec<MeasurementRuntimeSample>>;

pub(super) fn validate_and_index_samples<'a>(
    definitions: &'a MeasurementDefinitions,
    entries: &[SchedulerEventLogEntry],
    mut samples: Vec<MeasurementRuntimeSample>,
) -> Result<SampleIndex<'a>, MeasurementEvaluationError> {
    samples.sort_unstable_by(|left, right| {
        (left.sequence, &left.measurement, &left.metric).cmp(&(
            right.sequence,
            &right.measurement,
            &right.metric,
        ))
    });
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
                measurement: ownership::copy_measurement(&sample.measurement)?,
                metric: ownership::copy_metric(&sample.metric)?,
                custody: crate::owned_decode::require_current_custody()
                    .map_err(MeasurementEvaluationError::OriginalAdmission)?,
                sequence: sample.sequence,
            });
        }
        let Ok(index) = definitions
            .definitions()
            .binary_search_by(|definition| definition.id.cmp(&sample.measurement))
        else {
            return Err(ownership::unknown_target(
                "measurement",
                sample.measurement.as_str(),
            )?);
        };
        let definition = &definitions.definitions()[index];
        let Some(metric) = definition
            .metrics
            .iter()
            .find(|metric| metric.id == sample.metric)
        else {
            return Err(ownership::unknown_target("metric", sample.metric.as_str())?);
        };
        if !sample_matches_type(&sample.value, &metric.value_type) {
            return Err(MeasurementEvaluationError::SampleTypeMismatch {
                measurement: ownership::copy_measurement(&sample.measurement)?,
                metric: ownership::copy_metric(&sample.metric)?,
                custody: crate::owned_decode::require_current_custody()
                    .map_err(MeasurementEvaluationError::OriginalAdmission)?,
            });
        }
        previous = Some((sample.sequence, &sample.measurement, &sample.metric));
    }
    for sample in samples {
        // Validation above proves that these borrowed keys are declared. Moving
        // the sample preserves its original producer allocation and avoids a
        // second copy of vector or enumerated values.
        let index = definitions
            .definitions()
            .binary_search_by(|definition| definition.id.cmp(&sample.measurement))
            .map_err(|_| MeasurementEvaluationError::ReplayMismatch)?;
        let definition = &definitions.definitions()[index];
        let metric = definition
            .metrics
            .iter()
            .find(|metric| metric.id == sample.metric)
            .ok_or(MeasurementEvaluationError::ReplayMismatch)?;
        let key = (&definition.id, &metric.id);
        if !indexed.contains_key(&key) {
            ownership::tree_entry::<(&MeasurementId, &MetricId), Vec<MeasurementRuntimeSample>>()?;
        }
        let group = indexed.entry(key).or_default();
        ownership::reserve(group, 1)?;
        group.push(sample);
    }
    Ok(indexed)
}

pub(super) fn sample_matches_type(value: &MeasurementSampleValue, kind: &MetricValueType) -> bool {
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

pub(super) fn event_for_sequence(
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

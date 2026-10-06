//! Strict projection of guest protocol events into measurement samples.

use super::*;

pub(super) fn normalize_guest_measurements(
    definitions: &MeasurementDefinitions,
    entries: &[SchedulerEventLogEntry],
) -> Result<Vec<MeasurementRuntimeSample>, CrucibleMeasurementError> {
    let definitions_by_id = definitions.definitions();
    let mut open = BTreeSet::<(&NodeId, &MeasurementId, &MeasurementInstanceKey)>::new();
    let mut samples = Vec::new();
    let mut sample_work_bytes = 0usize;

    for entry in entries {
        match entry.payload() {
            SchedulerEventLogPayload::Observable(ObservableEventPayload::GuestMeasurement {
                node,
                event,
                ..
            }) => match event {
                GuestMeasurementEvent::Begin {
                    measurement,
                    instance,
                } => {
                    let (measurement, instance, definition) = guest_measurement_basis(
                        definitions_by_id,
                        node,
                        measurement,
                        instance,
                        entry.sequence(),
                    )?;
                    if open.len() >= MAX_OPEN_GUEST_MEASUREMENT_INSTANCES {
                        return Err(guest_measurement_error(
                            entry.sequence(),
                            "open measurement instance limit exceeded",
                        ));
                    }
                    if open.contains(&(node, measurement, instance)) {
                        return Err(guest_measurement_error(
                            entry.sequence(),
                            format_args!(
                                "measurement `{}` instance is already open",
                                definition.id
                            ),
                        ));
                    }
                    crucible::owned_decode::charge_btree_set_entry::<(
                        &NodeId,
                        &MeasurementId,
                        &MeasurementInstanceKey,
                    )>()
                    .map_err(admission)?;
                    open.insert((node, measurement, instance));
                }
                GuestMeasurementEvent::Sample {
                    measurement,
                    instance,
                    metric,
                    value,
                } => {
                    let (measurement, instance, definition) = guest_measurement_basis(
                        definitions_by_id,
                        node,
                        measurement,
                        instance,
                        entry.sequence(),
                    )?;
                    if !open.contains(&(node, measurement, instance)) {
                        return Err(guest_measurement_error(
                            entry.sequence(),
                            format_args!("measurement `{measurement}` instance is not open"),
                        ));
                    }
                    validate_protocol_identifier(metric, entry.sequence(), "metric")?;
                    let contract = definition
                        .metrics
                        .iter()
                        .find(|candidate| candidate.id.as_str() == metric)
                        .ok_or_else(|| {
                            guest_measurement_error(
                                entry.sequence(),
                                format_args!(
                                    "measurement `{measurement}` does not declare metric `{metric}`"
                                ),
                            )
                        })?;
                    if contract.source != MetricSource::Guest {
                        return Err(guest_measurement_error(
                            entry.sequence(),
                            format_args!("metric `{metric}` is not guest-sourced"),
                        ));
                    }
                    if samples.len() == MAX_MEASUREMENT_RUNTIME_SAMPLES {
                        return Err(crucible::model::MeasurementEvaluationError::LimitExceeded {
                            limit: "measurement-runtime-samples",
                        }
                        .into());
                    }
                    validate_guest_measurement_value(value, contract)
                        .map_err(|error| guest_measurement_error(entry.sequence(), error))?;
                    sample_work_bytes = sample_work_bytes
                        .checked_add(guest_sample_normalization_work(
                            measurement.as_str(),
                            metric.as_str(),
                            value,
                        )?)
                        .ok_or(crucible::model::MeasurementEvaluationError::LimitExceeded {
                            limit: "measurement-runtime-sample-bytes",
                        })?;
                    if sample_work_bytes > MAX_MEASUREMENT_RUNTIME_SAMPLE_BYTES {
                        return Err(crucible::model::MeasurementEvaluationError::LimitExceeded {
                            limit: "measurement-runtime-sample-bytes",
                        }
                        .into());
                    }
                    let value =
                        normalize_guest_measurement_value(value).map_err(|error| match error {
                            GuestMeasurementValueError::OriginalAdmission(source) => {
                                admission(source)
                            }
                            source => guest_measurement_error(entry.sequence(), source),
                        })?;
                    crucible::owned_decode::reserve_vec(&mut samples, 1).map_err(admission)?;
                    samples.push(MeasurementRuntimeSample::new(
                        entry.sequence(),
                        MeasurementId::parse(
                            crucible::owned_decode::display_string(measurement)
                                .map_err(admission)?,
                        )
                        .map_err(|error| guest_measurement_error(entry.sequence(), error))?,
                        MetricId::parse(
                            crucible::owned_decode::display_string(&contract.id)
                                .map_err(admission)?,
                        )
                        .map_err(|error| guest_measurement_error(entry.sequence(), error))?,
                        value,
                    ));
                }
                GuestMeasurementEvent::End {
                    measurement,
                    instance,
                } => {
                    let (measurement, instance, _definition) = guest_measurement_basis(
                        definitions_by_id,
                        node,
                        measurement,
                        instance,
                        entry.sequence(),
                    )?;
                    if !open.remove(&(node, measurement, instance)) {
                        return Err(guest_measurement_error(
                            entry.sequence(),
                            format_args!("measurement `{measurement}` instance is not open"),
                        ));
                    }
                }
            },
            SchedulerEventLogPayload::Observable(ObservableEventPayload::GuestSemanticMarker {
                node,
                marker,
                instance,
                ..
            }) => {
                validate_protocol_identifier(marker, entry.sequence(), "semantic marker")?;
                validate_protocol_identifier(instance, entry.sequence(), "marker instance")?;
                if !definitions.definitions().iter().any(|definition| {
                    cohort_contains(&definition.cohort, node)
                        && (boundary_accepts_semantic_marker(&definition.begin, marker, instance)
                            || boundary_accepts_semantic_marker(&definition.end, marker, instance))
                }) {
                    return Err(guest_measurement_error(
                        entry.sequence(),
                        format_args!(
                            "semantic marker `{marker}` instance `{instance}` is not declared"
                        ),
                    ));
                }
            }
            _ => {}
        }
    }

    if let Some((_node, measurement, instance)) = open.into_iter().next() {
        return Err(guest_measurement_error(
            entries
                .last()
                .map_or(0, SchedulerEventLogEntry::sequence)
                .saturating_add(1),
            format_args!("measurement `{measurement}` instance `{instance}` was not ended"),
        ));
    }
    Ok(samples)
}

fn guest_measurement_basis<'a>(
    definitions: &'a [MeasurementDefinition],
    node: &NodeId,
    measurement: &str,
    instance: &str,
    sequence: u64,
) -> Result<
    (
        &'a MeasurementId,
        &'a MeasurementInstanceKey,
        &'a MeasurementDefinition,
    ),
    CrucibleMeasurementError,
> {
    validate_protocol_identifier(measurement, sequence, "measurement")?;
    validate_protocol_identifier(instance, sequence, "measurement instance")?;
    let definition = definitions
        .binary_search_by(|definition| definition.id.as_str().cmp(measurement))
        .ok()
        .and_then(|index| definitions.get(index))
        .ok_or_else(|| {
            guest_measurement_error(
                sequence,
                format_args!("measurement `{measurement}` is not declared"),
            )
        })?;
    if !cohort_contains(&definition.cohort, node) {
        return Err(guest_measurement_error(
            sequence,
            format_args!(
                "node `{}` is outside measurement `{measurement}` cohort",
                node.name
            ),
        ));
    }
    let expected_instance = guest_measurement_instance(definition, sequence)?;
    if instance != expected_instance.as_str() {
        return Err(guest_measurement_error(
            sequence,
            format_args!(
                "measurement `{measurement}` requires instance `{expected_instance}`, got `{instance}`"
            ),
        ));
    }
    Ok((&definition.id, expected_instance, definition))
}

fn guest_measurement_instance(
    definition: &MeasurementDefinition,
    sequence: u64,
) -> Result<&MeasurementInstanceKey, CrucibleMeasurementError> {
    let mut candidate = None;
    if !collect_boundary_instance(&definition.begin, &mut candidate)
        || !collect_boundary_instance(&definition.end, &mut candidate)
    {
        return Err(guest_measurement_error(
            sequence,
            format_args!(
                "guest-sourced measurement `{}` declares conflicting marker instances",
                definition.id
            ),
        ));
    }
    candidate.ok_or_else(|| {
        guest_measurement_error(
            sequence,
            format_args!(
                "guest-sourced measurement `{}` does not declare an exact marker instance",
                definition.id
            ),
        )
    })
}

fn collect_boundary_instance<'a>(
    selector: &'a BoundarySelector,
    candidate: &mut Option<&'a MeasurementInstanceKey>,
) -> bool {
    match selector {
        BoundarySelector::GuestMarker {
            instance: Some(instance),
            ..
        } => {
            if candidate.is_some_and(|existing| existing != instance) {
                return false;
            }
            *candidate = Some(instance);
            true
        }
        BoundarySelector::All { selectors } | BoundarySelector::Any { selectors } => selectors
            .iter()
            .all(|selector| collect_boundary_instance(selector, candidate)),
        _ => true,
    }
}

fn cohort_contains(cohort: &CohortPolicy, node: &NodeId) -> bool {
    match cohort {
        CohortPolicy::All(nodes) | CohortPolicy::Any(nodes) => nodes.binary_search(node).is_ok(),
        CohortPolicy::Quorum { nodes, .. } => nodes.binary_search(node).is_ok(),
    }
}

#[derive(Debug, thiserror::Error)]
pub(super) enum GuestMeasurementValueError<'a> {
    #[error(transparent)]
    OriginalAdmission(#[from] crucible::owned_decode::DecodeAdmissionError),
    #[error(transparent)]
    InvalidRational(#[from] crucible::model::MeasurementEvaluationError),
    #[error("rational sample is not canonical reduced form")]
    NonCanonicalRational,
    #[error("metric `{metric}` value violates its declared type or guest protocol bound")]
    ContractMismatch { metric: &'a MetricId },
}

fn normalize_guest_measurement_value(
    value: &GuestMeasurementValue,
) -> Result<MeasurementSampleValue, GuestMeasurementValueError<'static>> {
    match value {
        GuestMeasurementValue::Signed(value) => Ok(MeasurementSampleValue::Signed(*value)),
        GuestMeasurementValue::Unsigned(value) => Ok(MeasurementSampleValue::Unsigned(*value)),
        GuestMeasurementValue::Rational(value) => {
            let reduced = ReducedRational::new(value.negative, value.numerator, value.denominator)?;
            if reduced.is_negative() != value.negative
                || reduced.numerator() != value.numerator
                || reduced.denominator() != value.denominator
            {
                return Err(GuestMeasurementValueError::NonCanonicalRational);
            }
            Ok(MeasurementSampleValue::Rational(reduced))
        }
        GuestMeasurementValue::Boolean(value) => Ok(MeasurementSampleValue::Boolean(*value)),
        GuestMeasurementValue::Enumerated(value) => Ok(MeasurementSampleValue::Enumerated(
            crucible::owned_decode::display_string(value)
                .map_err(GuestMeasurementValueError::OriginalAdmission)?,
        )),
        GuestMeasurementValue::SignedVector(value) => {
            let mut copied = Vec::new();
            crucible::owned_decode::reserve_vec(&mut copied, value.len())
                .map_err(GuestMeasurementValueError::OriginalAdmission)?;
            copied.extend_from_slice(value);
            Ok(MeasurementSampleValue::SignedVector(copied))
        }
        GuestMeasurementValue::UnsignedVector(value) => {
            let mut copied = Vec::new();
            crucible::owned_decode::reserve_vec(&mut copied, value.len())
                .map_err(GuestMeasurementValueError::OriginalAdmission)?;
            copied.extend_from_slice(value);
            Ok(MeasurementSampleValue::UnsignedVector(copied))
        }
    }
}

pub(super) fn validate_guest_measurement_value<'a>(
    value: &GuestMeasurementValue,
    metric: &'a MetricDefinition,
) -> Result<(), GuestMeasurementValueError<'a>> {
    let valid = match (value, &metric.value_type) {
        (GuestMeasurementValue::Signed(_), MetricValueType::SignedInteger)
        | (GuestMeasurementValue::Unsigned(_), MetricValueType::UnsignedInteger)
        | (GuestMeasurementValue::Rational(_), MetricValueType::ReducedRational)
        | (GuestMeasurementValue::Boolean(_), MetricValueType::Boolean) => true,
        (GuestMeasurementValue::Enumerated(value), MetricValueType::Enumerated { variants }) => {
            value.len() <= WHITEBOX_MEASUREMENT_IDENTIFIER_MAX_BYTES
                && variants.binary_search(value).is_ok()
        }
        (
            GuestMeasurementValue::SignedVector(values),
            MetricValueType::IntegerVector {
                signed: true,
                maximum_elements,
            },
        ) => {
            values.len() <= WHITEBOX_MEASUREMENT_VECTOR_MAX_ELEMENTS
                && values.len() <= *maximum_elements as usize
        }
        (
            GuestMeasurementValue::UnsignedVector(values),
            MetricValueType::IntegerVector {
                signed: false,
                maximum_elements,
            },
        ) => {
            values.len() <= WHITEBOX_MEASUREMENT_VECTOR_MAX_ELEMENTS
                && values.len() <= *maximum_elements as usize
        }
        _ => false,
    };
    if !valid {
        return Err(GuestMeasurementValueError::ContractMismatch { metric: &metric.id });
    }
    Ok(())
}

fn guest_sample_normalization_work(
    measurement: &str,
    metric: &str,
    value: &GuestMeasurementValue,
) -> Result<usize, CrucibleMeasurementError> {
    let value_bytes = match value {
        GuestMeasurementValue::Signed(_)
        | GuestMeasurementValue::Unsigned(_)
        | GuestMeasurementValue::Rational(_)
        | GuestMeasurementValue::Boolean(_) => 64,
        GuestMeasurementValue::Enumerated(value) => value.len(),
        GuestMeasurementValue::SignedVector(values) => values.len().saturating_mul(21),
        GuestMeasurementValue::UnsignedVector(values) => values.len().saturating_mul(20),
    };
    256usize
        .checked_add(measurement.len())
        .and_then(|bytes| bytes.checked_add(metric.len()))
        .and_then(|bytes| bytes.checked_add(value_bytes))
        .ok_or_else(|| {
            crucible::model::MeasurementEvaluationError::LimitExceeded {
                limit: "measurement-runtime-sample-bytes",
            }
            .into()
        })
}

fn validate_protocol_identifier(
    value: &str,
    sequence: u64,
    kind: &'static str,
) -> Result<(), CrucibleMeasurementError> {
    if kind != "semantic marker"
        && (value.is_empty()
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/' | b':')
            }))
    {
        return Err(guest_measurement_error(
            sequence,
            format_args!("invalid {kind} identifier `{value}`"),
        ));
    }
    if value.len() > WHITEBOX_MEASUREMENT_IDENTIFIER_MAX_BYTES {
        return Err(guest_measurement_error(
            sequence,
            format_args!(
                "{kind} identifier exceeds {} bytes",
                WHITEBOX_MEASUREMENT_IDENTIFIER_MAX_BYTES
            ),
        ));
    }
    Ok(())
}

fn boundary_accepts_semantic_marker(
    selector: &BoundarySelector,
    marker: &str,
    instance: &str,
) -> bool {
    match selector {
        BoundarySelector::GuestMarker {
            marker: expected,
            instance: Some(expected_instance),
        } => expected.name == marker && expected_instance.as_str() == instance,
        BoundarySelector::All { selectors } | BoundarySelector::Any { selectors } => selectors
            .iter()
            .any(|selector| boundary_accepts_semantic_marker(selector, marker, instance)),
        _ => false,
    }
}

fn guest_measurement_error(
    sequence: u64,
    reason: impl std::fmt::Display,
) -> CrucibleMeasurementError {
    let custody = match require_current_custody() {
        Ok(custody) => custody,
        Err(source) => return admission(source),
    };
    match crucible::owned_decode::display_string(&reason) {
        Ok(reason) => CrucibleMeasurementError::GuestMeasurementProtocol {
            sequence,
            reason,
            custody,
        },
        Err(source) => admission(source),
    }
}

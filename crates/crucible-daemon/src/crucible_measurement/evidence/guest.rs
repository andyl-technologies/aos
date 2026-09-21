//! Strict projection of guest protocol events into measurement samples.

use super::*;

pub(super) fn normalize_guest_measurements(
    definitions: &MeasurementDefinitions,
    entries: &[SchedulerEventLogEntry],
) -> Result<Vec<MeasurementRuntimeSample>, CrucibleMeasurementError> {
    let definitions_by_id = definitions
        .definitions()
        .iter()
        .map(|definition| (definition.id.clone(), definition))
        .collect::<BTreeMap<_, _>>();
    let mut open = BTreeSet::<(NodeId, MeasurementId, MeasurementInstanceKey)>::new();
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
                        &definitions_by_id,
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
                    if !open.insert((node.clone(), measurement, instance)) {
                        return Err(guest_measurement_error(
                            entry.sequence(),
                            format!("measurement `{}` instance is already open", definition.id),
                        ));
                    }
                }
                GuestMeasurementEvent::Sample {
                    measurement,
                    instance,
                    metric,
                    value,
                } => {
                    let (measurement, instance, definition) = guest_measurement_basis(
                        &definitions_by_id,
                        node,
                        measurement,
                        instance,
                        entry.sequence(),
                    )?;
                    if !open.contains(&(node.clone(), measurement.clone(), instance)) {
                        return Err(guest_measurement_error(
                            entry.sequence(),
                            format!("measurement `{measurement}` instance is not open"),
                        ));
                    }
                    validate_protocol_identifier(metric, entry.sequence(), "metric")?;
                    let metric = MetricId::parse(metric.clone()).map_err(|error| {
                        guest_measurement_error(entry.sequence(), error.to_string())
                    })?;
                    let contract = definition
                        .metrics
                        .iter()
                        .find(|candidate| candidate.id == metric)
                        .ok_or_else(|| {
                            guest_measurement_error(
                                entry.sequence(),
                                format!(
                                    "measurement `{measurement}` does not declare metric `{metric}`"
                                ),
                            )
                        })?;
                    if contract.source != MetricSource::Guest {
                        return Err(guest_measurement_error(
                            entry.sequence(),
                            format!("metric `{metric}` is not guest-sourced"),
                        ));
                    }
                    if samples.len() == MAX_MEASUREMENT_RUNTIME_SAMPLES {
                        return Err(crucible::model::MeasurementEvaluationError::LimitExceeded {
                            limit: "measurement-runtime-samples",
                        }
                        .into());
                    }
                    validate_guest_measurement_value(value, contract).map_err(|error| {
                        guest_measurement_error(entry.sequence(), error.to_string())
                    })?;
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
                    let value = normalize_guest_measurement_value(value).map_err(|error| {
                        guest_measurement_error(entry.sequence(), error.to_string())
                    })?;
                    samples.push(MeasurementRuntimeSample::new(
                        entry.sequence(),
                        measurement,
                        metric,
                        value,
                    ));
                }
                GuestMeasurementEvent::End {
                    measurement,
                    instance,
                } => {
                    let (measurement, instance, _definition) = guest_measurement_basis(
                        &definitions_by_id,
                        node,
                        measurement,
                        instance,
                        entry.sequence(),
                    )?;
                    if !open.remove(&(node.clone(), measurement.clone(), instance)) {
                        return Err(guest_measurement_error(
                            entry.sequence(),
                            format!("measurement `{measurement}` instance is not open"),
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
                let instance =
                    MeasurementInstanceKey::parse(instance.clone()).map_err(|error| {
                        guest_measurement_error(entry.sequence(), error.to_string())
                    })?;
                if !definitions.definitions().iter().any(|definition| {
                    cohort_contains(&definition.cohort, node)
                        && (boundary_accepts_semantic_marker(&definition.begin, marker, &instance)
                            || boundary_accepts_semantic_marker(&definition.end, marker, &instance))
                }) {
                    return Err(guest_measurement_error(
                        entry.sequence(),
                        format!("semantic marker `{marker}` instance `{instance}` is not declared"),
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
            format!("measurement `{measurement}` instance `{instance}` was not ended"),
        ));
    }
    Ok(samples)
}

fn guest_measurement_basis<'a>(
    definitions: &'a BTreeMap<MeasurementId, &'a MeasurementDefinition>,
    node: &NodeId,
    measurement: &str,
    instance: &str,
    sequence: u64,
) -> Result<
    (
        MeasurementId,
        MeasurementInstanceKey,
        &'a MeasurementDefinition,
    ),
    CrucibleMeasurementError,
> {
    validate_protocol_identifier(measurement, sequence, "measurement")?;
    validate_protocol_identifier(instance, sequence, "measurement instance")?;
    let measurement = MeasurementId::parse(measurement.to_owned())
        .map_err(|error| guest_measurement_error(sequence, error.to_string()))?;
    let instance = MeasurementInstanceKey::parse(instance.to_owned())
        .map_err(|error| guest_measurement_error(sequence, error.to_string()))?;
    let definition = definitions.get(&measurement).copied().ok_or_else(|| {
        guest_measurement_error(
            sequence,
            format!("measurement `{measurement}` is not declared"),
        )
    })?;
    if !cohort_contains(&definition.cohort, node) {
        return Err(guest_measurement_error(
            sequence,
            format!(
                "node `{}` is outside measurement `{measurement}` cohort",
                node.name
            ),
        ));
    }
    let expected_instance = guest_measurement_instance(definition, sequence)?;
    if &instance != expected_instance {
        return Err(guest_measurement_error(
            sequence,
            format!(
                "measurement `{measurement}` requires instance `{expected_instance}`, got `{instance}`"
            ),
        ));
    }
    Ok((measurement, instance, definition))
}

fn guest_measurement_instance(
    definition: &MeasurementDefinition,
    sequence: u64,
) -> Result<&MeasurementInstanceKey, CrucibleMeasurementError> {
    let mut instances = BTreeSet::new();
    collect_boundary_instances(&definition.begin, &mut instances);
    collect_boundary_instances(&definition.end, &mut instances);
    let mut instances = instances.into_iter();
    let Some(instance) = instances.next() else {
        return Err(guest_measurement_error(
            sequence,
            format!(
                "guest-sourced measurement `{}` does not declare an exact marker instance",
                definition.id
            ),
        ));
    };
    if instances.next().is_some() {
        return Err(guest_measurement_error(
            sequence,
            format!(
                "guest-sourced measurement `{}` declares conflicting marker instances",
                definition.id
            ),
        ));
    }
    Ok(instance)
}

fn collect_boundary_instances<'a>(
    selector: &'a BoundarySelector,
    instances: &mut BTreeSet<&'a MeasurementInstanceKey>,
) {
    match selector {
        BoundarySelector::GuestMarker {
            instance: Some(instance),
            ..
        } => {
            instances.insert(instance);
        }
        BoundarySelector::All { selectors } | BoundarySelector::Any { selectors } => {
            for selector in selectors {
                collect_boundary_instances(selector, instances);
            }
        }
        _ => {}
    }
}

fn cohort_contains(cohort: &CohortPolicy, node: &NodeId) -> bool {
    match cohort {
        CohortPolicy::All(nodes) | CohortPolicy::Any(nodes) => nodes.binary_search(node).is_ok(),
        CohortPolicy::Quorum { nodes, .. } => nodes.binary_search(node).is_ok(),
    }
}

#[derive(Debug, thiserror::Error)]
pub(super) enum GuestMeasurementValueError {
    #[error(transparent)]
    InvalidRational(#[from] crucible::model::MeasurementEvaluationError),
    #[error("rational sample is not canonical reduced form")]
    NonCanonicalRational,
    #[error("metric `{metric}` value violates its declared type or guest protocol bound")]
    ContractMismatch { metric: MetricId },
}

fn normalize_guest_measurement_value(
    value: &GuestMeasurementValue,
) -> Result<MeasurementSampleValue, GuestMeasurementValueError> {
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
        GuestMeasurementValue::Enumerated(value) => {
            Ok(MeasurementSampleValue::Enumerated(value.clone()))
        }
        GuestMeasurementValue::SignedVector(value) => {
            Ok(MeasurementSampleValue::SignedVector(value.clone()))
        }
        GuestMeasurementValue::UnsignedVector(value) => {
            Ok(MeasurementSampleValue::UnsignedVector(value.clone()))
        }
    }
}

pub(super) fn validate_guest_measurement_value(
    value: &GuestMeasurementValue,
    metric: &MetricDefinition,
) -> Result<(), GuestMeasurementValueError> {
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
        return Err(GuestMeasurementValueError::ContractMismatch {
            metric: metric.id.clone(),
        });
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
    if value.len() > WHITEBOX_MEASUREMENT_IDENTIFIER_MAX_BYTES {
        return Err(guest_measurement_error(
            sequence,
            format!(
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
    instance: &MeasurementInstanceKey,
) -> bool {
    match selector {
        BoundarySelector::GuestMarker {
            marker: expected,
            instance: Some(expected_instance),
        } => expected.name == marker && expected_instance == instance,
        BoundarySelector::All { selectors } | BoundarySelector::Any { selectors } => selectors
            .iter()
            .any(|selector| boundary_accepts_semantic_marker(selector, marker, instance)),
        _ => false,
    }
}

fn guest_measurement_error(sequence: u64, reason: impl Into<String>) -> CrucibleMeasurementError {
    CrucibleMeasurementError::GuestMeasurementProtocol {
        sequence,
        reason: reason.into(),
    }
}

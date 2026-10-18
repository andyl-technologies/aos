//! Failure-artifact identity validation and canonical material helpers.

use super::*;

mod reporting;

pub(in crate::model) use reporting::*;

pub(in crate::model) fn validate_finding_static_identity(
    finding: &FindingReproductionArtifact,
) -> Result<(), EngineError> {
    let artifact = finding.artifact.id();
    if finding.replay.artifact != artifact {
        return Err(EngineError::ReplayTargetMismatch {
            expected: artifact,
            actual: finding.replay.artifact,
        });
    }

    let scenario = finding.artifact.scenario_form().id();
    if finding.replay.scenario != scenario {
        return Err(EngineError::ReplayTargetMismatch {
            expected: scenario,
            actual: finding.replay.scenario,
        });
    }

    let schedule = finding.artifact.schedule().content_hash();
    if finding.replay.schedule != schedule {
        return Err(EngineError::ReplayTargetMismatch {
            expected: schedule,
            actual: finding.replay.schedule,
        });
    }

    let configuration = Configuration {
        def: finding.artifact.scenario_def(),
        schedule: finding.artifact.schedule().clone(),
    };
    let configuration_id = configuration.id();
    if finding.configuration != configuration_id {
        return Err(EngineError::ReplayTargetMismatch {
            expected: configuration_id,
            actual: finding.configuration,
        });
    }

    Ok(())
}

pub(in crate::model) fn validate_recorded_event_log_for_finding(
    finding: &FindingReproductionArtifact,
    event_log: &FailureRecordedEventLog,
) -> Result<(), EngineError> {
    let artifact = finding.artifact.id();
    if event_log.artifact != artifact {
        return Err(EngineError::ReplayTargetMismatch {
            expected: artifact,
            actual: event_log.artifact,
        });
    }
    Ok(())
}

pub(in crate::model) fn validate_violation_for_finding(
    finding: &FindingReproductionArtifact,
    violation: &FailurePropertyViolationRecord,
) -> Result<(), EngineError> {
    let artifact = finding.artifact.id();
    if violation.violation.reproduction_artifact != artifact {
        return Err(EngineError::ReplayTargetMismatch {
            expected: artifact,
            actual: violation.violation.reproduction_artifact,
        });
    }
    Ok(())
}

pub(in crate::model) fn validate_divergence_point(
    event_log: &FailureRecordedEventLog,
    divergence: &EventLogCausalDivergencePoint,
) -> Result<usize, EngineError> {
    if let Some((index, _)) =
        event_log
            .projection
            .entries()
            .iter()
            .enumerate()
            .find(|(_, entry)| {
                entry.raw_index == divergence.raw_index
                    && entry.entry.time().stamp == divergence.at
                    && entry.entry.source() == &divergence.source
                    && entry.entry.event_payload().kind() == divergence.kind
            })
    {
        return Ok(index);
    }

    Err(EngineError::UnifiedOperationEvidenceMismatch {
        operation: "failure-signature.divergence",
        reason: "divergence bisection point is absent from recorded causal projection",
    })
}

fn host_assertion_transition_index(
    event_log: &FailureRecordedEventLog,
    violation: &FailurePropertyViolationRecord,
) -> Result<Option<usize>, EngineError> {
    let mismatch = || EngineError::UnifiedOperationEvidenceMismatch {
        operation: "failure-signature.violation",
        reason: "host assertion transition is ambiguous or inconsistent",
    };
    let mut matches = event_log
        .projection
        .entries()
        .iter()
        .enumerate()
        .filter(|(_, entry)| {
            entry.entry.event_payload().kind() == violation.violation.event_kind
                && entry.entry.at() == violation.violation.at_virtual_time
                && violation_event_assertion_matches(
                    entry.entry.event_payload(),
                    &violation.violation,
                )
        });
    let Some((index, transition)) = matches.next() else {
        return Ok(None);
    };
    if matches.next().is_some() {
        return Err(mismatch());
    }

    let entry = &transition.entry;
    let boundary_stamp = entry.time().stamp.node.is_none()
        && entry.time().stamp.tick.ticks == entry.at().ticks
        && entry.time().stamp.retired.is_none();
    if entry.source() != &EventSource::Engine
        || !boundary_stamp
        || !matches!(
            entry.payload(),
            SchedulerEventLogPayload::Observable(ObservableEventPayload::AssertionStateChanged {
                state: AssertionPhase::Violated,
                ..
            })
        )
    {
        return Err(mismatch());
    }
    Ok(Some(index))
}

pub(in crate::model) struct ValidatedPropertyViolation {
    pub(in crate::model) causal_cone: FailureCausalCone,
    pub(in crate::model) anchor: Option<usize>,
}

pub(in crate::model) fn validated_property_violation(
    finding: &FindingReproductionArtifact,
    event_log: &FailureRecordedEventLog,
    violation: &FailurePropertyViolationRecord,
    canonicalizer: &FailureSymmetryCanonicalizer,
) -> Result<ValidatedPropertyViolation, EngineError> {
    let mismatch = || EngineError::UnifiedOperationEvidenceMismatch {
        operation: "failure-signature.violation",
        reason: "violation record is absent from recorded causal projection and host assertion replay",
    };

    let scenario = finding.artifact.scenario_form();
    let report = OfflineAssertionChecker::new()
        .with_world_white_box_policies(&scenario.world)
        .check_run(&scenario.properties, &event_log.raw_entries)
        .map_err(|_| mismatch())?;
    let matches_expected = |replayed: &HostAssertionViolation| {
        let mut replayed = replayed.clone();
        replayed.reproduction_artifact = finding.artifact.id();
        replayed == violation.violation
    };
    if !report.violations().iter().any(&matches_expected) {
        return Err(mismatch());
    }

    let transition =
        host_assertion_transition_index(event_log, violation).map_err(|_| mismatch())?;
    let outcome_is_violated = report.outcomes().iter().any(|outcome| {
        outcome.assertion == violation.violation.assertion
            && outcome.at == violation.violation.at_virtual_time
            && outcome.quantifier == violation.violation.quantifier
            && matches!(
                outcome.kind,
                HostAssertionOutcomeKind::Violated | HostAssertionOutcomeKind::NeverReachedFail
            )
    });
    // A host-only recorded log can omit the runtime's derived transition.
    // When one is retained, it must agree with the rechecked verdict.
    if transition.is_some() && !outcome_is_violated {
        return Err(mismatch());
    }
    let anchor = transition.or_else(|| {
        event_log
            .projection
            .entries()
            .iter()
            .enumerate()
            .rfind(|(_, entry)| entry.entry.at() <= violation.violation.at_virtual_time)
            .map(|(index, _)| index)
    });
    let mut material = anchor.map_or_else(
        || String::from("causal_cone_events=0"),
        |index| {
            failure_causal_cone_through_index(event_log, index, canonicalizer)
                .canonical_material()
                .to_owned()
        },
    );

    // The checker establishes the failed predicate from the exact raw log.
    // Retain the physical marker coordinate independently of the scheduler
    // boundary so replay cannot substitute a different guest observation.
    let claims_guest_marker = violation.violation.node.is_some()
        && violation.violation.detail.contains("guest marker marker=");
    let marker_witnesses = event_log
        .raw_entries
        .iter()
        .enumerate()
        .filter_map(|(raw_index, entry)| match entry.payload() {
            SchedulerEventLogPayload::Observable(ObservableEventPayload::GuestMarker {
                retired_icount,
                node,
                marker,
            }) if claims_guest_marker
                && violation.violation.at_icount == Some(*retired_icount)
                && violation.violation.node.as_ref() == Some(node)
                && entry.at() <= violation.violation.at_virtual_time
                && violation
                    .violation
                    .detail
                    .contains(&format!("guest marker marker={} matched", marker.name)) =>
            {
                Some((raw_index, entry.at(), node, marker, retired_icount))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    // The detail was regenerated and compared above, so its witness label is
    // checker-owned rather than an unchecked claim from the replay payload.
    if marker_witnesses.len() > 1 || (claims_guest_marker && marker_witnesses.len() != 1) {
        return Err(mismatch());
    }
    if let (Some(index), Some((raw_index, ..))) = (transition, marker_witnesses.first())
        && *raw_index >= event_log.projection.entries()[index].raw_index
    {
        return Err(mismatch());
    }
    if let Some((_, at, node, marker, icount)) = marker_witnesses.first() {
        let node = canonicalizer.canonical_node(node);
        material.push_str(&format!(
            "\nguest_marker_witness=marker:{:?};node:{:?};icount:{};at:{}",
            marker.name, node.name, icount.retired, at.ticks
        ));
    }
    material.push_str(&format!(
        "\nhost_assertion_violation=assertion:{:?};quantifier:{:?};at:{};detail:{:?}",
        violation.violation.assertion.name,
        violation.violation.quantifier,
        violation.violation.at_virtual_time.ticks,
        violation.violation.detail
    ));
    Ok(ValidatedPropertyViolation {
        causal_cone: FailureCausalCone::from_canonical_material(material),
        anchor,
    })
}

pub(in crate::model) fn validate_timeout_point(
    event_log: &FailureRecordedEventLog,
    timeout: &FailureTimeoutRecord,
) -> Result<usize, EngineError> {
    if timeout.reproduction_artifact != event_log.artifact() {
        return Err(EngineError::ReplayTargetMismatch {
            expected: event_log.artifact(),
            actual: timeout.reproduction_artifact,
        });
    }
    event_log
        .projection
        .entries()
        .iter()
        .enumerate()
        .find(|(_, entry)| {
            entry.entry.event_payload().kind() == timeout.event_kind
                && entry.entry.at() == timeout.at_virtual_time
                && entry.entry.event_payload().string("budget_kind")
                    == Some(failure_timeout_budget_kind_label(timeout.budget_kind))
                && entry.entry.time().stamp.node == timeout.node
                && timeout
                    .at_icount
                    .map(|icount| entry.entry.time().stamp.retired == Some(icount))
                    .unwrap_or(true)
        })
        .map(|(index, _)| index)
        .ok_or(EngineError::UnifiedOperationEvidenceMismatch {
            operation: "failure-signature.timeout",
            reason: "timeout boundary is absent from recorded causal projection",
        })
}

pub(in crate::model) fn violation_event_assertion_matches(
    payload: &crate::scheduler::EventPayload,
    violation: &HostAssertionViolation,
) -> bool {
    matches!(
        payload.attribute("id"),
        Some(EventAttributeValue::String(value)) if value == &violation.assertion.name
    )
}

pub(in crate::model) fn divergence_faulting_node(
    divergence: &EventLogCausalDivergencePoint,
) -> Option<NodeId> {
    match &divergence.source {
        EventSource::Node { node } | EventSource::Guest { node } => Some(node.clone()),
        EventSource::Scenario { .. } | EventSource::Engine | EventSource::Command { .. } => {
            divergence.at.node.clone()
        }
    }
}

pub(in crate::model) fn failure_causal_cone_through_index(
    event_log: &FailureRecordedEventLog,
    causal_index: usize,
    canonicalizer: &FailureSymmetryCanonicalizer,
) -> FailureCausalCone {
    let cone = failure_causal_cone_entries(event_log, causal_index, canonicalizer);
    let mut lines = vec![format!("causal_cone_events={}", cone.len())];
    for (cone_index, entry) in cone.into_iter().enumerate() {
        push_failure_causal_slice_entry_lines(cone_index, entry, canonicalizer, &mut lines);
    }
    FailureCausalCone::from_canonical_material(lines.join("\n"))
}

pub(in crate::model) fn failure_causal_cone_entries<'a>(
    event_log: &'a FailureRecordedEventLog,
    causal_index: usize,
    canonicalizer: &FailureSymmetryCanonicalizer,
) -> Vec<&'a crate::scheduler::EventLogCausalProjectionEntry> {
    let anchor = &event_log.projection.entries()[causal_index];
    let anchor_keys = failure_causal_dependency_keys(anchor, canonicalizer);
    event_log
        .projection
        .entries()
        .iter()
        .take(causal_index + 1)
        .filter(|entry| {
            entry.raw_index == anchor.raw_index
                || failure_causal_dependency_keys(entry, canonicalizer)
                    .iter()
                    .any(|key| anchor_keys.contains(key))
        })
        .collect()
}

pub(in crate::model) fn failure_causal_dependency_keys(
    entry: &crate::scheduler::EventLogCausalProjectionEntry,
    canonicalizer: &FailureSymmetryCanonicalizer,
) -> BTreeSet<String> {
    let mut keys = BTreeSet::new();
    match entry.entry.source() {
        EventSource::Scenario { event } => {
            keys.insert(format!("event:{}:{}", event.name.len(), event.name));
        }
        EventSource::Engine | EventSource::Command { .. } => {}
        EventSource::Node { node } | EventSource::Guest { node } => {
            keys.insert(format!(
                "node:{}",
                failure_node_value(&canonicalizer.canonical_node(node))
            ));
        }
    }
    if let Some(node) = &entry.entry.time().stamp.node {
        keys.insert(format!(
            "node:{}",
            failure_node_value(&canonicalizer.canonical_node(node))
        ));
    }
    for value in entry.entry.event_payload().attributes().values() {
        push_failure_dependency_keys_for_attribute(value, canonicalizer, &mut keys);
    }
    keys
}

pub(in crate::model) fn push_failure_dependency_keys_for_attribute(
    value: &EventAttributeValue,
    canonicalizer: &FailureSymmetryCanonicalizer,
    keys: &mut BTreeSet<String>,
) {
    match value {
        EventAttributeValue::String(value) => {
            keys.insert(format!("string:{}:{}", value.len(), value));
        }
        EventAttributeValue::Node(node) => {
            keys.insert(format!(
                "node:{}",
                failure_node_value(&canonicalizer.canonical_node(node))
            ));
        }
        EventAttributeValue::Event(event) => {
            keys.insert(format!("event:{}:{}", event.name.len(), event.name));
        }
        EventAttributeValue::Bool(_)
        | EventAttributeValue::U64(_)
        | EventAttributeValue::U128(_)
        | EventAttributeValue::Bytes(_)
        | EventAttributeValue::VirtualTime(_)
        | EventAttributeValue::Icount(_)
        | EventAttributeValue::Level(_) => {}
    }
}

pub(in crate::model) fn push_failure_causal_slice_entry_lines(
    cone_index: usize,
    entry: &crate::scheduler::EventLogCausalProjectionEntry,
    canonicalizer: &FailureSymmetryCanonicalizer,
    lines: &mut Vec<String>,
) {
    lines.push(format!("entry.cone_index={cone_index}"));
    match &entry.entry.time().stamp.node {
        Some(node) => lines.push(failure_node_material(
            "entry.icount.node",
            &canonicalizer.canonical_node(node),
        )),
        None => lines.push(String::from("entry.icount.node=none")),
    }
    lines.push(failure_event_source_material(
        "entry.source",
        entry.entry.source(),
        canonicalizer,
    ));
    lines.push(format!(
        "entry.level={}",
        failure_event_level_label(entry.entry.level())
    ));
    lines.push(format!(
        "entry.class={}",
        failure_event_class_label(entry.entry.class())
    ));
    lines.push(format!("entry.kind={}", entry.entry.event_payload().kind()));
    for (name, value) in entry.entry.event_payload().attributes() {
        if let Some(material) = failure_event_attribute_material(value, canonicalizer) {
            lines.push(format!("entry.attr.{name}={material}"));
        }
    }
}

pub(in crate::model) fn failure_event_source_material(
    prefix: &str,
    source: &EventSource,
    canonicalizer: &FailureSymmetryCanonicalizer,
) -> String {
    match source {
        EventSource::Scenario { event } => {
            format!("{prefix}=scenario:{}", event.name)
        }
        EventSource::Engine => format!("{prefix}=engine"),
        EventSource::Node { node } => {
            format!(
                "{prefix}=node:{}",
                failure_node_value(&canonicalizer.canonical_node(node))
            )
        }
        EventSource::Guest { node } => {
            format!(
                "{prefix}=guest:{}",
                failure_node_value(&canonicalizer.canonical_node(node))
            )
        }
        EventSource::Command { command_id } => format!("{prefix}=command:{command_id}"),
    }
}

pub(in crate::model) fn failure_event_attribute_material(
    value: &EventAttributeValue,
    canonicalizer: &FailureSymmetryCanonicalizer,
) -> Option<String> {
    match value {
        EventAttributeValue::Bool(value) => Some(format!("bool:{value}")),
        EventAttributeValue::U64(value) => Some(format!("u64:{value}")),
        EventAttributeValue::U128(value) => Some(format!("u128:{value}")),
        EventAttributeValue::String(value) => Some(format!("string:{}:{}", value.len(), value)),
        EventAttributeValue::Bytes(value) => {
            Some(format!("bytes:{}:{}", value.len(), bytes_hex(value)))
        }
        EventAttributeValue::Node(node) => Some(format!(
            "node:{}",
            failure_node_value(&canonicalizer.canonical_node(node))
        )),
        EventAttributeValue::Event(event) => {
            Some(format!("event:{}:{}", event.name.len(), event.name))
        }
        EventAttributeValue::VirtualTime(_) | EventAttributeValue::Icount(_) => None,
        EventAttributeValue::Level(level) => {
            Some(format!("level:{}", failure_event_level_label(*level)))
        }
    }
}

pub(in crate::model) fn failure_node_material(prefix: &str, node: &NodeId) -> String {
    format!("{prefix}={}", failure_node_value(node))
}

pub(in crate::model) fn failure_node_value(node: &NodeId) -> String {
    format!("{}:{}", node.name.len(), node.name)
}

pub(in crate::model) fn failure_event_level_label(level: EventLevel) -> &'static str {
    match level {
        EventLevel::Trace => "trace",
        EventLevel::Debug => "debug",
        EventLevel::Info => "info",
        EventLevel::Warn => "warn",
        EventLevel::Error => "error",
    }
}

pub(in crate::model) fn failure_event_class_label(class: SchedulerEventLogClass) -> &'static str {
    match class {
        SchedulerEventLogClass::Causal => "causal",
        SchedulerEventLogClass::Observational => "observational",
    }
}

pub(in crate::model) fn failure_signature_material(signature: &FailureSignature) -> String {
    let mut lines = Vec::new();
    lines.push(format!(
        "failure_kind={}",
        failure_kind_label(signature.failure_kind)
    ));
    match &signature.property {
        Some(property) => {
            lines.push(String::from("property=some"));
            lines.push(assertion_id_material(&property.id));
            lines.push(format!(
                "property_quantifier={}",
                failure_assertion_quantifier_label(property.quantifier)
            ));
        }
        None => lines.push(String::from("property=none")),
    }
    lines.push(format!(
        "first_failing_event_kind_len={}",
        signature.first_failing_point.event_kind.len()
    ));
    lines.push(format!(
        "first_failing_event_kind={}",
        signature.first_failing_point.event_kind
    ));
    match &signature.first_failing_point.faulting_node {
        Some(node) => lines.push(node_ref_material("faulting_node", node)),
        None => lines.push(String::from("faulting_node=none")),
    }
    lines.push(format!(
        "coverage_class_algorithm={}",
        signature.coverage_class.algorithm
    ));
    lines.push(format!(
        "coverage_class_bucket={}",
        signature.coverage_class.bucket
    ));
    lines.push(
        signature
            .causal_slice_hash
            .map(|hash| format!("causal_slice_hash={}", hash.to_hex()))
            .unwrap_or_else(|| String::from("causal_slice_hash=none")),
    );
    lines.join("\n")
}

pub(in crate::model) fn failure_signature_report_material(signature: &FailureSignature) -> String {
    let mut lines = vec![signature.canonical_material()];
    lines.push(format!(
        "evidence_binding={}",
        signature.evidence_binding.to_hex()
    ));
    lines.push(
        signature
            .at_icount_report_only
            .map(|icount| format!("at_icount_report_only={}", icount.retired))
            .unwrap_or_else(|| String::from("at_icount_report_only=none")),
    );
    match &signature.causal_cone {
        Some(cone) => {
            lines.push(String::from("causal_cone=some"));
            lines.push(String::from("causal_cone_material_BEGIN"));
            lines.push(cone.canonical_material().to_owned());
            lines.push(String::from("causal_cone_material_END"));
        }
        None => lines.push(String::from("causal_cone=none")),
    }
    lines.join("\n")
}

pub(in crate::model) fn failure_signature_key_material(
    signature: &FailureSignature,
    policy: SignaturePolicy,
) -> String {
    let mut lines = vec![failure_signature_policy_material(policy)];
    lines.push(String::from("key_fields_BEGIN"));
    lines.push(format!(
        "failure_kind={}",
        failure_kind_label(signature.failure_kind)
    ));
    match &signature.property {
        Some(property) => {
            lines.push(String::from("property=some"));
            lines.push(assertion_id_material(&property.id));
            if policy.level >= SignaturePolicyLevel::Default {
                lines.push(format!(
                    "property_quantifier={}",
                    failure_assertion_quantifier_label(property.quantifier)
                ));
            }
        }
        None => lines.push(String::from("property=none")),
    }
    if policy.level >= SignaturePolicyLevel::Default {
        lines.push(format!(
            "first_failing_event_kind_len={}",
            signature.first_failing_point.event_kind.len()
        ));
        lines.push(format!(
            "first_failing_event_kind={}",
            signature.first_failing_point.event_kind
        ));
        match &signature.first_failing_point.faulting_node {
            Some(node) => lines.push(node_ref_material("faulting_node", node)),
            None => lines.push(String::from("faulting_node=none")),
        }
        lines.push(format!(
            "coverage_class_algorithm={}",
            signature.coverage_class.algorithm
        ));
        lines.push(format!(
            "coverage_class_bucket={}",
            signature.coverage_class.bucket
        ));
    }
    if policy.keys_causal_slice_hash() {
        lines.push(
            signature
                .causal_slice_hash
                .map(|hash| format!("causal_slice_hash={}", hash.to_hex()))
                .unwrap_or_else(|| String::from("causal_slice_hash=none")),
        );
    }
    if policy.keys_absolute_icount() {
        lines.push(
            signature
                .at_icount_report_only
                .map(|icount| format!("at_icount_key={}", icount.retired))
                .unwrap_or_else(|| String::from("at_icount_key=none")),
        );
        match &signature.causal_cone {
            Some(cone) => {
                lines.push(String::from("exact_causal_cone=some"));
                lines.push(String::from("exact_causal_cone_material_BEGIN"));
                lines.push(cone.canonical_material().to_owned());
                lines.push(String::from("exact_causal_cone_material_END"));
            }
            None => lines.push(String::from("exact_causal_cone=none")),
        }
    }
    lines.push(String::from("key_fields_END"));
    lines.join("\n")
}

pub(in crate::model) fn failure_signature_policy_material(policy: SignaturePolicy) -> String {
    [
        format!(
            "signature_policy_schema_version={}",
            policy.schema_version()
        ),
        format!(
            "signature_policy_level={}",
            signature_policy_level_label(policy.level())
        ),
        format!(
            "coverage_class_algorithm={}",
            policy.coverage_class_algorithm()
        ),
        format!("minimize_merge_allowed={}", policy.allows_minimize_merge()),
    ]
    .join("\n")
}

pub(in crate::model) fn failure_findings_ledger_material(ledger: &FailureFindingsLedger) -> String {
    let mut lines = vec![
        format!("artifact_count={}", ledger.artifacts.len()),
        format!("signed_finding_count={}", ledger.findings.len()),
    ];
    for (index, artifact) in ledger.artifacts.iter().enumerate() {
        lines.push(format!("artifact.{index}={}", content_hash_hex(*artifact)));
    }
    for (index, finding) in ledger.findings.iter().enumerate() {
        lines.push(format!(
            "finding.{index}.reproduction_artifact={}",
            content_hash_hex(finding.reproduction_artifact)
        ));
        lines.push(format!("finding.{index}.signature_BEGIN"));
        lines.push(finding.signature.report_material());
        lines.push(format!("finding.{index}.signature_END"));
    }
    lines.join("\n")
}

pub(in crate::model) fn failure_triage_result_identity_material(
    identity: FailureTriageResultIdentity,
) -> String {
    [
        format!(
            "triage_result_schema_version={}",
            SIGNATURE_POLICY_SCHEMA_VERSION
        ),
        format!(
            "findings_ledger={}",
            content_hash_hex(identity.findings_ledger)
        ),
        identity.policy.canonical_material(),
    ]
    .join("\n")
}

pub(in crate::model) fn failure_triage_signature_self_check_material(
    check: &FailureTriageSignatureSelfCheck,
) -> String {
    let mut lines = vec![
        format!("checked_count={}", check.checked_count),
        format!("check_record_count={}", check.checks.len()),
        format!("mismatch_count={}", check.mismatches.len()),
    ];
    for (index, record) in check.checks.iter().enumerate() {
        let prefix = format!("check.{index}");
        lines.push(format!(
            "{prefix}.reproduction_artifact={}",
            content_hash_hex(record.reproduction_artifact)
        ));
        lines.push(format!(
            "{prefix}.discovery_signature_hash={}",
            content_hash_hex(record.discovery_signature_hash)
        ));
        lines.push(format!(
            "{prefix}.recomputed_signature_hash={}",
            content_hash_hex(record.recomputed_signature_hash)
        ));
        lines.push(format!(
            "{prefix}.discovery_signature_bytes={}",
            content_hash_hex(record.discovery_signature_bytes)
        ));
        lines.push(format!(
            "{prefix}.recomputed_signature_bytes={}",
            content_hash_hex(record.recomputed_signature_bytes)
        ));
        lines.push(format!("{prefix}.matched={}", record.matched));
    }
    for (index, mismatch) in check.mismatches.iter().enumerate() {
        let prefix = format!("mismatch.{index}");
        lines.push(format!(
            "{prefix}.reproduction_artifact={}",
            content_hash_hex(mismatch.reproduction_artifact)
        ));
        lines.push(format!(
            "{prefix}.discovery_signature_hash={}",
            content_hash_hex(mismatch.discovery_signature_hash)
        ));
        lines.push(format!(
            "{prefix}.recomputed_signature_hash={}",
            content_hash_hex(mismatch.recomputed_signature_hash)
        ));
        lines.push(format!(
            "{prefix}.discovery_signature_bytes={}",
            content_hash_hex(mismatch.discovery_signature_bytes)
        ));
        lines.push(format!(
            "{prefix}.recomputed_signature_bytes={}",
            content_hash_hex(mismatch.recomputed_signature_bytes)
        ));
    }
    lines.join("\n")
}

pub(in crate::model) fn failure_triage_result_material(result: &FailureTriageResult) -> String {
    let mut lines = vec![
        result.identity.canonical_material(),
        format!(
            "triage_result_identity={}",
            content_hash_hex(result.identity.content_hash())
        ),
        format!(
            "clustering_result={}",
            content_hash_hex(result.clustering.content_hash())
        ),
        format!(
            "minimization_result={}",
            content_hash_hex(result.minimization.content_hash())
        ),
        format!(
            "report_set={}",
            content_hash_hex(result.report_set.content_hash())
        ),
        format!(
            "signature_self_check={}",
            content_hash_hex(result.signature_self_check.content_hash())
        ),
        format!("cluster_count={}", result.clustering.cluster_count()),
        format!("member_count={}", result.clustering.member_count()),
    ];
    for (index, report) in result.report_set.reports.iter().enumerate() {
        lines.push(format!(
            "report.{index}.cluster_id={}",
            content_hash_hex(report.cluster_id)
        ));
        lines.push(format!(
            "report.{index}.content_hash={}",
            content_hash_hex(report.content_hash())
        ));
        lines.push(format!(
            "report.{index}.minimal_representative={}",
            content_hash_hex(report.minimal_representative)
        ));
    }
    lines.join("\n")
}

pub(in crate::model) fn failure_triage_result_diff_material(
    diff: &FailureTriageResultDiff,
) -> String {
    let mut lines = vec![
        format!("baseline={}", content_hash_hex(diff.baseline)),
        format!("candidate={}", content_hash_hex(diff.candidate)),
        format!("added_count={}", diff.added_clusters.len()),
    ];
    for (index, cluster) in diff.added_clusters.iter().enumerate() {
        lines.push(format!("added.{index}={}", content_hash_hex(*cluster)));
    }
    lines.push(format!("removed_count={}", diff.removed_clusters.len()));
    for (index, cluster) in diff.removed_clusters.iter().enumerate() {
        lines.push(format!("removed.{index}={}", content_hash_hex(*cluster)));
    }
    lines.push(format!("changed_count={}", diff.changed_clusters.len()));
    for (index, changed) in diff.changed_clusters.iter().enumerate() {
        lines.push(format!(
            "changed.{index}.cluster_id={}",
            content_hash_hex(changed.cluster_id)
        ));
        lines.push(format!(
            "changed.{index}.baseline_report={}",
            content_hash_hex(changed.baseline_report)
        ));
        lines.push(format!(
            "changed.{index}.candidate_report={}",
            content_hash_hex(changed.candidate_report)
        ));
    }
    lines.push(format!("unchanged_count={}", diff.unchanged_clusters.len()));
    for (index, cluster) in diff.unchanged_clusters.iter().enumerate() {
        lines.push(format!("unchanged.{index}={}", content_hash_hex(*cluster)));
    }
    lines.join("\n")
}

pub(in crate::model) fn failure_signature_report_bytes_hash(material: &str) -> ContentHash {
    ContentHash::from_canonical_material(FAILURE_TRIAGE_SIGNATURE_SELF_CHECK_DOMAIN, material)
}

pub(in crate::model) fn failure_triage_artifact_bytes(domain: &str, material: &str) -> Vec<u8> {
    format!("{domain}\n{material}\n").into_bytes()
}

pub(in crate::model) fn store_failure_triage_artifact<S>(
    store: &S,
    bytes: &[u8],
) -> Result<FailureTriageStoredArtifact, DagStoreError>
where
    S: DagStore + ?Sized,
{
    let key = ContentHash::from_bytes(bytes);
    let cache_hit = store.exists(&key)?;
    let stored_key = store.put(bytes)?;
    if stored_key != key {
        return Err(DagStoreError::ContentMismatch {
            expected: key,
            actual: stored_key,
        });
    }
    Ok(FailureTriageStoredArtifact {
        key: stored_key,
        cache_hit,
        size_bytes: bytes.len(),
    })
}

pub(in crate::model) fn triage_report_hashes_by_cluster(
    result: &FailureTriageResult,
) -> BTreeMap<ContentHash, ContentHash> {
    result
        .report_set
        .reports
        .iter()
        .map(|report| (report.cluster_id, report.content_hash()))
        .collect()
}

pub(in crate::model) fn failure_clustering_result_material(
    result: &FailureClusteringResult,
) -> String {
    let mut lines = vec![
        result.policy.canonical_material(),
        format!("cluster_count={}", result.clusters.len()),
        format!("member_count={}", result.member_count()),
    ];
    for (cluster_index, cluster) in result.clusters.iter().enumerate() {
        lines.push(format!("cluster.index={cluster_index}"));
        lines.push(format!("cluster.id={}", content_hash_hex(cluster.id)));
        lines.push(String::from("cluster.signature_key_BEGIN"));
        lines.push(cluster.signature_key.canonical_material().to_owned());
        lines.push(String::from("cluster.signature_key_END"));
        lines.push(format!("cluster.member_count={}", cluster.members.len()));
        for (member_index, member) in cluster.members.iter().enumerate() {
            lines.push(format!("cluster.member.index={member_index}"));
            lines.push(format!(
                "cluster.member.reproduction_artifact={}",
                content_hash_hex(member.reproduction_artifact)
            ));
            lines.push(format!(
                "cluster.member.signature={}",
                content_hash_hex(member.signature.content_hash())
            ));
        }
    }
    lines.join("\n")
}

pub(in crate::model) fn signature_policy_level_label(level: SignaturePolicyLevel) -> &'static str {
    match level {
        SignaturePolicyLevel::Coarse => "coarse",
        SignaturePolicyLevel::Default => "default",
        SignaturePolicyLevel::Fine => "fine",
        SignaturePolicyLevel::Exact => "exact",
    }
}

pub(in crate::model) fn failure_kind_label(kind: FailureKind) -> &'static str {
    match kind {
        FailureKind::PropertyViolation => "property-violation",
        FailureKind::Divergence => "divergence",
        FailureKind::Timeout => "timeout",
    }
}

pub(in crate::model) fn failure_timeout_budget_kind_label(
    kind: FailureTimeoutBudgetKind,
) -> &'static str {
    match kind {
        FailureTimeoutBudgetKind::ExecutionQuanta => "execution-quanta",
        FailureTimeoutBudgetKind::VirtualTime => "virtual-time",
    }
}

pub(in crate::model) fn failure_assertion_quantifier_label(
    quantifier: AssertionQuantifierKind,
) -> &'static str {
    match quantifier {
        AssertionQuantifierKind::Always => "always",
        AssertionQuantifierKind::Sometimes => "sometimes",
        AssertionQuantifierKind::Eventually => "eventually",
        AssertionQuantifierKind::AfterQuiescence => "after-quiescence",
        AssertionQuantifierKind::Reachable => "reachable",
        AssertionQuantifierKind::GuestAlways => "guest-always",
        AssertionQuantifierKind::GuestSometimes => "guest-sometimes",
        AssertionQuantifierKind::GuestReachable => "guest-reachable",
        AssertionQuantifierKind::GuestUnreachable => "guest-unreachable",
    }
}

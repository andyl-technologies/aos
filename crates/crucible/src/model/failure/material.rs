fn validate_finding_static_identity(
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

fn validate_recorded_event_log_for_finding(
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

fn validate_violation_for_finding(
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

fn validate_divergence_point(
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
                    && entry.entry.time().icount == divergence.at
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

fn validate_violation_point(
    event_log: &FailureRecordedEventLog,
    violation: &FailurePropertyViolationRecord,
) -> Result<usize, EngineError> {
    if let Some((index, _)) =
        event_log
            .projection
            .entries()
            .iter()
            .enumerate()
            .find(|(_, entry)| {
                entry.entry.event_payload().kind() == violation.violation.event_kind
                    && entry.entry.at() == violation.violation.at_virtual_time
                    && violation_event_icount_matches(entry.entry.time(), &violation.violation)
                    && violation_event_assertion_matches(
                        entry.entry.event_payload(),
                        &violation.violation,
                    )
            })
    {
        return Ok(index);
    }

    Err(EngineError::UnifiedOperationEvidenceMismatch {
        operation: "failure-signature.violation",
        reason: "violation record is absent from recorded causal projection",
    })
}

fn violation_event_icount_matches(
    at: &crate::scheduler::EventLogTime,
    violation: &HostAssertionViolation,
) -> bool {
    violation
        .at_icount
        .map(|icount| at.icount.icount == icount)
        .unwrap_or(true)
}

fn violation_event_assertion_matches(
    payload: &crate::scheduler::EventPayload,
    violation: &HostAssertionViolation,
) -> bool {
    matches!(
        payload.attribute("id"),
        Some(EventAttributeValue::String(value)) if value == &violation.assertion.name
    )
}

fn divergence_faulting_node(divergence: &EventLogCausalDivergencePoint) -> Option<NodeId> {
    match &divergence.source {
        EventSource::Node { node } | EventSource::Guest { node } => Some(node.clone()),
        EventSource::Scenario { .. } | EventSource::Engine | EventSource::Command { .. } => {
            divergence.at.node.clone()
        }
    }
}

fn failure_causal_cone_through_index(
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

fn failure_causal_cone_entries<'a>(
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

fn failure_causal_dependency_keys(
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
    if let Some(node) = &entry.entry.time().icount.node {
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

fn push_failure_dependency_keys_for_attribute(
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
        EventAttributeValue::Fault(fault) => {
            keys.insert(format!("fault:{}:{}", fault.name.len(), fault.name));
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

fn push_failure_causal_slice_entry_lines(
    cone_index: usize,
    entry: &crate::scheduler::EventLogCausalProjectionEntry,
    canonicalizer: &FailureSymmetryCanonicalizer,
    lines: &mut Vec<String>,
) {
    lines.push(format!("entry.cone_index={cone_index}"));
    match &entry.entry.time().icount.node {
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

fn failure_event_source_material(
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

fn failure_event_attribute_material(
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
        EventAttributeValue::Fault(fault) => {
            Some(format!("fault:{}:{}", fault.name.len(), fault.name))
        }
        EventAttributeValue::VirtualTime(_) | EventAttributeValue::Icount(_) => None,
        EventAttributeValue::Level(level) => {
            Some(format!("level:{}", failure_event_level_label(*level)))
        }
    }
}

fn failure_node_material(prefix: &str, node: &NodeId) -> String {
    format!("{prefix}={}", failure_node_value(node))
}

fn failure_node_value(node: &NodeId) -> String {
    format!("{}:{}", node.name.len(), node.name)
}

fn failure_event_level_label(level: EventLevel) -> &'static str {
    match level {
        EventLevel::Trace => "trace",
        EventLevel::Debug => "debug",
        EventLevel::Info => "info",
        EventLevel::Warn => "warn",
        EventLevel::Error => "error",
    }
}

fn failure_event_class_label(class: SchedulerEventLogClass) -> &'static str {
    match class {
        SchedulerEventLogClass::Causal => "causal",
        SchedulerEventLogClass::Observational => "observational",
    }
}

fn failure_signature_material(signature: &FailureSignature) -> String {
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

fn failure_signature_report_material(signature: &FailureSignature) -> String {
    let mut lines = vec![signature.canonical_material()];
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

fn failure_signature_key_material(signature: &FailureSignature, policy: SignaturePolicy) -> String {
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

fn failure_signature_policy_material(policy: SignaturePolicy) -> String {
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

fn failure_findings_ledger_material(ledger: &FailureFindingsLedger) -> String {
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

fn failure_triage_result_identity_material(identity: FailureTriageResultIdentity) -> String {
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

fn failure_triage_signature_self_check_material(check: &FailureTriageSignatureSelfCheck) -> String {
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

fn failure_triage_result_material(result: &FailureTriageResult) -> String {
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

fn failure_triage_result_diff_material(diff: &FailureTriageResultDiff) -> String {
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

fn failure_signature_report_bytes_hash(material: &str) -> ContentHash {
    ContentHash::from_canonical_material(FAILURE_TRIAGE_SIGNATURE_SELF_CHECK_DOMAIN, material)
}

fn failure_triage_artifact_bytes(domain: &str, material: &str) -> Vec<u8> {
    format!("{domain}\n{material}\n").into_bytes()
}

fn store_failure_triage_artifact<S>(
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

fn triage_report_hashes_by_cluster(
    result: &FailureTriageResult,
) -> BTreeMap<ContentHash, ContentHash> {
    result
        .report_set
        .reports
        .iter()
        .map(|report| (report.cluster_id, report.content_hash()))
        .collect()
}

fn failure_clustering_result_material(result: &FailureClusteringResult) -> String {
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

fn failure_signature_preserving_minimization_result_material(
    result: &FailureSignaturePreservingMinimizationResult,
) -> String {
    let mut lines = vec![
        result.policy.canonical_material(),
        format!("cluster_count={}", result.cluster_count()),
        format!("minimized_count={}", result.minimized_count()),
    ];
    for (run_index, run) in result.runs.iter().enumerate() {
        lines.push(format!("minimization.index={run_index}"));
        lines.push(format!(
            "minimization.cluster_id={}",
            content_hash_hex(run.cluster_id)
        ));
        lines.push(format!(
            "minimization.representative_artifact={}",
            content_hash_hex(run.representative_artifact)
        ));
        lines.push(String::from("minimization.target_signature_key_BEGIN"));
        lines.push(run.target_signature_key.canonical_material().to_owned());
        lines.push(String::from("minimization.target_signature_key_END"));
        lines.push(String::from("minimization.minimized_signature_key_BEGIN"));
        lines.push(run.minimized_signature_key.canonical_material().to_owned());
        lines.push(String::from("minimization.minimized_signature_key_END"));
        lines.push(format!(
            "minimization.seed={}",
            run.minimization.seed.to_hex()
        ));
        lines.push(format!(
            "minimization.target_fingerprint={}",
            content_hash_hex(run.minimization.target_fingerprint)
        ));
        lines.push(format!(
            "minimization.original_artifact={}",
            content_hash_hex(run.minimization.original.artifact.id())
        ));
        lines.push(format!(
            "minimization.minimized_artifact={}",
            content_hash_hex(run.minimized_artifact())
        ));
        lines.push(format!(
            "minimization.attempt_count={}",
            run.minimization.attempts.len()
        ));
        lines.push(format!(
            "minimization.accepted_attempt_count={}",
            run.minimization.accepted_attempts()
        ));
        for (attempt_index, attempt) in run.minimization.attempts.iter().enumerate() {
            push_minimization_attempt_lines(run_index, attempt_index, attempt, &mut lines);
        }
        lines.push(format!(
            "minimization.signature_preserved={}",
            run.preserves_signature()
        ));
    }
    lines.join("\n")
}

fn push_minimization_attempt_lines(
    run_index: usize,
    attempt_index: usize,
    attempt: &MinimizationAttempt,
    lines: &mut Vec<String>,
) {
    let prefix = format!("minimization.{run_index}.attempt.{attempt_index}");
    lines.push(format!("{prefix}.sequence={}", attempt.sequence));
    lines.push(format!(
        "{prefix}.removed_index_count={}",
        attempt.removed_indices.len()
    ));
    for (removed_index_index, removed_index) in attempt.removed_indices.iter().enumerate() {
        lines.push(format!(
            "{prefix}.removed_index.{removed_index_index}={removed_index}"
        ));
    }
    lines.push(format!(
        "{prefix}.removed_decision_count={}",
        attempt.removed_decisions.len()
    ));
    for (decision_index, decision) in attempt.removed_decisions.iter().enumerate() {
        let mut decision_lines = Vec::new();
        push_decision_lines(decision_index, decision, &mut decision_lines);
        for decision_line in decision_lines {
            lines.push(format!("{prefix}.removed_{decision_line}"));
        }
    }
    lines.push(format!(
        "{prefix}.candidate_artifact={}",
        content_hash_hex(attempt.candidate_artifact)
    ));
    lines.push(format!(
        "{prefix}.candidate_schedule={}",
        content_hash_hex(attempt.candidate_schedule)
    ));
    lines.push(format!(
        "{prefix}.replayed_state={}",
        content_hash_hex(attempt.replayed_state)
    ));
    match attempt.observed_fingerprint {
        Some(observed_fingerprint) => lines.push(format!(
            "{prefix}.observed_fingerprint={}",
            content_hash_hex(observed_fingerprint)
        )),
        None => lines.push(format!("{prefix}.observed_fingerprint=none")),
    }
    lines.push(format!("{prefix}.accepted={}", attempt.accepted));
}

fn failure_report_anchor_index(
    failure: &FailureClusterReportFailure,
    event_log: &FailureRecordedEventLog,
) -> Result<usize, EngineError> {
    match failure {
        FailureClusterReportFailure::Property(record) => {
            if record.violation.reproduction_artifact != event_log.artifact() {
                return Err(EngineError::ReplayTargetMismatch {
                    expected: event_log.artifact(),
                    actual: record.violation.reproduction_artifact,
                });
            }
            validate_violation_point(event_log, record)
        }
        FailureClusterReportFailure::Divergence(divergence) => {
            validate_divergence_point(event_log, &divergence.to_divergence_point())
        }
    }
}

fn failure_signature_for_report_failure(
    finding: &FindingReproductionArtifact,
    event_log: &FailureRecordedEventLog,
    failure: &FailureClusterReportFailure,
    normalization: &FailureSignatureNormalization,
) -> Result<FailureSignature, EngineError> {
    match failure {
        FailureClusterReportFailure::Property(record) => {
            FailureSignature::from_recorded_property_violation_with_normalization(
                finding,
                event_log,
                record,
                normalization,
            )
        }
        FailureClusterReportFailure::Divergence(divergence) => {
            FailureSignature::from_recorded_divergence_with_normalization(
                finding,
                event_log,
                &divergence.to_divergence_point(),
                normalization,
            )
        }
    }
}

fn failure_report_excerpt(
    event_log: &FailureRecordedEventLog,
    causal_index: usize,
    excerpt_len: usize,
    canonicalizer: &FailureSymmetryCanonicalizer,
) -> Vec<FailureClusterReportCausalStep> {
    if excerpt_len == 0 {
        return Vec::new();
    }
    let start = causal_index.saturating_add(1).saturating_sub(excerpt_len);
    event_log.projection.entries()[start..=causal_index]
        .iter()
        .map(|entry| failure_cluster_report_causal_step(entry, canonicalizer))
        .collect()
}

fn failure_cluster_report_causal_step(
    entry: &crate::scheduler::EventLogCausalProjectionEntry,
    canonicalizer: &FailureSymmetryCanonicalizer,
) -> FailureClusterReportCausalStep {
    let node = entry
        .entry
        .time()
        .icount
        .node
        .as_ref()
        .map(|node| canonicalizer.canonical_node(node))
        .or_else(|| match entry.entry.source() {
            EventSource::Node { node } | EventSource::Guest { node } => {
                Some(canonicalizer.canonical_node(node))
            }
            EventSource::Scenario { .. } | EventSource::Engine | EventSource::Command { .. } => {
                None
            }
        });
    let source = failure_event_source_material("source", entry.entry.source(), canonicalizer)
        .strip_prefix("source=")
        .unwrap_or("unknown")
        .to_owned();
    FailureClusterReportCausalStep {
        raw_index: entry.raw_index,
        sequence: entry.entry.sequence(),
        node,
        icount: entry.entry.time().icount.icount,
        kind: entry.entry.event_payload().kind().to_owned(),
        source,
        entry: entry.entry.content_hash(),
    }
}

fn failure_cluster_report_material(report: &FailureClusterReport) -> String {
    let mut lines = vec![
        report.policy.canonical_material(),
        format!("cluster_id={}", content_hash_hex(report.cluster_id)),
        String::from("signature_BEGIN"),
        report.signature.report_material(),
        String::from("signature_END"),
        format!("member_count={}", report.member_count),
    ];
    for (index, member) in report.member_hashes.iter().enumerate() {
        lines.push(format!(
            "member.{index}.reproduction_artifact={}",
            content_hash_hex(*member)
        ));
    }
    lines.push(format!(
        "representative_artifact={}",
        content_hash_hex(report.representative_artifact)
    ));
    lines.push(format!(
        "minimal_representative={}",
        content_hash_hex(report.minimal_representative)
    ));
    push_failure_report_reproduction_lines(
        "minimal_reproduction",
        &report.minimal_reproduction,
        &mut lines,
    );
    push_failure_report_failure_lines("failure", &report.failure, &mut lines);
    lines.push(format!(
        "event_log_excerpt_count={}",
        report.event_log_excerpt.len()
    ));
    for (index, step) in report.event_log_excerpt.iter().enumerate() {
        push_failure_report_step_lines(&format!("event_log_excerpt.{index}"), step, &mut lines);
    }
    lines.push(format!("causal_chain_count={}", report.causal_chain.len()));
    for (index, step) in report.causal_chain.iter().enumerate() {
        push_failure_report_step_lines(&format!("causal_chain.{index}"), step, &mut lines);
    }
    lines.push(format!(
        "replay_command_len={}",
        report.replay_command.len()
    ));
    lines.push(format!("replay_command={}", report.replay_command));
    lines.join("\n")
}

fn push_failure_report_reproduction_lines(
    prefix: &str,
    reproduction: &FailureClusterReportReproduction,
    lines: &mut Vec<String>,
) {
    lines.push(format!(
        "{prefix}.artifact={}",
        content_hash_hex(reproduction.artifact)
    ));
    lines.push(format!("{prefix}.seed={}", reproduction.seed.to_hex()));
    lines.push(format!(
        "{prefix}.scenario={}",
        content_hash_hex(reproduction.scenario)
    ));
    lines.push(format!(
        "{prefix}.schedule={}",
        content_hash_hex(reproduction.schedule)
    ));
}

fn push_failure_report_failure_lines(
    prefix: &str,
    failure: &FailureClusterReportFailure,
    lines: &mut Vec<String>,
) {
    match failure {
        FailureClusterReportFailure::Property(record) => {
            lines.push(format!("{prefix}.kind=property-violation"));
            lines.push(assertion_id_material(&record.violation.assertion));
            lines.push(format!(
                "{prefix}.property_message_len={}",
                record.violation.message.len()
            ));
            lines.push(format!(
                "{prefix}.property_message={}",
                record.violation.message
            ));
            lines.push(format!(
                "{prefix}.property_quantifier={}",
                failure_assertion_quantifier_label(record.violation.quantifier)
            ));
            lines.push(format!(
                "{prefix}.event_kind_len={}",
                record.violation.event_kind.len()
            ));
            lines.push(format!(
                "{prefix}.event_kind={}",
                record.violation.event_kind
            ));
            lines.push(
                record
                    .violation
                    .at_icount
                    .map(|icount| format!("{prefix}.at_icount={}", icount.retired))
                    .unwrap_or_else(|| format!("{prefix}.at_icount=none")),
            );
            match &record.violation.node {
                Some(node) => lines.push(node_ref_material(&format!("{prefix}.node"), node)),
                None => lines.push(format!("{prefix}.node=none")),
            }
            lines.push(format!(
                "{prefix}.detail_len={}",
                record.violation.detail.len()
            ));
            lines.push(format!("{prefix}.detail={}", record.violation.detail));
            lines.push(format!(
                "{prefix}.reproduction_artifact={}",
                content_hash_hex(record.violation.reproduction_artifact)
            ));
        }
        FailureClusterReportFailure::Divergence(divergence) => {
            lines.push(format!("{prefix}.kind=divergence"));
            lines.push(format!("{prefix}.raw_index={}", divergence.raw_index));
            match &divergence.node {
                Some(node) => lines.push(node_ref_material(&format!("{prefix}.node"), node)),
                None => lines.push(format!("{prefix}.node=none")),
            }
            match &divergence.icount_node {
                Some(node) => lines.push(node_ref_material(&format!("{prefix}.icount_node"), node)),
                None => lines.push(format!("{prefix}.icount_node=none")),
            }
            lines.push(format!("{prefix}.icount={}", divergence.icount.retired));
            lines.push(failure_event_source_material(
                &format!("{prefix}.source"),
                &divergence.source,
                &FailureSymmetryCanonicalizer::identity(ContentHash::default()),
            ));
            lines.push(format!("{prefix}.kind_len={}", divergence.kind.len()));
            lines.push(format!("{prefix}.event_kind={}", divergence.kind));
            lines.push(format!(
                "{prefix}.expected_state_summary_len={}",
                divergence.expected_state_summary.len()
            ));
            lines.push(format!(
                "{prefix}.expected_state_summary={}",
                divergence.expected_state_summary
            ));
            lines.push(format!(
                "{prefix}.reproduced_state_summary_len={}",
                divergence.reproduced_state_summary.len()
            ));
            lines.push(format!(
                "{prefix}.reproduced_state_summary={}",
                divergence.reproduced_state_summary
            ));
        }
    }
}

fn push_failure_report_step_lines(
    prefix: &str,
    step: &FailureClusterReportCausalStep,
    lines: &mut Vec<String>,
) {
    lines.push(format!("{prefix}.raw_index={}", step.raw_index));
    lines.push(format!("{prefix}.sequence={}", step.sequence));
    match &step.node {
        Some(node) => lines.push(node_ref_material(&format!("{prefix}.node"), node)),
        None => lines.push(format!("{prefix}.node=none")),
    }
    lines.push(format!("{prefix}.icount={}", step.icount.retired));
    lines.push(format!("{prefix}.kind_len={}", step.kind.len()));
    lines.push(format!("{prefix}.kind={}", step.kind));
    lines.push(format!("{prefix}.source_len={}", step.source.len()));
    lines.push(format!("{prefix}.source={}", step.source));
    lines.push(format!("{prefix}.entry={}", content_hash_hex(step.entry)));
}

fn failure_cluster_report_set_material(report_set: &FailureClusterReportSet) -> String {
    let mut lines = vec![
        report_set.policy.canonical_material(),
        format!("report_count={}", report_set.reports.len()),
    ];
    for (index, report) in report_set.reports.iter().enumerate() {
        lines.push(format!("report.index={index}"));
        lines.push(format!(
            "report.cluster_id={}",
            content_hash_hex(report.cluster_id)
        ));
        lines.push(format!(
            "report.content_hash={}",
            content_hash_hex(report.content_hash())
        ));
    }
    lines.join("\n")
}

fn failure_cluster_report_json(report: &FailureClusterReport) -> String {
    let members = report
        .member_hashes
        .iter()
        .map(|hash| json_string(&format_content_hash_ref(*hash)))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"schema\":{},\"cluster_id\":{},\"policy\":{},\"report_hash\":{},\"signature_hash\":{},\"member_count\":{},\"member_hashes\":[{}],\"minimal_representative\":{},\"replay_command\":{},\"canonical_material\":{}}}",
        json_string(FAILURE_CLUSTER_REPORT_DOMAIN),
        json_string(&format_content_hash_ref(report.cluster_id)),
        json_string(signature_policy_level_label(report.policy.level())),
        json_string(&format_content_hash_ref(report.content_hash())),
        json_string(&format_content_hash_ref(report.signature.content_hash())),
        report.member_count,
        members,
        json_string(&format_content_hash_ref(report.minimal_representative)),
        json_string(&report.replay_command),
        json_string(&report.canonical_material()),
    )
}

fn failure_cluster_report_set_json(report_set: &FailureClusterReportSet) -> String {
    let reports = report_set
        .reports
        .iter()
        .map(failure_cluster_report_json)
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"schema\":{},\"policy\":{},\"report_set_hash\":{},\"report_count\":{},\"reports\":[{}],\"canonical_material\":{}}}",
        json_string(FAILURE_CLUSTER_REPORT_SET_DOMAIN),
        json_string(signature_policy_level_label(report_set.policy.level())),
        json_string(&format_content_hash_ref(report_set.content_hash())),
        report_set.reports.len(),
        reports,
        json_string(&report_set.canonical_material()),
    )
}

fn failure_cluster_report_table(report: &FailureClusterReport) -> String {
    let mut lines = vec![
        String::from("field\tvalue"),
        format!("cluster_id\t{}", format_content_hash_ref(report.cluster_id)),
        format!(
            "minimal_representative\t{}",
            format_content_hash_ref(report.minimal_representative)
        ),
        format!("member_count\t{}", report.member_count),
        format!("replay_command\t{}", report.replay_command),
    ];
    for line in report.canonical_material().lines() {
        let (field, value) = line.split_once('=').unwrap_or((line, ""));
        lines.push(format!("canonical.{field}\t{value}"));
    }
    lines.join("\n")
}

fn failure_cluster_report_markdown(report: &FailureClusterReport) -> String {
    format!(
        "# Crucible Triage Cluster {}\n\n- Policy: {}\n- Members: {}\n- Minimal representative: {}\n- Replay: `{}`\n\n## Canonical Report\n\n```text\n{}\n```",
        format_content_hash_ref(report.cluster_id),
        signature_policy_level_label(report.policy.level()),
        report.member_count,
        format_content_hash_ref(report.minimal_representative),
        report.replay_command,
        report.canonical_material(),
    )
}

fn json_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len() + 2);
    escaped.push('"');
    for ch in value.chars() {
        match ch {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            '\u{08}' => escaped.push_str("\\b"),
            '\u{0c}' => escaped.push_str("\\f"),
            ch if ch.is_control() => {
                escaped.push_str(&format!("\\u{:04x}", u32::from(ch)));
            }
            ch => escaped.push(ch),
        }
    }
    escaped.push('"');
    escaped
}

fn signature_policy_level_label(level: SignaturePolicyLevel) -> &'static str {
    match level {
        SignaturePolicyLevel::Coarse => "coarse",
        SignaturePolicyLevel::Default => "default",
        SignaturePolicyLevel::Fine => "fine",
        SignaturePolicyLevel::Exact => "exact",
    }
}

fn failure_kind_label(kind: FailureKind) -> &'static str {
    match kind {
        FailureKind::PropertyViolation => "property-violation",
        FailureKind::Divergence => "divergence",
    }
}

fn failure_assertion_quantifier_label(quantifier: AssertionQuantifierKind) -> &'static str {
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

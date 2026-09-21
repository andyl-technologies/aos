//! Canonical findings-ledger parsing, validation, and reporting.

use super::*;

pub(crate) fn load_triage_findings_ledger(
    store: &crucible::LocalDagStore,
    source: &TriageFindingsSource,
) -> Result<LoadedTriageFindings, CliError> {
    match source {
        TriageFindingsSource::StoredLedger(hash) => {
            let bytes = store.get(hash).map_err(CliError::Store)?;
            parse_failure_findings_ledger_bytes(store, &bytes)
        }
        TriageFindingsSource::Path(path) if path.is_dir() => Err(artifact_error(format!(
            "triage FINDINGS `{}` is a directory; pass the signed findings ledger emitted by `search` or `fuzz`",
            path.display()
        ))),
        TriageFindingsSource::Path(path) => {
            let bytes = fs::read(path).map_err(|error| {
                artifact_error(format!(
                    "cannot read triage findings ledger `{}`: {error}",
                    path.display()
                ))
            })?;
            if bytes.is_empty() {
                return Err(artifact_error(format!(
                    "triage findings ledger `{}` is empty",
                    path.display()
                )));
            }
            if !looks_like_failure_findings_ledger(&bytes) {
                let input_kind = if decode_reproduction_artifact(&bytes).is_ok() {
                    "a reproduction artifact"
                } else {
                    "unsupported or malformed input"
                };
                return Err(artifact_error(format!(
                    "triage FINDINGS `{}` is {input_kind}, not a signed findings ledger emitted by `search` or `fuzz`",
                    path.display()
                )));
            }
            parse_failure_findings_ledger_bytes(store, &bytes)
        }
    }
}

pub(super) fn looks_like_failure_findings_ledger(bytes: &[u8]) -> bool {
    std::str::from_utf8(bytes)
        .ok()
        .and_then(|text| text.lines().next())
        .is_some_and(|schema| schema == FAILURE_TRIAGE_FINDINGS_LEDGER_SCHEMA)
}

pub(crate) fn parse_failure_findings_ledger_bytes(
    store: &crucible::LocalDagStore,
    bytes: &[u8],
) -> Result<LoadedTriageFindings, CliError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|error| artifact_error(format!("findings ledger is not UTF-8: {error}")))?;
    let mut lines = text.lines();
    if lines.next() != Some(FAILURE_TRIAGE_FINDINGS_LEDGER_SCHEMA) {
        return Err(artifact_error(
            "unsupported findings ledger artifact schema",
        ));
    }
    match lines.next() {
        Some("ledger_kind=reproduction") => {
            parse_reproduction_findings_ledger_bytes(store, bytes, text)
        }
        Some("ledger_kind=campaign") => parse_campaign_findings_ledger_bytes(store, bytes, text),
        _ => Err(artifact_error("unsupported findings ledger kind")),
    }
}

pub(super) fn parse_reproduction_findings_ledger_bytes(
    store: &crucible::LocalDagStore,
    bytes: &[u8],
    text: &str,
) -> Result<LoadedTriageFindings, CliError> {
    let mut by_index = BTreeMap::<usize, BTreeMap<String, String>>::new();
    let mut finding_count = None;
    for line in text.lines().skip(2) {
        if line.trim().is_empty() {
            continue;
        }
        if let Some(value) = line.strip_prefix("finding_count=") {
            if finding_count
                .replace(
                    value
                        .parse::<usize>()
                        .map_err(|_| artifact_error("malformed reproduction findings count"))?,
                )
                .is_some()
            {
                return Err(artifact_error("duplicate reproduction findings count"));
            }
            continue;
        }
        let Some(rest) = line.strip_prefix("finding.") else {
            return Err(artifact_error(
                "malformed reproduction findings ledger line",
            ));
        };
        let Some((index, field_value)) = rest.split_once('.') else {
            return Err(artifact_error(
                "malformed reproduction findings ledger field",
            ));
        };
        let index = index
            .parse::<usize>()
            .map_err(|_| artifact_error("malformed reproduction findings ledger index"))?;
        let Some((field, value)) = field_value.split_once('=') else {
            return Err(artifact_error(
                "malformed reproduction findings ledger value",
            ));
        };
        if by_index
            .entry(index)
            .or_default()
            .insert(field.to_owned(), value.to_owned())
            .is_some()
        {
            return Err(artifact_error(
                "duplicate reproduction findings ledger field",
            ));
        }
    }
    let finding_count = finding_count
        .ok_or_else(|| artifact_error("reproduction findings ledger is missing finding count"))?;
    if by_index.len() != finding_count || by_index.keys().copied().ne(0..finding_count) {
        return Err(artifact_error(
            "reproduction findings ledger count or indices are not canonical",
        ));
    }

    let mut findings = Vec::new();
    let mut evidence = BTreeMap::new();
    for (index, fields) in by_index {
        let item = parse_reproduction_finding_evidence(store, index, &fields)?;
        findings.push(crucible::FailureClusterFinding::new(
            item.finding.artifact.id(),
            item.discovery_signature.clone(),
        ));
        if evidence.insert(item.finding.artifact.id(), item).is_some() {
            return Err(artifact_error(
                "reproduction findings ledger repeats a reproduction artifact",
            ));
        }
    }
    let ledger = crucible::FailureFindingsLedger::from_signed_findings(findings).map_err(|_| {
        artifact_error("reproduction findings ledger contains conflicting signatures")
    })?;
    Ok(LoadedTriageFindings {
        ledger,
        evidence,
        campaign_evidence: Vec::new(),
        artifact_bytes: bytes.to_vec(),
    })
}

pub(super) fn parse_reproduction_finding_evidence(
    store: &crucible::LocalDagStore,
    index: usize,
    fields: &BTreeMap<String, String>,
) -> Result<TriageFindingEvidence, CliError> {
    let artifact = parse_required_hash_field(fields, "artifact")?;
    let discovery_path = parse_triage_discovery_path(required_field(fields, "discovery_path")?)?;
    let finding_fingerprint = parse_required_hash_field(fields, "finding_fingerprint")?;
    let coverage_fingerprint = parse_required_hash_field(fields, "coverage_fingerprint")?;
    let finding = crucible::FindingReproductionArtifact::load_from_store(
        discovery_path,
        finding_fingerprint,
        store,
        artifact,
    )
    .map_err(|error| artifact_error(format!("finding {index} artifact is invalid: {error}")))?;
    let frames = parse_reproduction_event_frames(fields)?;
    let evidence_kind = required_field(fields, "evidence")?;
    validate_reproduction_finding_field_set(fields, evidence_kind, frames.len())?;
    let item = match evidence_kind {
        "property" => {
            let assertion =
                crucible::AssertionId::from_name(parse_hex_string_field(fields, "assertion_hex")?);
            let message = parse_hex_string_field(fields, "message_hex")?;
            let quantifier = parse_assertion_quantifier(required_field(fields, "quantifier")?)?;
            let at_virtual_time = parse_u64_field(fields, "at_virtual_time")?;
            let at_icount = parse_optional_u64_field(fields, "at_icount")?
                .map(|retired| crucible::Icount { retired });
            let node = parse_optional_hex_string_field(fields, "node_hex")?
                .map(|name| crucible::NodeId { name });
            let detail = parse_hex_string_field(fields, "detail_hex")?;
            let violation = crucible_model::HostAssertionViolation {
                assertion,
                message,
                quantifier,
                event_kind: String::from("assertion_state_changed"),
                at_icount,
                at_virtual_time: crucible::VirtualTime {
                    ticks: at_virtual_time,
                },
                node,
                detail,
                reproduction_artifact: finding.artifact.id(),
            };
            triage_property_evidence_for_violation_with_recording(
                finding,
                violation,
                coverage_fingerprint,
                frames,
            )
        }
        "timeout" => {
            let budget_kind = match required_field(fields, "budget_kind")? {
                "execution-quanta" => crucible_model::FailureTimeoutBudgetKind::ExecutionQuanta,
                "virtual-time" => crucible_model::FailureTimeoutBudgetKind::VirtualTime,
                _ => return Err(artifact_error("unsupported timeout budget kind")),
            };
            let timeout = crucible_model::FailureTimeoutRecord::new(
                budget_kind,
                parse_optional_u64_field(fields, "configured_limit")?,
                parse_u64_field(fields, "observed_quanta")?,
                crucible::VirtualTime {
                    ticks: parse_u64_field(fields, "at_virtual_time")?,
                },
                parse_optional_u64_field(fields, "at_icount")?
                    .map(|retired| crucible::Icount { retired }),
                parse_optional_hex_string_field(fields, "node_hex")?
                    .map(|name| crucible::NodeId { name }),
                finding.artifact.id(),
            );
            triage_timeout_evidence(finding, timeout, coverage_fingerprint, frames)
        }
        _ => {
            return Err(artifact_error(
                "unsupported reproduction findings evidence kind",
            ));
        }
    }
    .map_err(|_| artifact_error(format!("finding {index} signature evidence is invalid")))?;

    let expected_signature = parse_required_hash_field(fields, "discovery_signature")?;
    if item.discovery_signature.content_hash() != expected_signature {
        return Err(artifact_error(format!(
            "finding {index} discovery signature does not match recorded evidence"
        )));
    }
    let material = parse_hex_string_field(fields, "discovery_signature_material_hex")?;
    if item.discovery_signature.report_material() != material {
        return Err(artifact_error(format!(
            "finding {index} discovery signature material does not match recorded evidence"
        )));
    }
    Ok(item)
}

pub(super) fn validate_reproduction_finding_field_set(
    fields: &BTreeMap<String, String>,
    evidence_kind: &str,
    frame_count: usize,
) -> Result<(), CliError> {
    let mut expected = [
        "artifact",
        "discovery_path",
        "finding_fingerprint",
        "coverage_fingerprint",
        "discovery_signature",
        "discovery_signature_material_hex",
        "evidence",
        "event_frame_count",
    ]
    .into_iter()
    .map(String::from)
    .collect::<BTreeSet<_>>();
    let evidence_fields: &[&str] = match evidence_kind {
        "property" => &[
            "assertion_hex",
            "message_hex",
            "quantifier",
            "at_virtual_time",
            "at_icount",
            "node_hex",
            "detail_hex",
        ],
        "timeout" => &[
            "budget_kind",
            "configured_limit",
            "observed_quanta",
            "at_virtual_time",
            "at_icount",
            "node_hex",
        ],
        _ => {
            return Err(artifact_error(
                "unsupported reproduction findings evidence kind",
            ));
        }
    };
    expected.extend(evidence_fields.iter().copied().map(String::from));
    expected.extend((0..frame_count).map(|index| format!("event_frame.{index}")));
    if fields.keys().any(|field| !expected.contains(field)) {
        return Err(artifact_error(
            "reproduction findings ledger contains a non-canonical field",
        ));
    }
    Ok(())
}

pub(crate) fn reproduction_findings_ledger_bytes(
    evidence: &[TriageFindingEvidence],
) -> Result<Vec<u8>, CliError> {
    let mut canonical_evidence = BTreeMap::new();
    for item in evidence {
        let artifact = item.finding.artifact.id();
        if let Some(existing) = canonical_evidence.insert(artifact, item)
            && existing != item
        {
            return Err(artifact_error(
                "cannot write conflicting evidence for one reproduction artifact",
            ));
        }
    }
    let mut lines = vec![
        String::from(FAILURE_TRIAGE_FINDINGS_LEDGER_SCHEMA),
        String::from("ledger_kind=reproduction"),
        format!("finding_count={}", canonical_evidence.len()),
    ];
    for (index, item) in canonical_evidence.values().enumerate() {
        let prefix = format!("finding.{index}");
        lines.push(format!(
            "{prefix}.artifact={}",
            item.finding.artifact.id().to_hex()
        ));
        lines.push(format!(
            "{prefix}.discovery_path={}",
            triage_discovery_path_label(item.finding.discovery_path)
        ));
        lines.push(format!(
            "{prefix}.finding_fingerprint={}",
            item.finding.finding_fingerprint.to_hex()
        ));
        lines.push(format!(
            "{prefix}.coverage_fingerprint={}",
            item.recorded_event_log.coverage_fingerprint().to_hex()
        ));
        lines.push(format!(
            "{prefix}.discovery_signature={}",
            item.discovery_signature.content_hash().to_hex()
        ));
        lines.push(format!(
            "{prefix}.discovery_signature_material_hex={}",
            ledger_hex(item.discovery_signature.report_material().as_bytes())
        ));
        match &item.failure {
            crucible_model::FailureClusterReportFailure::Property(record) => {
                lines.push(format!("{prefix}.evidence=property"));
                lines.push(format!(
                    "{prefix}.assertion_hex={}",
                    ledger_hex(record.violation.assertion.name.as_bytes())
                ));
                lines.push(format!(
                    "{prefix}.message_hex={}",
                    ledger_hex(record.violation.message.as_bytes())
                ));
                lines.push(format!(
                    "{prefix}.quantifier={}",
                    assertion_quantifier_label(record.violation.quantifier)
                ));
                lines.push(format!(
                    "{prefix}.at_virtual_time={}",
                    record.violation.at_virtual_time.ticks
                ));
                lines.push(format!(
                    "{prefix}.at_icount={}",
                    optional_u64_label(record.violation.at_icount.map(|value| value.retired))
                ));
                lines.push(format!(
                    "{prefix}.node_hex={}",
                    optional_hex_string_label(
                        record
                            .violation
                            .node
                            .as_ref()
                            .map(|node| node.name.as_str())
                    )
                ));
                lines.push(format!(
                    "{prefix}.detail_hex={}",
                    ledger_hex(record.violation.detail.as_bytes())
                ));
            }
            crucible_model::FailureClusterReportFailure::Timeout(timeout) => {
                lines.push(format!("{prefix}.evidence=timeout"));
                lines.push(format!(
                    "{prefix}.budget_kind={}",
                    match timeout.budget_kind {
                        crucible_model::FailureTimeoutBudgetKind::ExecutionQuanta => {
                            "execution-quanta"
                        }
                        crucible_model::FailureTimeoutBudgetKind::VirtualTime => "virtual-time",
                    }
                ));
                lines.push(format!(
                    "{prefix}.configured_limit={}",
                    optional_u64_label(timeout.configured_limit)
                ));
                lines.push(format!(
                    "{prefix}.observed_quanta={}",
                    timeout.observed_quanta
                ));
                lines.push(format!(
                    "{prefix}.at_virtual_time={}",
                    timeout.at_virtual_time.ticks
                ));
                lines.push(format!(
                    "{prefix}.at_icount={}",
                    optional_u64_label(timeout.at_icount.map(|value| value.retired))
                ));
                lines.push(format!(
                    "{prefix}.node_hex={}",
                    optional_hex_string_label(timeout.node.as_ref().map(|node| node.name.as_str()))
                ));
            }
            crucible_model::FailureClusterReportFailure::Divergence(_) => {
                return Err(artifact_error(
                    "reproduction findings ledger writer does not support divergence evidence",
                ));
            }
        }
        lines.push(format!(
            "{prefix}.event_frame_count={}",
            item.recorded_event_frames.len()
        ));
        for (frame_index, frame) in item.recorded_event_frames.iter().enumerate() {
            lines.push(format!(
                "{prefix}.event_frame.{frame_index}={}",
                ledger_hex(frame)
            ));
        }
    }
    lines.push(String::new());
    Ok(lines.join("\n").into_bytes())
}

pub(crate) fn write_reproduction_findings_ledger(
    artifact_dir: &Path,
    findings_out: Option<&Path>,
    evidence: &[TriageFindingEvidence],
) -> Result<(PathBuf, crucible::ContentHash, Vec<u8>), CliError> {
    let bytes = reproduction_findings_ledger_bytes(evidence)?;
    let digest = crucible::ContentHash::from_bytes(&bytes);
    let path = findings_out.map(Path::to_path_buf).unwrap_or_else(|| {
        artifact_dir
            .join("findings")
            .join(format!("{}.crucible-findings", digest.to_hex()))
    });
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, &bytes)?;
    Ok((path, digest, bytes))
}

pub(super) fn required_field<'a>(
    fields: &'a BTreeMap<String, String>,
    field: &'static str,
) -> Result<&'a str, CliError> {
    fields
        .get(field)
        .map(String::as_str)
        .ok_or_else(|| artifact_error(format!("signed findings ledger is missing `{field}`")))
}

pub(super) fn parse_required_hash_field(
    fields: &BTreeMap<String, String>,
    field: &'static str,
) -> Result<crucible::ContentHash, CliError> {
    parse_hex_content_hash(field, required_field(fields, field)?)
}

pub(super) fn parse_u64_field(
    fields: &BTreeMap<String, String>,
    field: &'static str,
) -> Result<u64, CliError> {
    parse_triage_u64(field, required_field(fields, field)?)
}

pub(super) fn parse_triage_u64(field: &'static str, value: &str) -> Result<u64, CliError> {
    value
        .parse::<u64>()
        .map_err(|_| artifact_error(format!("malformed signed findings ledger `{field}`")))
}

pub(super) fn parse_triage_discovery_path(
    value: &str,
) -> Result<crucible::FindingDiscoveryPath, CliError> {
    match value {
        "campaign-fork" => Ok(crucible::FindingDiscoveryPath::CampaignFork),
        "state-space-search" => Ok(crucible::FindingDiscoveryPath::StateSpaceSearch),
        "coverage-guided-fuzzing" => Ok(crucible::FindingDiscoveryPath::CoverageGuidedFuzzing),
        "retained-corpus-entry" => Ok(crucible::FindingDiscoveryPath::RetainedCorpusEntry),
        _ => Err(artifact_error(
            "malformed signed findings ledger discovery_path",
        )),
    }
}

pub(super) fn parse_assertion_quantifier(
    value: &str,
) -> Result<crucible_model::AssertionQuantifierKind, CliError> {
    match value {
        "always" => Ok(crucible_model::AssertionQuantifierKind::Always),
        "sometimes" => Ok(crucible_model::AssertionQuantifierKind::Sometimes),
        "eventually" => Ok(crucible_model::AssertionQuantifierKind::Eventually),
        "reachable" => Ok(crucible_model::AssertionQuantifierKind::Reachable),
        "after-quiescence" => Ok(crucible_model::AssertionQuantifierKind::AfterQuiescence),
        "guest-always" => Ok(crucible_model::AssertionQuantifierKind::GuestAlways),
        "guest-sometimes" => Ok(crucible_model::AssertionQuantifierKind::GuestSometimes),
        "guest-reachable" => Ok(crucible_model::AssertionQuantifierKind::GuestReachable),
        "guest-unreachable" => Ok(crucible_model::AssertionQuantifierKind::GuestUnreachable),
        _ => Err(artifact_error(
            "malformed signed findings ledger assertion quantifier",
        )),
    }
}

pub(super) fn assertion_quantifier_label(
    value: crucible_model::AssertionQuantifierKind,
) -> &'static str {
    match value {
        crucible_model::AssertionQuantifierKind::Always => "always",
        crucible_model::AssertionQuantifierKind::Sometimes => "sometimes",
        crucible_model::AssertionQuantifierKind::Eventually => "eventually",
        crucible_model::AssertionQuantifierKind::Reachable => "reachable",
        crucible_model::AssertionQuantifierKind::AfterQuiescence => "after-quiescence",
        crucible_model::AssertionQuantifierKind::GuestAlways => "guest-always",
        crucible_model::AssertionQuantifierKind::GuestSometimes => "guest-sometimes",
        crucible_model::AssertionQuantifierKind::GuestReachable => "guest-reachable",
        crucible_model::AssertionQuantifierKind::GuestUnreachable => "guest-unreachable",
    }
}

pub(super) fn triage_discovery_path_label(value: crucible::FindingDiscoveryPath) -> &'static str {
    match value {
        crucible::FindingDiscoveryPath::CampaignFork => "campaign-fork",
        crucible::FindingDiscoveryPath::StateSpaceSearch => "state-space-search",
        crucible::FindingDiscoveryPath::CoverageGuidedFuzzing => "coverage-guided-fuzzing",
        crucible::FindingDiscoveryPath::RetainedCorpusEntry => "retained-corpus-entry",
    }
}

pub(crate) fn ledger_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(super) fn parse_hex_string_field(
    fields: &BTreeMap<String, String>,
    field: &'static str,
) -> Result<String, CliError> {
    let bytes = parse_hex_bytes(0, field, required_field(fields, field)?)?;
    String::from_utf8(bytes).map_err(|error| {
        artifact_error(format!(
            "signed findings ledger `{field}` is not UTF-8: {error}"
        ))
    })
}

pub(super) fn parse_optional_hex_string_field(
    fields: &BTreeMap<String, String>,
    field: &'static str,
) -> Result<Option<String>, CliError> {
    match required_field(fields, field)? {
        "none" => Ok(None),
        _ => parse_hex_string_field(fields, field).map(Some),
    }
}

pub(super) fn parse_optional_u64_field(
    fields: &BTreeMap<String, String>,
    field: &'static str,
) -> Result<Option<u64>, CliError> {
    match required_field(fields, field)? {
        "none" => Ok(None),
        value => parse_triage_u64(field, value).map(Some),
    }
}

pub(super) fn parse_reproduction_event_frames(
    fields: &BTreeMap<String, String>,
) -> Result<Vec<Vec<u8>>, CliError> {
    let count = parse_u64_field(fields, "event_frame_count")?;
    let mut frames = Vec::new();
    for index in 0..count {
        let field = format!("event_frame.{index}");
        let value = fields.get(&field).ok_or_else(|| {
            artifact_error(format!("signed findings ledger is missing `{field}`"))
        })?;
        frames.push(parse_hex_bytes(index as usize, "event_frame", value)?);
    }
    Ok(frames)
}

pub(super) fn optional_u64_label(value: Option<u64>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| String::from("none"))
}

pub(super) fn optional_hex_string_label(value: Option<&str>) -> String {
    value
        .map(|value| ledger_hex(value.as_bytes()))
        .unwrap_or_else(|| String::from("none"))
}

pub(super) fn write_triage_report(
    plan: &TriageInvocationPlan,
    report_set: &crucible::FailureClusterReportSet,
) -> Result<PathBuf, CliError> {
    fs::create_dir_all(&plan.report_dir)?;
    let path = plan.report_dir.join(format!(
        "triage-report.{}",
        triage_report_extension(plan.format)
    ));
    fs::write(&path, report_set.render(plan.format))?;
    Ok(path)
}

pub(super) fn compare_triage_result(
    store: &crucible::LocalDagStore,
    result: &crucible::FailureTriageResult,
    target: &TriageCompareTarget,
) -> Result<TriageSummaryDiff, CliError> {
    let baseline = match target {
        TriageCompareTarget::StoredResult(hash) => {
            let bytes = store.get(hash).map_err(CliError::Store)?;
            TriageResultSummary::from_artifact_bytes(&bytes)?
        }
        TriageCompareTarget::Path(path) => {
            let bytes = fs::read(path)?;
            TriageResultSummary::from_artifact_bytes(&bytes)?
        }
    };
    Ok(TriageResultSummary::from_result(result).diff_from(&baseline))
}

pub(super) fn triage_report_extension(
    format: crucible::FailureClusterReportFormat,
) -> &'static str {
    match format {
        crucible::FailureClusterReportFormat::JsonLines => "jsonl",
        crucible::FailureClusterReportFormat::Json => "json",
        crucible::FailureClusterReportFormat::Table => "txt",
        crucible::FailureClusterReportFormat::Markdown => "md",
    }
}

pub(crate) fn parse_hex_content_hash(
    field: &'static str,
    hex: &str,
) -> Result<crucible::ContentHash, CliError> {
    let reference = format!("blake3:{hex}");
    crucible::ContentAddressedBlobRef::parse(field, &reference)
        .map(crucible::ContentAddressedBlobRef::hash)
        .map_err(|error| artifact_error(format!("invalid {field}: {error}")))
}

pub(crate) fn format_content_hash_ref(hash: crucible::ContentHash) -> String {
    crucible::ContentAddressedBlobRef::from_hash(hash).to_uri()
}

pub(super) fn parse_triage_findings_source(value: &str) -> TriageFindingsSource {
    if let Ok(reference) = crucible::ContentAddressedBlobRef::parse("findings", value) {
        TriageFindingsSource::StoredLedger(reference.hash())
    } else {
        TriageFindingsSource::Path(PathBuf::from(value))
    }
}

pub(super) fn parse_triage_compare_target(value: &str) -> Result<TriageCompareTarget, CliError> {
    if value.is_empty() {
        return Err(usage_error("--compare must not be empty"));
    }
    if let Ok(reference) = crucible::ContentAddressedBlobRef::parse("triage compare", value) {
        Ok(TriageCompareTarget::StoredResult(reference.hash()))
    } else {
        Ok(TriageCompareTarget::Path(PathBuf::from(value)))
    }
}

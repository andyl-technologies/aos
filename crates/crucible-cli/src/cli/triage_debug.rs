//! Failure triage and time-travel debugging planning.

use super::*;
pub(super) fn plan_triage_invocation(
    cli: &Cli,
    args: &TriageArgs,
) -> Result<TriageInvocationPlan, CliError> {
    if cli.daemon.is_some() {
        return Err(CliError::Backend(
            "triage is an offline DagStore operation and must not use --daemon".to_string(),
        ));
    }
    if args.findings.is_empty() {
        return Err(usage_error("triage requires a non-empty FINDINGS argument"));
    }

    let findings = parse_triage_findings_source(&args.findings);
    let compare = args
        .compare
        .as_deref()
        .map(parse_triage_compare_target)
        .transpose()?;
    let report_dir = args
        .report
        .clone()
        .unwrap_or_else(|| cli.artifact_dir.clone());
    let store_root = cli
        .store
        .clone()
        .unwrap_or_else(|| cli.artifact_dir.join("store"));
    let mut pipeline = vec![TriagePipelineStep::LoadFindingsLedger];
    if args.recompute_signatures {
        pipeline.push(TriagePipelineStep::RecomputeSignatureSelfCheck);
    }
    pipeline.push(TriagePipelineStep::Cluster);
    pipeline.push(match args.minimize {
        TriageMinimizeArg::None => TriagePipelineStep::SkipMinimization,
        TriageMinimizeArg::Representative => TriagePipelineStep::MinimizeRepresentative,
        TriageMinimizeArg::All => TriagePipelineStep::MinimizeAll,
    });
    pipeline.push(TriagePipelineStep::EmitReports);
    pipeline.push(TriagePipelineStep::StoreTriageResult);
    if compare.is_some() {
        pipeline.push(TriagePipelineStep::CompareContentDiff);
    }

    let plan = TriageInvocationPlan {
        findings,
        policy: args.policy.policy(),
        minimize: args.minimize,
        report_dir,
        format: cli.output_format().triage_report_format(),
        recompute_signatures: args.recompute_signatures,
        compare,
        store_root,
        pipeline,
        failure_exit_code: CliError::Triage(
            "triage self-check or signature-preserving minimization failed".to_string(),
        )
        .exit_code(),
        thin_driver: true,
        owns_run_state: false,
        offline: true,
        scheduler_started: false,
    };
    if !plan.proves_t_tri_7() {
        return Err(CliError::Backend(
            "triage planner does not satisfy the RFC-0010 thin-driver contract".to_string(),
        ));
    }
    Ok(plan)
}

pub(super) fn run_triage_invocation(
    cli: &Cli,
    args: &TriageArgs,
) -> Result<TriageRunReport, CliError> {
    let plan = plan_triage_invocation(cli, args)?;
    let store = crucible::LocalDagStore::new(plan.store_root.clone());
    let loaded_findings = load_triage_findings_ledger(&store, &plan.findings)?;
    let stored_ledger = store_loaded_findings_ledger(&store, &loaded_findings)?;
    let ledger = loaded_findings.ledger;
    if ledger.artifact_count() != 0 && ledger.signed_findings().is_empty() {
        return Err(CliError::Artifact(format!(
            "triage findings ledger contains {} artifact(s), but discovery-time signature evidence is not available in this ledger format",
            ledger.artifact_count()
        )));
    }

    let clustering = crucible::FailureClusteringResult::from_findings(
        plan.policy,
        ledger.signed_findings().iter().cloned(),
    )
    .map_err(|_| {
        CliError::Triage("triage clustering failed for the findings ledger".to_string())
    })?;
    let minimization = build_triage_minimization(&plan, &clustering, &loaded_findings.evidence)?;
    let report_set = build_triage_report_set(
        plan.policy,
        &clustering,
        &minimization,
        &loaded_findings.evidence,
    )?;
    let signature_self_check = if plan.recompute_signatures {
        build_triage_signature_self_check(&loaded_findings.evidence)?
    } else {
        crucible::FailureTriageSignatureSelfCheck::skipped()
    };
    let result = crucible::FailureTriageResult::from_parts(
        stored_ledger.key,
        clustering,
        minimization,
        report_set,
        signature_self_check,
    )
    .map_err(|_| CliError::Triage("triage result validation failed".to_string()))?;
    let report_path = write_triage_report(&plan, &result.report_set)?;
    let compare = plan
        .compare
        .as_ref()
        .map(|target| compare_triage_result(&store, &result, target))
        .transpose()?;
    let stored_result = result.store(&store).map_err(CliError::Store)?;

    Ok(TriageRunReport {
        plan,
        ledger,
        stored_ledger,
        result,
        stored_result,
        report_path,
        compare,
    })
}

pub(super) fn store_loaded_findings_ledger(
    store: &crucible::LocalDagStore,
    findings: &LoadedTriageFindings,
) -> Result<crucible::FailureTriageStoredArtifact, CliError> {
    let bytes = if findings.evidence.is_empty() {
        findings.ledger.artifact_bytes()
    } else {
        findings.artifact_bytes.clone()
    };
    let key = crucible::ContentHash::from_bytes(&bytes);
    let cache_hit = store.exists(&key).map_err(CliError::Store)?;
    let stored = store.put(&bytes).map_err(CliError::Store)?;
    if stored != key {
        return Err(artifact_error(
            "stored findings ledger key did not match content hash",
        ));
    }
    Ok(crucible::FailureTriageStoredArtifact {
        key,
        cache_hit,
        size_bytes: bytes.len(),
    })
}

pub(super) fn build_triage_minimization(
    plan: &TriageInvocationPlan,
    clustering: &crucible::FailureClusteringResult,
    evidence: &BTreeMap<crucible::ContentHash, TriageFindingEvidence>,
) -> Result<crucible::FailureSignaturePreservingMinimizationResult, CliError> {
    if clustering.cluster_count() == 0 {
        return Ok(crucible::FailureSignaturePreservingMinimizationResult {
            policy: plan.policy,
            runs: Vec::new(),
        });
    }

    match plan.minimize {
        TriageMinimizeArg::None => {
            let mut runs = Vec::new();
            for cluster in &clustering.clusters {
                let representative = cluster.representative_member().ok_or_else(|| {
                    CliError::Triage("triage cluster has no representative".to_string())
                })?;
                let representative_evidence = evidence
                    .get(&representative.reproduction_artifact)
                    .ok_or_else(|| {
                    artifact_error("missing representative evidence in findings ledger")
                })?;
                let target_signature_key = representative
                    .signature
                    .signature_key(plan.policy)
                    .map_err(|_| {
                        CliError::Triage(
                            "triage representative signature does not project under policy"
                                .to_string(),
                        )
                    })?;
                runs.push(crucible_model::FailureSignaturePreservingMinimizationRun {
                    cluster_id: cluster.id,
                    representative_artifact: representative.reproduction_artifact,
                    target_signature_key: target_signature_key.clone(),
                    minimized_signature_key: target_signature_key,
                    minimization: crucible_model::MinimizationRun {
                        seed: crucible::Seed::default(),
                        target_fingerprint: representative_evidence.finding.finding_fingerprint,
                        original: representative_evidence.finding.clone(),
                        minimized: representative_evidence.finding.clone(),
                        attempts: Vec::new(),
                    },
                });
            }
            Ok(crucible::FailureSignaturePreservingMinimizationResult {
                policy: plan.policy,
                runs,
            })
        }
        TriageMinimizeArg::Representative | TriageMinimizeArg::All => {
            let templates = triage_signature_templates_by_fingerprint(clustering, evidence)?;
            clustering
                .minimize_representatives(
                    crucible_model::MinimizationConfig::new(crucible::Seed::default()),
                    |artifact| {
                        evidence
                            .get(&artifact)
                            .map(|item| item.finding.clone())
                            .ok_or(
                                crucible_model::EngineError::UnifiedOperationEvidenceMismatch {
                                    operation: "triage-minimization",
                                    reason: "representative evidence missing from findings ledger",
                                },
                            )
                    },
                    |candidate| {
                        if let Some(item) = evidence.get(&candidate.artifact.id()) {
                            return Ok(Some(item.discovery_signature.clone()));
                        }
                        let template = templates.get(&candidate.finding_fingerprint).ok_or(
                            crucible_model::EngineError::UnifiedOperationEvidenceMismatch {
                                operation: "triage-minimization",
                                reason: "candidate evidence template missing from findings ledger",
                            },
                        )?;
                        triage_evidence_for_finding(candidate.clone(), template)
                            .map(|item| Some(item.discovery_signature))
                    },
                )
                .map_err(|_| {
                    CliError::Triage("triage signature-preserving minimization failed".to_string())
                })
        }
    }
}

pub(super) fn triage_signature_templates_by_fingerprint(
    clustering: &crucible::FailureClusteringResult,
    evidence: &BTreeMap<crucible::ContentHash, TriageFindingEvidence>,
) -> Result<BTreeMap<crucible::ContentHash, TriageFindingEvidence>, CliError> {
    let mut templates = BTreeMap::new();
    for cluster in &clustering.clusters {
        let representative = cluster
            .representative_member()
            .ok_or_else(|| CliError::Triage("triage cluster has no representative".to_string()))?;
        let item = evidence
            .get(&representative.reproduction_artifact)
            .ok_or_else(|| artifact_error("missing representative evidence in findings ledger"))?;
        match templates.entry(item.finding.finding_fingerprint) {
            Entry::Vacant(entry) => {
                entry.insert(item.clone());
            }
            Entry::Occupied(entry)
                if entry.get().discovery_signature.report_material()
                    == item.discovery_signature.report_material() => {}
            Entry::Occupied(_) => {
                return Err(CliError::Triage(
                    "triage findings reuse a fingerprint with conflicting signatures".to_string(),
                ));
            }
        }
    }
    Ok(templates)
}

pub(super) fn build_triage_report_set(
    policy: crucible::SignaturePolicy,
    clustering: &crucible::FailureClusteringResult,
    minimization: &crucible::FailureSignaturePreservingMinimizationResult,
    evidence: &BTreeMap<crucible::ContentHash, TriageFindingEvidence>,
) -> Result<crucible::FailureClusterReportSet, CliError> {
    let runs_by_cluster = minimization
        .runs
        .iter()
        .map(|run| (run.cluster_id, run))
        .collect::<BTreeMap<_, _>>();
    let mut reports = Vec::new();
    for cluster in &clustering.clusters {
        let run = runs_by_cluster
            .get(&cluster.id)
            .copied()
            .ok_or_else(|| CliError::Triage("missing triage minimization run".to_string()))?;
        let item = triage_report_evidence_for_minimization_run(run, evidence)?;
        let report = crucible_model::FailureClusterReport::from_cluster(
            policy,
            cluster,
            run,
            item.failure.clone(),
            &item.recorded_event_log,
            &crucible_model::FailureSignatureNormalization::identity(),
            8,
        )
        .map_err(|_| CliError::Triage("triage report construction failed".to_string()))?;
        reports.push(report);
    }
    crucible::FailureClusterReportSet::from_reports(policy, reports)
        .map_err(|_| CliError::Triage("triage report set assembly failed".to_string()))
}

pub(super) fn triage_report_evidence_for_minimization_run(
    run: &crucible_model::FailureSignaturePreservingMinimizationRun,
    evidence: &BTreeMap<crucible::ContentHash, TriageFindingEvidence>,
) -> Result<TriageFindingEvidence, CliError> {
    if let Some(item) = evidence.get(&run.minimized_artifact()) {
        return Ok(item.clone());
    }
    let template = evidence.get(&run.representative_artifact).ok_or_else(|| {
        artifact_error("missing minimized representative evidence in findings ledger")
    })?;
    triage_evidence_for_finding(run.minimization.minimized.clone(), template)
        .map_err(|_| CliError::Triage("triage report evidence reconstruction failed".to_string()))
}

pub(super) fn build_triage_signature_self_check(
    evidence: &BTreeMap<crucible::ContentHash, TriageFindingEvidence>,
) -> Result<crucible::FailureTriageSignatureSelfCheck, CliError> {
    let mut checks = Vec::new();
    for (artifact, item) in evidence {
        let recomputed = recompute_triage_evidence_signature(item)?;
        checks.push(crucible::FailureTriageSignatureSelfCheckInput::new(
            *artifact,
            item.discovery_signature.clone(),
            recomputed,
        ));
    }
    Ok(crucible::FailureTriageSignatureSelfCheck::from_signature_pairs(checks))
}

pub(super) fn recompute_triage_evidence_signature(
    item: &TriageFindingEvidence,
) -> Result<crucible_model::FailureSignature, CliError> {
    match &item.failure {
        crucible_model::FailureClusterReportFailure::Property(record) => {
            crucible_model::FailureSignature::from_recorded_property_violation(
                &item.finding,
                &item.recorded_event_log,
                record,
            )
        }
        crucible_model::FailureClusterReportFailure::Divergence(divergence) => {
            let _ = divergence;
            return Err(CliError::Triage(
                "triage divergence evidence is not supported by this ledger parser".to_string(),
            ));
        }
    }
    .map_err(|_| CliError::Triage("triage signature recomputation failed".to_string()))
}

pub(super) fn triage_evidence_for_finding(
    finding: crucible::FindingReproductionArtifact,
    template: &TriageFindingEvidence,
) -> Result<TriageFindingEvidence, crucible_model::EngineError> {
    match &template.failure {
        crucible_model::FailureClusterReportFailure::Property(record) => {
            let mut violation = record.violation.clone();
            violation.reproduction_artifact = finding.artifact.id();
            triage_property_evidence_for_violation(finding, violation)
        }
        crucible_model::FailureClusterReportFailure::Divergence(_) => Err(
            crucible_model::EngineError::UnifiedOperationEvidenceMismatch {
                operation: "triage-evidence",
                reason: "divergence evidence is not supported by this ledger parser",
            },
        ),
    }
}

pub(super) fn triage_property_evidence_for_violation(
    finding: crucible::FindingReproductionArtifact,
    violation: crucible_model::HostAssertionViolation,
) -> Result<TriageFindingEvidence, crucible_model::EngineError> {
    let entries = vec![
        crucible::SchedulerEventLogEntry::assertion_state_observation(
            0,
            violation.at_virtual_time,
            violation.assertion.clone(),
            crucible::AssertionPhase::Violated,
        ),
    ];
    let event_log_artifact = finding.artifact.event_log_debug_artifact(
        crucible::EventLogOffset::new(crucible::ContentHash::default(), 0, 0),
        &entries,
    );
    let recorded_event_log = crucible_model::FailureRecordedEventLog::from_recorded_artifact(
        &finding,
        &event_log_artifact,
        &entries,
    )?;
    let failure = crucible_model::FailureClusterReportFailure::property(
        crucible_model::FailurePropertyViolationRecord::new(violation),
    );
    let crucible_model::FailureClusterReportFailure::Property(record) = &failure else {
        return Err(
            crucible_model::EngineError::UnifiedOperationEvidenceMismatch {
                operation: "triage-evidence",
                reason: "property evidence did not construct a property failure",
            },
        );
    };
    let discovery_signature = crucible_model::FailureSignature::from_recorded_property_violation(
        &finding,
        &recorded_event_log,
        record,
    )?;
    Ok(TriageFindingEvidence {
        finding,
        recorded_event_log,
        failure,
        discovery_signature,
    })
}

pub(super) fn load_triage_findings_ledger(
    store: &crucible::LocalDagStore,
    source: &TriageFindingsSource,
) -> Result<LoadedTriageFindings, CliError> {
    match source {
        TriageFindingsSource::StoredLedger(hash) => {
            let bytes = store.get(hash).map_err(CliError::Store)?;
            parse_failure_findings_ledger_bytes(store, &bytes)
        }
        TriageFindingsSource::Path(path) if path.is_dir() => {
            let mut entries = fs::read_dir(path)?
                .collect::<Result<Vec<_>, io::Error>>()?
                .into_iter()
                .filter_map(|entry| {
                    entry
                        .file_type()
                        .ok()
                        .filter(|kind| kind.is_file())
                        .map(|_| entry.path())
                })
                .collect::<Vec<_>>();
            entries.sort();
            let mut artifacts = Vec::with_capacity(entries.len());
            for entry in entries {
                let bytes = fs::read(&entry)?;
                artifacts.push(store.put(&bytes).map_err(CliError::Store)?);
            }
            Ok(loaded_artifact_only_findings(
                crucible::FailureFindingsLedger::from_artifacts(artifacts),
            ))
        }
        TriageFindingsSource::Path(path) => {
            let bytes = fs::read(path)?;
            if looks_like_failure_findings_ledger(&bytes) {
                return parse_failure_findings_ledger_bytes(store, &bytes);
            }
            store
                .put(&bytes)
                .map(|hash| {
                    loaded_artifact_only_findings(crucible::FailureFindingsLedger::from_artifacts(
                        [hash],
                    ))
                })
                .map_err(CliError::Store)
        }
    }
}

pub(super) fn loaded_artifact_only_findings(
    ledger: crucible::FailureFindingsLedger,
) -> LoadedTriageFindings {
    LoadedTriageFindings {
        artifact_bytes: ledger.artifact_bytes(),
        ledger,
        evidence: BTreeMap::new(),
    }
}

pub(super) fn looks_like_failure_findings_ledger(bytes: &[u8]) -> bool {
    std::str::from_utf8(bytes)
        .ok()
        .and_then(|text| text.lines().next())
        .is_some_and(|schema| {
            schema == FAILURE_TRIAGE_FINDINGS_LEDGER_SCHEMA_V1
                || schema == FAILURE_TRIAGE_FINDINGS_LEDGER_SCHEMA_V2
        })
}

pub(super) fn parse_failure_findings_ledger_bytes(
    store: &crucible::LocalDagStore,
    bytes: &[u8],
) -> Result<LoadedTriageFindings, CliError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|error| artifact_error(format!("findings ledger is not UTF-8: {error}")))?;
    match text.lines().next() {
        Some(FAILURE_TRIAGE_FINDINGS_LEDGER_SCHEMA_V1) => {
            parse_failure_findings_ledger_v1_bytes(bytes, text)
        }
        Some(FAILURE_TRIAGE_FINDINGS_LEDGER_SCHEMA_V2) => {
            parse_failure_findings_ledger_v2_bytes(store, bytes, text)
        }
        _ => Err(artifact_error(
            "unsupported findings ledger artifact schema",
        )),
    }
}

pub(super) fn parse_failure_findings_ledger_v1_bytes(
    bytes: &[u8],
    text: &str,
) -> Result<LoadedTriageFindings, CliError> {
    let mut artifacts = Vec::new();
    for line in text.lines() {
        if let Some(hex) = line.strip_prefix("artifact.") {
            let Some((_, value)) = hex.split_once('=') else {
                return Err(artifact_error("malformed findings ledger artifact line"));
            };
            artifacts.push(parse_hex_content_hash("findings ledger artifact", value)?);
        }
        if line.starts_with("finding.") {
            return Err(artifact_error(
                "findings ledger signature evidence must come from engine-owned discovery artifacts",
            ));
        }
    }
    Ok(LoadedTriageFindings {
        ledger: crucible::FailureFindingsLedger::from_artifacts(artifacts),
        evidence: BTreeMap::new(),
        artifact_bytes: bytes.to_vec(),
    })
}

pub(super) fn parse_failure_findings_ledger_v2_bytes(
    store: &crucible::LocalDagStore,
    bytes: &[u8],
    text: &str,
) -> Result<LoadedTriageFindings, CliError> {
    let mut by_index = BTreeMap::<usize, BTreeMap<String, String>>::new();
    for line in text.lines().skip(1) {
        if line.trim().is_empty() {
            continue;
        }
        let Some(rest) = line.strip_prefix("finding.") else {
            return Err(artifact_error("malformed signed findings ledger line"));
        };
        let Some((index, field_value)) = rest.split_once('.') else {
            return Err(artifact_error("malformed signed findings ledger field"));
        };
        let index = index
            .parse::<usize>()
            .map_err(|_| artifact_error("malformed signed findings ledger index"))?;
        let Some((field, value)) = field_value.split_once('=') else {
            return Err(artifact_error("malformed signed findings ledger value"));
        };
        let previous = by_index
            .entry(index)
            .or_default()
            .insert(field.to_owned(), value.to_owned());
        if previous.is_some() {
            return Err(artifact_error("duplicate signed findings ledger field"));
        }
    }

    let mut findings = Vec::new();
    let mut evidence = BTreeMap::new();
    for (index, fields) in by_index {
        let item = parse_triage_property_finding_evidence(store, index, &fields)?;
        findings.push(crucible::FailureClusterFinding::new(
            item.finding.artifact.id(),
            item.discovery_signature.clone(),
        ));
        evidence.insert(item.finding.artifact.id(), item);
    }
    let ledger = crucible::FailureFindingsLedger::from_signed_findings(findings)
        .map_err(|_| artifact_error("signed findings ledger contains conflicting signatures"))?;
    Ok(LoadedTriageFindings {
        ledger,
        evidence,
        artifact_bytes: bytes.to_vec(),
    })
}

pub(super) fn parse_triage_property_finding_evidence(
    store: &crucible::LocalDagStore,
    index: usize,
    fields: &BTreeMap<String, String>,
) -> Result<TriageFindingEvidence, CliError> {
    let artifact = parse_required_hash_field(fields, "artifact")?;
    let discovery_path = parse_triage_discovery_path(required_field(fields, "discovery_path")?)?;
    let finding_fingerprint = parse_required_hash_field(fields, "finding_fingerprint")?;
    let assertion = crucible::AssertionId::from_name(required_field(fields, "assertion")?);
    let discovery_signature_assertion = fields
        .get("discovery_signature.assertion")
        .map(crucible::AssertionId::from_name);
    let message = required_field(fields, "message")?.to_owned();
    let quantifier = parse_assertion_quantifier(required_field(fields, "quantifier")?)?;
    let event_kind = required_field(fields, "event_kind")?.to_owned();
    if event_kind != "assertion_state_changed" {
        return Err(artifact_error(format!(
            "finding {index} event_kind `{event_kind}` is not supported by this ledger parser"
        )));
    }
    let at_icount = parse_u64_field(fields, "at_icount")?;
    let at_virtual_time = fields
        .get("at_virtual_time")
        .map(|value| parse_triage_u64("at_virtual_time", value))
        .transpose()?
        .unwrap_or(at_icount);
    let node = fields
        .get("node")
        .filter(|value| value.as_str() != "none")
        .map(|value| crucible::NodeId {
            name: value.to_owned(),
        });
    let detail = required_field(fields, "detail")?.to_owned();

    let finding = crucible::FindingReproductionArtifact::load_from_store(
        discovery_path,
        finding_fingerprint,
        store,
        artifact,
    )
    .map_err(|error| artifact_error(format!("finding {index} artifact is invalid: {error}")))?;
    let violation = crucible_model::HostAssertionViolation {
        assertion: assertion.clone(),
        message,
        quantifier,
        event_kind,
        at_icount: Some(crucible::Icount { retired: at_icount }),
        at_virtual_time: crucible::VirtualTime {
            ticks: at_virtual_time,
        },
        node,
        detail,
        reproduction_artifact: finding.artifact.id(),
    };
    let mut item = triage_property_evidence_for_violation(finding, violation)
        .map_err(|_| artifact_error(format!("finding {index} signature evidence is invalid")))?;
    if let Some(assertion) = discovery_signature_assertion {
        let property = item.discovery_signature.property.as_mut().ok_or_else(|| {
            artifact_error(format!(
                "finding {index} discovery signature cannot carry a property override"
            ))
        })?;
        property.id = assertion;
    }

    Ok(item)
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
        "interactive-fork" => Ok(crucible::FindingDiscoveryPath::InteractiveFork),
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

pub(super) fn parse_hex_content_hash(
    field: &'static str,
    hex: &str,
) -> Result<crucible::ContentHash, CliError> {
    let reference = format!("blake3:{hex}");
    crucible::ContentAddressedBlobRef::parse(field, &reference)
        .map(crucible::ContentAddressedBlobRef::hash)
        .map_err(|error| artifact_error(format!("invalid {field}: {error}")))
}

pub(super) fn format_content_hash_ref(hash: crucible::ContentHash) -> String {
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

pub(super) fn plan_debug_invocation(
    _cli: &Cli,
    args: &DebugArgs,
) -> Result<DebugInvocationPlan, CliError> {
    #[cfg(any(test, feature = "test-double"))]
    if _cli.backend == Backend::Double {
        return Err(CliError::Backend(
            "selected backend `double` does not implement open_gdbstub".to_string(),
        ));
    }

    let target = debug_target(args)?;
    let coordinate = debug_coordinate(args, &target)?;
    let checkpoint_stride = args
        .checkpoint_stride
        .map(validate_debug_checkpoint_stride)
        .transpose()?;
    if args.node.as_deref().is_some_and(str::is_empty) {
        return Err(usage_error("--node must not be empty"));
    }
    let gdb_listen = args
        .gdb_listen
        .clone()
        .unwrap_or_else(|| "127.0.0.1:0".to_string());
    crucible::DebugGdbEndpoint::new("gdb_listen", gdb_listen.clone())
        .map_err(|error| usage_error(format!("invalid --gdb-listen: {error}")))?;

    let verb = debug_verb(args)?;
    let explicit_fork = matches!(verb, DebugInteractiveVerbPlan::ForkDebug);
    if explicit_fork && !args.allow_mutate {
        return Err(usage_error(
            "fork-debug requires --allow-mutate authorization",
        ));
    }
    let read_only = !explicit_fork;
    let mut session_commands = vec![SessionCommand::query_snapshot(), SessionCommand::Snapshot];
    let mut engine_operations = vec![
        DebugEngineOperation::ResolveTarget,
        DebugEngineOperation::Instantiate,
        DebugEngineOperation::AttachGdbProxy,
        DebugEngineOperation::OpenGdbstub,
        DebugEngineOperation::Goto,
        DebugEngineOperation::RestoreNearestCheckpointReplay,
        DebugEngineOperation::ReadOnlyInspection,
        DebugEngineOperation::NoSymbolServer,
        DebugEngineOperation::MultiVcpuThreadEnumeration,
        DebugEngineOperation::DisableRawGdbSingleStep,
    ];

    match &verb {
        DebugInteractiveVerbPlan::AttachGdb => {
            engine_operations.push(DebugEngineOperation::AttachGdbProxy);
        }
        DebugInteractiveVerbPlan::ForkDebug => {
            session_commands.push(SessionCommand::fork_current());
            engine_operations.push(DebugEngineOperation::NonCanonicalBranchFork);
        }
        DebugInteractiveVerbPlan::Goto(_) => {
            engine_operations.push(DebugEngineOperation::Goto);
        }
        DebugInteractiveVerbPlan::ReverseStep { .. } => {
            session_commands.push(SessionCommand::query_snapshot());
            engine_operations.push(DebugEngineOperation::ReverseStep);
            engine_operations.push(DebugEngineOperation::RestoreNearestCheckpointReplay);
        }
        DebugInteractiveVerbPlan::ReverseContinue { .. } => {
            session_commands.push(SessionCommand::query_snapshot());
            engine_operations.push(DebugEngineOperation::ReverseContinue);
        }
    }

    if checkpoint_stride.is_some() {
        engine_operations.push(DebugEngineOperation::CheckpointCadence);
    }

    let plan = DebugInvocationPlan {
        target,
        coordinate,
        node: args.node.clone(),
        gdb_listen,
        read_only,
        allow_mutate: args.allow_mutate,
        checkpoint_stride,
        verb,
        session_commands,
        engine_operations,
        surface_contract: crucible::DebugCliSurfaceContract::rfc0010(),
        owns_debug_state: false,
        raw_gdb_single_step_allowed: false,
        non_canonical_branch_label: explicit_fork.then(|| "NON-CANONICAL debug branch".to_string()),
    };
    if !plan.proves_t_dbg_8() {
        return Err(CliError::Backend(
            "debug planner does not satisfy the RFC-0010 debug surface contract".to_string(),
        ));
    }
    Ok(plan)
}

pub(super) fn debug_target(args: &DebugArgs) -> Result<DebugPlanTarget, CliError> {
    match (&args.target, &args.session) {
        (Some(_), Some(_)) => Err(usage_error(
            "debug accepts either ARTIFACT|SAVEPOINT or --session, not both",
        )),
        (None, None) => Err(usage_error(
            "debug requires ARTIFACT|SAVEPOINT or --session",
        )),
        (None, Some(session)) => Ok(DebugPlanTarget::Session(session.clone())),
        (Some(target), None) => {
            if let Ok(reference) = crucible::ContentAddressedBlobRef::parse("debug target", target)
            {
                Ok(DebugPlanTarget::Savepoint(reference.hash()))
            } else {
                Ok(DebugPlanTarget::Artifact(PathBuf::from(target)))
            }
        }
    }
}

pub(super) fn debug_coordinate(
    args: &DebugArgs,
    target: &DebugPlanTarget,
) -> Result<DebugPlanCoordinate, CliError> {
    if let Some(at) = &args.at {
        return parse_debug_at_coordinate(at).map(DebugPlanCoordinate::At);
    }
    if let Some(sequence) = args.at_event {
        return Ok(DebugPlanCoordinate::AtEvent(sequence));
    }
    if args.at_failure {
        return Ok(DebugPlanCoordinate::AtFailure);
    }
    if let Some(checkpoint) = &args.at_checkpoint {
        return crucible::ContentAddressedBlobRef::parse("at-checkpoint", checkpoint)
            .map(|reference| DebugPlanCoordinate::AtCheckpoint(reference.hash()))
            .map_err(|error| usage_error(format!("invalid --at-checkpoint: {error}")));
    }
    Ok(match target {
        DebugPlanTarget::Artifact(_) => DebugPlanCoordinate::AtFailure,
        DebugPlanTarget::Savepoint(hash) => DebugPlanCoordinate::AtCheckpoint(*hash),
        DebugPlanTarget::Session(_) => DebugPlanCoordinate::Current,
    })
}

pub(super) fn parse_debug_at_coordinate(
    value: &str,
) -> Result<crucible::DebugCoordinate, CliError> {
    if let Some(ticks) = value.strip_prefix("vtime:") {
        return parse_virtual_time(ticks);
    }
    if let Some(node_icount) = value.strip_prefix("icount:") {
        return parse_node_icount(node_icount);
    }
    if value.contains(':') {
        return parse_node_icount(value);
    }
    parse_virtual_time(value)
}

pub(super) fn parse_virtual_time(value: &str) -> Result<crucible::DebugCoordinate, CliError> {
    let ticks = parse_u64_value("--at", value)?;
    Ok(crucible::DebugCoordinate::virtual_time(
        crucible::VirtualTime { ticks },
    ))
}

pub(super) fn parse_node_icount(value: &str) -> Result<crucible::DebugCoordinate, CliError> {
    let Some((node, retired)) = value.split_once(':') else {
        return Err(usage_error(
            "--at node-icount coordinates must be `icount:<node>:<retired>`",
        ));
    };
    if node.is_empty() {
        return Err(usage_error("--at node-icount coordinate has an empty node"));
    }
    let retired = parse_u64_value("--at", retired)?;
    Ok(crucible::DebugCoordinate::node_icount(
        crucible::NodeId {
            name: node.to_string(),
        },
        crucible::Icount { retired },
    ))
}

pub(super) fn parse_u64_value(field: &'static str, value: &str) -> Result<u64, CliError> {
    value.parse::<u64>().map_err(|_| {
        usage_error(format!(
            "{field} must be an unsigned integer value, got `{value}`"
        ))
    })
}

pub(super) fn validate_debug_checkpoint_stride(stride: u64) -> Result<u64, CliError> {
    let Ok(every) = usize::try_from(stride) else {
        return Err(usage_error(
            "--checkpoint-stride is too large for this platform",
        ));
    };
    if crucible::DebugCheckpointStride::new(every).is_none() {
        return Err(usage_error("--checkpoint-stride must be non-zero"));
    }
    Ok(stride)
}

pub(super) fn debug_verb(args: &DebugArgs) -> Result<DebugInteractiveVerbPlan, CliError> {
    match &args.verb {
        None | Some(DebugVerbArgs::AttachGdb) => Ok(DebugInteractiveVerbPlan::AttachGdb),
        Some(DebugVerbArgs::ForkDebug) => Ok(DebugInteractiveVerbPlan::ForkDebug),
        Some(DebugVerbArgs::Goto { coord }) => {
            parse_debug_at_coordinate(coord).map(DebugInteractiveVerbPlan::Goto)
        }
        Some(DebugVerbArgs::ReverseStep { grain }) => Ok(DebugInteractiveVerbPlan::ReverseStep {
            grain: grain.reverse_grain(),
        }),
        Some(DebugVerbArgs::ReverseContinue { condition }) => {
            Ok(DebugInteractiveVerbPlan::ReverseContinue {
                condition: condition.clone(),
            })
        }
    }
}

#[path = "triage_debug/slug.rs"]
mod slug;

pub(crate) use slug::*;

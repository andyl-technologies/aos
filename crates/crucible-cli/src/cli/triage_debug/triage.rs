//! Finding triage planning, minimization, and evidence construction.

use super::ledger_format::write_triage_report;
use super::*;

const MAX_CAMPAIGN_TRIAGE_FINDINGS: usize = 65_536;

pub(crate) fn run_campaign_triage_invocation<S>(
    cli: &Cli,
    args: &CampaignTriageArgs,
    client: &crucible_campaign::CampaignClient<S>,
    principal: crucible_campaign::CampaignPrincipal,
) -> Result<TriageRunReport, CliError>
where
    S: crucible_campaign::CampaignFindingOccurrenceService,
    S::Error: crucible_campaign::CampaignServiceFailureSource,
{
    let campaign = crucible_campaign::CampaignName::new(&args.name)
        .map_err(|error| usage_error(format!("invalid campaign name: {error}")))?;
    let snapshot = crucible_campaign::CampaignSnapshotId::parse(&args.snapshot)
        .map_err(|error| usage_error(format!("invalid campaign snapshot: {error}")))?;
    let mut finding_ids = Vec::new();
    let mut after = None;
    loop {
        let request = crucible_campaign::QueryCampaignFindingsRequest::new(
            principal.clone(),
            campaign.clone(),
            snapshot,
            after,
            crucible_campaign::MAX_CAMPAIGN_FINDING_QUERY_PAGE_ITEMS,
        )
        .map_err(|error| artifact_error(format!("build campaign findings query: {error}")))?;
        let response = client
            .query_campaign_findings(&request)
            .map_err(|error| artifact_error(format!("query campaign findings: {error}")))?;
        for finding in response.entries() {
            finding_ids.push(finding.id().map_err(|error| {
                artifact_error(format!("campaign finding ID is invalid: {error}"))
            })?);
            if finding_ids.len() > MAX_CAMPAIGN_TRIAGE_FINDINGS {
                return Err(artifact_error("campaign triage finding bound exceeded"));
            }
        }
        after = response.next_after();
        if after.is_none() {
            break;
        }
    }

    let mut evidence = Vec::with_capacity(finding_ids.len());
    for finding in finding_ids {
        evidence.push(
            campaign_evidence::capture_campaign_triage_finding_from_service(
                client,
                principal.clone(),
                campaign.clone(),
                snapshot,
                finding,
            )?,
        );
    }
    let ledger_bytes = campaign_evidence::campaign_findings_ledger_bytes(&evidence)?;
    let ledger_text = std::str::from_utf8(&ledger_bytes)
        .map_err(|_| artifact_error("internal campaign triage evidence is not UTF-8"))?;
    let store_root = cli.artifact_dir.join("campaign-triage-store");
    let store = crucible::LocalDagStore::new(store_root.clone());
    let loaded_findings = parse_campaign_findings_ledger_bytes(&store, &ledger_bytes, ledger_text)?;
    let report_dir = args
        .report
        .clone()
        .unwrap_or_else(|| cli.artifact_dir.clone());
    let plan = TriageInvocationPlan {
        policy: args.policy.policy(),
        minimize: args.minimize,
        report_dir,
        format: cli.output_format().triage_report_format(),
        recompute_signatures: args.recompute_signatures,
        store_root,
    };

    execute_triage_plan(plan, loaded_findings)
}

pub(crate) fn emit_triage_report(cli: &Cli, report: &TriageRunReport) {
    if cli.quiet {
        return;
    }
    println!(
        "crucible: triage findings=campaign findings_count={} ledger={} ledger_cache_hit={} policy={} minimize={} clusters={} report={} format={} store={} result={} cache_hit={} compare=none",
        report.ledger.artifact_count(),
        format_content_hash_ref(report.stored_ledger.key),
        report.stored_ledger.cache_hit,
        report.plan.policy_label(),
        report.plan.minimize_label(),
        report.result.clustering.cluster_count(),
        report.report_path.display(),
        report.plan.format_label(),
        report.plan.store_root.display(),
        format_content_hash_ref(report.stored_result.key),
        report.stored_result.cache_hit,
    );
}

fn execute_triage_plan(
    plan: TriageInvocationPlan,
    loaded_findings: LoadedTriageFindings,
) -> Result<TriageRunReport, CliError> {
    let store = crucible::LocalDagStore::new(plan.store_root.clone());
    let stored_ledger = store_loaded_findings_ledger(&store, &loaded_findings)?;
    let ledger = loaded_findings.ledger.clone();

    let clustering = crucible::FailureClusteringResult::from_findings(
        plan.policy,
        ledger.signed_findings().iter().cloned(),
    )
    .map_err(|_| {
        CliError::Triage("triage clustering failed for the findings ledger".to_string())
    })?;
    let minimization = build_triage_minimization(&plan, &clustering, &loaded_findings)?;
    let report_set =
        build_triage_report_set(plan.policy, &clustering, &minimization, &loaded_findings)?;
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
    let stored_result = result.store(&store).map_err(CliError::Store)?;

    Ok(TriageRunReport {
        plan,
        ledger,
        stored_ledger,
        result,
        stored_result,
        report_path,
    })
}

pub(super) fn store_loaded_findings_ledger(
    store: &crucible::LocalDagStore,
    findings: &LoadedTriageFindings,
) -> Result<crucible::FailureTriageStoredArtifact, CliError> {
    let bytes = findings.artifact_bytes.clone();
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

pub(crate) fn build_triage_minimization(
    plan: &TriageInvocationPlan,
    clustering: &crucible::FailureClusteringResult,
    findings: &LoadedTriageFindings,
) -> Result<crucible::FailureSignaturePreservingMinimizationResult, CliError> {
    let evidence = &findings.evidence;
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
                runs.push(triage_no_op_minimization_run(
                    plan.policy,
                    cluster,
                    evidence,
                    crucible_model::FailureMinimizationDisposition::NotRequested,
                )?);
            }
            Ok(crucible::FailureSignaturePreservingMinimizationResult {
                policy: plan.policy,
                runs,
            })
        }
        TriageMinimizeArg::Representative | TriageMinimizeArg::All => {
            if !findings.campaign_evidence.is_empty() {
                return build_campaign_triage_minimization(plan, clustering, findings);
            }
            let templates = triage_signature_templates_by_fingerprint(clustering, evidence)?;
            let mut runs = Vec::new();
            for cluster in &clustering.clusters {
                let selected_members =
                    selected_triage_members(plan.minimize, cluster.members.as_slice())?;
                for member in selected_members {
                    if member.signature.failure_kind == crucible::FailureKind::Timeout {
                        runs.push(triage_no_op_minimization_member_run(
                            plan.policy,
                            cluster,
                            member.reproduction_artifact,
                            &member.signature,
                            evidence,
                            crucible_model::FailureMinimizationDisposition::NotApplicableTimeout,
                        )?);
                        continue;
                    }
                    let single_cluster = crucible::FailureClusteringResult {
                        policy: clustering.policy,
                        clusters: vec![crucible::FailureCluster {
                            id: cluster.id,
                            signature_key: cluster.signature_key.clone(),
                            members: vec![member.clone()],
                        }],
                    };
                    let mut minimized = single_cluster
                        .minimize_representatives(
                            crucible_model::MinimizationConfig::new(crucible::Seed::default()),
                            |artifact| {
                                evidence
                                    .get(&artifact)
                                    .map(|item| item.finding.clone())
                                    .ok_or(
                                    crucible_model::EngineError::UnifiedOperationEvidenceMismatch {
                                        operation: "triage-minimization",
                                        reason: "selected evidence missing from findings ledger",
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
                            CliError::Triage(
                                "triage signature-preserving minimization failed".to_string(),
                            )
                        })?;
                    runs.append(&mut minimized.runs);
                }
            }
            Ok(crucible::FailureSignaturePreservingMinimizationResult {
                policy: plan.policy,
                runs,
            })
        }
    }
}

pub(super) fn triage_no_op_minimization_run(
    policy: crucible::SignaturePolicy,
    cluster: &crucible::FailureCluster,
    evidence: &BTreeMap<crucible::ContentHash, TriageFindingEvidence>,
    disposition: crucible_model::FailureMinimizationDisposition,
) -> Result<crucible_model::FailureSignaturePreservingMinimizationRun, CliError> {
    let representative = cluster
        .representative_member()
        .ok_or_else(|| CliError::Triage("triage cluster has no representative".to_string()))?;
    triage_no_op_minimization_member_run(
        policy,
        cluster,
        representative.reproduction_artifact,
        &representative.signature,
        evidence,
        disposition,
    )
}

fn triage_no_op_minimization_member_run(
    policy: crucible::SignaturePolicy,
    cluster: &crucible::FailureCluster,
    reproduction_artifact: crucible::ContentHash,
    signature: &crucible::FailureSignature,
    evidence: &BTreeMap<crucible::ContentHash, TriageFindingEvidence>,
    disposition: crucible_model::FailureMinimizationDisposition,
) -> Result<crucible_model::FailureSignaturePreservingMinimizationRun, CliError> {
    let member_evidence = evidence
        .get(&reproduction_artifact)
        .ok_or_else(|| artifact_error("missing representative evidence in findings ledger"))?;
    let target_signature_key = signature.signature_key(policy).map_err(|_| {
        CliError::Triage(
            "triage representative signature does not project under policy".to_string(),
        )
    })?;
    Ok(crucible_model::FailureSignaturePreservingMinimizationRun {
        cluster_id: cluster.id,
        representative_artifact: reproduction_artifact,
        target_signature_key: target_signature_key.clone(),
        minimized_signature_key: target_signature_key,
        disposition,
        minimization: crucible_model::MinimizationRun {
            seed: crucible::Seed::default(),
            interesting_window: None,
            target_fingerprint: member_evidence.finding.finding_fingerprint,
            original: member_evidence.finding.clone(),
            minimized: member_evidence.finding.clone(),
            attempts: Vec::new(),
        },
    })
}

pub(super) fn triage_signature_templates_by_fingerprint(
    clustering: &crucible::FailureClusteringResult,
    evidence: &BTreeMap<crucible::ContentHash, TriageFindingEvidence>,
) -> Result<BTreeMap<crucible::ContentHash, TriageFindingEvidence>, CliError> {
    let mut templates = BTreeMap::new();
    for cluster in &clustering.clusters {
        if cluster.members.is_empty() {
            return Err(CliError::Triage(
                "triage cluster has no representative".to_string(),
            ));
        }
        for member in &cluster.members {
            let item = evidence
                .get(&member.reproduction_artifact)
                .ok_or_else(|| artifact_error("missing member evidence in findings ledger"))?;
            match templates.entry(item.finding.finding_fingerprint) {
                Entry::Vacant(entry) => {
                    entry.insert(item.clone());
                }
                Entry::Occupied(entry)
                    if entry.get().discovery_signature.report_material()
                        == item.discovery_signature.report_material() => {}
                Entry::Occupied(_) => {
                    return Err(CliError::Triage(
                        "triage findings reuse a fingerprint with conflicting signatures"
                            .to_string(),
                    ));
                }
            }
        }
    }
    Ok(templates)
}

pub(crate) fn build_triage_report_set(
    policy: crucible::SignaturePolicy,
    clustering: &crucible::FailureClusteringResult,
    minimization: &crucible::FailureSignaturePreservingMinimizationResult,
    findings: &LoadedTriageFindings,
) -> Result<crucible::FailureClusterReportSet, CliError> {
    let mut reports = Vec::new();
    for cluster in &clustering.clusters {
        let representative = cluster
            .representative_member()
            .ok_or_else(|| CliError::Triage("triage cluster has no representative".to_string()))?;
        let run = minimization
            .runs
            .iter()
            .find(|run| {
                run.cluster_id == cluster.id
                    && run.representative_artifact == representative.reproduction_artifact
            })
            .ok_or_else(|| CliError::Triage("missing triage minimization run".to_string()))?;
        let item = if findings.campaign_evidence.is_empty()
            || run.minimized_artifact() == run.representative_artifact
        {
            triage_report_evidence_for_minimization_run(run, &findings.evidence)?
        } else {
            campaign_evidence::campaign_triage_report_evidence_for_run(
                run,
                &findings.campaign_evidence,
            )?
        };
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
        crucible_model::FailureClusterReportFailure::Timeout(timeout) => {
            crucible_model::FailureSignature::from_recorded_timeout(
                &item.finding,
                &item.recorded_event_log,
                timeout,
            )
        }
    }
    .map_err(|_| CliError::Triage("triage signature recomputation failed".to_string()))
}

pub(crate) fn triage_evidence_for_finding(
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
        crucible_model::FailureClusterReportFailure::Timeout(_) => Err(
            crucible_model::EngineError::UnifiedOperationEvidenceMismatch {
                operation: "triage-evidence",
                reason: "timeout candidates require live budget replay and are not minimized",
            },
        ),
    }
}

pub(crate) fn triage_property_evidence_for_violation(
    finding: crucible::FindingReproductionArtifact,
    violation: crucible_model::HostAssertionViolation,
) -> Result<TriageFindingEvidence, crucible_model::EngineError> {
    triage_property_evidence_for_violation_with_recording(
        finding,
        violation,
        crucible::ContentHash::default(),
        Vec::new(),
    )
}

pub(crate) fn triage_property_evidence_for_violation_with_recording(
    finding: crucible::FindingReproductionArtifact,
    violation: crucible_model::HostAssertionViolation,
    coverage_fingerprint: crucible::ContentHash,
    recorded_event_frames: Vec<Vec<u8>>,
) -> Result<TriageFindingEvidence, crucible_model::EngineError> {
    let at = exact_failure_event_time(
        "property triage evidence",
        violation.at_virtual_time,
        violation.node.clone(),
        violation.at_icount,
    )?;
    let entries = if recorded_event_frames.is_empty() {
        vec![
            crucible::SchedulerEventLogEntry::assertion_state_observation_with_time(
                0,
                at,
                violation.assertion.clone(),
                crucible::AssertionPhase::Violated,
            ),
        ]
    } else {
        triage_causal_entries_from_frames(&recorded_event_frames)?
    };
    let recorded_event_log =
        crucible_model::FailureRecordedEventLog::from_causal_entries_coverage_and_frames(
            &finding,
            &entries,
            coverage_fingerprint,
            &recorded_event_frames,
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
        causal_entries: entries,
        recorded_event_log,
        failure,
        discovery_signature,
        recorded_event_frames,
    })
}

pub(crate) fn triage_timeout_evidence(
    finding: crucible::FindingReproductionArtifact,
    timeout: crucible_model::FailureTimeoutRecord,
    coverage_fingerprint: crucible::ContentHash,
    recorded_event_frames: Vec<Vec<u8>>,
) -> Result<TriageFindingEvidence, crucible_model::EngineError> {
    let budget_kind = match timeout.budget_kind {
        crucible_model::FailureTimeoutBudgetKind::ExecutionQuanta => "execution-quanta",
        crucible_model::FailureTimeoutBudgetKind::VirtualTime => "virtual-time",
    };
    let at = exact_failure_event_time(
        "timeout triage evidence",
        timeout.at_virtual_time,
        timeout.node.clone(),
        timeout.at_icount,
    )?;
    let mut entries = triage_causal_entries_from_frames(&recorded_event_frames)?;
    entries.push(
        crucible::SchedulerEventLogEntry::execution_budget_exhausted_with_time(
            entries.len() as u64,
            at,
            budget_kind,
        ),
    );
    let recorded_event_log =
        crucible_model::FailureRecordedEventLog::from_causal_entries_coverage_and_frames(
            &finding,
            &entries,
            coverage_fingerprint,
            &recorded_event_frames,
        )?;
    let discovery_signature = crucible_model::FailureSignature::from_recorded_timeout(
        &finding,
        &recorded_event_log,
        &timeout,
    )?;
    Ok(TriageFindingEvidence {
        finding,
        causal_entries: entries,
        recorded_event_log,
        failure: crucible_model::FailureClusterReportFailure::timeout(timeout),
        discovery_signature,
        recorded_event_frames,
    })
}

fn exact_failure_event_time(
    operation: &'static str,
    virtual_time: crucible::VirtualTime,
    node: Option<crucible::NodeId>,
    icount: Option<crucible::Icount>,
) -> Result<crucible::EventLogTime, crucible_model::EngineError> {
    let icount = icount.ok_or(
        crucible_model::EngineError::UnifiedOperationEvidenceMismatch {
            operation,
            reason: "exact failure evidence omitted its retired instruction count",
        },
    )?;

    Ok(crucible::EventLogTime {
        virtual_time,
        icount: crucible::EventLogIcountStamp { node, icount },
    })
}

fn triage_causal_entries_from_frames(
    frames: &[Vec<u8>],
) -> Result<Vec<crucible::SchedulerEventLogEntry>, crucible_model::EngineError> {
    let mut entries = Vec::new();
    for (index, frame) in frames.iter().enumerate() {
        let text = std::str::from_utf8(frame).map_err(|_| triage_frame_evidence_error())?;
        if text.lines().next() != Some("crucible.rpc/event-frame") {
            return Err(triage_frame_evidence_error());
        }
        let mut fields = BTreeMap::<&str, Vec<&str>>::new();
        for line in text.lines().skip(1) {
            if line.is_empty() {
                continue;
            }
            let (name, value) = line
                .split_once('=')
                .ok_or_else(triage_frame_evidence_error)?;
            if !matches!(
                name,
                "generation"
                    | "cursor"
                    | "next-cursor"
                    | "sequence"
                    | "virtual-time-ticks"
                    | "icount-retired"
                    | "icount-node"
                    | "source"
                    | "level"
                    | "observational"
                    | "kind"
                    | "attribute"
            ) {
                return Err(triage_frame_evidence_error());
            }
            fields.entry(name).or_default().push(value);
        }
        let observational = triage_frame_singleton(&fields, "observational")?;
        if observational == "true" {
            continue;
        }
        if observational != "false" {
            return Err(triage_frame_evidence_error());
        }
        let _generation = triage_frame_u64(&fields, "generation")?;
        let sequence = triage_frame_u64(&fields, "sequence")?;
        let cursor = triage_frame_u64(&fields, "cursor")?;
        let next_cursor = triage_frame_u64(&fields, "next-cursor")?;
        if cursor != sequence || next_cursor != sequence.saturating_add(1) {
            return Err(triage_frame_evidence_error());
        }
        let at = crucible::EventLogTime {
            virtual_time: crucible::VirtualTime {
                ticks: triage_frame_u64(&fields, "virtual-time-ticks")?,
            },
            icount: crucible::EventLogIcountStamp {
                node: triage_frame_optional_node(&fields, "icount-node")?,
                icount: crucible::Icount {
                    retired: triage_frame_u64(&fields, "icount-retired")?,
                },
            },
        };
        let source = triage_frame_source(triage_frame_singleton(&fields, "source")?)?;
        let level = triage_frame_level(triage_frame_singleton(&fields, "level")?)?;
        let wire_kind = triage_frame_singleton(&fields, "kind")?;
        let kind = wire_kind
            .strip_prefix("crucible.event.")
            .unwrap_or(wire_kind);
        let mut attributes = BTreeMap::new();
        for value in fields.get("attribute").into_iter().flatten() {
            let (name, value) = triage_frame_attribute(index, value)?;
            if attributes.insert(name, value).is_some() {
                return Err(triage_frame_evidence_error());
            }
        }
        entries.push(
            crucible::SchedulerEventLogEntry::from_retained_open_event(
                sequence,
                at,
                source,
                level,
                crucible::SchedulerEventLogClass::Causal,
                crucible::EventPayload::new(kind, attributes),
            )
            .map_err(|_| triage_frame_evidence_error())?,
        );
    }
    Ok(entries)
}

fn triage_frame_singleton<'a>(
    fields: &'a BTreeMap<&str, Vec<&str>>,
    name: &str,
) -> Result<&'a str, crucible_model::EngineError> {
    match fields.get(name).map(Vec::as_slice) {
        Some([value]) => Ok(value),
        _ => Err(triage_frame_evidence_error()),
    }
}

fn triage_frame_u64(
    fields: &BTreeMap<&str, Vec<&str>>,
    name: &str,
) -> Result<u64, crucible_model::EngineError> {
    triage_frame_singleton(fields, name)?
        .parse()
        .map_err(|_| triage_frame_evidence_error())
}

fn triage_frame_optional_node(
    fields: &BTreeMap<&str, Vec<&str>>,
    name: &str,
) -> Result<Option<crucible::NodeId>, crucible_model::EngineError> {
    match triage_frame_singleton(fields, name)? {
        "none" => Ok(None),
        value => {
            triage_frame_hex_string(0, name, value).map(|name| Some(crucible::NodeId { name }))
        }
    }
}

fn triage_frame_source(value: &str) -> Result<crucible::EventSource, crucible_model::EngineError> {
    if value == "engine" {
        return Ok(crucible::EventSource::Engine);
    }
    let (kind, value) = value
        .split_once('|')
        .ok_or_else(triage_frame_evidence_error)?;
    match kind {
        "scenario" => triage_frame_hex_string(0, "source", value).map(|name| {
            crucible::EventSource::Scenario {
                event: crucible::EventId::from_name(name),
            }
        }),
        "node" => {
            triage_frame_hex_string(0, "source", value).map(|name| crucible::EventSource::Node {
                node: crucible::NodeId { name },
            })
        }
        "guest" => {
            triage_frame_hex_string(0, "source", value).map(|name| crucible::EventSource::Guest {
                node: crucible::NodeId { name },
            })
        }
        "command" => value
            .parse::<u64>()
            .map(|command_id| crucible::EventSource::Command { command_id })
            .map_err(|_| triage_frame_evidence_error()),
        _ => Err(triage_frame_evidence_error()),
    }
}

fn triage_frame_level(value: &str) -> Result<crucible::EventLevel, crucible_model::EngineError> {
    match value {
        "trace" => Ok(crucible::EventLevel::Trace),
        "debug" => Ok(crucible::EventLevel::Debug),
        "info" => Ok(crucible::EventLevel::Info),
        "warn" => Ok(crucible::EventLevel::Warn),
        "error" => Ok(crucible::EventLevel::Error),
        _ => Err(triage_frame_evidence_error()),
    }
}

fn triage_frame_attribute(
    index: usize,
    value: &str,
) -> Result<(String, crucible::EventAttributeValue), crucible_model::EngineError> {
    let mut parts = value.split('|');
    let name = parts.next().ok_or_else(triage_frame_evidence_error)?;
    let kind = parts.next().ok_or_else(triage_frame_evidence_error)?;
    let value = parts.next().ok_or_else(triage_frame_evidence_error)?;
    if parts.next().is_some() {
        return Err(triage_frame_evidence_error());
    }
    let name = triage_frame_hex_string(index, "attribute-name", name)?;
    let value = match kind {
        "bool" => match value {
            "true" => crucible::EventAttributeValue::Bool(true),
            "false" => crucible::EventAttributeValue::Bool(false),
            _ => return Err(triage_frame_evidence_error()),
        },
        "uint" => crucible::EventAttributeValue::U64(
            value.parse().map_err(|_| triage_frame_evidence_error())?,
        ),
        "uint128" => crucible::EventAttributeValue::U128(
            value.parse().map_err(|_| triage_frame_evidence_error())?,
        ),
        "string" => crucible::EventAttributeValue::String(triage_frame_hex_string(
            index,
            "attribute",
            value,
        )?),
        "bytes" => crucible::EventAttributeValue::Bytes(
            parse_hex_bytes(index, "attribute", value)
                .map_err(|_| triage_frame_evidence_error())?,
        ),
        "int" | "float64bits" => return Err(triage_frame_evidence_error()),
        _ => return Err(triage_frame_evidence_error()),
    };
    Ok((name, value))
}

fn triage_frame_hex_string(
    index: usize,
    field: &str,
    value: &str,
) -> Result<String, crucible_model::EngineError> {
    let bytes = parse_hex_bytes(index, field, value).map_err(|_| triage_frame_evidence_error())?;
    String::from_utf8(bytes).map_err(|_| triage_frame_evidence_error())
}

fn triage_frame_evidence_error() -> crucible_model::EngineError {
    crucible_model::EngineError::UnifiedOperationEvidenceMismatch {
        operation: "failure-findings-ledger.v4.reproduction.frames",
        reason: "retained canonical event frames are malformed or inconsistent",
    }
}

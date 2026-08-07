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
            "triage findings input contains {} artifact(s), but discovery-time signature evidence is not available; pass the signed findings ledger emitted by `search` or `fuzz` (use `--findings-out` to select its path)",
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
            let templates = triage_signature_templates_by_fingerprint(clustering, evidence)?;
            let mut runs = Vec::new();
            for cluster in &clustering.clusters {
                let representative = cluster.representative_member().ok_or_else(|| {
                    CliError::Triage("triage cluster has no representative".to_string())
                })?;
                if representative.signature.failure_kind == crucible::FailureKind::Timeout {
                    runs.push(triage_no_op_minimization_run(
                        plan.policy,
                        cluster,
                        evidence,
                        crucible_model::FailureMinimizationDisposition::NotApplicableTimeout,
                    )?);
                    continue;
                }
                let single_cluster = crucible::FailureClusteringResult {
                    policy: clustering.policy,
                    clusters: vec![cluster.clone()],
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
                        CliError::Triage(
                            "triage signature-preserving minimization failed".to_string(),
                        )
                    })?;
                runs.append(&mut minimized.runs);
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
    let representative_evidence = evidence
        .get(&representative.reproduction_artifact)
        .ok_or_else(|| artifact_error("missing representative evidence in findings ledger"))?;
    let target_signature_key = representative
        .signature
        .signature_key(policy)
        .map_err(|_| {
            CliError::Triage(
                "triage representative signature does not project under policy".to_string(),
            )
        })?;
    Ok(crucible_model::FailureSignaturePreservingMinimizationRun {
        cluster_id: cluster.id,
        representative_artifact: representative.reproduction_artifact,
        target_signature_key: target_signature_key.clone(),
        minimized_signature_key: target_signature_key,
        disposition,
        minimization: crucible_model::MinimizationRun {
            seed: crucible::Seed::default(),
            target_fingerprint: representative_evidence.finding.finding_fingerprint,
            original: representative_evidence.finding.clone(),
            minimized: representative_evidence.finding.clone(),
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
        crucible_model::FailureClusterReportFailure::Timeout(_) => Err(
            crucible_model::EngineError::UnifiedOperationEvidenceMismatch {
                operation: "triage-evidence",
                reason: "timeout candidates require live budget replay and are not minimized",
            },
        ),
    }
}

pub(super) fn triage_property_evidence_for_violation(
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

pub(super) fn triage_property_evidence_for_violation_with_recording(
    finding: crucible::FindingReproductionArtifact,
    violation: crucible_model::HostAssertionViolation,
    coverage_fingerprint: crucible::ContentHash,
    recorded_event_frames: Vec<Vec<u8>>,
) -> Result<TriageFindingEvidence, crucible_model::EngineError> {
    let at = crucible::EventLogTime {
        virtual_time: violation.at_virtual_time,
        icount: crucible::EventLogIcountStamp {
            node: violation.node.clone(),
            icount: violation.at_icount.unwrap_or(crucible::Icount {
                retired: violation.at_virtual_time.ticks,
            }),
        },
    };
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
        recorded_event_log,
        failure,
        discovery_signature,
        recorded_event_frames,
    })
}

pub(super) fn triage_timeout_evidence(
    finding: crucible::FindingReproductionArtifact,
    timeout: crucible_model::FailureTimeoutRecord,
    coverage_fingerprint: crucible::ContentHash,
    recorded_event_frames: Vec<Vec<u8>>,
) -> Result<TriageFindingEvidence, crucible_model::EngineError> {
    let budget_kind = match timeout.budget_kind {
        crucible_model::FailureTimeoutBudgetKind::ExecutionQuanta => "execution-quanta",
        crucible_model::FailureTimeoutBudgetKind::VirtualTime => "virtual-time",
    };
    let at = crucible::EventLogTime {
        virtual_time: timeout.at_virtual_time,
        icount: crucible::EventLogIcountStamp {
            node: timeout.node.clone(),
            icount: timeout.at_icount.unwrap_or(crucible::Icount {
                retired: timeout.at_virtual_time.ticks,
            }),
        },
    };
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
        recorded_event_log,
        failure: crucible_model::FailureClusterReportFailure::timeout(timeout),
        discovery_signature,
        recorded_event_frames,
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
        operation: "failure-findings-ledger.v3.frames",
        reason: "retained canonical event frames are malformed or inconsistent",
    }
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
        .is_some_and(|schema| {
            schema == FAILURE_TRIAGE_FINDINGS_LEDGER_SCHEMA_V1
                || schema == FAILURE_TRIAGE_FINDINGS_LEDGER_SCHEMA_V2
                || schema == FAILURE_TRIAGE_FINDINGS_LEDGER_SCHEMA_V3
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
        Some(FAILURE_TRIAGE_FINDINGS_LEDGER_SCHEMA_V3) => {
            parse_failure_findings_ledger_v3_bytes(store, bytes, text)
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

pub(super) fn parse_failure_findings_ledger_v3_bytes(
    store: &crucible::LocalDagStore,
    bytes: &[u8],
    text: &str,
) -> Result<LoadedTriageFindings, CliError> {
    let mut by_index = BTreeMap::<usize, BTreeMap<String, String>>::new();
    let mut finding_count = None;
    for line in text.lines().skip(1) {
        if line.trim().is_empty() {
            continue;
        }
        if let Some(value) = line.strip_prefix("finding_count=") {
            if finding_count
                .replace(
                    value
                        .parse::<usize>()
                        .map_err(|_| artifact_error("malformed v3 findings count"))?,
                )
                .is_some()
            {
                return Err(artifact_error("duplicate v3 findings count"));
            }
            continue;
        }
        let Some(rest) = line.strip_prefix("finding.") else {
            return Err(artifact_error("malformed v3 signed findings ledger line"));
        };
        let Some((index, field_value)) = rest.split_once('.') else {
            return Err(artifact_error("malformed v3 signed findings ledger field"));
        };
        let index = index
            .parse::<usize>()
            .map_err(|_| artifact_error("malformed v3 signed findings ledger index"))?;
        let Some((field, value)) = field_value.split_once('=') else {
            return Err(artifact_error("malformed v3 signed findings ledger value"));
        };
        if by_index
            .entry(index)
            .or_default()
            .insert(field.to_owned(), value.to_owned())
            .is_some()
        {
            return Err(artifact_error("duplicate v3 signed findings ledger field"));
        }
    }
    let finding_count = finding_count
        .ok_or_else(|| artifact_error("v3 signed findings ledger is missing finding count"))?;
    if by_index.len() != finding_count || by_index.keys().copied().ne(0..finding_count) {
        return Err(artifact_error(
            "v3 signed findings ledger count or indices are not canonical",
        ));
    }

    let mut findings = Vec::new();
    let mut evidence = BTreeMap::new();
    for (index, fields) in by_index {
        let item = parse_triage_v3_finding_evidence(store, index, &fields)?;
        findings.push(crucible::FailureClusterFinding::new(
            item.finding.artifact.id(),
            item.discovery_signature.clone(),
        ));
        if evidence.insert(item.finding.artifact.id(), item).is_some() {
            return Err(artifact_error(
                "v3 signed findings ledger repeats a reproduction artifact",
            ));
        }
    }
    let ledger = crucible::FailureFindingsLedger::from_signed_findings(findings)
        .map_err(|_| artifact_error("v3 signed findings ledger contains conflicting signatures"))?;
    Ok(LoadedTriageFindings {
        ledger,
        evidence,
        artifact_bytes: bytes.to_vec(),
    })
}

pub(super) fn parse_triage_v3_finding_evidence(
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
    let frames = parse_v3_event_frames(fields)?;
    let evidence_kind = required_field(fields, "evidence")?;
    validate_v3_finding_field_set(fields, evidence_kind, frames.len())?;
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
        _ => return Err(artifact_error("unsupported v3 findings evidence kind")),
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

pub(super) fn validate_v3_finding_field_set(
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
        _ => return Err(artifact_error("unsupported v3 findings evidence kind")),
    };
    expected.extend(evidence_fields.iter().copied().map(String::from));
    expected.extend((0..frame_count).map(|index| format!("event_frame.{index}")));
    if fields.keys().any(|field| !expected.contains(field)) {
        return Err(artifact_error(
            "v3 signed findings ledger contains a non-canonical field",
        ));
    }
    Ok(())
}

pub(super) fn failure_findings_ledger_v3_bytes(
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
        String::from(FAILURE_TRIAGE_FINDINGS_LEDGER_SCHEMA_V3),
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
                    "v3 findings ledger writer does not support divergence evidence",
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

pub(super) fn write_failure_findings_ledger_v3(
    artifact_dir: &Path,
    findings_out: Option<&Path>,
    evidence: &[TriageFindingEvidence],
) -> Result<(PathBuf, crucible::ContentHash, Vec<u8>), CliError> {
    let bytes = failure_findings_ledger_v3_bytes(evidence)?;
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
        crucible::FindingDiscoveryPath::InteractiveFork => "interactive-fork",
        crucible::FindingDiscoveryPath::StateSpaceSearch => "state-space-search",
        crucible::FindingDiscoveryPath::CoverageGuidedFuzzing => "coverage-guided-fuzzing",
        crucible::FindingDiscoveryPath::RetainedCorpusEntry => "retained-corpus-entry",
    }
}

pub(super) fn ledger_hex(bytes: &[u8]) -> String {
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

pub(super) fn parse_v3_event_frames(
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
    if let DebugPlanTarget::Session(session) = &target {
        parse_debug_session_ref(session)?;
    }
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
    let guest_shell = matches!(
        verb,
        DebugInteractiveVerbPlan::Exec { .. }
            | DebugInteractiveVerbPlan::Pty { .. }
            | DebugInteractiveVerbPlan::Ssh
    );
    if args.record_transcript.is_some() && !guest_shell {
        return Err(usage_error(
            "--record-transcript is available only with debug exec, pty, or ssh",
        ));
    }
    if args.guest_idle_timeout.is_some() && !guest_shell {
        return Err(usage_error(
            "--guest-idle-timeout is available only with debug exec, pty, or ssh",
        ));
    }
    let guest_idle_timeout = parse_run_duration_budget_ticks(
        args.guest_idle_timeout.as_deref().unwrap_or("30s"),
    )
    .map(Duration::from_nanos)
    .ok_or_else(|| {
        usage_error(
            "--guest-idle-timeout must be a positive duration using ticks, ns, us, ms, or s",
        )
    })?;
    if (explicit_fork || guest_shell) && !args.allow_mutate {
        return Err(usage_error(
            "the selected fork-debug or guest exec/PTY/SSH operation requires --allow-mutate authorization",
        ));
    }
    let read_only = !(explicit_fork || guest_shell);
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
        DebugInteractiveVerbPlan::Exec { .. }
        | DebugInteractiveVerbPlan::Pty { .. }
        | DebugInteractiveVerbPlan::Ssh => {
            engine_operations.push(DebugEngineOperation::GuestIntrospection);
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
        record_transcript: args.record_transcript.clone(),
        guest_idle_timeout,
        verb,
        session_commands,
        engine_operations,
        surface_contract: crucible::DebugCliSurfaceContract::rfc0010(),
        owns_debug_state: false,
        raw_gdb_single_step_allowed: false,
        non_canonical_branch_label: (explicit_fork || guest_shell)
            .then(|| "NON-CANONICAL debug branch".to_string()),
    };
    if !plan.proves_t_dbg_8() {
        return Err(CliError::Backend(
            "debug planner does not satisfy the RFC-0010 debug surface contract".to_string(),
        ));
    }
    Ok(plan)
}

pub(super) fn run_remote_debug_relay(
    cli: &Cli,
    plan: &DebugInvocationPlan,
) -> Result<(), CliError> {
    let daemon = cli
        .daemon
        .as_deref()
        .ok_or_else(|| backend_error("remote debugger relay requires --daemon"))?;
    let DebugPlanTarget::Session(session_text) = &plan.target else {
        return Err(usage_error(
            "remote debugger relay requires --session id:epoch:seed",
        ));
    };
    let backend_plan = plan_backend_selection(cli)?
        .ok_or_else(|| backend_error("remote debugger relay has no backend route"))?;
    if backend_plan.daemon_security.is_none() && !cli.trusted_unauthenticated_daemon {
        return Err(usage_error(
            "remote debugging requires daemon mutual TLS or explicit --trusted-unauthenticated-daemon",
        ));
    }
    let session = parse_debug_session_ref(session_text)?;
    let gdb_listen: std::net::SocketAddr = plan.gdb_listen.parse().map_err(|error| {
        usage_error(format!(
            "remote --gdb-listen must be a TCP socket address: {error}"
        ))
    })?;
    if !gdb_listen.ip().is_loopback() {
        return Err(usage_error(
            "remote --gdb-listen must use a loopback address",
        ));
    }
    let node = plan
        .node
        .as_deref()
        .ok_or_else(|| usage_error("remote debugger attachment requires --node NODE"))?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let node = crucible::NodeId {
        name: node.to_owned(),
    };
    match &plan.verb {
        DebugInteractiveVerbPlan::AttachGdb => runtime.block_on(run_remote_debug_relay_async(
            daemon,
            &backend_plan,
            session,
            node,
            gdb_listen,
        )),
        DebugInteractiveVerbPlan::Exec { argv } => runtime.block_on(run_remote_guest_channel(
            daemon,
            &backend_plan,
            session,
            node,
            crucible_api::GuestIntrospectionMessage::Exec {
                argv: argv.clone(),
                record_transcript: plan.record_transcript.is_some(),
            },
            false,
            plan.record_transcript.as_deref(),
            plan.guest_idle_timeout,
        )),
        DebugInteractiveVerbPlan::Pty {
            argv,
            columns,
            rows,
        } => runtime.block_on(run_remote_guest_channel(
            daemon,
            &backend_plan,
            session,
            node,
            crucible_api::GuestIntrospectionMessage::Pty {
                argv: argv.clone(),
                columns: *columns,
                rows: *rows,
                record_transcript: plan.record_transcript.is_some(),
            },
            true,
            plan.record_transcript.as_deref(),
            plan.guest_idle_timeout,
        )),
        DebugInteractiveVerbPlan::Ssh => runtime.block_on(run_remote_guest_channel(
            daemon,
            &backend_plan,
            session,
            node,
            crucible_api::GuestIntrospectionMessage::Ssh {
                record_transcript: plan.record_transcript.is_some(),
            },
            true,
            plan.record_transcript.as_deref(),
            plan.guest_idle_timeout,
        )),
        DebugInteractiveVerbPlan::ForkDebug => {
            runtime.block_on(run_remote_guest_fork(daemon, &backend_plan, session, node))
        }
        DebugInteractiveVerbPlan::Goto(_)
        | DebugInteractiveVerbPlan::ReverseStep { .. }
        | DebugInteractiveVerbPlan::ReverseContinue { .. } => runtime.block_on(
            run_remote_debug_reposition(daemon, &backend_plan, session, node, &plan.verb),
        ),
    }
}

async fn run_remote_debug_reposition(
    daemon: &str,
    backend_plan: &BackendSelectionPlan,
    session: SessionRef,
    node: crucible::NodeId,
    verb: &DebugInteractiveVerbPlan,
) -> Result<(), CliError> {
    let client = remote_rpc_client(daemon, backend_plan)?;
    let acquisition = crucible_api::DebugControllerAcquisition::new();
    let lease = client
        .acquire_debug_controller(session, &acquisition)
        .await
        .map_err(control_client_error)?;
    let reposition_result: Result<Option<crucible_api::DebugRepositionResult>, CliError> = async {
        client
            .attach_debugger(session, &lease, &node)
            .await
            .map_err(control_client_error)?;
        match verb {
            DebugInteractiveVerbPlan::Goto(target) => client
                .debug_goto(session, &lease, target)
                .await
                .map(Some)
                .map_err(control_client_error),
            DebugInteractiveVerbPlan::ReverseStep { grain } => client
                .debug_reverse_step(session, &lease, *grain)
                .await
                .map(Some)
                .map_err(control_client_error),
            DebugInteractiveVerbPlan::ReverseContinue { condition } => {
                let condition = parse_debug_reverse_condition(condition)?;
                client
                    .debug_reverse_continue(session, &lease, &condition)
                    .await
                    .map_err(control_client_error)
            }
            DebugInteractiveVerbPlan::AttachGdb
            | DebugInteractiveVerbPlan::ForkDebug
            | DebugInteractiveVerbPlan::Exec { .. }
            | DebugInteractiveVerbPlan::Pty { .. }
            | DebugInteractiveVerbPlan::Ssh => Err(backend_error(
                "non-reposition debug verb reached reposition dispatcher",
            )),
        }
    }
    .await;
    let release_result = client.release_debug_controller(session, &lease).await;
    let target = reposition_result?;
    release_result.map_err(control_client_error)?;
    match target {
        Some(target) => print_debug_landed_runtime(&target),
        None => println!("crucible: reverse-continue found no matching prior condition"),
    }
    Ok(())
}

fn print_debug_landed_runtime(result: &crucible_api::DebugRepositionResult) {
    let landed = &result.landed;
    println!("crucible: debugger repositioned");
    println!("requested-coordinate={}", landed.requested_coordinate);
    println!("landed-configuration={}", landed.configuration);
    println!("landed-runtime-state={}", landed.runtime_state);
    println!("landed-virtual-time={}", landed.virtual_time_ticks);
    println!("landed-schedule-prefix={}", landed.schedule_prefix_len);
    println!("landed-event-log-prefix={}", landed.event_log_prefix);
    println!("landed-event-log-bytes={}", landed.event_log_bytes);
    println!("landed-event-log-events={}", landed.event_log_events);
    for (node, retired) in &landed.node_icounts {
        println!("landed-node-icount.{node}={retired}");
    }
    println!("gateway-generation={}", landed.gateway_generation);
    println!("retired-world-cleanup={}", landed.retired_world_cleanup);
    if let Some(sequence) = result.target_event_sequence {
        println!("target-event-sequence={sequence}");
    }
}

pub(super) fn parse_debug_reverse_condition(value: &str) -> Result<crucible::Predicate, CliError> {
    if value == "quiescent" {
        return Ok(crucible::Predicate::quiescent());
    }
    if let Some(ticks) = value.strip_prefix("at:") {
        return Ok(crucible::Predicate::at(crucible::VirtualTime {
            ticks: parse_u64_value("reverse-continue at", ticks)?,
        }));
    }
    if let Some(encoded) = value.strip_prefix("hex:") {
        if !encoded.len().is_multiple_of(2) {
            return Err(usage_error(
                "reverse-continue hex condition has an odd number of digits",
            ));
        }
        let mut bytes = Vec::with_capacity(encoded.len() / 2);
        for pair in encoded.as_bytes().chunks_exact(2) {
            let high = hex_nibble(pair[0]).ok_or_else(|| {
                usage_error("reverse-continue hex condition contains a non-hex digit")
            })?;
            let low = hex_nibble(pair[1]).ok_or_else(|| {
                usage_error("reverse-continue hex condition contains a non-hex digit")
            })?;
            bytes.push((high << 4) | low);
        }
        return crucible::Predicate::from_compact_binary(&bytes)
            .map_err(|error| usage_error(format!("invalid reverse-continue condition: {error}")));
    }
    Err(usage_error(
        "reverse-continue condition must be `quiescent`, `at:<ticks>`, or `hex:<compact-predicate>`",
    ))
}

async fn run_remote_guest_fork(
    daemon: &str,
    backend_plan: &BackendSelectionPlan,
    session: SessionRef,
    node: crucible::NodeId,
) -> Result<(), CliError> {
    let client = remote_rpc_client(daemon, backend_plan)?;
    let acquisition = crucible_api::DebugControllerAcquisition::new();
    let lease = client
        .acquire_debug_controller(session, &acquisition)
        .await
        .map_err(control_client_error)?;
    let fork_result = async {
        client
            .attach_debugger(session, &lease, &node)
            .await
            .map_err(control_client_error)?;
        client
            .fork_debug_guest_introspection(session, &lease, &node)
            .await
            .map_err(control_client_error)
    }
    .await;
    let release_result = client.release_debug_controller(session, &lease).await;
    let features = fork_result?;
    release_result.map_err(control_client_error)?;
    println!(
        "crucible: forked non-canonical guest-introspection branch argv-exec={} pty={} resize={} ssh-bridge={} max-channels={}",
        features.argv_exec(),
        features.pty(),
        features.resize(),
        features.ssh_bridge(),
        features.max_channels(),
    );
    Ok(())
}

async fn run_remote_debug_relay_async(
    daemon: &str,
    backend_plan: &BackendSelectionPlan,
    session: SessionRef,
    node: crucible::NodeId,
    gdb_listen: std::net::SocketAddr,
) -> Result<(), CliError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let client = remote_rpc_client(daemon, backend_plan)?;
    let acquisition = crucible_api::DebugControllerAcquisition::new();
    let lease = client
        .acquire_debug_controller(session, &acquisition)
        .await
        .map_err(control_client_error)?;
    if let Err(error) = client.attach_debugger(session, &lease, &node).await {
        let _ = client.release_debug_controller(session, &lease).await;
        return Err(control_client_error(error));
    }
    let relay = match client.open_debug_relay(session, &lease).await {
        Ok(relay) => relay,
        Err(error) => {
            let _ = client.release_debug_controller(session, &lease).await;
            return Err(control_client_error(error));
        }
    };
    let listener = match tokio::net::TcpListener::bind(gdb_listen).await {
        Ok(listener) => listener,
        Err(error) => {
            let _ = client.close_debug_relay(session, &lease, relay).await;
            return Err(backend_error(format!(
                "cannot bind local GDB relay {gdb_listen}: {error}"
            )));
        }
    };
    let address = match listener.local_addr() {
        Ok(address) => address,
        Err(error) => {
            let _ = client.close_debug_relay(session, &lease, relay).await;
            return Err(backend_error(format!(
                "cannot read local GDB relay address: {error}"
            )));
        }
    };
    println!("crucible: remote GDB relay listening at {address}");
    let accepted = tokio::select! {
        biased;
        accepted = listener.accept() => Some(accepted),
        signal = tokio::signal::ctrl_c() => {
            match signal {
                Ok(()) => None,
                Err(error) => {
                    let _ = client.close_debug_relay(session, &lease, relay).await;
                    return Err(backend_error(format!("debug relay signal error: {error}")));
                }
            }
        }
    };
    let Some(accepted) = accepted else {
        let _ = client.close_debug_relay(session, &lease, relay).await;
        return Ok(());
    };
    let (mut local, _) = match accepted {
        Ok(accepted) => accepted,
        Err(error) => {
            let _ = client.close_debug_relay(session, &lease, relay).await;
            return Err(backend_error(format!(
                "cannot accept local GDB connection: {error}"
            )));
        }
    };
    let mut local_buffer = vec![0_u8; crucible_api::DEBUG_RELAY_CHUNK_MAX_BYTES];
    let mut poll = tokio::time::interval(Duration::from_millis(5));
    let relay_result: Result<(), CliError> = async {
        loop {
            tokio::select! {
            biased;
            read = local.read(&mut local_buffer) => {
                let length = read.map_err(|error| backend_error(format!("local GDB read failed: {error}")))?;
                if length == 0 {
                    break Ok(());
                }
                let written = client
                    .write_debug_relay(session, &lease, relay, &local_buffer[..length])
                    .await
                    .map_err(control_client_error)?;
                if written != length {
                    break Err(backend_error("remote GDB relay accepted a partial chunk"));
                }
            }
            _ = poll.tick() => {
                let chunk = client
                    .read_debug_relay(
                        session,
                        &lease,
                        relay,
                        crucible_api::DEBUG_RELAY_CHUNK_MAX_BYTES,
                    )
                    .await
                    .map_err(control_client_error)?;
                if !chunk.bytes.is_empty() {
                    local
                        .write_all(&chunk.bytes)
                        .await
                        .map_err(|error| backend_error(format!("local GDB write failed: {error}")))?;
                }
                if chunk.eof {
                    break Ok(());
                }
            }
            signal = tokio::signal::ctrl_c() => {
                signal.map_err(|error| backend_error(format!("debug relay signal error: {error}")))?;
                break Ok(());
            }
            }
        }
    }
    .await;
    let close_result = client.close_debug_relay(session, &lease, relay).await;
    relay_result?;
    close_result.map_err(control_client_error)?;
    Ok(())
}

pub(super) const GUEST_TRANSCRIPT_HEADER: &[u8; 8] = b"CRGT\x01\0\0\0";
const GUEST_TRANSCRIPT_MAX_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Copy)]
pub(super) enum GuestTranscriptDirection {
    HostToGuest = 1,
    GuestToHost = 2,
}

pub(super) struct GuestTranscriptWriter {
    file: tokio::fs::File,
    bytes_written: u64,
}

impl GuestTranscriptWriter {
    pub(super) async fn create(path: &Path) -> Result<Self, CliError> {
        use tokio::io::AsyncWriteExt as _;

        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .await
            .map_err(|error| {
                backend_error(format!(
                    "cannot create guest transcript {}: {error}",
                    path.display()
                ))
            })?;
        file.write_all(GUEST_TRANSCRIPT_HEADER)
            .await
            .map_err(|error| backend_error(format!("cannot write guest transcript: {error}")))?;
        Ok(Self {
            file,
            bytes_written: GUEST_TRANSCRIPT_HEADER.len() as u64,
        })
    }

    pub(super) async fn record(
        &mut self,
        direction: GuestTranscriptDirection,
        record: &crucible_api::GuestIntrospectionRecord,
    ) -> Result<(), CliError> {
        use tokio::io::AsyncWriteExt as _;

        let encoded = record
            .encode()
            .map_err(|error| backend_error(format!("cannot encode guest transcript: {error}")))?;
        let length = u32::try_from(encoded.len())
            .map_err(|_| backend_error("guest transcript record exceeds u32 length"))?;
        let frame_len = 8_u64.saturating_add(u64::from(length));
        if self.bytes_written.saturating_add(frame_len) > GUEST_TRANSCRIPT_MAX_BYTES {
            return Err(backend_error(format!(
                "guest transcript exceeds the {}-byte recording limit",
                GUEST_TRANSCRIPT_MAX_BYTES
            )));
        }
        let mut header = [0_u8; 8];
        header[0] = direction as u8;
        header[4..].copy_from_slice(&length.to_le_bytes());
        self.file
            .write_all(&header)
            .await
            .map_err(|error| backend_error(format!("cannot write guest transcript: {error}")))?;
        self.file
            .write_all(&encoded)
            .await
            .map_err(|error| backend_error(format!("cannot write guest transcript: {error}")))?;
        self.bytes_written += frame_len;
        Ok(())
    }

    pub(super) async fn finish(&mut self) -> Result<(), CliError> {
        use tokio::io::AsyncWriteExt as _;

        self.file
            .flush()
            .await
            .map_err(|error| backend_error(format!("cannot flush guest transcript: {error}")))
    }
}

async fn exchange_guest_record(
    client: &RpcControlClient,
    session: SessionRef,
    lease: &crucible_api::DebugControllerAccess,
    node: &crucible::NodeId,
    channel_id: u64,
    request: Option<&crucible_api::GuestIntrospectionRecord>,
    transcript: &mut Option<GuestTranscriptWriter>,
) -> Result<Option<crucible_api::GuestIntrospectionRecord>, CliError> {
    let response = client
        .exchange_guest_introspection(session, lease, node, channel_id, request)
        .await
        .map_err(control_client_error)?;
    if let (Some(writer), Some(record)) = (transcript.as_mut(), request) {
        writer
            .record(GuestTranscriptDirection::HostToGuest, record)
            .await?;
    }
    if let (Some(writer), Some(record)) = (transcript.as_mut(), response.as_ref()) {
        writer
            .record(GuestTranscriptDirection::GuestToHost, record)
            .await?;
    }
    Ok(response)
}

// crucible-lint: allow rust-allow -- the guest-channel boundary keeps transport policy, branch identity, terminal mode, transcript ownership, and timeout policy explicit.
#[allow(clippy::too_many_arguments)]
async fn run_remote_guest_channel(
    daemon: &str,
    backend_plan: &BackendSelectionPlan,
    session: SessionRef,
    node: crucible::NodeId,
    open: crucible_api::GuestIntrospectionMessage,
    interactive: bool,
    transcript_path: Option<&Path>,
    guest_idle_timeout: Duration,
) -> Result<(), CliError> {
    use crucible_api::{GuestIntrospectionMessage, GuestIntrospectionRecord, GuestOutputStream};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const CHANNEL_ID: u64 = 1;
    let pty_channel = matches!(&open, GuestIntrospectionMessage::Pty { .. });
    let _terminal_mode = LocalTerminalMode::enter_raw(interactive)?;
    let mut resize_signal = local_resize_signal(interactive)?;
    let mut transcript = match transcript_path {
        Some(path) => Some(GuestTranscriptWriter::create(path).await?),
        None => None,
    };
    let client = remote_rpc_client(daemon, backend_plan)?;
    let acquisition = crucible_api::DebugControllerAcquisition::new();
    let lease = client
        .acquire_debug_controller(session, &acquisition)
        .await
        .map_err(control_client_error)?;
    let open = GuestIntrospectionRecord::new(CHANNEL_ID, open)
        .map_err(|error| backend_error(error.to_string()))?;
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut stderr = tokio::io::stderr();
    let mut input_closed = !interactive;
    let mut terminal_observed = false;
    let channel_result: Result<(), CliError> = async {
        exchange_guest_record(
            &client,
            session,
            &lease,
            &node,
            CHANNEL_ID,
            Some(&open),
            &mut transcript,
        )
        .await?;
        if !interactive {
            let close = GuestIntrospectionRecord::new(
                CHANNEL_ID,
                GuestIntrospectionMessage::Close,
            )
            .map_err(|error| backend_error(error.to_string()))?;
            exchange_guest_record(
                &client,
                session,
                &lease,
                &node,
                CHANNEL_ID,
                Some(&close),
                &mut transcript,
            )
            .await?;
        }
        let mut input = vec![0_u8; 4096];
        let mut poll = tokio::time::interval(Duration::from_millis(5));
        let mut idle_deadline = tokio::time::interval(guest_idle_timeout);
        idle_deadline.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        idle_deadline.tick().await;
        loop {
            tokio::select! {
                biased;
                _ = idle_deadline.tick() => {
                    break Err(backend_error(format!(
                        "guest agent produced no response for {} ms; verify that the non-canonical fork activated `crucible-guest agent` or increase --guest-idle-timeout",
                        guest_idle_timeout.as_millis()
                    )));
                }
                read = stdin.read(&mut input), if !input_closed => {
                    let length = read.map_err(|error| backend_error(format!("terminal input failed: {error}")))?;
                    let message = guest_input_message(pty_channel, &input[..length]);
                    let record = GuestIntrospectionRecord::new(CHANNEL_ID, message)
                        .map_err(|error| backend_error(error.to_string()))?;
                    exchange_guest_record(
                        &client,
                        session,
                        &lease,
                        &node,
                        CHANNEL_ID,
                        Some(&record),
                        &mut transcript,
                    )
                    .await?;
                    if length == 0 {
                        input_closed = true;
                    }
                }
                _ = poll.tick() => {
                    let Some(record) = exchange_guest_record(
                        &client,
                        session,
                        &lease,
                        &node,
                        CHANNEL_ID,
                        None,
                        &mut transcript,
                    )
                    .await?
                    else {
                        continue;
                    };
                    idle_deadline.reset();
                    if record.channel_id() != CHANNEL_ID {
                        continue;
                    }
                    match record.message() {
                        GuestIntrospectionMessage::Output { stream, bytes } => {
                            match stream {
                                GuestOutputStream::Stdout => stdout.write_all(bytes).await,
                                GuestOutputStream::Stderr => stderr.write_all(bytes).await,
                            }
                            .map_err(|error| backend_error(format!("terminal output failed: {error}")))?;
                        }
                        GuestIntrospectionMessage::Exit { status, signal } => {
                            terminal_observed = true;
                            stdout.flush().await.map_err(|error| backend_error(error.to_string()))?;
                            stderr.flush().await.map_err(|error| backend_error(error.to_string()))?;
                            if *status == 0 {
                                break Ok(());
                            }
                            break Err(backend_error(format!(
                                "guest command exited with status {status} signal {signal:?}"
                            )));
                        }
                        GuestIntrospectionMessage::Error { code, message } => {
                            terminal_observed = true;
                            break Err(backend_error(format!(
                                "guest introspection failed ({code:?}): {message}"
                            )));
                        }
                        GuestIntrospectionMessage::Features(_)
                        | GuestIntrospectionMessage::Exec { .. }
                        | GuestIntrospectionMessage::Pty { .. }
                        | GuestIntrospectionMessage::Ssh { .. }
                        | GuestIntrospectionMessage::Input(_)
                        | GuestIntrospectionMessage::Resize { .. }
                        | GuestIntrospectionMessage::Close => {
                            break Err(backend_error(
                                "guest agent returned an unexpected protocol record",
                            ));
                        }
                    }
                }
                resized = receive_local_resize(&mut resize_signal), if resize_signal.is_some() => {
                    if resized {
                        let (columns, rows) = local_terminal_size()?;
                        let record = GuestIntrospectionRecord::new(
                            CHANNEL_ID,
                            GuestIntrospectionMessage::Resize { columns, rows },
                        )
                        .map_err(|error| backend_error(error.to_string()))?;
                        exchange_guest_record(
                            &client,
                            session,
                            &lease,
                            &node,
                            CHANNEL_ID,
                            Some(&record),
                            &mut transcript,
                        )
                        .await?;
                    }
                }
                signal = tokio::signal::ctrl_c() => {
                    signal.map_err(|error| backend_error(format!("guest channel signal error: {error}")))?;
                    let close = GuestIntrospectionRecord::new(
                        CHANNEL_ID,
                        GuestIntrospectionMessage::Close,
                    )
                    .map_err(|error| backend_error(error.to_string()))?;
                    exchange_guest_record(
                        &client,
                        session,
                        &lease,
                        &node,
                        CHANNEL_ID,
                        Some(&close),
                        &mut transcript,
                    )
                    .await?;
                    break Ok(());
                }
            }
        }
    }
    .await;
    let cleanup_result: Result<(), CliError> = async {
        if terminal_observed {
            return Ok(());
        }
        let close = GuestIntrospectionRecord::new(CHANNEL_ID, GuestIntrospectionMessage::Close)
            .map_err(|error| backend_error(error.to_string()))?;
        let _response = exchange_guest_record(
            &client,
            session,
            &lease,
            &node,
            CHANNEL_ID,
            Some(&close),
            &mut transcript,
        )
        .await;
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let response = exchange_guest_record(
                    &client,
                    session,
                    &lease,
                    &node,
                    CHANNEL_ID,
                    None,
                    &mut transcript,
                )
                .await?;
                match response.as_ref().map(GuestIntrospectionRecord::message) {
                    Some(GuestIntrospectionMessage::Output { stream, bytes }) => {
                        match stream {
                            GuestOutputStream::Stdout => stdout.write_all(bytes).await,
                            GuestOutputStream::Stderr => stderr.write_all(bytes).await,
                        }
                        .map_err(|error| {
                            backend_error(format!("terminal cleanup output failed: {error}"))
                        })?;
                    }
                    Some(
                        GuestIntrospectionMessage::Exit { .. }
                        | GuestIntrospectionMessage::Error { .. },
                    ) => break Ok(()),
                    Some(_) | None => tokio::time::sleep(Duration::from_millis(5)).await,
                }
            }
        })
        .await
        .map_err(|_| backend_error("timed out closing guest-introspection channel"))?
    }
    .await;
    let transcript_result = match transcript.as_mut() {
        Some(transcript) => transcript.finish().await,
        None => Ok(()),
    };
    let release_result = client.release_debug_controller(session, &lease).await;
    if let Err(error) = channel_result {
        let _cleanup = cleanup_result;
        let _transcript = transcript_result;
        let _release = release_result;
        return Err(error);
    }
    cleanup_result?;
    transcript_result?;
    release_result.map_err(control_client_error)?;
    Ok(())
}

/// Converts local input into the guest channel's stream semantics.
fn guest_input_message(pty_channel: bool, input: &[u8]) -> crucible_api::GuestIntrospectionMessage {
    if !input.is_empty() {
        return crucible_api::GuestIntrospectionMessage::Input(input.to_vec());
    }
    if pty_channel {
        // Closing a PTY input descriptor is a hangup. EOT supplies ordinary
        // terminal EOF without killing a command that is still draining output.
        crucible_api::GuestIntrospectionMessage::Input(vec![0x04])
    } else {
        crucible_api::GuestIntrospectionMessage::Close
    }
}

struct LocalTerminalMode {
    original: Option<rustix::termios::Termios>,
}

impl LocalTerminalMode {
    fn enter_raw(enabled: bool) -> Result<Self, CliError> {
        use std::io::IsTerminal;

        if !enabled || !std::io::stdin().is_terminal() {
            return Ok(Self { original: None });
        }
        let original = rustix::termios::tcgetattr(std::io::stdin())
            .map_err(|error| backend_error(format!("cannot read local terminal mode: {error}")))?;
        let mut raw = original.clone();
        raw.make_raw();
        rustix::termios::tcsetattr(
            std::io::stdin(),
            rustix::termios::OptionalActions::Now,
            &raw,
        )
        .map_err(|error| backend_error(format!("cannot enter local terminal raw mode: {error}")))?;
        Ok(Self {
            original: Some(original),
        })
    }
}

impl Drop for LocalTerminalMode {
    fn drop(&mut self) {
        if let Some(original) = self.original.as_ref() {
            let _restored = rustix::termios::tcsetattr(
                std::io::stdin(),
                rustix::termios::OptionalActions::Now,
                original,
            );
        }
    }
}

fn local_resize_signal(enabled: bool) -> Result<Option<tokio::signal::unix::Signal>, CliError> {
    use std::io::IsTerminal;

    if !enabled || !std::io::stdin().is_terminal() {
        return Ok(None);
    }
    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())
        .map(Some)
        .map_err(|error| backend_error(format!("cannot monitor local terminal resize: {error}")))
}

async fn receive_local_resize(signal: &mut Option<tokio::signal::unix::Signal>) -> bool {
    match signal {
        Some(signal) => signal.recv().await.is_some(),
        None => std::future::pending().await,
    }
}

fn local_terminal_size() -> Result<(u16, u16), CliError> {
    let size = rustix::termios::tcgetwinsize(std::io::stdin())
        .map_err(|error| backend_error(format!("cannot read local terminal size: {error}")))?;
    if size.ws_col == 0 || size.ws_row == 0 {
        return Err(backend_error("local terminal reported a zero window size"));
    }
    Ok((size.ws_col, size.ws_row))
}

fn parse_debug_session_ref(value: &str) -> Result<SessionRef, CliError> {
    let mut fields = value.split(':');
    let id = parse_u64_value("--session id", fields.next().unwrap_or_default())?;
    let epoch = parse_u64_value("--session epoch", fields.next().unwrap_or_default())?;
    let seed_text = fields.next().unwrap_or_default();
    if fields.next().is_some() || seed_text.len() != 64 {
        return Err(usage_error(
            "--session must use id:epoch:64-lowercase-hex-seed",
        ));
    }
    let mut seed = [0_u8; 32];
    for (index, chunk) in seed_text.as_bytes().chunks_exact(2).enumerate() {
        let pair = std::str::from_utf8(chunk)
            .map_err(|_| usage_error("--session seed must be lowercase hexadecimal"))?;
        if pair.bytes().any(|byte| byte.is_ascii_uppercase()) {
            return Err(usage_error("--session seed must be lowercase hexadecimal"));
        }
        seed[index] = u8::from_str_radix(pair, 16)
            .map_err(|_| usage_error("--session seed must be lowercase hexadecimal"))?;
    }
    Ok(SessionRef::new(
        crucible_api::SessionId::new(id),
        epoch,
        crucible::Seed::from_bytes(seed),
    ))
}

#[cfg(test)]
mod remote_debug_tests {
    use super::*;

    #[test]
    fn remote_session_reference_requires_canonical_complete_identity() {
        let parsed = parse_debug_session_ref(
            "7:12:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap_or_else(|error| panic!("canonical session reference should parse: {error}"));
        assert_eq!(parsed.id.value, 7);
        assert_eq!(parsed.epoch, 12);

        assert!(parse_debug_session_ref("7:12:abcd").is_err());
        assert!(
            parse_debug_session_ref(
                "7:12:0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef"
            )
            .is_err()
        );
        assert!(
            parse_debug_session_ref(
                "7:12:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef:extra"
            )
            .is_err()
        );
    }
}

#[path = "triage_debug/coordinates.rs"]
mod coordinates;

pub(super) use coordinates::*;
#[path = "triage_debug/slug.rs"]
mod slug;

pub(crate) use slug::*;

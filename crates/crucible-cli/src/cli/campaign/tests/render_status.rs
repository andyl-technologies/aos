//! Campaign report rendering and status retry tests.

use super::*;

#[test]
fn campaign_head_report_renders_machine_and_human_forms() {
    let report = CampaignHeadReport {
        schema: CAMPAIGN_HEAD_REPORT_SCHEMA,
        operation: "watch",
        campaign: "example".to_owned(),
        snapshot: "snapshot".to_owned(),
        lineage: "lineage".to_owned(),
        policy: "policy".to_owned(),
        state: "running",
        advanced: Some(true),
        semantic: None,
        operational: None,
    };

    let json = render_campaign_head(&report, OutputFormat::Json).expect("JSON report");
    let decoded: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    assert_eq!(decoded["schema"], CAMPAIGN_HEAD_REPORT_SCHEMA);
    assert_eq!(decoded["advanced"], true);

    let table = render_campaign_head(&report, OutputFormat::Table).expect("table report");
    assert!(table.contains("campaign   example"));
    assert!(table.contains("advanced   true"));

    let markdown = render_campaign_head(&report, OutputFormat::Markdown).expect("Markdown report");
    assert!(markdown.contains("| state | running |"));
}

#[test]
fn campaign_mutation_report_renders_exact_transition_basis() {
    let report = CampaignMutationReport {
        schema: CAMPAIGN_MUTATION_REPORT_SCHEMA,
        operation: "pause",
        campaign: "example".to_owned(),
        command: hash("pause").to_hex(),
        prior_snapshot: snapshot("prior").to_string(),
        new_snapshot: snapshot("next").to_string(),
        replayed: true,
    };

    let json = render_campaign_mutation(&report, OutputFormat::Json).expect("JSON report");
    let decoded: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    assert_eq!(decoded["schema"], CAMPAIGN_MUTATION_REPORT_SCHEMA);
    assert_eq!(decoded["prior_snapshot"], report.prior_snapshot);
    assert_eq!(decoded["new_snapshot"], report.new_snapshot);
    assert_eq!(decoded["replayed"], true);

    let table = render_campaign_mutation(&report, OutputFormat::Table).expect("table report");
    assert!(table.contains("operation       pause"));
    assert!(table.contains("replayed        true"));

    let markdown =
        render_campaign_mutation(&report, OutputFormat::Markdown).expect("Markdown report");
    assert!(markdown.contains("| prior_snapshot |"));
    assert!(markdown.contains("| new_snapshot |"));
}

#[test]
fn campaign_acceptance_reports_render_exact_idempotent_results() {
    let reports = [
        CampaignAcceptanceReport::Create {
            schema: CAMPAIGN_ACCEPTANCE_REPORT_SCHEMA,
            campaign: "created".to_owned(),
            snapshot: snapshot("created").to_string(),
            lineage: lineage("lineage").to_string(),
            active_policy: policy("policy").to_string(),
            replayed: false,
            start: Some(CampaignCreateStartReport {
                command: hash("start").to_hex(),
                prior_snapshot: snapshot("created").to_string(),
                new_snapshot: snapshot("started").to_string(),
                replayed: false,
            }),
        },
        CampaignAcceptanceReport::Derive {
            schema: CAMPAIGN_ACCEPTANCE_REPORT_SCHEMA,
            source_campaign: "source".to_owned(),
            source_snapshot: snapshot("source").to_string(),
            campaign: "derived".to_owned(),
            new_snapshot: snapshot("derived").to_string(),
            active_policy: policy("policy").to_string(),
            replayed: true,
        },
        CampaignAcceptanceReport::Branch {
            schema: CAMPAIGN_ACCEPTANCE_REPORT_SCHEMA,
            campaign: "created".to_owned(),
            request: branch_request("render")
                .id()
                .expect("request ID")
                .to_string(),
            prior_snapshot: snapshot("prior").to_string(),
            new_snapshot: snapshot("next").to_string(),
            summary: CampaignBranchAcceptanceSummaryReport::new(
                BranchAcceptanceSummary::new(
                    BranchAcceptanceCount::Exact(1),
                    BranchAcceptanceCount::Exact(0),
                    BranchAcceptanceCount::Exact(1),
                    1,
                    1,
                )
                .expect("acceptance summary"),
                true,
            ),
            replayed: false,
        },
    ];

    for report in reports {
        let json = render_campaign_acceptance(&report, OutputFormat::Json).expect("JSON report");
        let decoded: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(decoded["schema"], CAMPAIGN_ACCEPTANCE_REPORT_SCHEMA);
        assert!(decoded.get("operation").is_some());
        assert!(decoded.get("replayed").is_some());
        if matches!(&report, CampaignAcceptanceReport::Create { .. }) {
            assert_eq!(decoded["start"]["command"], hash("start").to_hex());
            assert_eq!(
                decoded["start"]["prior_snapshot"],
                snapshot("created").to_string()
            );
            assert_eq!(
                decoded["start"]["new_snapshot"],
                snapshot("started").to_string()
            );
        }
        if matches!(&report, CampaignAcceptanceReport::Branch { .. }) {
            assert_eq!(decoded["validated_cardinality"]["kind"], "exact");
            assert_eq!(decoded["validated_cardinality"]["count"], 1);
            assert_eq!(decoded["deduplicated_existing_edges"]["count"], 0);
            assert_eq!(decoded["remaining_lazy_candidates"]["count"], 1);
            assert_eq!(decoded["budget"]["maximum_proposals"], 1);
            assert_eq!(decoded["budget"]["maximum_attempts"], 1);
            assert_eq!(decoded["summary_provenance"], "recorded");
        }

        let table = render_campaign_acceptance(&report, OutputFormat::Table).expect("table report");
        assert!(table.contains("operation"));
        assert!(table.contains("replayed"));
        if matches!(&report, CampaignAcceptanceReport::Create { .. }) {
            assert!(table.contains("start_command"));
            assert!(table.contains("start_snapshot"));
        }
        if matches!(&report, CampaignAcceptanceReport::Branch { .. }) {
            assert!(table.contains("validated_cardinality 1"));
            assert!(table.contains("deduplicated_edges 0"));
            assert!(table.contains("remaining_candidates 1"));
            assert!(table.contains("summary_provenance recorded"));
        }
        let markdown =
            render_campaign_acceptance(&report, OutputFormat::Markdown).expect("Markdown report");
        assert!(markdown.contains("| replayed |"));
        if matches!(&report, CampaignAcceptanceReport::Create { .. }) {
            assert!(markdown.contains("| start_prior_snapshot |"));
            assert!(markdown.contains("| start_replayed |"));
        }
        if matches!(&report, CampaignAcceptanceReport::Branch { .. }) {
            assert!(markdown.contains("| validated_cardinality | 1 |"));
            assert!(markdown.contains("| summary_provenance | recorded |"));
        }
    }
}

#[test]
fn campaign_branch_acceptance_summary_json_has_exact_and_range_goldens() {
    let exact = CampaignBranchAcceptanceSummaryReport::new(
        BranchAcceptanceSummary::new(
            BranchAcceptanceCount::Exact(3),
            BranchAcceptanceCount::Exact(1),
            BranchAcceptanceCount::Exact(2),
            3,
            2,
        )
        .expect("exact acceptance summary"),
        true,
    );
    assert_eq!(
        serde_json::to_string(&exact).expect("exact summary JSON"),
        r#"{"validated_cardinality":{"kind":"exact","count":3},"deduplicated_existing_edges":{"kind":"exact","count":1},"remaining_lazy_candidates":{"kind":"exact","count":2},"budget":{"maximum_proposals":3,"maximum_attempts":2},"summary_provenance":"recorded"}"#
    );

    let ranged = CampaignBranchAcceptanceSummaryReport::new(
        BranchAcceptanceSummary::new(
            BranchAcceptanceCount::between(4, 8).expect("cardinality range"),
            BranchAcceptanceCount::between(0, 2).expect("deduplication range"),
            BranchAcceptanceCount::between(2, 4).expect("remaining range"),
            4,
            1,
        )
        .expect("ranged acceptance summary"),
        false,
    );
    assert_eq!(
        serde_json::to_string(&ranged).expect("ranged summary JSON"),
        r#"{"validated_cardinality":{"kind":"range","minimum":4,"maximum":8},"deduplicated_existing_edges":{"kind":"range","minimum":0,"maximum":2},"remaining_lazy_candidates":{"kind":"range","minimum":2,"maximum":4},"budget":{"maximum_proposals":4,"maximum_attempts":1},"summary_provenance":"legacy-recomputed"}"#
    );
    assert_eq!(
        ranged.human_fields(),
        vec![
            ("validated_cardinality", "4..=8".to_owned()),
            ("deduplicated_edges", "0..=2".to_owned()),
            ("remaining_candidates", "2..=4".to_owned()),
            ("maximum_proposals", "4".to_owned()),
            ("maximum_attempts", "1".to_owned()),
            ("summary_provenance", "legacy-recomputed".to_owned()),
        ]
    );
}

#[test]
fn campaign_page_reports_render_all_query_shapes() {
    let snapshot = snapshot("page").to_string();
    let reports = [
        CampaignPageReport {
            schema: CAMPAIGN_PAGE_REPORT_SCHEMA,
            operation: "graph",
            campaign: "example".to_owned(),
            snapshot: snapshot.clone(),
            start_after: None,
            page_limit: 1,
            page_budget: 1,
            pages_scanned: 1,
            response_bytes: 1,
            complete: false,
            next_after: Some(hash("cursor").to_hex()),
            entries: vec![CampaignPageEntry::Graph {
                key: hash("graph-key").to_hex(),
                object: ContentId::for_bytes(ObjectKind::CampaignFact, 1, b"object").to_string(),
            }],
        },
        CampaignPageReport {
            schema: CAMPAIGN_PAGE_REPORT_SCHEMA,
            operation: "choices",
            campaign: "example".to_owned(),
            snapshot: snapshot.clone(),
            start_after: None,
            page_limit: 1,
            page_budget: 1,
            pages_scanned: 1,
            response_bytes: 1,
            complete: true,
            next_after: None,
            entries: vec![CampaignPageEntry::Choice {
                opportunity: "choice".to_owned(),
            }],
        },
        CampaignPageReport {
            schema: CAMPAIGN_PAGE_REPORT_SCHEMA,
            operation: "frontier",
            campaign: "example".to_owned(),
            snapshot: snapshot.clone(),
            start_after: None,
            page_limit: 1,
            page_budget: 1,
            pages_scanned: 1,
            response_bytes: 1,
            complete: true,
            next_after: None,
            entries: vec![CampaignPageEntry::Frontier {
                request: "request".to_owned(),
                branch_point: "branch-point".to_owned(),
                state: "waiting-for-feedback",
                completed_visits: Some(3),
                required_visits: Some(5),
            }],
        },
        CampaignPageReport {
            schema: CAMPAIGN_PAGE_REPORT_SCHEMA,
            operation: "findings",
            campaign: "example".to_owned(),
            snapshot,
            start_after: None,
            page_limit: 1,
            page_budget: 1,
            pages_scanned: 1,
            response_bytes: 1,
            complete: false,
            next_after: Some(hash("finding-cursor").to_hex()),
            entries: vec![CampaignPageEntry::Finding {
                finding: "finding".to_owned(),
                cluster: hash("cluster").to_hex(),
                finding_kind: "timeout",
                fingerprint: hash("fingerprint").to_hex(),
                property: None,
                failure_class: "timeout.execution".to_owned(),
                observation: "observation".to_owned(),
                occurrences: 3,
                reproduction: "reproduction".to_owned(),
                minimized: None,
            }],
        },
    ];

    for report in reports {
        let json = render_campaign_page(&report, OutputFormat::Json).expect("JSON page");
        let decoded: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(decoded["schema"], CAMPAIGN_PAGE_REPORT_SCHEMA);
        assert_eq!(decoded["operation"], report.operation);
        assert_eq!(decoded["pages_scanned"], 1);
        assert_eq!(decoded["response_bytes"], 1);
        assert_eq!(decoded["entries"].as_array().map(Vec::len), Some(1));

        let table = render_campaign_page(&report, OutputFormat::Table).expect("table page");
        assert!(table.contains("campaign    example"));
        assert!(table.contains("page_budget 1"));
        let markdown =
            render_campaign_page(&report, OutputFormat::Markdown).expect("Markdown page");
        assert!(markdown.contains("| entries | 1 |"));
        assert!(markdown.contains("| pages | 1 |"));
    }
}

#[test]
fn campaign_status_and_watch_use_the_checked_loopback_transport() {
    let status = CampaignCommand::Status(CampaignStatusArgs {
        name: "example".to_owned(),
    });
    let status_report = query_over_loopback(&status);
    assert_eq!(status_report.operation, "status");
    assert_eq!(status_report.snapshot, snapshot("current").to_string());
    assert_eq!(status_report.advanced, None);
    let status_json =
        render_campaign_head(&status_report, OutputFormat::Json).expect("campaign status JSON");
    let status_value: serde_json::Value =
        serde_json::from_str(&status_json).expect("valid campaign status JSON");
    assert_eq!(status_value["schema"], CAMPAIGN_STATUS_REPORT_SCHEMA);
    assert_eq!(status_value["semantic"]["latent_or_open_continuations"], 10);
    assert_eq!(status_value["semantic"]["admitted_attempts"], 13);
    assert_eq!(status_value["semantic"]["stored_graph_nodes"], 17);
    assert_eq!(status_value["semantic"]["continuation_records_scanned"], 28);
    assert_eq!(status_value["operational"]["availability"], "observed");
    assert_eq!(status_value["operational"]["running_worlds"], 23);
    assert_eq!(status_value["operational"]["retained_checkpoint_roots"], 43);
    assert_eq!(status_value["operational"]["materialized_checkpoints"], 47);
    let status_table =
        render_campaign_head(&status_report, OutputFormat::Table).expect("campaign status table");
    assert!(status_table.contains("latent_or_open_continuations 10"));
    assert!(status_table.contains("operational observed"));
    assert!(status_table.contains("running_worlds 23"));

    let watch = CampaignCommand::Watch(CampaignWatchArgs {
        name: "example".to_owned(),
        after: Some(snapshot("previous").to_string()),
    });
    let watch_report = query_over_loopback(&watch);
    assert_eq!(watch_report.operation, "watch");
    assert_eq!(watch_report.state, "running");
    assert_eq!(watch_report.advanced, Some(true));
    let watch_value = serde_json::to_value(&watch_report).expect("watch JSON");
    assert!(watch_value.get("semantic").is_none());
    assert!(watch_value.get("operational").is_none());
}

#[test]
fn campaign_status_refreshes_the_entire_pair_after_one_stale_snapshot() {
    let calls = Arc::new(StatusSequenceCalls::default());
    let client = CampaignClient::new(StatusSequenceService {
        calls: Arc::clone(&calls),
        stale_statuses: 1,
        terminal_failure: None,
    });
    let command = CampaignCommand::Status(CampaignStatusArgs {
        name: "example".to_string(),
    });

    let report = query_campaign_head(
        &client,
        CampaignPrincipal::new("operator").expect("campaign principal"),
        &command,
    )
    .expect("the refreshed paired read succeeds");

    assert_eq!(report.snapshot, snapshot("head-b").to_string());
    assert_eq!(calls.get.load(Ordering::SeqCst), 2);
    assert_eq!(calls.status.load(Ordering::SeqCst), 2);
}

#[test]
fn campaign_status_stops_after_bounded_snapshot_churn() {
    let calls = Arc::new(StatusSequenceCalls::default());
    let client = CampaignClient::new(StatusSequenceService {
        calls: Arc::clone(&calls),
        stale_statuses: usize::MAX,
        terminal_failure: None,
    });
    let command = CampaignCommand::Status(CampaignStatusArgs {
        name: "example".to_string(),
    });

    let error = match query_campaign_head(
        &client,
        CampaignPrincipal::new("operator").expect("campaign principal"),
        &command,
    ) {
        Ok(_) => panic!("persistent churn must remain a terminal status failure"),
        Err(error) => error,
    };

    let rendered = error.to_string();
    assert!(rendered.contains("stale"), "unexpected error: {rendered}");
    assert_eq!(
        calls.get.load(Ordering::SeqCst),
        MAX_CAMPAIGN_STATUS_PAIR_ATTEMPTS
    );
    assert_eq!(
        calls.status.load(Ordering::SeqCst),
        MAX_CAMPAIGN_STATUS_PAIR_ATTEMPTS
    );
}

#[test]
fn campaign_status_does_not_retry_a_non_stale_failure() {
    let calls = Arc::new(StatusSequenceCalls::default());
    let client = CampaignClient::new(StatusSequenceService {
        calls: Arc::clone(&calls),
        stale_statuses: 0,
        terminal_failure: Some(CampaignServiceFailure::Unauthorized),
    });
    let command = CampaignCommand::Status(CampaignStatusArgs {
        name: "example".to_string(),
    });

    let error = match query_campaign_head(
        &client,
        CampaignPrincipal::new("operator").expect("campaign principal"),
        &command,
    ) {
        Ok(_) => panic!("authorization failure must remain terminal"),
        Err(error) => error,
    };

    assert!(error.to_string().contains("not authorized"));
    assert_eq!(calls.get.load(Ordering::SeqCst), 1);
    assert_eq!(calls.status.load(Ordering::SeqCst), 1);
}

#[test]
fn campaign_validation_authenticates_connected_and_offline_targets() {
    let validate = CampaignValidateArgs {
        name: Some("example".to_owned()),
        policy: None,
    };
    let (client_stream, mut server_stream) = UnixStream::pair().expect("campaign stream pair");
    let server = thread::spawn(move || {
        serve_loopback_campaign_once(&mut server_stream, &FixedHeadService)
            .expect("serve one campaign validation");
    });
    let service = LoopbackCampaignService::new(client_stream).expect("loopback client");
    let client = CampaignClient::new(service);
    let report = query_campaign_validation(
        &client,
        CampaignPrincipal::new("operator").expect("campaign principal"),
        &validate,
    )
    .expect("checked campaign validation");
    server.join().expect("campaign server thread");
    let validation::CampaignValidationReport::Campaign {
        campaign,
        snapshot: current,
        state,
        ..
    } = &report
    else {
        panic!("connected validation report");
    };
    assert_eq!(campaign, "example");
    assert_eq!(current, &snapshot("current").to_string());
    assert_eq!(*state, "running");
    let rendered =
        render_campaign_validation(&report, OutputFormat::Json).expect("campaign validation JSON");
    let value: serde_json::Value = serde_json::from_str(&rendered).expect("valid JSON");
    assert_eq!(
        value["schema"],
        validation::CAMPAIGN_VALIDATION_REPORT_SCHEMA
    );
    assert_eq!(value["subject"], "campaign");

    let temporary = tempfile::tempdir().expect("temporary policy input");
    let path = temporary.path().join("policy.bin");
    let (_, policy) = campaign_records();
    let canonical = policy.canonical_bytes();
    std::fs::write(&path, &canonical).expect("write canonical policy");
    let report = validate_campaign_policy_file(&path).expect("offline policy validation");
    let validation::CampaignValidationReport::Policy {
        policy: validated,
        encoded_bytes,
        choice_policies,
        ..
    } = &report
    else {
        panic!("offline policy validation report");
    };
    assert_eq!(validated, &policy.id().expect("policy ID").to_string());
    assert_eq!(*encoded_bytes, canonical.len());
    assert_eq!(*choice_policies, 0);
    assert!(
        render_campaign_validation(&report, OutputFormat::Markdown)
            .expect("policy validation Markdown")
            .contains("| subject | policy |")
    );
    let invocation = Cli::try_parse_from([
        std::ffi::OsString::from("crucible"),
        std::ffi::OsString::from("campaign"),
        std::ffi::OsString::from("validate"),
        std::ffi::OsString::from("--policy"),
        path.as_os_str().to_owned(),
    ])
    .expect("offline validation invocation");
    let Commands::Campaign(args) = &invocation.command else {
        panic!("campaign validation command");
    };
    run_campaign_invocation(&invocation, args).expect("offline validation without a socket");

    let mut malformed = canonical;
    malformed.push(0);
    std::fs::write(&path, malformed).expect("write malformed policy");
    assert!(validate_campaign_policy_file(&path).is_err());
}

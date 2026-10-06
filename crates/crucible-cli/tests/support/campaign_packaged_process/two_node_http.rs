//! Bounded two-guest HTTP exchange through the public packaged campaign runtime.
//!
//! Completion requires routed request and response bytes plus an authenticated
//! client marker emitted only after checking the exact response body. This cold
//! execution flight does not claim retained-source or hot-fork functionality.

use super::*;
use crucible_core::model::{
    Aggregation, BoundarySelector, CohortPolicy, MeasurementDefinition, MeasurementDefinitions,
    MeasurementId, MeasurementInstanceKey, MetricDefinition, MetricId, MetricSource,
    MetricValueType, UnitId,
};
use crucible_core::{FramePredicate, LinkId};
use crucible_daemon::{AttemptExecutionOrigin, AttemptRuntimeState};
use crucible_session::engine::{LinkDef, LinkLossProbability, MarkerId};

const HTTP_VIRTUAL_BUDGET_TICKS: u64 = 2_000_000_000_000;
// This watchdog bounds a broken host/runtime operation; it is not simulation
// time and does not determine the canonical outcome.
const HTTP_STARTUP_WATCHDOG: Duration = Duration::from_secs(1800);
const HTTP_APPLICATION_WATCHDOG: Duration = Duration::from_secs(180);
const HTTP_RESPONSE: &[u8] = b"Crucible reached nginx\n";
const HTTP_MARKER: &str = "http.request-response";
const HTTP_MARKER_INSTANCE: &str = "instance-1";

fn http_measurement_definitions(
    world: &World,
    plan: &Plan,
) -> Result<MeasurementDefinitions, Box<dyn Error>> {
    // Measure the response marker's own coordinate directly; retained execution
    // evidence need not contain a scenario-ready event.
    let response_marker = BoundarySelector::GuestMarker {
        marker: MarkerId::from_name(HTTP_MARKER),
        instance: Some(MeasurementInstanceKey::parse(HTTP_MARKER_INSTANCE)?),
    };

    Ok(MeasurementDefinitions::new(
        world,
        plan,
        &Properties::empty(),
        vec![MeasurementDefinition {
            id: MeasurementId::parse(HTTP_MARKER)?,
            begin: response_marker.clone(),
            end: response_marker,
            timeout: None,
            cohort: CohortPolicy::All(vec![NodeId {
                name: "curl".into(),
            }]),
            metrics: vec![MetricDefinition {
                id: MetricId::parse("completion_virtual_time")?,
                value_type: MetricValueType::UnsignedInteger,
                unit: UnitId::parse("virtual_ticks")?,
                source: MetricSource::VirtualTime,
                aggregation: Aggregation::Max,
            }],
        }],
    )?)
}

#[test]
#[ignore = "requires packaged QEMU and isolated cgroup-v2/project-quota roots"]
fn public_two_node_http_request_and_response_are_authenticated() -> Result<(), Box<dyn Error>> {
    let fixture = FlightFixture::new()?;
    println!("two_node_http_stage=compile");
    let compiled = compile_http_scenario(&fixture)?;
    println!("two_node_http_stage=import");
    guest_choice::create_guest_choice_campaign_with_timeout(
        &fixture,
        &compiled,
        "qemu-11.1.1-crucible",
        Some(HTTP_VIRTUAL_BUDGET_TICKS),
    )?;
    let authority = guest_choice::write_component_authority(&fixture)?;
    println!("two_node_http_stage=start-runtime");
    let mut service =
        guest_choice::start_callback_witness_flight_service(&fixture, &authority, None, 10400)?;
    let mut processes = process_audit::ProcessAudit::with_cpu_diagnostics(256);

    println!("two_node_http_virtual_budget_ticks={HTTP_VIRTUAL_BUDGET_TICKS}");
    println!("two_node_http_startup_host_watchdog_seconds=1800");
    println!("two_node_http_application_host_watchdog_seconds=180");
    let exchange = (|| {
        guest_choice::grant_and_start_guest_choice_campaign(&fixture)?;
        println!("two_node_http_campaign_started=true");
        let explanation = wait_for_http_completion(&fixture, &mut service, &mut processes)?;
        if explanation["observation"]["stop"] != "terminal-success"
            || explanation["observation"]["discovered_choices"] != serde_json::json!([])
        {
            return Err(format!("HTTP exchange did not complete cleanly: {explanation}").into());
        }
        envoy_network::require_semantic_marker(&explanation, HTTP_MARKER, "curl")?;
        processes.require_guest_workloads(&["httpget", "httpd"])?;
        println!("two_node_http_attempt={explanation}");
        Ok::<(), Box<dyn Error>>(())
    })();
    if exchange.is_err() {
        guest_choice::report_recent_control_callback_witness(&service);
    }
    processes.report_observed_processes("before-http-cleanup");
    println!("two_node_http_stage=cleanup");
    let shutdown = service.stop();
    let cleanup = processes.verify_cleanup();
    let mut failures = Vec::new();
    for (stage, result) in [
        ("HTTP exchange", exchange),
        ("HTTP service shutdown", shutdown),
        ("HTTP QEMU cleanup", cleanup),
    ] {
        if let Err(error) = result {
            failures.push(format!("{stage} failed: {error}"));
        }
    }
    if !failures.is_empty() {
        return Err(failures.join("; ").into());
    }

    let run_root = required_path("CRUCIBLE_FLIGHT_RUN_ROOT")?;
    if fs::read_dir(&run_root)?.next().transpose()?.is_some() {
        return Err(format!(
            "HTTP cleanup retained an attempt directory in {}",
            run_root.display()
        )
        .into());
    }
    if fixture
        ._temporary
        .path()
        .join("guest-choice-executor.sock")
        .exists()
    {
        return Err("HTTP cleanup retained its executor socket".into());
    }
    println!("two_node_http_request_response_authenticated=true");
    println!("two_node_http_exact_body_authenticated=true");
    println!("two_node_http_cold_execution=true");
    println!("two_node_http_cleanup_authenticated=true");
    Ok(())
}

fn compile_http_scenario(fixture: &FlightFixture) -> Result<Value, Box<dyn Error>> {
    let kernel = ContentAddressedBlobRef::from_hash(ContentHash::from_bytes(&fs::read(
        required_path("CRUCIBLE_KERNEL")?,
    )?));
    let root_image = ContentAddressedBlobRef::from_hash(ContentHash::from_bytes(&fs::read(
        required_path("CRUCIBLE_ROOT_IMAGE")?,
    )?));
    let client = WorldNode {
        id: NodeId { name: "curl".into() },
        arch: VmArchitecture::X86_64,
        memory_mib: 256,
        cmdline: "console=ttyS0 net.ifnames=0 root=/dev/vda rw init=/init nokaslr norandmaps random.trust_cpu=off crucible.workload=httpget".into(),
        ready_point: ReadyPoint::FixedIcount { icount: Icount { retired: 0 } },
        white_box: WhiteBoxPolicy::Enabled,
        smp_vcpus: 1,
        kernel: Some(kernel),
        root_image: Some(root_image),
        initrd: None,
    };
    let server = WorldNode {
        id: NodeId {
            name: "nginx".into(),
        },
        cmdline: client.cmdline.replace("httpget", "httpd"),
        ..client.clone()
    };
    let link_id = LinkId::for_endpoints(&client.id, &server.id);
    let link = LinkDef::with_transport(
        client.id.clone(),
        server.id.clone(),
        SimDuration { ticks: 250_000_000 },
        SimDuration { ticks: 0 },
        LinkLossProbability::ZERO,
        None,
    )?;
    let world = World::from_nodes_and_links(vec![client, server], vec![link])?;
    let graph = EventGraph::builder()
        .event("complete-http-exchange")
        .entrypoint()
        .when(Predicate::all_of(vec![
            Predicate::once(Predicate::network_match(
                Some(link_id.clone()),
                FramePredicate::contains(b"GET / HTTP/1.1".to_vec()),
            )),
            Predicate::once(Predicate::network_match(
                Some(link_id),
                FramePredicate::contains(HTTP_RESPONSE.to_vec()),
            )),
            Predicate::once(Predicate::guest_marker(MarkerId::from_name(HTTP_MARKER))),
        ]))
        .action(Action::Pass)
        .build_for_world(&world)?;
    let plan = Plan::from_event_graph_for_world(&world, graph)?;
    let measurements = http_measurement_definitions(&world, &plan)?;
    let scenario = ScenarioDefForm::from_components_with_measurements(
        &world,
        &plan,
        &Properties::empty(),
        &measurements,
        Seed::from_u64(104),
    )?;
    let source = fixture
        ._temporary
        .path()
        .join("two-node-http.scenario.toml");
    fs::write(&source, scenario.to_canonical_toml()?)?;
    run_json(
        command(&["--format", "jsonl", "campaign", "scenario", "compile"])
            .arg(source)
            .arg("--output")
            .arg(&fixture.fixture),
        "compile two-node HTTP scenario",
    )
}

/// Tracks operational phases using only host-reported authenticated setup events.
struct HttpHostWatchdog {
    began: Instant,
    application_started: Option<Instant>,
    setup_nodes: BTreeSet<&'static str>,
}

impl HttpHostWatchdog {
    fn new(began: Instant) -> Self {
        Self {
            began,
            application_started: None,
            setup_nodes: BTreeSet::new(),
        }
    }

    fn observe(&mut self, stderr: &str, now: Instant) {
        self.setup_nodes
            .extend(stderr.lines().filter_map(setup_receipt_node));
        if self.application_started.is_none()
            && self.setup_nodes.len() == 2
            && now.duration_since(self.began) < HTTP_STARTUP_WATCHDOG
        {
            self.application_started = Some(now);
        }
    }

    fn phase(&self) -> &'static str {
        if self.application_started.is_some() {
            "application"
        } else {
            "startup"
        }
    }

    fn expired(&self, now: Instant) -> bool {
        match self.application_started {
            Some(started) => now.duration_since(started) >= HTTP_APPLICATION_WATCHDOG,
            None => now.duration_since(self.began) >= HTTP_STARTUP_WATCHDOG,
        }
    }
}

fn setup_receipt_node(line: &str) -> Option<&'static str> {
    let mut fields = line
        .strip_prefix("CRUCIBLE-RUNTIME-BOOT-V1 ")?
        .split_whitespace();
    match fields.next()? {
        "stage=before-quantum" | "stage=after-quantum" => {}
        _ => return None,
    }
    let node = match fields.next()? {
        "node=\"curl\"" => "curl",
        "node=\"nginx\"" => "nginx",
        _ => return None,
    };
    fields.next()?.strip_prefix("guest_stage=")?;
    fields
        .next()?
        .strip_prefix("stage_icount=")?
        .parse::<u64>()
        .ok()?;
    let receipts = fields
        .next()?
        .strip_prefix("setup_receipts=")?
        .parse::<u64>()
        .ok()?;
    (receipts > 0).then_some(node)
}

fn wait_for_http_completion(
    fixture: &FlightFixture,
    service: &mut CampaignServiceChild,
    processes: &mut process_audit::ProcessAudit,
) -> Result<Value, Box<dyn Error>> {
    let began = Instant::now();
    let deadline = began + HTTP_STARTUP_WATCHDOG + HTTP_APPLICATION_WATCHDOG;
    let mut watchdog = HttpHostWatchdog::new(began);
    let mut last_report = began;
    let mut last_states = String::new();
    let completed = wait_for_process_observation(deadline, || {
        let stderr = service.stderr_tail();
        if let Some(error) = first_execution_error(&stderr) {
            return Err(format!("HTTP packaged execution failed: {error}; stderr={stderr}").into());
        }
        if let Some(status) = service.child.try_wait()? {
            return Err(format!(
                "HTTP service exited before completion: {status}; stderr={stderr}"
            )
            .into());
        }
        processes.observe(service.child.id(), false)?;
        watchdog.observe(&stderr, Instant::now());
        let states = guest_choice::attempt_states(fixture)?;
        last_states = format!("{states:?}");
        if last_report.elapsed() >= Duration::from_secs(5) {
            println!(
                "two_node_http_wait elapsed_host_seconds={} operational_phase={} authenticated_setup_nodes={:?} states={last_states}",
                began.elapsed().as_secs(),
                watchdog.phase(),
                watchdog.setup_nodes,
            );
            processes.report_observed_processes("http-wait");
            let diagnostics = stderr
                .lines()
                .filter(|line| {
                    line.starts_with("CRUCIBLE-GUEST-SELECTABLE-BOUNDARY-V1 ")
                        || line.starts_with("CRUCIBLE-EXACT-RESUME-PROGRESS-V1 ")
                        || line.starts_with("CRUCIBLE-RUNTIME-PROGRESS-V1 ")
                        || line.starts_with("CRUCIBLE-RUNTIME-BOOT-V1 ")
                })
                .rev()
                .take(10)
                .collect::<Vec<_>>();
            for diagnostic in diagnostics.into_iter().rev() {
                println!("two_node_http_runtime_diagnostic={diagnostic}");
            }
            last_report = Instant::now();
        }
        for (key, state) in states {
            if state.origin() != AttemptExecutionOrigin::Initial {
                continue;
            }
            match state {
                AttemptRuntimeState::Completed { .. } => {
                    if watchdog.setup_nodes.len() != 2 {
                        return Err(format!(
                            "HTTP completed without both authenticated guest setup receipts; nodes={:?}; stderr={stderr}",
                            watchdog.setup_nodes
                        ).into());
                    }
                    return guest_choice::wait_for_attempt_observation(fixture, key).map(Some);
                }
                AttemptRuntimeState::TerminalFailure { .. } => {
                    return Err(format!(
                        "HTTP execution failed: {key:?}; stderr={}",
                        service.stderr_tail()
                    )
                    .into());
                }
                _ => {}
            }
        }
        if watchdog.expired(Instant::now()) {
            return Err(format!(
                "HTTP {} host panic fallback expired; authenticated_setup_nodes={:?}; states={last_states}; stderr={stderr}",
                watchdog.phase(), watchdog.setup_nodes,
            ).into());
        }
        Ok(None)
    })?;
    completed.ok_or_else(|| {
        format!(
            "HTTP overall host panic fallback expired; operational_phase={}; authenticated_setup_nodes={:?}; states={last_states}; stderr={}",
            watchdog.phase(), watchdog.setup_nodes, service.stderr_tail()
        )
        .into()
    })
}

fn first_execution_error(stderr: &str) -> Option<&str> {
    // A retryable worker failure can leave the durable attempt Running. Surface
    // its original diagnostic promptly instead of waiting for TerminalFailure.
    stderr
        .lines()
        .find(|line| line.starts_with("packaged campaign execution ") && line.contains(" failed:"))
}

#[test]
fn setup_receipts_require_host_prefix_declared_node_and_positive_count() {
    let valid = "CRUCIBLE-RUNTIME-BOOT-V1 stage=after-quantum node=\"curl\" guest_stage=setup-complete stage_icount=42 setup_receipts=1 console_bytes=12 console_tail_partial=true console_tail=\"boot\"";
    assert_eq!(setup_receipt_node(valid), Some("curl"));
    for invalid in [
        valid.replace("CRUCIBLE-RUNTIME-BOOT-V1", "guest-console"),
        valid.replace("node=\"curl\"", "node=\"other\""),
        valid.replace("setup_receipts=1", "setup_receipts=0"),
        valid.replace("setup_receipts=1", "setup_receipts=one"),
        valid.replace("stage_icount=42", "stage_icount=broken"),
        valid.replace("stage=after-quantum", "stage=guest-claimed"),
        format!("console_tail={valid:?}"),
    ] {
        assert_eq!(setup_receipt_node(&invalid), None, "{invalid}");
    }
}

#[test]
fn host_fallback_transitions_only_after_both_guest_setup_receipts() {
    let began = Instant::now();
    let curl = "CRUCIBLE-RUNTIME-BOOT-V1 stage=after-quantum node=\"curl\" guest_stage=setup-complete stage_icount=42 setup_receipts=1";
    let nginx = curl.replace("node=\"curl\"", "node=\"nginx\"");
    let mut watchdog = HttpHostWatchdog::new(began);

    watchdog.observe(curl, began + Duration::from_secs(10));
    watchdog.observe(curl, began + Duration::from_secs(20));
    assert_eq!(watchdog.phase(), "startup");
    assert!(!watchdog.expired(began + Duration::from_secs(1799)));

    watchdog.observe(&nginx, began + Duration::from_secs(30));
    assert_eq!(watchdog.phase(), "application");
    assert!(!watchdog.expired(began + Duration::from_secs(209)));
    assert!(watchdog.expired(began + Duration::from_secs(210)));

    let mut late = HttpHostWatchdog::new(began);
    late.observe(curl, began);
    assert!(late.expired(began + HTTP_STARTUP_WATCHDOG));
    late.observe(&nginx, began + HTTP_STARTUP_WATCHDOG);
    assert_eq!(late.phase(), "startup");
    assert!(late.expired(began + HTTP_STARTUP_WATCHDOG));
}

#[test]
fn http_wait_reports_retryable_execution_failure_without_misclassifying_warnings() {
    let failure = "packaged campaign execution example failed: backend refused request";
    assert_eq!(first_execution_error(failure), Some(failure));
    assert_eq!(
        first_execution_error("qemu-system-x86_64: warning: unrelated diagnostic"),
        None
    );
    assert_eq!(
        first_execution_error("a guest printed packaged campaign execution example failed: text"),
        None
    );
    assert_eq!(
        first_execution_error("packaged campaign execution example completed"),
        None
    );
}

#[test]
fn http_measurement_publication_accepts_only_the_declared_client_marker()
-> Result<(), Box<dyn Error>> {
    use crucible_campaign::{ConfigurationId, ScenarioDefId};
    use crucible_core::SchedulerEventLogEntry;
    use crucible_core::model::{
        MeasurementAggregateValue, MeasurementEvaluationError, MeasurementSampleValue,
        MeasurementTerminalState, MeasurementWindowOutcome,
    };
    use crucible_daemon::{
        CrucibleMeasurementError, evaluate_crucible_measurement_publication,
        verify_crucible_measurement_publication,
    };

    let client = NodeId {
        name: "curl".into(),
    };
    let server = NodeId {
        name: "nginx".into(),
    };
    let world = World::from_nodes(vec![WorldNode {
        id: client.clone(),
        arch: VmArchitecture::X86_64,
        memory_mib: 256,
        cmdline: "crucible.workload=httpget".into(),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 0 },
        },
        white_box: WhiteBoxPolicy::Enabled,
        smp_vcpus: 1,
        kernel: None,
        root_image: None,
        initrd: None,
    }])?;
    let plan = Plan::empty();
    let definitions = http_measurement_definitions(&world, &plan)?;
    let form = ScenarioDefForm::from_components_with_measurements(
        &world,
        &plan,
        &Properties::empty(),
        &definitions,
        Seed::from_u64(104),
    )?;
    let restored = ScenarioDefForm::from_canonical_toml(&form.to_canonical_toml()?)?;
    assert_eq!(
        restored.measurements().content_hash(),
        definitions.content_hash()
    );
    let scenario =
        ScenarioDefId::from_hash(CampaignHash::derive("http-measurement-test", b"scenario"));
    let configuration = ConfigurationId::from_hash(CampaignHash::derive(
        "http-measurement-test",
        b"configuration",
    ));
    let evaluate = |definitions: &MeasurementDefinitions, node: NodeId, instance: &str, ready| {
        evaluate_crucible_measurement_publication(
            scenario,
            configuration,
            definitions,
            vec![SchedulerEventLogEntry::guest_semantic_marker_observation(
                0,
                Icount { retired: 5 },
                node,
                HTTP_MARKER.into(),
                instance.into(),
                Vec::new(),
            )],
            MeasurementTerminalState {
                scenario_ready_at: ready,
                at: VirtualTime { ticks: 10 },
                node_icounts: BTreeMap::from([(client.clone(), Icount { retired: 5 })]),
                scheduler_quiescent: true,
            },
            1024 * 1024,
        )
    };

    let undeclared = evaluate(
        &MeasurementDefinitions::empty(),
        client.clone(),
        "instance-1",
        None,
    );
    assert!(
        matches!(undeclared, Err(CrucibleMeasurementError::GuestMeasurementProtocol { sequence: 0, reason }) if reason == "semantic marker `http.request-response` instance `instance-1` is not declared")
    );
    let mut needs_ready = definitions.definitions().to_vec();
    needs_ready[0].begin = BoundarySelector::ScenarioReady;
    let needs_ready =
        MeasurementDefinitions::new(&world, &plan, &Properties::empty(), needs_ready)?;
    assert!(matches!(
        evaluate(&needs_ready, client.clone(), HTTP_MARKER_INSTANCE, None),
        Err(CrucibleMeasurementError::Evaluation(
            MeasurementEvaluationError::EmptySamples { aggregation: "max" }
        ))
    ));

    let no_response_marker = evaluate_crucible_measurement_publication(
        scenario,
        configuration,
        restored.measurements(),
        Vec::new(),
        MeasurementTerminalState {
            scenario_ready_at: None,
            at: VirtualTime { ticks: 10 },
            node_icounts: BTreeMap::new(),
            scheduler_quiescent: true,
        },
        1024 * 1024,
    );
    assert!(matches!(
        no_response_marker,
        Err(CrucibleMeasurementError::Evaluation(
            MeasurementEvaluationError::EmptySamples { aggregation: "max" }
        ))
    ));

    for ready in [
        None,
        Some(VirtualTime { ticks: 1 }),
        Some(VirtualTime { ticks: 6 }),
    ] {
        let accepted = evaluate(
            restored.measurements(),
            client.clone(),
            HTTP_MARKER_INSTANCE,
            ready,
        )?;
        let evaluation = verify_crucible_measurement_publication(
            accepted.measurement_set(),
            accepted.evidence(),
            scenario,
            configuration,
            restored.measurements(),
        )?;
        let outcome = &evaluation.outcomes()[&MeasurementId::parse(HTTP_MARKER)?];
        let MeasurementWindowOutcome::Completed { begin, end } = outcome.window() else {
            panic!("response marker must close its own measurement window");
        };
        let marker = &accepted.evidence().entries()[0];
        assert_eq!(begin, end);
        assert_eq!(begin.sequence(), Some(marker.sequence()));
        assert_eq!(begin.at(), marker.at());
        assert_eq!(begin.events()[0].content_hash(), marker.content_hash());

        let metric = &outcome.metrics()[&MetricId::parse("completion_virtual_time")?];
        assert_eq!(metric.samples().len(), 1);
        assert_eq!(
            metric.samples()[0].value(),
            &MeasurementSampleValue::Unsigned(marker.at().ticks)
        );
        assert_eq!(
            metric.aggregate(),
            &MeasurementAggregateValue::Unsigned(marker.at().ticks)
        );
    }

    for refused in [
        evaluate(&definitions, client.clone(), "instance-2", None),
        evaluate(&definitions, server, "instance-1", None),
    ] {
        assert!(matches!(
            refused,
            Err(CrucibleMeasurementError::GuestMeasurementProtocol { sequence: 0, .. })
        ));
    }
    Ok(())
}

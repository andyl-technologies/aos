//! Independent one-guest execution and disk-backed materialization environments.
//!
//! Both flights use the public campaign service and the packaged QEMU/plugin.
//! The static initramfs registers real guest choices and reports their selected
//! values. Its attached small root disk still uses the production writable
//! overlay, pinned descriptors, credentials, and project quota.
//! Both flights enable the bounded control callback witness, including the
//! fork materialization, replay, and restore stages of the second flight.

use super::*;
use crucible_campaign::{AttemptExecutionScope, AttemptId, CampaignFactId, ExactCheckpointId};
use crucible_daemon::{AttemptExecutionKey, AttemptRuntimeState, ExactCheckpointStore};
use crucible_qemu::QemuLaunchArtifactIdentity;
use crucible_session::engine::MarkerId;

const VIRTUAL_BUDGET_PS: u64 = 2_000_000_000_000;
const HOST_WATCHDOG: Duration = Duration::from_secs(180);
const SELECTED_MARKER: &str = "selected-fast-q7";
const COMPLETION_MARKER: &str = "selected-fast-q7-progress-000003";

#[test]
#[ignore = "requires packaged QEMU, cgroup v2, and project quotas in the dedicated VM"]
fn public_single_guest_executes_and_cleans_up() -> Result<(), Box<dyn Error>> {
    run_single_guest(false)
}

#[test]
#[ignore = "requires packaged QEMU, cgroup v2, and project quotas in the dedicated VM"]
fn public_single_guest_forks_replays_and_restores() -> Result<(), Box<dyn Error>> {
    run_single_guest(true)
}

fn run_single_guest(materialization: bool) -> Result<(), Box<dyn Error>> {
    let fixture = FlightFixture::new()?;
    if materialization {
        grant_savepoint_permission(&fixture)?;
    }
    let compiled = compile_single_guest(&fixture)?;
    let packaged = QemuLaunchArtifactIdentity::authenticate(
        required_path("CRUCIBLE_FLIGHT_QEMU")?,
        required_path("CRUCIBLE_FLIGHT_PLUGIN")?,
    )?;
    guest_choice::create_guest_choice_campaign_with_timeout(
        &fixture,
        &compiled,
        packaged.qemu_build_id(),
        Some(VIRTUAL_BUDGET_PS),
    )?;
    let authority = guest_choice::write_component_authority(&fixture)?;
    let hot_fork = materialization
        .then(|| guest_choice::materialization_flight_deployment(&fixture))
        .transpose()?;
    let mut service = guest_choice::start_callback_witness_flight_service(
        &fixture,
        &authority,
        hot_fork.as_deref(),
        4400,
    )?;
    let mut processes = process_audit::ProcessAudit::default();
    stage("guest-start");
    guest_choice::grant_and_start_guest_choice_campaign(&fixture)?;

    let known = BTreeSet::new();
    let (discovery, discovered) = wait_for_observation(
        &fixture,
        &mut service,
        &known,
        &mut processes,
        materialization,
        "guest-discovery",
    )?;
    require_bounded_boundary(&discovered, "next-choice")?;
    if materialization {
        guest_choice::assert_materialization_tier(
            &guest_choice::capture_materialization_events(&service)?,
            discovery.attempt(),
            "HotFork",
        )?;
        processes.require_private_fork("guest-discovery")?;
        println!("single_guest_private_disk_fork_authenticated=true");
    }

    let recovery = choice_at(&fixture, &discovered, "campaign.recovery-policy")?;
    let mut known = guest_choice::attempt_states(&fixture)?
        .into_keys()
        .collect::<BTreeSet<_>>();
    guest_choice::submit_choice(
        &fixture,
        &recovery,
        &format!("discrete:{}", guest_choice::FAST_ALTERNATIVE),
        "next-choice",
        0x81,
    )?;
    let (_, selected_recovery) = wait_for_observation(
        &fixture,
        &mut service,
        &known,
        &mut processes,
        materialization,
        "select-recovery",
    )?;
    let quanta_choice = choice_at(&fixture, &selected_recovery, "campaign.retry-quanta")?;

    if materialization {
        stage("retire-fork-source");
        service.stop()?;
        processes.verify_cleanup()?;
        service =
            guest_choice::start_callback_witness_flight_service(&fixture, &authority, None, 4400)?;
        assert_eq!(
            choice_at(&fixture, &selected_recovery, "campaign.retry-quanta")?,
            quanta_choice
        );
    }
    known = guest_choice::attempt_states(&fixture)?
        .into_keys()
        .collect();

    // Named stops match guest marker names, not event-graph trigger IDs.
    let selected_stop = format!(
        "boundary:{}",
        if materialization {
            SELECTED_MARKER
        } else {
            COMPLETION_MARKER
        }
    );
    guest_choice::submit_choice(&fixture, &quanta_choice, "u64:7", &selected_stop, 0x82)?;
    let (selected, selection) = wait_for_observation(
        &fixture,
        &mut service,
        &known,
        &mut processes,
        false,
        "selected-guest-result",
    )?;
    assert_eq!(selection["selection"]["value"], "u64:7");
    if materialization {
        require_bounded_boundary(&selection, &selected_stop)?;
    } else {
        assert_eq!(selection["observation"]["stop"], "terminal-success");
    }
    println!("single_guest_selected_result={SELECTED_MARKER}");

    if materialization {
        guest_choice::assert_materialization_tier(
            &guest_choice::capture_materialization_events(&service)?,
            selected.attempt(),
            "ThinReplay",
        )?;
        println!("single_guest_thin_replay_authenticated=true");
        capture_and_restore(&fixture, &mut service, &selection, &mut processes)?;
    }

    let head = campaign_status(&fixture)?;
    run_json(
        connected_campaign(&fixture).args([
            "stop",
            CAMPAIGN,
            "--expected",
            &json_string(&head, "snapshot")?,
            "--command",
            &"86".repeat(32),
        ]),
        "stop single-guest campaign",
    )?;
    assert_eq!(campaign_status(&fixture)?["state"], "completed");
    stage("service-stop-and-cleanup");
    processes.observe(service.child.id(), false)?;
    service.stop()?;
    processes.verify_cleanup()?;
    println!("single_guest_process_cleanup_authenticated=true");
    println!("single_guest_public_execution_authenticated=true");
    Ok(())
}

fn compile_single_guest(fixture: &FlightFixture) -> Result<Value, Box<dyn Error>> {
    let root_image = required_path("CRUCIBLE_ROOT_IMAGE")?;
    assert_eq!(fs::metadata(&root_image)?.len(), 1024 * 1024);
    let reference = |name| -> Result<ContentAddressedBlobRef, Box<dyn Error>> {
        Ok(ContentAddressedBlobRef::from_hash(ContentHash::from_bytes(
            &fs::read(required_path(name)?)?,
        )))
    };
    let node = WorldNode {
        id: NodeId {
            name: "single".into(),
        },
        arch: VmArchitecture::X86_64,
        memory_mib: 128,
        cmdline: "console=ttyS0 rdinit=/init quiet nokaslr norandmaps random.trust_cpu=off".into(),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 0 },
        },
        white_box: WhiteBoxPolicy::Enabled,
        smp_vcpus: 1,
        kernel: Some(reference("CRUCIBLE_KERNEL")?),
        root_image: Some(reference("CRUCIBLE_ROOT_IMAGE")?),
        initrd: Some(reference("CRUCIBLE_INITRD")?),
    };
    let world = World::from_nodes_and_links(vec![node], Vec::new())?;
    let selectables = guest_choice::guest_choice_selectables_with_prefix(&world, "campaign")?;
    let graph = EventGraph::builder()
        .event("single.selected")
        .entrypoint()
        .when(Predicate::once(Predicate::guest_marker(
            MarkerId::from_name(SELECTED_MARKER),
        )))
        .action(Action::Group(Vec::new()))
        .event("single.complete")
        .when(Predicate::once(Predicate::guest_marker(
            MarkerId::from_name(COMPLETION_MARKER),
        )))
        .action(Action::Pass)
        .build_for_world(&world)?;
    let plan = Plan::from_event_graph_for_world(&world, graph)?;
    let scenario =
        ScenarioDefForm::from_components(&world, &plan, &Properties::empty(), Seed::from_u64(103))?
            .with_selectables(selectables)?;
    let path = fixture._temporary.path().join("single-guest.scenario.toml");
    fs::write(&path, scenario.to_canonical_toml()?)?;
    run_json(
        command(&["--format", "jsonl", "campaign", "scenario", "compile"])
            .arg(path)
            .arg("--output")
            .arg(&fixture.fixture),
        "compile one-guest environment",
    )
}

fn choice_at(
    fixture: &FlightFixture,
    report: &Value,
    selectable: &str,
) -> Result<guest_choice::PublicChoice, Box<dyn Error>> {
    guest_choice::wait_for_choice_with_timeout(
        fixture,
        selectable,
        &json_string(&report["observation"], "child_artifact")?,
        &json_string(&report["observation"], "child")?,
        Duration::from_secs(30),
    )
}

fn grant_savepoint_permission(fixture: &FlightFixture) -> Result<(), Box<dyn Error>> {
    // The ordinary execution fixture stays unprivileged for exact captures.
    // Install only this campaign's grant before the service loads its policy.
    let mut policy = fs::OpenOptions::new()
        .append(true)
        .open(&fixture.peer_policy)?;
    writeln!(
        policy,
        "\n[[grants]]\nprincipal = {PRINCIPAL:?}\noperation = \"campaign-savepoint\"\ncampaign = {CAMPAIGN:?}"
    )?;
    Ok(())
}

fn capture_and_restore(
    fixture: &FlightFixture,
    service: &mut CampaignServiceChild,
    source: &Value,
    processes: &mut process_audit::ProcessAudit,
) -> Result<(), Box<dyn Error>> {
    stage("capture-selected-guest-state");
    let head = campaign_status(fixture)?;
    let capture = run_json(
        connected_campaign(fixture).args([
            "capture-attempt",
            CAMPAIGN,
            "--snapshot",
            &json_string(&head, "snapshot")?,
            "--attempt",
            &json_string(&source["attempt"], "id")?,
            "--command",
            &"83".repeat(32),
        ]),
        "capture selected one-guest boundary",
    )?;
    let request = json_string(&capture, "request")?;
    let ready = wait_with_progress(service, "checkpoint-ready", || {
        let head = campaign_status(fixture)?;
        let report = run_json(
            connected_campaign(fixture).args([
                "capture-status",
                CAMPAIGN,
                "--snapshot",
                &json_string(&head, "snapshot")?,
                "--request",
                &request,
            ]),
            "inspect single-guest capture",
        )?;
        match report["outcome"].as_str() {
            Some("ready") => Ok(Some(report)),
            Some("pending") => Ok(None),
            _ => Err(format!("single-guest capture failed: {report}").into()),
        }
    })?;
    assert_eq!(ready["source_observation"], source["observation"]["id"]);
    assert_eq!(
        ready["reached_configuration"],
        source["observation"]["child"]
    );
    let checkpoints = guest_choice::directory_checkpoint_inspection_store(fixture)?;
    let ready_checkpoint = ExactCheckpointId::parse(&json_string(&ready, "checkpoint")?)?;
    let ready_root = checkpoints.load_attempt_checkpoint(ready_checkpoint)?;
    let raw_checkpoint = ready_root.promotion_source().unwrap_or(ready_checkpoint);
    let attempt = AttemptId::parse(&json_string(&ready, "attempt")?)?;
    let capture_scope = AttemptExecutionScope::SavepointCapture {
        request: CampaignFactId::parse(&request)?,
    };
    // Ready authenticates the captured root. Restart requires its durable
    // replay-validated replacement before shutdown cancels promotion workers.
    let mut last_runtime = None;
    let checkpoint = wait_with_progress(service, "checkpoint-promoted", || {
        // The public Ready response requires Paused; publication temporarily
        // owns CheckpointPromoting, so inspect the original scoped ledger first.
        let mut states = guest_choice::attempt_states(fixture)?
            .into_iter()
            .filter(|(key, _)| key.attempt() == attempt && key.scope() == capture_scope);
        let (_, state) = states.next().ok_or("Ready capture runtime is absent")?;
        if states.next().is_some() {
            return Err("Ready capture runtime is ambiguous".into());
        }
        last_runtime = Some(state);
        let checkpoint = match state {
            AttemptRuntimeState::Paused { checkpoint, .. } => checkpoint,
            AttemptRuntimeState::CheckpointPromoting { .. } => return Ok(None),
            _ => return Err(format!("Ready capture runtime changed: {state:?}").into()),
        };
        let Some(checkpoint) =
            matching_capture_promotion(&checkpoints, checkpoint, raw_checkpoint)?
        else {
            return Ok(None);
        };
        let head = campaign_status(fixture)?;
        let report = run_json(
            connected_campaign(fixture).args([
                "capture-status",
                CAMPAIGN,
                "--snapshot",
                &json_string(&head, "snapshot")?,
                "--request",
                &request,
            ]),
            "inspect single-guest capture promotion",
        )?;
        assert_eq!(report["outcome"], "ready");
        assert_eq!(report["attempt"], ready["attempt"]);
        assert_eq!(report["source_observation"], ready["source_observation"]);
        assert_eq!(
            report["reached_configuration"],
            ready["reached_configuration"]
        );
        assert_eq!(
            ExactCheckpointId::parse(&json_string(&report, "checkpoint")?)?,
            checkpoint
        );
        Ok(Some(checkpoint))
    })
    .map_err(|error| format!("{error}; last_capture_runtime={last_runtime:?}"))?;
    let checkpoint = checkpoint.to_string();
    println!("single_guest_saved_checkpoint={checkpoint}");
    processes.observe(service.child.id(), false)?;
    service.stop()?;
    processes.verify_cleanup()?;
    let authority = guest_choice::write_component_authority(fixture)?;
    *service = guest_choice::start_materialization_flight_service(fixture, &authority, None)?;

    stage("restore-selected-guest-state");
    let known = guest_choice::attempt_states(fixture)?.into_keys().collect();
    let head = campaign_status(fixture)?;
    let completion_stop = format!("boundary:{COMPLETION_MARKER}");
    let selected = run_json(
        connected_campaign(fixture).args([
            "select-capture",
            CAMPAIGN,
            "--snapshot",
            &json_string(&head, "snapshot")?,
            "--request",
            &request,
            "--command",
            &"84".repeat(32),
            "--stop",
            &completion_stop,
        ]),
        "select saved one-guest continuation",
    )?;
    let continuation = AttemptId::parse(&json_string(&selected, "attempt")?)?;
    let (key, restored) = wait_for_observation(
        fixture,
        service,
        &known,
        processes,
        false,
        "exact-restore-progress",
    )?;
    assert_eq!(key.attempt(), continuation);
    assert_eq!(restored["runtime"]["origin"], "selected-savepoint");
    assert_eq!(restored["runtime"]["origin_checkpoint"], checkpoint);
    assert_eq!(restored["runtime"]["source_request"], request);
    assert_eq!(restored["observation"]["stop"], "terminal-success");
    guest_choice::assert_materialization_tier(
        &guest_choice::capture_materialization_events(service)?,
        continuation,
        "ExactRestore",
    )?;
    println!("single_guest_exact_restore_authenticated=true");
    Ok(())
}

fn matching_capture_promotion(
    checkpoints: &ExactCheckpointStore,
    checkpoint: ExactCheckpointId,
    raw_checkpoint: ExactCheckpointId,
) -> Result<Option<ExactCheckpointId>, Box<dyn std::error::Error>> {
    let loaded = checkpoints.load_attempt_checkpoint(checkpoint)?;
    Ok((loaded.promotion_source() == Some(raw_checkpoint)).then_some(checkpoint))
}

fn wait_for_observation(
    fixture: &FlightFixture,
    service: &mut CampaignServiceChild,
    known: &BTreeSet<AttemptExecutionKey>,
    processes: &mut process_audit::ProcessAudit,
    hot_fork: bool,
    label: &str,
) -> Result<(AttemptExecutionKey, Value), Box<dyn Error>> {
    let pid = service.child.id();
    wait_with_progress(service, label, || {
        processes.observe(pid, hot_fork)?;
        for (key, state) in guest_choice::attempt_states(fixture)? {
            if known.contains(&key) {
                continue;
            }
            if matches!(state, AttemptRuntimeState::TerminalFailure { .. }) {
                return Err(
                    format!("single-guest attempt {} failed: {state:?}", key.attempt()).into(),
                );
            }
            if matches!(state, AttemptRuntimeState::Completed { .. }) {
                let report = guest_choice::wait_for_attempt_observation(fixture, key)?;
                return Ok(Some((key, report)));
            }
        }
        Ok(None)
    })
}

fn wait_with_progress<T>(
    service: &mut CampaignServiceChild,
    label: &str,
    mut poll: impl FnMut() -> Result<Option<T>, Box<dyn Error>>,
) -> Result<T, Box<dyn Error>> {
    stage(label);
    let started = Instant::now();
    let deadline = started + HOST_WATCHDOG;
    let mut next_progress = started;
    let observation = wait_for_process_observation(deadline, || {
        let stderr = service.stderr_tail();
        if let Some(failure) = first_execution_failure(&stderr) {
            return Err(
                format!("single-guest stage {label}: {failure}; service stderr: {stderr}").into(),
            );
        }
        if let Some(status) = service.child.try_wait()? {
            return Err(
                format!("single-guest service exited during {label}: {status}; {stderr}").into(),
            );
        }
        if let Some(value) = poll()? {
            return Ok(Some(value));
        }
        if Instant::now() >= next_progress {
            let progress = guest_progress_summary(&stderr);
            // A closed diagnostic sink must not replace the flight's actual result.
            let _write_result = writeln!(
                std::io::stderr().lock(),
                "single_guest_wait stage={label} host_elapsed_s={} guest_progress={progress}",
                started.elapsed().as_secs()
            );
            next_progress = Instant::now() + Duration::from_secs(5);
        }
        Ok(None)
    });
    if !matches!(observation, Ok(Some(_))) {
        guest_choice::report_recent_control_callback_witness(service);
    }
    let observation = observation?;
    observation.ok_or_else(|| {
        format!(
            "single-guest operational host watchdog expired during {label}; deterministic virtual budget is {VIRTUAL_BUDGET_PS}ps; stderr={}",
            service.stderr_tail()
        )
        .into()
    })
}

/// Forwards retained runtime coordinates while waiting for a guest boundary.
fn guest_progress_summary(stderr: &str) -> String {
    if let Some(boundary) = stderr.lines().rev().find(|line| {
        line.starts_with("CRUCIBLE-GUEST-SELECTABLE-BOUNDARY-V1 ")
            || line.starts_with("CRUCIBLE-EXACT-RESUME-PROGRESS-V1 ")
    }) {
        return boundary.to_owned();
    }

    // The host reporter already bounds nodes and console bytes. Limit each
    // forwarded row to 1 KiB as well; unrelated serialized records stay hidden.
    let retained_row = |prefix: &str| {
        stderr
            .lines()
            .rev()
            .find(|line| line.len() <= 1024 && line.starts_with(prefix))
    };
    let frontier = stderr.lines().rev().find(|line| {
        line.len() <= 1024
            && (line.starts_with("CRUCIBLE-RUNTIME-PROGRESS-V1 stage=after-quantum quanta=")
                || line.starts_with("CRUCIBLE-RUNTIME-PROGRESS-V1 stage=before-quantum quanta="))
    });
    let boot = retained_row("CRUCIBLE-RUNTIME-BOOT-V1 ");
    if frontier.is_none() && boot.is_none() {
        return "guest boundary not reached; runtime report unavailable".to_owned();
    }
    format!(
        "frontier_report={}; boot_report={}",
        frontier.unwrap_or("unavailable"),
        boot.unwrap_or("unavailable")
    )
}

fn first_execution_failure(stderr: &str) -> Option<&str> {
    stderr
        .lines()
        .find(|line| line.starts_with("packaged campaign execution ") && line.contains(" failed:"))
}

// The virtual policy wraps each primary stop in a proof-bearing outcome.
fn require_bounded_boundary(report: &Value, primary: &str) -> Result<(), Box<dyn Error>> {
    let stop = json_string(&report["observation"], "stop")?;
    let (frontier, quanta) = bounded_boundary_progress(&stop, primary).ok_or_else(|| {
        format!("expected successful bounded {primary} with valid progress before {VIRTUAL_BUDGET_PS}ps; observed {stop}")
    })?;
    eprintln!(
        "single_guest_boundary primary={primary} frontier_ps={frontier} completed_quanta={quanta}"
    );
    Ok(())
}

fn bounded_boundary_progress(stop: &str, primary: &str) -> Option<(u64, u64)> {
    let prefix = format!("bounded-primary-reached:{primary}:frontier-ps=");
    let (frontier, quanta) = stop.strip_prefix(&prefix)?.split_once(":quanta=")?;
    let canonical_integer = |value: &str| {
        let parsed = value.parse::<u64>().ok()?;
        (parsed.to_string() == value).then_some(parsed)
    };
    let frontier = canonical_integer(frontier)?;
    let quanta = canonical_integer(quanta)?;
    (frontier > 0 && frontier < VIRTUAL_BUDGET_PS && quanta > 0).then_some((frontier, quanta))
}

fn stage(label: &str) {
    eprintln!(
        "single_guest_stage={label} deterministic_virtual_budget_ps={VIRTUAL_BUDGET_PS} operational_host_watchdog_s={}",
        HOST_WATCHDOG.as_secs()
    );
}

#[test]
fn materialization_policy_authorizes_its_exact_savepoint_operation() -> Result<(), Box<dyn Error>> {
    use crucible_campaign::{
        CampaignAuthorizationError, CampaignHash, CampaignName, CampaignPrincipal,
        CampaignServiceOperation,
    };

    let fixture = FlightFixture::new()?;
    let principal = CampaignPrincipal::new(PRINCIPAL)?;
    let campaign = CampaignName::new(CAMPAIGN)?;
    let digest = CampaignHash::derive("single-guest-savepoint-policy-test", b"capture");
    let original = UnixPeerCampaignPolicy::from_toml_bytes(&fs::read(&fixture.peer_policy)?)?;
    assert_eq!(
        original.authorize(
            &principal,
            CampaignServiceOperation::CampaignSavepoint,
            &campaign,
            digest,
        ),
        Err(CampaignAuthorizationError::Unauthorized)
    );

    grant_savepoint_permission(&fixture)?;
    let policy = UnixPeerCampaignPolicy::from_toml_bytes(&fs::read(&fixture.peer_policy)?)?;
    policy.authorize(
        &principal,
        CampaignServiceOperation::CampaignSavepoint,
        &campaign,
        digest,
    )?;
    for (principal, operation, campaign) in [
        (
            PRINCIPAL,
            CampaignServiceOperation::CampaignSavepoint,
            "another-campaign",
        ),
        (
            "another-principal",
            CampaignServiceOperation::CampaignSavepoint,
            CAMPAIGN,
        ),
        (
            PRINCIPAL,
            CampaignServiceOperation::QueryCampaignFindings,
            CAMPAIGN,
        ),
        (PRINCIPAL, CampaignServiceOperation::DebugCampaign, CAMPAIGN),
    ] {
        assert_eq!(
            policy.authorize(
                &CampaignPrincipal::new(principal)?,
                operation,
                &CampaignName::new(campaign)?,
                digest,
            ),
            Err(CampaignAuthorizationError::Unauthorized)
        );
    }
    Ok(())
}

#[test]
fn waiting_progress_forwards_bounded_runtime_frontier_and_boot_evidence() {
    let frontier = "CRUCIBLE-RUNTIME-PROGRESS-V1 stage=after-quantum quanta=2213 frontier_ps=553189141800 pending_network_outputs=0 node_count=1 omitted_nodes=0 published_slot_status=unavailable tx_rx_counters=unavailable";
    let boot = "CRUCIBLE-RUNTIME-BOOT-V1 stage=after-quantum node=\"single\" guest_stage=setup-complete stage_icount=553125992750 setup_receipts=1 console_bytes=0 console_tail_partial=true console_tail=\"\"";
    let stderr = format!("{frontier}\n{boot}\nunrelated serialized payload\n");
    let summary = guest_progress_summary(&stderr);
    assert!(summary.contains(frontier));
    assert!(summary.contains(boot));
    assert!(!summary.contains("serialized payload"));
    assert!(summary.len() <= 2 * 1024 + 40);

    let before = frontier.replace("stage=after-quantum", "stage=before-quantum");
    let summary = guest_progress_summary(&format!("{stderr}{before}\n"));
    assert!(summary.contains(&before));
    assert!(!summary.contains(frontier));

    let boundary =
        "CRUCIBLE-GUEST-SELECTABLE-BOUNDARY-V1 stage=source-discovery attempt=synthetic-regression";
    assert_eq!(
        guest_progress_summary(&format!("{boundary}\n{stderr}")),
        boundary
    );
    let oversized = format!("CRUCIBLE-RUNTIME-BOOT-V1 {}\n", "x".repeat(1024));
    assert_eq!(
        guest_progress_summary(&oversized),
        "guest boundary not reached; runtime report unavailable"
    );
}

#[test]
fn bounded_boundary_success_preserves_primary_and_physical_progress() {
    for primary in [
        String::from("next-choice"),
        format!("boundary:{SELECTED_MARKER}"),
        format!("boundary:{COMPLETION_MARKER}"),
    ] {
        let stop =
            format!("bounded-primary-reached:{primary}:frontier-ps=553189141800:quanta=2213");
        assert_eq!(
            bounded_boundary_progress(&stop, &primary),
            Some((553_189_141_800, 2213))
        );
    }
}

#[test]
fn bounded_boundary_rejects_timeouts_wrong_primary_and_invalid_progress() {
    for stop in [
        "terminal-success",
        "reached:next-choice",
        "bounded-primary-timeout:next-choice:frontier-ps=1:quanta=1",
        "policy-timeout:VirtualTime:next-choice:frontier-ps=1:quanta=1",
        "bounded-primary-reached:boundary:single.complete:frontier-ps=1:quanta=1",
        "bounded-primary-reached:next-choice:frontier-ps=1",
        "bounded-primary-reached:next-choice:frontier-ps=:quanta=1",
        "bounded-primary-reached:next-choice:frontier-ps=1:quanta=",
        "bounded-primary-reached:next-choice:frontier-ps=+1:quanta=1",
        "bounded-primary-reached:next-choice:frontier-ps=01:quanta=1",
        "bounded-primary-reached:next-choice:frontier-ps=0:quanta=1",
        "bounded-primary-reached:next-choice:frontier-ps=1:quanta=0",
        "bounded-primary-reached:next-choice:frontier-ps=2000000000000:quanta=1",
        "bounded-primary-reached:next-choice:frontier-ps=18446744073709551616:quanta=1",
        "bounded-primary-reached:next-choice:frontier-ps=1:quanta=18446744073709551616",
        "bounded-primary-reached:next-choice:frontier-ps=1:quanta=1:extra=1",
    ] {
        assert_eq!(
            bounded_boundary_progress(stop, "next-choice"),
            None,
            "{stop}"
        );
    }
}

#[test]
fn execution_rejection_is_reported_without_waiting_for_the_watchdog() {
    let stderr = "qemu warning: feature unavailable\npackaged campaign execution abc failed: retryable execution failure: child-private copy EIO\n  caused by [1]: exact native copy refused\n";
    assert_eq!(
        first_execution_failure(stderr),
        Some(
            "packaged campaign execution abc failed: retryable execution failure: child-private copy EIO"
        )
    );
    assert!(first_execution_failure("qemu warning: feature unavailable").is_none());
}

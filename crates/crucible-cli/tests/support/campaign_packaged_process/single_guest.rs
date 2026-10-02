//! Independent one-guest execution and disk-backed materialization environments.
//!
//! Both flights use the public campaign service and the packaged QEMU/plugin.
//! The static initramfs registers real guest choices and reports their selected
//! values. Its attached small root disk still uses the production writable
//! overlay, pinned descriptors, credentials, and project quota.

use super::*;
use crucible_campaign::AttemptId;
use crucible_daemon::{AttemptExecutionKey, AttemptRuntimeState};
use crucible_session::engine::MarkerId;

#[path = "single_guest/resource_audit.rs"]
mod resource_audit;

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
    let compiled = compile_single_guest(&fixture)?;
    guest_choice::create_guest_choice_campaign_with_timeout(
        &fixture,
        &compiled,
        "qemu-11.1.1-crucible",
        Some(VIRTUAL_BUDGET_PS),
    )?;
    let authority = guest_choice::write_component_authority(&fixture)?;
    let hot_fork = materialization
        .then(|| guest_choice::materialization_flight_deployment(&fixture))
        .transpose()?;
    let mut service = guest_choice::start_materialization_flight_service(
        &fixture,
        &authority,
        hot_fork.as_deref(),
    )?;
    let mut processes = resource_audit::ProcessAudit::default();
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
    assert_eq!(discovered["observation"]["stop"], "reached:next-choice");
    if materialization {
        guest_choice::assert_materialization_tier(
            &guest_choice::capture_materialization_events(&service)?,
            discovery.attempt(),
            "HotFork",
        )?;
        processes.require_private_fork()?;
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
    let retry = choice_at(&fixture, &selected_recovery, "campaign.retry-quanta")?;

    if materialization {
        stage("retire-fork-source");
        service.stop()?;
        processes.verify_cleanup()?;
        service = guest_choice::start_materialization_flight_service(&fixture, &authority, None)?;
        assert_eq!(
            choice_at(&fixture, &selected_recovery, "campaign.retry-quanta")?,
            retry
        );
    }
    known = guest_choice::attempt_states(&fixture)?
        .into_keys()
        .collect();
    guest_choice::submit_choice(
        &fixture,
        &retry,
        "u64:7",
        if materialization {
            "boundary:single.selected"
        } else {
            "boundary:single.complete"
        },
        0x82,
    )?;
    let (selected, selection) = wait_for_observation(
        &fixture,
        &mut service,
        &known,
        &mut processes,
        false,
        "selected-guest-result",
    )?;
    assert_eq!(selection["selection"]["value"], "u64:7");
    assert_eq!(
        selection["observation"]["stop"],
        if materialization {
            "reached:boundary:single.selected"
        } else {
            "reached:boundary:single.complete"
        }
    );
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

fn capture_and_restore(
    fixture: &FlightFixture,
    service: &mut CampaignServiceChild,
    source: &Value,
    processes: &mut resource_audit::ProcessAudit,
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
    let checkpoint = json_string(&ready, "checkpoint")?;
    println!("single_guest_saved_checkpoint={checkpoint}");
    processes.observe(service.child.id(), false)?;
    service.stop()?;
    processes.verify_cleanup()?;
    let authority = guest_choice::write_component_authority(fixture)?;
    *service = guest_choice::start_materialization_flight_service(fixture, &authority, None)?;

    stage("restore-selected-guest-state");
    let known = guest_choice::attempt_states(fixture)?.into_keys().collect();
    let head = campaign_status(fixture)?;
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
            "boundary:single.complete",
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
    assert_eq!(
        restored["observation"]["stop"],
        "reached:boundary:single.complete"
    );
    guest_choice::assert_materialization_tier(
        &guest_choice::capture_materialization_events(service)?,
        continuation,
        "ExactRestore",
    )?;
    println!("single_guest_exact_restore_authenticated=true");
    Ok(())
}

fn wait_for_observation(
    fixture: &FlightFixture,
    service: &mut CampaignServiceChild,
    known: &BTreeSet<AttemptExecutionKey>,
    processes: &mut resource_audit::ProcessAudit,
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
    loop {
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
            return Ok(value);
        }
        if Instant::now() >= next_progress {
            let progress = stderr
                .lines()
                .rev()
                .find(|line| {
                    line.starts_with("CRUCIBLE-GUEST-SELECTABLE-BOUNDARY-V1 ")
                        || line.starts_with("CRUCIBLE-EXACT-RESUME-PROGRESS-V1 ")
                })
                .unwrap_or("guest boundary not reached");
            eprintln!(
                "single_guest_wait stage={label} host_elapsed_s={} guest_progress={progress}",
                started.elapsed().as_secs()
            );
            next_progress = Instant::now() + Duration::from_secs(5);
        }
        if Instant::now() >= deadline {
            return Err(format!("single-guest operational host watchdog expired during {label}; deterministic virtual budget is {VIRTUAL_BUDGET_PS}ps; stderr={stderr}").into());
        }
        std::thread::sleep(PROCESS_OBSERVATION_INTERVAL);
    }
}

fn first_execution_failure(stderr: &str) -> Option<&str> {
    stderr
        .lines()
        .find(|line| line.starts_with("packaged campaign execution ") && line.contains(" failed:"))
}

fn stage(label: &str) {
    eprintln!(
        "single_guest_stage={label} deterministic_virtual_budget_ps={VIRTUAL_BUDGET_PS} operational_host_watchdog_s={}",
        HOST_WATCHDOG.as_secs()
    );
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

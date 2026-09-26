//! Public CLI campaign lifecycle against packaged QEMU and the campaign daemon.

use super::*;

#[test]
#[ignore = "requires packaged QEMU, cgroup-v2, and ext4 project quota inside the VM check"]
fn public_packaged_campaign_lifecycle_uses_only_cli() -> Result<(), Box<dyn Error>> {
    let fixture = FlightFixture::new()?;
    let (compiled, _scenario) = compile_guest_choice_campaign(&fixture)?;
    create_guest_choice_campaign(&fixture, &compiled, "qemu-11.1.1-crucible")?;
    let steering_policy = prepare_steering_policy(&fixture, &compiled)?;
    let authority = write_component_authority(&fixture)?;
    let mut service = start_packaged_service(&fixture, &authority)?;

    let created = campaign_status(&fixture)?;
    assert_eq!(created["state"], "created");
    assert_eq!(created["semantic"]["admitted_attempts"], 0);
    let created_snapshot = json_string(&created, "snapshot")?;
    let created_report = campaign_report(&fixture, &created_snapshot)?;
    assert_eq!(created_report["explored_attempts"], 0);
    assert_eq!(created_report["unexplored_attempts"], 0);

    grant_and_start_guest_choice_campaign(&fixture)?;
    let (parent, configuration) = wait_for_public_discovery(&fixture, &mut service, &compiled)?;
    let recovery = wait_for_choice(&fixture, "network.recovery-policy", &parent, &configuration)?;
    let widened = campaign_status(&fixture)?;
    assert!(json_u64(&widened["semantic"], "admitted_attempts")? >= 1);
    assert_ne!(widened["snapshot"], created_snapshot);

    let fast = submit_choice(
        &fixture,
        &recovery,
        &format!("discrete:{FAST_ALTERNATIVE}"),
        "next-choice",
        0xa1,
    )?;
    let fast_request = accepted_branch_request(&fast)?;
    let fast_explanation = wait_for_public_request_observation(
        &fixture,
        &mut service,
        &fast_request,
        &format!("discrete:{FAST_ALTERNATIVE}"),
    )?;
    assert_eq!(
        fast_explanation["observation"]["stop"],
        "reached:next-choice"
    );
    assert_eq!(fast_explanation["proposal"]["request"], fast_request);

    let safe = submit_choice(
        &fixture,
        &recovery,
        &format!("discrete:{SAFE_ALTERNATIVE}"),
        "next-choice",
        0xa2,
    )?;
    let safe_request = accepted_branch_request(&safe)?;
    let safe_explanation = wait_for_public_request_observation(
        &fixture,
        &mut service,
        &safe_request,
        &format!("discrete:{SAFE_ALTERNATIVE}"),
    )?;
    assert_eq!(
        safe_explanation["observation"]["stop"],
        "reached:next-choice"
    );
    assert_eq!(safe_explanation["proposal"]["request"], safe_request);

    let finite = submit_all_choices(&fixture, &recovery)?;
    assert_eq!(finite["validated_cardinality"]["count"], 2);
    assert_eq!(finite["deduplicated_existing_edges"]["count"], 2);
    assert_eq!(finite["remaining_lazy_candidates"]["count"], 0);

    let running = campaign_status(&fixture)?;
    let running_snapshot = json_string(&running, "snapshot")?;
    let running_report = campaign_report(&fixture, &running_snapshot)?;
    assert!(json_u64(&running_report, "explored_attempts")? >= 3);
    run_json(
        connected_campaign(&fixture).args([
            "pause",
            CAMPAIGN,
            "--expected",
            &running_snapshot,
            "--command",
            &"a3".repeat(32),
            "--active",
            "drain",
        ]),
        "pause public campaign after finite branches",
    )?;
    let paused = campaign_status(&fixture)?;
    assert_eq!(paused["state"], "paused");
    let paused_snapshot = json_string(&paused, "snapshot")?;
    service.stop()?;

    let mut restarted = start_packaged_service(&fixture, &authority)?;
    let reopened = campaign_status(&fixture)?;
    assert_eq!(reopened["state"], "paused");
    assert_eq!(reopened["snapshot"], paused_snapshot);
    run_json(
        connected_campaign(&fixture).args([
            "resume",
            CAMPAIGN,
            "--expected",
            &paused_snapshot,
            "--command",
            &"a4".repeat(32),
        ]),
        "resume public campaign after service restart",
    )?;
    assert_eq!(campaign_status(&fixture)?["state"], "running");

    let safe_parent = json_string(&safe_explanation["observation"], "child_artifact")?;
    let safe_configuration = json_string(&safe_explanation["observation"], "child")?;
    let retry = wait_for_choice(
        &fixture,
        "network.retry-quanta",
        &safe_parent,
        &safe_configuration,
    )?;
    let resumed = campaign_status(&fixture)?;
    run_json(
        connected_campaign(&fixture).args([
            "pause",
            CAMPAIGN,
            "--expected",
            &json_string(&resumed, "snapshot")?,
            "--command",
            &"a5".repeat(32),
            "--active",
            "drain",
        ]),
        "pause resumed campaign before bounded expansion",
    )?;
    assert_eq!(campaign_status(&fixture)?["state"], "paused");

    let pressured = submit_bounded_choices(&fixture, &retry)?;
    assert_eq!(pressured["budget"]["maximum_proposals"], 3);
    assert_eq!(pressured["budget"]["maximum_attempts"], 1);
    assert_eq!(pressured["validated_cardinality"]["count"], 3);
    assert!(acceptance_count_minimum(&pressured["remaining_lazy_candidates"])? >= 1);
    let pressure_request = accepted_branch_request(&pressured)?;
    let pressure_paused = campaign_status(&fixture)?;
    run_json(
        connected_campaign(&fixture).args([
            "resume",
            CAMPAIGN,
            "--expected",
            &json_string(&pressure_paused, "snapshot")?,
            "--command",
            &"a9".repeat(32),
        ]),
        "release one bounded campaign attempt",
    )?;
    let pressure_explanation =
        wait_for_public_request_observation(&fixture, &mut restarted, &pressure_request, "u64:1")?;
    assert_eq!(
        pressure_explanation["observation"]["stop"],
        "terminal-success"
    );
    let pressure_running = campaign_status(&fixture)?;
    run_json(
        connected_campaign(&fixture).args([
            "pause",
            CAMPAIGN,
            "--expected",
            &json_string(&pressure_running, "snapshot")?,
            "--command",
            &"aa".repeat(32),
            "--active",
            "drain",
        ]),
        "pause after one budgeted campaign attempt",
    )?;

    let before_steer = campaign_status(&fixture)?;
    assert_eq!(before_steer["state"], "paused");
    let steered = run_json(
        connected_campaign(&fixture).args([
            "steer",
            CAMPAIGN,
            "--expected",
            &json_string(&before_steer, "snapshot")?,
            "--command",
            &"a6".repeat(32),
            "--policy",
            &steering_policy,
        ]),
        "steer paused campaign to a compatible imported policy",
    )?;
    assert_eq!(steered["operation"], "steer");
    let after_steer = campaign_status(&fixture)?;
    assert_eq!(after_steer["state"], "paused");
    assert_eq!(after_steer["policy"], steering_policy);

    let stopped = run_json(
        connected_campaign(&fixture).args([
            "stop",
            CAMPAIGN,
            "--expected",
            &json_string(&after_steer, "snapshot")?,
            "--command",
            &"a7".repeat(32),
        ]),
        "gracefully complete public campaign",
    )?;
    assert_eq!(stopped["operation"], "stop");
    let completed = campaign_status(&fixture)?;
    assert_eq!(completed["state"], "completed");
    let completed_report = campaign_report(&fixture, &json_string(&completed, "snapshot")?)?;
    assert!(json_u64(&completed_report, "explored_attempts")? >= 4);
    restarted.stop()?;

    println!("campaign_lifecycle_lazy_widening=true");
    println!("campaign_lifecycle_finite_branch_deduplication=true");
    println!("campaign_lifecycle_live_status_explanation=true");
    println!("campaign_lifecycle_bounded_pressure=true");
    println!("campaign_lifecycle_pause_restart_resume=true");
    println!("campaign_lifecycle_steering_graceful_stop=true");
    Ok(())
}

fn prepare_steering_policy(
    fixture: &FlightFixture,
    compiled: &Value,
) -> Result<String, Box<dyn Error>> {
    let root = fixture._temporary.path();
    let original_policy = fs::read_to_string(root.join("guest-choice-policy.toml"))?;
    let changed_policy =
        original_policy.replace("breadth_first_percent = 0", "breadth_first_percent = 100");
    assert_ne!(original_policy, changed_policy);
    let steering_input = root.join("steering-policy.toml");
    let steering_policy = root.join("steering-policy.bin");
    fs::write(&steering_input, changed_policy)?;
    run_json(
        command(&["--format", "jsonl", "campaign", "policy", "compile"])
            .arg(&steering_input)
            .arg("--output")
            .arg(&steering_policy),
        "compile compatible steering policy",
    )?;

    // Derivation publishes the policy through the public service without
    // changing the source campaign's current snapshot or execution state.
    let manifest = json_path(compiled, "manifest")?;
    let mut service = fixture.start_service(Some(&manifest))?;
    let source = campaign_status(fixture)?;
    let derived = run_json(
        connected_campaign(fixture)
            .args([
                "derive",
                CAMPAIGN,
                "--snapshot",
                &json_string(&source, "snapshot")?,
                "steering-policy-source",
                "--policy",
            ])
            .arg(&steering_policy),
        "import steering policy through campaign derivation",
    )?;
    let policy_id = json_string(&derived, "active_policy")?;
    assert_ne!(policy_id, json_string(&source, "policy")?);
    service.stop()?;
    Ok(policy_id)
}

fn wait_for_public_discovery(
    fixture: &FlightFixture,
    service: &mut CampaignServiceChild,
    compiled: &Value,
) -> Result<(String, String), Box<dyn Error>> {
    let genesis = json_string(compiled, "genesis_artifact")?;
    let deadline = Instant::now() + Duration::from_secs(900);
    wait_for_process_observation(deadline, || {
        if let Some(status) = service.child.try_wait()? {
            return Err(format!("campaign service exited before discovery: {status}").into());
        }
        let head = campaign_status(fixture)?;
        if json_u64(&head["semantic"], "admitted_attempts")? == 0 {
            return Ok(None);
        }
        let snapshot = json_string(&head, "snapshot")?;
        let graph_output = connected_campaign(fixture)
            .args([
                "graph",
                CAMPAIGN,
                "--snapshot",
                &snapshot,
                "--limit",
                "256",
                "--pages",
                "16",
            ])
            .output()?;
        if is_stale_snapshot_response(&graph_output) {
            return Ok(None);
        }
        let graph = parse_json_output(graph_output, "scan public discovery graph")?;
        assert_eq!(graph["complete"], true);
        let entries = graph["entries"]
            .as_array()
            .ok_or("public graph omitted entries")?;
        let mut discovered = None;
        for entry in entries {
            let key = json_string(entry, "key")?;
            let object_output = connected_campaign(fixture)
                .args([
                    "graph-object",
                    CAMPAIGN,
                    "--snapshot",
                    &snapshot,
                    "--key",
                    &key,
                ])
                .output()?;
            if is_stale_snapshot_response(&object_output) {
                return Ok(None);
            }
            let object = parse_json_output(object_output, "inspect public graph object")?;
            let object = &object["object"];
            if object["kind"] != "configuration" || object["object"] == genesis {
                continue;
            }
            let candidate = (
                json_string(object, "object")?,
                json_string(object, "configuration")?,
            );
            if discovered.replace(candidate).is_some() {
                return Err("public discovery produced multiple child configurations".into());
            }
        }
        Ok(discovered)
    })?
    .ok_or_else(|| "public discovery did not publish a child configuration".into())
}

fn wait_for_public_request_observation(
    fixture: &FlightFixture,
    service: &mut CampaignServiceChild,
    request: &str,
    value: &str,
) -> Result<Value, Box<dyn Error>> {
    let deadline = Instant::now() + GUEST_CHOICE_ATTEMPT_WAIT;
    wait_for_process_observation(deadline, || {
        if let Some(status) = service.child.try_wait()? {
            return Err(
                format!("campaign service exited before request {request}: {status}").into(),
            );
        }
        let head = campaign_status(fixture)?;
        let snapshot = json_string(&head, "snapshot")?;
        let page_output = connected_campaign(fixture)
            .args([
                "request-attempts",
                CAMPAIGN,
                "--snapshot",
                &snapshot,
                "--request",
                request,
                "--pages",
                "16",
            ])
            .output()?;
        if is_stale_snapshot_response(&page_output) {
            return Ok(None);
        }
        let page = parse_json_output(page_output, "read public request attempts")?;
        assert_eq!(page["complete"], true);
        let entries = page["entries"]
            .as_array()
            .ok_or("public request-attempt page omitted entries")?;
        if entries.len() > 1 {
            return Err(format!(
                "one-attempt request {request} admitted {} attempts",
                entries.len()
            )
            .into());
        }
        for entry in entries {
            assert_eq!(entry["request"], request);
            assert_eq!(entry["value"], value);
            let attempt = json_string(entry, "attempt")?;
            let explanation_output = connected_campaign(fixture)
                .args([
                    "explain-attempt",
                    CAMPAIGN,
                    "--snapshot",
                    &snapshot,
                    "--attempt",
                    &attempt,
                ])
                .output()?;
            if is_stale_snapshot_response(&explanation_output) {
                return Ok(None);
            }
            let explanation =
                parse_json_output(explanation_output, "explain public request attempt")?;
            if !explanation["observation"].is_null()
                && explanation["runtime"]["phase"] == "completed"
            {
                return Ok(Some(explanation));
            }
        }
        Ok(None)
    })?
    .ok_or_else(|| format!("request {request} did not publish a public observation").into())
}

fn submit_all_choices(
    fixture: &FlightFixture,
    choice: &PublicChoice,
) -> Result<Value, Box<dyn Error>> {
    for _ in 0..MAX_STALE_BRANCH_RETRIES {
        let head = campaign_status(fixture)?;
        let output = connected_campaign(fixture)
            .args([
                "branch",
                CAMPAIGN,
                "--expected",
                &json_string(&head, "snapshot")?,
                "--branch-point",
                &choice.branch_point,
                "--parent",
                &choice.parent,
                "--opportunity",
                &choice.opportunity,
                "--domain",
                &choice.domain,
                "--all",
                "--attempts",
                "1",
                "--stop",
                "next-choice",
            ])
            .output()?;
        if is_stale_snapshot_response(&output) {
            continue;
        }
        return parse_json_output(output, "submit authenticated finite domain");
    }

    Err("finite branch remained stale across bounded snapshot reads".into())
}

fn submit_bounded_choices(
    fixture: &FlightFixture,
    choice: &PublicChoice,
) -> Result<Value, Box<dyn Error>> {
    for _ in 0..MAX_STALE_BRANCH_RETRIES {
        let head = campaign_status(fixture)?;
        let output = connected_campaign(fixture)
            .args([
                "branch",
                CAMPAIGN,
                "--expected",
                &json_string(&head, "snapshot")?,
                "--command",
                &"a8".repeat(32),
                "--branch-point",
                &choice.branch_point,
                "--parent",
                &choice.parent,
                "--opportunity",
                &choice.opportunity,
                "--domain",
                &choice.domain,
                "--value",
                "u64:1",
                "--value",
                "u64:3",
                "--value",
                "u64:5",
                "--proposals",
                "3",
                "--attempts",
                "1",
                "--stop",
                "terminal",
            ])
            .output()?;
        if is_stale_snapshot_response(&output) {
            continue;
        }
        return parse_json_output(output, "submit bounded finite branch");
    }

    Err("bounded branch remained stale across bounded snapshot reads".into())
}

fn acceptance_count_minimum(count: &Value) -> Result<u64, Box<dyn Error>> {
    match count["kind"].as_str() {
        Some("exact") => json_u64(count, "count"),
        Some("range") => json_u64(count, "minimum"),
        _ => Err(format!("branch acceptance omitted a bounded count: {count}").into()),
    }
}

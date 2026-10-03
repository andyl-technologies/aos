//! Public CLI campaign lifecycle against packaged QEMU and the campaign daemon.

use super::*;
use crucible_cas::content_store::{ContentId, ObjectKind};

// A fresh packaged realization must boot to its authenticated selectable.
// The previous 90-second host wait reached only 203 ms of virtual time;
// source discovery on the same clock reaches its marker near 555 ms.
const LIFECYCLE_SELECTABLE_WAIT: Duration = Duration::from_secs(600);

// Cold replay of one guest-choice branch takes 341-400 host seconds on TCG.
const LIFECYCLE_BRANCH_OBSERVATION_WAIT: Duration = Duration::from_secs(600);

// The public service classifies Unavailable as retryable after bounded backoff.
const LIFECYCLE_ALL_BRANCH_RETRY_WAIT: Duration = Duration::from_secs(60);
const LIFECYCLE_ALL_BRANCH_RETRY_BACKOFF: Duration = Duration::from_millis(250);

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
    // Initial NextChoice discovers an opportunity on the genesis configuration;
    // a distinct child artifact is not published until a branch is selected.
    let (parent, configuration) = wait_for_public_genesis(&fixture, &mut service, &compiled)?;
    let recovery = wait_for_choice_with_timeout(
        &fixture,
        "network.recovery-policy",
        &parent,
        &configuration,
        LIFECYCLE_SELECTABLE_WAIT,
    )?;
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
    let retry = wait_for_choice_with_timeout(
        &fixture,
        "network.retry-quanta",
        &safe_parent,
        &safe_configuration,
        LIFECYCLE_SELECTABLE_WAIT,
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

fn wait_for_public_genesis(
    fixture: &FlightFixture,
    service: &mut CampaignServiceChild,
    compiled: &Value,
) -> Result<(String, String), Box<dyn Error>> {
    let genesis = json_string(compiled, "genesis_artifact")?;
    let genesis_id = crucible_campaign::ConfigurationArtifactId::parse(&genesis)?;
    let genesis_configuration = json_string(compiled, "genesis")?;
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
        let mut found_genesis = false;
        let mut choice_index_anchors = 0;
        for entry in entries {
            if is_choice_index_anchor(entry)? {
                choice_index_anchors += 1;
                continue;
            }
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
            if object["kind"] != "configuration"
                || object["object"] != genesis_id.content_id().to_string()
            {
                continue;
            }
            if found_genesis {
                return Err("public graph repeated the genesis configuration".into());
            }
            assert_eq!(json_string(object, "configuration")?, genesis_configuration);
            found_genesis = true;
        }
        assert_eq!(choice_index_anchors, 1);
        Ok(found_genesis.then(|| (genesis.clone(), genesis_configuration.clone())))
    })?
    .ok_or_else(|| "public graph did not authenticate the genesis configuration".into())
}

fn is_choice_index_anchor(entry: &Value) -> Result<bool, Box<dyn Error>> {
    let key = CampaignHash::parse(&json_string(entry, "key")?)?;
    let object = ContentId::parse(&json_string(entry, "object")?)?;
    let anchor = CampaignHash::derive("crucible.campaign-graph-choice-index.v1", b"");
    let is_anchor = key == anchor;

    // QueryGraph proves the complete Merkle page, including its internal index
    // anchor. GraphObject only exposes configuration and opportunity envelopes.
    if is_anchor != (object.kind() == ObjectKind::MerkleNode) {
        return Err("public graph choice-index anchor has an unexpected key or object kind".into());
    }
    Ok(is_anchor)
}

#[test]
fn public_graph_object_selection_skips_only_the_choice_index_anchor() -> Result<(), Box<dyn Error>>
{
    let anchor = CampaignHash::derive("crucible.campaign-graph-choice-index.v1", b"");
    let other_key = CampaignHash::derive("crucible.test-public-graph-key.v1", b"");
    let merkle = ContentId::for_bytes(ObjectKind::MerkleNode, 1, b"index");
    let configuration = ContentId::for_bytes(ObjectKind::Configuration, 1, b"configuration");

    let anchor_entry = serde_json::json!({ "key": anchor.to_hex(), "object": merkle.encode() });
    let public_entry =
        serde_json::json!({ "key": other_key.to_hex(), "object": configuration.encode() });
    let wrong_anchor =
        serde_json::json!({ "key": anchor.to_hex(), "object": configuration.encode() });
    let unexpected_index =
        serde_json::json!({ "key": other_key.to_hex(), "object": merkle.encode() });

    assert!(is_choice_index_anchor(&anchor_entry)?);
    assert!(!is_choice_index_anchor(&public_entry)?);
    assert!(is_choice_index_anchor(&wrong_anchor).is_err());
    assert!(is_choice_index_anchor(&unexpected_index).is_err());
    Ok(())
}

fn wait_for_public_request_observation(
    fixture: &FlightFixture,
    service: &mut CampaignServiceChild,
    request: &str,
    value: &str,
) -> Result<Value, Box<dyn Error>> {
    let deadline = Instant::now() + LIFECYCLE_BRANCH_OBSERVATION_WAIT;
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
    retry_finite_branch_submission(
        || json_string(&campaign_status(fixture)?, "snapshot"),
        |snapshot| {
            Ok(connected_campaign(fixture)
                .args([
                    "branch",
                    CAMPAIGN,
                    "--expected",
                    snapshot,
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
                .output()?)
        },
        LIFECYCLE_ALL_BRANCH_RETRY_WAIT,
        LIFECYCLE_ALL_BRANCH_RETRY_BACKOFF,
    )
}

fn retry_finite_branch_submission(
    mut read_snapshot: impl FnMut() -> Result<String, Box<dyn Error>>,
    mut submit: impl FnMut(&str) -> Result<std::process::Output, Box<dyn Error>>,
    wait: Duration,
    backoff: Duration,
) -> Result<Value, Box<dyn Error>> {
    let deadline = Instant::now() + wait;
    let mut snapshot = read_snapshot()?;
    let mut stale_retries = 0;
    let mut last_unavailable = None;

    loop {
        // The CLI response is the readiness signal. Retain the last unavailable
        // response so a timeout reports the service's actual failure.
        let output = wait_for_process_observation_with_interval(deadline, backoff, || {
            let output = submit(&snapshot)?;
            if is_finite_branch_temporarily_unavailable(&output) {
                // The canonical request and snapshot stay fixed across retries;
                // an already accepted request returns its prior result.
                last_unavailable = Some(output);
                return Ok(None);
            }
            Ok(Some(output))
        })?
        .or_else(|| last_unavailable.take())
        .ok_or("finite branch retry ended without a service response")?;

        if is_stale_snapshot_response(&output) {
            stale_retries += 1;
            if stale_retries == MAX_STALE_BRANCH_RETRIES {
                return Err("finite branch remained stale across bounded snapshot reads".into());
            }
            snapshot = read_snapshot()?;
            continue;
        }

        return parse_json_output(output, "submit authenticated finite domain");
    }
}

fn is_finite_branch_temporarily_unavailable(output: &std::process::Output) -> bool {
    output.status.code() == Some(4)
        && String::from_utf8_lossy(&output.stderr).trim_end()
            == "crucible: campaign branch failed: campaign service is temporarily unavailable"
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

#[cfg(test)]
mod retry_tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;

    fn output(status: i32, stdout: &str, stderr: &str) -> std::process::Output {
        std::process::Output {
            status: std::process::ExitStatus::from_raw(status << 8),
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    #[test]
    fn finite_branch_retries_unavailable_with_same_snapshot() {
        let mut snapshots = 0;
        let mut submitted = Vec::new();
        let result = retry_finite_branch_submission(
            || {
                snapshots += 1;
                Ok("snapshot-a".to_owned())
            },
            |snapshot| {
                submitted.push(snapshot.to_owned());
                Ok(if submitted.len() == 1 {
                    output(
                        4,
                        "",
                        "crucible: campaign branch failed: campaign service is temporarily unavailable\n",
                    )
                } else {
                    output(0, "{\"accepted\":true}\n", "")
                })
            },
            Duration::from_secs(1),
            Duration::ZERO,
        )
        .expect("bounded unavailable retry should recover");

        assert_eq!(result["accepted"], true);
        assert_eq!(snapshots, 1);
        assert_eq!(submitted, ["snapshot-a", "snapshot-a"]);
    }

    #[test]
    fn finite_branch_refreshes_snapshot_only_after_stale_response() {
        let mut snapshots = 0;
        let mut submitted = Vec::new();
        let result = retry_finite_branch_submission(
            || {
                snapshots += 1;
                Ok(format!("snapshot-{snapshots}"))
            },
            |snapshot| {
                submitted.push(snapshot.to_owned());
                Ok(match submitted.len() {
                    1 => output(
                        4,
                        "",
                        "crucible: campaign branch failed: campaign service is temporarily unavailable\n",
                    ),
                    2 => output(
                        4,
                        "",
                        "crucible: campaign branch failed: campaign request used stale snapshot\n",
                    ),
                    _ => output(0, "{\"accepted\":true}\n", ""),
                })
            },
            Duration::from_secs(1),
            Duration::ZERO,
        )
        .expect("explicit stale response should refresh the snapshot");

        assert_eq!(result["accepted"], true);
        assert_eq!(snapshots, 2);
        assert_eq!(submitted, ["snapshot-1", "snapshot-1", "snapshot-2"]);
    }

    #[test]
    fn finite_branch_preserves_persistent_unavailable_response() {
        let mut submissions = 0;
        let error = retry_finite_branch_submission(
            || Ok("snapshot-a".to_owned()),
            |_| {
                submissions += 1;
                Ok(output(
                    4,
                    "last response",
                    "crucible: campaign branch failed: campaign service is temporarily unavailable\n",
                ))
            },
            Duration::from_millis(30),
            Duration::from_millis(1),
        )
        .expect_err("persistent unavailable must fail after the bound");

        assert!(submissions > 1);
        assert!(error.to_string().contains("stdout=`last response`"));
        assert!(error
            .to_string()
            .contains("campaign service is temporarily unavailable"));
    }

    #[test]
    fn finite_branch_does_not_retry_other_failures() {
        let mut submissions = 0;
        let error = retry_finite_branch_submission(
            || Ok("snapshot-a".to_owned()),
            |_| {
                submissions += 1;
                Ok(output(
                    4,
                    "",
                    "crucible: campaign branch failed: integrity error\n",
                ))
            },
            Duration::from_secs(1),
            Duration::ZERO,
        )
        .expect_err("non-transient failure must fail immediately");

        assert_eq!(submissions, 1);
        assert!(error.to_string().contains("integrity error"));
    }
}

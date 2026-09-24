//! Five-node Envoy campaign flight through the public fixture and campaign CLI.

use super::*;
use crucible_campaign::{
    AlternativeId, Attempt, AttemptId, AttemptStart, BranchPath, CampaignHash, CampaignLineage,
    CampaignPolicy, ChoiceDomain, ChoiceTuple, ChoiceValue, StopCondition,
};
use crucible_core::NetworkFaultSelectable;

const ATTEMPT_WAIT: Duration = Duration::from_secs(600);
const WITHDRAW_THEN_RELEARN: [u8; 32] = [0x22; 32];
const RETAIN_AND_PROBE: [u8; 32] = [0x11; 32];

struct FlightProgress {
    parent: String,
    configuration: String,
}

#[test]
#[ignore = "requires packaged QEMU and a dedicated five-guest cgroup and project quota"]
fn public_five_node_envoy_network_reaches_measured_failover() -> Result<(), Box<dyn Error>> {
    let fixture = FlightFixture::new()?;
    let kernel = required_path("CRUCIBLE_KERNEL")?;
    let root_image = required_path("CRUCIBLE_ROOT_IMAGE")?;
    let generated = run_json(
        command(&[
            "--format",
            "jsonl",
            "campaign",
            "fixture",
            "worked-network",
            "--output",
        ])
        .arg(&fixture.fixture)
        .arg("--kernel")
        .arg(&kernel)
        .arg("--root-image")
        .arg(&root_image)
        .arg("--qemu")
        .arg(required_path("CRUCIBLE_FLIGHT_QEMU")?)
        .arg("--plugin")
        .arg(required_path("CRUCIBLE_FLIGHT_PLUGIN")?),
        "materialize the five-node Envoy fixture",
    )?;
    let manifest = json_path(&generated, "manifest")?;
    // The exported scenario supplies the exact guest group identity; all
    // campaign reads and mutations below still go through the public CLI.
    let scenario =
        ScenarioDefForm::from_compact_binary(&fs::read(fixture.fixture.join("scenario.bin"))?)?;
    let fault_declaration = scenario
        .selectables()
        .declaration("fault.network")
        .ok_or("Envoy scenario omits fault.network")?;
    assert_eq!(fault_declaration, &NetworkFaultSelectable::declaration()?);
    let fault = group_argument(NetworkFaultSelectable::selected_value(
        "link_down",
        "primary",
        30_000_000,
        0,
        0,
    )?);
    let recovery = recovery_argument(&scenario, WITHDRAW_THEN_RELEARN)?;
    let followup_fault = group_argument(NetworkFaultSelectable::selected_value(
        "packet_loss",
        "backup",
        10_000_000,
        1_000,
        0,
    )?);
    let followup_recovery = recovery_argument(&scenario, RETAIN_AND_PROBE)?;
    let lineage = json_path(&generated, "lineage")?;
    let policy = compile_bounded_policy(&fixture, &generated)?;
    println!("envoy_five_node_fixture={generated}");

    let mut importer = fixture.start_service(Some(&manifest))?;
    run_json(
        connected_campaign(&fixture)
            .args(["create", CAMPAIGN, "--lineage"])
            .arg(&lineage)
            .arg("--policy")
            .arg(&policy),
        "create imported five-node campaign",
    )?;
    importer.stop()?;

    let authority = component_authority(&fixture)?;
    let mut service = start_packaged_network_service(&fixture, &authority)?;
    let initial = campaign_status(&fixture)?;
    run_json(
        connected_campaign(&fixture)
            .args([
                "budget",
                CAMPAIGN,
                "--expected",
                &json_string(&initial, "snapshot")?,
                "--command",
            ])
            .arg("71".repeat(32))
            .args(["add", "12", "--proposals", "12"]),
        "grant bounded five-node campaign budget",
    )?;
    let budgeted = campaign_status(&fixture)?;
    run_json(
        connected_campaign(&fixture)
            .args([
                "start",
                CAMPAIGN,
                "--expected",
                &json_string(&budgeted, "snapshot")?,
                "--command",
            ])
            .arg("72".repeat(32)),
        "start five-node campaign",
    )?;

    let genesis = json_string(&generated, "configuration")?;
    let discovery_attempt = initial_discovery_attempt(&lineage, &policy)?;
    let discovery = wait_for_public_attempt(
        &fixture,
        &mut service,
        discovery_attempt,
        Duration::from_secs(900),
    )?;
    assert_eq!(discovery["attempt"]["configuration"], genesis);
    assert_eq!(discovery["observation"]["stop"], "reached:next-choice");
    println!("envoy_five_node_baseline={discovery}");

    let mut progress = FlightProgress {
        parent: json_string(&discovery["observation"], "child_artifact")?,
        configuration: json_string(&discovery["observation"], "child")?,
    };

    let disruption = choose(
        &fixture,
        &mut service,
        &mut progress,
        "fault.network",
        &fault,
        "next-choice",
        0x73,
    )?;
    let pending_recovery = guest_choice::wait_for_choice(
        &fixture,
        "recovery.response",
        &progress.parent,
        &progress.configuration,
    )?;
    service.stop()?;
    service = start_packaged_network_service(&fixture, &authority)?;
    let requeried_recovery = guest_choice::wait_for_choice(
        &fixture,
        "recovery.response",
        &progress.parent,
        &progress.configuration,
    )?;
    assert_eq!(requeried_recovery, pending_recovery);
    let response = choose_known(
        &fixture,
        &mut service,
        &mut progress,
        &requeried_recovery,
        &recovery,
        "next-choice",
        0x74,
    )?;
    require_network_effect(
        &[&disruption, &response],
        "availability",
        &["segment-router-a-router-b", "segment-router-b-router-c"],
        Some("down"),
    )?;
    require_semantic_marker(&response, "fault.transport.primary-probed", "router-a")?;
    require_semantic_marker(&response, "network.failover.observed", "traffic-west")?;
    require_measured_backup_route(&response)?;
    println!("envoy_five_node_failover_response={response}");

    let followup_disruption = choose(
        &fixture,
        &mut service,
        &mut progress,
        "fault.network",
        &followup_fault,
        "next-choice",
        0x75,
    )?;
    let completion = choose(
        &fixture,
        &mut service,
        &mut progress,
        "recovery.response",
        &followup_recovery,
        "boundary:campaign.complete",
        0x76,
    )?;
    require_network_effect(
        &[&followup_disruption, &completion],
        "frame-loss",
        &["segment-router-a-router-c"],
        None,
    )?;
    require_semantic_marker(&completion, "fault.followup.primary-probed", "router-a")?;
    require_semantic_marker(&completion, "campaign.complete", "traffic-west")?;
    println!("envoy_five_node_completion={completion}");

    prove_pending_recovery_exact_replay(&fixture, &mut service, &disruption, &requeried_recovery)?;
    println!("envoy_five_node_failover_and_recovery_authenticated=true");

    let status = campaign_status(&fixture)?;
    assert_eq!(status["state"], "running");
    service.stop()?;
    Ok(())
}

fn group_argument(value: ChoiceValue) -> String {
    assert!(matches!(value, ChoiceValue::Group(_)));
    format!("group:{}", hex::encode(value.canonical_bytes()))
}

#[test]
fn typed_fault_group_argument_uses_cli_canonical_encoding() -> Result<(), Box<dyn Error>> {
    let selected =
        NetworkFaultSelectable::selected_value("link_down", "primary", 30_000_000, 0, 0)?;
    let argument = group_argument(selected.clone());
    let encoded = argument
        .strip_prefix("group:")
        .ok_or("missing group prefix")?;

    assert_eq!(
        ChoiceValue::from_canonical_bytes(&hex::decode(encoded)?)?,
        selected
    );
    Ok(())
}

fn recovery_argument(
    scenario: &ScenarioDefForm,
    strategy: [u8; 32],
) -> Result<String, Box<dyn Error>> {
    let declaration = scenario
        .selectables()
        .declaration("recovery.response")
        .ok_or("Envoy scenario omits recovery.response")?;
    let ChoiceDomain::Group(group) = declaration.domain() else {
        return Err("Envoy recovery.response is not a group".into());
    };
    let ChoiceValue::Group(default) = declaration.default() else {
        return Err("Envoy recovery.response default is not a group".into());
    };
    default.validate_resolved(group)?;

    let strategy_id = group
        .declarations()
        .iter()
        .find(|(_, member)| member.name() == "recovery.strategy")
        .map(|(id, _)| *id)
        .ok_or("Envoy recovery.response omits recovery.strategy")?;
    let mut values = default.tuple().values().clone();
    values.insert(
        strategy_id,
        ChoiceValue::Discrete(AlternativeId::from_hash(CampaignHash::from_bytes(strategy))),
    );
    Ok(group_argument(ChoiceValue::Group(
        group.select(ChoiceTuple::new(values))?,
    )))
}

fn choose(
    fixture: &FlightFixture,
    service: &mut CampaignServiceChild,
    progress: &mut FlightProgress,
    name: &str,
    value: &str,
    stop: &str,
    command_byte: u8,
) -> Result<Value, Box<dyn Error>> {
    let choice =
        guest_choice::wait_for_choice(fixture, name, &progress.parent, &progress.configuration)?;
    choose_known(
        fixture,
        service,
        progress,
        &choice,
        value,
        stop,
        command_byte,
    )
}

fn choose_known(
    fixture: &FlightFixture,
    service: &mut CampaignServiceChild,
    progress: &mut FlightProgress,
    choice: &guest_choice::PublicChoice,
    value: &str,
    stop: &str,
    command_byte: u8,
) -> Result<Value, Box<dyn Error>> {
    let submission = guest_choice::submit_choice(fixture, choice, value, stop, command_byte)?;
    let request = guest_choice::accepted_branch_request(&submission)?;
    let explanation = wait_for_request_attempt(fixture, service, &request, value, ATTEMPT_WAIT)?;
    assert_eq!(
        explanation["observation"]["stop"],
        format!("reached:{stop}")
    );
    println!("envoy_five_node_choice={explanation}");

    if stop == "next-choice" {
        progress.parent = json_string(&explanation["observation"], "child_artifact")?;
        progress.configuration = json_string(&explanation["observation"], "child")?;
    }
    Ok(explanation)
}

fn prove_pending_recovery_exact_replay(
    fixture: &FlightFixture,
    service: &mut CampaignServiceChild,
    disruption: &Value,
    pending_recovery: &guest_choice::PublicChoice,
) -> Result<(), Box<dyn Error>> {
    let source_observation = json_string(&disruption["observation"], "id")?;
    let source_configuration = json_string(&disruption["observation"], "child")?;
    let source_parent = json_string(&disruption["observation"], "child_artifact")?;
    let attempt = json_string(&disruption["attempt"], "id")?;
    let current_choice = guest_choice::wait_for_choice(
        fixture,
        "recovery.response",
        &source_parent,
        &source_configuration,
    )?;
    assert_eq!(&current_choice, pending_recovery);

    let head = campaign_status(fixture)?;
    let capture = run_json(
        connected_campaign(fixture)
            .args([
                "capture-attempt",
                CAMPAIGN,
                "--snapshot",
                &json_string(&head, "snapshot")?,
                "--attempt",
                &attempt,
                "--command",
            ])
            .arg("77".repeat(32)),
        "request exact Envoy pending-choice capture",
    )?;
    assert_eq!(capture["schema"], "crucible.cli.campaign-savepoint.v1");
    assert_eq!(capture["operation"], "capture-attempt");
    let request = json_string(&capture, "request")?;
    let ready = wait_for_capture_ready(fixture, service, &request)?;
    assert_eq!(ready["attempt"], attempt);
    assert_eq!(ready["source_observation"], source_observation);
    assert_eq!(ready["reached_configuration"], source_configuration);
    let checkpoint = json_string(&ready, "checkpoint")?;

    let head = campaign_status(fixture)?;
    let selected = run_json(
        connected_campaign(fixture)
            .args([
                "select-capture",
                CAMPAIGN,
                "--snapshot",
                &json_string(&head, "snapshot")?,
                "--request",
                &request,
                "--command",
            ])
            .arg("78".repeat(32))
            .args(["--stop", "boundary:campaign.complete"]),
        "select exact Envoy pending-choice continuation",
    )?;
    assert_eq!(selected["schema"], "crucible.cli.campaign-savepoint.v1");
    assert_eq!(selected["operation"], "select-capture");
    assert_eq!(selected["request"], request);
    let continuation = AttemptId::parse(&json_string(&selected, "attempt")?)?;
    let restored = wait_for_public_completed_attempt(fixture, service, continuation)?;
    assert_eq!(restored["attempt"]["start"], "after-attempt");
    assert_eq!(restored["attempt"]["origin"], attempt);
    assert_eq!(restored["attempt"]["reached"], source_parent);
    assert_eq!(
        restored["observation"]["stop"],
        "reached:boundary:campaign.complete"
    );
    assert_eq!(restored["runtime"]["phase"], "completed");
    assert_eq!(restored["runtime"]["origin"], "selected-savepoint");
    assert_eq!(restored["runtime"]["origin_checkpoint"], checkpoint);
    assert_eq!(restored["runtime"]["source_request"], request);
    require_semantic_marker(&restored, "fault.transport.primary-probed", "router-a")?;
    require_semantic_marker(&restored, "fault.transport.signaled", "router-a")?;
    require_semantic_marker(&restored, "campaign.complete", "traffic-west")?;
    println!("envoy_five_node_pending_choice_exact_replay={restored}");
    Ok(())
}

fn wait_for_capture_ready(
    fixture: &FlightFixture,
    service: &mut CampaignServiceChild,
    request: &str,
) -> Result<Value, Box<dyn Error>> {
    let deadline = Instant::now() + ATTEMPT_WAIT;
    wait_for_process_observation(deadline, || {
        if let Some(status) = service.child.try_wait()? {
            return Err(format!(
                "Envoy campaign service exited before capture {request}: {status}"
            )
            .into());
        }
        let head = campaign_status(fixture)?;
        let snapshot = json_string(&head, "snapshot")?;
        let output = connected_campaign(fixture)
            .args([
                "capture-status",
                CAMPAIGN,
                "--snapshot",
                &snapshot,
                "--request",
                request,
            ])
            .output()?;
        if !output.status.success()
            && String::from_utf8_lossy(&output.stderr)
                .contains("campaign request used stale snapshot")
        {
            return Ok(None);
        }
        let report = parse_json_output(output, "inspect exact Envoy capture")?;
        assert_eq!(report["schema"], "crucible.cli.campaign-savepoint.v1");
        assert_eq!(report["operation"], "capture-status");
        assert_eq!(report["request"], request);
        match report["outcome"].as_str() {
            Some("ready") => Ok(Some(report)),
            Some("pending") => Ok(None),
            Some("failed" | "canceled") => {
                Err(format!("Envoy capture {request} failed: {report}").into())
            }
            _ => Err(format!("Envoy capture {request} has invalid outcome: {report}").into()),
        }
    })?
    .ok_or_else(|| format!("capture {request} did not become ready within {ATTEMPT_WAIT:?}").into())
}

fn wait_for_public_completed_attempt(
    fixture: &FlightFixture,
    service: &mut CampaignServiceChild,
    attempt: AttemptId,
) -> Result<Value, Box<dyn Error>> {
    let deadline = Instant::now() + ATTEMPT_WAIT;
    wait_for_process_observation(deadline, || {
        if let Some(status) = service.child.try_wait()? {
            return Err(format!(
                "Envoy campaign service exited before exact continuation {attempt}: {status}"
            )
            .into());
        }
        let head = campaign_status(fixture)?;
        let snapshot = json_string(&head, "snapshot")?;
        let Some(explanation) = explain_public_attempt(fixture, &snapshot, &attempt.to_string())?
        else {
            return Ok(None);
        };
        Ok((!explanation["observation"].is_null()
            && explanation["runtime"]["phase"] == "completed")
            .then_some(explanation))
    })?
    .ok_or_else(|| {
        format!("exact continuation {attempt} did not complete within {ATTEMPT_WAIT:?}").into()
    })
}

fn initial_discovery_attempt(
    lineage_path: &Path,
    policy_path: &Path,
) -> Result<AttemptId, Box<dyn Error>> {
    let lineage = CampaignLineage::from_canonical_bytes(&fs::read(lineage_path)?)?;
    let policy = CampaignPolicy::from_canonical_bytes(&fs::read(policy_path)?)?;
    let path = BranchPath::new(Vec::new())?;
    Ok(Attempt::new(
        AttemptStart::Discover {
            configuration: lineage.genesis_content(),
        },
        path.id()?,
        policy.bound_stop(StopCondition::NextChoice)?,
    )?
    .id()?)
}

fn initial_discovery_admitted(status: &Value) -> Result<bool, Box<dyn Error>> {
    let admitted = status["semantic"]["admitted_attempts"]
        .as_u64()
        .ok_or("public campaign status omitted its admitted-attempt count")?;
    Ok(admitted > 0)
}

#[test]
fn initial_discovery_wait_requires_typed_public_admission_count() -> Result<(), Box<dyn Error>> {
    let pending = serde_json::json!({ "semantic": { "admitted_attempts": 0 } });
    let admitted = serde_json::json!({ "semantic": { "admitted_attempts": 1 } });
    let malformed = serde_json::json!({ "semantic": { "admitted_attempts": "1" } });

    assert!(!initial_discovery_admitted(&pending)?);
    assert!(initial_discovery_admitted(&admitted)?);
    assert!(initial_discovery_admitted(&malformed).is_err());
    Ok(())
}

fn explain_public_attempt(
    fixture: &FlightFixture,
    snapshot: &str,
    attempt: &str,
) -> Result<Option<Value>, Box<dyn Error>> {
    let output = connected_campaign(fixture)
        .args([
            "explain-attempt",
            CAMPAIGN,
            "--snapshot",
            snapshot,
            "--attempt",
            attempt,
        ])
        .output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("campaign request used stale snapshot") {
            return Ok(None);
        }
    }
    parse_json_output(output, "explain public Envoy attempt").map(Some)
}

fn wait_for_public_attempt(
    fixture: &FlightFixture,
    service: &mut CampaignServiceChild,
    attempt: AttemptId,
    timeout: Duration,
) -> Result<Value, Box<dyn Error>> {
    let deadline = Instant::now() + timeout;
    let explanation = wait_for_process_observation(deadline, || {
        if let Some(status) = service.child.try_wait()? {
            return Err(format!(
                "Envoy campaign service exited before attempt {attempt}: {status}"
            )
            .into());
        }
        let head = campaign_status(fixture)?;
        // This empty-frontier campaign can only admit discovery first. Wait
        // for its execution basis before requesting the snapshot explanation.
        if !initial_discovery_admitted(&head)? {
            return Ok(None);
        }
        let snapshot = json_string(&head, "snapshot")?;
        let Some(explanation) = explain_public_attempt(fixture, &snapshot, &attempt.to_string())?
        else {
            return Ok(None);
        };
        Ok((!explanation["observation"].is_null()).then_some(explanation))
    })?;
    explanation.ok_or_else(|| {
        format!("attempt {attempt} has no public observation within {timeout:?}").into()
    })
}

fn wait_for_request_attempt(
    fixture: &FlightFixture,
    service: &mut CampaignServiceChild,
    request: &str,
    value: &str,
    timeout: Duration,
) -> Result<Value, Box<dyn Error>> {
    let deadline = Instant::now() + timeout;
    let completed = wait_for_process_observation(deadline, || {
        if let Some(status) = service.child.try_wait()? {
            return Err(format!(
                "Envoy campaign service exited before request {request}: {status}"
            )
            .into());
        }
        let head = campaign_status(fixture)?;
        let snapshot = json_string(&head, "snapshot")?;
        let output = connected_campaign(fixture)
            .args([
                "request-attempts",
                CAMPAIGN,
                "--snapshot",
                &snapshot,
                "--request",
                request,
                "--pages",
                "256",
            ])
            .output()?;
        if !output.status.success()
            && String::from_utf8_lossy(&output.stderr)
                .contains("campaign request used stale snapshot")
        {
            return Ok(None);
        }
        let page = parse_json_output(output, "query authenticated request attempts")?;
        assert_eq!(page["schema"], "crucible.cli.campaign-request-attempts.v2");
        assert_eq!(page["request"], request);
        if page["complete"] != true {
            return Err(
                format!("request {request} exceeds the bounded public attempt scan").into(),
            );
        }
        let entries = page["entries"]
            .as_array()
            .ok_or("request-attempt query omitted entries")?;
        for entry in entries {
            let attempt = json_string(entry, "attempt")?;
            let proposal = json_string(entry, "proposal")?;
            if entry["request"] != request || entry["value"] != value {
                return Err(format!(
                    "request {request} admitted an unexpected proposal {proposal}"
                )
                .into());
            }
            let role = json_string(entry, "role")?;
            let Some(explanation) = explain_public_attempt(fixture, &snapshot, &attempt)? else {
                continue;
            };
            match role.as_str() {
                "execution-basis" => {
                    if explanation["proposal"]["id"] != proposal
                        || explanation["proposal"]["request"] != request
                        || explanation["selection"]["value"] != value
                    {
                        return Err(format!(
                            "request {request} has a mismatched execution-basis attempt {attempt}"
                        )
                        .into());
                    }
                }
                "additional-cause" => {}
                _ => return Err(format!("request {request} has unknown role {role}").into()),
            }
            if !explanation["observation"].is_null() {
                return Ok(Some(explanation));
            }
        }
        Ok(None)
    })?;
    completed.ok_or_else(|| {
        format!("request {request} has no public completed attempt within {timeout:?}").into()
    })
}

fn require_network_effect(
    explanations: &[&Value],
    kind: &str,
    segments: &[&str],
    state: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    for explanation in explanations {
        let Some(evidence) = explanation
            .get("effect_evidence")
            .filter(|value| !value.is_null())
        else {
            continue;
        };
        assert_eq!(
            evidence["schema"],
            "crucible.cli.campaign-attempt-effect-evidence.v2"
        );
        let effects = evidence["network_effects"]
            .as_array()
            .ok_or("attempt effect evidence omitted network effects")?;
        let applied = effects.iter().any(|effect| {
            effect["kind"] == kind
                && effect["target"]["kind"] == "network_segment"
                && segments
                    .iter()
                    .any(|segment| effect["target"]["parameters"]["segment"] == *segment)
                && state.is_none_or(|expected| effect["parameters"]["state"] == expected)
                && effect["evidence_digest"].as_str().is_some()
        });
        if applied {
            let trace = json_string(evidence, "resolved_effect_trace")?;
            crucible_cas::content_store::ContentId::parse(&trace)?;
            return Ok(());
        }
    }
    Err(format!("attempts lack applied {kind} effect on {segments:?}: {explanations:?}").into())
}

fn require_semantic_marker(
    explanation: &Value,
    name: &str,
    node: &str,
) -> Result<(), Box<dyn Error>> {
    let markers = explanation["effect_evidence"]["semantic_markers"]
        .as_array()
        .ok_or("attempt effect evidence omitted semantic markers")?;
    if !markers.iter().any(|marker| {
        marker["name"] == name
            && marker["node"] == node
            && marker["instance"] == "instance-1"
            && marker["entry"].as_str().is_some()
    }) {
        return Err(format!("attempt lacks authenticated {name} marker: {markers:?}").into());
    }
    Ok(())
}

fn require_measured_backup_route(explanation: &Value) -> Result<(), Box<dyn Error>> {
    let evidence = &explanation["effect_evidence"];
    assert_eq!(
        evidence["schema"],
        "crucible.cli.campaign-attempt-effect-evidence.v2"
    );

    let routes = evidence["route_events"]
        .as_array()
        .ok_or("attempt effect evidence omitted route events")?;
    let backup_route = routes.iter().any(|route| {
        route["node"] == "traffic-west"
            && route["name"] == "network.failover.observed"
            && route["instance"] == "instance-1"
            && route["path"] == "a-c-east"
            && route["route_sequence"]
                .as_u64()
                .is_some_and(|sequence| sequence > 0)
            && route["entry"].as_str().is_some()
    });
    if !backup_route {
        return Err(format!("attempt lacks an authenticated A-C-east route: {routes:?}").into());
    }

    let samples = evidence["metric_samples"]
        .as_array()
        .ok_or("attempt effect evidence omitted metric samples")?;
    let delivered = samples.iter().any(|sample| {
        sample["node"] == "traffic-west"
            && sample["measurement"] == "traffic-window"
            && sample["instance"] == "instance-1"
            && sample["name"] == "traffic_success_packets"
            && sample["value_kind"] == "u64"
            && sample["value"].as_u64().is_some_and(|count| count > 0)
            && sample["entry"].as_str().is_some()
    });
    if !delivered {
        return Err(format!("attempt lacks authenticated successful traffic: {samples:?}").into());
    }

    for metric in ["traffic_loss_packets", "response_completion_inversions"] {
        let recorded = samples.iter().any(|sample| {
            sample["node"] == "traffic-west"
                && sample["measurement"] == "traffic-window"
                && sample["instance"] == "instance-1"
                && sample["name"] == metric
                && sample["value_kind"] == "u64"
                && sample["value"].as_u64().is_some()
                && sample["entry"].as_str().is_some()
        });
        if !recorded {
            return Err(format!("attempt lacks authenticated {metric} sample: {samples:?}").into());
        }
    }
    Ok(())
}

fn compile_bounded_policy(
    fixture: &FlightFixture,
    generated: &Value,
) -> Result<PathBuf, Box<dyn Error>> {
    let lineage =
        CampaignLineage::from_canonical_bytes(&fs::read(json_path(generated, "lineage")?)?)?;
    let input = fixture._temporary.path().join("envoy-policy.toml");
    let output = fixture._temporary.path().join("envoy-policy.bin");

    // The reference search policy remains in the generated fixture. This
    // single-flight policy reserves attempts for explicit public branches.
    fs::write(
        &input,
        format!(
            r#"schema_version = 3
scenario = {:?}
campaign_seed = "5152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f70"
mode = "strict"
stop_conditions = ["scenario-complete"]
admit_scenario_defaults = false

[explorer]
kind = "exhaustive"
maximum_cardinality = 32

[fairness]
breadth_first_percent = 0
novelty_reserve = 0

[retention]
retain_all_findings = true
survivor_limit = 8
exact_findings = true
exact_user_pins = true
"#,
            lineage.scenario().to_string(),
        ),
    )?;
    run_json(
        command(&["--format", "jsonl", "campaign", "policy", "compile"])
            .arg(&input)
            .arg("--output")
            .arg(&output),
        "compile bounded Envoy operator flight policy",
    )?;
    Ok(output)
}

fn component_authority(fixture: &FlightFixture) -> Result<PathBuf, Box<dyn Error>> {
    let authority = fixture
        ._temporary
        .path()
        .join("envoy-component-authority.bin");
    let mut bytes = b"CRUCCA01".to_vec();
    bytes.extend_from_slice(&[0x41; 32]);
    bytes.extend_from_slice(&[0x42; 32]);
    fs::write(&authority, bytes)?;
    fs::set_permissions(&authority, fs::Permissions::from_mode(0o600))?;
    Ok(authority)
}

fn start_packaged_network_service(
    fixture: &FlightFixture,
    authority: &Path,
) -> Result<CampaignServiceChild, Box<dyn Error>> {
    let mut invocation = fixture.service_command(None);
    invocation
        .arg("--qemu")
        .arg(required_path("CRUCIBLE_FLIGHT_QEMU")?)
        .arg("--plugin")
        .arg(required_path("CRUCIBLE_FLIGHT_PLUGIN")?)
        .args([
            "--production-qemu",
            "--qemu-rendezvous-icount",
            "250000000",
            "--campaign-runtime-all",
            "--campaign-component-authority",
        ])
        .arg(authority)
        .arg("--campaign-packaged-executor")
        .arg(required_path("CRUCIBLE_FLIGHT_DEPLOYMENT")?)
        .arg("--campaign-executor-socket")
        .arg(fixture._temporary.path().join("envoy-executor.sock"));
    // Capturing baked genesis copies the RAM and disk of all five guests
    // before the service binds its campaign socket.
    fixture.start_service_command(invocation, Duration::from_secs(600))
}

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
        .arg(&root_image),
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
    let lineage = compile_packaged_lineage(&fixture, &generated)?;
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
    let response = choose(
        &fixture,
        &mut service,
        &mut progress,
        "recovery.response",
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
    let submission = guest_choice::submit_choice(fixture, &choice, value, stop, command_byte)?;
    let request = guest_choice::accepted_branch_request(&submission)?;
    let explanation = wait_for_request_attempt(fixture, service, &request, value, ATTEMPT_WAIT)?;
    assert_eq!(explanation["proposal"]["request"], request);
    assert_eq!(explanation["selection"]["value"], value);
    assert_eq!(
        explanation["observation"]["stop"],
        format!("reached:{stop}")
    );
    println!("envoy_five_node_choice_{name}={explanation}");

    if stop == "next-choice" {
        progress.parent = json_string(&explanation["observation"], "child_artifact")?;
        progress.configuration = json_string(&explanation["observation"], "child")?;
    }
    Ok(explanation)
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
        if stderr.contains("campaign-attempt-is-not-in-snapshot")
            || stderr.contains("campaign request used stale snapshot")
        {
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
            let Some(explanation) = explain_public_attempt(fixture, &snapshot, &attempt)? else {
                continue;
            };
            if explanation["proposal"]["request"] != request
                || explanation["selection"]["value"] != value
            {
                return Err(
                    format!("request {request} admitted an unexpected attempt {attempt}").into(),
                );
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
            "crucible.cli.campaign-attempt-effect-evidence.v1"
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

fn compile_packaged_lineage(
    fixture: &FlightFixture,
    generated: &Value,
) -> Result<PathBuf, Box<dyn Error>> {
    let source =
        CampaignLineage::from_canonical_bytes(&fs::read(json_path(generated, "lineage")?)?)?;
    let input = fixture._temporary.path().join("envoy-lineage.toml");
    let output = fixture._temporary.path().join("envoy-lineage.bin");
    fs::write(
        &input,
        format!(
            r#"schema_version = 1
scenario = {:?}
scenario_content = {:?}
genesis = {:?}
genesis_content = {:?}
crucible_version = {:?}
qemu_build = "qemu-11.1.1-crucible"
scenario_schema = {}
exact_closure_schema = {}

[protocol_versions]
control = 3
shared-memory = 25
"#,
            source.scenario().to_string(),
            source.scenario_content().to_string(),
            source.genesis().to_string(),
            source.genesis_content().to_string(),
            source.crucible_version(),
            source.scenario_schema(),
            source.exact_closure_schema(),
        ),
    )?;
    run_json(
        command(&["--format", "jsonl", "campaign", "lineage", "compile"])
            .arg(&input)
            .arg("--output")
            .arg(&output),
        "compile packaged QEMU lineage",
    )?;
    Ok(output)
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

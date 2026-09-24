//! Five-node Envoy campaign flight through the public fixture and campaign CLI.

use super::*;
use crucible_campaign::CampaignLineage;

const RECOVERY_STRATEGY: &str =
    "discrete:2222222222222222222222222222222222222222222222222222222222222222";
const RECOVERY_CHOICES: [(&str, &str); 4] = [
    ("recovery.strategy", RECOVERY_STRATEGY),
    ("recovery.hold_down_us", "u64:0"),
    ("recovery.retry_limit", "u64:3"),
    ("recovery.fast_reroute", "true"),
];

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
    let (discovery_attempt, discovery) =
        guest_choice::wait_for_initial_discovery(&fixture, &mut service, &genesis)?;
    assert_eq!(discovery["observation"]["stop"], "reached:next-choice");
    println!("envoy_five_node_baseline={discovery}");

    let mut known = guest_choice::attempt_states(&fixture)?
        .into_keys()
        .collect::<BTreeSet<_>>();
    known.insert(discovery_attempt);
    let mut parent = json_string(&discovery["observation"], "child_artifact")?;
    let mut configuration = json_string(&discovery["observation"], "child")?;

    for (index, (selectable, value)) in RECOVERY_CHOICES.iter().enumerate() {
        let choice = guest_choice::wait_for_choice(&fixture, selectable, &parent, &configuration)?;
        let stop = if index + 1 == RECOVERY_CHOICES.len() {
            "boundary:network.failover.observed"
        } else {
            "next-choice"
        };
        let submission =
            guest_choice::submit_choice(&fixture, &choice, value, stop, 0x73 + index as u8)?;
        let request = guest_choice::accepted_branch_request(&submission)?;
        let attempt = guest_choice::wait_for_new_completed_attempt_with_timeout(
            &fixture,
            &mut service,
            &known,
            &request,
            Duration::from_secs(600),
        )?;
        known.insert(attempt);
        let explanation = guest_choice::wait_for_attempt_observation(&fixture, attempt)?;
        assert_eq!(explanation["proposal"]["request"], request);
        assert_eq!(explanation["selection"]["value"], *value);
        println!("envoy_five_node_choice_{selectable}={explanation}");

        if index + 1 == RECOVERY_CHOICES.len() {
            assert_eq!(
                explanation["observation"]["stop"],
                "reached:boundary:network.failover.observed"
            );
            println!("envoy_five_node_failover_and_recovery_authenticated=true");
        } else {
            assert_eq!(explanation["observation"]["stop"], "reached:next-choice");
            parent = json_string(&explanation["observation"], "child_artifact")?;
            configuration = json_string(&explanation["observation"], "child")?;
        }
    }

    let status = campaign_status(&fixture)?;
    assert_eq!(status["state"], "running");
    service.stop()?;
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
    fixture.start_service_command(invocation, Duration::from_secs(120))
}

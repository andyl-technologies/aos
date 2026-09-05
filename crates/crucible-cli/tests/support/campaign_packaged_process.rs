//! Public packaged-executor startup/restart flight for an isolated Linux VM.
//!
//! The test authors its scenario through the public model, then uses only CLI
//! commands for compilation, import, campaign creation, and daemon startup.
//! Startup must capture a real native baked genesis before binding the service.

use super::*;
use crucible_session::engine::{
    Action, ContentAddressedBlobRef, ContentHash, EventGraph, Icount, NodeId, Plan, Properties,
    ReadyPoint, ScenarioDefForm, Seed, VmArchitecture, WhiteBoxPolicy, World, WorldNode,
};

#[test]
#[ignore = "requires dedicated cgroup-v2 and ext4 project-quota roots inside the VM check"]
fn public_packaged_executor_captures_genesis_and_restarts() -> Result<(), Box<dyn Error>> {
    packaged_campaign_flight(false)
}

#[test]
#[ignore = "requires dedicated cgroup-v2 and ext4 project-quota roots inside the VM check"]
fn public_packaged_executor_completes_initial_discovery() -> Result<(), Box<dyn Error>> {
    packaged_campaign_flight(true)
}

fn packaged_campaign_flight(execute: bool) -> Result<(), Box<dyn Error>> {
    let fixture = FlightFixture::new()?;
    let root = fixture._temporary.path();
    let kernel = required_path("CRUCIBLE_KERNEL")?;
    let root_image = required_path("CRUCIBLE_ROOT_IMAGE")?;
    let world = World::from_nodes_and_links(
        vec![WorldNode {
            id: NodeId {
                name: "node".into(),
            },
            arch: VmArchitecture::X86_64,
            memory_mib: 128,
            cmdline: "console=ttyS0".into(),
            ready_point: ReadyPoint::FixedIcount {
                icount: Icount { retired: 0 },
            },
            white_box: WhiteBoxPolicy::Disabled,
            smp_vcpus: 1,
            icount_shift: 0,
            kernel: Some(ContentAddressedBlobRef::from_hash(ContentHash::from_bytes(
                &fs::read(kernel)?,
            ))),
            root_image: Some(ContentAddressedBlobRef::from_hash(ContentHash::from_bytes(
                &fs::read(root_image)?,
            ))),
            initrd: None,
        }],
        vec![],
    )?;
    // An empty plan does not terminate a running machine. Give the execution
    // flight an explicit modeled completion at its first event boundary.
    let plan = Plan::from_event_graph_for_world(
        &world,
        EventGraph::builder()
            .event("complete-flight")
            .entrypoint()
            .action(Action::Pass)
            .build_for_world(&world)?,
    )?;
    let scenario =
        ScenarioDefForm::from_components(&world, &plan, &Properties::empty(), Seed::from_u64(42))?;
    let scenario_path = root.join("scenario.toml");
    fs::write(&scenario_path, scenario.to_canonical_toml()?)?;
    let compiled = run_json(
        command(&["--format", "jsonl", "campaign", "scenario", "compile"])
            .arg(&scenario_path)
            .arg("--output")
            .arg(&fixture.fixture),
        "compile real-asset scenario",
    )?;
    let lineage_input = root.join("lineage.toml");
    let lineage = root.join("lineage.bin");
    fs::write(
        &lineage_input,
        format!(
            "schema_version = 1\nscenario = {:?}\nscenario_content = {:?}\ngenesis = {:?}\ngenesis_content = {:?}\ncrucible_version = \"0.1.0\"\nqemu_build = \"qemu-10.0-crucible\"\nscenario_schema = 3\nexact_closure_schema = 4\n[protocol_versions]\ncontrol = 2\nshared-memory = 5\n",
            json_string(&compiled, "scenario")?,
            json_string(&compiled, "scenario_artifact")?,
            json_string(&compiled, "genesis")?,
            json_string(&compiled, "genesis_artifact")?,
        ),
    )?;
    run_json(
        command(&["--format", "jsonl", "campaign", "lineage", "compile"])
            .arg(&lineage_input)
            .arg("--output")
            .arg(&lineage),
        "compile lineage",
    )?;
    let policy_input = root.join("policy.toml");
    let policy = root.join("policy.bin");
    fs::write(
        &policy_input,
        format!(
            r#"schema_version = 1
scenario = {:?}
campaign_seed = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
mode = "strict"
stop_conditions = ["scenario-complete"]
admit_scenario_defaults = false
[explorer]
kind = "exhaustive"
maximum_cardinality = 1
[fairness]
breadth_first_percent = 0
novelty_reserve = 0
[retention]
retain_all_findings = true
survivor_limit = 1
exact_findings = true
exact_user_pins = true
"#,
            json_string(&compiled, "scenario")?
        ),
    )?;
    run_json(
        command(&["--format", "jsonl", "campaign", "policy", "compile"])
            .arg(&policy_input)
            .arg("--output")
            .arg(&policy),
        "compile policy",
    )?;

    let manifest = json_path(&compiled, "manifest")?;
    let mut service = fixture.start_service(Some(&manifest))?;
    run_json(
        connected_campaign(&fixture)
            .args(["create", CAMPAIGN, "--lineage"])
            .arg(&lineage)
            .arg("--policy")
            .arg(&policy),
        "create packaged campaign",
    )?;
    let original = campaign_status(&fixture)?;
    service.stop()?;

    let authority = root.join("authority.bin");
    let mut authority_bytes = b"CRUCCA01".to_vec();
    authority_bytes.extend_from_slice(&[0x31; 32]);
    authority_bytes.extend_from_slice(&[0x32; 32]);
    fs::write(&authority, authority_bytes)?;
    fs::set_permissions(&authority, fs::Permissions::from_mode(0o600))?;
    let deployment = required_path("CRUCIBLE_FLIGHT_DEPLOYMENT")?;
    let executor_socket = root.join("executor.sock");
    for _ in 0..if execute { 1 } else { 2 } {
        let mut invocation = fixture.service_command(None);
        invocation
            .arg("--qemu")
            .arg(required_path("CRUCIBLE_FLIGHT_QEMU")?)
            .arg("--plugin")
            .arg(required_path("CRUCIBLE_FLIGHT_PLUGIN")?);
        invocation
            .args([
                "--production-qemu",
                "--campaign-runtime-all",
                "--campaign-component-authority",
            ])
            .arg(&authority)
            .arg("--campaign-packaged-executor")
            .arg(&deployment)
            .arg("--campaign-executor-socket")
            .arg(&executor_socket);
        let mut packaged = fixture.start_service_command(invocation, Duration::from_secs(120))?;
        assert!(fs::metadata(&executor_socket)?.file_type().is_socket());
        let head = campaign_status(&fixture)?;
        assert_eq!(head["state"], original["state"]);
        assert_eq!(head["snapshot"], original["snapshot"]);
        if execute
            && let Err(error) = execute_initial_discovery(
                &fixture,
                &head,
                &json_string(&compiled, "genesis_artifact")?,
            )
        {
            let shutdown = packaged.stop();
            return Err(format!("{error}; service shutdown: {shutdown:?}").into());
        }
        packaged.stop()?;
        assert!(!executor_socket.exists());
    }
    if execute {
        println!("public_packaged_initial_discovery=true");
    } else {
        println!("public_packaged_genesis_restart=true");
    }
    Ok(())
}

fn execute_initial_discovery(
    fixture: &FlightFixture,
    head: &Value,
    genesis: &str,
) -> Result<(), Box<dyn Error>> {
    let path = crucible_campaign::BranchPath::new(Vec::new())?;
    let attempt = crucible_campaign::Attempt::new(
        crucible_campaign::AttemptStart::Discover {
            configuration: crucible_campaign::ConfigurationArtifactId::parse(genesis)?,
        },
        path.id()?,
        crucible_campaign::StopCondition::NextChoice,
    )?
    .id()?
    .to_string();
    let before = snapshot_at(fixture, &json_string(head, "snapshot")?)?;
    run_json(
        connected_campaign(fixture)
            .args([
                "budget",
                CAMPAIGN,
                "--expected",
                &json_string(head, "snapshot")?,
                "--command",
            ])
            .arg("51".repeat(32))
            .args(["add", "1", "--proposals", "1"]),
        "grant initial discovery budget",
    )?;
    let budgeted = campaign_status(fixture)?;
    run_json(
        connected_campaign(fixture)
            .args([
                "start",
                CAMPAIGN,
                "--expected",
                &json_string(&budgeted, "snapshot")?,
                "--command",
            ])
            .arg("52".repeat(32)),
        "start initial discovery",
    )?;

    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let head = campaign_status(fixture)?;
        let snapshot = snapshot_at(fixture, &json_string(&head, "snapshot")?)?;
        if snapshot["snapshot"]["roots"]["observations"]
            != before["snapshot"]["roots"]["observations"]
        {
            let explanation = run_json(
                connected_campaign(fixture).args([
                    "explain-attempt",
                    CAMPAIGN,
                    "--snapshot",
                    &json_string(&head, "snapshot")?,
                    "--attempt",
                    &attempt,
                ]),
                "authenticate initial discovery completion",
            )?;
            assert_eq!(explanation["attempt"]["id"], attempt);
            assert_eq!(explanation["admission"]["admission_ordinal"], 1);
            assert_eq!(explanation["observation"]["stop"], "terminal-success");
            return Ok(());
        }
        if Instant::now() >= deadline {
            let explanation = run_json(
                connected_campaign(fixture).args([
                    "explain-attempt",
                    CAMPAIGN,
                    "--snapshot",
                    &json_string(&head, "snapshot")?,
                    "--attempt",
                    &attempt,
                ]),
                "explain stalled initial discovery",
            );
            return Err(format!("running packaged campaign produced no initial discovery observation within 30s: {head}; snapshot={snapshot}; attempt={explanation:?}").into());
        }
        // The public watch command is a coalesced read, not a subscription.
        // Bound this process-flight wait without a tight client request loop.
        thread::sleep(Duration::from_millis(200));
    }
}

fn snapshot_at(fixture: &FlightFixture, snapshot: &str) -> Result<Value, Box<dyn Error>> {
    run_json(
        connected_campaign(fixture).args(["snapshot", CAMPAIGN, "--snapshot", snapshot]),
        "inspect execution observation root",
    )
}

fn required_path(name: &str) -> Result<PathBuf, Box<dyn Error>> {
    std::env::var_os(name)
        .map(PathBuf::from)
        .ok_or_else(|| format!("missing {name}").into())
}

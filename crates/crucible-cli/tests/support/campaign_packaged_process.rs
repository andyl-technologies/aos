//! Public packaged-executor startup/restart flight for an isolated Linux VM.
//!
//! The test authors its scenario through the public model, then uses only CLI
//! commands for compilation, import, campaign creation, and daemon startup.
//! Startup must capture a real native baked genesis before binding the service.

use super::*;
use crucible_session::engine::{
    ContentAddressedBlobRef, ContentHash, Icount, NodeId, Plan, Properties, ReadyPoint,
    ScenarioDefForm, Seed, VmArchitecture, WhiteBoxPolicy, World, WorldNode,
};

#[test]
#[ignore = "requires dedicated cgroup-v2 and ext4 project-quota roots inside the VM check"]
fn public_packaged_executor_captures_genesis_and_restarts() -> Result<(), Box<dyn Error>> {
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
    let scenario = ScenarioDefForm::from_components(
        &world,
        &Plan::empty(),
        &Properties::empty(),
        Seed::from_u64(42),
    )?;
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
    for _ in 0..2 {
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
        packaged.stop()?;
        assert!(!executor_socket.exists());
    }
    println!("public_packaged_genesis_restart=true");
    Ok(())
}

fn required_path(name: &str) -> Result<PathBuf, Box<dyn Error>> {
    std::env::var_os(name)
        .map(PathBuf::from)
        .ok_or_else(|| format!("missing {name}").into())
}

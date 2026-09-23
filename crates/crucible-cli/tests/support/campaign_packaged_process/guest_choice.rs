//! Real guest-choice, exact-checkpoint, and daemon-restart campaign flight.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::sync::Arc;

use super::*;
use crucible_campaign::{
    AlternativeId, BranchPointId, CampaignHash, ChoiceClassContext, ChoiceDomain,
    ChoiceOpportunityId, ChoiceOpportunitySemanticId, ChoiceSource, ChoiceValue, ConfigurationId,
    DiscreteAlternative, DiscreteDomain, ExactCheckpointId, ExactRational, IntegerDomain,
    IntegerRepresentation, IntegerValue, SelectableDeclaration,
};
use crucible_core::{FramePredicate, LinkId, RegexProgram};
use crucible_daemon::{
    AttemptExecutionKey, AttemptExecutionOrigin, AttemptRuntimeState, ExactCheckpointStore,
    visit_directory_attempt_states_bounded,
};
use crucible_session::engine::{LinkDef, LinkLossProbability, MarkerId};

pub(crate) const FAST_ALTERNATIVE: &str =
    "0101010101010101010101010101010101010101010101010101010101010101";
const SAFE_ALTERNATIVE: &str = "0202020202020202020202020202020202020202020202020202020202020202";
const GUEST_CHOICE_RENDEZVOUS_ICOUNT: &str = "250000000";
const GUEST_CHOICE_ATTEMPT_WAIT: Duration = Duration::from_secs(240);
const MAX_GUEST_CHOICE_ATTEMPT_RECORDS: usize = 65_536;
const MAX_DIAGNOSTIC_ATTEMPTS: usize = 16;
const MAX_DIAGNOSTIC_ENTRIES: usize = 256;
const MAX_DIAGNOSTIC_FILE_BYTES: u64 = 8 * 1024;
const MAX_STALE_BRANCH_RETRIES: usize = 8;
const GUEST_SELECTABLE_BOUNDARY_PREFIX: &str = "CRUCIBLE-GUEST-SELECTABLE-BOUNDARY-V1 ";
const MAX_GUEST_SELECTABLE_BOUNDARY_EVENTS: usize = 256;
const MAX_GUEST_SELECTABLE_BOUNDARY_LINES: usize = MAX_GUEST_SELECTABLE_BOUNDARY_EVENTS + 1;
const MAX_GUEST_SELECTABLE_BOUNDARY_LINE_BYTES: usize = 8 * 1024;

#[path = "guest_choice/maintenance_transfer.rs"]
mod maintenance_transfer;

#[test]
#[ignore = "requires dedicated cgroup-v2 and ext4 project-quota roots inside the VM check"]
fn public_guest_choices_survive_exact_checkpoint_and_daemon_restart() -> Result<(), Box<dyn Error>>
{
    let fixture = FlightFixture::new()?;
    let (compiled, _scenario) = compile_guest_choice_campaign(&fixture)?;
    create_guest_choice_campaign(&fixture, &compiled, "qemu-11.1.1-crucible")?;

    let authority = write_component_authority(&fixture)?;
    let immutable_inputs = guest_choice_immutable_inputs(&authority)?;
    attest_guest_choice_immutable_inputs("source-discovery", &immutable_inputs, &authority)?;
    require_empty_guest_choice_run_root("source-discovery")?;
    let mut service = start_packaged_service(&fixture, &authority)?;
    println!("\nguest_choice_rendezvous_icount={GUEST_CHOICE_RENDEZVOUS_ICOUNT}");
    grant_and_start_guest_choice_campaign(&fixture)?;

    let genesis_artifact = json_string(&compiled, "genesis_artifact")?;
    let (discovery_attempt, discovery_explanation) =
        wait_for_initial_discovery(&fixture, &mut service, &genesis_artifact)?;
    let discovery_parent = json_string(&discovery_explanation["observation"], "child_artifact")?;
    let discovery_parent_configuration =
        json_string(&discovery_explanation["observation"], "child")?;
    let mut known_attempts = attempt_states(&fixture)?
        .into_keys()
        .collect::<BTreeSet<_>>();
    known_attempts.insert(discovery_attempt);
    let recovery = wait_for_choice(
        &fixture,
        "network.recovery-policy",
        &discovery_parent,
        &discovery_parent_configuration,
    )?;

    attest_guest_choice_immutable_inputs("fast-replay", &immutable_inputs, &authority)?;
    require_empty_guest_choice_run_root("fast-replay")?;

    let fast_submission = submit_choice(
        &fixture,
        &recovery,
        &format!("discrete:{FAST_ALTERNATIVE}"),
        "next-choice",
        0x61,
    )?;
    let fast_request = accepted_branch_request(&fast_submission)?;
    let fast_attempt = wait_for_new_completed_attempt_with_timeout(
        &fixture,
        &mut service,
        &known_attempts,
        &fast_request,
        GUEST_CHOICE_ATTEMPT_WAIT,
    )?;
    known_attempts.insert(fast_attempt);
    let fast_explanation = wait_for_attempt_observation(&fixture, fast_attempt)?;
    assert_eq!(fast_explanation["proposal"]["request"], fast_request);
    assert_eq!(
        fast_explanation["selection"]["value"],
        format!("discrete:{FAST_ALTERNATIVE}")
    );
    assert_eq!(
        fast_explanation["observation"]["stop"],
        "reached:next-choice"
    );

    let fast_parent = json_string(&fast_explanation["observation"], "child_artifact")?;
    let fast_parent_configuration = json_string(&fast_explanation["observation"], "child")?;
    let retry = wait_for_choice(
        &fixture,
        "network.retry-quanta",
        &fast_parent,
        &fast_parent_configuration,
    )?;
    assert_eq!(retry.domain_kind, "integer");

    attest_guest_choice_immutable_inputs("safe-replay", &immutable_inputs, &authority)?;
    require_empty_guest_choice_run_root("safe-replay")?;

    // A second branch proves the selected values change a frame received by
    // the linked peer, rather than only a marker emitted by the sender.
    let safe_submission = submit_choice(
        &fixture,
        &recovery,
        &format!("discrete:{SAFE_ALTERNATIVE}"),
        "next-choice",
        0x63,
    )?;
    let safe_request = accepted_branch_request(&safe_submission)?;
    let safe_attempt = wait_for_new_completed_attempt_with_timeout(
        &fixture,
        &mut service,
        &known_attempts,
        &safe_request,
        GUEST_CHOICE_ATTEMPT_WAIT,
    )?;
    known_attempts.insert(safe_attempt);
    let safe_explanation = wait_for_attempt_observation(&fixture, safe_attempt)?;
    assert_eq!(safe_explanation["proposal"]["request"], safe_request);
    assert_eq!(
        safe_explanation["selection"]["value"],
        format!("discrete:{SAFE_ALTERNATIVE}")
    );

    let safe_parent = json_string(&safe_explanation["observation"], "child_artifact")?;
    let safe_parent_configuration = json_string(&safe_explanation["observation"], "child")?;
    let safe_retry = wait_for_choice(
        &fixture,
        "network.retry-quanta",
        &safe_parent,
        &safe_parent_configuration,
    )?;
    assert_eq!(safe_retry.domain_kind, "integer");

    attest_guest_choice_immutable_inputs("safe-retry-replay", &immutable_inputs, &authority)?;
    require_empty_guest_choice_run_root("safe-retry-replay")?;

    let safe_retry_submission = submit_choice(&fixture, &safe_retry, "u64:1", "terminal", 0x64)?;
    let safe_retry_request = accepted_branch_request(&safe_retry_submission)?;
    let safe_retry_attempt = wait_for_new_completed_attempt_with_timeout(
        &fixture,
        &mut service,
        &known_attempts,
        &safe_retry_request,
        GUEST_CHOICE_ATTEMPT_WAIT,
    )?;
    known_attempts.insert(safe_retry_attempt);
    let safe_retry_explanation = wait_for_attempt_observation(&fixture, safe_retry_attempt)?;
    assert_eq!(
        safe_retry_explanation["proposal"]["request"],
        safe_retry_request
    );
    assert_eq!(safe_retry_explanation["selection"]["value"], "u64:1");
    assert_eq!(
        safe_retry_explanation["observation"]["stop"],
        "terminal-success"
    );

    // The integer request belongs to the exact child state published by the
    // first branch. Restart the service before replying so its public identity
    // and the subsequent fresh-QEMU realization are both exercised.
    service.stop()?;
    attest_guest_choice_immutable_inputs("post-restart-replay", &immutable_inputs, &authority)?;
    require_empty_guest_choice_run_root("post-restart-replay")?;
    let mut selected_service = start_packaged_service(&fixture, &authority)?;
    let retry_after_restart = wait_for_choice(
        &fixture,
        "network.retry-quanta",
        &fast_parent,
        &fast_parent_configuration,
    )?;
    assert_eq!(retry_after_restart, retry);
    assert_eq!(retry_after_restart.domain_kind, "integer");
    println!("\nguest_choice_pending_choice_identity_preserved=true");

    // Re-submit the fast/q7 branch with a terminal stop. The selected guest
    // parks after its marker, so checkpoint capture cannot race completion.
    let terminal_submission =
        submit_choice(&fixture, &retry_after_restart, "u64:7", "terminal", 0x65)?;
    let terminal_request = accepted_branch_request(&terminal_submission)?;
    let terminal_attempt = wait_for_new_running_attempt(
        &fixture,
        &mut selected_service,
        &known_attempts,
        &terminal_request,
    )?;
    let terminal_before_pause = wait_for_attempt_explanation(&fixture, terminal_attempt)?;
    assert_eq!(terminal_before_pause["attempt"]["stop"], "terminal");
    assert_eq!(
        terminal_before_pause["proposal"]["request"],
        terminal_request
    );
    assert_eq!(terminal_before_pause["selection"]["value"], "u64:7");
    println!("\nguest_choice_pending_choice_answered_after_restart=true");
    attest_fingerprint_enabled_qemu_descendants(
        &selected_service,
        "post-restart terminal attempt",
    )?;
    println!("\nguest_choice_initial_qemu_fingerprint_enabled=true");

    let mut checkpoint_command = 0x70_u64;
    let checkpoint = capture_checkpoint_after_progress(
        &fixture,
        terminal_attempt,
        &mut checkpoint_command,
        None,
    )?;
    let checkpoint_text = checkpoint.to_string();
    let mut boundary_events = capture_guest_selectable_boundary_events(
        &fixture,
        &selected_service,
        "selected-service-stop",
    )?;
    selected_service.stop()?;

    let mut restarted = start_packaged_service(&fixture, &authority)?;
    let paused = campaign_status(&fixture)?;
    assert_eq!(paused["state"], "paused");
    attest_fingerprint_enabled_qemu_descendants(&restarted, "restarted paused exact restore")?;
    println!("\nguest_choice_restarted_qemu_fingerprint_enabled=true");

    resume_campaign(&fixture, &next_command_identity(&mut checkpoint_command)?)?;
    let resumed = wait_for_resumed_attempt(&fixture, terminal_attempt, checkpoint)?;
    assert_eq!(resumed, checkpoint);

    let after_resume_checkpoint = capture_checkpoint_after_progress(
        &fixture,
        terminal_attempt,
        &mut checkpoint_command,
        Some(checkpoint),
    )?;
    assert_ne!(after_resume_checkpoint, checkpoint);

    let resumed_explanation = wait_for_attempt_explanation(&fixture, terminal_attempt)?;
    assert_eq!(resumed_explanation["selection"]["value"], "u64:7");

    boundary_events.extend(capture_guest_selectable_boundary_events(
        &fixture,
        &restarted,
        "restarted-service-stop",
    )?);
    require_guest_selectable_boundary_stage(&boundary_events, "source-discovery")?;
    require_guest_selectable_boundary_stage(&boundary_events, "replay")?;
    restarted.stop()?;

    println!("\nguest_choice_discrete_and_integer=true");
    println!("\nguest_choice_negative_result=true");
    println!("guest_choice_observed_marker=selected-fast-q7");
    println!("guest_choice_checkpoint={checkpoint_text}");
    println!("guest_choice_resumed_checkpoint={after_resume_checkpoint}");
    println!("guest_choice_boundary_diagnostics=true");
    println!("guest_choice_restart_process=true");
    println!("\nguest_choice_resume_source_exact=true");
    println!("\nguest_choice_post_resume_progress=true");
    println!("guest_choice_network_frame_observed=true");
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PublicChoice {
    opportunity: String,
    parent: String,
    branch_point: String,
    domain: String,
    domain_kind: String,
}

fn compile_guest_choice_campaign(
    fixture: &FlightFixture,
) -> Result<(Value, ScenarioDefForm), Box<dyn Error>> {
    let root = fixture._temporary.path();
    let kernel = required_path("CRUCIBLE_KERNEL")?;
    let root_image = required_path("CRUCIBLE_ROOT_IMAGE")?;
    let initrd = required_path("CRUCIBLE_INITRD")?;
    let node = WorldNode {
        id: NodeId {
            name: "choice-node".into(),
        },
        arch: VmArchitecture::X86_64,
        memory_mib: 128,
        cmdline: "console=ttyS0 rdinit=/init quiet nokaslr norandmaps random.trust_cpu=off".into(),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 0 },
        },
        white_box: WhiteBoxPolicy::Enabled,
        smp_vcpus: 1,
        icount_shift: 0,
        kernel: Some(ContentAddressedBlobRef::from_hash(ContentHash::from_bytes(
            &fs::read(kernel)?,
        ))),
        root_image: Some(ContentAddressedBlobRef::from_hash(ContentHash::from_bytes(
            &fs::read(root_image)?,
        ))),
        initrd: Some(ContentAddressedBlobRef::from_hash(ContentHash::from_bytes(
            &fs::read(initrd)?,
        ))),
    };
    let peer = WorldNode {
        id: NodeId {
            name: "choice-peer".into(),
        },
        cmdline: format!("{} -- crucible-campaign-peer", node.cmdline),
        ..node.clone()
    };
    // The 250 ms modeled one-way link gives the conservative scheduler the
    // same lookahead as this flight's 250M-icount rendezvous interval.
    let link = LinkDef::with_transport(
        node.id.clone(),
        peer.id.clone(),
        SimDuration { nanos: 250_000_000 },
        SimDuration { nanos: 0 },
        LinkLossProbability::ZERO,
        None,
    )?;
    let peer_id = peer.id.clone();
    let link_id = LinkId::for_endpoints(&node.id, &peer_id);
    let world = World::from_nodes_and_links(vec![node, peer], vec![link])?;
    let selectables = guest_choice_selectables_with_prefix(&world, "network")?;
    // The pass requires modeled delivery and a receive marker from the peer's
    // own console, so it cannot complete on a sender-only event or early
    // scheduler quiescence with an uncommitted frame.
    let graph = EventGraph::builder()
        .event("network-observed-selected-safe-q1")
        .entrypoint()
        .when(Predicate::all_of(vec![
            Predicate::once(Predicate::network_match(
                Some(link_id),
                FramePredicate::contains(b"crucible-selected-safe-q1".to_vec()),
            )),
            Predicate::once(Predicate::console_match(
                peer_id,
                RegexProgram::from_pattern("CRUCIBLE-CAMPAIGN-PEER-RECEIVED:selected-safe-q1"),
            )),
            Predicate::once(Predicate::guest_marker(MarkerId::from_name(
                "network-observed-selected-safe-q1",
            ))),
        ]))
        .action(Action::Pass)
        .build_for_world(&world)?;
    let plan = Plan::from_event_graph_for_world(&world, graph)?;
    let scenario =
        ScenarioDefForm::from_components(&world, &plan, &Properties::empty(), Seed::from_u64(43))?
            .with_selectables(selectables)?;
    let scenario_path = root.join("guest-choice-scenario.toml");
    fs::write(&scenario_path, scenario.to_canonical_toml()?)?;

    let compiled = run_json(
        command(&["--format", "jsonl", "campaign", "scenario", "compile"])
            .arg(&scenario_path)
            .arg("--output")
            .arg(&fixture.fixture),
        "compile guest-choice scenario",
    )?;
    Ok((compiled, scenario))
}

#[cfg(feature = "packaged-midpoint-flight")]
pub(crate) fn guest_choice_selectables(
    world: &World,
) -> Result<ScenarioSelectables, Box<dyn Error>> {
    guest_choice_selectables_with_prefix(world, "campaign")
}

fn guest_choice_selectables_with_prefix(
    world: &World,
    prefix: &str,
) -> Result<ScenarioSelectables, Box<dyn Error>> {
    let node = world
        .vm_nodes()
        .first()
        .ok_or("guest-choice world has no VM node")?;
    let source = || ChoiceSource::Guest {
        node: node.id.name.clone(),
        protocol_version: u32::from(crucible_protocol::SELECTABLE_PROTOCOL_VERSION),
    };
    let class_context = || ChoiceClassContext::new(BTreeSet::new());

    let fast = AlternativeId::parse(FAST_ALTERNATIVE)?;
    let safe = AlternativeId::parse(SAFE_ALTERNATIVE)?;
    let recovery_domain = ChoiceDomain::Discrete(DiscreteDomain::new(
        1,
        BTreeMap::from([
            (fast, DiscreteAlternative::new(fast, "fast", None)?),
            (safe, DiscreteAlternative::new(safe, "safe", None)?),
        ]),
    )?);
    let recovery = SelectableDeclaration::new(
        format!("{prefix}.recovery-policy"),
        source(),
        recovery_domain,
        ChoiceValue::Discrete(safe),
        class_context()?,
        BTreeSet::new(),
        true,
    )?;

    let retry_domain = ChoiceDomain::Integer(IntegerDomain::new(
        1,
        IntegerRepresentation::Unsigned64,
        IntegerValue::Unsigned(1),
        IntegerValue::Unsigned(9),
        2,
        Some(String::from("quanta")),
        ExactRational::new(1, 1)?,
        Vec::new(),
    )?);
    let retry = SelectableDeclaration::new(
        format!("{prefix}.retry-quanta"),
        source(),
        retry_domain,
        ChoiceValue::Integer(IntegerValue::Unsigned(3)),
        class_context()?,
        BTreeSet::new(),
        true,
    )?;

    let limits = ScenarioSelectableLimits::new(2, 2, 64, 128)?;
    Ok(ScenarioSelectables::new(
        world,
        limits,
        vec![recovery, retry],
    )?)
}

fn create_guest_choice_campaign(
    fixture: &FlightFixture,
    compiled: &Value,
    qemu_build: &str,
) -> Result<(), Box<dyn Error>> {
    let root = fixture._temporary.path();
    let lineage_input = root.join("guest-choice-lineage.toml");
    let lineage = root.join("guest-choice-lineage.bin");
    fs::write(
        &lineage_input,
        format!(
            "schema_version = 1\nscenario = {:?}\nscenario_content = {:?}\ngenesis = {:?}\ngenesis_content = {:?}\ncrucible_version = \"0.1.0\"\nqemu_build = {qemu_build:?}\nscenario_schema = 3\nexact_closure_schema = 5\n[protocol_versions]\ncontrol = 3\nshared-memory = 25\n",
            json_string(compiled, "scenario")?,
            json_string(compiled, "scenario_artifact")?,
            json_string(compiled, "genesis")?,
            json_string(compiled, "genesis_artifact")?,
        ),
    )?;
    run_json(
        command(&["--format", "jsonl", "campaign", "lineage", "compile"])
            .arg(&lineage_input)
            .arg("--output")
            .arg(&lineage),
        "compile guest-choice lineage",
    )?;

    let policy_input = root.join("guest-choice-policy.toml");
    let policy = root.join("guest-choice-policy.bin");
    fs::write(
        &policy_input,
        format!(
            r#"schema_version = 3
scenario = {:?}
campaign_seed = "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
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
            json_string(compiled, "scenario")?
        ),
    )?;
    run_json(
        command(&["--format", "jsonl", "campaign", "policy", "compile"])
            .arg(&policy_input)
            .arg("--output")
            .arg(&policy),
        "compile guest-choice policy",
    )?;

    let manifest = json_path(compiled, "manifest")?;
    let mut service = fixture.start_service(Some(&manifest))?;
    run_json(
        connected_campaign(fixture)
            .args(["create", CAMPAIGN, "--lineage"])
            .arg(&lineage)
            .arg("--policy")
            .arg(&policy),
        "create guest-choice campaign",
    )?;
    service.stop()
}

fn write_component_authority(fixture: &FlightFixture) -> Result<PathBuf, Box<dyn Error>> {
    let authority = fixture._temporary.path().join("guest-choice-authority.bin");
    let mut authority_bytes = b"CRUCCA01".to_vec();
    authority_bytes.extend_from_slice(&[0x41; 32]);
    authority_bytes.extend_from_slice(&[0x42; 32]);
    fs::write(&authority, authority_bytes)?;
    fs::set_permissions(&authority, fs::Permissions::from_mode(0o600))?;
    Ok(authority)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct GuestChoiceImmutableInput {
    label: &'static str,
    bytes: u64,
    hash: ContentHash,
}

fn guest_choice_immutable_inputs(
    authority: &Path,
) -> Result<Vec<GuestChoiceImmutableInput>, Box<dyn Error>> {
    let paths = [
        ("qemu", required_path("CRUCIBLE_FLIGHT_QEMU")?),
        ("plugin", required_path("CRUCIBLE_FLIGHT_PLUGIN")?),
        ("kernel", required_path("CRUCIBLE_KERNEL")?),
        ("initrd", required_path("CRUCIBLE_INITRD")?),
        ("root-image", required_path("CRUCIBLE_ROOT_IMAGE")?),
        (
            "executor-deployment",
            required_path("CRUCIBLE_FLIGHT_DEPLOYMENT")?,
        ),
        ("component-authority", authority.to_owned()),
    ];
    paths
        .into_iter()
        .map(|(label, path)| {
            let file = fs::File::open(&path)?;
            let bytes = file.metadata()?.len();
            let hash = ContentHash::from_reader(file)?;
            Ok(GuestChoiceImmutableInput { label, bytes, hash })
        })
        .collect()
}

fn attest_guest_choice_immutable_inputs(
    stage: &str,
    expected: &[GuestChoiceImmutableInput],
    authority: &Path,
) -> Result<(), Box<dyn Error>> {
    let observed = guest_choice_immutable_inputs(authority)?;
    if observed != expected {
        return Err(format!(
            "guest-choice immutable launch inputs changed before {stage}: expected={expected:?} observed={observed:?}"
        )
        .into());
    }

    for input in observed {
        println!(
            "guest_choice_immutable_input stage={stage} input={} bytes={} hash={}",
            input.label,
            input.bytes,
            input.hash.to_hex(),
        );
    }
    Ok(())
}

fn require_empty_guest_choice_run_root(stage: &str) -> Result<(), Box<dyn Error>> {
    let root = required_path("CRUCIBLE_FLIGHT_RUN_ROOT")?;
    let mut entries = Vec::new();
    for entry in fs::read_dir(&root)?.take(MAX_DIAGNOSTIC_ENTRIES) {
        entries.push(entry?.file_name());
    }
    if !entries.is_empty() {
        return Err(format!(
            "guest-choice fresh run root is not empty before {stage}: root={} entries={entries:?}",
            root.display()
        )
        .into());
    }

    println!(
        "guest_choice_fresh_run_root_empty stage={stage} root={}",
        root.display()
    );
    Ok(())
}

fn start_packaged_service(
    fixture: &FlightFixture,
    authority: &Path,
) -> Result<CampaignServiceChild, Box<dyn Error>> {
    let deployment = required_path("CRUCIBLE_FLIGHT_DEPLOYMENT")?;
    let qemu = required_path("CRUCIBLE_FLIGHT_QEMU")?;
    let plugin = required_path("CRUCIBLE_FLIGHT_PLUGIN")?;
    start_packaged_service_with_artifacts(fixture, authority, &deployment, &qemu, &plugin)
}

fn start_packaged_service_with_artifacts(
    fixture: &FlightFixture,
    authority: &Path,
    deployment: &Path,
    qemu: &Path,
    plugin: &Path,
) -> Result<CampaignServiceChild, Box<dyn Error>> {
    let executor_socket = fixture._temporary.path().join("guest-choice-executor.sock");
    let mut invocation = fixture.service_command(None);
    invocation
        .arg("--qemu")
        .arg(qemu)
        .arg("--plugin")
        .arg(plugin)
        .args([
            "--production-qemu",
            "--qemu-rendezvous-icount",
            GUEST_CHOICE_RENDEZVOUS_ICOUNT,
            "--campaign-runtime-all",
            "--campaign-component-authority",
        ])
        .arg(authority)
        .arg("--campaign-packaged-executor")
        .arg(deployment)
        .arg("--campaign-executor-socket")
        .arg(executor_socket);
    fixture.start_service_command(invocation, Duration::from_secs(120))
}

fn grant_and_start_guest_choice_campaign(fixture: &FlightFixture) -> Result<(), Box<dyn Error>> {
    let initial = campaign_status(fixture)?;
    run_json(
        connected_campaign(fixture)
            .args([
                "budget",
                CAMPAIGN,
                "--expected",
                &json_string(&initial, "snapshot")?,
                "--command",
            ])
            .arg("55".repeat(32))
            .args(["add", "16", "--proposals", "16"]),
        "grant guest-choice campaign budget",
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
            .arg("56".repeat(32)),
        "start guest-choice campaign",
    )?;
    Ok(())
}

pub(crate) fn wait_for_choice(
    fixture: &FlightFixture,
    selectable: &str,
    parent_artifact: &str,
    parent_configuration: &str,
) -> Result<PublicChoice, Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut cursor = None;
    let mut last_head = None;
    let mut last_choices = None;
    let matched = wait_for_process_observation(deadline, || {
        let head = campaign_watch(fixture, cursor.as_deref())?;
        let snapshot = json_string(&head, "snapshot")?;
        let advanced = head["advanced"]
            .as_bool()
            .ok_or("campaign watch omitted its cursor-advance verdict")?;
        if cursor.as_deref() == Some(snapshot.as_str()) {
            if advanced {
                return Err("campaign watch advanced without changing its snapshot".into());
            }
            return Ok(None);
        }
        if !advanced {
            return Err("campaign watch changed its snapshot without advancing".into());
        }
        cursor = Some(snapshot.clone());

        let choices_output = connected_campaign(fixture)
            .args([
                "choices",
                CAMPAIGN,
                "--snapshot",
                &snapshot,
                "--limit",
                "8",
                "--pages",
                "16",
            ])
            .output()?;
        if is_stale_snapshot_response(&choices_output) {
            return Ok(None);
        }
        let choices = parse_json_output(choices_output, "list guest-choice opportunities")?;
        assert_eq!(json_string(&choices, "snapshot")?, snapshot);
        if choices["complete"] != true {
            return Err(format!(
                "guest-choice scan did not reach authenticated end-of-page at snapshot {snapshot}: {choices}"
            )
            .into());
        }
        last_head = Some(head);
        last_choices = Some(choices.clone());

        let entries = choices["entries"]
            .as_array()
            .ok_or("campaign choices entries are not an array")?;
        let mut matched = None;
        for entry in entries {
            let opportunity = json_string(entry, "opportunity")?;
            let declaration_output = connected_campaign(fixture)
                .args([
                    "choice-object",
                    CAMPAIGN,
                    "--snapshot",
                    &snapshot,
                    "--opportunity",
                    &opportunity,
                    "--kind",
                    "declaration",
                ])
                .output()?;
            if is_stale_snapshot_response(&declaration_output) {
                return Ok(None);
            }
            let declaration =
                parse_json_output(declaration_output, "inspect guest-choice declaration")?;
            assert_eq!(json_string(&declaration, "snapshot")?, snapshot);
            let opportunity_view = &declaration["object"]["opportunity"];
            assert_eq!(json_string(opportunity_view, "opportunity")?, opportunity);
            if declaration["object"]["name"] == selectable {
                let semantic_opportunity = json_string(opportunity_view, "semantic_opportunity")?;
                let branch_point =
                    derive_branch_point(parent_configuration, &semantic_opportunity)?;
                let Some(authenticated_for_parent) = choice_is_authenticated_for_parent(
                    fixture,
                    &snapshot,
                    &opportunity,
                    &semantic_opportunity,
                    &branch_point,
                )?
                else {
                    return Ok(None);
                };
                if !authenticated_for_parent {
                    continue;
                }
                let choice = PublicChoice {
                    opportunity,
                    parent: parent_artifact.to_owned(),
                    branch_point,
                    domain: json_string(opportunity_view, "domain")?,
                    domain_kind: json_string(&declaration["object"], "domain_kind")?,
                };
                if matched.replace(choice).is_some() {
                    return Err(format!(
                        "selectable `{selectable}` matched multiple authenticated opportunities at snapshot {snapshot}"
                    )
                    .into());
                }
            }
        }
        Ok(matched)
    })?;
    if let Some(choice) = matched {
        return Ok(choice);
    }

    Err(format!(
        "campaign did not expose selectable `{selectable}` for parent artifact {parent_artifact} at configuration {parent_configuration}; status={:?}; choices={:?}; attempts={:?}",
        last_head,
        last_choices,
        attempt_states(fixture)?
    )
    .into())
}

fn campaign_watch(fixture: &FlightFixture, after: Option<&str>) -> Result<Value, Box<dyn Error>> {
    let mut command = connected_campaign(fixture);
    command.args(["watch", CAMPAIGN]);
    if let Some(after) = after {
        command.args(["--after", after]);
    }
    run_json(&mut command, "watch guest-choice campaign head")
}

fn choice_is_authenticated_for_parent(
    fixture: &FlightFixture,
    snapshot: &str,
    opportunity: &str,
    semantic_opportunity: &str,
    branch_point: &str,
) -> Result<Option<bool>, Box<dyn Error>> {
    let opportunity_id = ChoiceOpportunityId::parse(opportunity)?;
    let branch_point = BranchPointId::parse(branch_point)?;
    let mut canonical = Vec::new();
    canonical.extend_from_slice(&branch_point.as_hash().as_bytes());
    canonical.extend_from_slice(opportunity_id.content_id().encode().as_bytes());
    let membership_key =
        CampaignHash::derive("crucible.campaign-branch-point-opportunity.v1", &canonical).to_hex();

    let Some(membership_present) =
        membership_key_is_in_authenticated_graph(fixture, snapshot, &membership_key)?
    else {
        return Ok(None);
    };
    if !membership_present {
        return Ok(Some(false));
    }

    let output = connected_campaign(fixture)
        .args([
            "graph-object",
            CAMPAIGN,
            "--snapshot",
            snapshot,
            "--key",
            &membership_key,
        ])
        .output()?;
    if !output.status.success() {
        if is_stale_snapshot_response(&output) {
            return Ok(None);
        }
        require_success(&output, "authenticate guest-choice parent membership")?;
        return Ok(Some(false));
    }

    let membership = parse_json_output(output, "authenticate guest-choice parent membership")?;
    assert_eq!(json_string(&membership, "snapshot")?, snapshot);
    assert_eq!(json_string(&membership["object"], "key")?, membership_key);
    assert_eq!(membership["object"]["kind"], "opportunity");
    assert_eq!(
        json_string(&membership["object"], "object")?,
        opportunity_id.content_id().to_string()
    );
    assert_eq!(
        json_string(&membership["object"], "opportunity")?,
        opportunity
    );
    assert_eq!(
        json_string(&membership["object"], "semantic_opportunity")?,
        semantic_opportunity
    );
    Ok(Some(true))
}

fn membership_key_is_in_authenticated_graph(
    fixture: &FlightFixture,
    snapshot: &str,
    membership_key: &str,
) -> Result<Option<bool>, Box<dyn Error>> {
    let output = connected_campaign(fixture)
        .args([
            "graph",
            CAMPAIGN,
            "--snapshot",
            snapshot,
            "--limit",
            "256",
            "--pages",
            "256",
        ])
        .output()?;
    if is_stale_snapshot_response(&output) {
        return Ok(None);
    }

    let graph = parse_json_output(output, "scan authenticated campaign graph")?;
    authenticated_graph_contains_key(&graph, snapshot, membership_key).map(Some)
}

fn authenticated_graph_contains_key(
    graph: &Value,
    snapshot: &str,
    membership_key: &str,
) -> Result<bool, Box<dyn Error>> {
    if graph["operation"] != "graph" {
        return Err("campaign graph scan returned the wrong operation".into());
    }
    if json_string(graph, "snapshot")? != snapshot {
        return Err("campaign graph scan returned the wrong snapshot".into());
    }
    if graph["complete"] != true || !graph["next_after"].is_null() {
        return Err(format!(
            "campaign graph scan did not reach authenticated end-of-page at snapshot {snapshot}: {graph}"
        )
        .into());
    }

    let entries = graph["entries"]
        .as_array()
        .ok_or("campaign graph entries are not an array")?;
    let mut found = false;
    for entry in entries {
        if entry["kind"] != "graph" {
            return Err("campaign graph scan returned a non-graph entry".into());
        }
        let key = json_string(entry, "key")?;
        CampaignHash::parse(&key)?;
        if key == membership_key {
            if found {
                return Err(format!(
                    "campaign graph scan returned duplicate membership key {membership_key}"
                )
                .into());
            }
            found = true;
        }
    }
    Ok(found)
}

#[test]
fn parent_membership_presence_requires_a_complete_authenticated_graph_scan() {
    let snapshot = "snapshot-a";
    let membership_key = "11".repeat(32);
    let unrelated_key = "22".repeat(32);
    let graph = serde_json::json!({
        "operation": "graph",
        "snapshot": snapshot,
        "complete": true,
        "entries": [
            {
                "kind": "graph",
                "key": unrelated_key,
                "object": "unrelated-object"
            }
        ]
    });

    assert!(
        !authenticated_graph_contains_key(&graph, snapshot, &membership_key)
            .expect("complete authenticated absence")
    );

    let mut present = graph.clone();
    present["entries"]
        .as_array_mut()
        .expect("graph entries")
        .push(serde_json::json!({
            "kind": "graph",
            "key": membership_key,
            "object": "membership-object"
        }));
    assert!(
        authenticated_graph_contains_key(&present, snapshot, &membership_key)
            .expect("authenticated membership presence")
    );

    let mut incomplete = graph;
    incomplete["complete"] = false.into();
    incomplete["next_after"] = "33".repeat(32).into();
    assert!(
        authenticated_graph_contains_key(&incomplete, snapshot, &membership_key)
            .expect_err("truncated graph cannot prove absence")
            .to_string()
            .contains("did not reach authenticated end-of-page")
    );
}

fn is_stale_snapshot_response(output: &std::process::Output) -> bool {
    // Live feedback may advance the head between reading it and a proof-bound
    // request. Only that exact consistency response permits a retry.
    output.status.code() == Some(4)
        && String::from_utf8_lossy(&output.stderr).contains("campaign request used stale snapshot")
}

#[test]
fn guest_choice_refresh_classifies_only_explicit_stale_snapshot_failures() {
    use std::os::unix::process::ExitStatusExt;

    let output = |status, stderr: &str| std::process::Output {
        status: std::process::ExitStatus::from_raw(status << 8),
        stdout: Vec::new(),
        stderr: stderr.as_bytes().to_vec(),
    };

    assert!(is_stale_snapshot_response(&output(
        4,
        "crucible: campaign choices query failed: campaign request used stale snapshot old; current snapshot is new",
    )));
    assert!(is_stale_snapshot_response(&output(
        4,
        "crucible: campaign branch failed: campaign request used stale snapshot old; current snapshot is new",
    )));
    assert!(!is_stale_snapshot_response(&output(
        4,
        "crucible: campaign choices query failed: proof validation failed",
    )));
    assert!(!is_stale_snapshot_response(&output(
        0,
        "campaign request used stale snapshot",
    )));
}

fn derive_branch_point(
    parent_configuration: &str,
    semantic_opportunity: &str,
) -> Result<String, Box<dyn Error>> {
    let parent = ConfigurationId::from_hash(CampaignHash::parse(parent_configuration)?);
    let opportunity = ChoiceOpportunitySemanticId::parse(semantic_opportunity)?;
    let mut canonical = Vec::with_capacity(64);
    canonical.extend_from_slice(&parent.as_hash().as_bytes());
    canonical.extend_from_slice(&opportunity.as_hash().as_bytes());
    Ok(
        BranchPointId::from_hash(CampaignHash::derive("crucible.branch-point.v1", &canonical))
            .to_string(),
    )
}

pub(crate) fn submit_choice(
    fixture: &FlightFixture,
    choice: &PublicChoice,
    value: &str,
    stop: &str,
    command_byte: u8,
) -> Result<Value, Box<dyn Error>> {
    let command = format!("{command_byte:02x}").repeat(32);
    for _ in 0..MAX_STALE_BRANCH_RETRIES {
        let head = campaign_status(fixture)?;
        let output = connected_campaign(fixture)
            .args([
                "branch",
                CAMPAIGN,
                "--expected",
                &json_string(&head, "snapshot")?,
                "--command",
                &command,
                "--branch-point",
                &choice.branch_point,
                "--parent",
                &choice.parent,
                "--opportunity",
                &choice.opportunity,
                "--domain",
                &choice.domain,
                "--value",
                value,
                "--attempts",
                "1",
                "--stop",
                stop,
            ])
            .output()?;
        if is_stale_snapshot_response(&output) {
            continue;
        }
        return parse_json_output(output, "submit guest-choice branch");
    }

    Err(format!(
        "guest-choice branch remained stale across {MAX_STALE_BRANCH_RETRIES} snapshot reads"
    )
    .into())
}

pub(crate) fn accepted_branch_request(submission: &Value) -> Result<String, Box<dyn Error>> {
    assert_eq!(submission["operation"], "branch");
    assert_eq!(submission["budget"]["maximum_attempts"], 1);
    json_string(submission, "request")
}

pub(crate) fn attempt_states(
    fixture: &FlightFixture,
) -> Result<BTreeMap<AttemptExecutionKey, AttemptRuntimeState>, Box<dyn Error>> {
    let mut states = BTreeMap::new();
    let complete = visit_directory_attempt_states_bounded(
        &fixture.state.join("executor-ledger"),
        MAX_GUEST_CHOICE_ATTEMPT_RECORDS,
        &mut |key, state| {
            states.insert(key, state);
        },
    )?;
    if !complete {
        return Err(format!(
            "guest-choice attempt inventory exceeded {} records",
            MAX_GUEST_CHOICE_ATTEMPT_RECORDS
        )
        .into());
    }
    Ok(states)
}

pub(crate) fn wait_for_new_completed_attempt(
    fixture: &FlightFixture,
    service: &mut CampaignServiceChild,
    known: &BTreeSet<AttemptExecutionKey>,
    request: &str,
) -> Result<AttemptExecutionKey, Box<dyn Error>> {
    wait_for_new_completed_attempt_with_timeout(
        fixture,
        service,
        known,
        request,
        Duration::from_secs(120),
    )
}

pub(crate) fn wait_for_new_completed_attempt_with_timeout(
    fixture: &FlightFixture,
    service: &mut CampaignServiceChild,
    known: &BTreeSet<AttemptExecutionKey>,
    request: &str,
    timeout: Duration,
) -> Result<AttemptExecutionKey, Box<dyn Error>> {
    wait_for_new_attempt(
        fixture,
        service,
        known,
        "completed",
        Some(request),
        timeout,
        |state| matches!(state, AttemptRuntimeState::Completed { .. }),
    )
}

pub(crate) fn wait_for_initial_discovery(
    fixture: &FlightFixture,
    service: &mut CampaignServiceChild,
    genesis_artifact: &str,
) -> Result<(AttemptExecutionKey, Value), Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(300);
    let discovery = wait_for_process_observation(deadline, || {
        for (key, state) in attempt_states(fixture)? {
            if !matches!(state, AttemptRuntimeState::Completed { .. })
                || state.origin() != AttemptExecutionOrigin::Initial
            {
                continue;
            }

            let explanation = wait_for_attempt_observation(fixture, key)?;
            if explanation["attempt"]["start"] == "discover"
                && explanation["attempt"]["configuration"] == genesis_artifact
            {
                return Ok(Some((key, explanation)));
            }
        }
        Ok(None)
    })?;
    if let Some(discovery) = discovery {
        return Ok(discovery);
    }

    let diagnostics = campaign_execution_diagnostics(fixture, service, &BTreeSet::new());
    Err(format!(
        "initial guest-choice discovery from genesis artifact {genesis_artifact} did not complete; {diagnostics}"
    )
    .into())
}

fn campaign_execution_diagnostics(
    fixture: &FlightFixture,
    service: &mut CampaignServiceChild,
    known_attempts: &BTreeSet<AttemptExecutionKey>,
) -> String {
    let boundary_log = fixture._temporary.path().join(format!(
        "guest-selectable-boundary-{}.log",
        service.child.id()
    ));
    let boundary_summary =
        match capture_guest_selectable_boundary_events(fixture, service, "failure-diagnostics") {
            Ok(lines) => format!(
                "captured(count={}, raw_log={})",
                lines.len(),
                boundary_log.display()
            ),
            Err(error) => format!("capture-failed({error})"),
        };
    let status = campaign_status(fixture);
    let ledger = attempt_states(fixture);
    let service_process = match service.child.try_wait() {
        Ok(Some(exit)) => format!("exited({exit})"),
        Ok(None) => format!("running(pid={})", service.child.id()),
        Err(error) => format!("status-error({error})"),
    };
    let mut diagnostics = String::new();
    let _ = write!(
        diagnostics,
        "status={status:?}; ledger={ledger:?}; service={service_process}; guest_selectable_boundaries={boundary_summary}; service_stderr={:?}",
        service.stderr_tail(),
    );
    append_new_attempt_explanations(fixture, known_attempts, &status, &ledger, &mut diagnostics);

    append_diagnostic_tree("campaign-state", &fixture.state, &mut diagnostics);
    if let Some(run_root) = std::env::var_os("CRUCIBLE_FLIGHT_RUN_ROOT") {
        append_diagnostic_tree(
            "attempt-run-root",
            &PathBuf::from(run_root),
            &mut diagnostics,
        );
    }
    append_process_diagnostics(&mut diagnostics);
    diagnostics
}

fn capture_guest_selectable_boundary_events(
    fixture: &FlightFixture,
    service: &CampaignServiceChild,
    capture_stage: &str,
) -> Result<Vec<String>, Box<dyn Error>> {
    let lines = service.stderr_lines_with_prefix(
        GUEST_SELECTABLE_BOUNDARY_PREFIX,
        MAX_GUEST_SELECTABLE_BOUNDARY_LINES,
        MAX_GUEST_SELECTABLE_BOUNDARY_LINE_BYTES,
    )?;
    let path = fixture._temporary.path().join(format!(
        "guest-selectable-boundary-{}.log",
        service.child.id()
    ));
    let mut raw = lines.join("\n");
    if !raw.is_empty() {
        raw.push('\n');
    }
    fs::write(&path, raw)?;

    println!(
        "guest_choice_boundary_capture_stage={capture_stage} service_pid={} event_count={} raw_log={}",
        service.child.id(),
        lines.len(),
        path.display(),
    );
    for line in &lines {
        println!("{line}");
    }
    let _ = std::io::Write::flush(&mut std::io::stdout());
    Ok(lines)
}

fn require_guest_selectable_boundary_stage(
    lines: &[String],
    required_stage: &str,
) -> Result<(), Box<dyn Error>> {
    let field = format!(" stage={required_stage} ");
    if lines.iter().any(|line| line.contains(&field)) {
        return Ok(());
    }

    Err(
        format!("guest-choice flight captured no `{required_stage}` selectable boundary record")
            .into(),
    )
}

fn append_new_attempt_explanations(
    fixture: &FlightFixture,
    known_attempts: &BTreeSet<AttemptExecutionKey>,
    status: &Result<Value, Box<dyn Error>>,
    ledger: &Result<BTreeMap<AttemptExecutionKey, AttemptRuntimeState>, Box<dyn Error>>,
    diagnostics: &mut String,
) {
    diagnostics.push_str("; new_attempts=[");
    let (Ok(status), Ok(ledger)) = (status, ledger) else {
        diagnostics.push_str("<status-or-ledger-unavailable>]");
        return;
    };
    let Ok(snapshot) = json_string(status, "snapshot") else {
        diagnostics.push_str("<snapshot-unavailable>]");
        return;
    };
    let new_attempt_count = ledger
        .keys()
        .filter(|key| !known_attempts.contains(key))
        .count();

    for (key, state) in ledger
        .iter()
        .filter(|(key, _)| !known_attempts.contains(key))
        .take(MAX_DIAGNOSTIC_ATTEMPTS)
    {
        let attempt = key.attempt().to_string();
        let output = connected_campaign(fixture)
            .args([
                "explain-attempt",
                CAMPAIGN,
                "--snapshot",
                &snapshot,
                "--attempt",
                &attempt,
            ])
            .output();
        match output {
            Ok(output) => {
                let _ = write!(
                    diagnostics,
                    "key={key:?} state={state:?} exit={:?} stdout={:?} stderr={:?}; ",
                    output.status.code(),
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr),
                );
            }
            Err(error) => {
                let _ = write!(
                    diagnostics,
                    "key={key:?} state={state:?} query_error={error}; "
                );
            }
        }
    }
    if new_attempt_count > MAX_DIAGNOSTIC_ATTEMPTS {
        let omitted = new_attempt_count - MAX_DIAGNOSTIC_ATTEMPTS;
        let _ = write!(diagnostics, "<{omitted} additional attempts omitted>; ");
    }
    diagnostics.push(']');
}

fn append_diagnostic_tree(label: &str, root: &Path, diagnostics: &mut String) {
    let _ = write!(diagnostics, "; {label}={} [", root.display());
    let mut visited = 0;
    append_diagnostic_directory(root, root, &mut visited, diagnostics);
    if visited == MAX_DIAGNOSTIC_ENTRIES {
        let _ = write!(diagnostics, "<entry-limit>; ");
    }
    diagnostics.push(']');
}

fn append_diagnostic_directory(
    root: &Path,
    directory: &Path,
    visited: &mut usize,
    diagnostics: &mut String,
) {
    if *visited >= MAX_DIAGNOSTIC_ENTRIES {
        return;
    }
    let Ok(entries) = fs::read_dir(directory) else {
        let _ = write!(diagnostics, "{}=<unreadable>; ", directory.display());
        return;
    };
    let mut entries = entries.filter_map(Result::ok).collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        if *visited >= MAX_DIAGNOSTIC_ENTRIES {
            return;
        }
        *visited += 1;

        let path = entry.path();
        let relative = path.strip_prefix(root).unwrap_or(&path);
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            let _ = write!(diagnostics, "{}=<metadata-error>; ", relative.display());
            continue;
        };
        if metadata.is_dir() {
            let _ = write!(diagnostics, "{}/; ", relative.display());
            append_diagnostic_directory(root, &path, visited, diagnostics);
        } else if metadata.is_file() {
            let _ = write!(diagnostics, "{}={}B", relative.display(), metadata.len());
            if diagnostic_text_file(&path) {
                let tail = diagnostic_file_tail(&path, metadata.len());
                let _ = write!(diagnostics, " tail={tail:?}");
            }
            diagnostics.push_str("; ");
        } else {
            let _ = write!(diagnostics, "{}=<special>; ", relative.display());
        }
    }
}

fn diagnostic_text_file(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    name.ends_with(".json")
        || name.ends_with(".jsonl")
        || name.ends_with(".log")
        || name.ends_with(".txt")
        || name.starts_with("run-state")
}

fn diagnostic_file_tail(path: &Path, length: u64) -> String {
    let Ok(mut file) = fs::File::open(path) else {
        return String::from("<open-error>");
    };
    let start = length.saturating_sub(MAX_DIAGNOSTIC_FILE_BYTES);
    if file.seek(SeekFrom::Start(start)).is_err() {
        return String::from("<seek-error>");
    }
    let mut bytes = Vec::new();
    if file
        .take(MAX_DIAGNOSTIC_FILE_BYTES)
        .read_to_end(&mut bytes)
        .is_err()
    {
        return String::from("<read-error>");
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

fn attest_fingerprint_enabled_qemu_descendants(
    service: &CampaignServiceChild,
    phase: &str,
) -> Result<(), Box<dyn Error>> {
    let expected_qemu = required_path("CRUCIBLE_FLIGHT_QEMU")?
        .to_string_lossy()
        .into_owned();
    let expected_plugin = required_path("CRUCIBLE_FLIGHT_PLUGIN")?
        .to_string_lossy()
        .into_owned();
    let deadline = Instant::now() + Duration::from_secs(10);
    let observed = wait_for_process_observation(deadline, || {
        let descendants = descendant_process_commands(service.child.id())?;
        let qemu_commands = descendants
            .into_iter()
            .filter(|(_pid, arguments)| arguments.first() == Some(&expected_qemu))
            .collect::<Vec<_>>();
        if attest_fingerprint_enabled_qemu_launches(&qemu_commands, &expected_plugin, phase)? {
            return Ok(Some(()));
        }
        Ok(None)
    })?;
    if observed.is_some() {
        return Ok(());
    }

    Err(format!(
        "{phase} exposed no live `{expected_qemu}` descendant of campaign service {} within 10s",
        service.child.id()
    )
    .into())
}

fn attest_fingerprint_enabled_qemu_launches(
    qemu_commands: &[(u32, Vec<String>)],
    expected_plugin: &str,
    phase: &str,
) -> Result<bool, Box<dyn Error>> {
    let expected_prefix = format!("{expected_plugin},");
    let mut completed_launches = 0;
    for (pid, arguments) in qemu_commands {
        let Some(plugin_configuration) = arguments
            .windows(2)
            .find(|pair| pair[0] == "-plugin")
            .map(|pair| pair[1].as_str())
        else {
            // The stopped white-box setup probe deliberately omits the plugin.
            // Presence of the production plugin argument is the concrete point
            // at which the launch is complete enough for this assertion.
            continue;
        };
        completed_launches += 1;
        if !plugin_configuration.starts_with(&expected_prefix)
            || !plugin_configuration
                .split(',')
                .any(|argument| argument == "fingerprint=on")
        {
            return Err(format!(
                "{phase} QEMU descendant {pid} did not enable the packaged fingerprint sampler: {plugin_configuration:?}"
            )
            .into());
        }
    }
    Ok(completed_launches != 0)
}

#[test]
fn fingerprint_attestation_waits_past_setup_probe_until_production_launch() {
    let expected_plugin = "/nix/store/plugin/lib/crucible.so";
    let setup_probe = (
        41,
        vec![
            String::from("/nix/store/qemu/bin/qemu-system-x86_64"),
            String::from("-S"),
        ],
    );
    assert!(
        !attest_fingerprint_enabled_qemu_launches(
            std::slice::from_ref(&setup_probe),
            expected_plugin,
            "setup race",
        )
        .expect("setup probe remains an incomplete launch")
    );

    let production = (
        42,
        vec![
            String::from("/nix/store/qemu/bin/qemu-system-x86_64"),
            String::from("-plugin"),
            format!("{expected_plugin},fingerprint=on,whitebox=on"),
        ],
    );
    assert!(
        attest_fingerprint_enabled_qemu_launches(
            &[setup_probe, production],
            expected_plugin,
            "production launch",
        )
        .expect("production launch attestation")
    );
}

fn wait_for_new_running_attempt(
    fixture: &FlightFixture,
    service: &mut CampaignServiceChild,
    known: &BTreeSet<AttemptExecutionKey>,
    request: &str,
) -> Result<AttemptExecutionKey, Box<dyn Error>> {
    wait_for_new_attempt(
        fixture,
        service,
        known,
        "running",
        Some(request),
        GUEST_CHOICE_ATTEMPT_WAIT,
        |state| matches!(state, AttemptRuntimeState::Running { .. }),
    )
}

fn wait_for_new_attempt(
    fixture: &FlightFixture,
    service: &mut CampaignServiceChild,
    known: &BTreeSet<AttemptExecutionKey>,
    expected_state: &str,
    request: Option<&str>,
    timeout: Duration,
    predicate: impl Fn(AttemptRuntimeState) -> bool,
) -> Result<AttemptExecutionKey, Box<dyn Error>> {
    let deadline = Instant::now() + timeout;
    let attempt = wait_for_process_observation(deadline, || {
        let states = attempt_states(fixture)?;
        if let Some((key, _)) = states
            .into_iter()
            .find(|(key, state)| !known.contains(key) && predicate(*state))
        {
            return Ok(Some(key));
        }
        Ok(None)
    })?;
    if let Some(attempt) = attempt {
        return Ok(attempt);
    }

    let request = request.unwrap_or("<not-captured>");
    let diagnostics = campaign_execution_diagnostics(fixture, service, known);
    Err(format!(
        "campaign attempt for branch request {request} did not reach executor state {expected_state}; {diagnostics}"
    )
    .into())
}

pub(crate) fn wait_for_attempt_observation(
    fixture: &FlightFixture,
    key: AttemptExecutionKey,
) -> Result<Value, Box<dyn Error>> {
    wait_for_attempt_explanation_matching(fixture, key, true)
}

fn wait_for_attempt_explanation(
    fixture: &FlightFixture,
    key: AttemptExecutionKey,
) -> Result<Value, Box<dyn Error>> {
    wait_for_attempt_explanation_matching(fixture, key, false)
}

fn wait_for_attempt_explanation_matching(
    fixture: &FlightFixture,
    key: AttemptExecutionKey,
    require_observation: bool,
) -> Result<Value, Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut cursor = None;
    let mut last_output = None;
    let explanation = wait_for_process_observation(deadline, || {
        let head = campaign_watch(fixture, cursor.as_deref())?;
        let snapshot = json_string(&head, "snapshot")?;
        let advanced = head["advanced"]
            .as_bool()
            .ok_or("campaign watch omitted its cursor-advance verdict")?;
        if cursor.as_deref() == Some(snapshot.as_str()) {
            if advanced {
                return Err("campaign watch advanced without changing its snapshot".into());
            }
            return Ok(None);
        }
        if !advanced {
            return Err("campaign watch changed its snapshot without advancing".into());
        }
        cursor = Some(snapshot.clone());

        let output = connected_campaign(fixture)
            .args([
                "explain-attempt",
                CAMPAIGN,
                "--snapshot",
                &snapshot,
                "--attempt",
                &key.attempt().to_string(),
            ])
            .output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let pending = stderr.contains("campaign-attempt-is-not-in-snapshot")
                || stderr.contains("campaign request used stale snapshot");
            if pending {
                last_output = Some(output);
                return Ok(None);
            }
            return parse_json_output(output, "explain guest-choice attempt").map(Some);
        }

        let explanation = parse_json_output(output, "explain guest-choice attempt")?;
        if !require_observation || !explanation["observation"].is_null() {
            return Ok(Some(explanation));
        }
        Ok(None)
    })?;
    if let Some(explanation) = explanation {
        return Ok(explanation);
    }

    let (stdout, stderr) = last_output
        .map(|output| (output.stdout, output.stderr))
        .unwrap_or_default();
    Err(format!(
        "campaign did not expose attempt {}; stdout=`{}` stderr=`{}`",
        key.attempt(),
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr)
    )
    .into())
}

fn capture_checkpoint_after_progress(
    fixture: &FlightFixture,
    key: AttemptExecutionKey,
    command_sequence: &mut u64,
    previous_checkpoint: Option<ExactCheckpointId>,
) -> Result<ExactCheckpointId, Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(180);
    let captured = wait_for_process_observation(deadline, || {
        // A Running ledger state can precede the next quantum. Only the
        // replay-authenticated marker in the promoted checkpoint acknowledges
        // guest progress, so an unchanged marker is resumed and observed again.
        pause_for_exact_checkpoint(fixture, &next_command_identity(command_sequence)?)?;
        let checkpoint = wait_for_promoted_checkpoint(fixture, key)?;
        if Some(checkpoint) != previous_checkpoint {
            return Ok(Some(checkpoint));
        }

        resume_campaign(fixture, &next_command_identity(command_sequence)?)?;
        wait_for_resumed_attempt(fixture, key, checkpoint)?;
        Ok(None)
    })?;
    if let Some(captured) = captured {
        return Ok(captured);
    }

    Err(format!(
        "attempt {} did not publish a new promoted checkpoint within 180s",
        key.attempt()
    )
    .into())
}

fn next_command_identity(command_sequence: &mut u64) -> Result<String, Box<dyn Error>> {
    let current = *command_sequence;
    *command_sequence = command_sequence
        .checked_add(1)
        .ok_or("guest-choice command identity sequence overflowed")?;
    Ok(format!("{current:064x}"))
}

fn pause_for_exact_checkpoint(
    fixture: &FlightFixture,
    command_identity: &str,
) -> Result<(), Box<dyn Error>> {
    let head = campaign_status(fixture)?;
    run_json(
        connected_campaign(fixture)
            .args([
                "pause",
                CAMPAIGN,
                "--expected",
                &json_string(&head, "snapshot")?,
                "--command",
            ])
            .arg(command_identity)
            .args(["--active", "checkpoint"]),
        "pause guest-choice campaign at exact checkpoint",
    )?;
    Ok(())
}

fn wait_for_promoted_checkpoint(
    fixture: &FlightFixture,
    key: AttemptExecutionKey,
) -> Result<ExactCheckpointId, Box<dyn Error>> {
    // The two-node oracle replays roughly 750 bounded QEMU advances. A 180s
    // wait stopped during the first node; a 360s diagnostic reached the peer
    // comparison. Allow margin for the strict comparison and publication.
    let deadline = Instant::now() + Duration::from_secs(480);
    let backend: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "guest-choice-checkpoint-inspection",
        &fixture.objects,
    ));
    let checkpoints = ExactCheckpointStore::new(backend, 1024 * 1024 * 1024)?;
    let checkpoint = wait_for_process_observation(deadline, || {
        if let Some(AttemptRuntimeState::Paused { checkpoint, .. }) =
            attempt_states(fixture)?.get(&key).copied()
            && checkpoints
                .load_attempt_checkpoint(checkpoint)
                .is_ok_and(|loaded| loaded.promotion_source().is_some())
        {
            return Ok(Some(checkpoint));
        }
        Ok(None)
    })?;
    if let Some(checkpoint) = checkpoint {
        return Ok(checkpoint);
    }

    Err(format!(
        "attempt {} did not publish a replay-validated exact checkpoint; ledger={:?}",
        key.attempt(),
        attempt_states(fixture)?
    )
    .into())
}

fn resume_campaign(fixture: &FlightFixture, command_identity: &str) -> Result<(), Box<dyn Error>> {
    let head = campaign_status(fixture)?;
    run_json(
        connected_campaign(fixture)
            .args([
                "resume",
                CAMPAIGN,
                "--expected",
                &json_string(&head, "snapshot")?,
                "--command",
            ])
            .arg(command_identity),
        "resume exact guest-choice campaign",
    )?;
    Ok(())
}

fn wait_for_resumed_attempt(
    fixture: &FlightFixture,
    key: AttemptExecutionKey,
    expected_checkpoint: ExactCheckpointId,
) -> Result<ExactCheckpointId, Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(120);
    let resumed = wait_for_process_observation(deadline, || {
        if let Some(AttemptRuntimeState::Running { origin, .. }) =
            attempt_states(fixture)?.get(&key).copied()
            && let AttemptExecutionOrigin::ExactCheckpoint { checkpoint, .. } = origin
        {
            if checkpoint != expected_checkpoint {
                return Err(format!(
                    "resumed attempt used checkpoint {checkpoint}, expected {expected_checkpoint}"
                )
                .into());
            }
            return Ok(Some(checkpoint));
        }
        Ok(None)
    })?;
    if let Some(checkpoint) = resumed {
        return Ok(checkpoint);
    }

    Err(format!(
        "attempt {} did not resume from exact checkpoint {expected_checkpoint}; ledger={:?}",
        key.attempt(),
        attempt_states(fixture)?
    )
    .into())
}

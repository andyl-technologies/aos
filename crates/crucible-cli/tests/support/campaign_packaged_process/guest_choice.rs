//! Real guest-choice, exact-checkpoint, and daemon-restart campaign flight.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::sync::Arc;

use super::*;
use crucible_api::{ProductionExactCheckpointResumeBasis, install_exact_checkpoint_closure};
use crucible_campaign::{
    AlternativeId, BranchPointId, CampaignHash, ChoiceClassContext, ChoiceDomain,
    ChoiceOpportunityId, ChoiceOpportunitySemanticId, ChoiceSource, ChoiceValue, ConfigurationId,
    DiscreteAlternative, DiscreteDomain, ExactCheckpointId, ExactRational, IntegerDomain,
    IntegerRepresentation, IntegerValue, SelectableDeclaration,
};
use crucible_core::{ObservableEventPayload, SchedulerEventLogPayload};
use crucible_daemon::{
    AttemptExecutionKey, AttemptExecutionOrigin, AttemptRuntimeState, ExactCheckpointStore,
    LoadedAttemptCheckpoint, visit_directory_attempt_states_bounded,
};

const FAST_ALTERNATIVE: &str = "0101010101010101010101010101010101010101010101010101010101010101";
const SAFE_ALTERNATIVE: &str = "0202020202020202020202020202020202020202020202020202020202020202";
const GUEST_CHOICE_RENDEZVOUS_ICOUNT: &str = "100000000";
const MAX_GUEST_CHOICE_ATTEMPT_RECORDS: usize = 65_536;
const MAX_DIAGNOSTIC_ATTEMPTS: usize = 16;
const MAX_DIAGNOSTIC_ENTRIES: usize = 256;
const MAX_DIAGNOSTIC_FILE_BYTES: u64 = 8 * 1024;

type ProcessCommand = (u32, Vec<String>);

#[test]
#[ignore = "requires dedicated cgroup-v2 and ext4 project-quota roots inside the VM check"]
fn public_guest_choices_survive_exact_checkpoint_and_daemon_restart() -> Result<(), Box<dyn Error>>
{
    let fixture = FlightFixture::new()?;
    let (compiled, scenario) = compile_guest_choice_campaign(&fixture)?;
    create_guest_choice_campaign(&fixture, &compiled)?;

    let authority = write_component_authority(&fixture)?;
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
        "campaign.recovery-policy",
        &discovery_parent,
        &discovery_parent_configuration,
    )?;

    let fast_submission = submit_choice(
        &fixture,
        &recovery,
        &format!("discrete:{FAST_ALTERNATIVE}"),
        "next-choice",
        0x61,
    )?;
    let fast_request = accepted_branch_request(&fast_submission)?;
    let fast_attempt =
        wait_for_new_completed_attempt(&fixture, &mut service, &known_attempts, &fast_request)?;
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
        "campaign.retry-quanta",
        &fast_parent,
        &fast_parent_configuration,
    )?;
    let fast_retry_submission =
        submit_choice(&fixture, &retry, "u64:7", "boundary:selected-fast-q7", 0x62)?;
    let fast_retry_request = accepted_branch_request(&fast_retry_submission)?;
    let fast_retry_attempt = wait_for_new_completed_attempt(
        &fixture,
        &mut service,
        &known_attempts,
        &fast_retry_request,
    )?;
    known_attempts.insert(fast_retry_attempt);
    let fast_retry_explanation = wait_for_attempt_observation(&fixture, fast_retry_attempt)?;
    assert_eq!(
        fast_retry_explanation["proposal"]["request"],
        fast_retry_request
    );
    assert_eq!(fast_retry_explanation["selection"]["value"], "u64:7");
    assert_eq!(
        fast_retry_explanation["observation"]["stop"],
        "reached:boundary:selected-fast-q7"
    );

    // A second branch proves that the result marker is computed from the
    // guest's replies rather than emitted unconditionally by the fixture.
    let safe_submission = submit_choice(
        &fixture,
        &recovery,
        &format!("discrete:{SAFE_ALTERNATIVE}"),
        "next-choice",
        0x63,
    )?;
    let safe_request = accepted_branch_request(&safe_submission)?;
    let safe_attempt =
        wait_for_new_completed_attempt(&fixture, &mut service, &known_attempts, &safe_request)?;
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
        "campaign.retry-quanta",
        &safe_parent,
        &safe_parent_configuration,
    )?;
    let safe_retry_submission = submit_choice(
        &fixture,
        &safe_retry,
        "u64:1",
        "boundary:selected-safe-q1",
        0x64,
    )?;
    let safe_retry_request = accepted_branch_request(&safe_retry_submission)?;
    let safe_retry_attempt = wait_for_new_completed_attempt(
        &fixture,
        &mut service,
        &known_attempts,
        &safe_retry_request,
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
        "reached:boundary:selected-safe-q1"
    );

    // Re-submit the fast/q7 branch with a terminal stop. The selected guest
    // parks after its marker, so checkpoint capture cannot race completion.
    let terminal_submission = submit_choice(&fixture, &retry, "u64:7", "terminal", 0x65)?;
    let terminal_request = accepted_branch_request(&terminal_submission)?;
    let terminal_attempt =
        wait_for_new_running_attempt(&fixture, &mut service, &known_attempts, &terminal_request)?;
    let terminal_before_pause = wait_for_attempt_explanation(&fixture, terminal_attempt)?;
    assert_eq!(terminal_before_pause["attempt"]["stop"], "terminal");
    assert_eq!(
        terminal_before_pause["proposal"]["request"],
        terminal_request
    );
    assert_eq!(terminal_before_pause["selection"]["value"], "u64:7");
    assert_eq!(
        terminal_before_pause["path"]["id"],
        fast_retry_explanation["path"]["id"]
    );
    attest_on_demand_qemu_descendants(&service, "pre-checkpoint terminal attempt")?;
    println!("\nguest_choice_initial_qemu_fingerprint_mode=on-demand-v1");

    let mut checkpoint_command = 0x70;
    let (checkpoint, before_restart) = capture_checkpoint_after_progress(
        &fixture,
        terminal_attempt,
        "selected-fast-q7",
        1,
        &mut checkpoint_command,
        &scenario,
    )?;
    let checkpoint_text = checkpoint.to_string();
    service.stop()?;

    let mut restarted = start_packaged_service(&fixture, &authority)?;
    let paused = campaign_status(&fixture)?;
    assert_eq!(paused["state"], "paused");
    attest_on_demand_qemu_descendants(&restarted, "restarted paused exact restore")?;
    println!("\nguest_choice_restarted_qemu_fingerprint_mode=on-demand-v1");
    resume_campaign(&fixture, next_command_byte(&mut checkpoint_command)?)?;
    let resumed = wait_for_resumed_attempt(&fixture, terminal_attempt, checkpoint)?;
    assert_eq!(resumed, checkpoint);

    let minimum_resumed_progress = before_restart
        .progress_sequence
        .checked_add(1)
        .ok_or("guest progress sequence overflowed")?;
    let (after_resume_checkpoint, after_resume) = capture_checkpoint_after_progress(
        &fixture,
        terminal_attempt,
        "selected-fast-q7",
        minimum_resumed_progress,
        &mut checkpoint_command,
        &scenario,
    )?;
    assert_ne!(after_resume_checkpoint, checkpoint);
    assert!(after_resume.event_count > before_restart.event_count);
    assert!(after_resume.progress_sequence > before_restart.progress_sequence);
    assert!(after_resume.progress_icount > before_restart.progress_icount);
    assert!(after_resume.progress_event_sequence >= before_restart.event_count);

    let resumed_explanation = wait_for_attempt_explanation(&fixture, terminal_attempt)?;
    assert_eq!(resumed_explanation["selection"]["value"], "u64:7");
    assert_eq!(
        resumed_explanation["path"]["id"],
        fast_retry_explanation["path"]["id"]
    );
    assert_eq!(
        fast_retry_explanation["observation"]["stop"],
        "reached:boundary:selected-fast-q7"
    );

    restarted.stop()?;

    println!("\nguest_choice_discrete_and_integer=true");
    println!("\nguest_choice_negative_result=true");
    println!("guest_choice_observed_marker=selected-fast-q7");
    println!("guest_choice_checkpoint={checkpoint_text}");
    println!("guest_choice_resumed_checkpoint={after_resume_checkpoint}");
    println!(
        "guest_choice_progress_sequence={}..{}",
        before_restart.progress_sequence, after_resume.progress_sequence
    );
    println!(
        "guest_choice_progress_icount={}..{}",
        before_restart.progress_icount, after_resume.progress_icount
    );
    println!("guest_choice_restart_process=true");
    println!("\nguest_choice_resume_source_exact=true");
    println!("\nguest_choice_post_resume_progress=true");
    Ok(())
}

#[derive(Clone, Debug)]
struct PublicChoice {
    opportunity: String,
    parent: String,
    branch_point: String,
    domain: String,
}

#[derive(Clone, Copy, Debug)]
struct CheckpointProgress {
    event_count: u64,
    progress_sequence: u64,
    progress_event_sequence: u64,
    progress_icount: u64,
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
    let world = World::from_nodes_and_links(vec![node], vec![])?;
    let selectables = guest_choice_selectables(&world)?;
    let graph = EventGraph::builder()
        .event("keep-selected-guest-running")
        .entrypoint()
        .action(Action::Group(Vec::new()))
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

fn guest_choice_selectables(world: &World) -> Result<ScenarioSelectables, Box<dyn Error>> {
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
        "campaign.recovery-policy",
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
        "campaign.retry-quanta",
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
) -> Result<(), Box<dyn Error>> {
    let root = fixture._temporary.path();
    let lineage_input = root.join("guest-choice-lineage.toml");
    let lineage = root.join("guest-choice-lineage.bin");
    fs::write(
        &lineage_input,
        format!(
            "schema_version = 1\nscenario = {:?}\nscenario_content = {:?}\ngenesis = {:?}\ngenesis_content = {:?}\ncrucible_version = \"0.1.0\"\nqemu_build = \"qemu-10.0-crucible\"\nscenario_schema = 3\nexact_closure_schema = 4\n[protocol_versions]\ncontrol = 2\nshared-memory = 5\n",
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
            r#"schema_version = 1
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

fn start_packaged_service(
    fixture: &FlightFixture,
    authority: &Path,
) -> Result<CampaignServiceChild, Box<dyn Error>> {
    let deployment = required_path("CRUCIBLE_FLIGHT_DEPLOYMENT")?;
    let executor_socket = fixture._temporary.path().join("guest-choice-executor.sock");
    let mut invocation = fixture.service_command(None);
    invocation
        .arg("--qemu")
        .arg(required_path("CRUCIBLE_FLIGHT_QEMU")?)
        .arg("--plugin")
        .arg(required_path("CRUCIBLE_FLIGHT_PLUGIN")?)
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

fn wait_for_choice(
    fixture: &FlightFixture,
    selectable: &str,
    parent_artifact: &str,
    parent_configuration: &str,
) -> Result<PublicChoice, Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        let head = campaign_status(fixture)?;
        let snapshot = json_string(&head, "snapshot")?;
        let choices = run_json(
            connected_campaign(fixture).args([
                "choices",
                CAMPAIGN,
                "--snapshot",
                &snapshot,
                "--limit",
                "8",
                "--pages",
                "16",
            ]),
            "list guest-choice opportunities",
        )?;
        assert_eq!(json_string(&choices, "snapshot")?, snapshot);
        if choices["complete"] != true {
            return Err(format!(
                "guest-choice scan did not reach authenticated end-of-page at snapshot {snapshot}: {choices}"
            )
            .into());
        }
        let entries = choices["entries"]
            .as_array()
            .ok_or("campaign choices entries are not an array")?;
        let mut matched = None;
        for entry in entries {
            let opportunity = json_string(entry, "opportunity")?;
            let declaration = run_json(
                connected_campaign(fixture).args([
                    "choice-object",
                    CAMPAIGN,
                    "--snapshot",
                    &snapshot,
                    "--opportunity",
                    &opportunity,
                    "--kind",
                    "declaration",
                ]),
                "inspect guest-choice declaration",
            )?;
            assert_eq!(json_string(&declaration, "snapshot")?, snapshot);
            let opportunity_view = &declaration["object"]["opportunity"];
            assert_eq!(json_string(opportunity_view, "opportunity")?, opportunity);
            if declaration["object"]["name"] == selectable {
                let semantic_opportunity = json_string(opportunity_view, "semantic_opportunity")?;
                let branch_point =
                    derive_branch_point(parent_configuration, &semantic_opportunity)?;
                if !choice_is_authenticated_for_parent(
                    fixture,
                    &snapshot,
                    &opportunity,
                    &semantic_opportunity,
                    &branch_point,
                )? {
                    continue;
                }
                let choice = PublicChoice {
                    opportunity,
                    parent: parent_artifact.to_owned(),
                    branch_point,
                    domain: json_string(opportunity_view, "domain")?,
                };
                if matched.replace(choice).is_some() {
                    return Err(format!(
                        "selectable `{selectable}` matched multiple authenticated opportunities at snapshot {snapshot}"
                    )
                    .into());
                }
            }
        }
        if let Some(choice) = matched {
            return Ok(choice);
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "campaign did not expose selectable `{selectable}` for parent artifact {parent_artifact} at configuration {parent_configuration}; status={head}; choices={choices}; attempts={:?}",
                attempt_states(fixture)?
            )
            .into());
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn choice_is_authenticated_for_parent(
    fixture: &FlightFixture,
    snapshot: &str,
    opportunity: &str,
    semantic_opportunity: &str,
    branch_point: &str,
) -> Result<bool, Box<dyn Error>> {
    let opportunity_id = ChoiceOpportunityId::parse(opportunity)?;
    let branch_point = BranchPointId::parse(branch_point)?;
    let mut canonical = Vec::new();
    canonical.extend_from_slice(&branch_point.as_hash().as_bytes());
    canonical.extend_from_slice(opportunity_id.content_id().encode().as_bytes());
    let membership_key =
        CampaignHash::derive("crucible.campaign-branch-point-opportunity.v1", &canonical).to_hex();

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
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("campaign-graph-object-key-is-not-present") {
            return Ok(false);
        }
        require_success(&output, "authenticate guest-choice parent membership")?;
        return Ok(false);
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
    Ok(true)
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

fn submit_choice(
    fixture: &FlightFixture,
    choice: &PublicChoice,
    value: &str,
    stop: &str,
    command_byte: u8,
) -> Result<Value, Box<dyn Error>> {
    let head = campaign_status(fixture)?;
    run_json(
        connected_campaign(fixture)
            .args([
                "branch",
                CAMPAIGN,
                "--expected",
                &json_string(&head, "snapshot")?,
                "--command",
            ])
            .arg(format!("{command_byte:02x}").repeat(32))
            .args([
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
            ]),
        "submit guest-choice branch",
    )
}

fn accepted_branch_request(submission: &Value) -> Result<String, Box<dyn Error>> {
    assert_eq!(submission["operation"], "branch");
    assert_eq!(submission["budget"]["maximum_attempts"], 1);
    json_string(submission, "request")
}

fn attempt_states(
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

fn wait_for_new_completed_attempt(
    fixture: &FlightFixture,
    service: &mut CampaignServiceChild,
    known: &BTreeSet<AttemptExecutionKey>,
    request: &str,
) -> Result<AttemptExecutionKey, Box<dyn Error>> {
    wait_for_new_attempt(
        fixture,
        service,
        known,
        "completed",
        Some(request),
        |state| matches!(state, AttemptRuntimeState::Completed { .. }),
    )
}

fn wait_for_initial_discovery(
    fixture: &FlightFixture,
    service: &mut CampaignServiceChild,
    genesis_artifact: &str,
) -> Result<(AttemptExecutionKey, Value), Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
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
                return Ok((key, explanation));
            }
        }
        if Instant::now() >= deadline {
            let diagnostics = campaign_execution_diagnostics(fixture, service, &BTreeSet::new());
            return Err(format!(
                "initial guest-choice discovery from genesis artifact {genesis_artifact} did not complete; {diagnostics}"
            )
            .into());
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn campaign_execution_diagnostics(
    fixture: &FlightFixture,
    service: &mut CampaignServiceChild,
    known_attempts: &BTreeSet<AttemptExecutionKey>,
) -> String {
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
        "status={status:?}; ledger={ledger:?}; service={service_process}; service_stderr={:?}",
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

fn append_process_diagnostics(diagnostics: &mut String) {
    diagnostics.push_str("; processes=[");
    let Ok(entries) = fs::read_dir("/proc") else {
        diagnostics.push_str("<proc-unreadable>]");
        return;
    };
    let mut process_directories = entries
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.bytes().all(|byte| byte.is_ascii_digit()))
        })
        .collect::<Vec<_>>();
    process_directories.sort_by_key(|entry| entry.file_name());
    for entry in process_directories {
        let process = entry.path();
        let command = fs::read(process.join("cmdline"))
            .map(|bytes| {
                String::from_utf8_lossy(&bytes)
                    .replace('\0', " ")
                    .trim()
                    .to_owned()
            })
            .unwrap_or_default();
        if !command.contains("crucible")
            && !command.contains("qemu-system")
            && !command.contains("campaign_store_process")
        {
            continue;
        }
        let status = fs::read_to_string(process.join("status"))
            .unwrap_or_else(|_| String::from("<status-unreadable>"));
        let wait_channel = fs::read_to_string(process.join("wchan"))
            .unwrap_or_else(|_| String::from("<wchan-unreadable>"));
        let _ = write!(
            diagnostics,
            "pid={} cmd={command:?} wchan={:?} status={status:?}; ",
            entry.file_name().to_string_lossy(),
            wait_channel.trim(),
        );
    }
    diagnostics.push(']');
}

fn attest_on_demand_qemu_descendants(
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

    loop {
        let descendants = descendant_process_commands(service.child.id())?;
        let qemu_commands = descendants
            .into_iter()
            .filter(|(_pid, arguments)| arguments.first() == Some(&expected_qemu))
            .collect::<Vec<_>>();
        if !qemu_commands.is_empty() {
            for (pid, arguments) in &qemu_commands {
                let plugin_configuration = arguments
                    .windows(2)
                    .find(|pair| pair[0] == "-plugin")
                    .map(|pair| pair[1].as_str())
                    .ok_or_else(|| {
                        format!(
                            "{phase} QEMU descendant {pid} has no `-plugin` argument: {arguments:?}"
                        )
                    })?;
                let expected_prefix = format!("{expected_plugin},");
                if !plugin_configuration.starts_with(&expected_prefix)
                    || !plugin_configuration
                        .split(',')
                        .any(|argument| argument == "fingerprint=on")
                    || !plugin_configuration
                        .split(',')
                        .any(|argument| argument == "fingerprint_mode=on-demand-v1")
                {
                    return Err(format!(
                        "{phase} QEMU descendant {pid} did not use the packaged plugin in on-demand fingerprint mode: {plugin_configuration:?}"
                    )
                    .into());
                }
            }
            return Ok(());
        }

        if Instant::now() >= deadline {
            return Err(format!(
                "{phase} exposed no live `{expected_qemu}` descendant of campaign service {} within 10s",
                service.child.id()
            )
            .into());
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn descendant_process_commands(root_pid: u32) -> Result<Vec<ProcessCommand>, Box<dyn Error>> {
    let mut processes = Vec::new();
    for entry in fs::read_dir("/proc")?.filter_map(Result::ok) {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(stat) = fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        let Some(parent_pid) = process_parent_pid(&stat) else {
            continue;
        };
        processes.push((pid, parent_pid, entry.path()));
    }

    let mut descendants = BTreeSet::from([root_pid]);
    loop {
        let previous_count = descendants.len();
        for (pid, parent_pid, _path) in &processes {
            if descendants.contains(parent_pid) {
                descendants.insert(*pid);
            }
        }
        if descendants.len() == previous_count {
            break;
        }
    }

    let mut commands = Vec::new();
    for (pid, _parent_pid, path) in processes {
        if pid == root_pid || !descendants.contains(&pid) {
            continue;
        }
        let Ok(command_line) = fs::read(path.join("cmdline")) else {
            continue;
        };
        let arguments = command_line
            .split(|byte| *byte == 0)
            .filter(|argument| !argument.is_empty())
            .map(|argument| String::from_utf8_lossy(argument).into_owned())
            .collect::<Vec<_>>();
        commands.push((pid, arguments));
    }
    Ok(commands)
}

fn process_parent_pid(stat: &str) -> Option<u32> {
    let after_name = stat.rsplit_once(") ")?.1;
    after_name.split_whitespace().nth(1)?.parse().ok()
}

fn wait_for_new_running_attempt(
    fixture: &FlightFixture,
    service: &mut CampaignServiceChild,
    known: &BTreeSet<AttemptExecutionKey>,
    request: &str,
) -> Result<AttemptExecutionKey, Box<dyn Error>> {
    wait_for_new_attempt(fixture, service, known, "running", Some(request), |state| {
        matches!(state, AttemptRuntimeState::Running { .. })
    })
}

fn wait_for_new_attempt(
    fixture: &FlightFixture,
    service: &mut CampaignServiceChild,
    known: &BTreeSet<AttemptExecutionKey>,
    expected_state: &str,
    request: Option<&str>,
    predicate: impl Fn(AttemptRuntimeState) -> bool,
) -> Result<AttemptExecutionKey, Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let states = attempt_states(fixture)?;
        if let Some((key, _)) = states
            .into_iter()
            .find(|(key, state)| !known.contains(key) && predicate(*state))
        {
            return Ok(key);
        }
        if Instant::now() >= deadline {
            let request = request.unwrap_or("<not-captured>");
            let diagnostics = campaign_execution_diagnostics(fixture, service, known);
            return Err(format!(
                "campaign attempt for branch request {request} did not reach executor state {expected_state}; {diagnostics}"
            )
            .into());
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn wait_for_attempt_observation(
    fixture: &FlightFixture,
    key: AttemptExecutionKey,
) -> Result<Value, Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let explanation = wait_for_attempt_explanation(fixture, key)?;
        if !explanation["observation"].is_null() {
            return Ok(explanation);
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "completed attempt {} was not incorporated into a public campaign snapshot",
                key.attempt()
            )
            .into());
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn wait_for_attempt_explanation(
    fixture: &FlightFixture,
    key: AttemptExecutionKey,
) -> Result<Value, Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let head = campaign_status(fixture)?;
        let output = connected_campaign(fixture)
            .args([
                "explain-attempt",
                CAMPAIGN,
                "--snapshot",
                &json_string(&head, "snapshot")?,
                "--attempt",
                &key.attempt().to_string(),
            ])
            .output()?;
        if output.status.success() {
            return parse_json_output(output, "explain guest-choice attempt");
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "campaign did not expose attempt {}; stdout=`{}` stderr=`{}`",
                key.attempt(),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn capture_checkpoint_after_progress(
    fixture: &FlightFixture,
    key: AttemptExecutionKey,
    selection: &str,
    minimum_progress_sequence: u64,
    command_byte: &mut u8,
    scenario: &ScenarioDefForm,
) -> Result<(ExactCheckpointId, CheckpointProgress), Box<dyn Error>> {
    for _ in 0..20 {
        thread::sleep(Duration::from_secs(1));
        pause_for_exact_checkpoint(fixture, next_command_byte(command_byte)?)?;
        let checkpoint = wait_for_promoted_checkpoint(fixture, key, scenario)?;
        let progress = checkpoint_progress(fixture, checkpoint, selection, scenario)?;
        if progress.progress_sequence >= minimum_progress_sequence {
            return Ok((checkpoint, progress));
        }

        resume_campaign(fixture, next_command_byte(command_byte)?)?;
        wait_for_resumed_attempt(fixture, key, checkpoint)?;
    }

    Err(format!(
        "attempt {} did not emit `{selection}` progress sequence {minimum_progress_sequence} after 20 exact checkpoint windows",
        key.attempt()
    )
    .into())
}

fn next_command_byte(command_byte: &mut u8) -> Result<u8, Box<dyn Error>> {
    let current = *command_byte;
    *command_byte = command_byte
        .checked_add(1)
        .ok_or("guest-choice command identity byte overflowed")?;
    Ok(current)
}

fn pause_for_exact_checkpoint(
    fixture: &FlightFixture,
    command_byte: u8,
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
            .arg(format!("{command_byte:02x}").repeat(32))
            .args(["--active", "checkpoint"]),
        "pause guest-choice campaign at exact checkpoint",
    )?;
    Ok(())
}

fn wait_for_promoted_checkpoint(
    fixture: &FlightFixture,
    key: AttemptExecutionKey,
    scenario: &ScenarioDefForm,
) -> Result<ExactCheckpointId, Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(180);
    let backend: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "guest-choice-checkpoint-inspection",
        &fixture.objects,
    ));
    let checkpoints = ExactCheckpointStore::new(backend, 1024 * 1024 * 1024)?;
    loop {
        if let Some(AttemptRuntimeState::Paused { checkpoint, .. }) =
            attempt_states(fixture)?.get(&key).copied()
            && checkpoints
                .load_attempt_checkpoint(checkpoint)
                .is_ok_and(|loaded| checkpoint_is_replay_validated(fixture, &loaded, scenario))
        {
            return Ok(checkpoint);
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "attempt {} did not publish a replay-validated exact checkpoint; ledger={:?}",
                key.attempt(),
                attempt_states(fixture)?
            )
            .into());
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn checkpoint_is_replay_validated(
    fixture: &FlightFixture,
    checkpoint: &LoadedAttemptCheckpoint,
    scenario: &ScenarioDefForm,
) -> bool {
    checkpoint
        .as_production()
        .and_then(|production| authenticated_resume_basis(fixture, production, scenario).ok())
        .is_some_and(|basis| basis.replay_oracle_ready())
}

fn authenticated_resume_basis(
    fixture: &FlightFixture,
    checkpoint: &crucible_daemon::LoadedProductionExactCheckpoint,
    scenario: &ScenarioDefForm,
) -> Result<ProductionExactCheckpointResumeBasis, Box<dyn Error>> {
    let inspection = fixture._temporary.path().join("checkpoint-inspection");
    fs::create_dir_all(&inspection)?;
    let closure = install_exact_checkpoint_closure(&inspection, scenario, checkpoint)?;
    Ok(closure.authenticate_resume_basis()?)
}

fn checkpoint_progress(
    fixture: &FlightFixture,
    checkpoint: ExactCheckpointId,
    selection: &str,
    scenario: &ScenarioDefForm,
) -> Result<CheckpointProgress, Box<dyn Error>> {
    let backend: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "guest-choice-progress-inspection",
        &fixture.objects,
    ));
    let checkpoints = ExactCheckpointStore::new(backend, 1024 * 1024 * 1024)?;
    let loaded = checkpoints.load_attempt_checkpoint(checkpoint)?;
    let production = loaded
        .as_production()
        .ok_or("packaged flight published a non-production exact checkpoint")?;
    let basis = authenticated_resume_basis(fixture, production, scenario)?;
    if !basis.replay_oracle_ready() {
        return Err(
            format!("checkpoint {checkpoint} lacks matching replay-oracle evidence").into(),
        );
    }

    let scheduler = basis.scheduler();
    let event_count = scheduler.event_log_offset().events;
    let progress_prefix = format!("{selection}-progress-");
    let mut selection_icount = None;
    let mut latest_progress = None;
    for entry in scheduler.retained_event_log_entries() {
        let SchedulerEventLogPayload::Observable(ObservableEventPayload::GuestMarker {
            retired_icount,
            marker,
            ..
        }) = entry.payload()
        else {
            continue;
        };
        if marker.name == selection {
            selection_icount = Some(retired_icount.retired);
        }
        let Some(sequence) = marker.name.strip_prefix(&progress_prefix) else {
            continue;
        };
        let sequence = sequence.parse::<u64>()?;
        if latest_progress.is_none_or(|(prior, _, _)| sequence > prior) {
            latest_progress = Some((sequence, entry.sequence(), retired_icount.retired));
        }
    }

    let selection_icount = selection_icount.ok_or_else(|| {
        format!("checkpoint {checkpoint} does not retain selected result marker `{selection}`")
    })?;
    let (progress_sequence, progress_event_sequence, progress_icount) =
        latest_progress.unwrap_or((0, 0, selection_icount));
    if progress_sequence > 0 && progress_icount <= selection_icount {
        return Err(format!(
            "checkpoint {checkpoint} progress marker did not advance beyond selected result marker"
        )
        .into());
    }

    Ok(CheckpointProgress {
        event_count,
        progress_sequence,
        progress_event_sequence,
        progress_icount,
    })
}

fn resume_campaign(fixture: &FlightFixture, command_byte: u8) -> Result<(), Box<dyn Error>> {
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
            .arg(format!("{command_byte:02x}").repeat(32)),
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
    loop {
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
            return Ok(checkpoint);
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "attempt {} did not resume from exact checkpoint {expected_checkpoint}; ledger={:?}",
                key.attempt(),
                attempt_states(fixture)?
            )
            .into());
        }
        thread::sleep(Duration::from_millis(50));
    }
}

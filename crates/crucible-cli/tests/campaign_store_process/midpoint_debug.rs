//! Public finding-to-midpoint operational continuity flight.

use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::sync::{Condvar, Mutex, mpsc};
use std::thread;

use crucible_campaign::{AlternativeId, ChoiceValue, IntegerValue, SelectionOrigin};
use crucible_session::engine::{
    Action, AssertionDef, AssertionId, AssertionQuantifierKind, ContentAddressedBlobRef,
    ContentHash, Decision, EventGraph, Icount, MarkerId, NodeId, Plan, Predicate, Properties,
    Property, ReadyPoint, ScenarioDefForm, Schedule, Seed, VmArchitecture, WhiteBoxPolicy, World,
    WorldNode,
};

use super::*;

#[path = "midpoint_signal.rs"]
pub(super) mod signal;

const MIDPOINT_TIMEOUT: Duration = Duration::from_secs(60);
const PROCESS_OBSERVATION_INTERVAL: Duration = Duration::from_millis(100);
const GUEST_CHOICE_RENDEZVOUS_ICOUNT: &str = "100000000";
const FAILURE_MARKER: &str = "selected-fast-q7";

#[derive(Clone, Copy)]
pub(super) enum FindingScenario {
    /// Existing q7 marker finding without an authored fault program.
    MarkerOnly,
    /// The same guest finding with a QEMU-applied CPU-service fault.
    CpuServiceFault,
}

pub(super) fn run_public_campaign_debug_flight_with_stopped_finding(
    scenario: FindingScenario,
    handoff: impl FnOnce(&FlightFixture, &str, &str) -> Result<(), Box<dyn Error>>,
) -> Result<(), Box<dyn Error>> {
    let fixture = FlightFixture::new()?;
    grant_midpoint_debug_operations(&fixture.peer_policy)?;
    let compiled = compile_failing_scenario(&fixture, scenario)?;
    let manifest = json_path(&compiled, "manifest")?;
    let lineage = compile_lineage(&fixture, &compiled)?;
    let policy = compile_policy(&fixture, &compiled)?;

    let mut importing_service = fixture.start_service(Some(&manifest))?;
    run_json(
        connected_campaign(&fixture)
            .args(["create", CAMPAIGN, "--lineage"])
            .arg(&lineage)
            .arg("--policy")
            .arg(&policy),
        "create midpoint-debug campaign",
    )?;
    importing_service.stop()?;

    let authority = write_component_authority(&fixture)?;
    let executor_socket = fixture._temporary.path().join("midpoint-executor.sock");
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
        .arg(&authority)
        .arg("--campaign-packaged-executor")
        .arg(required_path("CRUCIBLE_FLIGHT_DEPLOYMENT")?)
        .arg("--campaign-executor-socket")
        .arg(&executor_socket);
    let mut service = fixture.start_service_command(invocation, Duration::from_secs(120))?;

    let head = campaign_status(&fixture)?;
    let genesis = json_string(&compiled, "genesis_artifact")?;
    begin_initial_discovery(&fixture, &head)?;
    let failure_attempt = drive_fast_q7_failure(&fixture, &mut service, &genesis)?;
    let (snapshot, finding, finding_before) = wait_for_retained_finding(&fixture, &failure_attempt)
        .map_err(|error| format!("{error}; campaign service stderr={}", service.stderr_tail()))?;
    let finding_proof = query_authenticated_finding_proof(&fixture, &snapshot, &finding)?;
    let replay_evidence = validate_replayed_failure_boundary(&fixture, &finding_proof)?;

    let first = run_public_debug_client(&fixture, service.daemon_url(), &snapshot, &finding)?;
    let second = run_public_debug_client(&fixture, service.daemon_url(), &snapshot, &finding)?;
    let first_selection = validate_public_debug_selection(&fixture, &first, &finding_proof)?;
    let second_selection = validate_public_debug_selection(&fixture, &second, &finding_proof)?;
    assert_eq!(first_selection, second_selection);
    assert_eq!(
        first.session_response, second.session_response,
        "exact retry changed checkpoint or session"
    );
    assert_eq!(
        first.stop_reply_class, second.stop_reply_class,
        "exact retry changed the read-only RSP stop-reply class"
    );

    let finding_after = query_findings(&fixture, &snapshot)?;
    assert_eq!(finding_after, finding_before);
    exercise_public_exact_pin_gc_flow(
        &fixture,
        &mut service,
        &failure_attempt.pinnable_configuration,
    )?;
    validate_imported_production_capture_handoff(&fixture, &finding)?;
    handoff(&fixture, &snapshot, &finding)?;

    println!("public_finding_midpoint_debug=true");
    println!("authenticated_exact_checkpoint=true");
    println!("authenticated_replay_violation_boundary=true");
    println!("authenticated_replay_selection_sequence=fast,q7");
    println!("authenticated_replay_marker={FAILURE_MARKER}");
    println!(
        "authenticated_replay_causal_entries={}",
        replay_evidence.causal_entries
    );
    println!(
        "minimization_original_replay={}",
        replay_evidence.minimization_original
    );
    println!(
        "verification_original_replay={}",
        replay_evidence.verification_original
    );
    println!("fast_midpoint_restore=true");
    println!("read_only_rsp_safe_read=true");
    println!(
        "read_only_rsp_stop_class={}",
        char::from(first.stop_reply_class)
    );
    println!("authenticated_restore_bytes={}", first_selection.0);
    println!("authenticated_checkpoint_candidates={}", first_selection.1);
    println!("retry_session_identity_stable=true");
    println!("campaign_finding_immutable=true");
    println!("public_exact_pin_gc_flow=true");
    println!("imported_production_capture_handoff=true");
    println!("production_qemu=true");
    Ok(())
}

fn validate_imported_production_capture_handoff(
    fixture: &FlightFixture,
    finding: &str,
) -> Result<(), Box<dyn Error>> {
    use crucible_campaign::{CampaignArchivePolicy, CampaignFindingTriageReplayRole, FindingId};
    use crucible_cas::content_store::{DirectoryRefBackend, DurabilityRequirement};

    let source = crucible_campaign::CampaignRepository::new(
        Arc::new(DirectoryBlobBackend::new(
            "midpoint-debug-handoff-source",
            &fixture.objects,
        )),
        Arc::new(DirectoryRefBackend::new(
            fixture._temporary.path().join("refs"),
        )),
    );
    let head = source.head(CAMPAIGN)?;
    let plan = source.plan_campaign_archive(
        head.snapshot_id(),
        CampaignArchivePolicy::Executable,
        [],
        None,
    )?;
    source.stage_campaign_archive_metadata(&plan)?;

    let private = tempfile::tempdir()?;
    let imported = crucible_campaign::CampaignRepository::new(
        Arc::new(DirectoryBlobBackend::new(
            "midpoint-debug-handoff-private",
            private.path().join("objects"),
        )),
        Arc::new(DirectoryRefBackend::new(private.path().join("refs"))),
    );
    source.transfer_campaign_archive_objects(
        &imported,
        &plan,
        DurabilityRequirement::new(1, false)?,
    )?;
    imported.publish_transferred_campaign("private-midpoint-handoff", None, plan.manifest_id())?;
    drop(source);

    let capture = crucible_daemon::load_archived_finding_production_capture(
        &imported,
        plan.manifest_id(),
        FindingId::parse(finding)?,
        CampaignFindingTriageReplayRole::MinimizationOriginal,
    )?;
    let assets = crucible_daemon::materialize_finding_replay_guest_assets(
        capture.deployment(),
        &required_path("CRUCIBLE_FLIGHT_QEMU")?,
        &required_path("CRUCIBLE_FLIGHT_PLUGIN")?,
        private.path(),
    )?;
    let guest = assets
        .guest_assets()
        .first()
        .ok_or("imported capture has no guest assets")?;
    if fs::metadata(guest.kernel())?.len() == 0 || fs::metadata(guest.root_image())?.len() == 0 {
        return Err("imported capture materialized empty guest assets".into());
    }
    Ok(())
}

fn grant_midpoint_debug_operations(policy: &Path) -> Result<(), Box<dyn Error>> {
    let mut policy = fs::OpenOptions::new().append(true).open(policy)?;
    for operation in [
        "query-campaign-findings",
        "get-campaign-finding-object",
        "debug-campaign",
        "pin-campaign",
    ] {
        writeln!(
            policy,
            "\n[[grants]]\nprincipal = {PRINCIPAL:?}\noperation = {operation:?}\ncampaign = \"*\""
        )?;
    }
    Ok(())
}

fn compile_failing_scenario(
    fixture: &FlightFixture,
    scenario: FindingScenario,
) -> Result<Value, Box<dyn Error>> {
    let kernel = required_path("CRUCIBLE_KERNEL")?;
    let root_image = required_path("CRUCIBLE_ROOT_IMAGE")?;
    let initrd = required_path("CRUCIBLE_INITRD")?;
    let node = NodeId {
        name: String::from("choice-node"),
    };
    let world = World::from_nodes_and_links(
        vec![WorldNode {
            id: node,
            arch: VmArchitecture::X86_64,
            memory_mib: 128,
            cmdline: String::from(
                "console=ttyS0 rdinit=/init quiet nokaslr norandmaps random.trust_cpu=off",
            ),
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
        }],
        Vec::new(),
    )?;
    let selectables = super::packaged::guest_choice::guest_choice_selectables(&world)?;
    let graph = EventGraph::builder()
        .event("keep-midpoint-guest-running")
        .entrypoint()
        .action(Action::Group(Vec::new()))
        .event("complete-after-selection-marker")
        .when(Predicate::any_of(
            ["fast", "safe"]
                .into_iter()
                .flat_map(|policy| {
                    [1_u64, 3, 5, 7, 9].map(move |quanta| {
                        Predicate::guest_marker(MarkerId::from_name(format!(
                            "selected-{policy}-q{quanta}"
                        )))
                    })
                })
                .collect(),
        ))
        .action(Action::Pass)
        .build_for_world(&world)?;
    let mut plan = Plan::from_event_graph_for_world(&world, graph)?;
    if matches!(scenario, FindingScenario::CpuServiceFault) {
        plan = plan.with_fault_signals_for_world(&world, signal::cpu_service_fault(&world)?)?;
    }
    let properties = Properties::from_assertions_for_world(
        &world,
        vec![AssertionDef {
            id: AssertionId::from_name("known-midpoint-failure"),
            message: String::from("the selected fast q7 guest marker must remain absent"),
            property: Property::Always {
                predicate: Predicate::not(Predicate::guest_marker(MarkerId::from_name(
                    FAILURE_MARKER,
                ))),
            },
        }],
    )?;
    let scenario =
        ScenarioDefForm::from_components(&world, &plan, &properties, Seed::from_u64(43))?
            .with_selectables(selectables)?;
    let scenario_path = fixture._temporary.path().join("midpoint-scenario.toml");
    fs::write(&scenario_path, scenario.to_canonical_toml()?)?;

    run_json(
        command(&["--format", "jsonl", "campaign", "scenario", "compile"])
            .arg(&scenario_path)
            .arg("--output")
            .arg(&fixture.fixture),
        "compile midpoint-debug scenario",
    )
}

fn compile_lineage(fixture: &FlightFixture, compiled: &Value) -> Result<PathBuf, Box<dyn Error>> {
    let input = fixture._temporary.path().join("midpoint-lineage.toml");
    let output = fixture._temporary.path().join("midpoint-lineage.bin");
    fs::write(
        &input,
        format!(
            "schema_version = 1\nscenario = {:?}\nscenario_content = {:?}\ngenesis = {:?}\ngenesis_content = {:?}\ncrucible_version = \"0.1.0\"\nqemu_build = \"qemu-11.1.1-crucible\"\nscenario_schema = 3\nexact_closure_schema = 5\n[protocol_versions]\ncontrol = 3\nshared-memory = 25\n",
            json_string(compiled, "scenario")?,
            json_string(compiled, "scenario_artifact")?,
            json_string(compiled, "genesis")?,
            json_string(compiled, "genesis_artifact")?,
        ),
    )?;
    run_json(
        command(&["--format", "jsonl", "campaign", "lineage", "compile"])
            .arg(&input)
            .arg("--output")
            .arg(&output),
        "compile midpoint-debug lineage",
    )?;
    Ok(output)
}

fn compile_policy(fixture: &FlightFixture, compiled: &Value) -> Result<PathBuf, Box<dyn Error>> {
    let input = fixture._temporary.path().join("midpoint-policy.toml");
    let output = fixture._temporary.path().join("midpoint-policy.bin");
    fs::write(
        &input,
        format!(
            r#"schema_version = 3
scenario = {:?}
campaign_seed = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
mode = "strict"
stop_conditions = ["scenario-complete"]
admit_scenario_defaults = false
[explorer]
kind = "exhaustive"
maximum_cardinality = 2
[fairness]
breadth_first_percent = 0
novelty_reserve = 0
[retention]
retain_all_findings = true
survivor_limit = 8
exact_findings = true
exact_user_pins = true
"#,
            json_string(compiled, "scenario")?,
        ),
    )?;
    run_json(
        command(&["--format", "jsonl", "campaign", "policy", "compile"])
            .arg(&input)
            .arg("--output")
            .arg(&output),
        "compile midpoint-debug policy",
    )?;
    Ok(output)
}

fn write_component_authority(fixture: &FlightFixture) -> Result<PathBuf, Box<dyn Error>> {
    let authority = fixture._temporary.path().join("midpoint-authority.bin");
    let mut bytes = b"CRUCCA01".to_vec();
    bytes.extend_from_slice(&[0x31; 32]);
    bytes.extend_from_slice(&[0x32; 32]);
    fs::write(&authority, bytes)?;
    fs::set_permissions(&authority, fs::Permissions::from_mode(0o600))?;
    Ok(authority)
}

fn wait_for_retained_finding(
    fixture: &FlightFixture,
    failure: &AuthenticatedFailureAttempt,
) -> Result<(String, String, Value), Box<dyn Error>> {
    let deadline = Instant::now() + MIDPOINT_TIMEOUT;
    let mut last = None;
    let found = wait_for_process_observation(deadline, || {
        let head = campaign_status(fixture)?;
        let snapshot = json_string(&head, "snapshot")?;
        let findings = query_findings(fixture, &snapshot)?;
        last = Some((head, findings.clone()));
        let entries = findings["entries"]
            .as_array()
            .ok_or("campaign findings entries are not an array")?;
        let mut matches = entries
            .iter()
            .filter(|entry| entry["observation"] == failure.observation);
        let Some(entry) = matches.next() else {
            return Ok(None);
        };
        if matches.next().is_some() {
            return Err(format!(
                "campaign retained multiple findings for q7 observation {}",
                failure.observation
            )
            .into());
        }
        let finding = json_string(entry, "finding")?;
        Ok(Some((snapshot, finding, findings)))
    })?;
    if let Some(found) = found {
        return Ok(found);
    }

    let head = campaign_status(fixture)?;
    let explanation = run_json(
        connected_campaign(fixture).args([
            "explain-attempt",
            CAMPAIGN,
            "--snapshot",
            &json_string(&head, "snapshot")?,
            "--attempt",
            &failure.attempt,
        ]),
        "explain midpoint-debug attempt without a retained finding",
    );
    Err(format!(
        "campaign produced no retained finding: last={last:?}; head={head}; attempt={explanation:?}"
    )
    .into())
}

fn begin_initial_discovery(fixture: &FlightFixture, head: &Value) -> Result<(), Box<dyn Error>> {
    run_json(
        connected_campaign(fixture)
            .args([
                "budget",
                CAMPAIGN,
                "--expected",
                &json_string(head, "snapshot")?,
                "--command",
            ])
            .arg("61".repeat(32))
            .args(["add", "16", "--proposals", "16"]),
        "grant midpoint-debug discovery budget",
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
            .arg("62".repeat(32)),
        "start midpoint-debug discovery",
    )?;
    Ok(())
}

struct AuthenticatedFailureAttempt {
    attempt: String,
    observation: String,
    pinnable_configuration: String,
}

fn drive_fast_q7_failure(
    fixture: &FlightFixture,
    service: &mut CampaignServiceChild,
    genesis: &str,
) -> Result<AuthenticatedFailureAttempt, Box<dyn Error>> {
    use super::packaged::guest_choice;
    use crucible_campaign::{ObservationId, PropertyVerdict};

    let (discovery_attempt, discovery) =
        guest_choice::wait_for_initial_discovery(fixture, service, genesis)?;
    let discovery_parent = json_string(&discovery["observation"], "child_artifact")?;
    let discovery_configuration = json_string(&discovery["observation"], "child")?;
    let recovery = guest_choice::wait_for_choice(
        fixture,
        "campaign.recovery-policy",
        &discovery_parent,
        &discovery_configuration,
    )?;

    let mut known_attempts = BTreeSet::from([discovery_attempt]);
    let fast_submission = guest_choice::submit_choice(
        fixture,
        &recovery,
        &format!("discrete:{}", guest_choice::FAST_ALTERNATIVE),
        "next-choice",
        0x63,
    )?;
    let fast_request = guest_choice::accepted_branch_request(&fast_submission)?;
    let fast_attempt = guest_choice::wait_for_new_completed_attempt(
        fixture,
        service,
        &known_attempts,
        &fast_request,
    )?;
    known_attempts.insert(fast_attempt);
    let fast = guest_choice::wait_for_attempt_observation(fixture, fast_attempt)?;
    if fast["proposal"]["request"] != fast_request
        || fast["selection"]["value"] != format!("discrete:{}", guest_choice::FAST_ALTERNATIVE)
        || fast["observation"]["stop"] != "reached:next-choice"
    {
        return Err(format!("fast midpoint branch returned unexpected evidence: {fast}").into());
    }

    let fast_parent = json_string(&fast["observation"], "child_artifact")?;
    let fast_configuration = json_string(&fast["observation"], "child")?;
    let next_choice = guest_choice::wait_for_choice(
        fixture,
        "campaign.retry-quanta",
        &fast_parent,
        &fast_configuration,
    )?;
    let q7_submission = guest_choice::submit_choice(
        fixture,
        &next_choice,
        "u64:7",
        "boundary:selected-fast-q7",
        0x64,
    )?;
    let q7_request = guest_choice::accepted_branch_request(&q7_submission)?;
    // The q7 branch and candidates in both finding replay passes run the guest.
    // A packaged run was still in finding postprocessing at 300 seconds, so
    // bound this host wait without changing any executor deadline.
    let q7_attempt = guest_choice::wait_for_new_completed_attempt_with_timeout(
        fixture,
        service,
        &known_attempts,
        &q7_request,
        Duration::from_secs(600),
    )?;
    let q7 = guest_choice::wait_for_attempt_observation(fixture, q7_attempt)?;
    // The marker reaches the requested boundary; its failed property owns the stop outcome.
    if q7["proposal"]["request"] != q7_request
        || q7["selection"]["value"] != "u64:7"
        || q7["observation"]["stop"] != "assertion-failure:known-midpoint-failure"
    {
        return Err(format!("q7 midpoint branch returned unexpected evidence: {q7}").into());
    }

    let attempt = q7_attempt.attempt().to_string();
    if json_string(&q7["observation"], "attempt")? != attempt {
        return Err("q7 midpoint observation belongs to another attempt".into());
    }
    let observation = json_string(&q7["observation"], "id")?;
    let repository = crucible_campaign::CampaignRepository::new(
        Arc::new(DirectoryBlobBackend::new(
            "midpoint-debug-verdict-inspection",
            &fixture.objects,
        )),
        Arc::new(crucible_cas::content_store::DirectoryRefBackend::new(
            fixture._temporary.path().join("refs"),
        )),
    );
    let observation_record = repository.load_observation(ObservationId::parse(&observation)?)?;
    let verdicts = repository.load_property_verdict_set(observation_record.properties())?;
    if verdicts
        .properties()
        .get("known-midpoint-failure")
        .map(|evidence| evidence.verdict())
        != Some(PropertyVerdict::Failed)
    {
        return Err(
            format!("q7 observation did not fail the expected property: {verdicts:?}").into(),
        );
    }

    println!("midpoint_attempt={attempt}");
    Ok(AuthenticatedFailureAttempt {
        attempt,
        observation,
        pinnable_configuration: fast_configuration,
    })
}

fn exercise_public_exact_pin_gc_flow(
    fixture: &FlightFixture,
    service: &mut CampaignServiceChild,
    configuration: &str,
) -> Result<(), Box<dyn Error>> {
    use crucible_campaign::{CampaignName, ConfigurationId};
    use crucible_daemon::{
        DirectoryExactPinMaterializationStore, EXACT_PIN_MATERIALIZATION_DIRECTORY,
        ExactPinRetentionAdmin,
    };

    let head = campaign_status(fixture)?;
    let pinned = run_json(
        connected_campaign(fixture).args([
            "pin",
            CAMPAIGN,
            configuration,
            "--expected",
            &json_string(&head, "snapshot")?,
            "--command",
            &"65".repeat(32),
            "--tier",
            "exact",
            "--reason",
            "retain public GC flight checkpoint",
        ]),
        "pin exact materialization through public campaign service",
    )?;
    assert_eq!(pinned["operation"], "pin");

    // Operational status synchronously reconciles the semantic pin with the
    // packaged materializer before the owner is stopped for offline GC.
    let pinned_head = campaign_status(fixture)?;
    assert_eq!(pinned_head["snapshot"], pinned["new_snapshot"]);
    service.stop()?;

    let campaign = CampaignName::new(CAMPAIGN)?;
    let configuration = ConfigurationId::parse(configuration)?;
    let exact_pin_root = fixture.state.join(EXACT_PIN_MATERIALIZATION_DIRECTORY);
    let mut selections = DirectoryExactPinMaterializationStore::open(&exact_pin_root)?;
    let checkpoint = {
        let mut fence = selections.acquire_exact_pin_retention_fence()?;
        fence
            .selection(&campaign, configuration)?
            .ok_or("packaged materializer omitted the public exact pin")?
            .checkpoint()
    };
    drop(selections);

    let orphan_bytes = b"public exact-pin GC apply orphan";
    let orphan = ContentId::for_bytes(ObjectKind::Trace, 1, orphan_bytes);
    DirectoryBlobBackend::new("public-exact-pin-gc", &fixture.objects)
        .put_if_absent(orphan, &BlobHandle::from_bytes(orphan_bytes.to_vec()))?;

    let planned = run_json(
        &mut fixture.gc_command("plan"),
        "plan GC with public exact pin",
    )?;
    assert_eq!(planned["operation"], "plan");
    {
        let journal = DirectoryCampaignGcJournal::open(&fixture.journal)?;
        assert!(
            journal
                .roots()
                .iter()
                .any(|root| root == checkpoint.content_id()),
            "public exact pin did not root its materialized checkpoint"
        );
        assert!(
            !journal
                .candidates()
                .iter()
                .any(|candidate| candidate.id() == checkpoint.content_id()),
            "public exact pin checkpoint entered the deletion manifest"
        );
    }

    let applied = run_json(
        &mut fixture.gc_command("apply"),
        "apply GC with public exact pin",
    )?;
    assert_eq!(applied["phase"], "complete");
    assert_eq!(applied["apply_status"], "applied");

    let mut unpin_service = fixture.start_service(None)?;
    let unpin_head = campaign_status(fixture)?;
    let unpinned = run_json(
        connected_campaign(fixture).args([
            "unpin",
            CAMPAIGN,
            &configuration.to_string(),
            "--expected",
            &json_string(&unpin_head, "snapshot")?,
            "--command",
            &"66".repeat(32),
            "--reason",
            "release public GC flight checkpoint",
        ]),
        "unpin exact materialization through public campaign service",
    )?;
    assert_eq!(unpinned["operation"], "unpin");
    unpin_service.stop()?;

    let after_unpin_journal = fixture._temporary.path().join("gc-after-public-unpin");
    let replanned = run_json(
        &mut fixture.gc_command_at("plan", &after_unpin_journal),
        "replan GC after public unpin",
    )?;
    assert_eq!(replanned["operation"], "plan");
    let journal = DirectoryCampaignGcJournal::open(after_unpin_journal)?;
    assert!(
        !journal
            .roots()
            .iter()
            .any(|root| root == checkpoint.content_id()),
        "stale exact-pin selection remained a GC root after public unpin"
    );
    assert!(
        journal
            .candidates()
            .iter()
            .any(|candidate| candidate.id() == checkpoint.content_id()),
        "unpin did not return the exact checkpoint to the deletion candidates"
    );

    Ok(())
}

fn wait_for_process_observation<T>(
    deadline: Instant,
    mut observe: impl FnMut() -> Result<Option<T>, Box<dyn Error>>,
) -> Result<Option<T>, Box<dyn Error>> {
    loop {
        if let Some(observation) = observe()? {
            return Ok(Some(observation));
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(None);
        }
        wait_for_external_progress(PROCESS_OBSERVATION_INTERVAL.min(remaining))?;
    }
}

fn query_findings(fixture: &FlightFixture, snapshot: &str) -> Result<Value, Box<dyn Error>> {
    let findings = run_json(
        connected_campaign(fixture).args([
            "findings",
            CAMPAIGN,
            "--snapshot",
            snapshot,
            "--limit",
            "4",
            "--pages",
            "16",
        ]),
        "query midpoint-debug finding",
    )?;
    if findings["operation"] != "findings"
        || findings["campaign"] != CAMPAIGN
        || findings["snapshot"] != snapshot
        || findings["complete"] != true
    {
        return Err(format!(
            "campaign findings query did not return one complete authenticated page: {findings}"
        )
        .into());
    }
    Ok(findings)
}

fn query_authenticated_finding_proof(
    fixture: &FlightFixture,
    snapshot: &str,
    finding: &str,
) -> Result<crucible_campaign::GetCampaignFindingObjectResponse, Box<dyn Error>> {
    use crucible_campaign::CampaignService;

    let request = crucible_campaign::GetCampaignFindingObjectRequest::new(
        crucible_campaign::CampaignPrincipal::new(PRINCIPAL)?,
        crucible_campaign::CampaignName::new(CAMPAIGN)?,
        crucible_campaign::CampaignSnapshotId::parse(snapshot)?,
        crucible_campaign::FindingId::parse(finding)?,
        crucible_campaign::CampaignFindingObjectKind::Reproduction,
    )?;
    let stream = UnixStream::connect(&fixture.socket)?;
    let service = crucible_daemon::LoopbackCampaignService::new(stream)?;
    let response = service.get_campaign_finding_object(&request)?;
    response.validate_for(&request)?;
    Ok(response)
}

#[derive(Debug)]
struct AuthenticatedReplayBoundaryEvidence {
    causal_entries: usize,
    minimization_original: crucible_campaign::FindingTriageReplayEvidenceId,
    verification_original: crucible_campaign::FindingTriageReplayEvidenceId,
}

fn validate_replayed_failure_boundary(
    fixture: &FlightFixture,
    finding: &crucible_campaign::GetCampaignFindingObjectResponse,
) -> Result<AuthenticatedReplayBoundaryEvidence, Box<dyn Error>> {
    let signature = finding.finding().signature();
    if signature.property() != Some("known-midpoint-failure")
        || signature.causal_evidence().is_empty()
    {
        return Err(
            "campaign finding omitted its exact failure identity or causal evidence".into(),
        );
    }
    let bundle_id = finding.finding().latest_candidate_bundle();
    let repository = crucible_campaign::CampaignRepository::new(
        Arc::new(DirectoryBlobBackend::new(
            "midpoint-debug-replay-proof",
            &fixture.objects,
        )),
        Arc::new(crucible_cas::content_store::DirectoryRefBackend::new(
            fixture._temporary.path().join("refs"),
        )),
    );
    let bundle = repository.load_finding_candidate_bundle(bundle_id)?;
    let triage = bundle
        .triage_evidence()
        .ok_or("campaign finding omitted native replay evidence")?;
    let replay_ids = [
        triage.minimization_original(),
        triage.verification_original(),
    ];
    if replay_ids[0] == replay_ids[1] {
        return Err("campaign finding reused one replay record for both original proofs".into());
    }
    let mut causal_entries = 0_usize;
    for replay_id in replay_ids {
        let record = repository.load_finding_triage_replay_evidence(replay_id)?;
        let reproduction = repository.load_reproduction_artifact(record.reproduction())?;
        let artifact =
            crucible_core::ReproductionArtifact::from_compact_binary(reproduction.payload())?;
        let replay = artifact.replay()?;
        let configuration = crucible_core::Configuration {
            def: artifact.scenario_def(),
            schedule: artifact.schedule().clone(),
        }
        .id();
        if reproduction.scenario().as_hash()
            != crucible_campaign::CampaignHash::from_bytes(artifact.scenario_def().id().bytes)
            || reproduction.configuration().as_hash()
                != crucible_campaign::CampaignHash::from_bytes(configuration.bytes)
        {
            return Err("campaign replay reproduction identity is inconsistent".into());
        }
        let native_finding = crucible_core::FindingReproductionArtifact {
            discovery_path: crucible_core::FindingDiscoveryPath::StateSpaceSearch,
            finding_fingerprint: crucible_core::ContentHash {
                bytes: reproduction.finding_fingerprint().as_bytes(),
            },
            configuration,
            artifact,
            replay,
        };
        let native_replay = crucible_core::FailureTriageReplayEvidence::from_compact_binary(
            native_finding,
            record.payload(),
        )?;
        if native_replay.schema_version() != record.payload_schema()
            || native_replay
                .signature()
                .property
                .as_ref()
                .map(|property| property.id.name.as_str())
                != record.observed_signature().property()
        {
            return Err("campaign replay payload disagrees with its authenticated record".into());
        }
        let crucible_core::FailureClusterReportFailure::Property(property) =
            native_replay.failure()
        else {
            return Err("campaign finding replay did not retain a property violation".into());
        };
        if property.violation.assertion.name != "known-midpoint-failure"
            || property.violation.quantifier != AssertionQuantifierKind::Always
            || property.violation.node.as_ref().map(|node| node.name.as_str())
                != Some("choice-node")
            || !property.violation.detail.contains(
                "observed=not predicate was false; inner guest marker marker=selected-fast-q7 matched",
            )
        {
            return Err(format!(
                "campaign finding replay reached the wrong violation: {:?}",
                property.violation
            )
            .into());
        }
        if native_replay.causal_entries().is_empty() {
            return Err("campaign finding replay retained an empty causal projection".into());
        }
        validate_fast_q7_schedule(native_replay.finding().artifact.schedule())?;
        causal_entries = causal_entries
            .checked_add(native_replay.causal_entries().len())
            .ok_or("campaign replay causal-entry count overflow")?;
    }

    Ok(AuthenticatedReplayBoundaryEvidence {
        causal_entries,
        minimization_original: replay_ids[0],
        verification_original: replay_ids[1],
    })
}

fn validate_fast_q7_schedule(schedule: &Schedule) -> Result<(), Box<dyn Error>> {
    let selections = schedule
        .decisions()
        .iter()
        .filter_map(|decision| match decision {
            Decision::Selection(selection) => Some(selection.selection()),
            _ => None,
        })
        .collect::<Result<Vec<_>, _>>()?;
    if selections.len() != 2 {
        return Err(format!(
            "campaign replay schedule retained {} selections instead of fast then q7",
            selections.len()
        )
        .into());
    }

    let expected = [
        ChoiceValue::Discrete(AlternativeId::parse(
            super::packaged::guest_choice::FAST_ALTERNATIVE,
        )?),
        ChoiceValue::Integer(IntegerValue::Unsigned(7)),
    ];
    for (index, (selection, expected_value)) in selections.iter().zip(expected).enumerate() {
        if selection.value() != &expected_value
            || !matches!(selection.origin(), SelectionOrigin::CampaignBranch { .. })
        {
            return Err(format!(
                "campaign replay selection {index} is not the authenticated expected branch: {selection:?}"
            )
            .into());
        }
    }
    Ok(())
}

fn run_public_debug_client(
    fixture: &FlightFixture,
    daemon_url: &str,
    snapshot: &str,
    finding: &str,
) -> Result<PublicDebugEvidence, Box<dyn Error>> {
    let relay_address = reserve_loopback_address()?;
    let mut invocation = command(&[
        "--daemon",
        daemon_url,
        "--trusted-unauthenticated-daemon",
        "campaign",
        "--socket",
    ]);
    invocation
        .arg(&fixture.socket)
        .args([
            "--principal",
            PRINCIPAL,
            "debug",
            CAMPAIGN,
            "--snapshot",
            snapshot,
            "--finding",
            finding,
            "--node",
            "choice-node",
            "--gdb-listen",
            &relay_address.to_string(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = invocation.spawn()?;
    let child_stdout = child
        .stdout
        .take()
        .ok_or("campaign debug did not expose its readiness stream")?;
    let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
    let ready_line = format!("crucible: remote GDB relay listening at {relay_address}");
    let stdout_reader = thread::spawn(move || -> std::io::Result<Vec<u8>> {
        let mut reader = BufReader::new(child_stdout);
        let mut retained = Vec::new();
        let mut readiness_sent = false;
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line)? == 0 {
                break;
            }
            retained.extend_from_slice(line.as_bytes());
            if !readiness_sent && line.trim_end() == ready_line {
                ready_sender.send(Ok(())).ok();
                readiness_sent = true;
            }
        }
        if !readiness_sent {
            ready_sender
                .send(Err(String::from(
                    "campaign debug exited before publishing relay readiness",
                )))
                .ok();
        }
        Ok(retained)
    });
    let relay_result = (|| {
        ready_receiver
            .recv_timeout(MIDPOINT_TIMEOUT)
            .map_err(|error| format!("campaign debug readiness handshake failed: {error}"))??;
        let mut relay = TcpStream::connect(relay_address).map_err(|error| {
            format!("campaign debug relay {relay_address} connect failed: {error}")
        })?;
        relay.set_read_timeout(Some(Duration::from_secs(10)))?;
        relay.write_all(b"$?#3f")?;
        let stop_reply_class = read_single_rsp_stop_reply(&mut relay)?;
        relay.shutdown(Shutdown::Both)?;
        Ok::<_, Box<dyn Error>>(stop_reply_class)
    })();
    let stop_reply_class = match relay_result {
        Ok(stop_reply_class) => stop_reply_class,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_reader.join();
            return Err(error);
        }
    };

    let output = child.wait_with_output()?;
    require_success(&output, "public campaign debug")?;
    let stdout = stdout_reader
        .join()
        .map_err(|_| "campaign debug readiness reader panicked")??;
    let stdout = String::from_utf8(stdout)?;
    assert!(stdout.contains("read_only=true"));
    assert!(stdout.contains("crucible: remote GDB relay listening at"));
    let session_response = stdout
        .lines()
        .find(|line| line.starts_with("campaign-debug\t"))
        .ok_or_else(|| -> Box<dyn Error> {
            format!("campaign debug omitted its exact session response: {stdout}").into()
        })?;
    let mut evidence = parse_campaign_debug_response(session_response)?;
    evidence.stop_reply_class = stop_reply_class;

    Ok(evidence)
}

#[derive(Debug)]
struct PublicDebugEvidence {
    session_response: String,
    checkpoint: crucible_campaign::ExactCheckpointId,
    configuration: String,
    role: crucible_daemon::CampaignDebugCheckpointRole,
    stop_reply_class: u8,
}

fn parse_campaign_debug_response(line: &str) -> Result<PublicDebugEvidence, Box<dyn Error>> {
    let fields = line.split('\t').collect::<Vec<_>>();
    let [
        "campaign-debug",
        checkpoint,
        configuration,
        role,
        "read_only=true",
        session,
    ] = fields.as_slice()
    else {
        return Err(format!("campaign debug returned malformed session evidence: {line}").into());
    };
    let checkpoint = checkpoint
        .strip_prefix("checkpoint=")
        .ok_or("campaign debug response omitted checkpoint")?;
    let checkpoint = crucible_campaign::ExactCheckpointId::parse(checkpoint)?;
    let configuration = configuration
        .strip_prefix("configuration=")
        .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or("campaign debug response has an invalid configuration identity")?
        .to_owned();
    let role = match role.strip_prefix("role=") {
        Some("PostFailure") => crucible_daemon::CampaignDebugCheckpointRole::PostFailure,
        Some("PreFailure") => crucible_daemon::CampaignDebugCheckpointRole::PreFailure,
        Some("MeasurementBoundary") => {
            crucible_daemon::CampaignDebugCheckpointRole::MeasurementBoundary
        }
        Some("Additional") => crucible_daemon::CampaignDebugCheckpointRole::Additional,
        _ => return Err("campaign debug response has an invalid checkpoint role".into()),
    };
    let session = session
        .strip_prefix("session=")
        .ok_or("campaign debug response omitted session identity")?;
    let session_parts = session.split(':').collect::<Vec<_>>();
    let [id, epoch, seed] = session_parts.as_slice() else {
        return Err("campaign debug response has a malformed session identity".into());
    };
    id.parse::<u64>()?;
    epoch.parse::<u64>()?;
    if seed.len() != 64 || !seed.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("campaign debug response has an invalid session seed".into());
    }

    Ok(PublicDebugEvidence {
        session_response: line.to_owned(),
        checkpoint,
        configuration,
        role,
        stop_reply_class: 0,
    })
}

fn validate_public_debug_selection(
    fixture: &FlightFixture,
    evidence: &PublicDebugEvidence,
    finding: &crucible_campaign::GetCampaignFindingObjectResponse,
) -> Result<(u64, usize), Box<dyn Error>> {
    let pins = finding.finding().exact_pin_retention();
    let role_pins = match evidence.role {
        crucible_daemon::CampaignDebugCheckpointRole::PostFailure => pins.post_failure(),
        crucible_daemon::CampaignDebugCheckpointRole::PreFailure => pins.pre_failure(),
        crucible_daemon::CampaignDebugCheckpointRole::MeasurementBoundary => {
            pins.measurement_boundary()
        }
        crucible_daemon::CampaignDebugCheckpointRole::Additional => pins.additional(),
    };
    if !role_pins.contains(&evidence.checkpoint) {
        return Err(
            "campaign debug selected a checkpoint outside its authenticated finding role".into(),
        );
    }

    let backend = Arc::new(DirectoryBlobBackend::new(
        "midpoint-debug-selection-proof",
        &fixture.objects,
    ));
    let checkpoints = crucible_daemon::ExactCheckpointStore::new(backend, 1024 * 1024 * 1024)?;
    let loaded = checkpoints.load_attempt_checkpoint(evidence.checkpoint)?;
    if evidence.configuration != loaded.configuration().to_hex() {
        return Err(
            "campaign debug response configuration disagrees with its authenticated checkpoint"
                .into(),
        );
    }

    let roles = [
        (
            crucible_daemon::CampaignDebugCheckpointRole::PostFailure,
            pins.post_failure(),
        ),
        (
            crucible_daemon::CampaignDebugCheckpointRole::PreFailure,
            pins.pre_failure(),
        ),
        (
            crucible_daemon::CampaignDebugCheckpointRole::MeasurementBoundary,
            pins.measurement_boundary(),
        ),
        (
            crucible_daemon::CampaignDebugCheckpointRole::Additional,
            pins.additional(),
        ),
    ];
    let mut expected = None;
    let mut candidate_count = 0_usize;
    for (role, candidates) in roles {
        for checkpoint in candidates {
            candidate_count = candidate_count
                .checked_add(1)
                .ok_or("checkpoint candidate count overflow")?;
            let candidate = checkpoints.load_attempt_checkpoint(*checkpoint)?;
            let restore_bytes = candidate.authenticated_restore_bytes()?;
            let key = (restore_bytes, debug_role_rank(role), *checkpoint);
            if expected.as_ref().is_none_or(|(current, _)| key < *current) {
                expected = Some((key, role));
            }
        }
    }
    let Some(((restore_bytes, _, checkpoint), role)) = expected else {
        return Err("authenticated finding retained no exact debug checkpoint".into());
    };
    if candidate_count < 2 {
        return Err("campaign debug flight requires competing authenticated checkpoints".into());
    }
    if (evidence.checkpoint, evidence.role) != (checkpoint, role) {
        return Err(format!(
            "campaign debug did not choose the cheapest authenticated state: expected {role:?} {checkpoint}, got {:?} {}",
            evidence.role, evidence.checkpoint
        )
        .into());
    }

    Ok((restore_bytes, candidate_count))
}

const fn debug_role_rank(role: crucible_daemon::CampaignDebugCheckpointRole) -> u8 {
    match role {
        crucible_daemon::CampaignDebugCheckpointRole::PostFailure => 0,
        crucible_daemon::CampaignDebugCheckpointRole::PreFailure => 1,
        crucible_daemon::CampaignDebugCheckpointRole::MeasurementBoundary => 2,
        crucible_daemon::CampaignDebugCheckpointRole::Additional => 3,
    }
}

fn read_single_rsp_stop_reply(relay: &mut TcpStream) -> Result<u8, Box<dyn Error>> {
    const MAXIMUM_REPLY_BYTES: usize = 256;
    let mut response = Vec::new();
    loop {
        if response.len() == MAXIMUM_REPLY_BYTES {
            return Err("read-only RSP reply exceeded its byte limit".into());
        }

        let mut chunk = [0_u8; 64];
        let available = MAXIMUM_REPLY_BYTES - response.len();
        let count = relay.read(&mut chunk[..available.min(64)])?;
        if count == 0 {
            return Err("read-only RSP relay closed before one complete reply".into());
        }
        response.extend_from_slice(&chunk[..count]);

        let Some(stop_reply_class) = parse_single_rsp_stop_reply(&response)? else {
            continue;
        };

        relay.set_read_timeout(Some(Duration::from_millis(25)))?;
        let mut trailing = [0_u8; 1];
        match relay.read(&mut trailing) {
            Ok(0) => {}
            Ok(_) => {
                return Err(format!(
                    "read-only RSP query returned trailing data after its stop reply: {trailing:?}"
                )
                .into());
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(error) => return Err(error.into()),
        }

        return Ok(stop_reply_class);
    }
}

fn parse_single_rsp_stop_reply(bytes: &[u8]) -> Result<Option<u8>, Box<dyn Error>> {
    let packet_start = match bytes.first() {
        None => return Ok(None),
        Some(b'+') if bytes.len() == 1 => return Ok(None),
        Some(b'+') => 1,
        Some(b'$') => 0,
        Some(byte) => {
            return Err(
                format!("read-only RSP reply has unexpected leading byte {byte:#04x}").into(),
            );
        }
    };
    if bytes.get(packet_start) != Some(&b'$') {
        return Err("read-only RSP acknowledgement was not followed by one packet".into());
    }

    let Some(relative_checksum) = bytes[packet_start + 1..]
        .iter()
        .position(|byte| *byte == b'#')
    else {
        return Ok(None);
    };
    let checksum_offset = packet_start + 1 + relative_checksum;
    let packet_end = checksum_offset + 3;
    if bytes.len() < packet_end {
        return Ok(None);
    }
    if bytes.len() != packet_end {
        return Err("read-only RSP reply contains trailing or multiple packets".into());
    }

    let payload = &bytes[packet_start + 1..checksum_offset];
    if payload.len() < 3
        || !matches!(payload[0], b'T' | b'S' | b'W' | b'X')
        || decode_rsp_hex(payload[1]).is_none()
        || decode_rsp_hex(payload[2]).is_none()
    {
        return Err(
            format!("read-only RSP query returned an invalid stop reply: {payload:?}").into(),
        );
    }
    let high = decode_rsp_hex(bytes[checksum_offset + 1])
        .ok_or("read-only RSP reply has invalid checksum syntax")?;
    let low = decode_rsp_hex(bytes[checksum_offset + 2])
        .ok_or("read-only RSP reply has invalid checksum syntax")?;
    let supplied_checksum = (high << 4) | low;
    let computed_checksum = payload
        .iter()
        .fold(0_u8, |checksum, byte| checksum.wrapping_add(*byte));
    if supplied_checksum != computed_checksum {
        return Err("read-only RSP reply checksum does not match its payload".into());
    }

    Ok(Some(payload[0]))
}

fn decode_rsp_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[test]
fn rsp_safe_read_requires_one_authenticated_stop_reply() {
    assert_eq!(
        parse_single_rsp_stop_reply(b"+$T05#b9").expect("valid stop reply"),
        Some(b'T')
    );
    assert_eq!(
        parse_single_rsp_stop_reply(b"$S05#b8").expect("valid stop reply without ack"),
        Some(b'S')
    );
    assert_eq!(
        parse_single_rsp_stop_reply(b"+").expect("incomplete acknowledgement"),
        None
    );
    assert_eq!(
        parse_single_rsp_stop_reply(b"+$T05#").expect("incomplete checksum"),
        None
    );
}

#[test]
fn rsp_safe_read_rejects_errors_malformed_checksums_and_extra_data() {
    for invalid in [
        b"+$E22#a9".as_slice(),
        b"+$T05#00".as_slice(),
        b"+$T05#xz".as_slice(),
        b"+$T05#b9+".as_slice(),
        b"+$T05#b9$S05#b8".as_slice(),
        b"++$T05#b9".as_slice(),
    ] {
        assert!(
            parse_single_rsp_stop_reply(invalid).is_err(),
            "accepted hostile RSP reply {invalid:?}"
        );
    }
}

fn reserve_loopback_address() -> Result<SocketAddr, Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    drop(listener);
    Ok(address)
}

/// Yields to the external service without making host scheduling part of the assertion.
fn wait_for_external_progress(timeout: Duration) -> Result<(), Box<dyn Error>> {
    let readiness = Mutex::new(false);
    let changed = Condvar::new();
    let guard = readiness
        .lock()
        .map_err(|_| "midpoint readiness mutex was poisoned")?;
    let _ = changed
        .wait_timeout(guard, timeout)
        .map_err(|_| "midpoint readiness wait was poisoned")?;
    Ok(())
}

fn required_path(name: &str) -> Result<PathBuf, Box<dyn Error>> {
    std::env::var_os(name)
        .map(PathBuf::from)
        .ok_or_else(|| format!("missing {name}").into())
}

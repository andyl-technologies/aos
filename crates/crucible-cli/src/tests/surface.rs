//! CLI parsing, planning, backend selection, and run workflow tests.

use super::*;

use clap::CommandFactory;

pub(super) const TEST_SCENARIO: &str = "builtin:happy-path.scn";

#[derive(Default)]
pub(super) struct RecordingOperationRecorder {
    session_commands: Vec<SessionCommandKind>,
    api_calls: Vec<CliApiCall>,
    drivers: Vec<CliDelegatedDriver>,
    state_references: Vec<CliStateReferenceKind>,
}

impl CliOperationRecorder for RecordingOperationRecorder {
    fn record_session_command(&mut self, command: SessionCommandKind) {
        self.session_commands.push(command);
    }

    fn record_api_call(&mut self, call: CliApiCall) {
        self.api_calls.push(call);
    }

    fn record_driver(&mut self, driver: CliDelegatedDriver) {
        self.drivers.push(driver);
    }

    fn record_state_reference(&mut self, reference: CliStateReferenceKind) {
        self.state_references.push(reference);
    }
}

#[derive(Default)]
pub(super) struct RecordingBackendRouteRecorder {
    pub(super) remote_daemons: Vec<String>,
    pub(super) local_backends: Vec<ResolvedLocalBackend>,
    pub(super) announcements: Vec<String>,
}

impl BackendRouteRecorder for RecordingBackendRouteRecorder {
    fn record_remote_daemon(&mut self, daemon: &str) {
        self.remote_daemons.push(daemon.to_string());
    }

    fn record_local_backend(&mut self, backend: &ResolvedLocalBackend) {
        self.local_backends.push(backend.clone());
    }

    fn record_backend_announcement(&mut self, message: &str) {
        self.announcements.push(message.to_string());
    }
}

#[derive(Default)]
pub(super) struct RecordingBackendCommandRunner {
    pub(super) local_runs: Vec<ResolvedLocalBackend>,
    pub(super) remote_runs: Vec<String>,
    pub(super) outcomes: Vec<BackendCommandOutcome>,
    pub(super) evidence_override: Option<BackendExecutionEvidence>,
}

impl BackendCommandRunner for RecordingBackendCommandRunner {
    fn run_local(
        &mut self,
        backend: &ResolvedLocalBackend,
        thin_plan: &CliThinWrapperPlan,
        backend_plan: &BackendSelectionPlan,
        ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
        _run_plan: Option<&RunInvocationPlan>,
        _verify_plan: Option<&VerifyInvocationPlan>,
        _save_plan: Option<&SaveInvocationPlan>,
    ) -> Result<BackendCommandExecution, CliError> {
        self.local_runs.push(backend.clone());
        let outcome = backend_command_outcome(thin_plan, backend_plan, ergonomics_plan);
        self.outcomes.push(outcome.clone());
        Ok(BackendCommandExecution {
            outcome,
            evidence: self
                .evidence_override
                .clone()
                .or_else(|| backend_plan.expected_execution_evidence())
                .ok_or_else(|| backend_error("test local route has no execution identity"))?,
        })
    }

    fn run_remote(
        &mut self,
        daemon: &str,
        thin_plan: &CliThinWrapperPlan,
        backend_plan: &BackendSelectionPlan,
        ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
        _run_plan: Option<&RunInvocationPlan>,
        _verify_plan: Option<&VerifyInvocationPlan>,
        _save_plan: Option<&SaveInvocationPlan>,
    ) -> Result<BackendCommandExecution, CliError> {
        self.remote_runs.push(daemon.to_string());
        let outcome = backend_command_outcome(thin_plan, backend_plan, ergonomics_plan);
        self.outcomes.push(outcome.clone());
        Ok(BackendCommandExecution {
            outcome,
            evidence: self.evidence_override.clone().unwrap_or_else(|| {
                BackendExecutionEvidence::RemoteDaemon {
                    daemon: daemon.to_string(),
                }
            }),
        })
    }
}

#[derive(Default)]
pub(super) struct RecordingDeterminismErgonomicsRecorder {
    pub(super) seeds: Vec<ResolvedSeed>,
    pub(super) formats: Vec<OutputFormat>,
    pub(super) failure_rules: Vec<FailureArtifactRule>,
}

impl DeterminismErgonomicsRecorder for RecordingDeterminismErgonomicsRecorder {
    fn record_seed_resolution(&mut self, seed: &ResolvedSeed) {
        self.seeds.push(seed.clone());
    }

    fn record_trace_format(&mut self, format: OutputFormat) {
        self.formats.push(format);
    }

    fn record_failure_artifact_rule(&mut self, rule: &FailureArtifactRule) {
        self.failure_rules.push(rule.clone());
    }
}

pub(super) fn write_valid_run_scenario(temp: &TempDir) -> Result<PathBuf, Box<dyn Error>> {
    let form = valid_run_scenario_form()?;
    let path = temp.path().join("scenario.toml");
    fs::write(&path, form.to_canonical_toml()?)?;
    Ok(path)
}

pub(super) fn valid_run_scenario_form() -> Result<crucible::ScenarioDefForm, Box<dyn Error>> {
    let fixture = crucible::happy_path_scenario()?;
    Ok(crucible::ScenarioDefForm::from_components(
        fixture.scenario.world(),
        &crucible::Plan::empty(),
        &crucible::Properties::empty(),
        fixture.scenario.seed(),
    )?)
}

pub(super) fn write_search_frontier_scenario(temp: &TempDir) -> Result<PathBuf, Box<dyn Error>> {
    let form = search_frontier_scenario_form()?;
    let path = temp.path().join("search-frontier-scenario.toml");
    fs::write(&path, form.to_canonical_toml()?)?;
    Ok(path)
}

pub(super) fn write_search_named_truth_scenario(temp: &TempDir) -> Result<PathBuf, Box<dyn Error>> {
    let form = search_named_truth_scenario_form()?;
    let path = temp.path().join("search-named-truth-scenario.toml");
    fs::write(&path, form.to_canonical_toml()?)?;
    Ok(path)
}

pub(super) fn write_search_retained_evidence_scenario(
    temp: &TempDir,
) -> Result<PathBuf, Box<dyn Error>> {
    let form = search_retained_evidence_scenario_form()?;
    let path = temp.path().join("search-retained-evidence-scenario.toml");
    fs::write(&path, form.to_canonical_toml()?)?;
    Ok(path)
}

pub(super) fn write_search_terminal_quiescence_scenario(
    temp: &TempDir,
) -> Result<PathBuf, Box<dyn Error>> {
    let form = search_terminal_quiescence_scenario_form()?;
    let path = temp.path().join("search-terminal-quiescence-scenario.toml");
    fs::write(&path, form.to_canonical_toml()?)?;
    Ok(path)
}

pub(super) fn write_search_terminal_sometimes_scenario(
    temp: &TempDir,
) -> Result<PathBuf, Box<dyn Error>> {
    let form = search_terminal_sometimes_scenario_form()?;
    let path = temp.path().join("search-terminal-sometimes-scenario.toml");
    fs::write(&path, form.to_canonical_toml()?)?;
    Ok(path)
}

pub(super) fn search_named_truth_scenario_form() -> Result<crucible::ScenarioDefForm, Box<dyn Error>>
{
    let world = search_frontier_world()?;
    let properties = crucible::Properties::from_assertions_for_world(
        &world,
        vec![crucible::AssertionDef {
            id: crucible::AssertionId::from_name("cli-search-named-truth"),
            message: String::from("CLI search named truth must hold"),
            property: crucible::Property::Always {
                predicate: crucible::Predicate::named("cli-search/named-truth"),
            },
        }],
    )?;
    Ok(crucible::ScenarioDefForm::from_components(
        &world,
        &crucible::Plan::empty(),
        &properties,
        crucible::Seed::from_u64(0x5151),
    )?)
}

pub(super) fn search_retained_evidence_scenario_form()
-> Result<crucible::ScenarioDefForm, Box<dyn Error>> {
    let world = search_retained_evidence_world()?;
    let properties = crucible::Properties::from_assertions_for_world(
        &world,
        vec![crucible::AssertionDef {
            id: crucible::AssertionId::from_name("cli-search-retained-evidence"),
            message: String::from("CLI search retained evidence marker must not appear"),
            property: crucible::Property::Always {
                predicate: crucible::Predicate::not(crucible::Predicate::guest_marker(
                    crucible::MarkerId::from_name("forbidden-search-marker"),
                )),
            },
        }],
    )?;
    Ok(crucible::ScenarioDefForm::from_components(
        &world,
        &crucible::Plan::empty(),
        &properties,
        crucible::Seed::from_u64(0x5252),
    )?)
}

pub(super) fn search_terminal_quiescence_scenario_form()
-> Result<crucible::ScenarioDefForm, Box<dyn Error>> {
    let world = search_retained_evidence_world()?;
    let properties = crucible::Properties::from_assertions_for_world(
        &world,
        vec![crucible::AssertionDef {
            id: crucible::AssertionId::from_name("cli-search-retained-terminal-quiescence"),
            message: String::from("CLI search terminal quiescence must not be retained"),
            property: crucible::Property::AfterQuiescence {
                predicate: crucible::Predicate::not(crucible::Predicate::quiescent()),
            },
        }],
    )?;
    Ok(crucible::ScenarioDefForm::from_components(
        &world,
        &crucible::Plan::empty(),
        &properties,
        crucible::Seed::from_u64(0x5353),
    )?)
}

pub(super) fn search_terminal_sometimes_scenario_form()
-> Result<crucible::ScenarioDefForm, Box<dyn Error>> {
    let world = search_retained_evidence_world()?;
    let properties = crucible::Properties::from_assertions_for_world(
        &world,
        vec![crucible::AssertionDef {
            id: crucible::AssertionId::from_name("cli-search-retained-terminal-sometimes"),
            message: String::from("CLI search terminal retained marker must eventually appear"),
            property: crucible::Property::Sometimes {
                predicate: crucible::Predicate::guest_marker(crucible::MarkerId::from_name(
                    "never-terminal-sometimes-marker",
                )),
            },
        }],
    )?;
    Ok(crucible::ScenarioDefForm::from_components(
        &world,
        &crucible::Plan::empty(),
        &properties,
        crucible::Seed::from_u64(0x5454),
    )?)
}

pub(super) fn write_search_schedule_named_truths(
    temp: &TempDir,
    value: bool,
) -> Result<PathBuf, Box<dyn Error>> {
    let path = temp.path().join(if value {
        "search-named-truths-true.toml"
    } else {
        "search-named-truths-false.toml"
    });
    fs::write(&path, valid_search_schedule_named_truths_toml(value))?;
    Ok(path)
}

pub(super) fn valid_search_schedule_named_truths_toml(value: bool) -> String {
    format!(
        r#"schema = "crucible.search-schedule-named-truths.v1"

[[truth]]
name = "cli-search/named-truth"
value = {value}
"#
    )
}

pub(super) fn write_search_retained_evidence(temp: &TempDir) -> Result<PathBuf, Box<dyn Error>> {
    let path = temp.path().join("search-retained-evidence.toml");
    fs::write(&path, valid_search_retained_evidence_toml("root"))?;
    Ok(path)
}

pub(super) fn write_search_terminal_quiescence_retained_evidence(
    temp: &TempDir,
) -> Result<PathBuf, Box<dyn Error>> {
    let path = temp
        .path()
        .join("search-terminal-quiescence-retained-evidence.toml");
    fs::write(
        &path,
        valid_search_terminal_quiescence_retained_evidence_toml("root"),
    )?;
    Ok(path)
}

pub(super) fn write_search_terminal_sometimes_retained_evidence(
    temp: &TempDir,
) -> Result<PathBuf, Box<dyn Error>> {
    let path = temp
        .path()
        .join("search-terminal-sometimes-retained-evidence.toml");
    fs::write(
        &path,
        valid_search_terminal_sometimes_retained_evidence_toml("root"),
    )?;
    Ok(path)
}

pub(super) fn valid_search_retained_evidence_toml(configuration: &str) -> String {
    format!(
        r#"schema = "crucible.search-retained-evidence.v1"

[[evidence]]
configuration = "{configuration}"
kind = "guest-marker"
node = "cli-search-retained-node"
marker = "forbidden-search-marker"
retired_icount = 7
"#
    )
}

pub(super) fn valid_search_terminal_quiescence_retained_evidence_toml(
    configuration: &str,
) -> String {
    format!(
        r#"schema = "crucible.search-retained-evidence.v1"

[[evidence]]
configuration = "{configuration}"
kind = "terminal-quiescence"
quiescent = true
"#
    )
}

pub(super) fn valid_search_terminal_sometimes_retained_evidence_toml(
    configuration: &str,
) -> String {
    format!(
        r#"schema = "crucible.search-retained-evidence.v1"

[[evidence]]
configuration = "{configuration}"
kind = "evaluation-boundary"
virtual_time_ticks = 50

[[evidence]]
configuration = "{configuration}"
kind = "terminal-quiescence"
quiescent = true
"#
    )
}

pub(super) fn valid_fuzz_family_toml() -> &'static str {
    r#"schema = "crucible.scenario-family.v2"
topology_shapes = ["ring"]

[seed_space]
kind = "generated"
meta_seed = "0x55"
count = 2

[topology_size]
min = 1
max = 2

[node_template]
fixed_icount = 17
cmdline = "cli-fuzz-family"
"#
}

pub(super) fn write_valid_fuzz_family(temp: &TempDir) -> Result<PathBuf, Box<dyn Error>> {
    let path = temp.path().join("family.toml");
    fs::write(&path, valid_fuzz_family_toml())?;
    Ok(path)
}

pub(super) fn write_signed_triage_findings_ledger(
    dir: &Path,
    store_root: &Path,
    file_name: &str,
    discovery_signature_assertion: Option<&str>,
) -> Result<(PathBuf, crucible::FindingReproductionArtifact), Box<dyn Error>> {
    fs::create_dir_all(dir)?;
    let form = search_frontier_scenario_form()?;
    let configuration = crucible::try_step(
        &crucible::Configuration::genesis(form.scenario_def()),
        search_frontier_decisions()
            .into_iter()
            .nth(1)
            .ok_or_else(|| std::io::Error::other("missing triage fixture decision"))?,
    )?;
    let finding_fingerprint = crucible::ContentHash::from_bytes(b"cli triage signed finding");
    let finding = crucible::FindingReproductionArtifact::capture(
        crucible::FindingDiscoveryPath::StateSpaceSearch,
        finding_fingerprint,
        &form,
        &configuration,
    )?;
    let store = crucible::LocalDagStore::new(store_root.to_path_buf());
    let artifact = finding.store_artifact(&store)?;
    assert_eq!(artifact, finding.artifact.id());

    let assertion = "cli-triage-signed-finding";
    let mut ledger = format!(
        "\
{FAILURE_TRIAGE_FINDINGS_LEDGER_SCHEMA_V2}
finding.0.artifact={artifact}
finding.0.discovery_path=state-space-search
finding.0.finding_fingerprint={finding_fingerprint}
finding.0.assertion={assertion}
finding.0.message=CLI triage signed finding violated
finding.0.quantifier=always
finding.0.event_kind=assertion_state_changed
finding.0.at_icount=8
finding.0.at_virtual_time=8
finding.0.node=triage-node
finding.0.detail=synthetic signed finding evidence
",
        artifact = artifact.to_hex(),
        finding_fingerprint = finding_fingerprint.to_hex()
    );
    if let Some(discovery_signature_assertion) = discovery_signature_assertion {
        ledger.push_str(&format!(
            "finding.0.discovery_signature.assertion={discovery_signature_assertion}\n"
        ));
    }
    let path = dir.join(file_name);
    fs::write(&path, ledger)?;
    Ok((path, finding))
}

pub(super) fn search_frontier_scenario_form() -> Result<crucible::ScenarioDefForm, Box<dyn Error>> {
    let world = search_frontier_world()?;
    Ok(crucible::ScenarioDefForm::from_components(
        &world,
        &crucible::Plan::empty(),
        &crucible::Properties::empty(),
        crucible::Seed::default(),
    )?)
}

pub(super) fn search_frontier_world() -> Result<crucible::World, Box<dyn Error>> {
    Ok(crucible::World::from_nodes(vec![crucible::WorldNode {
        id: crucible::NodeId {
            name: String::from("cli-search-node"),
        },
        arch: crucible::NodeTemplate::DEFAULT_ARCH,
        memory_mib: crucible::NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: String::from("crucible-cli-search-frontier"),
        ready_point: crucible::ReadyPoint::FixedIcount {
            icount: crucible::Icount { retired: 100 },
        },
        white_box: crucible::WhiteBoxPolicy::Disabled,
        smp_vcpus: crucible::NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: crucible::NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }])?)
}

pub(super) fn search_retained_evidence_world() -> Result<crucible::World, Box<dyn Error>> {
    Ok(crucible::World::from_nodes(vec![crucible::WorldNode {
        id: crucible::NodeId {
            name: String::from("cli-search-retained-node"),
        },
        arch: crucible::NodeTemplate::DEFAULT_ARCH,
        memory_mib: crucible::NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: String::from("crucible-cli-search-retained"),
        ready_point: crucible::ReadyPoint::FixedIcount {
            icount: crucible::Icount { retired: 100 },
        },
        white_box: crucible::WhiteBoxPolicy::Enabled,
        smp_vcpus: crucible::NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: crucible::NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }])?)
}

pub(super) fn search_frontier_decisions() -> Vec<crucible::Decision> {
    vec![
        crucible::Decision::RngDraw(crucible::RngDecision {
            stream: crucible::RngStreamId::from_name("cli-search/packet-loss"),
            value: 1,
        }),
        crucible::Decision::RngDraw(crucible::RngDecision {
            stream: crucible::RngStreamId::from_name("cli-search/decision-rng"),
            value: 0xa5a5_5a5a,
        }),
        crucible::Decision::Override(crucible::OverrideDecision {
            point: crucible::SchedulingPoint {
                key: String::from("cli-search/scheduler-point"),
            },
            choice: crucible::ChoiceTag {
                name: String::from("non-default-choice"),
            },
        }),
    ]
}

pub(super) fn write_property_selector_scenario(temp: &TempDir) -> Result<PathBuf, Box<dyn Error>> {
    let form = property_selector_scenario_form()?;
    let path = temp.path().join("property-selector-scenario.toml");
    fs::write(&path, form.to_canonical_toml()?)?;
    Ok(path)
}

pub(super) fn property_selector_scenario_form() -> Result<crucible::ScenarioDefForm, Box<dyn Error>>
{
    let fixture = crucible::happy_path_scenario()?;
    let properties = crucible::Properties::from_assertions_for_world(
        fixture.scenario.world(),
        vec![
            property_selector_assertion(SAVE_DOUBLE_ASSERTION_VIOLATION),
            property_selector_assertion("split-active"),
        ],
    )?;
    Ok(crucible::ScenarioDefForm::from_components(
        fixture.scenario.world(),
        &crucible::Plan::empty(),
        &properties,
        fixture.scenario.seed(),
    )?)
}

pub(super) fn write_marker_selector_scenario(temp: &TempDir) -> Result<PathBuf, Box<dyn Error>> {
    write_marker_selector_scenario_with_policy(
        temp,
        "marker-selector-scenario.toml",
        crucible::WhiteBoxPolicy::Enabled,
    )
}

pub(super) fn write_marker_selector_without_source_scenario(
    temp: &TempDir,
) -> Result<PathBuf, Box<dyn Error>> {
    write_marker_selector_scenario_with_policy(
        temp,
        "marker-selector-no-source-scenario.toml",
        crucible::WhiteBoxPolicy::Disabled,
    )
}

pub(super) fn write_marker_selector_scenario_with_policy(
    temp: &TempDir,
    file_name: &str,
    white_box: crucible::WhiteBoxPolicy,
) -> Result<PathBuf, Box<dyn Error>> {
    let form = marker_selector_scenario_form(white_box)?;
    let path = temp.path().join(file_name);
    fs::write(&path, form.to_canonical_toml()?)?;
    Ok(path)
}

pub(super) fn marker_selector_scenario_form(
    white_box: crucible::WhiteBoxPolicy,
) -> Result<crucible::ScenarioDefForm, Box<dyn Error>> {
    let world = crucible::World::from_nodes(vec![crucible::WorldNode {
        id: crucible::NodeId {
            name: String::from("marker-node"),
        },
        arch: crucible::NodeTemplate::DEFAULT_ARCH,
        memory_mib: crucible::NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: String::from("crucible-marker-selector=1 crucible-guest-marker=phase-two-marker"),
        ready_point: crucible::ReadyPoint::FixedIcount {
            icount: crucible::Icount { retired: 1 },
        },
        white_box,
        smp_vcpus: crucible::NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: crucible::NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }])?;
    Ok(crucible::ScenarioDefForm::from_components(
        &world,
        &crucible::Plan::empty(),
        &crucible::Properties::empty(),
        crucible::Seed::from_u64(14),
    )?)
}

pub(super) fn property_selector_assertion(name: &str) -> crucible::AssertionDef {
    crucible::AssertionDef {
        id: crucible::AssertionId::from_name(name),
        message: format!("{name} test selector"),
        property: crucible::Property::Always {
            predicate: crucible::Predicate::at(crucible::VirtualTime { ticks: 999 }),
        },
    }
}

pub(super) fn spawn_production_lifecycle_server() -> Result<String, Box<dyn Error>> {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
    listener.set_nonblocking(true)?;
    let address = listener.local_addr()?;
    std::thread::spawn(move || {
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(_) => return,
        };
        runtime.block_on(async move {
            let listener = match tokio::net::TcpListener::from_std(listener) {
                Ok(listener) => listener,
                Err(_) => return,
            };
            let control_plane = LifecycleControlPlane::new(
                "crucible-cli-test-daemon",
                Vec::new(),
                |_scenario: &crucible::ScenarioDef, _seed| QuiescentLifecycleLoop::new(),
            );
            let _server = crucible_api::serve_lifecycle_http2(listener, control_plane).await;
        });
    });
    Ok(address.to_string())
}

pub(super) fn spawn_save_recording_lifecycle_server() -> Result<String, Box<dyn Error>> {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
    listener.set_nonblocking(true)?;
    let address = listener.local_addr()?;
    std::thread::spawn(move || {
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(_) => return,
        };
        runtime.block_on(async move {
            let listener = match tokio::net::TcpListener::from_std(listener) {
                Ok(listener) => listener,
                Err(_) => return,
            };
            let control_plane = LifecycleControlPlane::new_with_source_factory(
                "crucible-cli-save-selector-test-daemon",
                Vec::new(),
                move |_scenario: &crucible::ScenarioDef, scenario_form, _seed| {
                    let scenario_form = scenario_form
                        .expect("save selector daemon requires inline scenario source");
                    SaveRecordingLifecycleLoop::new(SaveRecordingSources::from_scenario_form(
                        scenario_form,
                    ))
                    .with_selector_delay_quanta(2)
                },
            );
            let _server = crucible_api::serve_lifecycle_http2(listener, control_plane).await;
        });
    });
    Ok(address.to_string())
}

pub(super) fn spawn_resume_recording_lifecycle_server(
    fixture: ResumeRecordingFixture,
    frontier: VirtualTime,
) -> Result<String, Box<dyn Error>> {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
    listener.set_nonblocking(true)?;
    let address = listener.local_addr()?;
    std::thread::spawn(move || {
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(_) => return,
        };
        runtime.block_on(async move {
            let listener = match tokio::net::TcpListener::from_std(listener) {
                Ok(listener) => listener,
                Err(_) => return,
            };
            let control_plane = LifecycleControlPlane::new(
                "crucible-cli-resume-test-daemon",
                Vec::new(),
                move |_scenario: &crucible::ScenarioDef, _seed| match fixture.clone() {
                    ResumeRecordingFixture::None => ResumeRecordingLifecycleLoop::new(frontier),
                    ResumeRecordingFixture::PropertyViolation { assertion } => {
                        ResumeRecordingLifecycleLoop::with_property_violation(frontier, assertion)
                    }
                },
            );
            let _server = crucible_api::serve_lifecycle_http2(listener, control_plane).await;
        });
    });
    Ok(address.to_string())
}

#[derive(Default)]
pub(super) struct FakeSeedEnvironment {
    pub(super) seed: Option<String>,
}

impl SeedEnvironment for FakeSeedEnvironment {
    fn variable(&self, name: &'static str) -> Option<String> {
        if name == CRUCIBLE_SEED_ENV {
            self.seed.clone()
        } else {
            None
        }
    }
}

pub(super) struct FakeSeedEntropySource {
    pub(super) next: u64,
    pub(super) draws: usize,
}

impl FakeSeedEntropySource {
    pub(super) fn new(next: u64) -> Self {
        Self { next, draws: 0 }
    }
}

impl SeedEntropySource for FakeSeedEntropySource {
    fn generated_seed(&mut self) -> Result<u64, CliError> {
        self.draws += 1;
        Ok(self.next)
    }
}

#[derive(Default)]
pub(super) struct FakeQemuDiscoveryEnvironment {
    qemu: Option<String>,
    plugin: Option<String>,
}

impl QemuDiscoveryEnvironment for FakeQemuDiscoveryEnvironment {
    fn variable(&self, name: &'static str) -> Option<String> {
        match name {
            CRUCIBLE_QEMU_ENV => self.qemu.clone(),
            CRUCIBLE_PLUGIN_ENV => self.plugin.clone(),
            _ => None,
        }
    }
}

#[derive(Default)]
pub(super) struct FakeAosQemuPackageSet {
    qemu: Option<PathBuf>,
    plugin: Option<PathBuf>,
}

impl AosQemuPackageSet for FakeAosQemuPackageSet {
    fn qemu_path(&self) -> Option<PathBuf> {
        self.qemu.clone()
    }

    fn plugin_path(&self) -> Option<PathBuf> {
        self.plugin.clone()
    }
}

pub(super) fn canonical_trace_entries() -> Vec<CanonicalLogEntry> {
    vec![
        CanonicalLogEntry {
            sequence: 0,
            virtual_time_ticks: 10,
            node: String::from("node-a"),
            kind: String::from("decision"),
            summary: String::from("deliver packet"),
        },
        CanonicalLogEntry {
            sequence: 1,
            virtual_time_ticks: 12,
            node: String::from("node-b"),
            kind: String::from("assertion"),
            summary: String::from("property ok"),
        },
    ]
}

pub(super) fn verify_compare_artifacts_with_paths(
    left: &Path,
    right_bytes: &[u8],
    _cli: &Cli,
) -> Result<CliError, Box<dyn Error>> {
    let temp = TempDir::new()?;
    let right = temp.path().join("right.crucible");
    fs::write(&right, right_bytes)?;
    let compare_cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--backend"),
        String::from("double"),
        String::from("verify"),
        String::from("--compare"),
        left.display().to_string(),
        right.display().to_string(),
    ]);
    let Commands::Verify(args) = &compare_cli.command else {
        panic!("expected verify command");
    };
    let verify_plan = plan_verify_invocation(args, temp.path())?;
    let error = execute_backend_routed_command(
        &plan_cli_invocation(&compare_cli),
        &plan_backend_selection(&compare_cli)?.expect("verify should require backend selection"),
        None,
        None,
        Some(&verify_plan),
        None,
        &mut NullBackendCommandRunner,
    )
    .expect_err("mismatched compare artifacts should fail");
    Ok(error)
}

pub(super) fn temp_qemu_artifacts(temp: &TempDir) -> Result<(String, String), Box<dyn Error>> {
    qemu_artifacts_in_dir(
        temp.path(),
        "test-qemu-build-v1",
        &required_qemu_plugin_abi(),
    )
}

pub(super) fn qemu_artifacts_in_dir(
    dir: &Path,
    qemu_build_id: &str,
    plugin_abi: &str,
) -> Result<(String, String), Box<dyn Error>> {
    fs::create_dir_all(dir)?;
    let qemu = dir.join("qemu-system-x86_64");
    let plugin = dir.join("crucible-qemu-plugin.so");
    fs::copy(std::env::current_exe()?, &qemu)?;
    fs::write(&plugin, qemu_plugin_elf_fixture())?;
    write_qemu_artifact_markers(dir, qemu_build_id, plugin_abi)?;
    Ok((
        qemu.to_string_lossy().into_owned(),
        plugin.to_string_lossy().into_owned(),
    ))
}

fn qemu_plugin_elf_fixture() -> Vec<u8> {
    qemu_plugin_elf_fixture_with_symbol_section(1)
}

fn qemu_plugin_elf_fixture_with_symbol_section(symbol_section: u16) -> Vec<u8> {
    let strings = b"\0qemu_plugin_install\0qemu_plugin_version\0";
    let string_offset = 64_usize;
    let symbol_offset = (string_offset + strings.len() + 7) & !7;
    let section_offset = symbol_offset + 3 * 24;
    let mut bytes = vec![0_u8; section_offset + 3 * 64];
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[16..18].copy_from_slice(&3_u16.to_le_bytes());
    bytes[40..48].copy_from_slice(&(section_offset as u64).to_le_bytes());
    bytes[58..60].copy_from_slice(&64_u16.to_le_bytes());
    bytes[60..62].copy_from_slice(&3_u16.to_le_bytes());
    bytes[string_offset..string_offset + strings.len()].copy_from_slice(strings);

    let install = symbol_offset + 24;
    bytes[install..install + 4].copy_from_slice(&1_u32.to_le_bytes());
    bytes[install + 4] = 0x12;
    bytes[install + 6..install + 8].copy_from_slice(&symbol_section.to_le_bytes());
    let version = symbol_offset + 48;
    let version_name = 1 + b"qemu_plugin_install".len() + 1;
    bytes[version..version + 4].copy_from_slice(&(version_name as u32).to_le_bytes());
    bytes[version + 4] = 0x11;
    bytes[version + 6..version + 8].copy_from_slice(&symbol_section.to_le_bytes());

    let dynstr = section_offset + 64;
    bytes[dynstr + 4..dynstr + 8].copy_from_slice(&3_u32.to_le_bytes());
    bytes[dynstr + 24..dynstr + 32].copy_from_slice(&(string_offset as u64).to_le_bytes());
    bytes[dynstr + 32..dynstr + 40].copy_from_slice(&(strings.len() as u64).to_le_bytes());
    let dynsym = section_offset + 128;
    bytes[dynsym + 4..dynsym + 8].copy_from_slice(&11_u32.to_le_bytes());
    bytes[dynsym + 24..dynsym + 32].copy_from_slice(&(symbol_offset as u64).to_le_bytes());
    bytes[dynsym + 32..dynsym + 40].copy_from_slice(&(72_u64).to_le_bytes());
    bytes[dynsym + 40..dynsym + 44].copy_from_slice(&1_u32.to_le_bytes());
    bytes[dynsym + 56..dynsym + 64].copy_from_slice(&(24_u64).to_le_bytes());
    bytes
}

#[test]
fn cli_hermetic_qemu_discovery_rejects_text_artifact_impersonation() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let (qemu, plugin) = temp_qemu_artifacts(&temp)?;
    fs::write(&qemu, b"#!/bin/false\n")?;
    let error = validate_qemu_artifacts(Path::new(&qemu), Path::new(&plugin))
        .expect_err("a text file must not impersonate the patched executable");
    assert!(error.to_string().contains("ELF artifact"));

    fs::copy(std::env::current_exe()?, &qemu)?;
    fs::write(&plugin, b"qemu_plugin_install\0qemu_plugin_version\0")?;
    let error = validate_qemu_artifacts(Path::new(&qemu), Path::new(&plugin))
        .expect_err("symbol-shaped text must not impersonate the plugin");
    assert!(error.to_string().contains("ELF artifact"));

    let mut names_only = vec![0_u8; 64];
    names_only[..4].copy_from_slice(b"\x7fELF");
    names_only[4] = 2;
    names_only[5] = 1;
    names_only[16..18].copy_from_slice(&3_u16.to_le_bytes());
    names_only.extend_from_slice(b"qemu_plugin_install\0qemu_plugin_version\0");
    fs::write(&plugin, names_only)?;
    let error = probe_qemu_plugin(Path::new(&plugin))
        .expect_err("names outside .dynsym must not impersonate exported symbols");
    assert!(error.to_string().contains("dynamic symbol table"));

    fs::write(&plugin, qemu_plugin_elf_fixture_with_symbol_section(0))?;
    let error = probe_qemu_plugin(Path::new(&plugin))
        .expect_err("undefined dynamic symbols must not satisfy plugin discovery");
    assert!(error.to_string().contains("qemu_plugin_install"));
    Ok(())
}

pub(super) fn write_qemu_artifact_markers(
    dir: &Path,
    qemu_build_id: &str,
    plugin_abi: &str,
) -> Result<(), Box<dyn Error>> {
    let shmem_abi_version = crucible::SHMEM_ABI_VERSION;
    fs::write(
        dir.join("qemu-build-identity.env"),
        format!(
            "qemu_plugins_enabled=true\nqemu_crucible_patches_applied=true\nqemu_sim_capability=qemu-crucible\nqemu_patch_series_hash=sha256-test-qemu-patch-series\nqemu_shmem_abi_version={shmem_abi_version}\nqemu_shmem_abi={plugin_abi}\nqemu_shmem_header=include/aos/crucible/crucible_shmem_abi.h\nqemu_shmem_header_hash=sha256-test-shmem-header\nqemu_build_id={qemu_build_id}\n"
        ),
    )?;
    fs::write(
        dir.join("crucible-qemu-plugin-build-info"),
        format!(
            "package=crucible-qemu-plugin\nqemu_package=qemu-crucible\nqemu_build_id={qemu_build_id}\nshmem_abi_version={shmem_abi_version}\nshmem_abi={plugin_abi}\nshmem_generated_header=include/aos/crucible/crucible_shmem_abi.h\nshmem_generated_header_hash=sha256-test-shmem-header\nplugin_abi={plugin_abi}\n"
        ),
    )?;
    Ok(())
}

pub(super) fn write_savepoint_handle_fixture(
    dir: &Path,
    label: &str,
    form: &crucible::ScenarioDefForm,
    schedule: &Schedule,
    checkpoint: crucible::ContentHash,
    frontier_ticks: u64,
    canonical_log: &str,
) -> Result<PathBuf, Box<dyn Error>> {
    fs::create_dir_all(dir)?;
    let scenario = form.scenario_def();
    let scenario_payload = form.to_compact_binary();
    let schedule_payload = schedule.to_compact_binary();
    let mut text = String::new();
    artifact_line(&mut text, &["schema", SAVEPOINT_HANDLE_SCHEMA]);
    artifact_line(&mut text, &["label", label]);
    artifact_line(
        &mut text,
        &["checkpoint", &format_content_hash_ref(checkpoint)],
    );
    artifact_line(
        &mut text,
        &["scenario", &scenario.id().to_hex(), "resume-scenario.toml"],
    );
    artifact_line(
        &mut text,
        &[
            "scenario-payload",
            &content_address_bytes(&scenario_payload),
            &hex_bytes(&scenario_payload),
        ],
    );
    artifact_line(
        &mut text,
        &[
            "schedule-payload",
            &content_address_bytes(&schedule_payload),
            &hex_bytes(&schedule_payload),
        ],
    );
    artifact_line(&mut text, &["frontier", &frontier_ticks.to_string()]);
    artifact_line(&mut text, &["at", "quiescence"]);
    artifact_line(&mut text, &["selector", "none"]);
    artifact_line(
        &mut text,
        &[
            "boundary-proof",
            "breakpoint",
            "1",
            "suspend",
            &frontier_ticks.to_string(),
            &schedule.len().to_string(),
        ],
    );
    let boundary_predicate = crucible::Predicate::quiescent().to_compact_binary();
    artifact_line(
        &mut text,
        &[
            "boundary-predicate",
            &content_address_bytes(&boundary_predicate),
            &hex_bytes(&boundary_predicate),
        ],
    );
    artifact_line(&mut text, &["terminal-condition", "quiescence"]);
    artifact_line(&mut text, &["materialization", "create-savepoint", "reply"]);
    artifact_line(&mut text, &["oracle", "fat==thin-passed"]);
    artifact_line(&mut text, &["canonical-log", canonical_log]);
    let path = dir.join("resume-source.crucible-savepoint");
    fs::write(&path, text)?;
    Ok(path)
}

pub(super) fn write_checkpoint_closure_fixture(
    store_root: &Path,
    form: &crucible::ScenarioDefForm,
    schedule: &Schedule,
) -> Result<crucible::ContentHash, Box<dyn Error>> {
    let checkpoint = crucible::Configuration {
        def: form.scenario_def(),
        schedule: schedule.clone(),
    }
    .id();
    let artifact = crucible::ReproductionArtifact::capture(form, schedule)?;
    let store = crucible::LocalDagStore::new(store_root.to_path_buf());
    let artifact_key = store.put(&artifact.to_compact_binary())?;
    let frontier = schedule.recorded_virtual_time().unwrap_or_default();
    let index = store.write_checkpoint_closure_index(checkpoint, artifact_key, frontier)?;
    let loaded = store.read_checkpoint_closure_index(checkpoint)?;
    assert_eq!(loaded.checkpoint, checkpoint);
    assert_eq!(loaded.reproduction_artifact, artifact_key);
    assert_eq!(loaded.frontier, frontier);
    assert!(store.exists(&index)?);
    Ok(artifact_key)
}

pub(super) fn replay_to_savepoint_schedule(len: usize) -> Schedule {
    Schedule::from_decisions((0..len).map(|index| {
        crucible::Decision::DeliveryOrder(crucible::DeliveryOrderDecision {
            at: VirtualTime {
                ticks: (index as u64).saturating_add(1),
            },
            order: Vec::new(),
        })
    }))
}

pub(super) fn externalized_replay_artifact_text(
    artifact_bytes: &[u8],
    store_root: &Path,
    keep_inline_payloads: bool,
) -> Result<String, Box<dyn Error>> {
    let mut decoded = decode_reproduction_artifact(artifact_bytes)?;
    let store = crucible::LocalDagStore::new(store_root.to_path_buf());
    let mut store_uris = BTreeMap::new();
    for payload in &decoded.payloads {
        let key = store.put(&payload.bytes)?;
        store_uris.insert(payload.digest.clone(), format_content_hash_ref(key));
    }
    if let Some(store_uri) = store_uris.get(&decoded.scenario.digest) {
        decoded.scenario.store_uri = store_uri.clone();
    }
    for component in &mut decoded.components {
        if let Some(store_uri) = store_uris.get(&component.digest) {
            component.store_uri = store_uri.clone();
        }
    }
    if !keep_inline_payloads {
        decoded.payloads.clear();
    }
    Ok(canonical_artifact_text(&decoded))
}

pub(super) fn fork_artifact_path(
    outcome: &BackendCommandOutcome,
) -> Result<PathBuf, Box<dyn Error>> {
    let line = outcome
        .stdout
        .iter()
        .find(|line| line.starts_with("fork-artifact\t"))
        .ok_or("fork workflow did not emit fork-artifact line")?;
    let path = line
        .split('\t')
        .find_map(|field| field.strip_prefix("path="))
        .ok_or("fork-artifact line did not include path")?;
    Ok(PathBuf::from(path))
}

pub(super) fn assert_fork_artifact_replays(
    cli: &Cli,
    outcome: &BackendCommandOutcome,
    expected_seed: u64,
) -> Result<(), Box<dyn Error>> {
    let path = fork_artifact_path(outcome)?;
    let report = replay_reproduction_artifact(
        cli,
        &ReplayArgs {
            artifact: path.clone(),
            to: None,
            check: None,
            bisect: None,
        },
    )?;
    assert_eq!(report.path, path);
    assert!(report.digest.starts_with(CONTENT_ADDRESS_PREFIX));
    assert_eq!(report.seed, expected_seed);
    assert!(report.check.is_none());
    assert!(report.bisect.is_none());
    Ok(())
}

pub(super) fn backend_routed_subcommand_cases() -> Vec<(CliSubcommand, Vec<&'static str>)> {
    vec![
        (CliSubcommand::Run, vec!["run", TEST_SCENARIO]),
        (CliSubcommand::Verify, vec!["verify", TEST_SCENARIO]),
        (
            CliSubcommand::Save,
            vec!["save", TEST_SCENARIO, "--at", "quiescence"],
        ),
        (
            CliSubcommand::Resume,
            vec!["resume", "blake3:test-savepoint"],
        ),
        (CliSubcommand::Fork, vec!["fork", "blake3:test-savepoint"]),
        (CliSubcommand::Replay, vec!["replay", "case.crucible"]),
        (CliSubcommand::Search, vec!["search", TEST_SCENARIO]),
        (CliSubcommand::Fuzz, vec!["fuzz", "builtin:fault-campaign"]),
        (CliSubcommand::Debug, vec!["debug", "case.crucible"]),
        (
            CliSubcommand::Serve,
            vec!["serve", "--listen", "127.0.0.1:9000"],
        ),
    ]
}

pub(super) fn cli_from_owned(args: Vec<String>) -> Cli {
    Cli::parse_from(args)
}

#[test]
fn cli_output_format_defaults_follow_stdout_destination() {
    assert_eq!(resolve_output_format(None, true), OutputFormat::Table);
    assert_eq!(resolve_output_format(None, false), OutputFormat::Jsonl);
    assert_eq!(
        resolve_output_format(Some(OutputFormat::Json), true),
        OutputFormat::Json
    );
    assert_eq!(
        resolve_output_format(Some(OutputFormat::Table), false),
        OutputFormat::Table
    );

    let cli = Cli::parse_from(["crucible", "run", TEST_SCENARIO]);
    assert_eq!(cli.format, None);
}

#[test]
pub(super) fn cli_skeleton_exposes_closed_subcommand_set() {
    let mut names = Cli::command()
        .get_subcommands()
        .map(|command| command.get_name().to_string())
        .collect::<Vec<_>>();
    names.sort();

    assert_eq!(
        names,
        [
            "campaign",
            "completions",
            "debug",
            "fork",
            "fuzz",
            "replay",
            "resume",
            "run",
            "save",
            "search",
            "selftest",
            "serve",
            "triage",
            "verify",
        ]
    );
}

#[test]
pub(super) fn cli_skeleton_parses_global_flag_block() {
    let cli = Cli::parse_from([
        "crucible",
        "--seed",
        "0x10",
        "--backend",
        "double",
        "--daemon",
        "127.0.0.1:9000",
        "--qemu",
        "/nix/store/qemu/bin/qemu-system-x86_64",
        "--plugin",
        "/nix/store/plugin/lib/crucible-qemu-plugin.so",
        "--store",
        ".crucible-store",
        "--format",
        "json",
        "--trace",
        "trace.jsonl",
        "--artifact-dir",
        "artifacts",
        "-vv",
        "--quiet",
        "run",
        TEST_SCENARIO,
    ]);

    assert_eq!(cli.seed.as_deref(), Some("0x10"));
    assert_eq!(cli.backend, Backend::Double);
    assert_eq!(cli.daemon.as_deref(), Some("127.0.0.1:9000"));
    assert_eq!(
        cli.qemu.as_ref().and_then(|path| path.to_str()),
        Some("/nix/store/qemu/bin/qemu-system-x86_64")
    );
    assert_eq!(
        cli.plugin.as_ref().and_then(|path| path.to_str()),
        Some("/nix/store/plugin/lib/crucible-qemu-plugin.so")
    );
    assert_eq!(
        cli.store.as_ref().and_then(|path| path.to_str()),
        Some(".crucible-store")
    );
    assert_eq!(cli.format, Some(OutputFormat::Json));
    assert_eq!(
        cli.trace.as_ref().and_then(|path| path.to_str()),
        Some("trace.jsonl")
    );
    assert_eq!(cli.artifact_dir.to_str(), Some("artifacts"));
    assert_eq!(cli.verbose, 2);
    assert!(cli.quiet);
    assert!(matches!(
        cli.command,
        Commands::Run(RunArgs {
            emit_mock_failure_artifact: false,
            ..
        })
    ));
}

#[test]
pub(super) fn cli_skeleton_rejects_unknown_subcommands() {
    let error = match Cli::try_parse_from(["crucible", "invented"]) {
        Ok(_) => panic!("invented subcommand must be rejected"),
        Err(error) => error,
    };

    assert_eq!(error.kind(), clap::error::ErrorKind::InvalidSubcommand);
}

#[test]
pub(super) fn cli_completions_generates_every_supported_shell_script() -> Result<(), Box<dyn Error>>
{
    let cases = [
        ("bash", Shell::Bash, "complete -F"),
        ("elvish", Shell::Elvish, "set edit:completion:arg-completer"),
        ("fish", Shell::Fish, "complete -c crucible"),
        (
            "powershell",
            Shell::PowerShell,
            "Register-ArgumentCompleter",
        ),
        ("zsh", Shell::Zsh, "#compdef crucible"),
    ];
    let covered_shells = cases.iter().map(|(_, shell, _)| *shell).collect::<Vec<_>>();
    assert_eq!(
        covered_shells,
        Shell::value_variants(),
        "completion tests must cover every shell accepted by Clap"
    );

    for (shell_name, expected_shell, shell_marker) in cases {
        let cli = Cli::parse_from(["crucible", "completions", shell_name]);
        let Commands::Completions(args) = cli.command else {
            panic!("expected completions command for {shell_name}");
        };
        assert_eq!(args.shell, expected_shell);

        let mut script = Vec::new();
        write_completions(args.shell, &mut script);
        let script = String::from_utf8(script)?;

        for needle in ["crucible", "verify", "completions", shell_marker] {
            assert!(
                script.contains(needle),
                "{shell_name} completions are missing `{needle}`:\n{script}"
            );
        }
    }

    Ok(())
}

#[test]
pub(super) fn cli_completions_requires_shell_argument() {
    let error = match Cli::try_parse_from(["crucible", "completions"]) {
        Ok(_) => panic!("completions without shell must be rejected"),
        Err(error) => error,
    };

    assert_eq!(
        error.kind(),
        clap::error::ErrorKind::MissingRequiredArgument
    );
}

#[test]
pub(super) fn cli_completions_ignores_global_daemon_for_thin_wrapper_metadata()
-> Result<(), Box<dyn Error>> {
    let cli = Cli::parse_from([
        "crucible",
        "--daemon",
        "127.0.0.1:9000",
        "completions",
        "bash",
    ]);
    let plan = plan_cli_invocation(&cli);

    assert_eq!(
        plan.delegated_drivers,
        vec![CliDelegatedDriver::ShellCompletionGenerator]
    );
    assert!(plan.state_references.is_empty());
    assert!(plan_backend_selection(&cli)?.is_none());

    Ok(())
}

#[test]
pub(super) fn cli_resume_help_and_version_surface_matches_rfc_copy() {
    let mut command = Cli::command();
    let top_help = command.render_long_help().to_string();
    for needle in [
        "Run and inspect Crucible simulations.",
        "run",
        "verify",
        "selftest",
        "save",
        "resume",
        "fork",
        "replay",
        "search",
        "fuzz",
        "serve",
        "completions",
        "--seed <u64|hex>",
        "--backend <auto|qemu|double>",
        "--daemon <addr>",
        "--qemu <path>",
        "--plugin <path>",
        "--store <path>",
        "--format <jsonl|json|table|markdown>",
        "--trace <path>",
        "--artifact-dir <path>",
        "--quiet",
    ] {
        assert!(
            top_help.contains(needle),
            "top-level help is missing `{needle}`:\n{top_help}"
        );
    }

    let version = Cli::command().render_version().to_string();
    assert_eq!(
        normalize_help_text(&version),
        format!("crucible {}", env!("CARGO_PKG_VERSION")),
        "version output must exactly name the binary and crate version"
    );
    let version_exit = Cli::try_parse_from(["crucible", "--version"])
        .expect_err("--version must render through Clap's display path");
    assert_eq!(cli_parse_error_exit_code(&version_exit), 0);

    for (name, needles) in [
        (
            "run",
            &[
                "SCENARIO",
                "--until <quiescence|virtual-time|property|stopped>",
                "--max-virtual-time <dur>",
                "--max-quanta <n>",
                "--interactive",
                "--save-on <fail|always|never>",
                "--watch",
            ][..],
        ),
        (
            "verify",
            &[
                "SCENARIO",
                "--runs <n>",
                "--adversarial",
                "--bisect",
                "--compare <a> <b>",
            ],
        ),
        (
            "selftest",
            &["--gates <list>", "--with-qemu", "--corpus <path>"],
        ),
        (
            "save",
            &[
                "SCENARIO",
                "--at <virtual-time|quiescence|property|marker>",
                "--label <name>",
                "--max-virtual-time <dur>",
                "--property <assertion>",
                "--marker <name>",
                "--out <path>",
            ],
        ),
        (
            "resume",
            &[
                "SAVEPOINT",
                "--until <quiescence|virtual-time|property|stopped>",
                "--max-virtual-time <dur>",
                "--interactive",
                "--watch",
            ],
        ),
        (
            "fork",
            &[
                "SAVEPOINT",
                "--seed <u64|hex>",
                "--override <decision=value>",
                "--until <quiescence|virtual-time|property|stopped>",
                "--max-virtual-time <dur>",
                "--label <name>",
                "--interactive",
                "--watch",
            ],
        ),
        (
            "replay",
            &[
                "ARTIFACT",
                "--to <savepoint>",
                "--check <original-log>",
                "--bisect <other-artifact>",
            ],
        ),
        (
            "search",
            &[
                "SCENARIO",
                "--strategy <bfs|dfs|guided>",
                "--max-depth <n>",
                "--max-states <n>",
                "--on-violation <stop|collect>",
                "--findings-out <path>",
                "--schedule-named-truths <path>",
            ],
        ),
        (
            "fuzz",
            &[
                "FAMILY",
                "--family <path|hash>",
                "--runs <n>",
                "--coverage <basic-block>",
                "--corpus <path>",
                "--on-violation <stop|collect>",
                "--findings-out <path>",
            ],
        ),
        (
            "serve",
            &[
                "--listen <addr>",
                "--store <path>",
                "--max-sessions <n>",
                "--read-only",
            ],
        ),
    ] {
        let help = command
            .find_subcommand_mut(name)
            .unwrap_or_else(|| panic!("{name} subcommand must be registered"))
            .render_long_help()
            .to_string();
        for needle in needles {
            assert!(
                help.contains(needle),
                "{name} help is missing `{needle}`:\n{help}"
            );
        }
    }
}

#[test]
pub(super) fn cli_help_surface_matches_normalized_exact_rfc_snapshots() {
    let snapshots = [
        (
            "run",
            &[
                "scenario",
                "until",
                "max_virtual_time",
                "max_quanta",
                "interactive",
                "save_on",
                "watch",
            ][..],
            "about=Run a scenario to completion (local or via a daemon)\nusage=Usage: crucible run [OPTIONS] <SCENARIO>\nscenario=Scenario file (the canonical TOML form, 06 §6.1) or its content hash\nuntil=Terminal condition. Default: quiescence\nmax_virtual_time=Stop with Timeout past this virtual time (20 §2)\nmax_quanta=Stop with Timeout at this scheduler-quantum boundary\ninteractive=Pause at genesis and drive the session interactively\nsave_on=Materialize a savepoint at the outcome. Default: never\nwatch=Stream the live status line (20 §9) alongside the trace\n",
        ),
        (
            "verify",
            &["scenario", "runs", "adversarial", "bisect", "compare"][..],
            "about=Prove determinism: run N times, diff fingerprints + causal logs\nusage=Usage: crucible verify [OPTIONS] <SCENARIO|--compare <a> <b>>\nscenario=Scenario file (the canonical TOML form, 06 §6.1) or its content hash\nruns=Number of runs to compare. Default: 2\nadversarial=Run under the hostile host-condition matrix (24 §7)\nbisect=On divergence, run divergence-bisection (24 §5) and print the report\ncompare=Diff two existing reproduction artifacts instead of running\n",
        ),
        (
            "selftest",
            &["gates", "with_qemu", "corpus"][..],
            "about=Run the packaged determinism gates\nusage=Usage: crucible selftest [OPTIONS]\ngates=Gate subset to run\nwith_qemu=Execute the QEMU-backed gates\ncorpus=Test-only manifest of built-in fixture names\n",
        ),
        (
            "save",
            &[
                "scenario",
                "at",
                "label",
                "max_virtual_time",
                "property",
                "marker",
                "out",
            ][..],
            "about=Run to a savepoint and export it as a resumable checkpoint\nusage=Usage: crucible save [OPTIONS] --at <virtual-time|quiescence|property|marker> <SCENARIO>\nscenario=Scenario file (the canonical TOML form, 06 §6.1) or its content hash\nat=Where to stop and save. Required\nlabel=Human label for the savepoint (07)\nmax_virtual_time=Coordinate for --at virtual-time\nproperty=Assertion selector for --at property\nmarker=Guest marker selector for --at marker\nout=Write the exported savepoint handle here. Default: --artifact-dir\n",
        ),
        (
            "resume",
            &[
                "savepoint",
                "until",
                "max_virtual_time",
                "interactive",
                "watch",
            ][..],
            "about=Resume a run from a checkpoint or savepoint\nusage=Usage: crucible resume [OPTIONS] <SAVEPOINT>\nsavepoint=A savepoint handle / checkpoint content hash (07)\nuntil=Terminal condition, as in `run` (§6)\nmax_virtual_time=Stop with Timeout past this virtual time (20 §2)\ninteractive=Drive the resumed session interactively (as in `run`)\nwatch=Stream the live status line (20 §9)\n",
        ),
        (
            "fork",
            &[
                "savepoint",
                "overrides",
                "until",
                "max_virtual_time",
                "label",
                "interactive",
                "watch",
            ][..],
            "about=Fork a run from a savepoint with a new seed or decision override\nusage=Usage: crucible fork [OPTIONS] <SAVEPOINT>\nsavepoint=The fork point: a savepoint handle / checkpoint hash (07)\noverrides=Override a decision at/after the fork point (05 §3). Repeatable\nuntil=Terminal condition, as in `run` (§6)\nmax_virtual_time=Stop with Timeout past this virtual time (20 §2)\nlabel=Label the forked branch\ninteractive=Drive the forked session interactively\nwatch=Stream the live status line (20 §9)\n",
        ),
        (
            "replay",
            &["artifact", "check", "to", "bisect"][..],
            "about=Replay a reproduction artifact, bit-identically\nusage=Usage: crucible replay [OPTIONS] <ARTIFACT>\nartifact=A reproduction artifact (06 §7.1) or its content hash\ncheck=Assert the replayed canonical log is byte-identical to this one\nto=Validate a target savepoint handle or checkpoint hash\nbisect=Bisect this artifact against another (24 §5)\n",
        ),
        (
            "search",
            &[
                "scenario",
                "strategy",
                "max_depth",
                "max_states",
                "on_violation",
                "findings_out",
                "schedule_named_truths",
            ][..],
            "about=Drive state-space search over the schedule space (22)\nusage=Usage: crucible search [OPTIONS] <SCENARIO>\nscenario=Scenario file (the canonical TOML form, 06 §6.1) or its content hash\nstrategy=Frontier expansion strategy (22)\nmax_depth=Decision-depth bound\nmax_states=Budget on materialized states\non_violation=Stop at the first finding, or collect findings within the search bound\nfindings_out=Write the signed findings ledger to this path\nschedule_named_truths=Load schedule-named assertion truth data\n",
        ),
        (
            "fuzz",
            &[
                "family",
                "family_flag",
                "runs",
                "coverage",
                "corpus",
                "on_violation",
                "findings_out",
            ][..],
            "about=Coverage-guided fuzzing over a scenario family (22)\nusage=Usage: crucible fuzz [OPTIONS] <FAMILY|--family <path|hash>>\nfamily=A ScenarioFamily (06 §7) to sample\nfamily_flag=A ScenarioFamily (06 §7) to sample\nruns=Number of family instances to run\ncoverage=Coverage signal guiding sampling (22)\ncorpus=Seed/regression corpus directory\non_violation=Stop at the first finding, or collect findings within the run bound\nfindings_out=Write the signed findings ledger to this path\n",
        ),
        (
            "serve",
            &[
                "listen",
                "max_sessions",
                "production_qemu",
                "qemu_rendezvous_icount",
                "read_only",
                "tls_cert",
                "tls_key",
                "client_ca",
                "trusted_unauthenticated_bind",
                "debug_role",
                "campaign_socket",
                "campaign_state",
                "campaign_policy",
                "campaign_component_authority",
                "campaign_import_manifest",
                "campaign_runtime",
                "campaign_executor_socket",
                "campaign_packaged_executor",
                "campaign_socket_mode",
            ][..],
            "about=Run the daemon hosting the API (21)\nusage=Usage: crucible serve [OPTIONS] --listen <addr>\nlisten=Address to bind the API (21) on. Required\nmax_sessions=Concurrency cap on live sessions\nproduction_qemu=Host sessions with the packaged production QEMU lifecycle\nqemu_rendezvous_icount=Cap production-QEMU RUNs at this deterministic icount interval\nread_only=Accept only read-only API calls (query/watch); no mutate\ntls_cert=Server certificate chain for authenticated remote access\ntls_key=Server private key for authenticated remote access\nclient_ca=CA certificate used to authenticate remote clients\ntrusted_unauthenticated_bind=Permit cleartext access on this explicitly trusted bind address\ndebug_role=Map a client certificate fingerprint to debugger capabilities\ncampaign_socket=Host the local CampaignService on this managed Unix socket\ncampaign_state=Retain local campaign objects and refs below this existing directory\ncampaign_policy=Load the strict local campaign peer policy from this file\ncampaign_component_authority=Load distinct planner/debugger component authority keys from this file\ncampaign_import_manifest=Import verified campaign creation artifacts before binding the socket\ncampaign_runtime=Attach the packaged planner and one local executor to an existing campaign; repeat in executor-socket order\ncampaign_executor_socket=Connect one attached campaign runtime to this owner-only Unix socket; repeat in runtime order\ncampaign_packaged_executor=Start the packaged local QEMU executor from this strict deployment file\ncampaign_socket_mode=Set the managed campaign socket's Unix permission bits in octal\n",
        ),
        (
            "debug",
            &[
                "target",
                "session",
                "at",
                "at_event",
                "at_failure",
                "at_checkpoint",
                "node",
                "gdb_listen",
                "read_only",
                "allow_mutate",
                "checkpoint_stride",
                "record_transcript",
                "guest_idle_timeout",
            ][..],
            "about=Open the time-travel debugger\nusage=Usage: crucible debug [OPTIONS] <ARTIFACT|SAVEPOINT|--session <SESSION>> [COMMAND]\ntarget=Attach to this artifact or savepoint\nsession=Attach to a running daemon session by id:epoch:64-lowercase-hex-seed\nat=Open at a virtual-time or node-icount coordinate\nat_event=Open at this event-log sequence\nat_failure=Open at the recorded failure point\nat_checkpoint=Open at this checkpoint content address\nnode=Attach this node's gdbstub\ngdb_listen=Listen for gdb-protocol clients here\nread_only=Keep the canonical run read-only\nallow_mutate=Authorize an explicit non-canonical debug fork\ncheckpoint_stride=Bound reverse-step replay distance\nrecord_transcript=Record the non-canonical guest channel to a new transcript file\nguest_idle_timeout=Fail when the guest agent produces no response for this duration\ncommand.attach-gdb=Open the mediated gdbstub channel\ncommand.fork-debug=Explicitly fork a non-canonical whole-world debug branch\ncommand.goto=Move to another debug coordinate\ncommand.reverse-step=Step backward by one deterministic grain\ncommand.reverse-continue=Continue backward to a matching condition\ncommand.exec=Execute an argv-based command through the guest debug agent\ncommand.pty=Open an interactive command on a guest PTY\ncommand.ssh=Bridge stdin/stdout to the guest agent's configured SSH server\n",
        ),
    ];

    let command = Cli::command();
    for (name, argument_ids, expected) in snapshots {
        let actual = normalized_subcommand_help_snapshot(&command, name, argument_ids);
        assert_eq!(actual, expected, "normalized `{name}` help drifted");
    }
}

pub(super) fn normalized_subcommand_help_snapshot(
    command: &clap::Command,
    name: &str,
    argument_ids: &[&str],
) -> String {
    let mut command = command.clone();
    command.build();
    let mut subcommand = command
        .find_subcommand(name)
        .unwrap_or_else(|| panic!("{name} subcommand must be registered"))
        .clone()
        .bin_name(format!("crucible {name}"));
    let about = subcommand
        .get_about()
        .unwrap_or_else(|| panic!("{name} subcommand must have help copy"))
        .to_string();
    let visible_local_argument_ids = subcommand
        .get_arguments()
        .filter(|argument| {
            !argument.is_global_set()
                && !argument.is_hide_set()
                && !matches!(argument.get_id().as_str(), "help" | "version")
        })
        .map(|argument| argument.get_id().as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        visible_local_argument_ids, argument_ids,
        "normalized `{name}` snapshot must enumerate every visible local argument exactly"
    );
    let usage = subcommand.render_usage().to_string();
    let mut snapshot = format!(
        "about={}\nusage={}\n",
        normalize_help_text(&about),
        normalize_help_text(&usage)
    );
    for id in argument_ids {
        let argument = subcommand
            .get_arguments()
            .find(|argument| argument.get_id().as_str() == *id)
            .unwrap_or_else(|| panic!("{name} help must contain `{id}`"));
        let help = argument
            .get_help()
            .unwrap_or_else(|| panic!("{name}.{id} must have user-facing help"));
        snapshot.push_str(id);
        snapshot.push('=');
        snapshot.push_str(&normalize_help_text(&help.to_string()));
        snapshot.push('\n');
    }
    for nested in subcommand.get_subcommands() {
        let about = nested
            .get_about()
            .unwrap_or_else(|| panic!("{name}.{} must have help copy", nested.get_name()));
        snapshot.push_str("command.");
        snapshot.push_str(nested.get_name());
        snapshot.push('=');
        snapshot.push_str(&normalize_help_text(&about.to_string()));
        snapshot.push('\n');
    }
    snapshot
}

pub(super) fn normalize_help_text(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[test]
pub(super) fn cli_parser_enforces_every_normatively_required_input() {
    for argv in [
        vec!["crucible", "run"],
        vec!["crucible", "verify"],
        vec!["crucible", "save", "builtin:happy-path.scn"],
        vec![
            "crucible",
            "save",
            "builtin:happy-path.scn",
            "--at",
            "virtual-time",
        ],
        vec![
            "crucible",
            "save",
            "builtin:happy-path.scn",
            "--at",
            "property",
        ],
        vec![
            "crucible",
            "save",
            "builtin:happy-path.scn",
            "--at",
            "marker",
        ],
        vec!["crucible", "resume"],
        vec![
            "crucible",
            "resume",
            "blake3:missing",
            "--until",
            "virtual-time",
        ],
        vec!["crucible", "fork"],
        vec![
            "crucible",
            "fork",
            "blake3:missing",
            "--until",
            "virtual-time",
        ],
        vec!["crucible", "search"],
        vec!["crucible", "fuzz"],
        vec!["crucible", "serve"],
        vec!["crucible", "debug"],
        vec!["crucible", "replay"],
    ] {
        let error = match Cli::try_parse_from(argv.clone()) {
            Ok(_) => panic!("missing required input parsed successfully for {argv:?}"),
            Err(error) => error,
        };
        assert_ne!(
            error.kind(),
            clap::error::ErrorKind::DisplayHelp,
            "missing input unexpectedly rendered help for {argv:?}"
        );
        assert_eq!(
            cli_parse_error_exit_code(&error),
            64,
            "missing required input must be a usage error for {argv:?}"
        );
    }

    assert!(
        Cli::try_parse_from([
            "crucible",
            "serve",
            "--listen",
            "127.0.0.1:0",
            "--campaign-socket",
            "/tmp/campaign.sock",
            "--campaign-state",
            "/tmp/campaign-state",
            "--campaign-policy",
            "/tmp/campaign-policy",
            "--campaign-component-authority",
            "/tmp/component-authority",
            "--campaign-runtime",
            "attached",
            "--campaign-executor-socket",
            "/tmp/executor.sock",
            "--campaign-packaged-executor",
            "/tmp/executor.toml",
        ])
        .is_err(),
        "packaged campaign execution must require the production QEMU backend"
    );

    assert!(Cli::try_parse_from(["crucible", "verify", "--compare", "left", "right"]).is_ok());
    assert!(Cli::try_parse_from(["crucible", "fuzz", "family.toml"]).is_ok());
    assert!(Cli::try_parse_from(["crucible", "fuzz", "--family", "blake3:family"]).is_ok());
    assert!(
        Cli::try_parse_from([
            "crucible",
            "--daemon",
            "127.0.0.1:9000",
            "debug",
            "--session",
            "7:12:1111111111111111111111111111111111111111111111111111111111111111",
        ])
        .is_ok()
    );
    assert!(Cli::try_parse_from(["crucible", "serve", "--listen", "127.0.0.1:9000"]).is_ok());
}

#[test]
pub(super) fn cli_parser_requires_daemon_for_remote_transport_options() {
    for option in ["--daemon-ca", "--daemon-cert", "--daemon-key"] {
        let error = Cli::try_parse_from(["crucible", option, "credential.pem", "run", "case.toml"])
            .expect_err("daemon credential without --daemon must be rejected");
        assert_eq!(cli_parse_error_exit_code(&error), 64);
        assert!(error.to_string().contains("--daemon"));
    }

    let error = Cli::try_parse_from([
        "crucible",
        "--trusted-unauthenticated-daemon",
        "run",
        "case.toml",
    ])
    .expect_err("daemon trust override without --daemon must be rejected");
    assert_eq!(cli_parse_error_exit_code(&error), 64);
    assert!(error.to_string().contains("--daemon"));
}

#[test]
pub(super) fn cli_parser_enforces_normative_alternative_and_conflicting_inputs() {
    for argv in [
        vec![
            "crucible",
            "verify",
            "scenario.toml",
            "--compare",
            "left",
            "right",
        ],
        vec![
            "crucible",
            "fuzz",
            "family.toml",
            "--family",
            "blake3:family",
        ],
        vec![
            "crucible",
            "fork",
            "blake3:savepoint",
            "--seed",
            "1",
            "--override",
            "decision=value",
        ],
    ] {
        let error = match Cli::try_parse_from(argv.clone()) {
            Ok(_) => panic!("conflicting input parsed successfully for {argv:?}"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);
        assert_eq!(cli_parse_error_exit_code(&error), 64);
    }
}

#[test]
pub(super) fn cli_help_surface_rejects_unimplemented_future_flags() {
    for argv in [
        vec![
            "crucible",
            "replay",
            "case.crucible",
            "--future-replay-flag",
        ],
        vec!["crucible", "serve", "--unknown-serve-flag"],
    ] {
        assert!(
            Cli::try_parse_from(argv).is_err(),
            "future flag must stay rejected until command behavior implements it"
        );
    }

    let serve = Cli::parse_from(["crucible", "serve", "--listen", "127.0.0.1:9001"]);
    let Commands::Serve(args) = serve.command else {
        panic!("expected serve command");
    };
    assert_eq!(args.listen, "127.0.0.1:9001");

    let max_sessions_serve = Cli::parse_from([
        "crucible",
        "serve",
        "--listen",
        "127.0.0.1:9000",
        "--max-sessions",
        "2",
    ]);
    let Commands::Serve(args) = &max_sessions_serve.command else {
        panic!("expected serve command");
    };
    assert_eq!(args.max_sessions, Some(2));

    let zero_max_sessions = Cli::parse_from([
        "crucible",
        "serve",
        "--listen",
        "127.0.0.1:9000",
        "--max-sessions",
        "0",
    ]);
    let Commands::Serve(args) = &zero_max_sessions.command else {
        panic!("expected serve command");
    };
    let error = match validate_serve_invocation(args) {
        Ok(_) => panic!("zero max sessions must be rejected before binding can start"),
        Err(error) => error,
    };
    assert!(matches!(error, CliError::Usage(_)));
    assert_eq!(error.exit_code(), 64);
    assert!(error.to_string().contains("--max-sessions"));

    let zero_max_sessions_run = Cli::parse_from([
        "crucible",
        "serve",
        "--listen",
        "127.0.0.1:notaport",
        "--max-sessions",
        "0",
    ]);
    let Commands::Serve(args) = &zero_max_sessions_run.command else {
        panic!("expected serve command");
    };
    let error = match run_serve_invocation(&zero_max_sessions_run, args) {
        Ok(_) => panic!("zero max sessions must be rejected before binding can start"),
        Err(error) => error,
    };
    assert!(matches!(error, CliError::Usage(_)));
    assert_eq!(error.exit_code(), 64);
    assert!(error.to_string().contains("--max-sessions"));

    let read_only_serve = Cli::parse_from([
        "crucible",
        "serve",
        "--listen",
        "127.0.0.1:9000",
        "--read-only",
    ]);
    let Commands::Serve(args) = read_only_serve.command else {
        panic!("expected serve command");
    };
    assert!(args.read_only);
}

#[test]
pub(super) fn cli_serve_shutdown_and_bind_errors_follow_exit_contract() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|error| panic!("current-thread runtime should build: {error}"));

    let clean_shutdown = Cli::parse_from([
        "crucible",
        "--quiet",
        "serve",
        "--listen",
        "127.0.0.1:0",
        "--max-sessions",
        "1",
        "--trusted-unauthenticated-bind",
    ]);
    let Commands::Serve(args) = &clean_shutdown.command else {
        panic!("expected serve command");
    };
    runtime
        .block_on(run_serve_invocation_until_shutdown(
            &clean_shutdown,
            args,
            async { Ok(()) },
        ))
        .unwrap_or_else(|error| panic!("injected serve shutdown should exit cleanly: {error}"));

    let shutdown_error_cli = Cli::parse_from([
        "crucible",
        "--quiet",
        "serve",
        "--listen",
        "127.0.0.1:0",
        "--trusted-unauthenticated-bind",
    ]);
    let Commands::Serve(args) = &shutdown_error_cli.command else {
        panic!("expected serve command");
    };
    let error = match runtime.block_on(run_serve_invocation_until_shutdown(
        &shutdown_error_cli,
        args,
        async { Err(serve_error("serve shutdown signal error: injected")) },
    )) {
        Ok(_) => panic!("serve shutdown signal errors must fail the invocation"),
        Err(error) => error,
    };
    assert!(matches!(error, CliError::Serve(_)));
    assert_eq!(error.exit_code(), 3);
    assert!(error.to_string().contains("serve shutdown signal error"));

    let bind_error = Cli::parse_from([
        "crucible",
        "serve",
        "--listen",
        "127.0.0.1:70000",
        "--trusted-unauthenticated-bind",
    ]);
    let Commands::Serve(args) = &bind_error.command else {
        panic!("expected serve command");
    };
    let error = match run_serve_invocation(&bind_error, args) {
        Ok(_) => panic!("invalid serve listen address must fail before serving"),
        Err(error) => error,
    };
    assert!(matches!(error, CliError::Serve(_)));
    assert_eq!(error.exit_code(), 3);
    assert!(error.to_string().contains("serve bind error"));
}

#[test]
pub(super) fn cli_serve_campaign_profile_is_exact_and_restart_safe() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::os::unix::net::UnixStream;

    use crucible_campaign::{
        CampaignClient, CampaignClientError, CampaignName, CampaignPrincipal,
        CampaignServiceFailure, GetCampaignRequest,
    };
    use crucible_daemon::{LoopbackCampaignService, LoopbackCampaignTimeouts};

    let directory = tempfile::tempdir().expect("campaign serve directory");
    fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
        .expect("secure campaign serve directory");
    let metadata = fs::metadata(directory.path()).expect("campaign serve metadata");
    let socket = directory.path().join("campaign.sock");
    let state = directory.path().join("state");
    fs::create_dir(&state).expect("campaign state directory");
    fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700))
        .expect("secure campaign state");
    let policy = directory.path().join("policy.toml");
    fs::write(
        &policy,
        format!(
            r#"schema = "crucible.campaign-local-policy"
version = 1

[[bindings]]
user_id = {}
group_id = {}
principal = "operator"

[[grants]]
principal = "operator"
operation = "get-campaign"
campaign = "*"
"#,
            metadata.uid(),
            metadata.gid()
        ),
    )
    .expect("campaign policy");
    fs::set_permissions(&policy, std::fs::Permissions::from_mode(0o600))
        .expect("secure campaign policy");
    let component_authority = directory.path().join("component-authorities.bin");
    let mut component_authority_bytes = Vec::from(*b"CRUCCA01");
    component_authority_bytes.extend_from_slice(&[0x31; 32]);
    component_authority_bytes.extend_from_slice(&[0x73; 32]);
    fs::write(&component_authority, component_authority_bytes)
        .expect("campaign component authority");
    fs::set_permissions(&component_authority, std::fs::Permissions::from_mode(0o600))
        .expect("secure component authority");
    let scenario = crucible::happy_path_scenario()
        .expect("happy-path scenario")
        .scenario;
    let scenario_path = directory.path().join("scenario.bin");
    fs::write(&scenario_path, scenario.to_compact_binary()).expect("campaign scenario import");
    fs::set_permissions(&scenario_path, std::fs::Permissions::from_mode(0o600))
        .expect("secure scenario import");
    let schedule_path = directory.path().join("schedule.bin");
    fs::write(
        &schedule_path,
        crucible::Schedule::empty().to_compact_binary(),
    )
    .expect("campaign schedule import");
    fs::set_permissions(&schedule_path, std::fs::Permissions::from_mode(0o600))
        .expect("secure schedule import");
    let manifest = directory.path().join("campaign-import.toml");
    fs::write(
        &manifest,
        format!(
            r#"schema = "crucible.campaign-import"
version = 1

[[configuration]]
scenario = {:?}
schedule = {:?}
"#,
            scenario_path, schedule_path
        ),
    )
    .expect("campaign import manifest");
    fs::set_permissions(&manifest, std::fs::Permissions::from_mode(0o600))
        .expect("secure import manifest");

    let cli = Cli::parse_from([
        "crucible",
        "--quiet",
        "serve",
        "--listen",
        "127.0.0.1:0",
        "--trusted-unauthenticated-bind",
        "--campaign-socket",
        socket.to_str().expect("socket path"),
        "--campaign-state",
        state.to_str().expect("state path"),
        "--campaign-policy",
        policy.to_str().expect("policy path"),
        "--campaign-component-authority",
        component_authority
            .to_str()
            .expect("component authority path"),
        "--campaign-import-manifest",
        manifest.to_str().expect("manifest path"),
    ]);
    let Commands::Serve(args) = &cli.command else {
        panic!("expected serve command");
    };
    assert_eq!(args.campaign_socket_mode, 0o600);
    validate_serve_invocation(args).expect("valid campaign serve profile");
    let request = GetCampaignRequest::new(
        CampaignPrincipal::new("operator").expect("campaign principal"),
        CampaignName::new("absent").expect("campaign name"),
    )
    .expect("campaign get request");
    let campaign_socket = socket.clone();
    let shutdown = async move {
        let mut attempts = 0_u16;
        let stream = loop {
            match UnixStream::connect(&campaign_socket) {
                Ok(stream) => break stream,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
                    ) =>
                {
                    attempts = attempts.saturating_add(1);
                    if attempts == 1_000 {
                        return Err(serve_error("campaign test connection timed out"));
                    }
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                Err(error) => {
                    return Err(serve_error(format!(
                        "campaign test connection error: {error}"
                    )));
                }
            }
        };
        let service =
            LoopbackCampaignService::with_timeouts(stream, LoopbackCampaignTimeouts::default())
                .map_err(|error| serve_error(format!("campaign test client error: {error}")))?;
        let client = CampaignClient::new(service);
        assert!(matches!(
            client.get_campaign(&request),
            Err(CampaignClientError::Service(
                CampaignServiceFailure::NotFound
            ))
        ));
        Ok(())
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("campaign serve runtime");
    runtime
        .block_on(run_serve_invocation_until_shutdown(&cli, args, shutdown))
        .expect("campaign and lifecycle services stop together");
    assert!(!socket.exists());
    assert!(state.join("objects").is_dir());
    assert!(state.join("refs").is_dir());

    runtime
        .block_on(run_serve_invocation_until_shutdown(&cli, args, async {
            Ok(())
        }))
        .expect("campaign service restarts over durable state");
    assert!(!socket.exists());

    let mut invalid_authority_bytes = Vec::from(*b"CRUCCA01");
    invalid_authority_bytes.extend_from_slice(&[0x31; 32]);
    invalid_authority_bytes.extend_from_slice(&[0x31; 32]);
    fs::write(&component_authority, invalid_authority_bytes).expect("replace component authority");
    let error = match open_local_campaign_service(args, None) {
        Ok(_) => panic!("equal component authorities must fail before bind"),
        Err(error) => error,
    };
    assert!(matches!(error, CliError::Serve(_)));
    assert!(
        error
            .to_string()
            .contains("component-authority file is invalid")
    );
    assert!(!socket.exists());
}

#[test]
pub(super) fn cli_campaign_import_failure_precedes_socket_bind() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let directory = tempfile::tempdir().expect("campaign import directory");
    fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
        .expect("secure campaign import directory");
    let metadata = fs::metadata(directory.path()).expect("campaign import metadata");
    let socket = directory.path().join("campaign.sock");
    let state = directory.path().join("state");
    fs::create_dir(&state).expect("campaign state directory");
    fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700))
        .expect("secure campaign state");
    let policy = directory.path().join("policy.toml");
    fs::write(
        &policy,
        format!(
            r#"schema = "crucible.campaign-local-policy"
version = 1

[[bindings]]
user_id = {}
group_id = {}
principal = "operator"
"#,
            metadata.uid(),
            metadata.gid()
        ),
    )
    .expect("campaign policy");
    fs::set_permissions(&policy, std::fs::Permissions::from_mode(0o600))
        .expect("secure campaign policy");
    let manifest = directory.path().join("campaign-import.toml");
    fs::write(&manifest, b"schema = [").expect("malformed import manifest");
    fs::set_permissions(&manifest, std::fs::Permissions::from_mode(0o600))
        .expect("secure import manifest");

    let cli = Cli::parse_from([
        "crucible",
        "serve",
        "--listen",
        "127.0.0.1:0",
        "--trusted-unauthenticated-bind",
        "--campaign-socket",
        socket.to_str().expect("socket path"),
        "--campaign-state",
        state.to_str().expect("state path"),
        "--campaign-policy",
        policy.to_str().expect("policy path"),
        "--campaign-import-manifest",
        manifest.to_str().expect("manifest path"),
    ]);
    let Commands::Serve(args) = &cli.command else {
        panic!("expected serve command");
    };
    let error = match open_local_campaign_service(args, None) {
        Ok(_) => panic!("malformed campaign import must fail"),
        Err(error) => error,
    };
    assert!(matches!(error, CliError::Serve(_)));
    assert!(error.to_string().contains("campaign import error"));
    assert!(!socket.exists());
}

#[test]
pub(super) fn cli_serve_campaign_profile_rejects_partial_or_invalid_input() {
    for argv in [
        vec![
            "crucible",
            "serve",
            "--listen",
            "127.0.0.1:0",
            "--campaign-socket",
            "/tmp/campaign.sock",
        ],
        vec![
            "crucible",
            "serve",
            "--listen",
            "127.0.0.1:0",
            "--campaign-socket",
            "/tmp/campaign.sock",
            "--campaign-state",
            "/tmp/campaign-state",
        ],
    ] {
        let cli = Cli::parse_from(argv);
        let Commands::Serve(args) = &cli.command else {
            panic!("expected serve command");
        };
        assert!(matches!(
            validate_serve_invocation(args),
            Err(CliError::Usage(_))
        ));
    }

    let invalid_mode = Cli::parse_from([
        "crucible",
        "serve",
        "--listen",
        "127.0.0.1:0",
        "--campaign-socket",
        "/tmp/campaign.sock",
        "--campaign-state",
        "/tmp/campaign-state",
        "--campaign-policy",
        "/tmp/campaign-policy",
        "--campaign-socket-mode",
        "000",
    ]);
    let Commands::Serve(args) = &invalid_mode.command else {
        panic!("expected serve command");
    };
    assert!(matches!(
        validate_serve_invocation(args),
        Err(CliError::Usage(_))
    ));
    assert!(
        Cli::try_parse_from([
            "crucible",
            "serve",
            "--listen",
            "127.0.0.1:0",
            "--campaign-socket",
            "/tmp/campaign.sock",
            "--campaign-state",
            "/tmp/campaign-state",
            "--campaign-policy",
            "/tmp/campaign-policy",
            "--campaign-socket-mode",
            "888",
        ])
        .is_err()
    );
    assert!(
        Cli::try_parse_from([
            "crucible",
            "serve",
            "--listen",
            "127.0.0.1:0",
            "--read-only",
            "--campaign-socket",
            "/tmp/campaign.sock",
            "--campaign-state",
            "/tmp/campaign-state",
            "--campaign-policy",
            "/tmp/campaign-policy",
            "--campaign-import-manifest",
            "/tmp/campaign-import.toml",
        ])
        .is_err()
    );

    for argv in [
        vec![
            "crucible",
            "serve",
            "--listen",
            "127.0.0.1:0",
            "--campaign-runtime",
            "attached",
        ],
        vec![
            "crucible",
            "serve",
            "--listen",
            "127.0.0.1:0",
            "--campaign-executor-socket",
            "/tmp/executor.sock",
        ],
        vec![
            "crucible",
            "serve",
            "--listen",
            "127.0.0.1:0",
            "--read-only",
            "--campaign-runtime",
            "attached",
            "--campaign-executor-socket",
            "/tmp/executor.sock",
        ],
    ] {
        assert!(
            Cli::try_parse_from(argv).is_err(),
            "runtime attachment must require its complete writable profile"
        );
    }

    let invalid_campaign = Cli::parse_from([
        "crucible",
        "serve",
        "--listen",
        "127.0.0.1:0",
        "--campaign-socket",
        "/tmp/campaign.sock",
        "--campaign-state",
        "/tmp/campaign-state",
        "--campaign-policy",
        "/tmp/campaign-policy",
        "--campaign-component-authority",
        "/tmp/component-authority",
        "--campaign-runtime",
        "bad:name",
        "--campaign-executor-socket",
        "/tmp/executor.sock",
    ]);
    let Commands::Serve(args) = &invalid_campaign.command else {
        panic!("expected serve command");
    };
    assert!(matches!(
        validate_serve_invocation(args),
        Err(CliError::Usage(_))
    ));

    let multiple = Cli::parse_from([
        "crucible",
        "serve",
        "--listen",
        "127.0.0.1:0",
        "--trusted-unauthenticated-bind",
        "--campaign-socket",
        "/tmp/campaign.sock",
        "--campaign-state",
        "/tmp/campaign-state",
        "--campaign-policy",
        "/tmp/campaign-policy",
        "--campaign-component-authority",
        "/tmp/component-authority",
        "--campaign-runtime",
        "alpha",
        "--campaign-executor-socket",
        "/tmp/executor-alpha.sock",
        "--campaign-runtime",
        "beta",
        "--campaign-executor-socket",
        "/tmp/executor-beta.sock",
    ]);
    let Commands::Serve(args) = &multiple.command else {
        panic!("expected serve command");
    };
    assert_eq!(args.campaign_runtime, ["alpha", "beta"]);
    assert_eq!(
        args.campaign_executor_socket,
        [
            PathBuf::from("/tmp/executor-alpha.sock"),
            PathBuf::from("/tmp/executor-beta.sock")
        ]
    );
    validate_serve_invocation(args).expect("two unique runtime pairs are valid");

    for invalid in [
        [
            "--campaign-runtime",
            "alpha",
            "--campaign-executor-socket",
            "/tmp/executor-alpha.sock",
            "--campaign-runtime",
            "beta",
        ]
        .as_slice(),
        [
            "--campaign-runtime",
            "alpha",
            "--campaign-executor-socket",
            "/tmp/executor-alpha.sock",
            "--campaign-runtime",
            "alpha",
            "--campaign-executor-socket",
            "/tmp/executor-beta.sock",
        ]
        .as_slice(),
    ] {
        let mut argv = vec![
            "crucible",
            "serve",
            "--listen",
            "127.0.0.1:0",
            "--trusted-unauthenticated-bind",
            "--campaign-socket",
            "/tmp/campaign.sock",
            "--campaign-state",
            "/tmp/campaign-state",
            "--campaign-policy",
            "/tmp/campaign-policy",
            "--campaign-component-authority",
            "/tmp/component-authority",
        ];
        argv.extend_from_slice(invalid);
        let cli = Cli::parse_from(argv);
        let Commands::Serve(args) = &cli.command else {
            panic!("expected serve command");
        };
        assert!(matches!(
            validate_serve_invocation(args),
            Err(CliError::Usage(_))
        ));
    }

    let multiple_with_packaged_executor = Cli::parse_from([
        "crucible",
        "serve",
        "--listen",
        "127.0.0.1:0",
        "--trusted-unauthenticated-bind",
        "--production-qemu",
        "--campaign-socket",
        "/tmp/campaign.sock",
        "--campaign-state",
        "/tmp/campaign-state",
        "--campaign-policy",
        "/tmp/campaign-policy",
        "--campaign-component-authority",
        "/tmp/component-authority",
        "--campaign-runtime",
        "alpha",
        "--campaign-executor-socket",
        "/tmp/executor-alpha.sock",
        "--campaign-runtime",
        "beta",
        "--campaign-executor-socket",
        "/tmp/executor-beta.sock",
        "--campaign-packaged-executor",
        "/tmp/executor-deployment.toml",
    ]);
    let Commands::Serve(args) = &multiple_with_packaged_executor.command else {
        panic!("expected serve command");
    };
    assert!(matches!(
        validate_serve_invocation(args),
        Err(CliError::Usage(_))
    ));
}

#[test]
pub(super) fn cli_campaign_executor_socket_requires_exact_owner_mode_and_identity() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::os::unix::net::UnixListener;

    let directory = tempfile::tempdir().expect("executor socket directory");
    let socket = directory.path().join("executor.sock");
    let listener = UnixListener::bind(&socket).expect("executor listener");
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))
        .expect("owner-only executor socket");
    let stream = connect_campaign_executor(&socket).expect("authenticated executor socket");
    drop(stream);

    fs::set_permissions(&socket, fs::Permissions::from_mode(0o660))
        .expect("broaden executor socket mode");
    assert!(connect_campaign_executor(&socket).is_err());
    drop(listener);

    let target = directory.path().join("target.sock");
    let _target_listener = UnixListener::bind(&target).expect("target listener");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600))
        .expect("owner-only target socket");
    let redirected = directory.path().join("redirected.sock");
    symlink(&target, &redirected).expect("executor socket symlink");
    assert!(connect_campaign_executor(&redirected).is_err());

    let regular = directory.path().join("not-a-socket");
    fs::write(&regular, b"not a socket").expect("regular file");
    fs::set_permissions(&regular, fs::Permissions::from_mode(0o600))
        .expect("owner-only regular file");
    assert!(connect_campaign_executor(&regular).is_err());
}

#[test]
pub(super) fn cli_thin_wrapper_maps_every_subcommand_to_session_api_or_declared_driver() {
    let cases = [
        (
            CliSubcommand::Run,
            vec![
                "crucible",
                "--daemon",
                "127.0.0.1:9000",
                "run",
                TEST_SCENARIO,
            ],
        ),
        (
            CliSubcommand::Verify,
            vec!["crucible", "verify", TEST_SCENARIO],
        ),
        (CliSubcommand::Selftest, vec!["crucible", "selftest"]),
        (
            CliSubcommand::Save,
            vec!["crucible", "save", TEST_SCENARIO, "--at", "quiescence"],
        ),
        (
            CliSubcommand::Resume,
            vec!["crucible", "resume", "blake3:test-savepoint"],
        ),
        (
            CliSubcommand::Fork,
            vec!["crucible", "fork", "blake3:test-savepoint"],
        ),
        (
            CliSubcommand::Replay,
            vec!["crucible", "replay", "case.crucible"],
        ),
        (
            CliSubcommand::Search,
            vec!["crucible", "search", TEST_SCENARIO],
        ),
        (
            CliSubcommand::Fuzz,
            vec!["crucible", "fuzz", "builtin:fault-campaign"],
        ),
        (
            CliSubcommand::Triage,
            vec!["crucible", "triage", "findings"],
        ),
        (
            CliSubcommand::Debug,
            vec!["crucible", "debug", "case.crucible"],
        ),
        (
            CliSubcommand::Serve,
            vec!["crucible", "serve", "--listen", "127.0.0.1:9000"],
        ),
        (
            CliSubcommand::Completions,
            vec!["crucible", "completions", "bash"],
        ),
    ];
    let mut observed = BTreeSet::new();

    for (expected, argv) in cases {
        let cli = Cli::parse_from(argv);
        let plan = plan_cli_invocation(&cli);
        observed.insert(plan.subcommand);

        assert_eq!(plan.subcommand, expected);
        assert!(
            plan.proves_t_cli_2(),
            "{expected:?} must satisfy the thin-wrapper contract: {plan:?}"
        );
        assert!(!plan.owns_canonical_run_state);
        assert!(!plan.implements_scheduler);
        assert!(!plan.implements_checkpoint_materialization);
        assert!(!plan.implements_fork_logic);
        assert!(plan.extra_control_capabilities.is_empty());
        assert!(
            plan.session_commands
                .iter()
                .all(|command| SessionCommandKind::ALL.contains(command))
        );
        assert!(
            plan.api_calls
                .iter()
                .all(|call| CliApiCall::ALL.contains(call)
                    && !call.control_client_method().is_empty())
        );

        let mut recorder = RecordingOperationRecorder::default();
        execute_cli_dispatch_plan(&plan, &mut recorder)
            .expect("thin-wrapper dispatch plan should execute");
        assert_eq!(recorder.session_commands, plan.session_commands);
        assert_eq!(recorder.api_calls, plan.api_calls);
        assert_eq!(recorder.drivers, plan.delegated_drivers);
        assert_eq!(recorder.state_references, plan.state_references);
    }

    assert_eq!(observed.len(), 13);
    assert!(observed.contains(&CliSubcommand::Run));
    assert!(observed.contains(&CliSubcommand::Completions));
}

#[test]
pub(super) fn cli_thin_wrapper_emits_only_control_client_methods_and_session_command_kinds() {
    let cli = Cli::parse_from([
        "crucible",
        "--daemon",
        "127.0.0.1:9000",
        "run",
        TEST_SCENARIO,
    ]);
    let plan = plan_cli_invocation(&cli);
    let mut recorder = RecordingOperationRecorder::default();

    execute_cli_dispatch_plan(&plan, &mut recorder)
        .expect("remote run should emit a valid thin-wrapper plan");

    assert!(recorder.drivers.contains(&CliDelegatedDriver::ControlApi));
    assert!(
        recorder
            .state_references
            .contains(&CliStateReferenceKind::DaemonConnection)
    );
    assert!(
        recorder
            .session_commands
            .iter()
            .all(|command| SessionCommandKind::ALL.contains(command))
    );
    assert_eq!(
        recorder
            .api_calls
            .iter()
            .map(|call| call.control_client_method())
            .collect::<Vec<_>>(),
        [
            "hello",
            "create_session",
            "watch_attach",
            "send_command",
            "get_reproduction",
        ]
    );
}

#[test]
pub(super) fn cli_thin_wrapper_rejects_canonical_state_or_extra_control_capabilities() {
    let cli = Cli::parse_from(["crucible", "run", TEST_SCENARIO]);
    let base = plan_cli_invocation(&cli);
    assert!(base.proves_t_cli_2());

    let mut owns_state = base.clone();
    owns_state.owns_canonical_run_state = true;
    assert!(!owns_state.proves_t_cli_2());

    let mut schedules = base.clone();
    schedules.implements_scheduler = true;
    assert!(!schedules.proves_t_cli_2());

    let mut materializes = base.clone();
    materializes.implements_checkpoint_materialization = true;
    assert!(!materializes.proves_t_cli_2());

    let mut forks = base.clone();
    forks.implements_fork_logic = true;
    assert!(!forks.proves_t_cli_2());

    let mut extra_control = base;
    extra_control
        .extra_control_capabilities
        .push("invented-control-capability");
    assert!(!extra_control.proves_t_cli_2());
    let mut recorder = RecordingOperationRecorder::default();
    let error = match execute_cli_dispatch_plan(&extra_control, &mut recorder) {
        Ok(_) => panic!("invented control capabilities must not dispatch"),
        Err(error) => error,
    };
    assert!(matches!(error, CliError::Backend(_)));
    assert!(recorder.session_commands.is_empty());
    assert!(recorder.api_calls.is_empty());
}

#[test]
pub(super) fn cli_hermetic_qemu_discovery_prefers_flags_then_env_then_aos_package_set()
-> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let plugin_abi = required_qemu_plugin_abi();
    let (flag_qemu, flag_plugin) =
        qemu_artifacts_in_dir(&temp.path().join("flag"), "flag-qemu-build", &plugin_abi)?;
    let (env_qemu, env_plugin) =
        qemu_artifacts_in_dir(&temp.path().join("env"), "env-qemu-build", &plugin_abi)?;
    let (aos_qemu, aos_plugin) =
        qemu_artifacts_in_dir(&temp.path().join("aos"), "aos-qemu-build", &plugin_abi)?;
    let env = FakeQemuDiscoveryEnvironment {
        qemu: Some(env_qemu.clone()),
        plugin: Some(env_plugin.clone()),
    };
    let package_set = FakeAosQemuPackageSet {
        qemu: Some(PathBuf::from(&aos_qemu)),
        plugin: Some(PathBuf::from(&aos_plugin)),
    };

    let flag_cli = Cli::parse_from([
        "crucible",
        "--qemu",
        &flag_qemu,
        "--plugin",
        &flag_plugin,
        "run",
        TEST_SCENARIO,
    ]);
    let flag_plan = plan_backend_selection_with_discovery(&flag_cli, &env, &package_set)?
        .expect("run should require backend selection");
    let Some(ResolvedLocalBackend::Qemu {
        qemu,
        plugin,
        qemu_source,
        plugin_source,
        ..
    }) = &flag_plan.resolved_backend
    else {
        panic!("flags should resolve QEMU");
    };
    assert_eq!(qemu, &PathBuf::from(&flag_qemu));
    assert_eq!(plugin, &PathBuf::from(&flag_plugin));
    assert_eq!(*qemu_source, QemuDiscoverySource::Flag);
    assert_eq!(*plugin_source, QemuDiscoverySource::Flag);
    assert!(flag_plan.proves_t_cli_5());

    let env_cli = Cli::parse_from(["crucible", "--backend", "qemu", "run", TEST_SCENARIO]);
    let env_plan = plan_backend_selection_with_discovery(&env_cli, &env, &package_set)?
        .expect("run should require backend selection");
    let Some(ResolvedLocalBackend::Qemu {
        qemu,
        plugin,
        qemu_source,
        plugin_source,
        ..
    }) = &env_plan.resolved_backend
    else {
        panic!("environment should resolve QEMU");
    };
    assert_eq!(qemu, &PathBuf::from(&env_qemu));
    assert_eq!(plugin, &PathBuf::from(&env_plugin));
    assert_eq!(*qemu_source, QemuDiscoverySource::Environment);
    assert_eq!(*plugin_source, QemuDiscoverySource::Environment);
    assert!(env_plan.proves_t_cli_5());

    let empty_env = FakeQemuDiscoveryEnvironment::default();
    let aos_cli = Cli::parse_from(["crucible", "run", TEST_SCENARIO]);
    let aos_plan = plan_backend_selection_with_discovery(&aos_cli, &empty_env, &package_set)?
        .expect("run should require backend selection");
    let Some(ResolvedLocalBackend::Qemu {
        qemu,
        plugin,
        qemu_source,
        plugin_source,
        ..
    }) = &aos_plan.resolved_backend
    else {
        panic!("AOS package set should resolve QEMU");
    };
    assert_eq!(qemu, &PathBuf::from(&aos_qemu));
    assert_eq!(plugin, &PathBuf::from(&aos_plugin));
    assert_eq!(*qemu_source, QemuDiscoverySource::AosPackageSet);
    assert_eq!(*plugin_source, QemuDiscoverySource::AosPackageSet);
    assert_eq!(
        aos_plan.reason,
        BackendSelectionReason::AutoQemuArtifactsSupplied
    );
    assert!(aos_plan.proves_t_cli_5());

    Ok(())
}

#[test]
pub(super) fn cli_hermetic_qemu_discovery_uses_compile_time_aos_package_hints()
-> Result<(), Box<dyn Error>> {
    let (Some(qemu_hint), Some(plugin_hint)) = (
        option_env!("CRUCIBLE_AOS_QEMU"),
        option_env!("CRUCIBLE_AOS_PLUGIN"),
    ) else {
        return Ok(());
    };
    let cli = Cli::parse_from(["crucible", "run", TEST_SCENARIO]);
    let plan = plan_backend_selection_with_discovery(
        &cli,
        &FakeQemuDiscoveryEnvironment::default(),
        &CompileTimeAosQemuPackageSet,
    )?
    .expect("run should require backend selection");
    let Some(ResolvedLocalBackend::Qemu {
        qemu,
        plugin,
        qemu_source,
        plugin_source,
        ..
    }) = &plan.resolved_backend
    else {
        panic!("compile-time AOS hints should resolve QEMU");
    };

    assert_eq!(qemu, &PathBuf::from(qemu_hint));
    assert_eq!(plugin, &PathBuf::from(plugin_hint));
    assert_eq!(*qemu_source, QemuDiscoverySource::AosPackageSet);
    assert_eq!(*plugin_source, QemuDiscoverySource::AosPackageSet);
    assert_eq!(
        plan.reason,
        BackendSelectionReason::AutoQemuArtifactsSupplied
    );
    assert!(plan.proves_t_cli_5());

    Ok(())
}

#[test]
pub(super) fn cli_hermetic_qemu_discovery_fails_absent_or_mismatched_artifacts_with_exit_4()
-> Result<(), Box<dyn Error>> {
    let missing_cli = Cli::parse_from(["crucible", "--backend", "qemu", "run", TEST_SCENARIO]);
    let error = match plan_backend_selection_with_discovery(
        &missing_cli,
        &FakeQemuDiscoveryEnvironment::default(),
        &FakeAosQemuPackageSet::default(),
    ) {
        Ok(_) => panic!("explicit qemu without hermetic sources must fail"),
        Err(error) => error,
    };
    assert!(matches!(error, CliError::Backend(_)));
    assert_eq!(error.exit_code(), 4);
    assert!(error.to_string().contains(CRUCIBLE_QEMU_ENV));
    assert!(error.to_string().contains("host $PATH QEMU is never used"));

    let temp = TempDir::new()?;
    let plugin_abi = required_qemu_plugin_abi();
    let shmem_abi_version = crucible::SHMEM_ABI_VERSION;
    let (qemu, plugin) =
        qemu_artifacts_in_dir(&temp.path().join("mismatch"), "qemu-build-a", &plugin_abi)?;
    fs::write(
        temp.path()
            .join("mismatch")
            .join("crucible-qemu-plugin-build-info"),
        format!(
            "package=crucible-qemu-plugin\nqemu_build_id=qemu-build-b\nshmem_abi_version={shmem_abi_version}\nshmem_abi={plugin_abi}\nshmem_generated_header_hash=sha256-test-shmem-header\nplugin_abi={plugin_abi}\n"
        ),
    )?;
    let mismatch_cli = Cli::parse_from([
        "crucible",
        "--backend",
        "qemu",
        "--qemu",
        &qemu,
        "--plugin",
        &plugin,
        "run",
        TEST_SCENARIO,
    ]);
    let error = match plan_backend_selection_with_discovery(
        &mismatch_cli,
        &FakeQemuDiscoveryEnvironment::default(),
        &FakeAosQemuPackageSet::default(),
    ) {
        Ok(_) => panic!("mismatched plugin must fail"),
        Err(error) => error,
    };
    assert!(matches!(error, CliError::Backend(_)));
    assert_eq!(error.exit_code(), 4);
    assert!(error.to_string().contains("built for QEMU identity"));

    let (qemu, plugin) = qemu_artifacts_in_dir(
        &temp.path().join("shmem-mismatch"),
        "qemu-build-c",
        &plugin_abi,
    )?;
    fs::write(
        temp.path()
            .join("shmem-mismatch")
            .join("qemu-build-identity.env"),
        "qemu_plugins_enabled=true\nqemu_crucible_patches_applied=true\nqemu_sim_capability=qemu-crucible\nqemu_patch_series_hash=sha256-test-qemu-patch-series\nqemu_shmem_abi_version=999\nqemu_shmem_abi=crucible-shmem-abi-v999\nqemu_shmem_header=include/aos/crucible/crucible_shmem_abi.h\nqemu_shmem_header_hash=sha256-test-shmem-header\nqemu_build_id=qemu-build-c\n",
    )?;
    let mismatch_cli = Cli::parse_from([
        "crucible",
        "--backend",
        "qemu",
        "--qemu",
        &qemu,
        "--plugin",
        &plugin,
        "run",
        TEST_SCENARIO,
    ]);
    let error = match plan_backend_selection_with_discovery(
        &mismatch_cli,
        &FakeQemuDiscoveryEnvironment::default(),
        &FakeAosQemuPackageSet::default(),
    ) {
        Ok(_) => panic!("mismatched QEMU shmem ABI must fail"),
        Err(error) => error,
    };
    assert!(matches!(error, CliError::Backend(_)));
    assert_eq!(error.exit_code(), 4);
    assert!(error.to_string().contains("advertises shmem ABI"));

    let (qemu, plugin) = qemu_artifacts_in_dir(
        &temp.path().join("shmem-version-mismatch"),
        "qemu-build-d",
        &plugin_abi,
    )?;
    fs::write(
        temp.path()
            .join("shmem-version-mismatch")
            .join("qemu-build-identity.env"),
        "qemu_plugins_enabled=true\nqemu_crucible_patches_applied=true\nqemu_sim_capability=qemu-crucible\nqemu_patch_series_hash=sha256-test-qemu-patch-series\nqemu_shmem_abi_version=999\nqemu_shmem_abi=crucible-shmem-abi-v1\nqemu_shmem_header=include/aos/crucible/crucible_shmem_abi.h\nqemu_shmem_header_hash=sha256-test-shmem-header\nqemu_build_id=qemu-build-d\n",
    )?;
    let mismatch_cli = Cli::parse_from([
        "crucible",
        "--backend",
        "qemu",
        "--qemu",
        &qemu,
        "--plugin",
        &plugin,
        "run",
        TEST_SCENARIO,
    ]);
    let error = match plan_backend_selection_with_discovery(
        &mismatch_cli,
        &FakeQemuDiscoveryEnvironment::default(),
        &FakeAosQemuPackageSet::default(),
    ) {
        Ok(_) => panic!("inconsistent QEMU shmem ABI version marker must fail"),
        Err(error) => error,
    };
    assert!(matches!(error, CliError::Backend(_)));
    assert_eq!(error.exit_code(), 4);
    assert!(error.to_string().contains("qemu_shmem_abi_version"));

    let (qemu, plugin) = qemu_artifacts_in_dir(
        &temp.path().join("shmem-header-hash-mismatch"),
        "qemu-build-e",
        &plugin_abi,
    )?;
    fs::write(
        temp.path()
            .join("shmem-header-hash-mismatch")
            .join("crucible-qemu-plugin-build-info"),
        format!(
            "package=crucible-qemu-plugin\nqemu_build_id=qemu-build-e\nshmem_abi_version={shmem_abi_version}\nshmem_abi={plugin_abi}\nshmem_generated_header_hash=sha256-different-shmem-header\nplugin_abi={plugin_abi}\n"
        ),
    )?;
    let mismatch_cli = Cli::parse_from([
        "crucible",
        "--backend",
        "qemu",
        "--qemu",
        &qemu,
        "--plugin",
        &plugin,
        "run",
        TEST_SCENARIO,
    ]);
    let error = match plan_backend_selection_with_discovery(
        &mismatch_cli,
        &FakeQemuDiscoveryEnvironment::default(),
        &FakeAosQemuPackageSet::default(),
    ) {
        Ok(_) => panic!("mismatched shmem generated-header hash must fail"),
        Err(error) => error,
    };
    assert!(matches!(error, CliError::Backend(_)));
    assert_eq!(error.exit_code(), 4);
    assert!(error.to_string().contains("shmem header hash"));

    Ok(())
}

#[test]
pub(super) fn cli_hermetic_qemu_discovery_pins_identity_into_failure_artifacts()
-> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let plugin_abi = required_qemu_plugin_abi();
    let (qemu, plugin) = qemu_artifacts_in_dir(temp.path(), "artifact-qemu-build", &plugin_abi)?;
    let cli = Cli::parse_from([
        "crucible",
        "--backend",
        "qemu",
        "--qemu",
        &qemu,
        "--plugin",
        &plugin,
        "run",
        TEST_SCENARIO,
    ]);
    let backend_plan = plan_backend_selection_with_discovery(
        &cli,
        &FakeQemuDiscoveryEnvironment::default(),
        &FakeAosQemuPackageSet::default(),
    )?
    .expect("run should require backend selection");
    let bytes = mock_failure_reproduction_artifact_bytes_for_backend(
        0x0010_0005,
        backend_plan.resolved_backend.as_ref(),
    )?;
    let artifact = decode_reproduction_artifact(&bytes)?;

    assert_eq!(
        artifact.identity.qemu_build_id,
        content_address_bytes(b"artifact-qemu-build")
    );
    assert_eq!(
        artifact.identity.qemu_patch_series_hash,
        "sha256-test-qemu-patch-series"
    );
    assert_eq!(
        artifact.identity.shmem_abi_version,
        crucible::SHMEM_ABI_VERSION.to_string()
    );
    assert_eq!(
        artifact.identity.guest_host_protocol_version,
        current_guest_host_protocol_version()
    );
    assert_eq!(artifact.identity.rpc_abi_version, current_rpc_abi_version());
    assert_eq!(artifact.identity.rpc_abi_build, current_rpc_abi_build());
    assert_eq!(artifact.identity.plugin_abi, plugin_abi);
    assert!(backend_plan.proves_t_cli_5());

    Ok(())
}

#[test]
pub(super) fn cli_save_workflow_plans_quiescence_and_virtual_time_savepoints()
-> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let scenario = write_valid_run_scenario(&temp)?;
    let artifact_dir = temp.path().join("artifacts");
    let out = temp.path().join("release.crucible-savepoint");
    let cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--artifact-dir"),
        artifact_dir.display().to_string(),
        String::from("save"),
        scenario.display().to_string(),
        String::from("--at"),
        String::from("quiescence"),
        String::from("--label"),
        String::from("release-candidate"),
        String::from("--out"),
        out.display().to_string(),
    ]);
    let Commands::Save(args) = &cli.command else {
        panic!("expected save command");
    };
    let plan = plan_save_invocation(args, temp.path(), &cli.artifact_dir)?;

    assert_eq!(plan.at, SaveAtArg::Quiescence);
    assert_eq!(plan.label, "release-candidate");
    assert_eq!(plan.output, SaveOutputTarget::Explicit(out));
    assert_eq!(plan.run_plan.save_policy, RunSavePolicy::Never);
    assert_eq!(
        plan.run_plan.terminal_condition,
        RunTerminalCondition::Quiescence
    );

    let quiescence_with_time = Cli::parse_from([
        String::from("crucible"),
        String::from("save"),
        scenario.display().to_string(),
        String::from("--at"),
        String::from("quiescence"),
        String::from("--max-virtual-time"),
        String::from("2ticks"),
    ]);
    let Commands::Save(args) = &quiescence_with_time.command else {
        panic!("expected save command");
    };
    let error = plan_save_invocation(args, temp.path(), temp.path())
        .expect_err("quiescence save must reject a virtual-time coordinate");
    assert!(matches!(error, CliError::Usage(_)));
    assert_eq!(error.exit_code(), 64);
    assert!(
        error
            .to_string()
            .contains("does not accept --max-virtual-time")
    );

    let virtual_time = Cli::parse_from([
        String::from("crucible"),
        String::from("save"),
        scenario.display().to_string(),
        String::from("--at"),
        String::from("virtual-time"),
        String::from("--max-virtual-time"),
        String::from("2ticks"),
    ]);
    let Commands::Save(args) = &virtual_time.command else {
        panic!("expected save command");
    };
    let plan = plan_save_invocation(args, temp.path(), temp.path())?;
    assert_eq!(plan.at, SaveAtArg::VirtualTime);
    assert_eq!(
        plan.run_plan.terminal_condition,
        RunTerminalCondition::VirtualTime
    );
    assert_eq!(plan.run_plan.max_virtual_time_ticks, Some(2));

    let property = Cli::parse_from([
        String::from("crucible"),
        String::from("save"),
        String::from("builtin:fault-campaign"),
        String::from("--at"),
        String::from("property"),
        String::from("--property"),
        String::from("no-split-brain"),
    ]);
    let Commands::Save(args) = &property.command else {
        panic!("expected save command");
    };
    let plan = plan_save_invocation(args, temp.path(), temp.path())?;
    assert_eq!(plan.at, SaveAtArg::Property);
    assert_eq!(
        plan.selector,
        Some(SaveAtSelector::PropertyViolation {
            assertion: String::from("no-split-brain")
        })
    );
    assert_eq!(
        plan.run_plan.terminal_condition,
        RunTerminalCondition::Property
    );

    let marker = Cli::parse_from([
        String::from("crucible"),
        String::from("save"),
        String::from("builtin:fault-campaign"),
        String::from("--at"),
        String::from("marker"),
        String::from("--marker"),
        String::from("compaction-started"),
    ]);
    let Commands::Save(args) = &marker.command else {
        panic!("expected save command");
    };
    let plan = plan_save_invocation(args, temp.path(), temp.path())?;
    assert_eq!(plan.at, SaveAtArg::Marker);
    assert_eq!(
        plan.selector,
        Some(SaveAtSelector::Marker {
            name: String::from("compaction-started")
        })
    );

    let unknown_property = Cli::parse_from([
        String::from("crucible"),
        String::from("save"),
        scenario.display().to_string(),
        String::from("--at"),
        String::from("property"),
        String::from("--property"),
        String::from("no-split-brain"),
    ]);
    let Commands::Save(args) = &unknown_property.command else {
        panic!("expected save command");
    };
    let error = match plan_save_invocation(args, temp.path(), temp.path()) {
        Ok(_) => panic!("property savepoint planning requires a declared assertion"),
        Err(error) => error,
    };
    assert!(matches!(error, CliError::InvalidScenario(_)));
    assert!(error.to_string().contains("not declared"));

    let error = match Cli::try_parse_from([
        String::from("crucible"),
        String::from("save"),
        scenario.display().to_string(),
    ]) {
        Ok(_) => panic!("save without --at must fail"),
        Err(error) => error,
    };
    assert_eq!(
        error.kind(),
        clap::error::ErrorKind::MissingRequiredArgument
    );
    assert_eq!(cli_parse_error_exit_code(&error), 64);

    let error = match Cli::try_parse_from([
        String::from("crucible"),
        String::from("save"),
        scenario.display().to_string(),
        String::from("--at"),
        String::from("virtual-time"),
    ]) {
        Ok(_) => panic!("virtual-time save without coordinate must fail"),
        Err(error) => error,
    };
    assert_eq!(
        error.kind(),
        clap::error::ErrorKind::MissingRequiredArgument
    );
    assert_eq!(cli_parse_error_exit_code(&error), 64);
    assert!(error.to_string().contains("--max-virtual-time"));

    for at in ["property", "marker"] {
        let error = match Cli::try_parse_from([
            String::from("crucible"),
            String::from("save"),
            scenario.display().to_string(),
            String::from("--at"),
            String::from(at),
        ]) {
            Ok(_) => panic!("{at} savepoint planning requires a concrete selector"),
            Err(error) => error,
        };
        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
        assert_eq!(cli_parse_error_exit_code(&error), 64);
        assert!(error.to_string().contains("required"));
    }

    Ok(())
}
#[path = "surface/backend_selection.rs"]
mod backend_selection;
#[path = "surface/debug_execution.rs"]
mod debug_execution;

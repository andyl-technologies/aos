//! Private construction and event-log helpers for production VM lifecycles.

use super::*;
use std::io::Read;

pub(super) fn validate_exact_checkpoint_target(
    node: &NodeId,
    target: &ProductionVmExactCheckpointTarget,
    fault_identity: ContentHash,
) -> Result<(), LifecycleApiError> {
    validate_exact_checkpoint_artifact(&target.overlay_artifact, "root overlay")?;
    validate_exact_checkpoint_artifact(&target.vmstate_artifact, "VMState")?;
    let observed = ContentHash::from_canonical_material(
        "crucible.production-vm-exact-checkpoint.v1",
        &format!(
            "configuration={}\nnode={}\ncounter={}\nscheduler_time={}\nsnapshot={}\nfault={}\noverlay={}\nvmstate={}",
            target.configuration.id().to_hex(),
            node.name,
            target.counter,
            target.scheduler_time.ticks,
            target.snapshot.id().to_hex(),
            fault_identity.to_hex(),
            target.overlay_artifact.identity.to_hex(),
            target.vmstate_artifact.identity.to_hex(),
        ),
    );
    if observed != target.manifest_identity {
        return Err(loop_factory_error(format!(
            "exact checkpoint target for `{}` failed manifest authentication",
            node.name
        )));
    }
    Ok(())
}

pub(super) const fn production_guest_architecture(
    architecture: crucible::VmArchitecture,
) -> ProductionGuestArchitecture {
    match architecture {
        crucible::VmArchitecture::X86_64 => ProductionGuestArchitecture::X86_64,
        crucible::VmArchitecture::Aarch64 => ProductionGuestArchitecture::Aarch64,
    }
}

pub(super) fn production_qemu_executable(
    configured: &Path,
    architecture: crucible::VmArchitecture,
) -> PathBuf {
    let executable_name = match architecture {
        crucible::VmArchitecture::X86_64 => "qemu-system-x86_64",
        crucible::VmArchitecture::Aarch64 => "qemu-system-aarch64",
    };
    configured.with_file_name(executable_name)
}

pub(super) const fn production_whitebox_switch(
    policy: crucible::WhiteBoxPolicy,
) -> ProductionPluginSwitch {
    match policy {
        crucible::WhiteBoxPolicy::Disabled => ProductionPluginSwitch::Off,
        crucible::WhiteBoxPolicy::Enabled => ProductionPluginSwitch::On,
    }
}

pub(super) fn production_app_random_launch_config(
    scenario: &ScenarioDef,
    branch: Option<&ProductionVmBranchConfig>,
    node: &NodeId,
) -> ProductionAppRandomConfig {
    let mut config = ProductionAppRandomConfig::from_seed(
        scenario.seed(),
        scenario.app_random_draw_cap(),
        node.name.clone(),
    );
    if let Some(branch) = branch
        && let Some(seed) = branch.seed
    {
        let prefix_draws = app_random_request_count(&branch.base, node);
        config = config.with_branch_seed(seed, prefix_draws);
    }
    config
}

pub(super) fn production_app_random_checkpoint_config(
    scheduler: &SingleSchedulerCheckpoint,
    scenario: &ScenarioDef,
    branch: Option<&ProductionVmBranchConfig>,
    node: &NodeId,
) -> Result<ProductionAppRandomConfig, SchedulerError> {
    let branch = if scheduler.branch_frontier_cap().is_some() {
        branch
    } else {
        None
    };
    let configuration = scheduler.configuration_for(scenario).map_err(|error| {
        SchedulerError::BoundaryViolation {
            message: format!("decode scheduler checkpoint configuration: {error}"),
        }
    })?;
    let decisions = configuration.schedule.decisions();
    let streams = decisions
        .iter()
        .enumerate()
        .filter_map(|(index, _decision)| app_random_request_stream(decisions, index, node))
        .collect::<std::collections::BTreeSet<_>>();
    let positions = scheduler
        .future_decision_rng_state()
        .positions
        .iter()
        .filter(|(stream, _position)| streams.contains(stream))
        .map(|(stream, position)| (stream.name.clone(), position.draws))
        .collect::<BTreeMap<_, _>>();
    let draw_offset = positions.values().try_fold(0_u64, |sum, draws| {
        sum.checked_add(*draws)
            .ok_or_else(|| SchedulerError::BoundaryViolation {
                message: format!(
                    "app-random continuation cursor overflow for `{}`",
                    node.name
                ),
            })
    })?;
    let mut config = ProductionAppRandomConfig::from_seed(
        scheduler.future_decision_seed(),
        scenario.app_random_draw_cap(),
        node.name.clone(),
    )
    .with_continuation(draw_offset, positions);
    if let Some(branch) = branch
        && let Some(seed) = branch.seed
    {
        let prefix_draws = app_random_request_count(&branch.base, node);
        config = config.with_branch_seed(seed, prefix_draws);
    }
    Ok(config)
}

fn app_random_request_count(configuration: &Configuration, node: &NodeId) -> u64 {
    let decisions = configuration.schedule.decisions();
    decisions
        .iter()
        .enumerate()
        .filter(|(index, _decision)| app_random_request_stream(decisions, *index, node).is_some())
        .count() as u64
}

fn app_random_request_stream<'a>(
    decisions: &'a [Decision],
    index: usize,
    node: &NodeId,
) -> Option<&'a crucible::RngStreamId> {
    match decisions.get(index)? {
        Decision::AppRandom(random) if random.node == *node => Some(&random.stream),
        Decision::Selection(selection)
            if selection.is_app_random_model_sample() || selection.is_campaign_branch() =>
        {
            let Decision::RngDraw(draw) = decisions.get(index.checked_sub(1)?)? else {
                return None;
            };
            crucible::app_random_stream_belongs_to_node(&draw.stream, node).then_some(&draw.stream)
        }
        _ => None,
    }
}

pub(super) fn private_backend_gdbstub_path(node_directory: &Path) -> PathBuf {
    node_directory.join("debug-rsp.sock")
}

pub(super) fn qemu_unix_gdbstub_endpoint(path: &Path) -> Result<String, LifecycleApiError> {
    let path = path.to_str().ok_or_else(|| {
        loop_factory_error(format!(
            "QEMU gdbstub path is not valid UTF-8: {}",
            path.display()
        ))
    })?;
    if path.contains([',', '\n', '\0']) {
        return Err(loop_factory_error(format!(
            "QEMU gdbstub path contains unsupported syntax: {path}"
        )));
    }
    Ok(format!("unix:{path},server=on,wait=off"))
}

pub(super) fn no_named_trigger_leaf(_leaf: ConditionLeaf<'_>) -> bool {
    false
}

pub(super) fn merge_event_log_append(
    outcome: &mut QuantumOutcome,
    append: SchedulerEventLogAppend,
) {
    outcome.event_log_entries.extend(append.entries);
    outcome.event_log_segment_bytes = append.segment_bytes;
    outcome.event_log_segment_text = append.segment_text;
    outcome.event_log_segment_hash = append.segment_hash;
    outcome.event_log_offset = append.offset;
}

pub(super) fn prepend_event_log_appends(
    outcome: &mut QuantumOutcome,
    appends: Vec<SchedulerEventLogAppend>,
) {
    let mut entries = appends
        .iter()
        .flat_map(|append| append.entries.iter().cloned())
        .collect::<Vec<_>>();
    entries.append(&mut outcome.event_log_entries);
    outcome.event_log_entries = entries;
    if outcome.event_log_segment_hash.is_none()
        && let Some(append) = appends.last()
    {
        outcome.event_log_segment_bytes = append.segment_bytes.clone();
        outcome.event_log_segment_text = append.segment_text.clone();
        outcome.event_log_segment_hash = append.segment_hash;
        outcome.event_log_offset = append.offset;
    }
}

pub(super) fn merge_terminal_verdict(
    terminal_verdict: &mut Option<QuantumTerminalVerdict>,
    firings: &EventFirings,
) {
    let mut passed = false;
    let mut violations = Vec::new();
    for firing in firings.iter() {
        collect_terminal_actions(firing.action(), &mut passed, &mut violations);
    }
    match (passed, violations.is_empty()) {
        (_, false) => match terminal_verdict {
            Some(QuantumTerminalVerdict::Failed(existing)) => existing.extend(violations),
            _ => *terminal_verdict = Some(QuantumTerminalVerdict::Failed(violations)),
        },
        (true, true) if terminal_verdict.is_none() => {
            *terminal_verdict = Some(QuantumTerminalVerdict::Passed);
        }
        _ => {}
    }
}

pub(super) fn collect_terminal_actions(
    action: &Action,
    passed: &mut bool,
    violations: &mut Vec<String>,
) {
    match action {
        Action::Pass => *passed = true,
        Action::Fail { reason } => violations.push(reason.clone()),
        Action::Group(actions) => {
            for action in actions {
                collect_terminal_actions(action, passed, violations);
            }
        }
        Action::ArmTimer { .. }
        | Action::CancelTimer { .. }
        | Action::StartNode { .. }
        | Action::StopNode { .. }
        | Action::CreateSavepoint { .. }
        | Action::Fork { .. }
        | Action::Log { .. } => {}
    }
}

pub(super) fn prepare_root_overlay(
    executable: &Path,
    root_image: &Path,
    run_directory: &Path,
) -> Result<(), LifecycleApiError> {
    let image_tool = executable.with_file_name("qemu-img");
    let overlay = run_directory.join(PRODUCTION_ROOT_OVERLAY_FILE_NAME);
    let virtual_size = fs::metadata(root_image)
        .map_err(|error| loop_factory_error(format!("read root image metadata: {error}")))?
        .len();
    let virtual_size = format!("{virtual_size}B");
    let output = Command::new(&image_tool)
        .arg("create")
        .arg("-q")
        .arg("-f")
        .arg("qcow2")
        .arg(&overlay)
        .arg(&virtual_size)
        .output()
        .map_err(|error| {
            loop_factory_error(format!("execute {}: {error}", image_tool.display()))
        })?;
    if output.status.success() {
        return Ok(());
    }
    Err(loop_factory_error(format!(
        "{} rejected root overlay creation with {}: {}",
        image_tool.display(),
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    )))
}

pub(super) fn hash_file(path: &Path) -> Result<crucible::ContentHash, std::io::Error> {
    let mut file = fs::File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(crucible::ContentHash {
        bytes: *hasher.finalize().as_bytes(),
    })
}

pub(super) fn loop_factory_error(message: impl Into<String>) -> LifecycleApiError {
    LifecycleApiError::LoopFactory {
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct RecordedLaunch {
        node: String,
        router: String,
        crash_detector: String,
        exact: Option<(ContentHash, bool)>,
    }

    struct RecordingRejectingLauncher {
        calls: Arc<std::sync::Mutex<Vec<RecordedLaunch>>>,
    }

    impl ProductionVmNodeLauncher for RecordingRejectingLauncher {
        fn launch(
            &mut self,
            request: ProductionVmNodeLaunchRequest<'_>,
        ) -> Result<QemuNode, LifecycleApiError> {
            let exact = match request.kind() {
                ProductionVmNodeLaunchKind::Fresh => None,
                ProductionVmNodeLaunchKind::Exact { snapshot, paused } => {
                    Some((snapshot.id(), paused))
                }
            };
            self.calls
                .lock()
                .unwrap_or_else(|_| panic!("launch recorder lock should remain healthy"))
                .push(RecordedLaunch {
                    node: request.node_name().to_owned(),
                    router: request.router_name().to_owned(),
                    crash_detector: request.crash_detector().to_owned(),
                    exact,
                });
            Err(loop_factory_error(
                "recording launcher rejects process spawn",
            ))
        }

        fn replay_candidate(&self) -> Result<Box<dyn ProductionVmNodeLauncher>, LifecycleApiError> {
            Err(loop_factory_error(
                "recording launcher rejects replay authority",
            ))
        }

        fn finish(&mut self) -> Result<(), LifecycleApiError> {
            Ok(())
        }
    }

    fn launch_snapshot(label: &str) -> QemuVmSnapshot {
        let scenario = ScenarioDef::from_canonical_material(
            "crucible.test.production-launch-authority",
            label,
        );
        let configuration = Configuration::genesis(scenario);
        let checkpoint = Checkpoint::from_recorded_configuration(
            &configuration,
            None,
            VirtualTime::default(),
            BTreeMap::new(),
            CheckpointKind::Fat,
            BTreeMap::new(),
        )
        .unwrap_or_else(|error| panic!("launch checkpoint should build: {error}"));
        QemuVmSnapshot::diskless(
            checkpoint,
            crucible_qemu::QemuReplayOracleValidation::NotRun,
        )
        .unwrap_or_else(|error| panic!("launch snapshot should build: {error}"))
    }

    #[test]
    fn production_vm_loop_can_move_to_the_session_actor() {
        fn assert_send<T: Send>() {}
        assert_send::<ProductionVmLifecycleLoop>();
    }

    #[test]
    fn production_lifecycle_routes_every_launch_mode_through_one_authority() {
        let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut launcher = RecordingRejectingLauncher {
            calls: Arc::clone(&calls),
        };
        let profile = ProductionLiveNodeStepGateConfig::new_with_root_image(
            "qemu",
            "plugin",
            "kernel",
            "root",
            "run-directory",
        );
        let snapshot = launch_snapshot("exact");

        for (crash_detector, kind) in [
            ("fresh", ProductionVmNodeLaunchKind::Fresh),
            (
                "exact-running",
                ProductionVmNodeLaunchKind::Exact {
                    snapshot: &snapshot,
                    paused: false,
                },
            ),
            (
                "exact-paused",
                ProductionVmNodeLaunchKind::Exact {
                    snapshot: &snapshot,
                    paused: true,
                },
            ),
        ] {
            let error = launch_production_node_generation(
                &mut launcher,
                &profile,
                Path::new("run-directory"),
                "node-a",
                crash_detector,
                kind,
            )
            .err()
            .unwrap_or_else(|| panic!("recording launcher should reject process spawn"));
            assert!(error.to_string().contains("recording launcher rejects"));
        }

        assert!(launcher.replay_candidate().is_err());
        assert_eq!(
            *calls
                .lock()
                .unwrap_or_else(|_| panic!("launch recorder lock should remain healthy")),
            vec![
                RecordedLaunch {
                    node: String::from("node-a"),
                    router: String::from("crucible-router"),
                    crash_detector: String::from("fresh"),
                    exact: None,
                },
                RecordedLaunch {
                    node: String::from("node-a"),
                    router: String::from("crucible-router"),
                    crash_detector: String::from("exact-running"),
                    exact: Some((snapshot.id(), false)),
                },
                RecordedLaunch {
                    node: String::from("node-a"),
                    router: String::from("crucible-router"),
                    crash_detector: String::from("exact-paused"),
                    exact: Some((snapshot.id(), true)),
                },
            ]
        );
    }

    #[test]
    fn scheduler_step_bound_counts_quanta_instead_of_instruction_slices() {
        let config =
            ProductionVmLifecycleConfig::new("qemu", "plugin", "kernel", "root", "run-state")
                .with_run_ceiling_icount(12_000_000_000)
                .with_quantum_budget(16);

        assert_eq!(config.maximum_scheduler_quanta(2), 19);
    }

    #[test]
    fn production_whitebox_switch_follows_the_authored_node_policy() {
        assert_eq!(
            production_whitebox_switch(crucible::WhiteBoxPolicy::Disabled),
            ProductionPluginSwitch::Off
        );
        assert_eq!(
            production_whitebox_switch(crucible::WhiteBoxPolicy::Enabled),
            ProductionPluginSwitch::On
        );
    }

    #[test]
    fn production_guest_architecture_follows_the_authored_node_architecture() {
        assert_eq!(
            production_guest_architecture(crucible::VmArchitecture::X86_64),
            ProductionGuestArchitecture::X86_64
        );
        assert_eq!(
            production_guest_architecture(crucible::VmArchitecture::Aarch64),
            ProductionGuestArchitecture::Aarch64
        );
    }

    #[test]
    fn production_qemu_executable_selects_the_guest_architecture_sibling() {
        let configured = Path::new("/aos/bin/qemu-system-x86_64");

        assert_eq!(
            production_qemu_executable(configured, crucible::VmArchitecture::X86_64),
            Path::new("/aos/bin/qemu-system-x86_64")
        );
        assert_eq!(
            production_qemu_executable(configured, crucible::VmArchitecture::Aarch64),
            Path::new("/aos/bin/qemu-system-aarch64")
        );
    }

    #[test]
    fn typed_app_random_checkpoint_restores_node_stream_cursors() {
        let Ok(initial_shift) = Shift::new(0) else {
            panic!("zero shift should be valid");
        };
        let scenario = ScenarioDef::from_canonical_material_with_seed_and_app_random_draw_cap(
            "crucible.test.production-app-random-checkpoint",
            "scenario=typed-app-random-checkpoint",
            Seed::from_u64(0x5eed),
            8,
        );
        let runtime = SchedulerLivenessScenario::from_canonical_material(
            "typed-app-random-checkpoint-runtime",
            initial_shift,
            8,
            SimInstant { nanos: 8 },
            Vec::new(),
            Vec::new(),
        )
        .with_scenario_def(scenario.clone());
        let Ok(mut scheduler) = SingleScheduler::new(runtime) else {
            panic!("scheduler should build");
        };
        let node = NodeId {
            name: String::from("node-a"),
        };
        let stream = crucible::RngStreamId::from_name("app-random/node:6:node-a/stream:4:test");
        let mut expected = scenario
            .seed()
            .decision_rng()
            .fork_in_domain(&stream.domain, &stream.name);
        let raw = expected.next_u64();

        let Ok((recorded, discoveries, _configuration, _append)) =
            QuantumLoop::append_backend_causal_decisions(
                &mut scheduler,
                vec![Decision::AppRandom(crucible::AppRandomDecision {
                    node: node.clone(),
                    stream: stream.clone(),
                    request_id: 7,
                    width: 8,
                    value: raw & 0xff,
                })],
            )
        else {
            panic!("live app-random decision should normalize");
        };
        assert_eq!(discoveries.len(), 1);

        let Ok(checkpoint) = scheduler.checkpoint() else {
            panic!("scheduler should checkpoint");
        };
        let Ok(resumed) =
            production_app_random_checkpoint_config(&checkpoint, &scenario, None, &node)
        else {
            panic!("typed app-random cursor should restore");
        };
        assert_eq!(resumed.draw_offset, 1);
        assert_eq!(resumed.stream_positions.get(&stream.name), Some(&1));

        let [
            Decision::RngDraw(recorded_draw),
            Decision::Selection(recorded_selection),
        ] = recorded.as_slice()
        else {
            panic!("live normalization should return one draw and one selection");
        };
        let Ok(selection) = recorded_selection.selection() else {
            panic!("recorded selection should decode");
        };
        let Ok(selectable) = crucible::AppRandomSelectable::from_model_sample_records(
            recorded_draw.stream.clone(),
            &selection,
            discoveries[0].declaration(),
            discoveries[0].opportunity(),
            discoveries[0].domain(),
        ) else {
            panic!("recorded app-random discovery should resolve");
        };
        let parent = crucible::step(
            &Configuration::genesis(scenario.clone()),
            Decision::RngDraw(recorded_draw.clone()),
        );
        let Ok(branch_selection) = selectable.branch_selection(&parent, (raw & 0xff) ^ 1) else {
            panic!("typed app-random branch should build");
        };
        let typed_branch = crucible::step(
            &parent,
            Decision::Selection(crucible::SelectionDecision::new(&branch_selection)),
        );
        assert_eq!(app_random_request_count(&typed_branch, &node), 1);

        let branch = ProductionVmBranchConfig {
            base: typed_branch,
            frontier: scheduler.frontier(),
            decisions: Vec::new(),
            seed: Some(Seed::from_u64(0x00b1_2ac4)),
        };
        let relaunched = production_app_random_launch_config(&scenario, Some(&branch), &node);
        assert_eq!(relaunched.branch_after_draws, Some(1));
    }

    #[test]
    fn private_gdbstub_endpoint_uses_the_node_run_directory() {
        let directory = Path::new("/tmp/crucible-node");
        let path = private_backend_gdbstub_path(directory);

        assert_eq!(path, directory.join("debug-rsp.sock"));
        let Ok(endpoint) = qemu_unix_gdbstub_endpoint(&path) else {
            panic!("ordinary private socket path must be accepted");
        };
        assert_eq!(
            endpoint,
            "unix:/tmp/crucible-node/debug-rsp.sock,server=on,wait=off"
        );
    }

    #[test]
    fn private_gdbstub_endpoint_rejects_qemu_option_delimiters() {
        let Err(error) = qemu_unix_gdbstub_endpoint(Path::new("/tmp/node,server=off")) else {
            panic!("comma must not enter the QEMU character-device syntax");
        };

        assert!(error.to_string().contains("unsupported syntax"));
    }

    #[test]
    fn grouped_terminal_actions_collect_failures_before_pass() {
        let action = Action::Group(vec![
            Action::Pass,
            Action::Group(vec![
                Action::Fail {
                    reason: String::from("first violation"),
                },
                Action::Fail {
                    reason: String::from("second violation"),
                },
            ]),
        ]);
        let mut passed = false;
        let mut violations = Vec::new();

        collect_terminal_actions(&action, &mut passed, &mut violations);

        assert!(passed);
        assert_eq!(
            violations,
            vec![
                String::from("first violation"),
                String::from("second violation")
            ]
        );
    }
}

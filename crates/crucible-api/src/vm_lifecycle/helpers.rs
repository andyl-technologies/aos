//! Private construction and event-log helpers for production VM lifecycles.

use super::*;

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
        let prefix_draws = branch
            .base
            .schedule
            .decisions()
            .iter()
            .filter(
                |decision| matches!(decision, Decision::AppRandom(random) if random.node == *node),
            )
            .count() as u64;
        config = config.with_branch_seed(seed, prefix_draws);
    }
    config
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
        Action::InjectFault { .. }
        | Action::HealFault { .. }
        | Action::ArmTimer { .. }
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

pub(super) fn loop_factory_error(message: impl Into<String>) -> LifecycleApiError {
    LifecycleApiError::LoopFactory {
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_vm_loop_can_move_to_the_session_actor() {
        fn assert_send<T: Send>() {}
        assert_send::<ProductionVmLifecycleLoop>();
    }

    #[test]
    fn scheduler_step_bound_counts_quanta_instead_of_instruction_slices() {
        let config = ProductionVmLifecycleConfig::new("qemu", "plugin", "kernel", "root")
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

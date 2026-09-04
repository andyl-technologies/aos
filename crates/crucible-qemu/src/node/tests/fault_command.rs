//! Exact-boundary QEMU fault-command regressions.

use super::*;

#[test]
fn invalid_fault_event_sequence_is_terminal_across_retries() -> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let mut node = scripted_node_with_fault_events(
        Arc::clone(&log),
        [fault_event_with_sequence(1), fault_event_with_sequence(3)],
    )?;
    let mut retained = Vec::new();
    assert!(node.fault_event_pending()?);

    let first_error = node
        .drain_fault_events(&mut retained)
        .expect_err("a sequence gap must fail closed");
    assert_eq!(retained.len(), 2);
    let second_error = node
        .drain_fault_events(&mut retained)
        .expect_err("retry must preserve the terminal sequence failure");
    assert_eq!(retained.len(), 2);
    assert_eq!(first_error.to_string(), second_error.to_string());
    assert!(first_error.to_string().contains("expected 2, observed 3"));
    let pending_error = node
        .fault_event_pending()
        .expect_err("checkpoint admission must observe the terminal failure");
    assert_eq!(first_error.to_string(), pending_error.to_string());

    node.shutdown_child()?;
    Ok(())
}

#[test]
fn fault_command_applies_at_exact_current_boundary_without_guest_progress()
-> Result<(), Box<dyn Error>> {
    for (command_flags, status) in [
        (0, FaultResultStatus::Applied),
        (FAULT_COMMAND_FLAG_PREPARE_ONLY, FaultResultStatus::Prepared),
    ] {
        let log = shared_log();
        let fault_commands = Arc::new(Mutex::new(Vec::new()));
        let payload = vec![1_u8, 2, 3, 4];
        let command = FaultCommandHeaderV1 {
            abi_major: FAULT_COMMAND_ABI_MAJOR,
            abi_minor: FAULT_COMMAND_ABI_MINOR,
            command_kind: FaultCommandKind::MemoryMutation,
            command_flags,
            phase: FaultBoundaryPhase::NodeBoundary,
            semantic_version: FAULT_COMMAND_SEMANTIC_VERSION,
            command_sequence: 7,
            target_node_hash: [1; 32],
            target_icount: 11,
            authorization_ceiling_icount: 11,
            binding_hash: [2; 32],
            opportunity_hash: [3; 32],
            expected_precondition_hash: [4; 32],
            payload_hash: *blake3::hash(&payload).as_bytes(),
            payload_offset: 0,
            payload_length: u32::try_from(payload.len())?,
        };
        let result_payload = vec![9_u8; 32];
        let result = DequeuedFaultResult::Valid {
            header: FaultResultHeaderV1 {
                abi_major: FAULT_COMMAND_ABI_MAJOR,
                abi_minor: FAULT_COMMAND_ABI_MINOR,
                command_kind: FaultCommandKind::MemoryMutation as u16,
                status,
                semantic_version: FAULT_COMMAND_SEMANTIC_VERSION,
                command_sequence: 7,
                observed_icount: 11,
                applied_icount: 11,
                capability_version: 1,
                phase: FaultBoundaryPhase::NodeBoundary,
                before_hash: [4; 32],
                after_hash: [5; 32],
                evidence_hash: [6; 32],
                result_payload_hash: *blake3::hash(&result_payload).as_bytes(),
                result_offset: 0,
                result_length: u32::try_from(result_payload.len())?,
            },
            payload: result_payload,
        };
        let child = Command::new("sleep").arg("60").spawn()?;
        let process_id = child.id();
        let channels = QemuNodeChannels::new(
            ScriptedPluginControl {
                log: Arc::clone(&log),
                fail_quit: false,
            },
            ScriptedShmemHotPath {
                log: Arc::clone(&log),
                fail_advance: false,
                coverage_enabled: false,
                quantum_coverage: Arc::new(Mutex::new(VecDeque::new())),
                teardown_coverage: Arc::new(Mutex::new(Vec::new())),
                fault_commands: Arc::clone(&fault_commands),
                stale_fault_results: Arc::new(Mutex::new(VecDeque::new())),
                fault_events: Arc::new(Mutex::new(VecDeque::new())),
                fingerprint_retry_countdown: Arc::new(Mutex::new(0)),
                hot_fork_setup_identity: None,
                hot_fork_ring_image: None,
            },
            ScriptedQmpMachineControl {
                log: Arc::clone(&log),
                process_id,
                fail_stop: false,
                fail_snapshot: false,
                timeout_snapshot: false,
                plugin_resources: None,
                plugin_barriers: None,
                last_plugin_barrier: Arc::new(Mutex::new(None)),
                private_ring_state: Arc::new(Mutex::new(None)),
                diagnostic_state: Arc::new(Mutex::new(None)),
                child_qmp_state: Arc::new(Mutex::new(None)),
                child_console_state: Arc::new(Mutex::new(None)),
                process_contract_state: Arc::new(Mutex::new(None)),
                fail_descriptor_install: false,
                fail_descriptor_close: false,
                fail_endpoint_install: false,
                mismatch_endpoint_disposition: false,
                mismatch_request_basis: false,
                serve_child_qmp: false,
                template_query_count: Arc::new(Mutex::new(0)),
                hot_fork_script: HotForkScript::Rejected,
            },
        );
        let mut node = QemuNode::new(
            QemuNodeChild::new(child),
            channels,
            node_shutdown_policy(),
            QemuAsyncDriverPolicy::fast_test(),
            QemuCrashDetector::new("vm-a"),
            ScriptedHostIoRuntime {
                log,
                outcomes: VecDeque::new(),
                fault_results: VecDeque::from([result.clone()]),
                staged_fault_events: Vec::new(),
                fingerprint_fault_events: VecDeque::new(),
                fail_hot_fork_clone: false,
            },
            2,
        )
        .with_fault_capabilities(vec![FaultCapabilityRowV1 {
            command_kind: FaultCommandKind::MemoryMutation,
            semantic_version: FAULT_COMMAND_SEMANTIC_VERSION,
            scope: FaultCapabilityScope::All,
            phase_mask: FaultBoundaryPhase::NodeBoundary.bit(),
            maximum_payload_bytes: 64,
            maximum_pending_commands: 1,
            required_feature_bits: 0,
            capability_hash: [7; 32],
        }]);

        if command_flags == 0 {
            assert!(matches!(
                node.apply_fault_preparation_at_current_boundary(
                    command.clone(),
                    &payload,
                    32,
                    crucible_shmem::HARD_FAULT_EVENT_CAPACITY as usize,
                ),
                Err(QemuNodeError::FaultCommand { message })
                    if message.contains("restricted to non-mutating PREPARE")
            ));
            assert!(fault_commands.lock().unwrap().is_empty());
        } else {
            assert_eq!(
                node.apply_fault_preparation_at_current_boundary(
                    command.clone(),
                    &payload,
                    31,
                    crucible_shmem::HARD_FAULT_EVENT_CAPACITY as usize,
                ),
                Err(QemuNodeError::FaultResultStorage {
                    requested: 32,
                    configured: 31,
                })
            );
        }

        assert_eq!(
            node.apply_fault_command_at_current_boundary(command.clone(), &payload)?,
            result
        );
        let expected_publications = if command_flags == 0 {
            vec![(command, payload)]
        } else {
            vec![(command.clone(), payload.clone()), (command, payload)]
        };
        assert_eq!(*fault_commands.lock().unwrap(), expected_publications);
    }
    Ok(())
}

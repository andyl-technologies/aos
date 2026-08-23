//! Exact-boundary QEMU fault-command regressions.

use super::*;

#[test]
fn fault_command_applies_at_exact_current_boundary_without_guest_progress()
-> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let fault_commands = Arc::new(Mutex::new(Vec::new()));
    let payload = vec![1_u8, 2, 3, 4];
    let command = FaultCommandHeaderV1 {
        abi_major: FAULT_COMMAND_ABI_MAJOR,
        abi_minor: FAULT_COMMAND_ABI_MINOR,
        command_kind: FaultCommandKind::MemoryMutation,
        command_flags: 0,
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
            status: FaultResultStatus::Applied,
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
        },
        ScriptedQmpMachineControl {
            log: Arc::clone(&log),
            fail_stop: false,
            fail_snapshot: false,
            timeout_snapshot: false,
        },
    );
    let child = Command::new("sleep").arg("60").spawn()?;
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

    assert_eq!(
        node.apply_fault_command_at_current_boundary(command.clone(), &payload)?,
        result
    );
    assert_eq!(*fault_commands.lock().unwrap(), vec![(command, payload)]);
    Ok(())
}

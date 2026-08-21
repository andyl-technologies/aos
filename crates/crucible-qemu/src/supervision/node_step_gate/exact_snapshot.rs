//! Exact snapshot/restore production gate and its checkpoint helpers.

use super::*;

/// Evidence that a genuinely retained frame survived a fresh QEMU process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuLiveRetainedNetworkSnapshotReport {
    /// Exact boot boundary at which QEMU reported backpressure.
    pub capture_icount: u64,
    /// Canonical retained frame identity preserved by the snapshot.
    pub retained_frame: crucible_shmem::FrameDeliveryKey,
    /// Delivery-attempt count captured and restored with the frame.
    pub restored_delivery_attempts: u32,
    /// Whether the restored guest userspace acknowledged that exact payload.
    pub guest_acknowledgement_seen: bool,
    /// Whether the frame left canonical shared memory after guest acceptance.
    pub retained_frame_consumed: bool,
    /// Whether the source QEMU was force-crashed before the restore launch.
    pub source_process_force_crashed: bool,
}

/// Captures a real backpressured network frame and restores it in fresh QEMU.
///
/// # Errors
///
/// Returns [`QemuLiveNodeStepGateError`] when exact-boundary backpressure,
/// snapshot capture, forced source-process death, fresh restore, canonical
/// retry, or guest-userspace acknowledgement cannot be proven.
pub fn run_qemu_live_retained_network_snapshot_gate(
    config: &QemuLiveNodeStepGateConfig,
    frame_payload: &[u8],
    guest_ack_payload: &[u8],
    completion_ceiling: u64,
) -> Result<QemuLiveRetainedNetworkSnapshotReport, QemuLiveNodeStepGateError> {
    const CAPTURE_ICOUNT: u64 = 1;
    const DRIVE_INCREMENT: u64 = 100_000_000;
    const MAX_DRIVE_STEPS: usize = 128;

    if frame_payload.is_empty() || guest_ack_payload.is_empty() || completion_ceiling <= 1 {
        return Err(QemuLiveNodeStepGateError::ExactSnapshotInvariant {
            reason: String::from(
                "retained-network exact gate requires payloads and a future ceiling",
            ),
        });
    }

    let capture_directory = config.run_directory.join("retained-network-capture");
    let restore_directory = config.run_directory.join("retained-network-restore");
    for directory in [&capture_directory, &restore_directory] {
        fs::create_dir_all(directory).map_err(|source| {
            QemuLiveNodeStepGateError::PrepareRunDirectory {
                path: directory.clone(),
                source,
            }
        })?;
    }

    let capture_config = config
        .clone()
        .with_boot_network_backpressure_capture(frame_payload.to_vec());
    let identity = node_id(GATE_NODE);
    let mut source = build_live_node(
        &capture_config,
        &capture_directory,
        LiveNodeIdentity {
            node: GATE_NODE,
            router: GATE_ROUTER,
            crash_detector: "retained-network-capture",
        },
        None,
        true,
    )?;
    let source_icount = source
        .current_icount()
        .map_err(|error| QemuLiveNodeStepGateError::node_op("read retained capture icount", error))?
        .retired;
    if source_icount != CAPTURE_ICOUNT {
        return Err(QemuLiveNodeStepGateError::ExactSnapshotInvariant {
            reason: format!(
                "retained-network capture reached icount {source_icount} instead of {CAPTURE_ICOUNT}"
            ),
        });
    }
    let source_transport = source
        .checkpoint_network_transport_for_gate()
        .map_err(|error| {
            QemuLiveNodeStepGateError::node_op("inspect retained capture transport", error)
        })?;
    let (retained_frame, source_attempts) =
        retained_transport_head(&source_transport, frame_payload)?;

    let checkpoint = retained_network_checkpoint(&identity, CAPTURE_ICOUNT);
    let snapshot = source
        .capture_exact_snapshot_paused(&identity, checkpoint)
        .map_err(|error| {
            QemuLiveNodeStepGateError::node_op("capture retained network snapshot", error)
        })?;
    let snapshot_retained = snapshot
        .node_continuation()
        .retained_network_inbound_head()
        .map_err(|error| QemuLiveNodeStepGateError::ExactSnapshotInvariant {
            reason: format!("captured retained network continuation is invalid: {error}"),
        })?;
    if snapshot_retained != Some((retained_frame, source_attempts)) {
        return Err(QemuLiveNodeStepGateError::ExactSnapshotInvariant {
            reason: format!(
                "captured retained continuation changed identity or attempts: source=({retained_frame:?}, {source_attempts}), snapshot={snapshot_retained:?}"
            ),
        });
    }
    copy_exact_gate_artifact(
        &capture_directory.join(crate::DEFAULT_VMSTATE_FILE_NAME),
        &restore_directory.join(crate::DEFAULT_VMSTATE_FILE_NAME),
    )?;
    source.force_crash_and_reap_for_gate().map_err(|error| {
        QemuLiveNodeStepGateError::node_op("force crash retained network source", error)
    })?;
    drop(source);

    let restore_config = capture_config
        .clone()
        .with_run_directory(&restore_directory);
    let mut restored = launch_qemu_live_node_exact_snapshot(
        &restore_config,
        &restore_directory,
        GATE_NODE,
        GATE_ROUTER,
        "retained-network-restore",
        &snapshot,
    )?;
    let restored_icount = restored
        .current_icount()
        .map_err(|error| QemuLiveNodeStepGateError::node_op("read retained restore icount", error))?
        .retired;
    let restored_transport = restored
        .checkpoint_network_transport_for_gate()
        .map_err(|error| {
            QemuLiveNodeStepGateError::node_op("inspect retained restored transport", error)
        })?;
    let (restored_frame, restored_attempts) =
        retained_transport_head(&restored_transport, frame_payload)?;
    if restored_icount != CAPTURE_ICOUNT
        || restored_frame != retained_frame
        || restored_attempts != source_attempts
    {
        return Err(QemuLiveNodeStepGateError::ExactSnapshotInvariant {
            reason: format!(
                "fresh retained restore changed boundary/state: icount={restored_icount}/{CAPTURE_ICOUNT}, frame={restored_frame:?}/{retained_frame:?}, attempts={restored_attempts}/{source_attempts}"
            ),
        });
    }

    let mut guest_acknowledgement_seen = false;
    let mut retained_frame_consumed = false;
    for _ in 0..MAX_DRIVE_STEPS {
        let current = restored
            .current_icount()
            .map_err(|error| {
                QemuLiveNodeStepGateError::node_op("read retained retry icount", error)
            })?
            .retired;
        if current >= completion_ceiling {
            break;
        }
        let idle = restored.idle_state().map_err(|error| {
            QemuLiveNodeStepGateError::node_op("read retained retry idle state", error)
        })?;
        let incremental = current.saturating_add(DRIVE_INCREMENT);
        let target = idle
            .next_deadline
            .filter(|deadline| deadline.retired > current)
            .map_or(incremental, |deadline| incremental.max(deadline.retired))
            .min(completion_ceiling);
        restored
            .advance_to_ceiling(Icount { retired: target })
            .map_err(|error| {
                QemuLiveNodeStepGateError::node_op("advance fresh retained retry", error)
            })?;
        let outputs =
            crucible::SimulationBackend::drain_network_outputs(&mut restored).map_err(|error| {
                QemuLiveNodeStepGateError::ExactSnapshotInvariant {
                    reason: format!("drain restored guest network outputs failed: {error}"),
                }
            })?;
        guest_acknowledgement_seen |= outputs.iter().any(|frame| {
            frame
                .payload
                .windows(guest_ack_payload.len())
                .any(|window| window == guest_ack_payload)
        });
        let transport = restored
            .checkpoint_network_transport_for_gate()
            .map_err(|error| {
                QemuLiveNodeStepGateError::node_op("inspect retained retry completion", error)
            })?;
        retained_frame_consumed = !transport
            .inbound
            .frames
            .iter()
            .any(|frame| frame.delivery_key() == retained_frame);
        if guest_acknowledgement_seen && retained_frame_consumed {
            break;
        }
    }
    if !guest_acknowledgement_seen || !retained_frame_consumed {
        let final_icount = restored
            .current_icount()
            .map_err(|error| {
                QemuLiveNodeStepGateError::node_op("read failed retained retry icount", error)
            })?
            .retired;
        let final_transport =
            restored
                .checkpoint_network_transport_for_gate()
                .map_err(|error| {
                    QemuLiveNodeStepGateError::node_op(
                        "inspect failed retained retry transport",
                        error,
                    )
                })?;
        return Err(QemuLiveNodeStepGateError::ExactSnapshotInvariant {
            reason: format!(
                "fresh retained retry incomplete at icount {final_icount}/{completion_ceiling}: guest_ack={guest_acknowledgement_seen}, consumed={retained_frame_consumed}, inbound={:?}",
                final_transport.inbound.frames,
            ),
        });
    }
    restored
        .shutdown_child()
        .map_err(|error| QemuLiveNodeStepGateError::Shutdown { source: error })?;

    Ok(QemuLiveRetainedNetworkSnapshotReport {
        capture_icount: CAPTURE_ICOUNT,
        retained_frame,
        restored_delivery_attempts: restored_attempts,
        guest_acknowledgement_seen,
        retained_frame_consumed,
        source_process_force_crashed: true,
    })
}

fn retained_transport_head(
    checkpoint: &crate::QemuNetworkTransportCheckpoint,
    expected_payload: &[u8],
) -> Result<(crucible_shmem::FrameDeliveryKey, u32), QemuLiveNodeStepGateError> {
    let Some(frame) = checkpoint.inbound.frames.first() else {
        return Err(QemuLiveNodeStepGateError::ExactSnapshotInvariant {
            reason: String::from("retained network checkpoint has no inbound head"),
        });
    };
    if checkpoint.inbound.frames.len() != 1
        || frame.delivery_state() != Ok(FrameDeliveryState::Retained)
        || frame.payload().ok() != Some(expected_payload)
        || frame.delivery_attempts() == 0
    {
        return Err(QemuLiveNodeStepGateError::ExactSnapshotInvariant {
            reason: format!(
                "retained network checkpoint is not canonical: {:?}",
                checkpoint.inbound.frames
            ),
        });
    }
    Ok((frame.delivery_key(), frame.delivery_attempts()))
}

fn retained_network_checkpoint(node: &NodeId, icount: u64) -> Checkpoint {
    let identity = ContentHash::from_canonical_material(
        "crucible.qemu.retained-network-exact-snapshot.v1",
        &format!("node={}\nicount={icount}", node.name),
    );
    let mut checkpoint = Checkpoint::new(identity, identity, CheckpointKind::Fat);
    checkpoint.virtual_time = VirtualTime { ticks: icount };
    checkpoint
        .node_icounts
        .insert(node.clone(), Icount { retired: icount });
    checkpoint
}

/// Runs an exact live snapshot through save, crash, load, and continued execution.
///
/// The VMState artifact is copied before the captured process continues to the
/// suffix as the uninterrupted oracle and is force-killed. Two separately
/// launched processes restore that copied checkpoint and must reproduce both
/// its exact boundary and the oracle suffix. When `require_pending_block_io` is
/// true, the function stops at the first completed quantum whose production
/// block continuation contains a guest-completed storage mutation still pending
/// in the Apache-side durability continuation. The transport itself is
/// quiescent so QEMU savevm can drain without waiting on an active virtio
/// request.
///
/// # Errors
///
/// Returns [`QemuLiveNodeStepGateError`] when launch, bounded execution, paired
/// capture, forced crash, artifact copy, restore, replay, or any identity and
/// fingerprint comparison fails.
pub fn run_qemu_live_exact_snapshot_gate(
    config: &QemuLiveNodeStepGateConfig,
    capture_ceiling: u64,
    suffix_increment: u64,
    require_pending_block_io: bool,
) -> Result<QemuLiveExactSnapshotReport, QemuLiveNodeStepGateError> {
    if capture_ceiling <= PRIME_CEILING_ICOUNT || suffix_increment == 0 {
        return Err(QemuLiveNodeStepGateError::ExactSnapshotInvariant {
            reason: String::from(
                "capture ceiling must follow priming and suffix increment must be nonzero",
            ),
        });
    }
    if config.root_image.is_some() {
        return Err(QemuLiveNodeStepGateError::ExactSnapshotInvariant {
            reason: String::from(
                "the live exact-snapshot gate accepts firmware plus shared-memory devices, not a separately managed root overlay",
            ),
        });
    }

    let capture_directory = config.run_directory.join("exact-capture");
    let restore_directory = config.run_directory.join("exact-restore");
    let replay_directory = config.run_directory.join("exact-replay");
    for directory in [&capture_directory, &restore_directory, &replay_directory] {
        fs::create_dir_all(directory).map_err(|source| {
            QemuLiveNodeStepGateError::PrepareRunDirectory {
                path: directory.clone(),
                source,
            }
        })?;
    }

    let identity = node_id(GATE_NODE);
    let mut capture_node = build_live_node(
        config,
        &capture_directory,
        LiveNodeIdentity {
            node: GATE_NODE,
            router: GATE_ROUTER,
            crash_detector: "live-exact-capture",
        },
        None,
        true,
    )?;
    let (capture_icount, pending_block_io_captured) = if require_pending_block_io {
        drive_to_pending_block_boundary(
            &mut capture_node,
            capture_ceiling,
            config.completion_timeout,
        )?
    } else {
        let quantum = advance_to_busy_ceiling(&mut capture_node, capture_ceiling)?;
        (quantum.completion_icount, false)
    };
    let checkpoint = exact_gate_checkpoint(&identity, capture_icount, require_pending_block_io);
    let snapshot = capture_node
        .capture_exact_snapshot_paused(&identity, checkpoint.clone())
        .map_err(|source| QemuLiveNodeStepGateError::node_op("capture exact snapshot", source))?;
    let capture_logical_time_offset = snapshot
        .node_continuation()
        .logical_time_calibration()
        .offset()
        .map_err(|source| QemuLiveNodeStepGateError::ExactSnapshotInvariant {
            reason: format!("captured logical-time calibration is invalid: {source}"),
        })?;
    let capture_fingerprint = capture_node
        .execution_fingerprint()
        .map_err(|source| QemuLiveNodeStepGateError::ExecutionFingerprint { source })?
        .hash;
    let capture_sample = capture_node.fingerprint_sample().map_err(|source| {
        QemuLiveNodeStepGateError::node_op("read capture fingerprint sample", source)
    })?;
    if capture_sample.sample_icount != capture_icount
        || capture_sample.vcpu_count != u32::from(config.smp_vcpus)
        || capture_sample.rr_switch_quantum == 0
        || capture_sample.rr_position_in_quantum == 0
        || capture_sample.rr_position_in_quantum >= capture_sample.rr_switch_quantum
        || capture_sample.rr_current_vcpu >= capture_sample.vcpu_count
    {
        return Err(QemuLiveNodeStepGateError::ExactSnapshotInvariant {
            reason: format!(
                "capture did not expose a valid nonzero intra-turn RR cursor: icount={}/{capture_icount}, vcpus={}/{}, current={}, position={}, quantum={}",
                capture_sample.sample_icount,
                capture_sample.vcpu_count,
                config.smp_vcpus,
                capture_sample.rr_current_vcpu,
                capture_sample.rr_position_in_quantum,
                capture_sample.rr_switch_quantum,
            ),
        });
    }
    let mut altered_cursor_sample = capture_sample;
    altered_cursor_sample.rr_position_in_quantum = 0;
    let altered_cursor_fingerprint =
        crate::mapped_quantum::black_box_execution_fingerprint(&identity, &altered_cursor_sample)
            .map_err(|source| QemuLiveNodeStepGateError::ExactSnapshotInvariant {
                reason: format!("cannot fingerprint altered RR cursor: {source}"),
            })?
            .hash;
    let expected_fingerprints = BTreeMap::from([(identity.clone(), capture_fingerprint)]);
    let altered_fingerprints = BTreeMap::from([(identity.clone(), altered_cursor_fingerprint)]);
    let rr_cursor_negative_control_rejected = matches!(
        crate::production_fault_runtime::validate_qemu_fingerprints(
            &expected_fingerprints,
            &altered_fingerprints,
        ),
        Err(crate::ProductionFaultRuntimeError::QemuFingerprintMismatch { .. })
    );
    if !rr_cursor_negative_control_rejected {
        return Err(QemuLiveNodeStepGateError::ExactSnapshotInvariant {
            reason: String::from(
                "production restore admission accepted a fingerprint with a reset RR cursor",
            ),
        });
    }
    let requested_suffix_icount =
        capture_icount
            .checked_add(suffix_increment)
            .ok_or_else(|| QemuLiveNodeStepGateError::ExactSnapshotInvariant {
                reason: String::from("post-restore suffix ceiling overflowed"),
            })?;
    copy_exact_gate_artifact(
        &capture_directory.join(crate::DEFAULT_VMSTATE_FILE_NAME),
        &restore_directory.join(crate::DEFAULT_VMSTATE_FILE_NAME),
    )?;
    copy_exact_gate_artifact(
        &capture_directory.join(crate::DEFAULT_VMSTATE_FILE_NAME),
        &replay_directory.join(crate::DEFAULT_VMSTATE_FILE_NAME),
    )?;
    capture_node.resume_after_restore().map_err(|source| {
        QemuLiveNodeStepGateError::node_op("resume source after exact snapshot", source)
    })?;
    let suffix_icount = advance_to_observable_suffix(&mut capture_node, requested_suffix_icount)?;
    let oracle_suffix_fingerprint = capture_node
        .execution_fingerprint()
        .map_err(|source| QemuLiveNodeStepGateError::ExecutionFingerprint { source })?
        .hash;
    let oracle_suffix_sample = capture_node.fingerprint_sample().map_err(|source| {
        QemuLiveNodeStepGateError::node_op("read source suffix fingerprint sample", source)
    })?;
    capture_node
        .force_crash_and_reap_for_gate()
        .map_err(|source| {
            QemuLiveNodeStepGateError::node_op("force crash after source continuation", source)
        })?;
    drop(capture_node);

    let restore_config = config.clone().with_run_directory(&restore_directory);
    let mut restored = launch_qemu_live_node_exact_snapshot(
        &restore_config,
        &restore_directory,
        GATE_NODE,
        GATE_ROUTER,
        "live-exact-restore",
        &snapshot,
    )?;
    let restored_icount = restored
        .current_icount()
        .map_err(|source| QemuLiveNodeStepGateError::node_op("read restored icount", source))?
        .retired;
    let restored_fingerprint = restored
        .execution_fingerprint()
        .map_err(|source| QemuLiveNodeStepGateError::ExecutionFingerprint { source })?
        .hash;
    let restored_sample = restored.fingerprint_sample().map_err(|source| {
        QemuLiveNodeStepGateError::node_op("read restored fingerprint sample", source)
    })?;
    if restored_icount != capture_icount
        || restored_fingerprint != capture_fingerprint
        || restored_sample != capture_sample
    {
        let components =
            fingerprint_sample_mismatch_components(&restored_sample, &capture_sample).join(",");
        return Err(QemuLiveNodeStepGateError::ExactSnapshotInvariant {
            reason: format!(
                "restore boundary differs: icount {restored_icount}/{capture_icount}, fingerprint {}/{}, RR cursor ({}, {})/({}, {}), differing components [{components}]",
                restored_fingerprint.to_hex(),
                capture_fingerprint.to_hex(),
                restored_sample.rr_current_vcpu,
                restored_sample.rr_position_in_quantum,
                capture_sample.rr_current_vcpu,
                capture_sample.rr_position_in_quantum,
            ),
        });
    }
    advance_to_busy_ceiling(&mut restored, suffix_icount)?;
    let suffix_fingerprint = restored
        .execution_fingerprint()
        .map_err(|source| QemuLiveNodeStepGateError::ExecutionFingerprint { source })?
        .hash;
    let restored_suffix_sample = restored.fingerprint_sample().map_err(|source| {
        QemuLiveNodeStepGateError::node_op("read restored suffix fingerprint sample", source)
    })?;
    if suffix_fingerprint != oracle_suffix_fingerprint
        || restored_suffix_sample != oracle_suffix_sample
    {
        let components =
            fingerprint_sample_mismatch_components(&restored_suffix_sample, &oracle_suffix_sample)
                .join(",");
        return Err(QemuLiveNodeStepGateError::ExactSnapshotInvariant {
            reason: format!(
                "restored suffix fingerprint {} differs from uninterrupted source {}; differing components [{components}]",
                suffix_fingerprint.to_hex(),
                oracle_suffix_fingerprint.to_hex(),
            ),
        });
    }
    restored
        .shutdown_child()
        .map_err(|source| QemuLiveNodeStepGateError::Shutdown { source })?;

    let replay_config = config.clone().with_run_directory(&replay_directory);
    let mut replay = launch_qemu_live_node_exact_snapshot(
        &replay_config,
        &replay_directory,
        GATE_NODE,
        GATE_ROUTER,
        "live-exact-replay",
        &snapshot,
    )?;
    let replay_capture_fingerprint = replay
        .execution_fingerprint()
        .map_err(|source| QemuLiveNodeStepGateError::ExecutionFingerprint { source })?
        .hash;
    let replay_capture_sample = replay.fingerprint_sample().map_err(|source| {
        QemuLiveNodeStepGateError::node_op("read replay capture fingerprint sample", source)
    })?;
    if replay_capture_fingerprint != capture_fingerprint || replay_capture_sample != capture_sample
    {
        let components =
            fingerprint_sample_mismatch_components(&capture_sample, &replay_capture_sample)
                .join(",");
        return Err(QemuLiveNodeStepGateError::ExactSnapshotInvariant {
            reason: format!(
                "second restore boundary differs: fingerprint {}/{}, differing components [{components}]",
                capture_fingerprint.to_hex(),
                replay_capture_fingerprint.to_hex(),
            ),
        });
    }
    advance_to_busy_ceiling(&mut replay, suffix_icount)?;
    let replay_suffix_fingerprint = replay
        .execution_fingerprint()
        .map_err(|source| QemuLiveNodeStepGateError::ExecutionFingerprint { source })?
        .hash;
    let replay_suffix_sample = replay.fingerprint_sample().map_err(|source| {
        QemuLiveNodeStepGateError::node_op("read replay suffix fingerprint sample", source)
    })?;
    let replay_oracle_pair_match = replay_suffix_fingerprint == oracle_suffix_fingerprint
        && replay_suffix_sample == oracle_suffix_sample
        && replay_suffix_fingerprint == suffix_fingerprint
        && replay_suffix_sample == restored_suffix_sample;
    if !replay_oracle_pair_match {
        let components =
            fingerprint_sample_mismatch_components(&oracle_suffix_sample, &replay_suffix_sample)
                .join(",");
        return Err(QemuLiveNodeStepGateError::ExactSnapshotInvariant {
            reason: format!(
                "second restored suffix fingerprint {} differs from uninterrupted source {}; differing components [{components}]; RR source=({}, {}) first=({}, {}) second=({}, {}); device digests source={:02x?} first={:02x?} second={:02x?}",
                replay_suffix_fingerprint.to_hex(),
                oracle_suffix_fingerprint.to_hex(),
                oracle_suffix_sample.rr_current_vcpu,
                oracle_suffix_sample.rr_position_in_quantum,
                restored_suffix_sample.rr_current_vcpu,
                restored_suffix_sample.rr_position_in_quantum,
                replay_suffix_sample.rr_current_vcpu,
                replay_suffix_sample.rr_position_in_quantum,
                oracle_suffix_sample.device_state_digest,
                restored_suffix_sample.device_state_digest,
                replay_suffix_sample.device_state_digest,
            ),
        });
    }
    replay
        .shutdown_child()
        .map_err(|source| QemuLiveNodeStepGateError::Shutdown { source })?;

    Ok(QemuLiveExactSnapshotReport {
        smp_vcpus: config.smp_vcpus,
        capture_icount,
        restored_icount,
        capture_rr_current_vcpu: capture_sample.rr_current_vcpu,
        capture_rr_position_in_quantum: capture_sample.rr_position_in_quantum,
        capture_rr_switch_quantum: capture_sample.rr_switch_quantum,
        suffix_icount,
        capture_logical_time_offset,
        capture_fingerprint,
        suffix_fingerprint,
        replay_oracle_pair_match,
        old_process_force_crashed: true,
        pending_block_io_captured,
        rr_cursor_negative_control_rejected,
    })
}

fn fingerprint_sample_mismatch_components(
    restored: &crucible_shmem::FingerprintSample,
    captured: &crucible_shmem::FingerprintSample,
) -> Vec<&'static str> {
    let mut components = Vec::new();
    if restored.sample_icount != captured.sample_icount {
        components.push("sample_icount");
    }
    if restored.vcpu_count != captured.vcpu_count {
        components.push("vcpu_count");
    }
    if restored.rr_current_vcpu != captured.rr_current_vcpu {
        components.push("rr_current_vcpu");
    }
    if restored.rr_position_in_quantum != captured.rr_position_in_quantum {
        components.push("rr_position_in_quantum");
    }
    if restored.rr_switch_quantum != captured.rr_switch_quantum {
        components.push("rr_switch_quantum");
    }
    if restored.component_failures != captured.component_failures {
        components.push("component_failures");
    }
    if restored.ram_bytes != captured.ram_bytes || restored.ram_digest != captured.ram_digest {
        components.push("ram");
    }
    if restored.device_state_bytes != captured.device_state_bytes
        || restored.device_state_digest != captured.device_state_digest
    {
        components.push("device_state");
    }
    if restored.device_state_schema_digest != captured.device_state_schema_digest {
        components.push("device_state_schema");
    }
    if restored.vcpus != captured.vcpus {
        components.push("vcpu_registers");
    }
    components
}

fn drive_to_pending_block_boundary(
    node: &mut QemuNode,
    ceiling: u64,
    completion_timeout: Duration,
) -> Result<(u64, bool), QemuLiveNodeStepGateError> {
    // Keep each live QEMU await comfortably below the bounded host timeout.
    // The block workload's configured ceiling is only a search limit; issuing
    // that entire span as one quantum can spend minutes in TCG before the host
    // gets the next deterministic opportunity to inspect real transport state.
    const PENDING_SEARCH_QUANTUM_ICOUNT: u64 = 10_000_000;
    const MAX_PENDING_SEARCH_QUANTA: usize = 8_192;
    let mut last = node
        .current_icount()
        .map_err(|source| QemuLiveNodeStepGateError::node_op("read block search icount", source))?
        .retired;
    for _ in 0..MAX_PENDING_SEARCH_QUANTA {
        let search_ceiling = last
            .saturating_add(PENDING_SEARCH_QUANTUM_ICOUNT)
            .min(ceiling);
        let _ = node
            .advance_to_ceiling(Icount {
                retired: search_ceiling,
            })
            .map_err(|source| {
                QemuLiveNodeStepGateError::node_op("advance toward pending block boundary", source)
            })?;
        let current = node
            .current_icount()
            .map_err(|source| {
                QemuLiveNodeStepGateError::node_op("read pending block boundary", source)
            })?
            .retired;
        let pending = node.has_pending_device_io_for_gate().map_err(|source| {
            QemuLiveNodeStepGateError::node_op("inspect pending block continuation", source)
        })?;
        let device_quiescent = node.checkpoint_device_io_is_quiescent().map_err(|source| {
            QemuLiveNodeStepGateError::node_op("inspect block coroutine quiescence", source)
        })?;
        if pending && device_quiescent {
            let checkpoint_ready = node
                .probe_checkpoint_device_io_for_gate(completion_timeout)
                .map_err(|source| {
                    QemuLiveNodeStepGateError::node_op(
                        "probe pending block checkpoint boundary",
                        source,
                    )
                })?;
            if checkpoint_ready {
                return Ok((current, true));
            }
        }
        // The Apache-side continuation becomes pending as soon as the response
        // is consumed, just before QEMU's block coroutine returns and clears
        // `device_io_active`. Permit another scheduler/main-loop rendezvous in
        // that narrow state, but never expose it as a savevm boundary.
        if current >= ceiling || ((device_quiescent || !pending) && current <= last) {
            break;
        }
        last = current;
    }
    Err(QemuLiveNodeStepGateError::ExactSnapshotInvariant {
        reason: format!(
            "no quiescent production block durability continuation was observed before ceiling {ceiling}"
        ),
    })
}

/// Advances the uninterrupted oracle beyond capture, crossing a retained idle timer if needed.
fn advance_to_observable_suffix(
    node: &mut QemuNode,
    requested_ceiling: u64,
) -> Result<u64, QemuLiveNodeStepGateError> {
    let initial = node
        .current_icount()
        .map_err(|source| QemuLiveNodeStepGateError::node_op("read pre-suffix icount", source))?
        .retired;
    node.advance_to_ceiling(Icount {
        retired: requested_ceiling,
    })
    .map_err(|source| QemuLiveNodeStepGateError::node_op("advance source suffix", source))?;
    let mut idle = node.idle_state().map_err(|source| {
        QemuLiveNodeStepGateError::node_op("read source suffix idle state", source)
    })?;
    if idle.current_icount.retired > initial {
        return Ok(idle.current_icount.retired);
    }

    let deadline = idle.next_deadline.ok_or_else(|| {
        QemuLiveNodeStepGateError::ExactSnapshotInvariant {
            reason: format!(
                "source suffix made no progress from {initial} toward {requested_ceiling} without publishing an idle deadline"
            ),
        }
    })?;
    if deadline.retired <= requested_ceiling {
        return Err(QemuLiveNodeStepGateError::ExactSnapshotInvariant {
            reason: format!(
                "source suffix stalled at {initial} despite due idle deadline {} before requested ceiling {requested_ceiling}",
                deadline.retired
            ),
        });
    }

    node.advance_to_ceiling(deadline).map_err(|source| {
        QemuLiveNodeStepGateError::node_op("advance source suffix to idle deadline", source)
    })?;
    idle = node.idle_state().map_err(|source| {
        QemuLiveNodeStepGateError::node_op("read source post-deadline idle state", source)
    })?;
    if idle.current_icount.retired <= initial {
        return Err(QemuLiveNodeStepGateError::ExactSnapshotInvariant {
            reason: format!(
                "source suffix did not cross idle deadline {} from capture coordinate {initial}",
                deadline.retired
            ),
        });
    }
    Ok(idle.current_icount.retired)
}

fn exact_gate_checkpoint(node: &NodeId, icount: u64, block: bool) -> Checkpoint {
    let identity = ContentHash::from_canonical_material(
        "crucible.qemu.live-exact-snapshot-gate.v1",
        &format!("node={}\nicount={icount}\nblock={block}", node.name),
    );
    let mut checkpoint = Checkpoint::new(identity, identity, CheckpointKind::Fat);
    checkpoint.virtual_time = VirtualTime { ticks: icount };
    checkpoint
        .node_icounts
        .insert(node.clone(), Icount { retired: icount });
    checkpoint
}

fn copy_exact_gate_artifact(
    source_path: &Path,
    destination_path: &Path,
) -> Result<(), QemuLiveNodeStepGateError> {
    fs::copy(source_path, destination_path).map_err(|source| {
        QemuLiveNodeStepGateError::SnapshotArtifactCopy {
            source_path: source_path.to_path_buf(),
            destination_path: destination_path.to_path_buf(),
            source,
        }
    })?;
    Ok(())
}

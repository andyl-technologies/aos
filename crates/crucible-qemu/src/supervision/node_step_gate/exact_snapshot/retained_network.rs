//! Durable retained-network exact-snapshot certification.

use super::*;
use std::io::Write as _;

/// Evidence that a genuinely retained frame survived a fresh QEMU process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuLiveRetainedNetworkSnapshotReport {
    /// Exact boot boundary at which QEMU reported backpressure.
    pub capture_icount: u64,
    /// Canonical retained frame identity preserved by the snapshot.
    pub retained_frame: crucible_shmem::FrameDeliveryKey,
    /// Delivery-attempt count captured and restored with the frame.
    pub restored_delivery_attempts: u32,
    /// First retry deadline observed unchanged before and attempted exactly at.
    pub first_retry_icount: u64,
    /// Whether the restored guest userspace acknowledged that exact payload.
    pub guest_acknowledgement_seen: bool,
    /// Retired-instruction coordinate of the unique post-restore acknowledgement.
    pub guest_ack_emit_icount: u64,
    /// Guest TX sequence of the unique post-restore acknowledgement.
    pub guest_ack_sequence: u64,
    /// Whether the frame left canonical shared memory after guest acceptance.
    pub retained_frame_consumed: bool,
    /// Whether the source QEMU was force-crashed before the restore launch.
    pub source_process_force_crashed: bool,
    /// Whether Apache continuation state crossed the durable canonical codec.
    pub durable_envelope_round_trip: bool,
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
    const CAPTURE_ICOUNT: u64 = 3_000_000_000;
    const DRIVE_CHUNK_ICOUNT: u64 = 250_000_000;

    if frame_payload.is_empty()
        || guest_ack_payload
            != crate::supervision::network_io_servicer::LIVE_NETWORK_BACKPRESSURE_ACK_PAYLOAD
        || completion_ceiling <= 1
    {
        return Err(QemuLiveNodeStepGateError::ExactSnapshotInvariant {
            reason: String::from(
                "retained-network exact gate requires payloads and a future ceiling",
            ),
        });
    }

    let capture_directory = config.run_directory.join("retained-network-capture");
    let restore_directory = config.run_directory.join("retained-network-restore");
    fs::create_dir_all(&capture_directory).map_err(|source| {
        QemuLiveNodeStepGateError::PrepareRunDirectory {
            path: capture_directory.clone(),
            source,
        }
    })?;

    let capture_config = config
        .clone()
        .with_boot_network_backpressure_capture_at(frame_payload.to_vec(), CAPTURE_ICOUNT);
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
    let (retained_frame, source_attempts, source_last_attempt_icount) =
        retained_transport_head(&source_transport, frame_payload)?;
    eprintln!("crucible-live-network-io phase=retained-capture status=frame-retained");

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
    reject_pending_backpressure_ack(
        "captured source continuation",
        &snapshot.node_continuation().pending_network_outputs,
        guest_ack_payload,
    )?;
    let envelope_path = restore_directory.join("crucible-retained-network-snapshot.cbor");
    let envelope = snapshot.to_canonical_bytes().map_err(|error| {
        QemuLiveNodeStepGateError::ExactSnapshotInvariant {
            reason: format!("encode retained canonical snapshot envelope failed: {error}"),
        }
    })?;
    persist_snapshot_closure(
        &capture_directory.join(crate::DEFAULT_VMSTATE_FILE_NAME),
        &restore_directory,
        &envelope,
    )?;
    source.force_crash_and_reap_for_gate().map_err(|error| {
        QemuLiveNodeStepGateError::node_op("force crash retained network source", error)
    })?;
    eprintln!("crucible-live-network-io phase=retained-capture status=durably-published");
    drop(source);
    drop(snapshot);

    let persisted_envelope = fs::read(&envelope_path).map_err(|source| {
        QemuLiveNodeStepGateError::SnapshotEnvelopeIo {
            path: envelope_path.clone(),
            source,
        }
    })?;
    let restored_snapshot = crate::QemuVmSnapshot::from_canonical_bytes(&persisted_envelope)
        .map_err(|error| QemuLiveNodeStepGateError::ExactSnapshotInvariant {
            reason: format!("decode persisted canonical snapshot envelope failed: {error}"),
        })?;
    if restored_snapshot.to_canonical_bytes().ok().as_deref() != Some(envelope.as_slice()) {
        return Err(QemuLiveNodeStepGateError::ExactSnapshotInvariant {
            reason: String::from("persisted retained snapshot envelope was not byte-canonical"),
        });
    }
    reject_pending_backpressure_ack(
        "persisted continuation",
        &restored_snapshot
            .node_continuation()
            .pending_network_outputs,
        guest_ack_payload,
    )?;
    drop(envelope);
    drop(persisted_envelope);

    let restore_config = capture_config
        .clone()
        .with_run_directory(&restore_directory);
    let mut restored = launch_qemu_live_node_exact_snapshot(
        &restore_config,
        &restore_directory,
        GATE_NODE,
        GATE_ROUTER,
        "retained-network-restore",
        &restored_snapshot,
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
    let (restored_frame, restored_attempts, restored_last_attempt_icount) =
        retained_transport_head(&restored_transport, frame_payload)?;
    if restored_icount != CAPTURE_ICOUNT
        || restored_frame != retained_frame
        || restored_attempts != source_attempts
        || restored_last_attempt_icount != source_last_attempt_icount
    {
        return Err(QemuLiveNodeStepGateError::ExactSnapshotInvariant {
            reason: format!(
                "fresh retained restore changed boundary/state: icount={restored_icount}/{CAPTURE_ICOUNT}, frame={restored_frame:?}/{retained_frame:?}, attempts={restored_attempts}/{source_attempts}, last_attempt={restored_last_attempt_icount}/{source_last_attempt_icount}"
            ),
        });
    }
    eprintln!("crucible-live-network-io phase=retained-restore status=state-verified");

    let first_retry_icount = restored_last_attempt_icount
        .checked_add(crucible_shmem::FRAME_DELIVERY_RETRY_INTERVAL_ICOUNT)
        .ok_or_else(|| QemuLiveNodeStepGateError::ExactSnapshotInvariant {
            reason: String::from("restored retained retry coordinate overflowed u64"),
        })?;
    let before_retry = first_retry_icount.checked_sub(1).ok_or_else(|| {
        QemuLiveNodeStepGateError::ExactSnapshotInvariant {
            reason: String::from("restored retained retry has no preceding boundary"),
        }
    })?;
    restored
        .advance_to_ceiling(Icount {
            retired: before_retry,
        })
        .map_err(|error| {
            QemuLiveNodeStepGateError::node_op("advance restored pre-retry boundary", error)
        })?;
    let pre_retry_icount = restored
        .current_icount()
        .map_err(|error| {
            QemuLiveNodeStepGateError::node_op("read restored pre-retry boundary", error)
        })?
        .retired;
    let pre_retry_transport =
        restored
            .checkpoint_network_transport_for_gate()
            .map_err(|error| {
                QemuLiveNodeStepGateError::node_op("inspect restored pre-retry transport", error)
            })?;
    let pre_retry_unchanged = pre_retry_transport.inbound.frames.iter().any(|frame| {
        frame.delivery_key() == retained_frame
            && frame.delivery_state() == Ok(FrameDeliveryState::Retained)
            && frame.delivery_attempts() == restored_attempts
            && frame.last_delivery_attempt_icount() == restored_last_attempt_icount
    });
    if pre_retry_icount != before_retry || !pre_retry_unchanged {
        return Err(QemuLiveNodeStepGateError::ExactSnapshotInvariant {
            reason: format!(
                "restored retained frame changed before retry: icount={pre_retry_icount}/{before_retry}, inbound={:?}",
                pre_retry_transport.inbound.frames
            ),
        });
    }

    restored
        .advance_to_ceiling(Icount {
            retired: first_retry_icount,
        })
        .map_err(|error| {
            QemuLiveNodeStepGateError::node_op("advance restored exact retry boundary", error)
        })?;
    let exact_retry_icount = restored
        .current_icount()
        .map_err(|error| {
            QemuLiveNodeStepGateError::node_op("read restored exact retry boundary", error)
        })?
        .retired;
    let exact_retry_transport =
        restored
            .checkpoint_network_transport_for_gate()
            .map_err(|error| {
                QemuLiveNodeStepGateError::node_op("inspect restored exact retry transport", error)
            })?;
    let retry_state_valid = exact_retry_transport
        .inbound
        .frames
        .iter()
        .find(|frame| frame.delivery_key() == retained_frame)
        .is_none_or(|frame| {
            frame.delivery_state() == Ok(FrameDeliveryState::Retained)
                && frame.delivery_attempts() == restored_attempts.saturating_add(1)
                && frame.last_delivery_attempt_icount() == first_retry_icount
        });
    if exact_retry_icount != first_retry_icount || !retry_state_valid {
        return Err(QemuLiveNodeStepGateError::ExactSnapshotInvariant {
            reason: format!(
                "restored retained frame missed exact retry: icount={exact_retry_icount}/{first_retry_icount}, inbound={:?}",
                exact_retry_transport.inbound.frames
            ),
        });
    }

    let remaining_retry_steps =
        u64::from(crucible_shmem::MAX_FRAME_DELIVERY_ATTEMPTS.saturating_sub(restored_attempts));
    let retry_capacity_ceiling = restored_last_attempt_icount.saturating_add(
        remaining_retry_steps.saturating_mul(crucible_shmem::FRAME_DELIVERY_RETRY_INTERVAL_ICOUNT),
    );
    if completion_ceiling > retry_capacity_ceiling {
        return Err(QemuLiveNodeStepGateError::ExactSnapshotInvariant {
            reason: format!(
                "retained completion ceiling {completion_ceiling} exceeds retry capacity {retry_capacity_ceiling}"
            ),
        });
    }
    // The first exact retry above proves the canonical deadline and state
    // transition directly. Drive the remaining finite retry chain through the
    // public production node-set scheduler path. That path reissues each
    // delivery-capped quantum under MAX_FRAME_DELIVERY_ATTEMPTS. Chunking only
    // the caller's requested ceiling lets the gate observe the exact guest ACK
    // without executing the remainder of the 4B-icount boot horizon after the
    // proof is complete; it does not skip or coalesce any 4M-icount retry.
    // Taking a full control-plane transport checkpoint after every retry would
    // add hundreds of unrelated snapshot handshakes before Linux enables RX.
    let mut restored_nodes = QemuNodeSet::new();
    if restored_nodes.insert(identity.clone(), restored).is_some() {
        return Err(QemuLiveNodeStepGateError::ExactSnapshotInvariant {
            reason: String::from("retained restore node identity collided"),
        });
    }
    let mut guest_ack_identity = None;
    loop {
        let current = crucible::SimulationBackend::node_now(&restored_nodes, &identity)
            .map_err(|error| QemuLiveNodeStepGateError::ExactSnapshotInvariant {
                reason: format!("read production retained retry coordinate failed: {error}"),
            })?
            .ticks;
        if current >= completion_ceiling {
            break;
        }
        let target = current
            .saturating_add(DRIVE_CHUNK_ICOUNT)
            .min(completion_ceiling);
        crucible::SimulationBackend::step_node_to(
            &mut restored_nodes,
            &identity,
            VirtualTime { ticks: target },
        )
        .map_err(|error| QemuLiveNodeStepGateError::ExactSnapshotInvariant {
            reason: format!("drive production retained retry chain failed: {error}"),
        })?;
        let outputs = crucible::SimulationBackend::drain_network_outputs(&mut restored_nodes)
            .map_err(|error| QemuLiveNodeStepGateError::ExactSnapshotInvariant {
                reason: format!("drain restored guest network outputs failed: {error}"),
            })?;
        for frame in outputs
            .iter()
            .filter(|frame| is_backpressure_ack_payload(&frame.payload, guest_ack_payload))
        {
            if frame.emit_icount.retired < first_retry_icount {
                return Err(QemuLiveNodeStepGateError::ExactSnapshotInvariant {
                    reason: format!(
                        "restored backpressure acknowledgement was emitted before the exact retry: emit_icount={}, retry_icount={}, sequence={}",
                        frame.emit_icount.retired, first_retry_icount, frame.sequence
                    ),
                });
            }
            let identity = (frame.emit_icount.retired, frame.sequence);
            if guest_ack_identity.replace(identity).is_some() {
                return Err(QemuLiveNodeStepGateError::ExactSnapshotInvariant {
                    reason: format!(
                        "restored retry emitted more than one backpressure acknowledgement; latest={identity:?}"
                    ),
                });
            }
        }
        let guest_acknowledgement_seen = guest_ack_identity.is_some();
        eprintln!(
            "crucible-live-network-io phase=retained-restore status=retry-progress icount={target} guest_ack={guest_acknowledgement_seen}"
        );
        if guest_acknowledgement_seen {
            break;
        }
    }
    let guest_acknowledgement_seen = guest_ack_identity.is_some();
    let mut restored = restored_nodes.take(&identity).ok_or_else(|| {
        QemuLiveNodeStepGateError::ExactSnapshotInvariant {
            reason: String::from("production retry chain lost the retained restore node"),
        }
    })?;
    let final_transport = restored
        .checkpoint_network_transport_for_gate()
        .map_err(|error| {
            QemuLiveNodeStepGateError::node_op("inspect retained retry completion", error)
        })?;
    let retained_frame_consumed = !final_transport
        .inbound
        .frames
        .iter()
        .any(|frame| frame.delivery_key() == retained_frame);
    if guest_ack_identity.is_none() || !retained_frame_consumed {
        let final_icount = restored
            .current_icount()
            .map_err(|error| {
                QemuLiveNodeStepGateError::node_op("read failed retained retry icount", error)
            })?
            .retired;
        return Err(QemuLiveNodeStepGateError::ExactSnapshotInvariant {
            reason: format!(
                "fresh retained retry incomplete at icount {final_icount}/{completion_ceiling}: guest_ack={guest_acknowledgement_seen}, consumed={retained_frame_consumed}, inbound={:?}",
                final_transport.inbound.frames,
            ),
        });
    }
    eprintln!("crucible-live-network-io phase=retained-restore status=guest-acknowledged");
    let (guest_ack_emit_icount, guest_ack_sequence) =
        guest_ack_identity.ok_or_else(|| QemuLiveNodeStepGateError::ExactSnapshotInvariant {
            reason: String::from("restored retry lost its acknowledged frame identity"),
        })?;
    restored
        .shutdown_child()
        .map_err(|error| QemuLiveNodeStepGateError::Shutdown { source: error })?;

    Ok(QemuLiveRetainedNetworkSnapshotReport {
        capture_icount: CAPTURE_ICOUNT,
        retained_frame,
        restored_delivery_attempts: restored_attempts,
        first_retry_icount,
        guest_acknowledgement_seen: true,
        guest_ack_emit_icount,
        guest_ack_sequence,
        retained_frame_consumed,
        source_process_force_crashed: true,
        durable_envelope_round_trip: true,
    })
}

fn is_backpressure_ack_payload(payload: &[u8], guest_ack_payload: &[u8]) -> bool {
    guest_ack_payload
        == crate::supervision::network_io_servicer::LIVE_NETWORK_BACKPRESSURE_ACK_PAYLOAD
        && crate::supervision::network_io_servicer::is_live_network_backpressure_ack(payload)
}

fn reject_pending_backpressure_ack(
    role: &str,
    outputs: &[crate::QemuNodeEmittedFrame],
    guest_ack_payload: &[u8],
) -> Result<(), QemuLiveNodeStepGateError> {
    if let Some(frame) = outputs
        .iter()
        .find(|frame| is_backpressure_ack_payload(&frame.payload, guest_ack_payload))
    {
        return Err(QemuLiveNodeStepGateError::ExactSnapshotInvariant {
            reason: format!(
                "{role} already contained a backpressure acknowledgement at icount {} sequence {}; restored retry causality would be ambiguous",
                frame.emit_icount.retired, frame.sequence
            ),
        });
    }
    Ok(())
}

fn persist_snapshot_closure(
    vmstate_source: &Path,
    destination: &Path,
    envelope: &[u8],
) -> Result<(), QemuLiveNodeStepGateError> {
    let parent =
        destination
            .parent()
            .ok_or_else(|| QemuLiveNodeStepGateError::ExactSnapshotInvariant {
                reason: format!(
                    "retained checkpoint directory {} has no parent",
                    destination.display()
                ),
            })?;
    let file_name = destination.file_name().ok_or_else(|| {
        QemuLiveNodeStepGateError::ExactSnapshotInvariant {
            reason: format!(
                "retained checkpoint directory {} has no file name",
                destination.display()
            ),
        }
    })?;
    let staging = parent.join(format!(".{}.staging", file_name.to_string_lossy()));
    fs::create_dir(&staging).map_err(|source| QemuLiveNodeStepGateError::PrepareRunDirectory {
        path: staging.clone(),
        source,
    })?;

    let envelope_path = staging.join("crucible-retained-network-snapshot.cbor");
    let mut envelope_file = fs::File::create(&envelope_path).map_err(|source| {
        QemuLiveNodeStepGateError::SnapshotEnvelopeIo {
            path: envelope_path.clone(),
            source,
        }
    })?;
    envelope_file
        .write_all(envelope)
        .and_then(|()| envelope_file.sync_all())
        .map_err(|source| QemuLiveNodeStepGateError::SnapshotEnvelopeIo {
            path: envelope_path,
            source,
        })?;

    let vmstate_path = staging.join(crate::DEFAULT_VMSTATE_FILE_NAME);
    copy_exact_gate_artifact(vmstate_source, &vmstate_path)?;
    fs::File::open(&staging)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| QemuLiveNodeStepGateError::SnapshotEnvelopeIo {
            path: staging.clone(),
            source,
        })?;
    fs::rename(&staging, destination).map_err(|source| {
        QemuLiveNodeStepGateError::SnapshotEnvelopeIo {
            path: destination.to_path_buf(),
            source,
        }
    })?;
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| QemuLiveNodeStepGateError::SnapshotEnvelopeIo {
            path: parent.to_path_buf(),
            source,
        })
}

fn retained_transport_head(
    checkpoint: &crate::QemuNetworkTransportCheckpoint,
    expected_payload: &[u8],
) -> Result<(crucible_shmem::FrameDeliveryKey, u32, u64), QemuLiveNodeStepGateError> {
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
    Ok((
        frame.delivery_key(),
        frame.delivery_attempts(),
        frame.last_delivery_attempt_icount(),
    ))
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

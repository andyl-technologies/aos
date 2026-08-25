//! Real-product guest-selectable exact-snapshot certification.

use super::*;
use crucible::{ObservableEventPayload, SimulationBackend};
use crucible_protocol::SelectionReply;
use crucible_protocol::selectable_catalog_plan::{
    SelectableCatalogPlan, SelectablePlanPendingRequest, SelectablePlanPhase,
};
use std::io::Write as _;

const SEARCH_QUANTUM_ICOUNT: u64 = 100_000_000;
const MAX_SEARCH_QUANTA: usize = 1_024;
const SNAPSHOT_ENVELOPE_FILE: &str = "crucible-selectable-snapshot.cbor";
const SELECTABLE_PLAN_FILE: &str = "crucible-selectable-plan.bin";

/// Evidence that a product guest's pending choice survived a fresh QEMU process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuLiveSelectableProductSnapshotReport {
    /// Exact instruction coordinate of the first pending product choice.
    pub capture_icount: u64,
    /// Identifier of the discrete choice captured before its reply.
    pub first_selectable: String,
    /// Identifier of the integral choice reached after the first reply.
    pub second_selectable: String,
    /// Whether the restored process exposed the byte-identical pending token.
    pub restored_pending_exact: bool,
    /// Whether snapshot metadata and selectable plan crossed canonical codecs.
    pub durable_envelope_round_trip: bool,
    /// Total completed product choices in the final mirrored plan.
    pub completed_requests: u64,
    /// Instruction coordinate at which the selected product behavior emitted traffic.
    pub selected_frame_icount: u64,
    /// Whether the source process was force-crashed before restore.
    pub source_process_force_crashed: bool,
    /// Whether the restored process shut down and reaped without leakage.
    pub orderly_child_exit: bool,
}

/// Restores one real product guest while its first selectable request is pending.
///
/// The configured cold catalog is reconciled against guest registrations. The
/// gate captures VMState while the first request owns its zero-filled reply
/// reservation, persists both the ordinary exact-snapshot envelope and the same
/// canonical catalog-plan sidecar used by the production checkpoint manifest,
/// kills the source process, and restores both into a fresh QEMU/plugin process.
/// It then supplies two exact replies and requires guest-originated network
/// traffic containing `selected_product_payload`.
///
/// # Errors
///
/// Returns [`QemuLiveNodeStepGateError`] when the launch profile lacks a
/// selectable catalog, either expected request is absent or reordered, the
/// checkpoint pair is not canonical, the restored token differs, reply
/// delivery fails, selected product traffic is absent, or teardown leaks.
pub fn run_qemu_live_selectable_product_snapshot_gate(
    config: &QemuLiveNodeStepGateConfig,
    first_selectable: &str,
    first_reply: &SelectionReply,
    second_selectable: &str,
    second_reply: &SelectionReply,
    selected_product_payload: &[u8],
    completion_ceiling: u64,
) -> Result<QemuLiveSelectableProductSnapshotReport, QemuLiveNodeStepGateError> {
    if first_selectable.is_empty()
        || second_selectable.is_empty()
        || first_selectable == second_selectable
        || selected_product_payload.is_empty()
    {
        return Err(invariant(
            "selectable product gate requires two distinct identifiers and a payload",
        ));
    }
    let cold_plan = config
        .selectable_catalog_plan()
        .ok_or_else(|| invariant("selectable product gate requires a catalog plan"))?;
    if cold_plan.continuation().phase() != SelectablePlanPhase::Registering
        || cold_plan.continuation().pending().is_some()
    {
        return Err(invariant(
            "selectable product gate requires a cold registering catalog",
        ));
    }

    let capture_directory = config.run_directory.join("selectable-capture");
    let restore_directory = config.run_directory.join("selectable-restore");
    for directory in [&capture_directory, &restore_directory] {
        fs::create_dir_all(directory).map_err(|source| {
            QemuLiveNodeStepGateError::PrepareRunDirectory {
                path: directory.clone(),
                source,
            }
        })?;
    }

    let identity = node_id(GATE_NODE);
    let mut source = build_live_node(
        config,
        &capture_directory,
        QemuLiveNodeIdentity {
            node: GATE_NODE,
            router: GATE_ROUTER,
            crash_detector: "selectable-product-capture",
        },
        None,
        true,
    )?;
    let first_pending = drive_until_pending(
        &mut source,
        first_selectable,
        completion_ceiling,
        "discover first product selectable",
    )?;
    if first_reply.sequence() != first_pending.request().sequence() {
        return Err(invariant(format!(
            "first reply sequence {} differs from pending sequence {}",
            first_reply.sequence(),
            first_pending.request().sequence()
        )));
    }
    if !source.selectable_reply_is_checkpoint_quiescent() {
        return Err(invariant(
            "first pending selectable unexpectedly had a queued reply",
        ));
    }
    let capture_icount = first_pending.icount();
    let observed_icount = source
        .current_icount()
        .map_err(|source| QemuLiveNodeStepGateError::node_op("read selectable capture", source))?
        .retired;
    if observed_icount != capture_icount {
        return Err(invariant(format!(
            "pending selectable icount {capture_icount} differs from node boundary {observed_icount}"
        )));
    }

    let checkpoint = exact_gate_checkpoint(&identity, capture_icount, false);
    let snapshot = source
        .capture_exact_snapshot_paused(&identity, checkpoint)
        .map_err(|source| {
            QemuLiveNodeStepGateError::node_op("capture pending selectable snapshot", source)
        })?;
    let captured_plan = source
        .selectable_catalog_plan()
        .ok_or_else(|| invariant("captured node lost its selectable catalog"))?;
    if captured_plan.continuation().pending() != Some(&first_pending) {
        return Err(invariant(
            "captured selectable plan differs from the drained pending request",
        ));
    }

    let snapshot_bytes = snapshot.to_canonical_bytes().map_err(|error| {
        invariant(format!(
            "encode selectable snapshot envelope failed: {error}"
        ))
    })?;
    let plan_bytes = captured_plan
        .encode()
        .map_err(|error| invariant(format!("encode selectable catalog plan failed: {error}")))?;
    copy_exact_gate_artifact(
        &capture_directory.join(crate::DEFAULT_VMSTATE_FILE_NAME),
        &restore_directory.join(crate::DEFAULT_VMSTATE_FILE_NAME),
    )?;
    persist_bytes(
        &restore_directory.join(SNAPSHOT_ENVELOPE_FILE),
        &snapshot_bytes,
    )?;
    persist_bytes(&restore_directory.join(SELECTABLE_PLAN_FILE), &plan_bytes)?;
    source.force_crash_and_reap_for_gate().map_err(|source| {
        QemuLiveNodeStepGateError::node_op("force crash selectable source", source)
    })?;
    drop(source);
    drop(snapshot);

    let restored_snapshot_bytes = read_persisted(
        &restore_directory.join(SNAPSHOT_ENVELOPE_FILE),
        "read selectable snapshot envelope",
    )?;
    let restored_plan_bytes = read_persisted(
        &restore_directory.join(SELECTABLE_PLAN_FILE),
        "read selectable catalog plan",
    )?;
    let restored_snapshot = crate::QemuVmSnapshot::from_canonical_bytes(&restored_snapshot_bytes)
        .map_err(|error| {
        invariant(format!(
            "decode selectable snapshot envelope failed: {error}"
        ))
    })?;
    let restored_plan = SelectableCatalogPlan::decode(&restored_plan_bytes)
        .map_err(|error| invariant(format!("decode selectable catalog plan failed: {error}")))?;
    let durable_envelope_round_trip = restored_snapshot
        .to_canonical_bytes()
        .is_ok_and(|bytes| bytes == snapshot_bytes)
        && restored_plan
            .encode()
            .is_ok_and(|bytes| bytes == plan_bytes);
    if !durable_envelope_round_trip {
        return Err(invariant(
            "persisted selectable checkpoint pair was not byte-canonical",
        ));
    }

    let restore_config = config
        .clone()
        .with_run_directory(&restore_directory)
        .with_selectable_catalog_plan(restored_plan);
    let mut restored = launch_qemu_live_node_exact_snapshot(
        &restore_config,
        &restore_directory,
        GATE_NODE,
        GATE_ROUTER,
        "selectable-product-restore",
        &restored_snapshot,
    )?;
    let restored_pending = take_one_pending(
        &mut restored,
        first_selectable,
        "inspect restored product selectable",
    )?;
    let restored_pending_exact = restored_pending == first_pending;
    if !restored_pending_exact {
        return Err(invariant(
            "fresh process restored a different pending selectable token",
        ));
    }

    restored
        .enqueue_selectable_reply(&restored_pending, first_reply)
        .map_err(|source| {
            QemuLiveNodeStepGateError::node_op("reply to restored product selectable", source)
        })?;
    let second_pending = drive_until_pending(
        &mut restored,
        second_selectable,
        completion_ceiling,
        "discover second product selectable",
    )?;
    if second_reply.sequence() != second_pending.request().sequence() {
        return Err(invariant(format!(
            "second reply sequence {} differs from pending sequence {}",
            second_reply.sequence(),
            second_pending.request().sequence()
        )));
    }
    restored
        .enqueue_selectable_reply(&second_pending, second_reply)
        .map_err(|source| {
            QemuLiveNodeStepGateError::node_op("reply to integral product selectable", source)
        })?;

    let selected_frame_icount =
        drive_until_product_frame(&mut restored, selected_product_payload, completion_ceiling)?;
    let final_plan = restored
        .selectable_catalog_plan()
        .ok_or_else(|| invariant("restored node lost its selectable catalog"))?;
    let completed_requests = final_plan.continuation().total_completed_requests();
    if final_plan.continuation().phase() != SelectablePlanPhase::Frozen
        || final_plan.continuation().pending().is_some()
        || completed_requests != 2
        || !restored.selectable_reply_is_checkpoint_quiescent()
    {
        return Err(invariant(format!(
            "final selectable continuation is not complete: phase={:?}, pending={}, completed={completed_requests}, reply_quiescent={}",
            final_plan.continuation().phase(),
            final_plan.continuation().pending().is_some(),
            restored.selectable_reply_is_checkpoint_quiescent(),
        )));
    }
    let shutdown = restored
        .shutdown_child()
        .map_err(|source| QemuLiveNodeStepGateError::Shutdown { source })?;
    let orderly_child_exit = shutdown.reaped && !shutdown.leaked;
    if !orderly_child_exit {
        return Err(invariant("restored selectable guest did not reap cleanly"));
    }

    Ok(QemuLiveSelectableProductSnapshotReport {
        capture_icount,
        first_selectable: first_selectable.to_owned(),
        second_selectable: second_selectable.to_owned(),
        restored_pending_exact,
        durable_envelope_round_trip,
        completed_requests,
        selected_frame_icount,
        source_process_force_crashed: true,
        orderly_child_exit,
    })
}

fn drive_until_pending(
    node: &mut QemuNode,
    expected_selectable: &str,
    completion_ceiling: u64,
    operation: &'static str,
) -> Result<SelectablePlanPendingRequest, QemuLiveNodeStepGateError> {
    if let Some(pending) = optional_pending(node, expected_selectable, operation)? {
        return Ok(pending);
    }
    for _ in 0..MAX_SEARCH_QUANTA {
        let (current, target) = next_search_target(node, completion_ceiling, operation)?;
        if current >= completion_ceiling {
            break;
        }
        node.advance_to_ceiling(Icount { retired: target })
            .map_err(|source| QemuLiveNodeStepGateError::node_op(operation, source))?;
        reject_guest_selectable_diagnostic(node, operation)?;
        if let Some(pending) = optional_pending(node, expected_selectable, operation)? {
            return Ok(pending);
        }
    }
    let console_tail = diagnostic_console_tail(node)?;
    let continuation = node
        .selectable_catalog_plan()
        .ok_or_else(|| invariant(format!("{operation} lost the selectable catalog")))?
        .continuation()
        .clone();
    Err(invariant(format!(
        "{operation} did not reach `{expected_selectable}` before icount {completion_ceiling}: phase={:?}, registered={:?}, registration_watermark={:?}, completed={}, pending={}, console_tail={console_tail:?}",
        continuation.phase(),
        continuation.registered(),
        continuation.last_registration_sequence(),
        continuation.total_completed_requests(),
        continuation.pending().is_some(),
    )))
}

fn diagnostic_console_tail(node: &mut QemuNode) -> Result<String, QemuLiveNodeStepGateError> {
    const TAIL_BYTES: usize = 4_096;
    let events = SimulationBackend::drain_observable_events(node).map_err(|source| {
        invariant(format!(
            "drain product guest console diagnostics failed: {source}"
        ))
    })?;
    let mut console = Vec::new();
    for event in events {
        if let ObservableEventPayload::ConsoleOutput { bytes, .. } = event.payload() {
            console.extend_from_slice(bytes);
        }
    }
    let start = console.len().saturating_sub(TAIL_BYTES);
    Ok(String::from_utf8_lossy(&console[start..]).into_owned())
}

fn reject_guest_selectable_diagnostic(
    node: &mut QemuNode,
    operation: &'static str,
) -> Result<(), QemuLiveNodeStepGateError> {
    const PREFIX: &[u8] = b"crucible-selectable-error-";
    let frames = SimulationBackend::drain_network_outputs(node).map_err(|source| {
        invariant(format!(
            "drain product guest diagnostics during {operation} failed: {source}"
        ))
    })?;
    for frame in frames {
        if let Some(offset) = frame
            .payload
            .windows(PREFIX.len())
            .position(|window| window == PREFIX)
        {
            let suffix = &frame.payload[offset + PREFIX.len()..];
            let end = suffix
                .iter()
                .position(|byte| !byte.is_ascii_digit())
                .unwrap_or(suffix.len());
            let stage = std::str::from_utf8(&suffix[..end]).unwrap_or("unknown");
            return Err(invariant(format!(
                "product guest failed selectable stage {stage} during {operation}"
            )));
        }
    }
    Ok(())
}

fn take_one_pending(
    node: &mut QemuNode,
    expected_selectable: &str,
    operation: &'static str,
) -> Result<SelectablePlanPendingRequest, QemuLiveNodeStepGateError> {
    optional_pending(node, expected_selectable, operation)?.ok_or_else(|| {
        invariant(format!(
            "{operation} did not expose pending `{expected_selectable}`"
        ))
    })
}

fn optional_pending(
    node: &mut QemuNode,
    expected_selectable: &str,
    operation: &'static str,
) -> Result<Option<SelectablePlanPendingRequest>, QemuLiveNodeStepGateError> {
    let mut pending = node
        .drain_pending_selectable_requests()
        .map_err(|source| QemuLiveNodeStepGateError::node_op(operation, source))?;
    if pending.len() > 1 {
        return Err(invariant(format!(
            "{operation} exposed {} pending requests instead of at most one",
            pending.len()
        )));
    }
    let pending = pending.pop();
    if let Some(pending) = &pending
        && pending.request().selectable_id() != expected_selectable
    {
        return Err(invariant(format!(
            "{operation} reached `{}` instead of `{expected_selectable}`",
            pending.request().selectable_id()
        )));
    }
    Ok(pending)
}

fn drive_until_product_frame(
    node: &mut QemuNode,
    selected_product_payload: &[u8],
    completion_ceiling: u64,
) -> Result<u64, QemuLiveNodeStepGateError> {
    for _ in 0..MAX_SEARCH_QUANTA {
        let (current, target) =
            next_search_target(node, completion_ceiling, "read selected product boundary")?;
        if current >= completion_ceiling {
            break;
        }
        node.advance_to_ceiling(Icount { retired: target })
            .map_err(|source| {
                QemuLiveNodeStepGateError::node_op("advance selected product guest", source)
            })?;
        if !node
            .drain_pending_selectable_requests()
            .map_err(|source| {
                QemuLiveNodeStepGateError::node_op("drain completed product selectables", source)
            })?
            .is_empty()
        {
            return Err(invariant(
                "product guest emitted an unexpected third selectable request",
            ));
        }
        let frames = SimulationBackend::drain_network_outputs(node).map_err(|source| {
            invariant(format!(
                "drain selected product network output failed: {source}"
            ))
        })?;
        if let Some(frame) = frames.into_iter().find(|frame| {
            frame
                .payload
                .windows(selected_product_payload.len())
                .any(|window| window == selected_product_payload)
        }) {
            return Ok(frame.emit_icount.retired);
        }
    }
    Err(invariant(format!(
        "selected product payload was absent before icount {completion_ceiling}"
    )))
}

fn next_search_target(
    node: &mut QemuNode,
    completion_ceiling: u64,
    operation: &'static str,
) -> Result<(u64, u64), QemuLiveNodeStepGateError> {
    let idle = node
        .idle_state()
        .map_err(|source| QemuLiveNodeStepGateError::node_op(operation, source))?;
    let current = idle.current_icount.retired;
    let ordinary = current.saturating_add(SEARCH_QUANTUM_ICOUNT);
    let target = idle
        .next_deadline
        .map_or(ordinary, |deadline| ordinary.max(deadline.retired))
        .min(completion_ceiling);
    Ok((current, target))
}

fn persist_bytes(path: &Path, bytes: &[u8]) -> Result<(), QemuLiveNodeStepGateError> {
    let mut file =
        fs::File::create(path).map_err(|source| QemuLiveNodeStepGateError::SnapshotEnvelopeIo {
            path: path.to_path_buf(),
            source,
        })?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|source| QemuLiveNodeStepGateError::SnapshotEnvelopeIo {
            path: path.to_path_buf(),
            source,
        })?;
    let parent = path
        .parent()
        .ok_or_else(|| invariant(format!("checkpoint path {} has no parent", path.display())))?;
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| QemuLiveNodeStepGateError::SnapshotEnvelopeIo {
            path: parent.to_path_buf(),
            source,
        })
}

fn read_persisted(
    path: &Path,
    _operation: &'static str,
) -> Result<Vec<u8>, QemuLiveNodeStepGateError> {
    fs::read(path).map_err(|source| QemuLiveNodeStepGateError::SnapshotEnvelopeIo {
        path: path.to_path_buf(),
        source,
    })
}

fn invariant(reason: impl Into<String>) -> QemuLiveNodeStepGateError {
    QemuLiveNodeStepGateError::ExactSnapshotInvariant {
        reason: reason.into(),
    }
}

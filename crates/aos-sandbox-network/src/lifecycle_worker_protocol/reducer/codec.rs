//! Canonical bounded binary snapshots for the dormant Network reducer.
//!
//! ```text
//! AOSNLSNP01 | assignment | namespace | kernel | state | resource
//! sequence/floor/anchor | pending? | compact receipts[] | full receipts[]
//! terminal/poison flags | snapshot digest
//! ```
//!
//! Every integer is big-endian, every option and closed union has a one-byte
//! discriminant, and every sequence has a checked `u32` element count.

use aos_sandbox_core::{
    AssignmentEpoch, BrokerAssignment, DesiredGeneration, IncarnationId, ObjectDigest, SandboxId,
};

use super::*;

const MAGIC: &[u8; 10] = b"AOSNLSNP01";
const INTENT_MAGIC: &[u8; 9] = b"AOSNINT01";
const CURRENT_MAGIC: &[u8; 9] = b"AOSNCUR01";
const OBSERVATION_MAGIC: &[u8; 9] = b"AOSNOBS01";

pub(super) fn decode_protected_intent(
    bytes: &[u8],
) -> Result<NetworkLifecycleIntentV1, NetworkLifecycleReducerError> {
    let mut input = Reader::new(bytes);
    if input.array::<9>()? != *INTENT_MAGIC {
        return Err(NetworkLifecycleReducerError::ObservationMismatch);
    }
    let value = decode_intent(&mut input)?;
    input.finish()?;
    Ok(value)
}

pub(super) fn decode_protected_current(
    bytes: &[u8],
) -> Result<ProtectedNetworkLifecycleCurrentV1, NetworkLifecycleReducerError> {
    let mut input = Reader::new(bytes);
    if input.array::<9>()? != *CURRENT_MAGIC {
        return Err(NetworkLifecycleReducerError::ObservationMismatch);
    }
    let value = ProtectedNetworkLifecycleCurrentV1 {
        intent_digest: input.digest()?,
        durable_reducer_digest: input.digest()?,
        fence_digest: input.digest()?,
        kernel_digest: input.digest()?,
        residual: decode_residual(&mut input)?,
        observed_boottime_nanoseconds: input.u64()?,
        observation_ordinal: input.u64()?,
    };
    input.finish()?;
    Ok(value)
}

pub(super) fn decode_protected_observation(
    bytes: &[u8],
) -> Result<ProtectedNetworkLifecycleObservationV1, NetworkLifecycleReducerError> {
    let mut input = Reader::new(bytes);
    if input.array::<9>()? != *OBSERVATION_MAGIC {
        return Err(NetworkLifecycleReducerError::ObservationMismatch);
    }
    let value = decode_observation(&mut input)?;
    input.finish()?;
    Ok(value)
}

pub(super) fn encode_snapshot(
    snapshot: &NetworkLifecycleRecoverySnapshotV1,
) -> Result<Vec<u8>, NetworkLifecycleReducerError> {
    let mut out = Writer::new();
    out.bytes(MAGIC);
    encode_assignment(&mut out, snapshot.assignment);
    encode_namespace(&mut out, snapshot.namespace);
    encode_kernel(&mut out, snapshot.kernel);
    encode_state(&mut out, snapshot.state);
    out.digest(snapshot.resource_digest);
    out.u64(snapshot.highest_sequence);
    out.u64(snapshot.receipt_floor_sequence);
    out.optional_digest(snapshot.receipt_anchor_digest);
    out.optional(snapshot.pending, encode_pending);
    out.sequence(&snapshot.compacted_receipt_index, encode_compacted_receipt)?;
    out.sequence(&snapshot.receipts, encode_receipt)?;
    out.boolean(snapshot.terminal_destroyed);
    out.boolean(snapshot.poisoned);
    out.digest(snapshot.digest);
    if out.overflowed {
        return Err(NetworkLifecycleReducerError::ReceiptHistoryExhausted);
    }
    Ok(out.bytes)
}

pub(super) fn decode_snapshot(
    bytes: &[u8],
) -> Result<NetworkLifecycleRecoverySnapshotV1, NetworkLifecycleReducerError> {
    if bytes.len() > MAXIMUM_RECOVERY_CHECKPOINT_BYTES {
        return Err(NetworkLifecycleReducerError::ObservationMismatch);
    }
    let mut input = Reader::new(bytes);
    if input.array::<10>()? != *MAGIC {
        return Err(NetworkLifecycleReducerError::ObservationMismatch);
    }
    let snapshot = NetworkLifecycleRecoverySnapshotV1 {
        assignment: decode_assignment(&mut input)?,
        namespace: decode_namespace(&mut input)?,
        kernel: decode_kernel(&mut input)?,
        state: decode_state(&mut input)?,
        resource_digest: input.digest()?,
        highest_sequence: input.u64()?,
        receipt_floor_sequence: input.u64()?,
        receipt_anchor_digest: input.optional_digest()?,
        pending: input.optional(decode_pending)?,
        compacted_receipt_index: input
            .sequence(MAXIMUM_COMPACTED_RECEIPTS, decode_compacted_receipt)?,
        receipts: input.sequence(MAXIMUM_RETAINED_RECEIPTS, decode_receipt)?,
        terminal_destroyed: input.boolean()?,
        poisoned: input.boolean()?,
        digest: input.digest()?,
    };
    input.finish()?;
    Ok(snapshot)
}

fn encode_assignment(out: &mut Writer, value: BrokerAssignment) {
    out.bytes(value.sandbox().as_bytes());
    out.bytes(value.incarnation().as_bytes());
    out.u64(value.epoch().get());
    out.u64(value.desired_generation().get());
    out.digest(value.digest());
}

fn decode_assignment(
    input: &mut Reader<'_>,
) -> Result<BrokerAssignment, NetworkLifecycleReducerError> {
    BrokerAssignment::new(
        SandboxId::from_bytes(input.array()?),
        IncarnationId::from_bytes(input.array()?),
        AssignmentEpoch::new(input.u64()?),
        DesiredGeneration::new(input.u64()?),
        input.digest()?,
    )
    .map_err(|_| NetworkLifecycleReducerError::ObservationMismatch)
}

fn encode_namespace(out: &mut Writer, value: NetworkNamespaceIdentityV1) {
    out.bytes(&value.network_handle());
    out.bytes(&value.kernel_boot_id());
    out.u64(value.namespace_device());
    out.u64(value.namespace_inode());
}

fn decode_namespace(
    input: &mut Reader<'_>,
) -> Result<NetworkNamespaceIdentityV1, NetworkLifecycleReducerError> {
    NetworkNamespaceIdentityV1::new(input.array()?, input.array()?, input.u64()?, input.u64()?)
        .map_err(|_| NetworkLifecycleReducerError::ObservationMismatch)
}

fn encode_state(out: &mut Writer, value: NetworkNamespaceObservedStateV1) {
    out.u8(match value.kind() {
        NetworkNamespaceObservedStateKindV1::DefaultDrop => 0,
        NetworkNamespaceObservedStateKindV1::Armed => 1,
        NetworkNamespaceObservedStateKindV1::Fenced => 2,
        NetworkNamespaceObservedStateKindV1::Absent => 3,
    });
    match value.lease() {
        None => out.u8(0),
        Some((digest, generation, deadline)) => {
            out.u8(1);
            out.digest(digest);
            out.u64(generation);
            out.u64(deadline);
        }
    }
}

fn decode_state(
    input: &mut Reader<'_>,
) -> Result<NetworkNamespaceObservedStateV1, NetworkLifecycleReducerError> {
    let kind = input.u8()?;
    let lease = match input.u8()? {
        0 => None,
        1 => Some((input.digest()?, input.u64()?, input.u64()?)),
        _ => return Err(NetworkLifecycleReducerError::ObservationMismatch),
    };
    match (kind, lease) {
        (0, None) => Ok(NetworkNamespaceObservedStateV1::default_drop()),
        (1, Some((digest, generation, deadline))) => {
            NetworkNamespaceObservedStateV1::armed(digest, generation, deadline)
                .map_err(|_| NetworkLifecycleReducerError::ObservationMismatch)
        }
        (2, Some((digest, generation, deadline))) => {
            NetworkNamespaceObservedStateV1::fenced(digest, generation, deadline)
                .map_err(|_| NetworkLifecycleReducerError::ObservationMismatch)
        }
        (3, None) => Ok(NetworkNamespaceObservedStateV1::absent()),
        _ => Err(NetworkLifecycleReducerError::ObservationMismatch),
    }
}

fn encode_fence(out: &mut Writer, value: NetworkLifecycleFenceV1) {
    encode_assignment(out, value.assignment);
    out.digest(value.ownership_lease_digest);
    out.u64(value.lease_generation);
    out.u64(value.fail_stop_boottime_nanoseconds);
    out.digest(value.session_digest);
    out.digest(value.currentness_digest);
    out.digest(value.digest);
}

fn decode_fence(
    input: &mut Reader<'_>,
) -> Result<NetworkLifecycleFenceV1, NetworkLifecycleReducerError> {
    let value = NetworkLifecycleFenceV1::new(
        decode_assignment(input)?,
        input.digest()?,
        input.u64()?,
        input.u64()?,
        input.digest()?,
        input.digest()?,
    )?;
    if input.digest()? != value.digest() {
        return Err(NetworkLifecycleReducerError::ObservationMismatch);
    }
    Ok(value)
}

fn encode_link(out: &mut Writer, value: NetworkLifecycleLinkIdentityV1) {
    match value {
        NetworkLifecycleLinkIdentityV1::Isolated { loopback_ifindex } => {
            out.u8(0);
            out.u32(loopback_ifindex);
        }
        NetworkLifecycleLinkIdentityV1::Veth {
            loopback_ifindex,
            host_ifindex,
            sandbox_ifindex,
            host_link_digest,
            sandbox_link_digest,
        } => {
            out.u8(1);
            out.u32(loopback_ifindex);
            out.u32(host_ifindex);
            out.u32(sandbox_ifindex);
            out.digest(host_link_digest);
            out.digest(sandbox_link_digest);
        }
    }
}

fn decode_link(
    input: &mut Reader<'_>,
) -> Result<NetworkLifecycleLinkIdentityV1, NetworkLifecycleReducerError> {
    match input.u8()? {
        0 => Ok(NetworkLifecycleLinkIdentityV1::Isolated {
            loopback_ifindex: input.u32()?,
        }),
        1 => Ok(NetworkLifecycleLinkIdentityV1::Veth {
            loopback_ifindex: input.u32()?,
            host_ifindex: input.u32()?,
            sandbox_ifindex: input.u32()?,
            host_link_digest: input.digest()?,
            sandbox_link_digest: input.digest()?,
        }),
        _ => Err(NetworkLifecycleReducerError::ObservationMismatch),
    }
}

fn encode_tc(out: &mut Writer, value: NetworkLifecycleTcIdentityV1) {
    match value {
        NetworkLifecycleTcIdentityV1::Absent => out.u8(0),
        NetworkLifecycleTcIdentityV1::LeaseGate {
            bpffs_device,
            bpffs_inode,
            host_ingress_program_id,
            host_egress_program_id,
            lease_map_id,
            artifact_digest,
            loader_binding_digest,
        } => {
            out.u8(1);
            out.u64(bpffs_device);
            out.u64(bpffs_inode);
            out.u32(host_ingress_program_id);
            out.u32(host_egress_program_id);
            out.u32(lease_map_id);
            out.digest(artifact_digest);
            out.digest(loader_binding_digest);
        }
    }
}

fn decode_tc(
    input: &mut Reader<'_>,
) -> Result<NetworkLifecycleTcIdentityV1, NetworkLifecycleReducerError> {
    match input.u8()? {
        0 => Ok(NetworkLifecycleTcIdentityV1::Absent),
        1 => Ok(NetworkLifecycleTcIdentityV1::LeaseGate {
            bpffs_device: input.u64()?,
            bpffs_inode: input.u64()?,
            host_ingress_program_id: input.u32()?,
            host_egress_program_id: input.u32()?,
            lease_map_id: input.u32()?,
            artifact_digest: input.digest()?,
            loader_binding_digest: input.digest()?,
        }),
        _ => Err(NetworkLifecycleReducerError::ObservationMismatch),
    }
}

fn encode_kernel(out: &mut Writer, value: NetworkLifecycleKernelIdentityV1) {
    encode_namespace(out, value.namespace);
    out.digest(value.kernel_plan_digest);
    out.digest(value.packet_policy_digest);
    encode_link(out, value.links);
    encode_tc(out, value.tc);
    out.digest(value.digest);
}

fn decode_kernel(
    input: &mut Reader<'_>,
) -> Result<NetworkLifecycleKernelIdentityV1, NetworkLifecycleReducerError> {
    let value = NetworkLifecycleKernelIdentityV1::new(
        decode_namespace(input)?,
        input.digest()?,
        input.digest()?,
        decode_link(input)?,
        decode_tc(input)?,
    )?;
    if input.digest()? != value.digest() {
        return Err(NetworkLifecycleReducerError::ObservationMismatch);
    }
    Ok(value)
}

fn encode_intent(out: &mut Writer, value: NetworkLifecycleIntentV1) {
    out.bytes(&value.request_id);
    out.u64(value.operation_sequence);
    out.u8(action(value.action));
    out.digest(value.prior_resource_digest);
    out.digest(value.prior_catalog_digest);
    encode_state(out, value.prior_state);
    encode_state(out, value.desired_state);
    encode_kernel(out, value.kernel);
    encode_fence(out, value.fence);
    out.digest(value.digest);
}

fn decode_intent(
    input: &mut Reader<'_>,
) -> Result<NetworkLifecycleIntentV1, NetworkLifecycleReducerError> {
    let value = NetworkLifecycleIntentV1::new(
        input.array()?,
        input.u64()?,
        decode_action(input.u8()?)?,
        input.digest()?,
        input.digest()?,
        decode_state(input)?,
        decode_state(input)?,
        decode_kernel(input)?,
        decode_fence(input)?,
    )?;
    if input.digest()? != value.digest() {
        return Err(NetworkLifecycleReducerError::ObservationMismatch);
    }
    Ok(value)
}

fn encode_residual(out: &mut Writer, value: NetworkLifecycleResidualV1) {
    out.digest(value.intent_digest);
    encode_assignment(out, value.assignment);
    out.digest(value.kernel_digest);
    encode_state(out, value.state);
    out.digest(value.resource_digest);
    out.digest(value.catalog_digest);
    out.digest(value.currentness_digest);
    out.u8(value.namespace as u8);
    out.u8(value.links as u8);
    encode_topology(out, value.topology);
    out.u8(value.link_operational as u8);
    out.u8(value.action_progress as u8);
    out.u8(value.bpffs as u8);
    out.u8(value.tc as u8);
    encode_gate(out, value.gate);
    encode_pin(out, value.pin_teardown);
    out.u64(value.observed_boottime_nanoseconds);
    out.u64(value.observation_ordinal);
    out.digest(value.first_snapshot_digest);
    out.digest(value.second_snapshot_digest);
    out.digest(value.digest);
}

fn decode_residual(
    input: &mut Reader<'_>,
) -> Result<NetworkLifecycleResidualV1, NetworkLifecycleReducerError> {
    Ok(NetworkLifecycleResidualV1 {
        intent_digest: input.digest()?,
        assignment: decode_assignment(input)?,
        kernel_digest: input.digest()?,
        state: decode_state(input)?,
        resource_digest: input.digest()?,
        catalog_digest: input.digest()?,
        currentness_digest: input.digest()?,
        namespace: presence(input.u8()?)?,
        links: presence(input.u8()?)?,
        topology: decode_topology(input)?,
        link_operational: link_operational(input.u8()?)?,
        action_progress: progress(input.u8()?)?,
        bpffs: presence(input.u8()?)?,
        tc: presence(input.u8()?)?,
        gate: decode_gate(input)?,
        pin_teardown: decode_pin(input)?,
        observed_boottime_nanoseconds: input.u64()?,
        observation_ordinal: input.u64()?,
        first_snapshot_digest: input.digest()?,
        second_snapshot_digest: input.digest()?,
        digest: input.digest()?,
    })
}

fn encode_topology(out: &mut Writer, value: NetworkLifecycleTopologyResidualV1) {
    match value {
        NetworkLifecycleTopologyResidualV1::Isolated { loopback } => {
            out.u8(0);
            out.u8(loopback as u8);
        }
        NetworkLifecycleTopologyResidualV1::Veth {
            loopback,
            host_peer,
            sandbox_peer,
            addresses,
            routes,
            neighbors,
        } => {
            out.u8(1);
            for value in [
                loopback,
                host_peer,
                sandbox_peer,
                addresses,
                routes,
                neighbors,
            ] {
                out.u8(value as u8);
            }
        }
    }
}

fn decode_topology(
    input: &mut Reader<'_>,
) -> Result<NetworkLifecycleTopologyResidualV1, NetworkLifecycleReducerError> {
    match input.u8()? {
        0 => Ok(NetworkLifecycleTopologyResidualV1::Isolated {
            loopback: presence(input.u8()?)?,
        }),
        1 => Ok(NetworkLifecycleTopologyResidualV1::Veth {
            loopback: presence(input.u8()?)?,
            host_peer: presence(input.u8()?)?,
            sandbox_peer: presence(input.u8()?)?,
            addresses: presence(input.u8()?)?,
            routes: presence(input.u8()?)?,
            neighbors: presence(input.u8()?)?,
        }),
        _ => Err(NetworkLifecycleReducerError::ObservationMismatch),
    }
}

fn encode_gate(out: &mut Writer, value: NetworkLifecycleGateResidualV1) {
    match value {
        NetworkLifecycleGateResidualV1::Armed {
            lease_digest,
            lease_generation,
            fail_stop_boottime_nanoseconds,
        } => {
            out.u8(0);
            out.digest(lease_digest);
            out.u64(lease_generation);
            out.u64(fail_stop_boottime_nanoseconds);
        }
        NetworkLifecycleGateResidualV1::DefaultDrop => out.u8(1),
        NetworkLifecycleGateResidualV1::Absent => out.u8(2),
        NetworkLifecycleGateResidualV1::Partial => out.u8(3),
    }
}

fn decode_gate(
    input: &mut Reader<'_>,
) -> Result<NetworkLifecycleGateResidualV1, NetworkLifecycleReducerError> {
    match input.u8()? {
        0 => Ok(NetworkLifecycleGateResidualV1::Armed {
            lease_digest: input.digest()?,
            lease_generation: input.u64()?,
            fail_stop_boottime_nanoseconds: input.u64()?,
        }),
        1 => Ok(NetworkLifecycleGateResidualV1::DefaultDrop),
        2 => Ok(NetworkLifecycleGateResidualV1::Absent),
        3 => Ok(NetworkLifecycleGateResidualV1::Partial),
        _ => Err(NetworkLifecycleReducerError::ObservationMismatch),
    }
}

fn encode_pin(out: &mut Writer, value: NetworkNamespacePinTeardownPhaseV1) {
    match value {
        NetworkNamespacePinTeardownPhaseV1::Retained => out.u8(0),
        NetworkNamespacePinTeardownPhaseV1::BrokerAuthorized(digest) => {
            out.u8(1);
            out.digest(digest);
        }
        NetworkNamespacePinTeardownPhaseV1::EffectUnknown(digest) => {
            out.u8(2);
            out.digest(digest);
        }
        NetworkNamespacePinTeardownPhaseV1::ObservedAbsent(digest) => {
            out.u8(3);
            out.digest(digest);
        }
    }
}

fn decode_pin(
    input: &mut Reader<'_>,
) -> Result<NetworkNamespacePinTeardownPhaseV1, NetworkLifecycleReducerError> {
    match input.u8()? {
        0 => Ok(NetworkNamespacePinTeardownPhaseV1::Retained),
        1 => Ok(NetworkNamespacePinTeardownPhaseV1::BrokerAuthorized(
            input.digest()?,
        )),
        2 => Ok(NetworkNamespacePinTeardownPhaseV1::EffectUnknown(
            input.digest()?,
        )),
        3 => Ok(NetworkNamespacePinTeardownPhaseV1::ObservedAbsent(
            input.digest()?,
        )),
        _ => Err(NetworkLifecycleReducerError::ObservationMismatch),
    }
}

fn encode_attempt(out: &mut Writer, value: NetworkLifecycleStepAttemptV1) {
    out.u8(value.step as u8);
    out.u64(value.attempt_ordinal);
    encode_residual(out, value.predecessor_residual);
    out.optional_u64(value.released_boottime_nanoseconds);
    out.optional_u64(value.released_observation_ordinal);
    out.optional_digest(value.evidence_digest);
    out.digest(value.digest);
}

fn decode_attempt(
    input: &mut Reader<'_>,
) -> Result<NetworkLifecycleStepAttemptV1, NetworkLifecycleReducerError> {
    Ok(NetworkLifecycleStepAttemptV1 {
        step: step(input.u8()?)?,
        attempt_ordinal: input.u64()?,
        predecessor_residual: decode_residual(input)?,
        released_boottime_nanoseconds: input.optional_u64()?,
        released_observation_ordinal: input.optional_u64()?,
        evidence_digest: input.optional_digest()?,
        digest: input.digest()?,
    })
}

fn encode_disposition(out: &mut Writer, value: NetworkLifecycleObservationDispositionV1) {
    match value {
        NetworkLifecycleObservationDispositionV1::Present(kernel) => {
            out.u8(0);
            encode_kernel(out, kernel);
        }
        NetworkLifecycleObservationDispositionV1::Destroyed(cleanup) => {
            out.u8(1);
            for value in [
                cleanup.namespace_absence_digest,
                cleanup.link_absence_digest,
                cleanup.bpffs_absence_digest,
                cleanup.tc_absence_digest,
                cleanup.digest,
            ] {
                out.digest(value);
            }
        }
    }
}

fn decode_disposition(
    input: &mut Reader<'_>,
) -> Result<NetworkLifecycleObservationDispositionV1, NetworkLifecycleReducerError> {
    match input.u8()? {
        0 => Ok(NetworkLifecycleObservationDispositionV1::Present(
            decode_kernel(input)?,
        )),
        1 => Ok(NetworkLifecycleObservationDispositionV1::Destroyed(
            NetworkLifecycleCleanupObservationV1 {
                namespace_absence_digest: input.digest()?,
                link_absence_digest: input.digest()?,
                bpffs_absence_digest: input.digest()?,
                tc_absence_digest: input.digest()?,
                digest: input.digest()?,
            },
        )),
        _ => Err(NetworkLifecycleReducerError::ObservationMismatch),
    }
}

fn encode_pending(out: &mut Writer, value: PendingNetworkLifecycleV1) {
    encode_intent(out, value.intent);
    out.u8(phase(value.phase));
    out.optional_digest(value.observation_digest);
    out.optional_digest(value.result_resource_digest);
    out.optional_bool(value.effect_applied);
    out.optional_digest(value.latest_residual_digest);
    out.optional(value.latest_residual, encode_residual);
    out.optional(value.latest_disposition, encode_disposition);
    out.u64(value.next_attempt_ordinal);
    out.optional(value.step_attempt, encode_attempt);
    out.boolean(value.any_effect_applied);
    out.u64(value.step_evidence_count);
    out.optional_digest(value.step_evidence_anchor);
    out.optional_digest(value.prior_step_evidence_anchor);
    out.optional(value.last_completed_attempt, encode_attempt);
    out.optional_digest(value.last_completed_residual_digest);
    out.optional(value.last_observation, encode_observation);
    encode_pin(out, value.pin_teardown_phase);
    out.optional_u64(value.last_released_boottime_nanoseconds);
    out.optional_u64(value.last_released_observation_ordinal);
    out.optional_u64(value.last_observation_ordinal);
    out.optional(value.observed_residual, encode_residual);
    out.optional(value.observed_disposition, encode_disposition);
    out.optional_digest(value.observed_release_digest);
}

fn decode_pending(
    input: &mut Reader<'_>,
) -> Result<PendingNetworkLifecycleV1, NetworkLifecycleReducerError> {
    Ok(PendingNetworkLifecycleV1 {
        intent: decode_intent(input)?,
        phase: phase_decode(input.u8()?)?,
        observation_digest: input.optional_digest()?,
        result_resource_digest: input.optional_digest()?,
        effect_applied: input.optional_bool()?,
        latest_residual_digest: input.optional_digest()?,
        latest_residual: input.optional(decode_residual)?,
        latest_disposition: input.optional(decode_disposition)?,
        next_attempt_ordinal: input.u64()?,
        step_attempt: input.optional(decode_attempt)?,
        any_effect_applied: input.boolean()?,
        step_evidence_count: input.u64()?,
        step_evidence_anchor: input.optional_digest()?,
        prior_step_evidence_anchor: input.optional_digest()?,
        last_completed_attempt: input.optional(decode_attempt)?,
        last_completed_residual_digest: input.optional_digest()?,
        last_observation: input.optional(decode_observation)?,
        pin_teardown_phase: decode_pin(input)?,
        last_released_boottime_nanoseconds: input.optional_u64()?,
        last_released_observation_ordinal: input.optional_u64()?,
        last_observation_ordinal: input.optional_u64()?,
        observed_residual: input.optional(decode_residual)?,
        observed_disposition: input.optional(decode_disposition)?,
        observed_release_digest: input.optional_digest()?,
    })
}

fn encode_observation(out: &mut Writer, value: ProtectedNetworkLifecycleObservationV1) {
    out.digest(value.intent_digest);
    out.digest(value.fence_digest);
    out.digest(value.prior_resource_digest);
    out.digest(value.result_resource_digest);
    encode_state(out, value.observed_state);
    encode_disposition(out, value.disposition);
    out.u64(value.observed_boottime_nanoseconds);
    out.u64(value.observation_ordinal);
    out.digest(value.step_attempt_digest);
    out.digest(value.release_digest);
    out.digest(value.step_evidence_digest);
    encode_residual(out, value.residual);
    out.digest(value.first_snapshot_digest);
    out.digest(value.second_snapshot_digest);
    out.digest(value.digest);
}

fn decode_observation(
    input: &mut Reader<'_>,
) -> Result<ProtectedNetworkLifecycleObservationV1, NetworkLifecycleReducerError> {
    Ok(ProtectedNetworkLifecycleObservationV1 {
        intent_digest: input.digest()?,
        fence_digest: input.digest()?,
        prior_resource_digest: input.digest()?,
        result_resource_digest: input.digest()?,
        observed_state: decode_state(input)?,
        disposition: decode_disposition(input)?,
        observed_boottime_nanoseconds: input.u64()?,
        observation_ordinal: input.u64()?,
        step_attempt_digest: input.digest()?,
        release_digest: input.digest()?,
        step_evidence_digest: input.digest()?,
        residual: decode_residual(input)?,
        first_snapshot_digest: input.digest()?,
        second_snapshot_digest: input.digest()?,
        digest: input.digest()?,
    })
}

fn encode_receipt(out: &mut Writer, value: NetworkLifecycleReceiptV1) {
    out.bytes(&value.request_id);
    out.u64(value.operation_sequence);
    out.u8(action(value.action));
    encode_assignment(out, value.assignment);
    for digest in [
        value.intent_digest,
        value.prior_resource_digest,
        value.result_resource_digest,
    ] {
        out.digest(digest);
    }
    encode_state(out, value.prior_state);
    encode_state(out, value.result_state);
    out.digest(value.observation_digest);
    out.digest(value.kernel_digest);
    out.boolean(value.effect_applied);
    out.u64(value.step_evidence_count);
    out.digest(value.step_evidence_anchor);
    out.optional_u64(value.last_released_boottime_nanoseconds);
    out.optional_u64(value.last_released_observation_ordinal);
    out.u64(value.last_observation_ordinal);
    out.optional_digest(value.namespace_pin_teardown_digest);
    out.boolean(value.terminal_destroyed);
    out.digest(value.digest);
}

fn encode_compacted_receipt(out: &mut Writer, value: CompactedNetworkLifecycleReceiptV1) {
    out.bytes(&value.request_id);
    out.u64(value.operation_sequence);
    out.digest(value.intent_digest);
    out.digest(value.receipt_digest);
    out.digest(value.result_resource_digest);
    encode_state(out, value.result_state);
    out.digest(value.kernel_digest);
}

fn decode_compacted_receipt(
    input: &mut Reader<'_>,
) -> Result<CompactedNetworkLifecycleReceiptV1, NetworkLifecycleReducerError> {
    Ok(CompactedNetworkLifecycleReceiptV1 {
        request_id: input.array()?,
        operation_sequence: input.u64()?,
        intent_digest: input.digest()?,
        receipt_digest: input.digest()?,
        result_resource_digest: input.digest()?,
        result_state: decode_state(input)?,
        kernel_digest: input.digest()?,
    })
}

fn decode_receipt(
    input: &mut Reader<'_>,
) -> Result<NetworkLifecycleReceiptV1, NetworkLifecycleReducerError> {
    Ok(NetworkLifecycleReceiptV1 {
        request_id: input.array()?,
        operation_sequence: input.u64()?,
        action: decode_action(input.u8()?)?,
        assignment: decode_assignment(input)?,
        intent_digest: input.digest()?,
        prior_resource_digest: input.digest()?,
        result_resource_digest: input.digest()?,
        prior_state: decode_state(input)?,
        result_state: decode_state(input)?,
        observation_digest: input.digest()?,
        kernel_digest: input.digest()?,
        effect_applied: input.boolean()?,
        step_evidence_count: input.u64()?,
        step_evidence_anchor: input.digest()?,
        last_released_boottime_nanoseconds: input.optional_u64()?,
        last_released_observation_ordinal: input.optional_u64()?,
        last_observation_ordinal: input.u64()?,
        namespace_pin_teardown_digest: input.optional_digest()?,
        terminal_destroyed: input.boolean()?,
        digest: input.digest()?,
    })
}

fn action(value: NetworkNamespaceLifecycleActionV1) -> u8 {
    super::action_code(value)
}
fn decode_action(
    value: u8,
) -> Result<NetworkNamespaceLifecycleActionV1, NetworkLifecycleReducerError> {
    match value {
        0 => Ok(NetworkNamespaceLifecycleActionV1::Arm),
        1 => Ok(NetworkNamespaceLifecycleActionV1::Renew),
        2 => Ok(NetworkNamespaceLifecycleActionV1::Disarm),
        3 => Ok(NetworkNamespaceLifecycleActionV1::Destroy),
        4 => Ok(NetworkNamespaceLifecycleActionV1::Fence),
        _ => Err(NetworkLifecycleReducerError::ObservationMismatch),
    }
}
fn presence(value: u8) -> Result<NetworkLifecycleResidualPresenceV1, NetworkLifecycleReducerError> {
    match value {
        0 => Ok(NetworkLifecycleResidualPresenceV1::Present),
        1 => Ok(NetworkLifecycleResidualPresenceV1::Absent),
        2 => Ok(NetworkLifecycleResidualPresenceV1::Partial),
        _ => Err(NetworkLifecycleReducerError::ObservationMismatch),
    }
}
fn link_operational(
    value: u8,
) -> Result<NetworkLifecycleLinkOperationalV1, NetworkLifecycleReducerError> {
    match value {
        0 => Ok(NetworkLifecycleLinkOperationalV1::Down),
        1 => Ok(NetworkLifecycleLinkOperationalV1::Up),
        2 => Ok(NetworkLifecycleLinkOperationalV1::Absent),
        3 => Ok(NetworkLifecycleLinkOperationalV1::Partial),
        _ => Err(NetworkLifecycleReducerError::ObservationMismatch),
    }
}
fn progress(value: u8) -> Result<NetworkLifecycleActionProgressV1, NetworkLifecycleReducerError> {
    use NetworkLifecycleActionProgressV1::*;
    match value {
        0 => Ok(Initial),
        1 => Ok(LinksDown),
        2 => Ok(GateProgrammed),
        3 => Ok(AddressesConfigured),
        4 => Ok(RoutesConfigured),
        5 => Ok(NeighborsConfigured),
        6 => Ok(PlanVerified),
        7 => Ok(LinksRaised),
        8 => Ok(TcDetached),
        9 => Ok(BpffsRemoved),
        10 => Ok(LinksRemoved),
        11 => Ok(PinAuthorized),
        12 => Ok(PinRemoved),
        _ => Err(NetworkLifecycleReducerError::ObservationMismatch),
    }
}
fn step(value: u8) -> Result<NetworkLifecycleEffectStepV1, NetworkLifecycleReducerError> {
    use NetworkLifecycleEffectStepV1::*;
    match value {
        0 => Ok(EnsureLinksDown),
        1 => Ok(ProgramLeaseGate),
        2 => Ok(ConfigureExactAddressPairs),
        3 => Ok(ConfigureExactRoutes),
        4 => Ok(ConfigureExactPermanentNeighbors),
        5 => Ok(VerifyExactPlanConfiguration),
        6 => Ok(RaiseLinks),
        7 => Ok(LowerLinks),
        8 => Ok(ProgramDefaultDrop),
        9 => Ok(DetachTcGate),
        10 => Ok(RemoveBpffsPins),
        11 => Ok(RemoveLinks),
        12 => Ok(AuthorizeNamespacePinTeardown),
        13 => Ok(RemoveNamespacePin),
        _ => Err(NetworkLifecycleReducerError::ObservationMismatch),
    }
}
fn phase(value: NetworkLifecycleReducerPhaseV1) -> u8 {
    super::phase_code(value)
}
fn phase_decode(value: u8) -> Result<NetworkLifecycleReducerPhaseV1, NetworkLifecycleReducerError> {
    match value {
        0 => Ok(NetworkLifecycleReducerPhaseV1::Prepared),
        1 => Ok(NetworkLifecycleReducerPhaseV1::EffectUnknown),
        2 => Ok(NetworkLifecycleReducerPhaseV1::ReleaseFrozen),
        3 => Ok(NetworkLifecycleReducerPhaseV1::Observed),
        _ => Err(NetworkLifecycleReducerError::ObservationMismatch),
    }
}

struct Writer {
    bytes: Vec<u8>,
    overflowed: bool,
}
impl Writer {
    fn new() -> Self {
        Self {
            bytes: Vec::new(),
            overflowed: false,
        }
    }
    fn bytes(&mut self, value: &[u8]) {
        if self
            .bytes
            .len()
            .checked_add(value.len())
            .is_some_and(|length| length <= MAXIMUM_RECOVERY_CHECKPOINT_BYTES)
        {
            self.bytes.extend_from_slice(value);
        } else {
            self.overflowed = true;
        }
    }
    fn u8(&mut self, value: u8) {
        self.bytes(&[value]);
    }
    fn u32(&mut self, value: u32) {
        self.bytes(&value.to_be_bytes());
    }
    fn u64(&mut self, value: u64) {
        self.bytes(&value.to_be_bytes());
    }
    fn boolean(&mut self, value: bool) {
        self.u8(u8::from(value));
    }
    fn digest(&mut self, value: ObjectDigest) {
        self.bytes(value.as_bytes());
    }
    fn optional_digest(&mut self, value: Option<ObjectDigest>) {
        self.optional(value, |out, value| out.digest(value));
    }
    fn optional_u64(&mut self, value: Option<u64>) {
        self.optional(value, |out, value| out.u64(value));
    }
    fn optional_bool(&mut self, value: Option<bool>) {
        self.optional(value, |out, value| out.boolean(value));
    }
    fn optional<T: Copy>(&mut self, value: Option<T>, encode: fn(&mut Self, T)) {
        match value {
            None => self.u8(0),
            Some(value) => {
                self.u8(1);
                encode(self, value);
            }
        }
    }
    fn sequence<T: Copy>(
        &mut self,
        values: &[T],
        encode: fn(&mut Self, T),
    ) -> Result<(), NetworkLifecycleReducerError> {
        let count = u32::try_from(values.len())
            .map_err(|_| NetworkLifecycleReducerError::ReceiptHistoryExhausted)?;
        self.u32(count);
        for value in values {
            encode(self, *value);
        }
        Ok(())
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}
impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], NetworkLifecycleReducerError> {
        let end = self
            .cursor
            .checked_add(N)
            .ok_or(NetworkLifecycleReducerError::ObservationMismatch)?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or(NetworkLifecycleReducerError::ObservationMismatch)?
            .try_into()
            .map_err(|_| NetworkLifecycleReducerError::ObservationMismatch)?;
        self.cursor = end;
        Ok(value)
    }
    fn u8(&mut self) -> Result<u8, NetworkLifecycleReducerError> {
        Ok(self.array::<1>()?[0])
    }
    fn u32(&mut self) -> Result<u32, NetworkLifecycleReducerError> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, NetworkLifecycleReducerError> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn boolean(&mut self) -> Result<bool, NetworkLifecycleReducerError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(NetworkLifecycleReducerError::ObservationMismatch),
        }
    }
    fn digest(&mut self) -> Result<ObjectDigest, NetworkLifecycleReducerError> {
        Ok(ObjectDigest::from_bytes(self.array()?))
    }
    fn optional_digest(&mut self) -> Result<Option<ObjectDigest>, NetworkLifecycleReducerError> {
        self.optional(Self::digest)
    }
    fn optional_u64(&mut self) -> Result<Option<u64>, NetworkLifecycleReducerError> {
        self.optional(Self::u64)
    }
    fn optional_bool(&mut self) -> Result<Option<bool>, NetworkLifecycleReducerError> {
        self.optional(Self::boolean)
    }
    fn optional<T>(
        &mut self,
        decode: fn(&mut Self) -> Result<T, NetworkLifecycleReducerError>,
    ) -> Result<Option<T>, NetworkLifecycleReducerError> {
        match self.u8()? {
            0 => Ok(None),
            1 => decode(self).map(Some),
            _ => Err(NetworkLifecycleReducerError::ObservationMismatch),
        }
    }
    fn sequence<T>(
        &mut self,
        maximum_count: usize,
        decode: fn(&mut Self) -> Result<T, NetworkLifecycleReducerError>,
    ) -> Result<Vec<T>, NetworkLifecycleReducerError> {
        let count = self.u32()? as usize;
        if count > maximum_count {
            return Err(NetworkLifecycleReducerError::ReceiptHistoryExhausted);
        }
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            values.push(decode(self)?);
        }
        Ok(values)
    }
    fn finish(self) -> Result<(), NetworkLifecycleReducerError> {
        if self.cursor == self.bytes.len() {
            Ok(())
        } else {
            Err(NetworkLifecycleReducerError::ObservationMismatch)
        }
    }
}

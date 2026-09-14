//! Canonical bounded binary snapshots for the dormant Guardian reducer.
//!
//! ```text
//! AOSGDSNP01 | authority | Network fence | managed state | worker | timer
//! sequence/floor/anchor | pending? | compact receipts[] | full receipts[]
//! terminal/poison flags | snapshot digest
//! ```
//!
//! Every integer is big-endian, every option and closed union has a one-byte
//! discriminant, and every sequence has a checked `u32` element count.

use aos_sandbox_core::{
    AssignmentEpoch, IncarnationId, LeaseAssignment, NodeId, ObjectDigest, SandboxId,
};

use super::*;

const MAGIC: &[u8; 10] = b"AOSGDSNP01";

pub(super) fn encode_snapshot(
    snapshot: &GuardianRecoverySnapshotV1,
) -> Result<Vec<u8>, GuardianReducerError> {
    let mut out = Writer::new();
    out.bytes(MAGIC);
    encode_authority(&mut out, snapshot.authority);
    encode_network(&mut out, snapshot.network);
    encode_managed(&mut out, snapshot.managed);
    out.digest(snapshot.worker_identity_digest);
    encode_timer(&mut out, snapshot.timer);
    out.u64(snapshot.highest_sequence);
    out.u64(snapshot.receipt_floor_sequence);
    out.optional_digest(snapshot.receipt_anchor_digest);
    out.optional(snapshot.pending, encode_pending);
    out.sequence(&snapshot.compacted_receipt_index, encode_compacted_receipt)?;
    out.sequence(&snapshot.receipts, encode_receipt)?;
    out.boolean(snapshot.terminal);
    out.boolean(snapshot.poisoned);
    out.digest(snapshot.digest);
    if out.overflowed {
        return Err(GuardianReducerError::Exhausted);
    }
    Ok(out.bytes)
}

pub(super) fn decode_snapshot(
    bytes: &[u8],
) -> Result<GuardianRecoverySnapshotV1, GuardianReducerError> {
    if bytes.len() > MAXIMUM_GUARDIAN_CHECKPOINT_BYTES {
        return Err(GuardianReducerError::ObservationMismatch);
    }
    let mut input = Reader::new(bytes);
    if input.array::<10>()? != *MAGIC {
        return Err(GuardianReducerError::ObservationMismatch);
    }
    let snapshot = GuardianRecoverySnapshotV1 {
        authority: decode_authority(&mut input)?,
        network: decode_network(&mut input)?,
        managed: decode_managed(&mut input)?,
        worker_identity_digest: input.digest()?,
        timer: decode_timer(&mut input)?,
        highest_sequence: input.u64()?,
        receipt_floor_sequence: input.u64()?,
        receipt_anchor_digest: input.optional_digest()?,
        pending: input.optional(decode_pending)?,
        compacted_receipt_index: input.sequence(
            MAXIMUM_COMPACTED_GUARDIAN_RECEIPTS,
            decode_compacted_receipt,
        )?,
        receipts: input.sequence(MAXIMUM_GUARDIAN_RECEIPTS, decode_receipt)?,
        terminal: input.boolean()?,
        poisoned: input.boolean()?,
        digest: input.digest()?,
    };
    input.finish()?;
    Ok(snapshot)
}

fn encode_assignment(out: &mut Writer, value: LeaseAssignment) {
    out.bytes(value.sandbox().as_bytes());
    out.bytes(value.incarnation().as_bytes());
    out.u64(value.epoch().get());
    out.digest(value.digest());
}

fn decode_assignment(input: &mut Reader<'_>) -> Result<LeaseAssignment, GuardianReducerError> {
    LeaseAssignment::new(
        SandboxId::from_bytes(input.array()?),
        IncarnationId::from_bytes(input.array()?),
        AssignmentEpoch::new(input.u64()?),
        input.digest()?,
    )
    .map_err(|_| GuardianReducerError::ObservationMismatch)
}

fn encode_authority(out: &mut Writer, value: GuardianAuthoritySnapshotV1) {
    encode_assignment(out, value.assignment);
    out.bytes(value.node.as_bytes());
    out.u64(value.desired_generation);
    out.digest(value.plan_digest);
    out.u64(value.lease_generation);
    out.digest(value.lease_digest);
    out.bytes(&value.host_boot_id);
    out.bytes(&value.clock_provenance);
    out.u64(value.fail_stop_boottime_nanoseconds);
    out.digest(value.durable_state_digest);
    out.digest(value.digest);
}

fn decode_authority(
    input: &mut Reader<'_>,
) -> Result<GuardianAuthoritySnapshotV1, GuardianReducerError> {
    let value = GuardianAuthoritySnapshotV1 {
        assignment: decode_assignment(input)?,
        node: NodeId::from_bytes(input.array()?),
        desired_generation: input.u64()?,
        plan_digest: input.digest()?,
        lease_generation: input.u64()?,
        lease_digest: input.digest()?,
        host_boot_id: input.array()?,
        clock_provenance: input.array()?,
        fail_stop_boottime_nanoseconds: input.u64()?,
        durable_state_digest: input.digest()?,
        digest: input.digest()?,
    };
    if value.digest != authority_digest(value) {
        return Err(GuardianReducerError::ObservationMismatch);
    }
    Ok(value)
}

fn encode_network(out: &mut Writer, value: GuardianNetworkFenceV1) {
    encode_assignment(out, value.assignment);
    out.bytes(&value.network_handle);
    out.bytes(&value.kernel_boot_id);
    out.u64(value.namespace_device);
    out.u64(value.namespace_inode);
    for digest in [
        value.network_kernel_identity_digest,
        value.kernel_plan_digest,
        value.packet_policy_digest,
        value.tc_gate_binding_digest,
        value.network_resource_digest,
        value.network_catalog_digest,
    ] {
        out.digest(digest);
    }
    out.u64(value.lease_generation);
    out.digest(value.lease_digest);
    out.u64(value.fail_stop_boottime_nanoseconds);
    out.digest(value.session_digest);
    out.digest(value.currentness_digest);
    out.digest(value.digest);
}

fn decode_network(input: &mut Reader<'_>) -> Result<GuardianNetworkFenceV1, GuardianReducerError> {
    let value = GuardianNetworkFenceV1::new(
        decode_assignment(input)?,
        input.array()?,
        input.array()?,
        input.u64()?,
        input.u64()?,
        input.digest()?,
        input.digest()?,
        input.digest()?,
        input.digest()?,
        input.digest()?,
        input.digest()?,
        input.u64()?,
        input.digest()?,
        input.u64()?,
        input.digest()?,
        input.digest()?,
    )?;
    if input.digest()? != value.digest() {
        return Err(GuardianReducerError::ObservationMismatch);
    }
    Ok(value)
}

fn encode_managed_state(out: &mut Writer, value: GuardianManagedStateV1) {
    out.u8(value.domain as u8);
    out.u64(value.generation);
    out.digest(value.resource_digest);
    out.digest(value.observation_digest);
    out.digest(value.catalog_digest);
    out.digest(value.currentness_digest);
    out.u8(value.status as u8);
}

fn decode_managed_state(
    input: &mut Reader<'_>,
) -> Result<GuardianManagedStateV1, GuardianReducerError> {
    GuardianManagedStateV1::new(
        domain(input.u8()?)?,
        input.u64()?,
        input.digest()?,
        input.digest()?,
        input.digest()?,
        input.digest()?,
        status(input.u8()?)?,
    )
}

fn encode_managed(out: &mut Writer, value: GuardianManagedSnapshotV1) {
    encode_assignment(out, value.assignment);
    for entry in value.entries {
        encode_managed_state(out, entry);
    }
    out.u64(value.observed_boottime_nanoseconds);
    out.digest(value.session_digest);
    out.digest(value.currentness_digest);
    out.digest(value.digest);
}

fn decode_managed(
    input: &mut Reader<'_>,
) -> Result<GuardianManagedSnapshotV1, GuardianReducerError> {
    let assignment = decode_assignment(input)?;
    let entries = [
        decode_managed_state(input)?,
        decode_managed_state(input)?,
        decode_managed_state(input)?,
        decode_managed_state(input)?,
    ];
    let value = GuardianManagedSnapshotV1::new(
        assignment,
        entries,
        input.u64()?,
        input.digest()?,
        input.digest()?,
    )?;
    if input.digest()? != value.digest() {
        return Err(GuardianReducerError::ObservationMismatch);
    }
    Ok(value)
}

fn encode_timer(out: &mut Writer, value: GuardianRenewalTimerV1) {
    out.bytes(&value.host_boot_id);
    out.bytes(&value.clock_provenance);
    out.u64(value.armed_boottime_nanoseconds);
    out.u64(value.early_freeze_boottime_nanoseconds);
    out.u64(value.hard_stop_boottime_nanoseconds);
    out.digest(value.policy_digest);
}

fn decode_timer(input: &mut Reader<'_>) -> Result<GuardianRenewalTimerV1, GuardianReducerError> {
    Ok(GuardianRenewalTimerV1 {
        host_boot_id: input.array()?,
        clock_provenance: input.array()?,
        armed_boottime_nanoseconds: input.u64()?,
        early_freeze_boottime_nanoseconds: input.u64()?,
        hard_stop_boottime_nanoseconds: input.u64()?,
        policy_digest: input.digest()?,
    })
}

fn encode_cause(out: &mut Writer, value: ProtectedGuardianCauseEvidenceV1) {
    out.u8(value.kind as u8);
    encode_assignment(out, value.assignment);
    out.digest(value.authority_digest);
    out.digest(value.source_digest);
    out.digest(value.session_digest);
    out.digest(value.currentness_digest);
    out.u64(value.observation_ordinal);
    out.digest(value.digest);
}

fn decode_cause(
    input: &mut Reader<'_>,
) -> Result<ProtectedGuardianCauseEvidenceV1, GuardianReducerError> {
    Ok(ProtectedGuardianCauseEvidenceV1 {
        kind: cause(input.u8()?)?,
        assignment: decode_assignment(input)?,
        authority_digest: input.digest()?,
        source_digest: input.digest()?,
        session_digest: input.digest()?,
        currentness_digest: input.digest()?,
        observation_ordinal: input.u64()?,
        digest: input.digest()?,
    })
}

fn encode_admission(out: &mut Writer, value: GuardianEffectAdmissionV1) {
    out.bytes(&value.request_id);
    out.u64(value.sequence);
    out.u8(value.action as u8);
    encode_authority(out, value.authority);
    encode_network(out, value.network);
    encode_managed(out, value.managed);
    encode_timer(out, value.timer);
    out.digest(value.worker_identity_digest);
    out.optional_digest(value.replacement_worker_digest);
    out.optional_digest(value.predecessor_receipt_digest);
    out.optional(value.cause_evidence, encode_cause);
    out.digest(value.digest);
}

fn decode_admission(
    input: &mut Reader<'_>,
) -> Result<GuardianEffectAdmissionV1, GuardianReducerError> {
    let value = GuardianEffectAdmissionV1::new(
        input.array()?,
        input.u64()?,
        action(input.u8()?)?,
        decode_authority(input)?,
        decode_network(input)?,
        decode_managed(input)?,
        decode_timer(input)?,
        input.digest()?,
        input.optional_digest()?,
        input.optional_digest()?,
        input.optional(decode_cause)?,
    )?;
    if input.digest()? != value.digest() {
        return Err(GuardianReducerError::ObservationMismatch);
    }
    Ok(value)
}

fn encode_current(out: &mut Writer, value: ProtectedGuardianCurrentV1) {
    for digest in [
        value.admission_digest,
        value.durable_reducer_digest,
        value.authority_digest,
        value.prior_network_fence_digest,
        value.admitted_network_fence_digest,
        value.managed_snapshot_digest,
    ] {
        out.digest(digest);
    }
    encode_managed(out, value.managed);
    out.bytes(&value.host_boot_id);
    out.bytes(&value.clock_provenance);
    out.u64(value.observed_boottime_nanoseconds);
    out.u64(value.observation_ordinal);
    out.digest(value.worker_identity_digest);
    out.digest(value.worker_resource_digest);
    out.digest(value.worker_currentness_digest);
    for value in [
        value.current_worker_live,
        value.old_worker_dead,
        value.admitted_worker_absent,
        value.network_default_drop,
        value.renewal_timer_current,
        value.network_lease_gate_current,
        value.payload_frozen,
        value.payload_stopped,
        value.payload_released,
    ] {
        out.boolean(value);
    }
}

fn decode_current(
    input: &mut Reader<'_>,
) -> Result<ProtectedGuardianCurrentV1, GuardianReducerError> {
    Ok(ProtectedGuardianCurrentV1 {
        admission_digest: input.digest()?,
        durable_reducer_digest: input.digest()?,
        authority_digest: input.digest()?,
        prior_network_fence_digest: input.digest()?,
        admitted_network_fence_digest: input.digest()?,
        managed_snapshot_digest: input.digest()?,
        managed: decode_managed(input)?,
        host_boot_id: input.array()?,
        clock_provenance: input.array()?,
        observed_boottime_nanoseconds: input.u64()?,
        observation_ordinal: input.u64()?,
        worker_identity_digest: input.digest()?,
        worker_resource_digest: input.digest()?,
        worker_currentness_digest: input.digest()?,
        current_worker_live: input.boolean()?,
        old_worker_dead: input.boolean()?,
        admitted_worker_absent: input.boolean()?,
        network_default_drop: input.boolean()?,
        renewal_timer_current: input.boolean()?,
        network_lease_gate_current: input.boolean()?,
        payload_frozen: input.boolean()?,
        payload_stopped: input.boolean()?,
        payload_released: input.boolean()?,
    })
}

fn encode_outcome(out: &mut Writer, value: ProtectedGuardianOutcomeV1) {
    for digest in [
        value.admission_digest,
        value.authority_digest,
        value.network_fence_digest,
        value.worker_identity_digest,
        value.worker_resource_digest,
        value.worker_currentness_digest,
    ] {
        out.digest(digest);
    }
    encode_managed(out, value.managed);
    out.u64(value.observation_ordinal);
    out.digest(value.effect_evidence_digest);
    out.digest(value.step_attempt_digest);
    out.digest(value.release_digest);
    out.digest(value.predecessor_digest);
    out.digest(value.first_snapshot_digest);
    out.digest(value.second_snapshot_digest);
    for value in [
        value.old_worker_dead,
        value.admitted_worker_live,
        value.network_default_drop,
        value.payload_frozen,
        value.payload_stopped,
        value.renewal_timer_current,
        value.network_lease_gate_current,
        value.payload_released,
    ] {
        out.boolean(value);
    }
    out.digest(value.digest);
}

fn decode_outcome(
    input: &mut Reader<'_>,
) -> Result<ProtectedGuardianOutcomeV1, GuardianReducerError> {
    Ok(ProtectedGuardianOutcomeV1 {
        admission_digest: input.digest()?,
        authority_digest: input.digest()?,
        network_fence_digest: input.digest()?,
        worker_identity_digest: input.digest()?,
        worker_resource_digest: input.digest()?,
        worker_currentness_digest: input.digest()?,
        managed: decode_managed(input)?,
        observation_ordinal: input.u64()?,
        effect_evidence_digest: input.digest()?,
        step_attempt_digest: input.digest()?,
        release_digest: input.digest()?,
        predecessor_digest: input.digest()?,
        first_snapshot_digest: input.digest()?,
        second_snapshot_digest: input.digest()?,
        old_worker_dead: input.boolean()?,
        admitted_worker_live: input.boolean()?,
        network_default_drop: input.boolean()?,
        payload_frozen: input.boolean()?,
        payload_stopped: input.boolean()?,
        renewal_timer_current: input.boolean()?,
        network_lease_gate_current: input.boolean()?,
        payload_released: input.boolean()?,
        digest: input.digest()?,
    })
}

fn encode_supersession(out: &mut Writer, value: ProtectedGuardianWorkerDeathSupersessionV1) {
    out.digest(value.admission_digest);
    out.u8(value.superseded_action as u8);
    out.u8(value.step as u8);
    out.u64(value.attempt_ordinal);
    out.digest(value.step_attempt_digest);
    encode_current(out, value.predecessor_current);
    out.digest(value.death_evidence_digest);
    encode_current(out, value.current);
    out.digest(value.digest);
}

fn decode_supersession(
    input: &mut Reader<'_>,
) -> Result<ProtectedGuardianWorkerDeathSupersessionV1, GuardianReducerError> {
    Ok(ProtectedGuardianWorkerDeathSupersessionV1 {
        admission_digest: input.digest()?,
        superseded_action: action(input.u8()?)?,
        step: step(input.u8()?)?,
        attempt_ordinal: input.u64()?,
        step_attempt_digest: input.digest()?,
        predecessor_current: decode_current(input)?,
        death_evidence_digest: input.digest()?,
        current: decode_current(input)?,
        digest: input.digest()?,
    })
}

fn encode_pending(out: &mut Writer, value: PendingGuardianEffectV1) {
    encode_admission(out, value.admission);
    out.u8(phase(value.phase));
    out.optional_digest(value.observation_digest);
    out.optional(value.observed_managed, encode_managed);
    out.optional_u64(value.released_boottime_nanoseconds);
    out.optional_u64(value.released_observation_ordinal);
    out.optional_u64(value.last_observation_ordinal);
    out.optional_digest(value.effect_evidence_digest);
    out.optional(value.step, |out, value| out.u8(value as u8));
    out.u64(value.next_attempt_ordinal);
    out.optional_u64(value.active_attempt_ordinal);
    out.u64(value.step_evidence_count);
    out.optional_digest(value.step_evidence_anchor);
    out.optional_digest(value.prior_step_evidence_anchor);
    out.optional(value.predecessor_current, encode_current);
    out.optional_digest(value.step_attempt_digest);
    out.optional(value.last_outcome, encode_outcome);
    out.optional(value.last_completed_action, |out, value| {
        out.u8(value as u8)
    });
    out.optional(value.last_completed_step, |out, value| out.u8(value as u8));
    out.optional(value.last_completed_predecessor, encode_current);
    out.optional_digest(value.last_completed_attempt_digest);
    out.optional_u64(value.last_completed_attempt_ordinal);
    out.optional_u64(value.last_completed_released_boottime_nanoseconds);
    out.optional_u64(value.last_completed_released_observation_ordinal);
    out.optional(value.containment_override, |out, value| {
        out.u8(override_code(value))
    });
    out.optional(value.worker_death_supersession, encode_supersession);
    for handoff in value.release_timer_handoffs {
        out.optional(handoff, encode_release_timer_handoff);
    }
}

fn decode_pending(input: &mut Reader<'_>) -> Result<PendingGuardianEffectV1, GuardianReducerError> {
    Ok(PendingGuardianEffectV1 {
        admission: decode_admission(input)?,
        phase: phase_decode(input.u8()?)?,
        observation_digest: input.optional_digest()?,
        observed_managed: input.optional(decode_managed)?,
        released_boottime_nanoseconds: input.optional_u64()?,
        released_observation_ordinal: input.optional_u64()?,
        last_observation_ordinal: input.optional_u64()?,
        effect_evidence_digest: input.optional_digest()?,
        step: input.optional(|input| step(input.u8()?))?,
        next_attempt_ordinal: input.u64()?,
        active_attempt_ordinal: input.optional_u64()?,
        step_evidence_count: input.u64()?,
        step_evidence_anchor: input.optional_digest()?,
        prior_step_evidence_anchor: input.optional_digest()?,
        predecessor_current: input.optional(decode_current)?,
        step_attempt_digest: input.optional_digest()?,
        last_outcome: input.optional(decode_outcome)?,
        last_completed_action: input.optional(|input| action(input.u8()?))?,
        last_completed_step: input.optional(|input| step(input.u8()?))?,
        last_completed_predecessor: input.optional(decode_current)?,
        last_completed_attempt_digest: input.optional_digest()?,
        last_completed_attempt_ordinal: input.optional_u64()?,
        last_completed_released_boottime_nanoseconds: input.optional_u64()?,
        last_completed_released_observation_ordinal: input.optional_u64()?,
        containment_override: input.optional(|input| override_decode(input.u8()?))?,
        worker_death_supersession: input.optional(decode_supersession)?,
        release_timer_handoffs: [
            input.optional(decode_release_timer_handoff)?,
            input.optional(decode_release_timer_handoff)?,
        ],
    })
}

fn encode_release_timer_handoff(out: &mut Writer, value: GuardianReleaseTimerHandoffV1) {
    out.u8(value.source_action as u8);
    out.u8(value.target_action as u8);
    out.u8(value.step as u8);
    out.u64(value.attempt_ordinal);
    out.digest(value.step_attempt_digest);
    out.digest(value.release_digest);
    encode_current(out, value.predecessor_current);
    out.u64(value.released_boottime_nanoseconds);
    out.u64(value.released_observation_ordinal);
    encode_current(out, value.current);
    out.digest(value.digest);
}

fn decode_release_timer_handoff(
    input: &mut Reader<'_>,
) -> Result<GuardianReleaseTimerHandoffV1, GuardianReducerError> {
    Ok(GuardianReleaseTimerHandoffV1 {
        source_action: action(input.u8()?)?,
        target_action: action(input.u8()?)?,
        step: step(input.u8()?)?,
        attempt_ordinal: input.u64()?,
        step_attempt_digest: input.digest()?,
        release_digest: input.digest()?,
        predecessor_current: decode_current(input)?,
        released_boottime_nanoseconds: input.u64()?,
        released_observation_ordinal: input.u64()?,
        current: decode_current(input)?,
        digest: input.digest()?,
    })
}

fn encode_receipt(out: &mut Writer, value: GuardianEffectReceiptV1) {
    out.bytes(&value.request_id);
    out.u64(value.sequence);
    out.u8(value.admitted_action as u8);
    out.u8(value.action as u8);
    for digest in [
        value.admission_digest,
        value.authority_digest,
        value.network_fence_digest,
        value.managed_snapshot_digest,
        value.observation_digest,
    ] {
        out.digest(digest);
    }
    out.u64(value.step_evidence_count);
    out.digest(value.step_evidence_anchor);
    out.u64(value.last_released_boottime_nanoseconds);
    out.u64(value.last_released_observation_ordinal);
    out.u64(value.last_observation_ordinal);
    out.optional_digest(value.worker_death_supersession_digest);
    out.boolean(value.terminal);
    out.digest(value.digest);
}

fn encode_compacted_receipt(out: &mut Writer, value: CompactedGuardianReceiptV1) {
    out.bytes(&value.request_id);
    out.u64(value.sequence);
    out.u8(value.action as u8);
    out.digest(value.admission_digest);
    out.digest(value.receipt_digest);
}

fn decode_compacted_receipt(
    input: &mut Reader<'_>,
) -> Result<CompactedGuardianReceiptV1, GuardianReducerError> {
    Ok(CompactedGuardianReceiptV1 {
        request_id: input.array()?,
        sequence: input.u64()?,
        action: action(input.u8()?)?,
        admission_digest: input.digest()?,
        receipt_digest: input.digest()?,
    })
}

fn decode_receipt(input: &mut Reader<'_>) -> Result<GuardianEffectReceiptV1, GuardianReducerError> {
    Ok(GuardianEffectReceiptV1 {
        request_id: input.array()?,
        sequence: input.u64()?,
        admitted_action: action(input.u8()?)?,
        action: action(input.u8()?)?,
        admission_digest: input.digest()?,
        authority_digest: input.digest()?,
        network_fence_digest: input.digest()?,
        managed_snapshot_digest: input.digest()?,
        observation_digest: input.digest()?,
        step_evidence_count: input.u64()?,
        step_evidence_anchor: input.digest()?,
        last_released_boottime_nanoseconds: input.u64()?,
        last_released_observation_ordinal: input.u64()?,
        last_observation_ordinal: input.u64()?,
        worker_death_supersession_digest: input.optional_digest()?,
        terminal: input.boolean()?,
        digest: input.digest()?,
    })
}

fn domain(value: u8) -> Result<GuardianManagedDomainV1, GuardianReducerError> {
    match value {
        0 => Ok(GuardianManagedDomainV1::Host),
        1 => Ok(GuardianManagedDomainV1::Storage),
        2 => Ok(GuardianManagedDomainV1::Mount),
        3 => Ok(GuardianManagedDomainV1::Network),
        _ => Err(GuardianReducerError::ObservationMismatch),
    }
}
fn status(value: u8) -> Result<GuardianManagedStatusV1, GuardianReducerError> {
    match value {
        0 => Ok(GuardianManagedStatusV1::Absent),
        1 => Ok(GuardianManagedStatusV1::Active),
        2 => Ok(GuardianManagedStatusV1::Contained),
        3 => Ok(GuardianManagedStatusV1::CleanupUnknown),
        4 => Ok(GuardianManagedStatusV1::Released),
        _ => Err(GuardianReducerError::ObservationMismatch),
    }
}
fn action(value: u8) -> Result<GuardianReducerActionV1, GuardianReducerError> {
    use GuardianReducerActionV1::*;
    match value {
        0 => Ok(Arm),
        1 => Ok(Renew),
        2 => Ok(EarlyFreeze),
        3 => Ok(Revoke),
        4 => Ok(Expire),
        5 => Ok(EnforcementLoss),
        6 => Ok(ReplaceWorker),
        7 => Ok(Cleanup),
        8 => Ok(Resume),
        _ => Err(GuardianReducerError::ObservationMismatch),
    }
}
fn cause(value: u8) -> Result<GuardianCauseKindV1, GuardianReducerError> {
    match value {
        0 => Ok(GuardianCauseKindV1::Revocation),
        1 => Ok(GuardianCauseKindV1::EnforcementLoss),
        _ => Err(GuardianReducerError::ObservationMismatch),
    }
}
fn step(value: u8) -> Result<GuardianEffectStepV1, GuardianReducerError> {
    use GuardianEffectStepV1::*;
    match value {
        0 => Ok(ProgramNetworkLeaseGate),
        1 => Ok(DefaultDropNetwork),
        2 => Ok(RequestPayloadFreeze),
        3 => Ok(StopPayload),
        4 => Ok(VerifyOldWorkerDead),
        5 => Ok(StartGuardianWorker),
        6 => Ok(ReleasePayload),
        7 => Ok(ProgramRenewalTimer),
        8 => Ok(TraverseHost),
        9 => Ok(TraverseStorage),
        10 => Ok(TraverseMount),
        11 => Ok(TraverseNetwork),
        12 => Ok(VerifyCompleteState),
        _ => Err(GuardianReducerError::ObservationMismatch),
    }
}
fn phase(value: GuardianReducerPhaseV1) -> u8 {
    super::guardian_phase_code(value)
}
fn phase_decode(value: u8) -> Result<GuardianReducerPhaseV1, GuardianReducerError> {
    match value {
        0 => Ok(GuardianReducerPhaseV1::Frozen),
        1 => Ok(GuardianReducerPhaseV1::EffectUnknown),
        2 => Ok(GuardianReducerPhaseV1::ReleaseFrozen),
        3 => Ok(GuardianReducerPhaseV1::ReissueFrozen),
        4 => Ok(GuardianReducerPhaseV1::Observed),
        5 => Ok(GuardianReducerPhaseV1::PlanExposed),
        _ => Err(GuardianReducerError::ObservationMismatch),
    }
}
fn override_code(value: GuardianContainmentOverrideV1) -> u8 {
    match value {
        GuardianContainmentOverrideV1::EarlyFreeze => 0,
        GuardianContainmentOverrideV1::Expire => 1,
        GuardianContainmentOverrideV1::EnforcementLoss => 2,
    }
}
fn override_decode(value: u8) -> Result<GuardianContainmentOverrideV1, GuardianReducerError> {
    match value {
        0 => Ok(GuardianContainmentOverrideV1::EarlyFreeze),
        1 => Ok(GuardianContainmentOverrideV1::Expire),
        2 => Ok(GuardianContainmentOverrideV1::EnforcementLoss),
        _ => Err(GuardianReducerError::ObservationMismatch),
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
            .is_some_and(|length| length <= MAXIMUM_GUARDIAN_CHECKPOINT_BYTES)
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
    ) -> Result<(), GuardianReducerError> {
        let count = u32::try_from(values.len()).map_err(|_| GuardianReducerError::Exhausted)?;
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
    fn array<const N: usize>(&mut self) -> Result<[u8; N], GuardianReducerError> {
        let end = self
            .cursor
            .checked_add(N)
            .ok_or(GuardianReducerError::ObservationMismatch)?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or(GuardianReducerError::ObservationMismatch)?
            .try_into()
            .map_err(|_| GuardianReducerError::ObservationMismatch)?;
        self.cursor = end;
        Ok(value)
    }
    fn u8(&mut self) -> Result<u8, GuardianReducerError> {
        Ok(self.array::<1>()?[0])
    }
    fn u32(&mut self) -> Result<u32, GuardianReducerError> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, GuardianReducerError> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn boolean(&mut self) -> Result<bool, GuardianReducerError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(GuardianReducerError::ObservationMismatch),
        }
    }
    fn digest(&mut self) -> Result<ObjectDigest, GuardianReducerError> {
        Ok(ObjectDigest::from_bytes(self.array()?))
    }
    fn optional_digest(&mut self) -> Result<Option<ObjectDigest>, GuardianReducerError> {
        self.optional(Self::digest)
    }
    fn optional_u64(&mut self) -> Result<Option<u64>, GuardianReducerError> {
        self.optional(Self::u64)
    }
    fn optional<T>(
        &mut self,
        decode: fn(&mut Self) -> Result<T, GuardianReducerError>,
    ) -> Result<Option<T>, GuardianReducerError> {
        match self.u8()? {
            0 => Ok(None),
            1 => decode(self).map(Some),
            _ => Err(GuardianReducerError::ObservationMismatch),
        }
    }
    fn sequence<T>(
        &mut self,
        maximum_count: usize,
        decode: fn(&mut Self) -> Result<T, GuardianReducerError>,
    ) -> Result<Vec<T>, GuardianReducerError> {
        let count = self.u32()? as usize;
        if count > maximum_count {
            return Err(GuardianReducerError::Exhausted);
        }
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            values.push(decode(self)?);
        }
        Ok(values)
    }
    fn finish(self) -> Result<(), GuardianReducerError> {
        if self.cursor == self.bytes.len() {
            Ok(())
        } else {
            Err(GuardianReducerError::ObservationMismatch)
        }
    }
}

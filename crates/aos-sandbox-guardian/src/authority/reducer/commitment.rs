//! Canonical domain-separated commitments for the Guardian reducer.

use aos_sandbox_core::{LeaseAssignment, ObjectDigest};
use sha2::{Digest as _, Sha256};

use super::{
    GuardianAuthoritySnapshotV1, GuardianEffectReceiptV1, GuardianManagedStateV1,
    GuardianNetworkFenceV1, GuardianReducerActionV1, GuardianRenewalTimerV1,
    ProtectedGuardianCauseEvidenceV1, ProtectedGuardianOutcomeV1,
};

const AUTHORITY_DOMAIN: &[u8] = b"aos.sandbox.guardian.reducer-authority.v1\0";
const NETWORK_FENCE_DOMAIN: &[u8] = b"aos.sandbox.guardian.network-fence.v1\0";
const MANAGED_SNAPSHOT_DOMAIN: &[u8] = b"aos.sandbox.guardian.managed-snapshot.v1\0";
const ADMISSION_DOMAIN: &[u8] = b"aos.sandbox.guardian.effect-admission.v1\0";
const RECEIPT_DOMAIN: &[u8] = b"aos.sandbox.guardian.effect-receipt.v1\0";

pub(super) fn authority_digest(value: GuardianAuthoritySnapshotV1) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(AUTHORITY_DOMAIN);
    update_assignment(&mut digest, value.assignment);
    digest.update(value.node.as_bytes());
    digest.update(value.desired_generation.to_be_bytes());
    digest.update(value.plan_digest.as_bytes());
    digest.update(value.lease_generation.to_be_bytes());
    digest.update(value.lease_digest.as_bytes());
    digest.update(value.host_boot_id);
    digest.update(value.clock_provenance);
    digest.update(value.fail_stop_boottime_nanoseconds.to_be_bytes());
    digest.update(value.durable_state_digest.as_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

pub(super) fn network_fence_digest(value: GuardianNetworkFenceV1) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(NETWORK_FENCE_DOMAIN);
    update_assignment(&mut digest, value.assignment);
    digest.update(value.network_handle);
    digest.update(value.kernel_boot_id);
    digest.update(value.namespace_device.to_be_bytes());
    digest.update(value.namespace_inode.to_be_bytes());
    digest.update(value.network_kernel_identity_digest.as_bytes());
    digest.update(value.kernel_plan_digest.as_bytes());
    digest.update(value.packet_policy_digest.as_bytes());
    digest.update(value.tc_gate_binding_digest.as_bytes());
    digest.update(value.network_resource_digest.as_bytes());
    digest.update(value.network_catalog_digest.as_bytes());
    digest.update(value.lease_generation.to_be_bytes());
    digest.update(value.lease_digest.as_bytes());
    digest.update(value.fail_stop_boottime_nanoseconds.to_be_bytes());
    digest.update(value.session_digest.as_bytes());
    digest.update(value.currentness_digest.as_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

pub(super) fn managed_snapshot_digest(
    assignment: LeaseAssignment,
    entries: [GuardianManagedStateV1; 4],
    observed_boottime_nanoseconds: u64,
    session_digest: ObjectDigest,
    currentness_digest: ObjectDigest,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(MANAGED_SNAPSHOT_DOMAIN);
    update_assignment(&mut digest, assignment);
    for entry in entries {
        digest.update([entry.domain as u8, entry.status as u8]);
        digest.update(entry.generation.to_be_bytes());
        digest.update(entry.resource_digest.as_bytes());
        digest.update(entry.observation_digest.as_bytes());
        digest.update(entry.catalog_digest.as_bytes());
        digest.update(entry.currentness_digest.as_bytes());
    }
    digest.update(observed_boottime_nanoseconds.to_be_bytes());
    digest.update(session_digest.as_bytes());
    digest.update(currentness_digest.as_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn admission_digest(
    request_id: [u8; 16],
    sequence: u64,
    action: GuardianReducerActionV1,
    authority_digest: ObjectDigest,
    network_digest: ObjectDigest,
    managed_digest: ObjectDigest,
    timer: GuardianRenewalTimerV1,
    worker_digest: ObjectDigest,
    replacement_digest: Option<ObjectDigest>,
    predecessor_receipt_digest: Option<ObjectDigest>,
    cause_evidence: Option<ProtectedGuardianCauseEvidenceV1>,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(ADMISSION_DOMAIN);
    digest.update(request_id);
    digest.update(sequence.to_be_bytes());
    digest.update([action as u8]);
    digest.update(authority_digest.as_bytes());
    digest.update(network_digest.as_bytes());
    digest.update(managed_digest.as_bytes());
    digest.update(timer.host_boot_id);
    digest.update(timer.clock_provenance);
    digest.update(timer.armed_boottime_nanoseconds.to_be_bytes());
    digest.update(timer.early_freeze_boottime_nanoseconds.to_be_bytes());
    digest.update(timer.hard_stop_boottime_nanoseconds.to_be_bytes());
    digest.update(timer.policy_digest.as_bytes());
    digest.update(worker_digest.as_bytes());
    match replacement_digest {
        None => digest.update([0; 33]),
        Some(value) => {
            digest.update([1]);
            digest.update(value.as_bytes());
        }
    }
    update_optional_digest(&mut digest, predecessor_receipt_digest);
    match cause_evidence {
        None => digest.update([0]),
        Some(value) => {
            digest.update([1, value.kind as u8]);
            digest.update(value.digest.as_bytes());
        }
    }
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn update_optional_digest(digest: &mut Sha256, value: Option<ObjectDigest>) {
    match value {
        None => digest.update([0; 33]),
        Some(value) => {
            digest.update([1]);
            digest.update(value.as_bytes());
        }
    }
}

pub(super) fn guardian_outcome_digest(outcome: &ProtectedGuardianOutcomeV1) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.guardian.effect-observation.v1\0");
    digest.update(outcome.admission_digest.as_bytes());
    digest.update(outcome.authority_digest.as_bytes());
    digest.update(outcome.network_fence_digest.as_bytes());
    digest.update(outcome.worker_identity_digest.as_bytes());
    digest.update(outcome.worker_resource_digest.as_bytes());
    digest.update(outcome.worker_currentness_digest.as_bytes());
    digest.update(outcome.managed.digest().as_bytes());
    digest.update(outcome.observation_ordinal.to_be_bytes());
    digest.update(outcome.effect_evidence_digest.as_bytes());
    digest.update(outcome.step_attempt_digest.as_bytes());
    digest.update(outcome.release_digest.as_bytes());
    digest.update(outcome.predecessor_digest.as_bytes());
    digest.update(outcome.first_snapshot_digest.as_bytes());
    digest.update(outcome.second_snapshot_digest.as_bytes());
    digest.update([
        u8::from(outcome.old_worker_dead),
        u8::from(outcome.admitted_worker_live),
        u8::from(outcome.network_default_drop),
        u8::from(outcome.payload_frozen),
        u8::from(outcome.payload_stopped),
        u8::from(outcome.renewal_timer_current),
        u8::from(outcome.network_lease_gate_current),
        u8::from(outcome.payload_released),
    ]);
    ObjectDigest::from_bytes(digest.finalize().into())
}

pub(super) fn receipt_digest(receipt: GuardianEffectReceiptV1) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(RECEIPT_DOMAIN);
    digest.update(receipt.request_id);
    digest.update(receipt.sequence.to_be_bytes());
    digest.update([receipt.admitted_action as u8]);
    digest.update([receipt.action as u8]);
    digest.update(receipt.admission_digest.as_bytes());
    digest.update(receipt.authority_digest.as_bytes());
    digest.update(receipt.network_fence_digest.as_bytes());
    digest.update(receipt.managed_snapshot_digest.as_bytes());
    digest.update(receipt.observation_digest.as_bytes());
    digest.update(receipt.step_evidence_count.to_be_bytes());
    digest.update(receipt.step_evidence_anchor.as_bytes());
    digest.update(receipt.last_released_boottime_nanoseconds.to_be_bytes());
    digest.update(receipt.last_released_observation_ordinal.to_be_bytes());
    digest.update(receipt.last_observation_ordinal.to_be_bytes());
    update_optional_digest(&mut digest, receipt.worker_death_supersession_digest);
    digest.update([u8::from(receipt.terminal)]);
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn update_assignment(digest: &mut Sha256, assignment: LeaseAssignment) {
    digest.update(assignment.sandbox().as_bytes());
    digest.update(assignment.incarnation().as_bytes());
    digest.update(assignment.epoch().get().to_be_bytes());
    digest.update(assignment.digest().as_bytes());
}

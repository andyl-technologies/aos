//! Protected current validation and ordered plans for Guardian effects.

use aos_sandbox_core::ObjectDigest;

use super::{
    GuardianEffectStepV1, GuardianReducerActionV1, GuardianReducerError, PendingGuardianEffectV1,
    ProtectedGuardianCurrentV1, ProtectedGuardianOutcomeV1, pending_effect_action,
};

pub(super) fn validate_guardian_effect_current(
    reducer_digest: ObjectDigest,
    prior_network_digest: ObjectDigest,
    pending: PendingGuardianEffectV1,
    current: ProtectedGuardianCurrentV1,
) -> Result<(), GuardianReducerError> {
    let admission = pending.admission;
    let expected_managed = pending.observed_managed.unwrap_or(admission.managed);
    let expected_worker_identity = admission
        .replacement_worker_digest
        .unwrap_or(admission.worker_identity_digest);
    if current.admission_digest != admission.digest()
        || current.durable_reducer_digest != reducer_digest
        || current.authority_digest != admission.authority.digest()
        || current.prior_network_fence_digest != prior_network_digest
        || current.admitted_network_fence_digest != admission.network.digest()
        || current.managed.digest() != current.managed_snapshot_digest
        || !current
            .managed
            .refreshes_same_managed_state(expected_managed)
        || !current.managed.matches_network_resource(admission.network)
        || current.host_boot_id != admission.timer.host_boot_id
        || current.clock_provenance != admission.timer.clock_provenance
        || current.observed_boottime_nanoseconds == 0
        || current.observed_boottime_nanoseconds != current.managed.observed_boottime_nanoseconds()
        || current.observation_ordinal == 0
        || admission
            .cause_evidence
            .is_some_and(|cause| current.observation_ordinal <= cause.observation_ordinal)
        || current.worker_identity_digest != expected_worker_identity
        || current.worker_resource_digest.as_bytes() == &[0; 32]
        || current.worker_currentness_digest.as_bytes() == &[0; 32]
        || current.current_worker_live == current.admitted_worker_absent
        || current.observed_boottime_nanoseconds < expected_managed.observed_boottime_nanoseconds()
        || current.observed_boottime_nanoseconds < admission.timer.armed_boottime_nanoseconds
    {
        return Err(GuardianReducerError::CurrentnessMismatch);
    }

    let now = current.observed_boottime_nanoseconds;
    match pending_effect_action(pending) {
        GuardianReducerActionV1::Arm
        | GuardianReducerActionV1::Renew
        | GuardianReducerActionV1::ReplaceWorker
        | GuardianReducerActionV1::Resume
            if now >= admission.timer.early_freeze_boottime_nanoseconds() =>
        {
            Err(GuardianReducerError::TimerMismatch)
        }
        GuardianReducerActionV1::Expire
            if now < admission.timer.hard_stop_boottime_nanoseconds() =>
        {
            Err(GuardianReducerError::TimerMismatch)
        }
        GuardianReducerActionV1::EarlyFreeze
            if now < admission.timer.early_freeze_boottime_nanoseconds()
                || now >= admission.timer.hard_stop_boottime_nanoseconds() =>
        {
            Err(GuardianReducerError::TimerMismatch)
        }
        GuardianReducerActionV1::Renew | GuardianReducerActionV1::EarlyFreeze
            if !current.current_worker_live =>
        {
            Err(GuardianReducerError::CurrentnessMismatch)
        }
        GuardianReducerActionV1::Arm
            if pending.phase == super::GuardianReducerPhaseV1::Frozen
                && current.current_worker_live =>
        {
            Err(GuardianReducerError::CurrentnessMismatch)
        }
        GuardianReducerActionV1::ReplaceWorker if !current.old_worker_dead => {
            Err(GuardianReducerError::OldWorkerStillLive)
        }
        GuardianReducerActionV1::Arm | GuardianReducerActionV1::ReplaceWorker
            if !current.current_worker_live && !current.admitted_worker_absent =>
        {
            Err(GuardianReducerError::CurrentnessMismatch)
        }
        GuardianReducerActionV1::Resume
            if !current.current_worker_live
                && (!current.old_worker_dead || !current.admitted_worker_absent) =>
        {
            Err(GuardianReducerError::CurrentnessMismatch)
        }
        _ => Ok(()),
    }
}

pub(super) fn next_effect_step_from_outcome(
    action: GuardianReducerActionV1,
    outcome: &ProtectedGuardianOutcomeV1,
) -> Option<GuardianEffectStepV1> {
    let current = ProtectedGuardianCurrentV1 {
        admission_digest: outcome.admission_digest,
        durable_reducer_digest: ObjectDigest::from_bytes([0; 32]),
        authority_digest: outcome.authority_digest,
        prior_network_fence_digest: outcome.network_fence_digest,
        admitted_network_fence_digest: outcome.network_fence_digest,
        managed_snapshot_digest: outcome.managed.digest(),
        managed: outcome.managed,
        host_boot_id: [0; 16],
        clock_provenance: [0; 16],
        observed_boottime_nanoseconds: outcome.managed.observed_boottime_nanoseconds(),
        observation_ordinal: outcome.observation_ordinal,
        worker_identity_digest: outcome.worker_identity_digest,
        worker_resource_digest: outcome.worker_resource_digest,
        worker_currentness_digest: outcome.worker_currentness_digest,
        current_worker_live: outcome.admitted_worker_live,
        old_worker_dead: outcome.old_worker_dead,
        admitted_worker_absent: !outcome.admitted_worker_live,
        network_default_drop: outcome.network_default_drop,
        renewal_timer_current: outcome.renewal_timer_current,
        network_lease_gate_current: outcome.network_lease_gate_current,
        payload_frozen: outcome.payload_frozen,
        payload_stopped: outcome.payload_stopped,
        payload_released: outcome.payload_released,
    };
    next_effect_step(action, current)
}

pub(super) fn next_effect_step(
    action: GuardianReducerActionV1,
    current: ProtectedGuardianCurrentV1,
) -> Option<GuardianEffectStepV1> {
    use GuardianEffectStepV1 as Step;

    match action {
        GuardianReducerActionV1::Arm => {
            if !current.current_worker_live {
                Some(Step::StartGuardianWorker)
            } else if !current.renewal_timer_current {
                Some(Step::ProgramRenewalTimer)
            } else if !current.network_lease_gate_current {
                Some(Step::ProgramNetworkLeaseGate)
            } else if !current.payload_released {
                Some(Step::ReleasePayload)
            } else {
                None
            }
        }
        GuardianReducerActionV1::Renew => {
            if !current.network_lease_gate_current {
                Some(Step::ProgramNetworkLeaseGate)
            } else if !current.renewal_timer_current {
                Some(Step::ProgramRenewalTimer)
            } else {
                None
            }
        }
        GuardianReducerActionV1::EarlyFreeze => {
            (!current.payload_frozen).then_some(Step::RequestPayloadFreeze)
        }
        GuardianReducerActionV1::Revoke
        | GuardianReducerActionV1::Expire
        | GuardianReducerActionV1::EnforcementLoss => {
            if !current.network_default_drop {
                Some(Step::DefaultDropNetwork)
            } else if !current.payload_frozen {
                Some(Step::RequestPayloadFreeze)
            } else if !current.payload_stopped {
                Some(Step::StopPayload)
            } else {
                None
            }
        }
        GuardianReducerActionV1::ReplaceWorker => {
            if current.admitted_worker_absent {
                Some(Step::StartGuardianWorker)
            } else if !current.renewal_timer_current {
                Some(Step::ProgramRenewalTimer)
            } else {
                None
            }
        }
        GuardianReducerActionV1::Cleanup => {
            if !current.network_default_drop {
                Some(Step::DefaultDropNetwork)
            } else if !current.payload_stopped {
                Some(Step::StopPayload)
            } else if !current.old_worker_dead {
                Some(Step::VerifyOldWorkerDead)
            } else if !matches!(
                current.managed.entries()[0].status(),
                super::GuardianManagedStatusV1::Absent | super::GuardianManagedStatusV1::Released
            ) {
                Some(Step::TraverseHost)
            } else if !matches!(
                current.managed.entries()[1].status(),
                super::GuardianManagedStatusV1::Absent | super::GuardianManagedStatusV1::Released
            ) {
                Some(Step::TraverseStorage)
            } else if !matches!(
                current.managed.entries()[2].status(),
                super::GuardianManagedStatusV1::Absent | super::GuardianManagedStatusV1::Released
            ) {
                Some(Step::TraverseMount)
            } else if !matches!(
                current.managed.entries()[3].status(),
                super::GuardianManagedStatusV1::Absent | super::GuardianManagedStatusV1::Released
            ) {
                Some(Step::TraverseNetwork)
            } else {
                None
            }
        }
        GuardianReducerActionV1::Resume => {
            if !current.current_worker_live {
                Some(Step::StartGuardianWorker)
            } else if !current.renewal_timer_current {
                Some(Step::ProgramRenewalTimer)
            } else if !current.network_lease_gate_current {
                Some(Step::ProgramNetworkLeaseGate)
            } else if !current.payload_released {
                Some(Step::ReleasePayload)
            } else {
                None
            }
        }
    }
}

//! Operator-visible recovery work derived solely from durable current state.

use super::*;

pub(crate) fn recovery_work(
    attempts: &BTreeMap<AttemptKeyV1, crate::model::AttemptRecordV1>,
    acquisitions: &BTreeMap<AcquisitionKeyV1, crate::model::AcquisitionRecordV1>,
    native_completions: &BTreeMap<
        ObjectDigest,
        crate::ledger::native_completion::NativeAcquireCompletionRecordV2,
    >,
) -> Vec<ProviderRecoveryWorkV1> {
    recovery_work_for_profiles(
        attempts,
        acquisitions,
        &native_completions.keys().copied().collect(),
    )
}

pub(super) fn recovery_work_for_profiles(
    attempts: &BTreeMap<AttemptKeyV1, crate::model::AttemptRecordV1>,
    acquisitions: &BTreeMap<AcquisitionKeyV1, crate::model::AcquisitionRecordV1>,
    native: &BTreeSet<ObjectDigest>,
) -> Vec<ProviderRecoveryWorkV1> {
    let mut work: Vec<_> = acquisitions
        .values()
        // Native acceptance can only retain the original FD. Generic backend
        // observation or reopen would create an unrelated cold remount.
        .filter(|record| !native.contains(&record.acquisition_id))
        .filter_map(|record| match record.state {
            ProviderAcquisitionStateV1::Applying => Some(ProviderRecoveryWorkV1::ObserveApplying {
                acquisition_id: record.acquisition_id,
                effect_id: record.effect_id,
            }),
            ProviderAcquisitionStateV1::Releasing => {
                record
                    .release_effect_id
                    .map(|effect_id| ProviderRecoveryWorkV1::ObserveReleasing {
                        acquisition_id: record.acquisition_id,
                        effect_id,
                    })
            }
            ProviderAcquisitionStateV1::Active => (!attempts.values().any(|attempt| {
                attempt.state == ProviderAttemptStateV1::Reserved
                    && attempt.method == SourceProviderMethod::Acquire
                    && attempt.provider == record.provider
                    && attempt.holder == record.holder
                    && attempt.operation_intent_digest == record.normalized_intent.digest()
            }))
            .then_some(ProviderRecoveryWorkV1::ReopenActive {
                acquisition_id: record.acquisition_id,
                backend_id: record.backend_id,
            }),
            ProviderAcquisitionStateV1::Pending => Some(ProviderRecoveryWorkV1::ObservePending {
                acquisition_id: record.acquisition_id,
                backend_id: record.backend_id,
            }),
            ProviderAcquisitionStateV1::Released | ProviderAcquisitionStateV1::Faulted => None,
        })
        .collect();
    work.extend(attempts.values().filter_map(|attempt| {
        (attempt.state == ProviderAttemptStateV1::Reserved
            && attempt.method == SourceProviderMethod::Inventory)
            .then_some(ProviderRecoveryWorkV1::ObserveInventoryReservation {
                attempt_digest: attempt.attempt_digest,
            })
    }));
    work.extend(attempts.values().filter_map(|attempt| {
        if attempt.state != ProviderAttemptStateV1::Reserved
            || attempt.method != SourceProviderMethod::Acquire
            || acquisitions
                .values()
                .any(|record| record.current_attempt_digest == attempt.attempt_digest)
        {
            return None;
        }
        acquisitions
            .values()
            .find(|record| {
                !native.contains(&record.acquisition_id)
                    && record.state == ProviderAcquisitionStateV1::Active
                    && record.provider == attempt.provider
                    && record.holder == attempt.holder
                    && record.normalized_intent.digest() == attempt.operation_intent_digest
            })
            .map(|record| ProviderRecoveryWorkV1::ObserveAcquireRebind {
                acquisition_id: record.acquisition_id,
                attempt_digest: attempt.attempt_digest,
            })
    }));
    work
}

//! Bounded classification of unresolved physical and admission recovery work.

use super::*;

pub(super) fn classify_work(
    payload: &CacheAtomicObjectPayloadV1,
    maximum: usize,
) -> Result<Vec<CacheRecoveryWorkV1>, RecoveryError> {
    let record_digest = payload.record.digest;
    let mut work = Vec::with_capacity(3);
    if matches!(
        payload.progress.stage,
        AdmissionStageV1::PrivateDestinationCreated
            | AdmissionStageV1::ContentTransferred
            | AdmissionStageV1::ContentVerified
            | AdmissionStageV1::WritersClosed
            | AdmissionStageV1::SealEnabledAndVerified
            | AdmissionStageV1::InodeSynced
            | AdmissionStageV1::CanonicalNamePublished
            | AdmissionStageV1::ParentSynced
    ) {
        push_recovery_work(
            &mut work,
            maximum,
            CacheRecoveryWorkV1::ObservePreparedArtifact {
                operation: payload.plan.operation,
                record_digest,
            },
        )?;
    }
    if payload.reservation.state == ReservationStateV1::Uncertain {
        push_recovery_work(
            &mut work,
            maximum,
            CacheRecoveryWorkV1::ObserveUncertainReservation {
                operation: payload.plan.operation,
                record_digest,
            },
        )?;
    }
    let mut quarantine_reported = false;
    if let Some(plan) = &payload.eviction_plan
        && let Some(progress) = payload
            .eviction_progress
            .iter()
            .find(|progress| progress.candidate.descriptor == payload.plan.descriptor)
    {
        match progress.state {
            EvictionCandidateStateV1::Deleting | EvictionCandidateStateV1::UnlinkAmbiguous => {
                push_recovery_work(
                    &mut work,
                    maximum,
                    CacheRecoveryWorkV1::ObserveDeletingObject {
                        operation: plan.operation,
                        record_digest,
                    },
                )?;
            }
            EvictionCandidateStateV1::RemovedAwaitingReclaim => {
                push_recovery_work(
                    &mut work,
                    maximum,
                    CacheRecoveryWorkV1::ObserveRemovedBacking {
                        operation: plan.operation,
                        record_digest,
                    },
                )?;
            }
            EvictionCandidateStateV1::Quarantined => {
                push_recovery_work(
                    &mut work,
                    maximum,
                    CacheRecoveryWorkV1::DiagnoseQuarantine {
                        operation: plan.operation,
                        record_digest,
                    },
                )?;
                quarantine_reported = true;
            }
            EvictionCandidateStateV1::Selected
            | EvictionCandidateStateV1::RestoredBeforeEffect
            | EvictionCandidateStateV1::Reclaimed
            | EvictionCandidateStateV1::RestoredAfterRename => {}
        }
    }
    if !quarantine_reported
        && (payload.progress.stage == AdmissionStageV1::Quarantined
            || payload
                .catalog
                .as_ref()
                .is_some_and(|entry| entry.presence == CatalogPresenceV1::Quarantined))
    {
        push_recovery_work(
            &mut work,
            maximum,
            CacheRecoveryWorkV1::DiagnoseQuarantine {
                operation: payload.plan.operation,
                record_digest,
            },
        )?;
    }
    for pin in &payload.pins {
        if matches!(
            pin.kind,
            CachePinKindV1::KernelReference | CachePinKindV1::BackingRegistration
        ) {
            push_recovery_work(
                &mut work,
                maximum,
                CacheRecoveryWorkV1::ObservePhysicalPinDrain {
                    operation: payload.plan.operation,
                    pin: pin.id,
                    record_digest,
                },
            )?;
        }
    }
    Ok(work)
}

pub(super) fn push_recovery_work(
    work: &mut Vec<CacheRecoveryWorkV1>,
    maximum: usize,
    item: CacheRecoveryWorkV1,
) -> Result<(), RecoveryError> {
    if work.len() >= maximum {
        return Err(RecoveryError::Capacity);
    }
    work.push(item);
    Ok(())
}

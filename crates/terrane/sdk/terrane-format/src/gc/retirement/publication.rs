//! Checks selected v2 retirement control changes and their owner associations.
//!
//! Whole canonical values are compared here. Actual selection, pointed-to
//! history, held authority and backend effects remain private runtime checks.

use super::*;
use crate::gc::publication::{LogicalChange, PublicationProof, PublicationTransaction};
use alloc::boxed::Box;

enum Control {
    Preparation(Box<CopiedRetirementPreparation>),
    Operation(Box<PermanentDeleteOperation>),
}

impl Control {
    fn decode(bytes: &[u8], key: &str, binding: &BackendBinding) -> Result<Self, PublicationError> {
        if let Ok(preparation) = CopiedRetirementPreparation::decode(bytes) {
            preparation
                .plan
                .check_key(key)
                .map_err(|_| PublicationError::Contradiction)?;
            if &preparation.plan.backend != binding {
                return Err(PublicationError::Contradiction);
            }
            return Ok(Self::Preparation(Box::new(preparation)));
        }

        let operation =
            PermanentDeleteOperation::decode(bytes).map_err(|_| PublicationError::Schema)?;
        operation
            .authorization
            .check_key(key)
            .map_err(|_| PublicationError::Contradiction)?;
        if operation.authorization.backend() != binding {
            return Err(PublicationError::Contradiction);
        }
        Ok(Self::Operation(Box::new(operation)))
    }
}

fn old_state(record: &PublicationTransaction) -> Result<&PublicationState, PublicationError> {
    record.old.as_ref().ok_or(PublicationError::Contradiction)
}

fn selector(
    operation: &PermanentDeleteOperation,
    key: &str,
) -> Result<PermanentBurnOwner, PublicationError> {
    let bytes = operation
        .authorization
        .encode()
        .map_err(|_| PublicationError::Schema)?;
    Ok(PermanentBurnOwner {
        pack: operation.authorization.exclusion().pack,
        selection: PermanentOwnerSelection::Permanent(RecordPointer {
            key: key.into(),
            digest: *blake3::hash(&bytes).as_bytes(),
        }),
    })
}

fn raw_preserves_state(record: &PublicationTransaction) -> Result<(), PublicationError> {
    let old = old_state(record)?;
    if !matches!(record.proof, PublicationProof::Raw)
        || old.burn_owners != record.new.burn_owners
        || old.guard != record.new.guard
        || old.loss_generation != record.new.loss_generation
        || old.sources != record.new.sources
    {
        return Err(PublicationError::Contradiction);
    }
    Ok(())
}

fn copied_visibility(state: &PublicationState, pack: &[u8; 16]) -> Result<(), PublicationError> {
    if state.guard.is_none()
        || !state.burn_owners.as_ref().is_some_and(|owners| {
            owners.iter().any(|owner| {
                &owner.pack == pack && owner.selection == PermanentOwnerSelection::CopiedVisibility
            })
        })
    {
        return Err(PublicationError::Contradiction);
    }
    Ok(())
}

fn ownership_proposal(
    record: &PublicationTransaction,
    operation: &PermanentDeleteOperation,
    key: &str,
) -> Result<(), PublicationError> {
    let PublicationProof::PermanentRetirement { authorization, .. } = &record.proof else {
        return Err(PublicationError::Contradiction);
    };
    let bytes = operation
        .authorization
        .encode()
        .map_err(|_| PublicationError::Schema)?;
    if operation.phase != OperationPhase::Proposed
        || &bytes != authorization
        || !record.new.burn_owners.as_ref().is_some_and(|owners| {
            selector(operation, key).is_ok_and(|expected| owners.contains(&expected))
        })
    {
        return Err(PublicationError::Contradiction);
    }
    Ok(())
}

/// Checks a complete selected control change without granting effect permission.
///
/// # Errors
/// Rejects local-v1/unknown values, wrong keys, changed plans or authorization,
/// phase/revision contradictions and missing represented ownership associations.
pub(crate) fn check_change(
    record: &PublicationTransaction,
    change: &LogicalChange,
) -> Result<(), PublicationError> {
    let next = Control::decode(
        change
            .new
            .as_deref()
            .ok_or(PublicationError::Contradiction)?,
        &change.key,
        &record.new.binding,
    )?;
    let previous = change
        .expected
        .as_deref()
        .map(|bytes| Control::decode(bytes, &change.key, &record.new.binding))
        .transpose()?;

    match (previous, next) {
        (None, Control::Preparation(next)) => {
            raw_preserves_state(record)?;
            let old = old_state(record)?;
            copied_visibility(old, &next.plan.exclusion.pack)?;
            let revision = super::validation::fence_revision(&next.plan.fence)
                .map_err(|_| PublicationError::Schema)?;
            if next.revision != 0
                || next.phase != PreparationPhase::Preparing
                || revision != old.revision
            {
                return Err(PublicationError::Contradiction);
            }
        }
        (Some(Control::Preparation(previous)), Control::Preparation(next)) => {
            raw_preserves_state(record)?;
            copied_visibility(old_state(record)?, &next.plan.exclusion.pack)?;
            previous
                .check_successor(&next)
                .map_err(|_| PublicationError::Contradiction)?;
        }
        (Some(Control::Preparation(previous)), Control::Operation(next)) => {
            ownership_proposal(record, &next, &change.key)?;
            let PermanentDeleteAuthorization::Copied(authorization) = &next.authorization else {
                return Err(PublicationError::Contradiction);
            };
            authorization
                .check_preparation(&previous, &authorization.preparation)
                .map_err(|_| PublicationError::Contradiction)?;
            let old = old_state(record)?;
            if next.revision
                != previous
                    .revision
                    .checked_add(1)
                    .ok_or(PublicationError::Exhausted)?
                || authorization.preparation.revision == old.revision
                    && record
                        .predecessor
                        .as_ref()
                        .is_none_or(|slot| slot.digest != authorization.preparation.digest)
            {
                return Err(PublicationError::Contradiction);
            }
        }
        (None, Control::Operation(next)) => {
            ownership_proposal(record, &next, &change.key)?;
            if next.revision != 0
                || !matches!(next.authorization, PermanentDeleteAuthorization::Sweep(_))
            {
                return Err(PublicationError::Contradiction);
            }
        }
        (Some(Control::Operation(previous)), Control::Operation(next)) => {
            // An ordinary remote proposal can already be staged at its physical
            // cache. Selecting those exact bytes is its first owner transition.
            if matches!(record.proof, PublicationProof::PermanentRetirement { .. }) {
                ownership_proposal(record, &next, &change.key)?;
                if previous != next
                    || next.revision != 0
                    || !matches!(next.authorization, PermanentDeleteAuthorization::Sweep(_))
                {
                    return Err(PublicationError::Contradiction);
                }
            } else {
                raw_preserves_state(record)?;
                previous
                    .check_successor(&next)
                    .map_err(|_| PublicationError::Contradiction)?;
                let old = old_state(record)?;
                let selected = old.burn_owners.as_ref().is_some_and(|owners| {
                    selector(&next, &change.key).is_ok_and(|expected| owners.contains(&expected))
                });
                if next.phase == OperationPhase::Cancelled {
                    if old.burn_owners.as_ref().is_none_or(|owners| {
                        owners.iter().any(|owner| {
                            owner.pack == next.authorization.exclusion().pack
                                && matches!(owner.selection, PermanentOwnerSelection::Permanent(_))
                        })
                    }) {
                        return Err(PublicationError::Contradiction);
                    }
                } else {
                    let owner = next.owner.as_ref().ok_or(PublicationError::Contradiction)?;
                    if !selected
                        || owner.revision > old.revision
                        || owner.revision == old.revision
                            && record
                                .predecessor
                                .as_ref()
                                .is_none_or(|slot| slot.digest != owner.digest)
                    {
                        return Err(PublicationError::Contradiction);
                    }
                    let pointer = next.pass.as_ref().ok_or(PublicationError::Contradiction)?;
                    let (_, nonce, _) = super::validation::pass_key(&pointer.key)
                        .map_err(|_| PublicationError::Schema)?;
                    if nonce != record.nonce {
                        return Err(PublicationError::Contradiction);
                    }
                }
            }
        }
        _ => return Err(PublicationError::Contradiction),
    }
    Ok(())
}

/// Checks that case 3 selects the exact represented ownership proposal.
///
/// # Errors
/// Rejects a missing control change, a different immutable authorization or a
/// proposal unrelated to the newly selected permanent owner.
pub(crate) fn check_owner_change(record: &PublicationTransaction) -> Result<(), PublicationError> {
    let PublicationProof::PermanentRetirement { authorization, .. } = &record.proof else {
        return Ok(());
    };
    let authorization = PermanentDeleteAuthorization::decode(authorization)
        .map_err(|_| PublicationError::Schema)?;
    let owner = record
        .new
        .burn_owners
        .as_ref()
        .and_then(|owners| {
            owners
                .iter()
                .find(|owner| owner.pack == authorization.exclusion().pack)
        })
        .ok_or(PublicationError::Contradiction)?;
    let PermanentOwnerSelection::Permanent(pointer) = &owner.selection else {
        return Err(PublicationError::Contradiction);
    };
    if !record
        .changes
        .iter()
        .any(|change| change.key == pointer.key)
    {
        return Err(PublicationError::Contradiction);
    }
    Ok(())
}

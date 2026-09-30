//! Exact original Pending signature storage with retained attempted custody.
//!
//! The existing native5 owner engine derives the sidecar/floor transfer. This
//! adapter retains its complete candidate before transfer/preflight postchecks;
//! it never reconstructs Security's original receive or signing authority.

use aos_sandbox_protocol::mount_source_acquisition_state::native_held_completion::{
    has_original_pending_closed_cut_v5,
};

use super::*;

impl MountOriginalNativeJournalAuthorityV5<'_> {
    /// Prepares exact original8 storage before the same-carrier zero-FD send.
    ///
    /// The coupled candidate is parked in `slot` before any transfer/preflight
    /// postcheck. A candidate whose checks fail remains noncommittable.
    ///
    /// # Errors
    ///
    /// Rejects occupied custody, stale physical phase10/native3, a different
    /// signature input, changed original Pending companions, unfunded transfer
    /// or any unchanged opened limit that cannot retain the complete suffix.
    pub fn prepare_root_closed_store_v5(
        &self,
        phase10: &OriginalRootProtectedReadbackV5,
        signed: &SignedNativeHeldControlV1,
        slot: &mut Option<PreparedOriginalRootAppendV5>,
    ) -> Result<(), JournalError> {
        custody::PreparationBoundaryV5::new(slot).run(|slot| {
            if slot.is_some() {
                return Err(invalid());
            }

            self.validate_readback(phase10)?;
            let floor = phase10.floor().ok_or_else(invalid)?;
            if floor.request().future_transactions != 3 {
                return Err(invalid());
            }
            let owners = root_closed_owners(phase10.graph(), phase10.attempt(), floor, signed)?;
            let (transaction, next, old) = derive_continuation(
                &self.authority.journal.state,
                &owners,
                phase10.attempt(),
                self.authority.journal.limits,
            )?;
            *slot = Some(PreparedOriginalRootAppendV5 {
                transaction,
                snapshot: phase10.snapshot.clone(),
                attempt: phase10.attempt(),
                digest: [0; 32],
                floor: next,
                preflight_complete: false,
                failed: core::cell::Cell::new(false),
                attempted: core::cell::Cell::new(false),
                actual: None,
            });

            let candidate = slot.as_mut().ok_or_else(invalid)?;
            candidate.digest = authority_preflight_digest(std::slice::from_ref(&candidate.transaction));
            require_store_transfer(candidate, &old)?;
            validate_transfer(
                &candidate.transaction,
                &old,
                candidate.floor.as_ref(),
                self.authority.journal.limits,
            )?;
            // Begin/three records/Commit consume five physical sequence positions.
            phase10
                .sequence()
                .checked_add(5)
                .ok_or(JournalError::SequenceExhausted)?;
            self.preflight(&candidate.transaction, candidate.attempt)?;
            self.validate_readback(phase10)?;
            candidate.preflight_complete = true;

            Ok(())
        })
    }
}

fn root_closed_owners(
    graph: &RootNativeHeldGraphV2,
    attempt: [u8; 32],
    floor: &OriginalRootCapacityRecordV5,
    signed: &SignedNativeHeldControlV1,
) -> Result<JournalTransaction, JournalError> {
    let old = graph.sidecars().get(&attempt).ok_or_else(invalid)?;
    if old.suffix().phase() != 10
        || !has_original_pending_closed_cut_v5(graph, old).map_err(|_| invalid())?
        || old.settlement().is_some()
        || old.terminal_verifier().is_some()
        || signed.kind() != NativeHeldControlKindV1::RootClosed
        || old.suffix().prepared() != Some(signed.prepared())
        || floor.request().owner_id != attempt
        || floor.request().future_transactions != 3
        || floor.admission_cut() != old.admission_cut()
    {
        return Err(invalid());
    }
    let cut = old.disposition_cut().ok_or_else(invalid)?;
    let captured = cut
        .reconstruct(graph.legacy(), attempt)
        .map_err(|_| invalid())?;
    if captured.canonical_records().len() != 4
        || captured
            .canonical_records()
            .iter()
            .any(|(key, value)| graph.canonical_records().get(key) != Some(value))
    {
        return Err(invalid());
    }

    let mut controls = old.suffix().controls().to_vec();
    controls.push(signed.clone());
    let suffix = NativeHeldCompletionSuffixV1::new(
        NativeHeldOwnerV1::Root,
        11,
        old.suffix().flight(),
        None,
        controls,
    )
    .map_err(|_| invalid())?;
    let stored = RootNativeHeldSidecarV2::new(
        *old.original_scope(),
        old.response_transaction(),
        old.disposition().cloned(),
        old.settlement().cloned(),
        old.terminal_verifier().cloned(),
        suffix,
        old.admission_cut().clone(),
        old.disposition_cut().cloned(),
        old.no_interest_terminal().cloned(),
    )
    .map_err(|_| invalid())?;

    JournalTransaction::new(
        store_transaction_id(
            floor.admission_transaction_id(),
            cut.capture_transaction(),
            signed,
        ),
        vec![JournalRecord::put(
            RecordNamespace::MountSourceAcquisition,
            native_root_sidecar_key_v2(attempt).map_err(|_| invalid())?,
            stored.to_canonical_bytes().map_err(|_| invalid())?,
        )],
    )
}

fn store_transaction_id(
    admission: [u8; 16],
    capture: [u8; 16],
    signed: &SignedNativeHeldControlV1,
) -> [u8; 16] {
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.mount.original-rootclosed-store-tx.v5\0");
    digest.update(admission);
    digest.update(capture);
    digest.update(signed.to_canonical_bytes());

    let hash: [u8; 32] = digest.finalize().into();
    let mut transaction = [0; 16];
    transaction.copy_from_slice(&hash[..16]);
    transaction
}

fn require_store_transfer(
    candidate: &PreparedOriginalRootAppendV5,
    old: &OriginalRootCapacityRecordV5,
) -> Result<(), JournalError> {
    let next = candidate.floor.as_ref().ok_or_else(invalid)?;
    if candidate.transaction.records().len() != 3
        || old.request().future_transactions != 3
        || next.request().future_transactions != 2
        || next.original_prepared() != old.original_prepared()
        || next.admission_cut() != old.admission_cut()
        || next.admission_transaction_id() != old.admission_transaction_id()
    {
        return Err(invalid());
    }

    Ok(())
}

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(super) use tests::phase11_funded_data;

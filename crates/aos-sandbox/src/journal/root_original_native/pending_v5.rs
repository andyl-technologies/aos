//! Bounded Pending preview, exact Closed construction and physical frame joins.
//!
//! The preview contains only DATA. Coupled original native5 continuation,
//! opened limits, replay and protected readback remain owned by the parent.

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_protocol::mount_source_acquisition_state::{
    acquisition_key, provider_attempt_key, provider_head_key,
    native_held_completion::{RootNativeReconstructedCutV1, native_root_sidecar_key_v1},
    validate_mount_source_state_graph_v2,
};
use aos_sandbox_source_provider_protocol::native_held_completion::{
    NativeHeldSectionTagV1 as Tag,
    assertion::{
        NativeHeldDispositionV1, RootNativeDispositionAssertionV1, RootNativeObservationV1,
    },
    witness::NativeHeldOwnerWitnessV1,
};

use super::*;

impl MountOriginalNativeJournalAuthorityV5<'_> {
    /// Captures prospective Pending companions without granting an append.
    ///
    /// # Errors
    ///
    /// Rejects a stale readback, non-phase1 prefix, anything except the exact
    /// three legacy PUT keys, invalid complete legacy graph or Pending cut.
    pub fn prospective_original_pending_cut_v5(
        &self,
        phase1: &OriginalRootProtectedReadbackV5,
        owners: &JournalTransaction,
    ) -> Result<(RootNativeCutV1, RootNativeReconstructedCutV1, u64), JournalError> {
        self.validate_readback(phase1)?;
        let before = &phase1.graph;
        let old = before.sidecars().get(&phase1.attempt).ok_or_else(invalid)?;
        let original = before
            .legacy()
            .provider_attempts
            .get(&phase1.attempt)
            .ok_or_else(invalid)?;
        if old.suffix().phase() != 1 || old.disposition().is_some() {
            return Err(invalid());
        }

        let keys = BTreeSet::from([
            provider_attempt_key(original.attempt_id),
            acquisition_key(original.owner.owner_id()),
            provider_head_key(
                original.scope.holder_authority_id,
                original.scope.provider_authority_id,
            ),
        ]);
        if owners.records().len() != 3
            || owners.records().iter().any(|record| {
                record.namespace() != RecordNamespace::MountSourceAcquisition
                    || record.value().is_none()
                    || !keys.contains(record.key())
            })
            || owners
                .records()
                .iter()
                .map(|record| record.key())
                .collect::<BTreeSet<_>>()
                .len()
                != 3
        {
            return Err(invalid());
        }

        let mut successor = apply(&self.authority.journal.state, owners.records())?;
        // Remove only already validated retained sidecars for the independent
        // legacy preview. Callers cannot nominate another filtered snapshot.
        for attempt in before.sidecars().keys() {
            successor.remove(&(
                RecordNamespace::MountSourceAcquisition,
                native_root_sidecar_key_v2(*attempt).map_err(|_| invalid())?,
            ));
        }
        for attempt in before.v1_sidecars().keys() {
            successor.remove(&(
                RecordNamespace::MountSourceAcquisition,
                native_root_sidecar_key_v1(*attempt).map_err(|_| invalid())?,
            ));
        }

        let legacy = validate_mount_source_state_graph_v2(successor.iter().filter_map(
            |((namespace, key), value)| {
                (*namespace == RecordNamespace::MountSourceAcquisition)
                    .then_some((key.as_slice(), value.as_slice()))
            },
        ))
        .map_err(|_| invalid())?;
        let cut = RootNativeCutV1::capture(
            RootNativeCutKindV1::Disposition,
            *owners.id(),
            &legacy,
            phase1.attempt,
        )
        .map_err(|_| invalid())?;
        if !cut.is_pending_disposition() {
            return Err(invalid());
        }

        let captured = cut
            .reconstruct(&legacy, phase1.attempt)
            .map_err(|_| invalid())?;
        let sequence = phase1
            .sequence()
            .checked_add(8)
            .ok_or(JournalError::SequenceExhausted)?;
        Ok((cut, captured, sequence))
    }

    /// Prepares the exact four-owner Closed response and six-record funded append.
    ///
    /// # Errors
    ///
    /// Rejects another unsigned8, original witness facts, frame sequence,
    /// response successor, exact owner proposal or unchanged opened limit.
    pub fn prepare_original_pending_closed_v5(
        &self,
        phase1: &OriginalRootProtectedReadbackV5,
        owners: &JournalTransaction,
        unsigned8: &PreparedNativeHeldControlV1,
        slot: &mut Option<PreparedOriginalRootAppendV5>,
    ) -> Result<(), JournalError> {
        custody::PreparationBoundaryV5::new(slot).run(|slot| {
            if slot.is_some() {
                return Err(invalid());
            }

            let (cut, captured, sequence) = self.prospective_original_pending_cut_v5(phase1, owners)?;
            let old = phase1
                .graph
                .sidecars()
                .get(&phase1.attempt)
                .ok_or_else(invalid)?;
            let r = RootNativeDispositionAssertionV1 {
                disposition: NativeHeldDispositionV1::Closed,
                observation: RootNativeObservationV1::PreparedOnly,
                scope: *old.original_scope(),
                source_artifact: ObjectDigest::from_bytes([0; 32]),
                descriptor_commitment: ObjectDigest::from_bytes([0; 32]),
                records: captured.witnesses().clone(),
            };
            if unsigned8.kind() != NativeHeldControlKindV1::RootClosed
                || unsigned8.scope() != old.original_scope()
                || unsigned8.section(Tag::RootDispositionAssertion)
                    != Some(r.to_canonical_bytes().map_err(|_| invalid())?.as_slice())
            {
                return Err(invalid());
            }

            validate_witness(old, unsigned8, &r, sequence)?;
            let suffix = NativeHeldCompletionSuffixV1::new(
                NativeHeldOwnerV1::Root,
                10,
                old.suffix().flight(),
                Some(unsigned8.clone()),
                old.suffix().controls().to_vec(),
            )
            .map_err(|_| invalid())?;
            let next = RootNativeHeldSidecarV2::new(
                *old.original_scope(),
                [0; 16],
                Some(r),
                None,
                None,
                suffix,
                old.admission_cut().clone(),
                Some(cut),
                None,
            )
            .map_err(|_| invalid())?;

            let mut records = owners.records().to_vec();
            records.push(JournalRecord::put(
                RecordNamespace::MountSourceAcquisition,
                native_root_sidecar_key_v2(phase1.attempt).map_err(|_| invalid())?,
                next.to_canonical_bytes().map_err(|_| invalid())?,
            ));
            let owners = JournalTransaction::new(*owners.id(), records)?;
            let (transaction, floor, old_floor) = derive_continuation(
                &self.authority.journal.state,
                &owners,
                phase1.attempt,
                self.authority.journal.limits,
            )?;
            *slot = Some(PreparedOriginalRootAppendV5 {
                transaction,
                snapshot: phase1.snapshot.clone(),
                attempt: phase1.attempt,
                digest: [0; 32],
                floor,
                preflight_complete: false,
                failed: core::cell::Cell::new(false),
                attempted: core::cell::Cell::new(false),
                actual: None,
            });

            // The completed coupled candidate is retained before every remaining
            // check. A failed candidate is permanently noncommittable.
            let prepared = slot.as_mut().ok_or_else(invalid)?;
            prepared.digest = authority_preflight_digest(std::slice::from_ref(&prepared.transaction));
            validate_transfer(
                &prepared.transaction,
                &old_floor,
                prepared.floor.as_ref(),
                self.authority.journal.limits,
            )?;
            validate_pending_sequence(
                &self.authority.journal.state,
                &prepared.transaction,
                phase1.attempt,
                sequence,
            )?;
            self.preflight(&prepared.transaction, phase1.attempt)?;
            self.validate_readback(phase1)?;
            prepared.preflight_complete = true;

            Ok(())
        })
    }
}

/// Rejoins physical sequence and original witness facts at prepare and replay.
pub(super) fn validate_pending_sequence(
    state: &State,
    transaction: &JournalTransaction,
    attempt: [u8; 32],
    successor_sequence: u64,
) -> Result<(), JournalError> {
    let before = graph(state)?;
    // Capacity DEL/PUT rows are independently checked by the exact funded
    // owner edge. This graph projection accepts only its namespace40 PUTs.
    let owners: Vec<_> = transaction
        .records()
        .iter()
        .filter(|record| record.namespace() == RecordNamespace::MountSourceAcquisition)
        .cloned()
        .collect();
    let after = graph(&apply(state, &owners)?)?;
    let Some(old) = before.sidecars().get(&attempt) else {
        return Ok(());
    };
    let next = after.sidecars().get(&attempt).ok_or_else(invalid)?;
    if old.suffix().phase() == 1
        && next
            .disposition_cut()
            .is_some_and(RootNativeCutV1::is_pending_disposition)
    {
        if transaction.records().len() != 6 {
            return Err(invalid());
        }
        validate_witness(
            old,
            next.suffix().prepared().ok_or_else(invalid)?,
            next.disposition().ok_or_else(invalid)?,
            successor_sequence,
        )?;
    }
    Ok(())
}

fn validate_witness(
    old: &RootNativeHeldSidecarV2,
    unsigned8: &PreparedNativeHeldControlV1,
    r: &RootNativeDispositionAssertionV1,
    sequence: u64,
) -> Result<(), JournalError> {
    let root1 = old
        .suffix()
        .control(NativeHeldControlKindV1::RootPrepared)
        .ok_or_else(invalid)?;
    let NativeHeldOwnerWitnessV1::Root(mut expected) = NativeHeldOwnerWitnessV1::from_canonical_bytes(
        NativeHeldOwnerV1::Root,
        root1.section(Tag::Witness).ok_or_else(invalid)?,
    )
    .map_err(|_| invalid())?
    else {
        return Err(invalid());
    };

    expected.journal_sequence = sequence;
    expected.records = r.records.clone();
    if unsigned8.signer() != root1.prepared().signer()
        || unsigned8.predecessor() != root1.digest()
        || unsigned8.section(Tag::Witness)
            != Some(
                NativeHeldOwnerWitnessV1::Root(expected)
                    .to_canonical_bytes()
                    .map_err(|_| invalid())?
                    .as_slice(),
            )
    {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(test)]
pub(super) mod tests;

//! Signs and retains the first current checkpoint beside immutable import proof.
//!
//! The private Core loan supplies the actual same-Window, World and read owner.
//! Neither this fixed DATA nor its MAC admits an operation. Rechecking this
//! initial seed still requires the genuine saved Observe/World/Hold producer;
//! future native progress needs a distinct signed suffix producer and consumer.

use super::*;
use crate::node_admission::{
    OriginalInstalledRestorationObservationSigningInputs, OriginalRestoredSuffixCheckpointData,
    OriginalRestoredSuffixConstructionData, OriginalRestoredSuffixSeedClaim,
};
use crate::node_contract::RuntimeError;
use crate::node_scheduling::NativeSchedulingObservation;
use crucible_node_contract::{ContentRef, Position};
use crucible_node_provider::reference_packet::{
    control::PacketNative5UnderlyingRecord, service::complete_restore::PacketNativeRestoredRecord,
};
use std::{
    cell::{Ref, RefCell, RefMut},
    mem::size_of,
    thread::ThreadId,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Stage {
    Started,
    Signed,
    Verified,
    Failed,
}

pub(super) struct OriginalRestoredSuffixSeed {
    process: u32,
    thread: ThreadId,
    source: *const PacketCompleteSemanticSource,
    controller: *const CnpController,
    checkpoint: Option<OriginalRestoredSuffixCheckpointData>,
    signature: Option<[u8; 32]>,
    stage: Stage,
}

// Each borrowed field is fixed inline data or a nonowning raw identity.
// Changing a field to an owning container must fail this defining census until
// its backing has an explicit visitor; the Source/controller pointees stay in
// their independent existing whole-owner rows.
type FixedSeedFields<'a> = (
    &'a u32,
    &'a ThreadId,
    &'a *const PacketCompleteSemanticSource,
    &'a *const CnpController,
    &'a Option<OriginalRestoredSuffixCheckpointData>,
    &'a Option<[u8; 32]>,
    &'a Stage,
);

impl OriginalRestoredSuffixSeed {
    pub(super) fn retained_heap_bytes_data(&self) -> usize {
        let Self {
            process,
            thread,
            source,
            controller,
            checkpoint,
            signature,
            stage,
        } = self;
        let _fixed_fields: FixedSeedFields<'_> = (
            process, thread, source, controller, checkpoint, signature, stage,
        );

        // The enclosing actual Source sizeof owns the entire Option/RefCell
        // payload in every phase. These exact fields add no heap or FD owner.
        0
    }

    pub(super) fn retained_counter_scratch_data() -> usize {
        size_of::<FixedSeedFields<'static>>() + size_of::<&Self>() + size_of::<usize>()
    }

    fn authenticate_origin_data(
        &self,
        source: &PacketCompleteSemanticSource,
    ) -> Result<(), RuntimeError> {
        source.storage_origin_with_error::<RuntimeError>()?;
        if self.process != std::process::id()
            || self.thread != std::thread::current().id()
            || !std::ptr::eq(self.source, source)
        {
            return Err(RuntimeError::ForeignAuthority);
        }

        Ok(())
    }

    fn authenticate_original_data(
        &self,
        source: &PacketCompleteSemanticSource,
        controller: &CnpController,
        checkpoint: &OriginalRestoredSuffixCheckpointData,
        key: &[u8; 32],
    ) -> Result<(), RuntimeError> {
        self.authenticate_origin_data(source)?;
        if !std::ptr::eq(self.controller, controller)
            || self.stage != Stage::Verified
            || self.checkpoint != Some(*checkpoint)
            || self.signature != Some(checkpoint_signature(key, checkpoint))
        {
            return Err(RuntimeError::InvalidReceipt);
        }

        Ok(())
    }
}

struct AttemptGuard<'a> {
    slot: &'a RefCell<Option<OriginalRestoredSuffixSeed>>,
}

impl Drop for AttemptGuard<'_> {
    fn drop(&mut self) {
        if let Ok(mut slot) = self.slot.try_borrow_mut() {
            if let Some(attempt) = slot.as_mut() {
                if matches!(attempt.stage, Stage::Started | Stage::Signed) {
                    attempt.stage = Stage::Failed;
                }
            }
        }
    }
}

impl PacketCompleteSemanticSource {
    /// Quotes a distinct future validation extent from actual first-Observe DATA.
    ///
    /// The same old validation extent is added independently; no prior allowance
    /// or current capacity is refunded. This helper does not construct a seed.
    ///
    /// # Errors
    /// Refuses foreign Source origin, arithmetic overflow or the original bound.
    pub(crate) fn original_restored_suffix_construction_data(
        &self,
        controller: &CnpController,
        observation: &restoration_observation::OriginalSourceRestorationObservationConstructionData,
        maximum: usize,
    ) -> Result<OriginalRestoredSuffixConstructionData, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        let scratch = Self::original_restored_suffix_counter_scratch_data()
            .checked_add(OriginalRestoredSuffixConstructionData::counter_scratch_data())
            .ok_or(RuntimeError::ResourceLimit)?;
        let requested = observation
            .requested_peak_bytes_data()
            .checked_add(size_of::<OriginalRestoredSuffixSeed>())
            .and_then(|bytes| bytes.checked_add(scratch))
            .ok_or(RuntimeError::ResourceLimit)?;
        if requested > maximum {
            return Err(RuntimeError::ResourceLimit);
        }

        Ok(OriginalRestoredSuffixConstructionData {
            process: std::process::id(),
            thread: std::thread::current().id(),
            source: self,
            controller,
            observation: *observation,
            requested,
            scratch,
            maximum,
        })
    }

    /// Retains a Source-keyed seed under the real first-Observe read fence.
    ///
    /// # Errors
    /// Refuses foreign originals, an occupied slot, invalid initial evidence,
    /// busy custody and any actual member/kernel/registrar fence failure.
    pub(crate) fn seed_original_restored_suffix_data(
        &self,
        controller: &CnpController,
        inputs: &OriginalInstalledRestorationObservationSigningInputs<'_>,
        row: &OriginalRestoredSuffixConstructionData,
        claim: &OriginalRestoredSuffixSeedClaim<'_>,
    ) -> Result<(), RuntimeError> {
        row.authenticate_original_data(self, controller)?;
        claim.authenticate_current_data(self, controller)?;

        let expected = self.original_restored_suffix_construction_data(
            controller,
            &row.observation,
            row.maximum,
        )?;
        if expected.requested != row.requested || expected.scratch != row.scratch {
            return Err(RuntimeError::ForeignAuthority);
        }

        begin_original_seed_source_data(self)?;
        let association = self
            .ack_peer_association
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let original = association.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        let slot = &original.restored_suffix;
        {
            let mut seed = slot.try_borrow_mut().map_err(|_| RuntimeError::OwnerBusy)?;
            if seed.is_some() {
                return Err(RuntimeError::OutstandingObligations);
            }
            // Retain an empty partial before the first native evidence read.
            // A different genuine Window cannot renew this Source's attempt.
            *seed = Some(OriginalRestoredSuffixSeed {
                process: std::process::id(),
                thread: std::thread::current().id(),
                source: self,
                controller,
                checkpoint: None,
                signature: None,
                stage: Stage::Started,
            });
        }
        let _attempt = AttemptGuard { slot };

        let evidence = self.original_verified_restoration_observation_data(
            controller,
            inputs,
            &row.observation,
        )?;
        evidence.with_original_suffix_seed_data(
            inputs,
            &row.observation,
            |record, underlying, scheduling| {
                claim.authenticate_current_data(self, controller)?;
                let checkpoint = checkpoint_data(
                    claim.restoration_proof_data(),
                    record,
                    underlying,
                    scheduling,
                )?;
                let mut seed = slot.try_borrow_mut().map_err(|_| RuntimeError::OwnerBusy)?;
                let seed = seed.as_mut().ok_or(RuntimeError::OwnerUnavailable)?;
                seed.authenticate_origin_data(self)?;
                if seed.stage != Stage::Started
                    || seed.checkpoint.is_some()
                    || seed.signature.is_some()
                {
                    return Err(RuntimeError::OutstandingObligations);
                }
                seed.checkpoint = Some(checkpoint);

                let birth = self
                    .ack_peer_birth
                    .try_borrow()
                    .map_err(|_| RuntimeError::OwnerBusy)?;
                let key = birth
                    .as_ref()
                    .ok_or(RuntimeError::OwnerUnavailable)?
                    .original_fresh_query_key_data()?;
                seed.signature = Some(checkpoint_signature(
                    key,
                    seed.checkpoint
                        .as_ref()
                        .ok_or(RuntimeError::OwnerUnavailable)?,
                ));
                seed.stage = Stage::Signed;
                Ok(())
            },
            || claim.authenticate_terminal_member_data(),
        )?;

        // SourceRead and the actual terminal member/kernel fence completed.
        // The outer Core guard still refuses its ledger if this tail fails.
        let mut seed = slot.try_borrow_mut().map_err(|_| RuntimeError::OwnerBusy)?;
        let seed = seed.as_mut().ok_or(RuntimeError::OwnerUnavailable)?;
        if seed.stage != Stage::Signed {
            return Err(RuntimeError::OutstandingObligations);
        }
        seed.stage = Stage::Verified;

        Ok(())
    }

    /// Rechecks the actual retained seed and lends its fixed current DATA.
    ///
    /// # Errors
    /// Refuses changed identity, MAC, initial native model/cursor, unfinished
    /// ownership, callback failure or the actual terminal Source fence.
    pub(crate) fn with_original_restored_suffix_seed_data(
        &self,
        controller: &CnpController,
        inputs: &OriginalInstalledRestorationObservationSigningInputs<'_>,
        row: &OriginalRestoredSuffixConstructionData,
        claim: &OriginalRestoredSuffixSeedClaim<'_>,
        inspect: impl FnOnce(&OriginalRestoredSuffixCheckpointData) -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        row.authenticate_original_data(self, controller)?;
        claim.authenticate_current_data(self, controller)?;

        let expected = self.original_restored_suffix_construction_data(
            controller,
            &row.observation,
            row.maximum,
        )?;
        if expected.requested != row.requested || expected.scratch != row.scratch {
            return Err(RuntimeError::ForeignAuthority);
        }

        let evidence = self.original_verified_restoration_observation_data(
            controller,
            inputs,
            &row.observation,
        )?;
        evidence.with_original_suffix_seed_data(
            inputs,
            &row.observation,
            |record, underlying, scheduling| {
                let checkpoint = checkpoint_data(
                    claim.restoration_proof_data(),
                    record,
                    underlying,
                    scheduling,
                )?;
                let association = self
                    .ack_peer_association
                    .try_borrow()
                    .map_err(|_| RuntimeError::OwnerBusy)?;
                let original = association.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
                let seed = original
                    .restored_suffix
                    .try_borrow()
                    .map_err(|_| RuntimeError::OwnerBusy)?;
                let seed = seed.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;

                let birth = self
                    .ack_peer_birth
                    .try_borrow()
                    .map_err(|_| RuntimeError::OwnerBusy)?;
                let key = birth
                    .as_ref()
                    .ok_or(RuntimeError::OwnerUnavailable)?
                    .original_fresh_query_key_data()?;

                seed.authenticate_original_data(self, controller, &checkpoint, key)?;
                claim.authenticate_current_data(self, controller)?;
                inspect(&checkpoint)
            },
            || claim.authenticate_terminal_member_data(),
        )
    }

    /// Names exact fixed seed, borrow, hash and returned-result counter views.
    pub(crate) fn original_restored_suffix_counter_scratch_data() -> usize {
        size_of::<OriginalRestoredSuffixSeed>()
            + size_of::<Option<OriginalRestoredSuffixSeed>>()
            + size_of::<std::cell::Cell<bool>>()
            + size_of::<Option<OriginalRestoredSuffixCheckpointData>>()
            + size_of::<Option<&OriginalRestoredSuffixCheckpointData>>()
            + size_of::<Result<&OriginalRestoredSuffixCheckpointData, RuntimeError>>()
            + size_of::<RefCell<Option<OriginalRestoredSuffixSeed>>>()
            + size_of::<Ref<'static, Option<OriginalRestoredSuffixSeed>>>()
            + size_of::<RefMut<'static, Option<OriginalRestoredSuffixSeed>>>()
            + size_of::<
                Result<Ref<'static, Option<OriginalRestoredSuffixSeed>>, std::cell::BorrowError>,
            >()
            + size_of::<
                Result<
                    RefMut<'static, Option<OriginalRestoredSuffixSeed>>,
                    std::cell::BorrowMutError,
                >,
            >()
            + size_of::<Result<Ref<'static, Option<OriginalRestoredSuffixSeed>>, RuntimeError>>()
            + size_of::<Result<RefMut<'static, Option<OriginalRestoredSuffixSeed>>, RuntimeError>>()
            + size_of::<Ref<'static, Option<OriginalAckPeerAssociation>>>()
            + size_of::<
                Result<Ref<'static, Option<OriginalAckPeerAssociation>>, std::cell::BorrowError>,
            >()
            + size_of::<Result<Ref<'static, Option<OriginalAckPeerAssociation>>, RuntimeError>>()
            + size_of::<Ref<'static, Option<super::super::birth::OriginalAckPeerBirth>>>()
            + size_of::<
                Result<
                    Ref<'static, Option<super::super::birth::OriginalAckPeerBirth>>,
                    std::cell::BorrowError,
                >,
            >()
            + size_of::<
                Result<
                    Ref<'static, Option<super::super::birth::OriginalAckPeerBirth>>,
                    RuntimeError,
                >,
            >()
            + size_of::<AttemptGuard<'static>>()
            + 2 * size_of::<OriginalRestoredSuffixCheckpointData>()
            + size_of::<Result<OriginalRestoredSuffixCheckpointData, RuntimeError>>()
            + size_of::<&OriginalRestoredSuffixConstructionData>()
            + size_of::<&OriginalRestoredSuffixSeedClaim<'static>>()
            + size_of::<&OriginalInstalledRestorationObservationSigningInputs<'static>>()
            + size_of::<(
                &PacketNativeRestoredRecord,
                &PacketNative5UnderlyingRecord,
                &NativeSchedulingObservation,
            )>()
            + size_of::<&OriginalRestoredSuffixCheckpointData>()
            + size_of::<&ContentRef>()
            + size_of::<&[u8]>()
            + size_of::<&[u8; 32]>()
            + 3 * size_of::<blake3::Hasher>()
            + 3 * size_of::<blake3::Hash>()
            + 4 * size_of::<[u8; 32]>()
            + 2 * size_of::<[u8; 8]>()
            + size_of::<[u8; 2]>()
            + size_of::<Position>()
            + size_of::<Option<&OriginalRestoredSuffixSeed>>()
            + size_of::<Option<&mut OriginalRestoredSuffixSeed>>()
            + size_of::<Result<&OriginalRestoredSuffixSeed, RuntimeError>>()
            + size_of::<Result<&mut OriginalRestoredSuffixSeed, RuntimeError>>()
            + size_of::<Result<&[u8; 32], RuntimeError>>()
            + size_of::<Result<&PacketNativeRestoredRecord, RuntimeError>>()
            + size_of::<Result<&PacketNative5UnderlyingRecord, RuntimeError>>()
            + size_of::<Result<&NativeSchedulingObservation, RuntimeError>>()
            + size_of::<&OriginalAckPeerAssociation>()
            + size_of::<&super::super::birth::OriginalAckPeerBirth>()
            + size_of::<Option<&OriginalAckPeerAssociation>>()
            + size_of::<Result<&OriginalAckPeerAssociation, RuntimeError>>()
            + size_of::<Option<&super::super::birth::OriginalAckPeerBirth>>()
            + size_of::<Result<&super::super::birth::OriginalAckPeerBirth, RuntimeError>>()
            + size_of::<Option<[u8; 32]>>()
            + size_of::<usize>()
            + size_of::<Option<usize>>()
            + size_of::<Result<(), RuntimeError>>()
    }
}

fn begin_original_seed_source_data(
    source: &PacketCompleteSemanticSource,
) -> Result<(), RuntimeError> {
    source.storage_origin_with_error::<RuntimeError>()?;
    if source.restored_suffix_attempted.replace(true) {
        return Err(RuntimeError::OutstandingObligations);
    }
    Ok(())
}

fn checkpoint_data(
    restoration_proof: [u8; 32],
    record: &PacketNativeRestoredRecord,
    underlying: &PacketNative5UnderlyingRecord,
    scheduling: &NativeSchedulingObservation,
) -> Result<OriginalRestoredSuffixCheckpointData, RuntimeError> {
    let reached = match underlying {
        PacketNative5UnderlyingRecord::Producer(record) => record.inventory.reached,
        PacketNative5UnderlyingRecord::Reactive(record) => record.inventory.reached,
    };
    if scheduling.reached != reached {
        return Err(RuntimeError::InvalidReceipt);
    }
    // The full native reference includes every inventory field and its actual
    // model cursor. The saved Observe reference independently binds scheduling.
    Ok(OriginalRestoredSuffixCheckpointData {
        restoration_proof,
        native_binding: content_binding(&record.native_receipt.native_record),
        observation_binding: content_binding(&scheduling.proof_ref),
        reached,
    })
}

fn content_binding(reference: &ContentRef) -> [u8; 32] {
    let mut hash = blake3::Hasher::new_derive_key("aos.restored-suffix.full-content.v1");
    hash_field(&mut hash, reference.hash.algorithm.as_bytes());
    hash_field(&mut hash, reference.hash.domain.as_bytes());
    hash_field(&mut hash, reference.hash.digest.as_bytes());
    hash.update(&reference.length.get().to_le_bytes());
    hash_field(&mut hash, reference.media_type.as_bytes());
    *hash.finalize().as_bytes()
}

fn hash_field(hash: &mut blake3::Hasher, bytes: &[u8]) {
    // Local fixed checkpoint only: this width is not a portable wire format.
    hash.update(&bytes.len().to_le_bytes());
    hash.update(bytes);
}

fn checkpoint_signature(
    key: &[u8; 32],
    checkpoint: &OriginalRestoredSuffixCheckpointData,
) -> [u8; 32] {
    let mut hash = blake3::Hasher::new_keyed(key);
    hash.update(b"aos.restored-suffix.initial-current.v1\0");
    hash.update(&checkpoint.restoration_proof);
    hash.update(&checkpoint.native_binding);
    hash.update(&checkpoint.observation_binding);
    hash.update(&checkpoint.reached.time_ps.get().to_le_bytes());
    hash.update(&checkpoint.reached.microstep.get().to_le_bytes());
    hash.update(&(checkpoint.reached.phase as u16).to_le_bytes());
    *hash.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_node_contract::{HashRef, Phase, Tick, U64};

    fn checkpoint() -> OriginalRestoredSuffixCheckpointData {
        OriginalRestoredSuffixCheckpointData {
            restoration_proof: [1; 32],
            native_binding: [2; 32],
            observation_binding: [3; 32],
            reached: Position::new(Tick::new(4), U64::new(5), Phase::Reaction),
        }
    }

    #[test]
    fn full_content_binding_preserves_length_media_type_and_inventory_digest() {
        let reference = ContentRef {
            hash: HashRef {
                algorithm: "blake3-256".into(),
                domain: "cnp.blob.v1".into(),
                digest: "ab".repeat(32),
            },
            length: U64::new(19),
            media_type: "application/json".into(),
        };
        let original = content_binding(&reference);

        let mut changed = reference.clone();
        changed.length = U64::new(20);
        assert_ne!(content_binding(&changed), original);

        changed = reference.clone();
        changed.media_type = "application/octet-stream".into();
        assert_ne!(content_binding(&changed), original);

        changed = reference;
        changed.hash.digest.replace_range(..2, "cd");
        assert_ne!(content_binding(&changed), original);
    }

    #[test]
    fn checkpoint_signature_separates_import_proof_native_current_and_cursor() {
        let original = checkpoint();
        let key = [7; 32];
        let signature = checkpoint_signature(&key, &original);

        let mut changed = original;
        changed.restoration_proof[0] ^= 1;
        assert_ne!(checkpoint_signature(&key, &changed), signature);

        changed = original;
        changed.native_binding[0] ^= 1;
        assert_ne!(checkpoint_signature(&key, &changed), signature);

        changed = original;
        changed.reached = Position::new(Tick::new(5), U64::new(5), Phase::Reaction);
        assert_ne!(checkpoint_signature(&key, &changed), signature);
        assert_ne!(checkpoint_signature(&[8; 32], &original), signature);
    }

    #[test]
    fn actual_producer_and_reactive_sources_keep_failed_fixed_seed_and_original_banks() {
        use crate::node_adapters::cnp::semantic::packet_complete_source::tests as fixture;
        use std::rc::Rc;

        for reactive in [false, true] {
            let installed = fixture::coordinator();
            let source = Rc::new(if reactive {
                PacketCompleteSemanticSource::new_reactive_for_collecting_world(
                    fixture::installation(&installed, 1),
                    fixture::reactive(&installed, 1),
                    installed,
                    fixture::storage_selection(),
                )
                .expect("actual reactive Source constructor")
            } else {
                PacketCompleteSemanticSource::new_producer_for_collecting_world(
                    fixture::installation(&installed, 0),
                    fixture::producer(),
                    installed,
                    fixture::storage_selection(),
                )
                .expect("actual producer Source constructor")
            });
            let installed = fixture::coordinator();
            let foreign = PacketCompleteSemanticSource::new_producer_for_collecting_world(
                fixture::installation(&installed, 0),
                fixture::producer(),
                installed,
                fixture::storage_selection(),
            )
            .expect("distinct actual Source");
            OriginalAckPeerAssociation::reserve_into(
                256,
                &mut source.ack_peer_association.borrow_mut(),
            )
            .expect("actual retained association banks");
            let holders = source
                .original_complete_holder_storage_data_with_error::<RuntimeError>(usize::MAX)
                .expect("actual sizeof Source/Rc and underlying owners");
            let banks = source
                .original_complete_boot_association_storage_data_with_error::<RuntimeError>(
                    usize::MAX,
                )
                .expect("actual bank capacities");

            {
                let association = source.ack_peer_association.borrow();
                let slot = &association
                    .as_ref()
                    .expect("same association")
                    .restored_suffix;
                // This is adverse custody DATA, not an issued Window claim or a
                // successful native proof. No authentication gate is bypassed.
                *slot.borrow_mut() = Some(OriginalRestoredSuffixSeed {
                    process: std::process::id(),
                    thread: std::thread::current().id(),
                    source: Rc::as_ptr(&source),
                    controller: std::ptr::null(),
                    checkpoint: Some(checkpoint()),
                    signature: Some([9; 32]),
                    stage: Stage::Signed,
                });
                {
                    let _attempt = AttemptGuard { slot };
                }
                let retained = slot.borrow();
                let retained = retained.as_ref().expect("failed partial owner retained");
                assert_eq!(retained.stage, Stage::Failed);
                assert_eq!(retained.signature, Some([9; 32]));
                assert!(retained.authenticate_origin_data(&source).is_ok());
                assert!(retained.authenticate_origin_data(&foreign).is_err());
            }

            assert_eq!(
                source.original_complete_holder_storage_data_with_error::<RuntimeError>(holders),
                Ok(holders)
            );
            assert_eq!(
                source.original_complete_boot_association_storage_data_with_error::<RuntimeError>(
                    banks
                ),
                Ok(banks)
            );
            assert!(
                source
                    .original_complete_boot_association_storage_data_with_error::<RuntimeError>(
                        banks - 1
                    )
                    .is_err()
            );
            assert!(source.authenticate_current_native().is_err());
        }
    }

    #[test]
    fn actual_source_preproof_loan_failure_cannot_renew_the_once_seed() {
        use crate::node_adapters::cnp::semantic::packet_complete_source::tests as fixture;
        let installed = fixture::coordinator();
        let source = PacketCompleteSemanticSource::new_producer_for_collecting_world(
            fixture::installation(&installed, 0),
            fixture::producer(),
            installed,
            fixture::storage_selection(),
        )
        .expect("actual collecting Source");
        let busy = source.ack_peer_association.borrow_mut();

        begin_original_seed_source_data(&source).expect("same defining once gate");
        assert!(source.ack_peer_association.try_borrow().is_err());
        drop(busy);

        assert!(source.restored_suffix_attempted.get());
        assert!(source.ack_peer_association.borrow().is_none());
        assert!(begin_original_seed_source_data(&source).is_err());
        // A later availability change supplies no fresh Source attempt.
        OriginalAckPeerAssociation::reserve_into(
            256,
            &mut source.ack_peer_association.borrow_mut(),
        )
        .expect("real retained association banks");
        assert!(begin_original_seed_source_data(&source).is_err());
    }

    #[test]
    fn reserved_seed_loan_and_partial_custody_refuse_prebirth_without_backing_discount() {
        use crate::node_adapters::cnp::semantic::packet_complete_source::tests as fixture;
        use std::rc::Rc;

        for reactive in [false, true] {
            let installed = fixture::coordinator();
            let source = Rc::new(if reactive {
                PacketCompleteSemanticSource::new_reactive_for_collecting_world(
                    fixture::installation(&installed, 1),
                    fixture::reactive(&installed, 1),
                    installed,
                    fixture::storage_selection(),
                )
                .expect("actual reactive Source")
            } else {
                PacketCompleteSemanticSource::new_producer_for_collecting_world(
                    fixture::installation(&installed, 0),
                    fixture::producer(),
                    installed,
                    fixture::storage_selection(),
                )
                .expect("actual producer Source")
            });
            OriginalAckPeerAssociation::reserve_into(
                256,
                &mut source.ack_peer_association.borrow_mut(),
            )
            .expect("actual association banks");
            let holders = source
                .original_complete_holder_storage_data_with_error::<RuntimeError>(usize::MAX)
                .expect("actual Source/Rc and underlying holder layouts");
            let association = source.ack_peer_association.borrow();
            let association = association.as_ref().expect("same retained association");
            let bytes = association.retained_heap_storage_data(usize::MAX).unwrap();
            association.authenticate_reserved_prebirth_data().unwrap();

            {
                let _busy = association.restored_suffix.borrow_mut();
                assert!(association.authenticate_reserved_prebirth_data().is_err());
                assert!(association.retained_heap_storage_data(bytes).is_err());
            }
            association.authenticate_reserved_prebirth_data().unwrap();
            *association.restored_suffix.borrow_mut() = Some(OriginalRestoredSuffixSeed {
                process: std::process::id(),
                thread: std::thread::current().id(),
                source: Rc::as_ptr(&source),
                controller: std::ptr::null(),
                checkpoint: None,
                signature: None,
                stage: Stage::Started,
            });
            {
                let _failed_attempt = AttemptGuard {
                    slot: &association.restored_suffix,
                };
            }

            assert!(association.authenticate_reserved_prebirth_data().is_err());
            assert_eq!(
                association.retained_heap_storage_data(bytes).unwrap(),
                bytes
            );
            assert!(association.retained_heap_storage_data(bytes - 1).is_err());
            let retained = association.restored_suffix.borrow();
            assert_eq!(retained.as_ref().unwrap().stage, Stage::Failed);
            assert_eq!(retained.as_ref().unwrap().retained_heap_bytes_data(), 0);
            assert_eq!(
                source.original_complete_holder_storage_data_with_error::<RuntimeError>(holders),
                Ok(holders),
            );
            assert!(source.authenticate_current_native().is_err());
        }
    }
}

/// Preserves the original seed as DATA without importing its process authority.
pub(crate) struct SourceRestoredSuffixSeedHistoryData<'a> {
    original: &'a OriginalRestoredSuffixSeed,
}

#[derive(serde::Serialize)]
struct SourceRestoredSuffixCheckpointHistoryData<'a> {
    restoration_proof: &'a [u8; 32],
    native_binding: &'a [u8; 32],
    observation_binding: &'a [u8; 32],
    reached: Position,
}

impl OriginalRestoredSuffixSeed {
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn historical_data(
        &self,
    ) -> SourceRestoredSuffixSeedHistoryData<'_> {
        SourceRestoredSuffixSeedHistoryData { original: self }
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn historical_counter_scratch_data()
    -> usize {
        size_of::<SourceRestoredSuffixSeedHistoryData<'static>>()
            + size_of::<SourceRestoredSuffixCheckpointHistoryData<'static>>()
            + size_of::<Option<SourceRestoredSuffixCheckpointHistoryData<'static>>>()
            + size_of::<&OriginalRestoredSuffixSeed>()
    }
}

impl serde::Serialize for SourceRestoredSuffixSeedHistoryData<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let OriginalRestoredSuffixSeed {
            process: _,
            thread: _,
            source: _,
            controller: _,
            checkpoint,
            signature,
            stage,
        } = self.original;
        let checkpoint = checkpoint.as_ref().map(|value| {
            let OriginalRestoredSuffixCheckpointData {
                restoration_proof,
                native_binding,
                observation_binding,
                reached,
            } = value;
            SourceRestoredSuffixCheckpointHistoryData {
                restoration_proof,
                native_binding,
                observation_binding,
                reached: *reached,
            }
        });
        let mut value = serializer.serialize_struct("SourceRestoredSuffixSeedHistory", 3)?;
        value.serialize_field("checkpoint", &checkpoint)?;
        value.serialize_field("signature", signature)?;
        value.serialize_field(
            "stage",
            match stage {
                Stage::Started => "started",
                Stage::Signed => "signed",
                Stage::Verified => "verified",
                Stage::Failed => "failed",
            },
        )?;
        value.end()
    }
}

impl OriginalRestoredSuffixSeed {
    pub(super) fn settled17_once_data(
        &self,
        source: &PacketCompleteSemanticSource,
        controller: &CnpController,
        key: &[u8; 32],
    ) -> Result<super::settled17_once::SuffixOnce17, RuntimeError> {
        let checkpoint = self
            .checkpoint
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        self.authenticate_original_data(source, controller, checkpoint, key)?;
        Ok(super::settled17_once::SuffixOnce17 {
            stage: super::settled17_once::VerifiedSuffixStage17::Verified,
            restoration_proof: checkpoint.restoration_proof,
            native_binding: checkpoint.native_binding,
            observation_binding: checkpoint.observation_binding,
            reached: checkpoint.reached,
            signature: self.signature.ok_or(RuntimeError::OwnerUnavailable)?,
        })
    }
}

pub(super) fn historical_checkpoint17_data(
    restoration_proof: [u8; 32],
    record: &PacketNativeRestoredRecord,
    underlying: &PacketNative5UnderlyingRecord,
    scheduling: &NativeSchedulingObservation,
) -> Result<OriginalRestoredSuffixCheckpointData, RuntimeError> {
    checkpoint_data(restoration_proof, record, underlying, scheduling)
}

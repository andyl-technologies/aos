//! One original live Storage offer through Source's phase-2 readback only.
//!
//! The same Root1/Acquire, first clock, Source writer, Storage child, both record
//! subjects and original mount FD remain resident. This module observes the
//! existing canonical acceptance and phase1->2 reducers; it does not spend a
//! challenge, Complete, sign Provider3, hand off SourceRoot, relay or settle.

use std::os::fd::OwnedFd;

use aos_sandbox::JournalRecord;
use aos_sandbox_source_provider_protocol::{
    SourceProviderDescriptorRole, StorageNativeAcquireReplyV3,
    StorageNativeAcquireVerificationV3, StorageZfsHoldReceiptV1,
    VerifiedStorageNativeAcquireV3,
    native_held_completion::suffix::NativeHeldCompletionSuffixV1,
};
use aos_sandbox_source_provider_security::OriginalStorageOfferTransportV5;
use sha2::{Digest as _, Sha256};

use super::*;
use super::producer::{
    OriginalProducerAppendV5 as Append, OriginalProducerClosureGuardV5,
    OriginalProducerErrorV5, OriginalProducerObservationV5, owner_transaction_v5,
};
use crate::backend::ProviderPhysicalSourceRootV1;
use crate::owner::FixedProviderOriginalStorageOfferProgressV5 as Progress;
use crate::ledger::native_completion::native_completion_key_v2;
use crate::ledger::native_held_completion::{
    SourceNativeHeldStepV1, propose_native_held_transition_v1,
};
use crate::zfs_hold_challenge::current_seconds;

#[derive(Clone, Copy, Eq, PartialEq)]
enum OfferStageV5 {
    StagePackets,
    Exchange,
    ObserveMount,
    ValidateReply,
    PrepareCheckpoint,
    CommitCheckpoint,
    Prepared,
    Closed,
}

enum OfferFailureV5 {
    Validation(OriginalProducerErrorV5),
    Transport,
    MountDuplicate,
    PhysicalObservation,
}

/// Contains no admission constructor; only the genuine Source producer parks it.
pub(super) struct OriginalStorageOfferV5 {
    stage: OfferStageV5,
    transport: OriginalStorageOfferTransportV5,
    control: Option<SignedNativeHeldControlV1>,
    reply: Option<StorageNativeAcquireReplyV3>,
    mount_duplicate: Option<Result<OwnedFd, std::io::Error>>,
    physical: Option<Result<ProviderPhysicalSourceRootV1, ProviderLedgerError>>,
    verified: Option<VerifiedStorageNativeAcquireV3>,
    record: Option<SourceNativeHeldCompletionRecordV1>,
    before: Vec<(Vec<u8>, Vec<u8>)>,
    after: Vec<(Vec<u8>, Vec<u8>)>,
    failure: Option<OfferFailureV5>,
}

impl OriginalStorageOfferV5 {
    pub(super) fn is_prepared(&self) -> bool {
        self.stage == OfferStageV5::Prepared && self.failure.is_none()
    }

    pub(super) fn physical(&self) -> Result<&ProviderPhysicalSourceRootV1, ProviderLedgerError> {
        self.physical.as_ref().and_then(|physical| physical.as_ref().ok())
            .ok_or(ProviderLedgerError::Unavailable)
    }

    pub(super) fn reply(&self) -> Result<&StorageNativeAcquireReplyV3, ProviderLedgerError> {
        self.reply.as_ref().ok_or(ProviderLedgerError::Unavailable)
    }

    pub(super) fn verified(&self) -> Result<&VerifiedStorageNativeAcquireV3, ProviderLedgerError> {
        self.verified.as_ref().ok_or(ProviderLedgerError::Unavailable)
    }

    pub(super) fn original_socket_cookie_v5(
        &mut self,
    ) -> Result<std::num::NonZeroU64, aos_sandbox_source_provider_security::OriginalStorageOfferErrorV5> {
        self.transport.original_socket_cookie_v5()
    }

    pub(super) fn original_transport_v5(&mut self) -> &mut OriginalStorageOfferTransportV5 {
        &mut self.transport
    }

    fn pending() -> Self {
        Self {
            stage: OfferStageV5::StagePackets,
            transport: OriginalStorageOfferTransportV5::pending_original(),
            control: None,
            reply: None,
            mount_duplicate: None,
            physical: None,
            verified: None,
            record: None,
            before: Vec::new(),
            after: Vec::new(),
            failure: None,
        }
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.failure.as_ref()? {
            OfferFailureV5::Validation(cause) => Some(cause),
            OfferFailureV5::Transport => self.transport.failure(),
            OfferFailureV5::MountDuplicate => self.mount_duplicate.as_ref()?.as_ref().err().map(|cause| cause as _),
            OfferFailureV5::PhysicalObservation => self.physical.as_ref()?.as_ref().err().map(|cause| cause as _),
        }
    }

    fn close(&mut self) {
        self.stage = OfferStageV5::Closed;
        self.transport.close_original();
    }
}

// Returned originals stay in their resident slots. Abort before a short loan's
// stack unwinding could drop a moved temporary. Deeper pre-return producer
// prefixes and allocator aborts are not claimed as a completed custody proof.
struct OriginalOfferCrossingV5;

impl Drop for OriginalOfferCrossingV5 {
    fn drop(&mut self) {
        if std::thread::panicking() {
            std::process::abort();
        }
    }
}

impl FixedProviderOwnerV1 {
    /// Advances the genuine resident original pair through StoragePrepared only.
    ///
    /// Publication and row bytes are comparison DATA. They cannot create a
    /// Session, request, issuer, floor, SourceRoot result or recovery authority.
    /// Failures remain owned here and permanently close the original lane.
    #[doc(hidden)]
    pub fn advance_original_storage_offer_v5(
        &mut self,
        publication: &[u8],
        rows: &[u8],
    ) -> Progress {
        if self.original_ingress.producer_closed_v5() {
            return Progress::Closed;
        }
        let mut guard = OriginalProducerClosureGuardV5 {
            owner: self,
            completed: false,
        };
        let _crossing = OriginalOfferCrossingV5;
        let result = guard.owner.advance_original_storage_offer_inner_v5(publication, rows);
        match result {
            Ok(progress) => {
                guard.completed = progress != Progress::Closed;
                progress
            }
            Err(cause) => {
                if let Ok(producer) = guard.owner.original_source_producer_mut_v5()
                    && let Some(offer) = producer.storage_offer.as_mut()
                {
                    if offer.failure.is_none() {
                        offer.failure = Some(OfferFailureV5::Validation(cause));
                    }
                    offer.close();
                } else {
                    guard.owner.original_ingress.retain_producer_failure_v5(cause);
                }
                Progress::Closed
            }
        }
    }

    /// Borrows the actual first cause retained by the original producer/offer.
    #[must_use]
    pub fn original_storage_offer_failure_v5(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(cause) = self.retained_original_producer_failure_v5() {
            return Some(cause);
        }
        self.original_source_producer_v5().ok()?.storage_offer.as_ref()?.failure()
    }

    /// Closes the same original writer/runtime after a returned outer failure.
    ///
    /// The existing closure guard keeps all originals resident and poisons
    /// progress before diagnostics. This has no reset, release or fallback.
    #[doc(hidden)]
    pub fn close_original_storage_offer_after_failure_v5(&mut self) {
        self.close_original_held_upper_failure_v5();
        let guard = OriginalProducerClosureGuardV5 {
            owner: self,
            completed: false,
        };
        if let Ok(producer) = guard.owner.original_source_producer_mut_v5()
            && let Some(offer) = producer.storage_offer.as_mut()
        {
            offer.close();
        }
    }

    fn advance_original_storage_offer_inner_v5(
        &mut self,
        publication: &[u8],
        rows: &[u8],
    ) -> Result<Progress, OriginalProducerErrorV5> {
        // This equality is an original signed-byte comparison, not hash authority.
        let expected = self.original_ingress.borrowed_selection_v5()?
            .original_publication_projection().1;
        if publication.len() != super::super::CANONICAL_CATALOG_PUBLICATION_BYTES
            || ObjectDigest::from_bytes(Sha256::digest(publication).into()) != expected
        {
            return Err(ProviderLedgerError::ConfigurationMismatch.into());
        }

        let has_offer = self.original_source_producer_v5()
            .is_ok_and(|producer| producer.storage_offer.is_some());
        if !has_offer {
            if !matches!(self.advance_original_source_producer_v5(rows), OriginalProducerObservationV5::Ready(_)) {
                return Ok(Progress::Closed);
            }
            // Park the entire fixed reservoir before endpoint or later key work.
            self.original_source_producer_mut_v5()?.storage_offer = Some(OriginalStorageOfferV5::pending());
        }
        self.require_original_offer_current_v5()?;
        let stage = self.original_offer_v5()?.stage;
        match stage {
            OfferStageV5::StagePackets => {
                let (root, _) = self.original_ingress.borrowed_pair_v5()?;
                let Some(FixedProviderOwnerStateV1::HeldReadOnly(held)) = self.state.as_mut() else {
                    return Err(ProviderLedgerError::Unavailable.into());
                };
                let producer = held.original.as_mut().and_then(|original| original.producer.as_mut())
                    .ok_or(ProviderLedgerError::Unavailable)?;
                let signed = producer.signed.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
                let clock = self.original_ingress.borrowed_clock_v5()?;
                let (initial, original_deadline) = clock.original_sample_and_deadline();
                let stage_deadline = clock.original_stage_deadline(signed.request().claims().validity().1)?;
                let offer = producer.storage_offer.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
                offer.transport.stage_original_packets(
                    root.control(), signed, initial, original_deadline, stage_deadline,
                )?;
                offer.stage = OfferStageV5::Exchange;
            }
            OfferStageV5::Exchange => {
                self.original_offer_mut_v5()?.transport.advance_original();
                if self.original_offer_v5()?.transport.is_closed() {
                    let offer = self.original_offer_mut_v5()?;
                    offer.failure = Some(OfferFailureV5::Transport);
                    offer.close();
                    return Ok(Progress::Closed);
                }
                // Verify the first control before consuming the second record.
                if self.original_offer_v5()?.control.is_none()
                    && self.original_offer_v5()?.transport.control_packet().is_some()
                {
                    self.retain_original_storage_control_v5()?;
                }
                if self.original_offer_v5()?.transport.is_offered() {
                    let offer = self.original_offer_mut_v5()?;
                    let packet = offer.transport.reply_packet().ok_or(ProviderLedgerError::Unavailable)?;
                    if offer.control.as_ref().and_then(|control| control.section(Tag::NativeReply)) != Some(packet)
                        || offer.reply.is_none()
                    {
                        return Err(ProviderLedgerError::Equivocation.into());
                    }
                    offer.stage = OfferStageV5::ObserveMount;
                }
            }
            OfferStageV5::ObserveMount => {
                self.observe_original_storage_mount_v5()?;
                if self.original_offer_v5()?.failure.is_some() {
                    self.original_offer_mut_v5()?.close();
                    return Ok(Progress::Closed);
                }
                self.original_offer_mut_v5()?.stage = OfferStageV5::ValidateReply;
            }
            OfferStageV5::ValidateReply => {
                self.validate_original_storage_reply_v5()?;
                self.original_offer_mut_v5()?.stage = OfferStageV5::PrepareCheckpoint;
            }
            OfferStageV5::PrepareCheckpoint => {
                self.prepare_original_storage_checkpoint_v5()?;
                self.original_offer_mut_v5()?.stage = OfferStageV5::CommitCheckpoint;
            }
            OfferStageV5::CommitCheckpoint => {
                self.append_original_producer_step_v5(Append::StoragePrepared)?;
                self.require_original_storage_readback_v5()?;
                self.original_offer_mut_v5()?.stage = OfferStageV5::Prepared;
            }
            OfferStageV5::Prepared => return Ok(Progress::StoragePrepared),
            OfferStageV5::Closed => return Ok(Progress::Closed),
        }
        self.require_original_offer_current_v5()?;
        Ok(if self.original_offer_v5()?.stage == OfferStageV5::Prepared {
            Progress::StoragePrepared
        } else {
            Progress::Pending
        })
    }

    pub(super) fn original_offer_v5(&self) -> Result<&OriginalStorageOfferV5, ProviderLedgerError> {
        self.original_source_producer_v5()?.storage_offer.as_ref().ok_or(ProviderLedgerError::Unavailable)
    }

    fn original_offer_mut_v5(&mut self) -> Result<&mut OriginalStorageOfferV5, ProviderLedgerError> {
        self.original_source_producer_mut_v5()?.storage_offer.as_mut().ok_or(ProviderLedgerError::Unavailable)
    }

    pub(super) fn require_original_offer_current_v5(&mut self) -> Result<(), OriginalProducerErrorV5> {
        self.require_original_producer_current_v5()?;
        let offer = self.original_offer_v5()?;
        if offer.stage == OfferStageV5::Closed || offer.failure.is_some() {
            return Err(ProviderLedgerError::RuntimePoisoned.into());
        }
        if !matches!(offer.stage, OfferStageV5::StagePackets)
            && (offer.transport.control_packet().is_some() || offer.transport.is_offered())
        {
            self.original_offer_mut_v5()?.transport.revalidate_original()?;
        }
        let offer = self.original_offer_v5()?;
        if let Some(Ok(physical)) = &offer.physical {
            physical.revalidate()?;
        }
        // Pair last, after the potentially lengthy real custody observations.
        let expires = offer.reply.as_ref().map(|reply| reply.receipt().receipt().validity().1);
        self.original_ingress.borrowed_clock_v5()?.revalidate(expires)?;
        Ok(())
    }

    fn retain_original_storage_control_v5(&mut self) -> Result<(), OriginalProducerErrorV5> {
        let Some(FixedProviderOwnerStateV1::HeldReadOnly(held)) = self.state.as_mut() else {
            return Err(ProviderLedgerError::Unavailable.into());
        };
        let original = held.original.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
        let producer = original.producer.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
        let signed = producer.signed.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
        let offer = producer.storage_offer.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
        let packet = offer.transport.control_packet().ok_or(ProviderLedgerError::Unavailable)?;
        offer.control = Some(SignedNativeHeldControlV1::from_canonical_bytes(packet)?);
        let control = offer.control.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
        let root = self.original_ingress.borrowed_pair_v5()?.0.control();
        let (signer, key) = original.history.storage.as_ref().ok_or(ProviderLedgerError::Unavailable)?
            .protocol_verifier()?.projection();
        if control.kind() != Kind::StorageHeld
            || control.predecessor() != root.digest()
            || control.section(Tag::RootPrepared) != Some(root.to_canonical_bytes().as_slice())
            || control.scope().original_native_request != signed.digest()
            || control.scope().provider_attempt != signed.request().claims().attempt().1
        {
            return Err(ProviderLedgerError::Equivocation.into());
        }
        control.scope().require_root_prefix(root.scope())?;
        control.verify_signature_claim(&NativeHeldSignerV1::Storage(signer), &key)?;
        offer.reply = Some(StorageNativeAcquireReplyV3::from_canonical_bytes(
            control.section(Tag::NativeReply).ok_or(ProviderLedgerError::Equivocation)?,
        )?);
        let expires = offer.reply.as_ref().ok_or(ProviderLedgerError::Unavailable)?
            .receipt().receipt().validity().1;
        let clock = self.original_ingress.borrowed_clock_v5()?;
        clock.revalidate(Some(expires))?;
        let cutoff = expires.min(signed.request().claims().validity().1);
        offer.transport.narrow_original_receipt(cutoff, clock.original_stage_deadline(cutoff)?)?;
        offer.transport.revalidate_original()?;
        Ok(())
    }

    fn observe_original_storage_mount_v5(&mut self) -> Result<(), OriginalProducerErrorV5> {
        let producer = self.original_source_producer_mut_v5()?;
        let plan = producer.physical_plan.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
        let offer = producer.storage_offer.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
        offer.mount_duplicate = Some(offer.transport.original_mount_descriptor()?.try_clone_to_owned());
        if offer.mount_duplicate.as_ref().is_some_and(Result::is_err) {
            offer.failure = Some(OfferFailureV5::MountDuplicate);
            return Ok(());
        }
        let descriptor = offer.mount_duplicate.take().and_then(Result::ok)
            .ok_or(ProviderLedgerError::Unavailable)?;
        offer.physical = Some(plan.observe_source_root(descriptor));
        if offer.physical.as_ref().is_some_and(Result::is_err) {
            offer.failure = Some(OfferFailureV5::PhysicalObservation);
        }
        Ok(())
    }

    fn validate_original_storage_reply_v5(&mut self) -> Result<(), OriginalProducerErrorV5> {
        let selection = self.original_ingress.borrowed_selection_v5()?;
        let (resource, snapshot) = selection.original_selected_tuple();
        let snapshot = snapshot.ok_or(ProviderLedgerError::ConfigurationMismatch)?;
        let Some(FixedProviderOwnerStateV1::HeldReadOnly(held)) = self.state.as_mut() else {
            return Err(ProviderLedgerError::Unavailable.into());
        };
        let original = held.original.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
        let current = original.history.current.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
        let storage = original.history.storage.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
        let producer = original.producer.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
        let signed = producer.signed.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
        let offer = producer.storage_offer.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
        offer.transport.revalidate_original()?;
        let reply = offer.reply.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
        let control = offer.control.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
        if control.section(Tag::NativeReply) != offer.transport.reply_packet() {
            return Err(ProviderLedgerError::Equivocation.into());
        }
        let physical = offer.physical.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or(ProviderLedgerError::Unavailable)?;
        let receipt = reply.receipt().receipt();
        let claims = signed.request().claims();
        // Selection is independently protected. Head/time are this genuine
        // same-child stored original offer's cut, not proof of a perpetual
        // remote global head or authority from self-agreeing decoded packets.
        let expected = StorageZfsHoldReceiptV1::new(
            claims.attempt().0, claims.attempt().1, claims.selection().0,
            resource.clone(), snapshot.clone(), receipt.head(),
            receipt.validity().0, receipt.validity().1,
        )?;
        let provider = signed.signer();
        let root = signed.request().signed_root_request().signer();
        if provider != current.outcome_signer() {
            return Err(ProviderLedgerError::ConfigurationMismatch.into());
        }
        let verified = reply.verify_for(StorageNativeAcquireVerificationV3 {
            request: signed,
            provider_signer: provider,
            provider_key: current.currently_eligible_public_key_for(provider)
                .ok_or(ProviderLedgerError::Unavailable)?,
            root_signer: root,
            root_key: current.currently_eligible_public_key_for(root)
                .ok_or(ProviderLedgerError::Unavailable)?,
            storage_verifier: storage.protocol_verifier()?,
            expected_receipt: &expected,
            observed_descriptor: physical.observation(),
            descriptor_roles: &[SourceProviderDescriptorRole::SourceRoot],
            now_seconds: current_seconds()?,
        })?;
        offer.verified = Some(verified);
        physical.bind_native_acceptance(offer.verified.as_ref().ok_or(ProviderLedgerError::Unavailable)?)?;
        storage.revalidate()?;
        offer.transport.revalidate_original()?;
        Ok(())
    }

    fn prepare_original_storage_checkpoint_v5(&mut self) -> Result<(), OriginalProducerErrorV5> {
        let Some(FixedProviderOwnerStateV1::HeldReadOnly(held)) = self.state.as_mut() else {
            return Err(ProviderLedgerError::Unavailable.into());
        };
        let producer = held.original.as_mut().and_then(|original| original.producer.as_mut())
            .ok_or(ProviderLedgerError::Unavailable)?;
        let signed = producer.signed.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
        let acquisition = signed.request().claims().provider_acquisition().1;
        let key = native_completion_key_v2(acquisition);
        let challenges = self.hold_challenges.original_history_v5()?;
        let authority = self.journal.as_mut().ok_or(ProviderLedgerError::RuntimePoisoned)?
            .claim_source_original_native_v5(&challenges)?;
        let replay = authority.replayed_origins()?;
        let previous = SourceNativeHeldCompletionRecordV1::from_canonical_bytes(
            &key, replay.current_rows().get(&(RecordNamespace::SourceProviderAuthority, key.clone()))
                .ok_or(ProviderLedgerError::Unavailable)?,
        )?;
        let issued = producer.staged.as_ref()
            .and_then(crate::zfs_hold_challenge::StagedZfsHoldChallengeV1::original_readback_v5)
            .ok_or(ProviderLedgerError::Unavailable)?;
        let offer = producer.storage_offer.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
        let original = previous.original().prepare_accepted(
            offer.reply.as_ref().ok_or(ProviderLedgerError::Unavailable)?.clone(),
            offer.verified.as_ref().ok_or(ProviderLedgerError::Unavailable)?,
        )?;
        let mut controls = previous.suffix().controls().to_vec();
        controls.push(offer.control.as_ref().ok_or(ProviderLedgerError::Unavailable)?.clone());
        offer.record = Some(SourceNativeHeldCompletionRecordV1::new(original,
            NativeHeldCompletionSuffixV1::new(
                Role::Provider, 2, previous.suffix().flight(),
                previous.suffix().prepared().cloned(), controls,
            )?,
        )?);
        let bytes = offer.record.as_ref().ok_or(ProviderLedgerError::Unavailable)?.to_canonical_bytes()?;
        let limits = authority.configured_limits();
        retain_projection(&mut offer.before, replay.current_rows(), None, limits)?;
        retain_projection(&mut offer.after, replay.current_rows(), Some((&key, &bytes)), limits)?;
        propose_native_held_transition_v1(
            offer.before.iter().map(|(key, value)| (key.as_slice(), value.as_slice())),
            offer.after.iter().map(|(key, value)| (key.as_slice(), value.as_slice())),
            acquisition, SourceNativeHeldStepV1::StoragePrepared, Some(issued),
        )?;
        let owner = owner_transaction_v5(b"original-source-storage-prepared-v5", vec![(key, Some(bytes))])?;
        let (before_floor, after_floor) = authority.derive_original_floor_transfer_v5(&owner, acquisition)?;
        let mut records = owner.records().to_vec();
        records.push(JournalRecord::delete(RecordNamespace::GlobalCapacityReservation,
            before_floor.to_journal_record()?.key().to_vec()));
        records.push(after_floor.to_journal_record()?);
        producer.park(Append::StoragePrepared, JournalTransaction::new(*owner.id(), records)?)?;
        held.session.current_projection()?;
        Ok(())
    }

    fn require_original_storage_readback_v5(&mut self) -> Result<(), OriginalProducerErrorV5> {
        let producer = self.original_source_producer_v5()?;
        let offer = producer.storage_offer.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
        let record = offer.record.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
        let acquisition = record.original().acquisition_id;
        let key = native_completion_key_v2(acquisition);
        let readback = producer.readback(Append::StoragePrepared)?;
        if readback.rows().get(&(RecordNamespace::SourceProviderAuthority, key))
            != Some(&record.to_canonical_bytes()?)
        {
            return Err(ProviderLedgerError::Equivocation.into());
        }
        Ok(())
    }
}

// The two projections are bounded DATA, never historical-prefix caches. Reserve
// their entries and park each empty row before fallible key/value retention.
pub(super) fn retain_projection(
    target: &mut Vec<(Vec<u8>, Vec<u8>)>,
    rows: &SourceCapacityStateV5,
    replacement: Option<(&[u8], &[u8])>,
    limits: aos_sandbox::JournalLimits,
) -> Result<(), OriginalProducerErrorV5> {
    if !target.is_empty() {
        return Err(ProviderLedgerError::Equivocation.into());
    }
    let mut count = 0_usize;
    let mut bytes = 0_usize;
    for ((namespace, key), value) in rows {
        if *namespace != RecordNamespace::SourceProviderAuthority {
            continue;
        }
        let value = replacement.filter(|(changed, _)| *changed == key.as_slice())
            .map_or(value.as_slice(), |(_, value)| value);
        count = count.checked_add(1).ok_or(ProviderLedgerError::Unavailable)?;
        bytes = bytes.checked_add(key.len()).and_then(|size| size.checked_add(value.len()))
            .ok_or(ProviderLedgerError::Unavailable)?;
        if count > limits.maximum_materialized_records || bytes > limits.maximum_materialized_bytes
            || key.len() > limits.maximum_key_bytes || value.len() > limits.maximum_record_bytes
        {
            return Err(ProviderLedgerError::Unavailable.into());
        }
    }
    target.try_reserve_exact(count)?;
    for ((namespace, key), value) in rows {
        if *namespace != RecordNamespace::SourceProviderAuthority {
            continue;
        }
        let value = replacement.filter(|(changed, _)| *changed == key.as_slice())
            .map_or(value.as_slice(), |(_, value)| value);
        target.push((Vec::new(), Vec::new()));
        let (retained_key, retained_value) = target.last_mut().ok_or(ProviderLedgerError::Unavailable)?;
        retained_key.try_reserve_exact(key.len())?;
        retained_key.extend_from_slice(key);
        retained_value.try_reserve_exact(value.len())?;
        retained_value.extend_from_slice(value);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! UNRUN bounded projection DATA, not genuine origins or journal fixtures.

    use super::*;

    fn rows() -> SourceCapacityStateV5 {
        let mut rows = SourceCapacityStateV5::new();
        rows.insert((RecordNamespace::SourceProviderAuthority, vec![1]), vec![2, 3]);
        rows
    }

    #[test]
    fn replacement_changes_only_the_borrowed_after_projection() {
        let rows = rows();
        let mut before = Vec::new();
        let mut after = Vec::new();

        retain_projection(&mut before, &rows, None, aos_sandbox::JournalLimits::default()).unwrap();
        retain_projection(&mut after, &rows, Some((&[1], &[4, 5])), aos_sandbox::JournalLimits::default()).unwrap();

        assert_eq!(before, vec![(vec![1], vec![2, 3])]);
        assert_eq!(after, vec![(vec![1], vec![4, 5])]);
        assert_eq!(rows.get(&(RecordNamespace::SourceProviderAuthority, vec![1])), Some(&vec![2, 3]));
    }

    #[test]
    fn extent_refusal_precedes_projection_allocation() {
        let limits = aos_sandbox::JournalLimits {
            maximum_materialized_bytes: 2,
            ..aos_sandbox::JournalLimits::default()
        };
        let mut retained = Vec::new();

        assert!(retain_projection(&mut retained, &rows(), None, limits).is_err());

        assert!(retained.is_empty());
        assert_eq!(retained.capacity(), 0);
    }

    #[test]
    fn nonempty_projection_cannot_be_overwritten() {
        let mut retained = vec![(vec![9], vec![8])];

        assert!(retain_projection(&mut retained, &rows(), None,
            aos_sandbox::JournalLimits::default()).is_err());

        assert_eq!(retained, vec![(vec![9], vec![8])]);
    }
}

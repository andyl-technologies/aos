//! Resident original phase5 preparation and phase6 signed Held readback.
//!
//! Only the hot Complete owner installs this child. Its two later appends use
//! the same archive, challenge, floor and Journal engines. The selected delivery
//! adapter subsequently sends once without releasing any original owner.

use super::*;
use aos_sandbox_source_provider_protocol::native_held_completion::{
    frame::{NativeHeldSectionV1, NativeHeldSignerV1},
    witness::NativeHeldOwnerWitnessV1,
};
use aos_sandbox_source_provider_security::{
    OriginalProviderHeldSignaturesV5, OriginalStorageOfferErrorV5,
    SourceProviderSecurityError,
};
use std::num::NonZeroU64;
use sha2::Digest as _;

#[derive(Clone, Copy, Eq, PartialEq)]
enum HeldStageV5 {
    Prepare,
    CommitPreparation,
    Sign,
    PrepareSigned,
    CommitSigned,
    Stored,
    Closed,
}

/// Empty only through the actual Complete owner; it is not a resume recipe.
pub(super) struct OriginalSourceHeldV5 {
    stage: HeldStageV5,
    signatures: OriginalProviderHeldSignaturesV5,
    source_cookie: Option<Result<NonZeroU64, SourceProviderSecurityError>>,
    storage_cookie: Option<Result<NonZeroU64, OriginalStorageOfferErrorV5>>,
    unsigned: Option<PreparedNativeHeldControlV1>,
    phase5: Option<SourceNativeHeldCompletionRecordV1>,
    phase6: Option<SourceNativeHeldCompletionRecordV1>,
    before: [Vec<(Vec<u8>, Vec<u8>)>; 2],
    after: [Vec<(Vec<u8>, Vec<u8>)>; 2],
    actions: [Option<Result<(), OriginalProducerErrorV5>>; 5],
    boundary: Option<OriginalProducerErrorV5>,
    postcheck_debt: Option<OriginalProducerErrorV5>,
}

impl OriginalSourceHeldV5 {
    fn pending(signatures: OriginalProviderHeldSignaturesV5) -> Self {
        Self {
            stage: HeldStageV5::Prepare,
            signatures,
            source_cookie: None,
            storage_cookie: None,
            unsigned: None,
            phase5: None,
            phase6: None,
            before: std::array::from_fn(|_| Vec::new()),
            after: std::array::from_fn(|_| Vec::new()),
            actions: std::array::from_fn(|_| None),
            boundary: None,
            postcheck_debt: None,
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.boundary.as_ref().map(|cause| cause as _)
            .or_else(|| self.source_cookie.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.storage_cookie.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.actions.iter().find_map(|result| {
                result.as_ref()?.as_ref().err().map(|cause| cause as _)
            }))
            .or_else(|| self.signatures.failure())
            .or_else(|| self.postcheck_debt.as_ref().map(|cause| cause as _))
    }
}

// Selected upper failure poisons the SAME Session before the existing producer
// guard closes its ingress/history/runtime. Neither guard takes original FDs.
struct OriginalHeldClosureV5<'owner> {
    original: OriginalProducerClosureGuardV5<'owner>,
}

impl Drop for OriginalHeldClosureV5<'_> {
    fn drop(&mut self) {
        if !self.original.completed {
            if let Some(FixedProviderOwnerStateV1::HeldReadOnly(held)) = self.original.owner.state.as_mut() {
                held.session.close_original_held_after_failure_v5();
            }
        }
    }
}

impl FixedProviderOwnerV1 {
    /// Advances the hot original flight through local Held and Complete sends.
    ///
    /// The same resident signing reservoir owns both whole native results.
    /// Local transmission never supplies Root acceptance, settlement or drain.
    #[doc(hidden)]
    pub fn advance_original_native_delivery_v5(
        &mut self,
        publication: &[u8],
        rows: &[u8],
    ) -> Progress {
        let started = self.original_held_v5()
            .is_ok_and(|child| child.signatures.delivery_started());
        if !started {
            match self.advance_original_native_held_v5(publication, rows) {
                Progress::HeldStored => {}
                progress => return progress,
            }
            // Genuine phase6 owns the empty reservoir already. Infallibly arm
            // its SAME carrier before any new delivery observation can fail.
            if let Some(FixedProviderOwnerStateV1::HeldReadOnly(held)) = self.state.as_mut()
                && let Some(child) = held.original.as_mut()
                    .and_then(|original| original.producer.as_mut())
                    .and_then(|producer| producer.original_completion.as_mut())
                    .and_then(|completion| completion.held.as_mut())
            {
                held.session.begin_original_held_delivery_v5(&mut child.signatures);
            } else {
                self.original_ingress.retain_producer_failure_v5(ProviderLedgerError::Unavailable.into());
                return Progress::Closed;
            }
        }
        if self.original_ingress.producer_closed_v5() {
            return Progress::Closed;
        }

        let mut guard = OriginalHeldClosureV5 {
            original: OriginalProducerClosureGuardV5 {
                owner: self,
                completed: false,
            },
        };
        let _crossing = OriginalCompletionCrossingV5;
        let progress = guard.original.owner.advance_original_delivery_inner_v5(publication, rows);
        guard.original.completed = progress != Progress::Closed;
        progress
    }

    fn advance_original_delivery_inner_v5(
        &mut self,
        publication: &[u8],
        rows: &[u8],
    ) -> Progress {
        let before = (|| {
            if self.original_ingress.borrowed_catalog_v1()? != rows {
                return Err(ProviderLedgerError::Equivocation.into());
            }
            let expected = self.original_ingress.borrowed_selection_v5()?.original_publication_projection().1;
            if publication.len() != super::super::super::CANONICAL_CATALOG_PUBLICATION_BYTES
                || ObjectDigest::from_bytes(sha2::Sha256::digest(publication).into()) != expected
            {
                return Err(ProviderLedgerError::ConfigurationMismatch.into());
            }
            self.require_original_held_current_v5()?;
            self.require_original_held_readback_v5(Append::HeldStored)
        })();
        if let Err(cause) = before {
            if let Ok(child) = self.original_held_mut_v5() {
                if child.failure().is_none() {
                    child.boundary = Some(cause);
                }
                child.stage = HeldStageV5::Closed;
            } else {
                self.original_ingress.retain_producer_failure_v5(cause);
            }
            return Progress::Closed;
        }
        if self.original_held_v5().is_ok_and(|child| child.signatures.delivery_complete()) {
            // A later observation may recheck, but never resends either packet.
            return Progress::CompleteSent;
        }

        let action = self.send_original_held_packet_v5();
        if let Err(cause) = action {
            if let Ok(child) = self.original_held_mut_v5() {
                if child.failure().is_none() {
                    child.boundary = Some(cause);
                }
            } else {
                self.original_ingress.retain_producer_failure_v5(cause);
                return Progress::Closed;
            }
        }
        // The actual native Result is already in the opaque child. These
        // upper bookends retain separate debt, including after successful send.
        let postcheck = self.require_original_held_current_v5()
            .and_then(|()| self.require_original_held_readback_v5(Append::HeldStored));
        let Ok(child) = self.original_held_mut_v5() else {
            if let Err(cause) = postcheck {
                self.original_ingress.retain_producer_failure_v5(cause);
            }
            return Progress::Closed;
        };
        if let Err(cause) = postcheck {
            if child.postcheck_debt.is_none() {
                child.postcheck_debt = Some(cause);
            }
        }
        if child.failure().is_some() {
            child.stage = HeldStageV5::Closed;
            Progress::Closed
        } else if child.signatures.delivery_complete() {
            Progress::CompleteSent
        } else if child.signatures.provider_held_sent() {
            Progress::ProviderHeldSent
        } else {
            child.stage = HeldStageV5::Closed;
            Progress::Closed
        }
    }

    fn send_original_held_packet_v5(&mut self) -> Result<(), OriginalProducerErrorV5> {
        let (root, acquire) = self.original_ingress.borrowed_pair_v5()?;
        let clock = self.original_ingress.borrowed_clock_v5()?;
        let (initial, _) = clock.original_sample_and_deadline();
        let expiry = self.original_held_expiry_v5()?;
        let deadline = clock.original_stage_deadline(expiry)?;
        let Some(FixedProviderOwnerStateV1::HeldReadOnly(held)) = self.state.as_mut() else {
            return Err(ProviderLedgerError::Unavailable.into());
        };
        let original = held.original.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
        let archive = original.history.archive.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
        let producer = original.producer.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
        let issued = producer.signed.as_ref().ok_or(ProviderLedgerError::Unavailable)?
            .request().claims().validity().0;
        let history = self.hold_challenges.original_history_v5()?;
        let authority = self.journal.as_mut().ok_or(ProviderLedgerError::RuntimePoisoned)?
            .claim_source_original_native_v5(&history)?;
        let (readback, completion, selected, offer) = producer.held_delivery_parts_v5()?;
        let validity = (
            issued.max(completion.lease.as_ref().ok_or(ProviderLedgerError::Unavailable)?.validity().0),
            expiry,
        );
        let physical = completion.handoff.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ProviderLedgerError::Unavailable)?;
        let complete = completion.signatures.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
        let lease = complete.signed_lease().ok_or(ProviderLedgerError::Unavailable)?;
        let response = complete.response().ok_or(ProviderLedgerError::Unavailable)?;
        let child = completion.held.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
        held.session.advance_original_held_delivery_v5(
            &authority, readback, root, acquire, physical, lease, archive, selected,
            offer.original_transport_v5(), response, initial, deadline, validity, &mut child.signatures,
        );
        Ok(())
    }

    /// Advances the SAME original Complete flight to an unsent resident Held.
    ///
    /// No DATA input can start this child after restart. Stored progress does
    /// not authorize Root acceptance, packet handoff, relay, settlement or drain.
    #[doc(hidden)]
    pub fn advance_original_native_held_v5(
        &mut self,
        publication: &[u8],
        rows: &[u8],
    ) -> Progress {
        let installed = self.original_completion_v5().is_ok_and(|completion| completion.held.is_some());
        if !installed {
            match self.advance_original_native_completion_v5(publication, rows) {
                Progress::CompleteCommitted => {}
                progress => return progress,
            }
            // No fallible check separates genuine Complete from ownership of
            // the empty child and persistent selected Session disposition.
            if let Some(FixedProviderOwnerStateV1::HeldReadOnly(held)) = self.state.as_mut()
                && let Some(completion) = held.original.as_mut()
                    .and_then(|original| original.producer.as_mut())
                    .and_then(|producer| producer.original_completion.as_mut())
            {
                completion.held = Some(OriginalSourceHeldV5::pending(
                    held.session.begin_original_held_v5(),
                ));
                return Progress::Pending;
            }
            self.original_ingress.retain_producer_failure_v5(ProviderLedgerError::Unavailable.into());
            return Progress::Closed;
        }
        if self.original_ingress.producer_closed_v5() {
            return Progress::Closed;
        }

        let mut guard = OriginalHeldClosureV5 {
            original: OriginalProducerClosureGuardV5 {
                owner: self,
                completed: false,
            },
        };
        let _crossing = OriginalCompletionCrossingV5;
        let progress = guard.original.owner.advance_original_held_inner_v5(publication, rows);
        guard.original.completed = progress != Progress::Closed;
        progress
    }

    fn original_held_v5(&self) -> Result<&OriginalSourceHeldV5, ProviderLedgerError> {
        self.original_completion_v5()?.held.as_ref()
            .ok_or(ProviderLedgerError::Unavailable)
    }

    fn original_held_mut_v5(&mut self) -> Result<&mut OriginalSourceHeldV5, ProviderLedgerError> {
        self.original_completion_mut_v5()?.held.as_mut()
            .ok_or(ProviderLedgerError::Unavailable)
    }

    pub(in crate::owner::original_journal) fn close_original_held_upper_failure_v5(&mut self) {
        if let Some(FixedProviderOwnerStateV1::HeldReadOnly(held)) = self.state.as_mut()
            && held.original.as_ref().and_then(|original| original.producer.as_ref())
                .and_then(|producer| producer.original_completion.as_ref())
                .is_some_and(|completion| completion.held.is_some())
        {
            held.session.close_original_held_after_failure_v5();
        }
    }

    pub(in crate::owner::original_journal) fn original_held_expiry_v5(
        &self,
    ) -> Result<i64, ProviderLedgerError> {
        self.original_completion_v5()?.lease.as_ref().map(|lease| lease.validity().1)
            .ok_or(ProviderLedgerError::Unavailable)
    }

    pub(in crate::owner::original_journal) fn require_original_held_current_v5(
        &mut self,
    ) -> Result<(), OriginalProducerErrorV5> {
        self.require_original_offer_current_v5()?;
        self.require_selected_enrollments_v1()?;
        let producer = self.original_source_producer_v5()?;
        if !producer.selected_archive_attempted
            || producer.selected_archive.as_ref().is_none_or(Result::is_err)
            || self.original_held_v5()?.stage == HeldStageV5::Closed
        {
            return Err(ProviderLedgerError::RuntimePoisoned.into());
        }
        self.require_retained_selected_archive_v1()?;
        let completion = self.original_completion_v5()?;
        if completion.stage != CompletionStageV5::CompleteHeld || completion.failure.is_some() {
            return Err(ProviderLedgerError::RuntimePoisoned.into());
        }
        let expiry = self.original_held_expiry_v5()?;
        let Some(FixedProviderOwnerStateV1::HeldReadOnly(held)) = self.state.as_mut() else {
            return Err(ProviderLedgerError::Unavailable.into());
        };
        let physical = held.original.as_ref().and_then(|original| original.producer.as_ref())
            .and_then(|producer| producer.original_completion.as_ref())
            .and_then(|completion| completion.handoff.as_ref())
            .and_then(|result| result.as_ref().ok())
            .ok_or(ProviderLedgerError::Unavailable)?;
        held.session.revalidate_original_held_mount_v5(physical)?;
        // Pair last after the complete current replay, enrollments and file.
        self.original_ingress.borrowed_clock_v5()?.revalidate(Some(expiry))?;
        Ok(())
    }

    fn advance_original_held_inner_v5(
        &mut self,
        publication: &[u8],
        rows: &[u8],
    ) -> Progress {
        let before = (|| {
            if self.original_ingress.borrowed_catalog_v1()? != rows {
                return Err(ProviderLedgerError::Equivocation.into());
            }
            let expected = self.original_ingress.borrowed_selection_v5()?.original_publication_projection().1;
            if publication.len() != super::super::super::CANONICAL_CATALOG_PUBLICATION_BYTES
                || ObjectDigest::from_bytes(sha2::Sha256::digest(publication).into()) != expected
            {
                return Err(ProviderLedgerError::ConfigurationMismatch.into());
            }
            self.require_original_held_current_v5()?;
            if self.original_held_v5()?.stage == HeldStageV5::Stored {
                self.require_original_held_readback_v5(Append::HeldStored)?;
            }
            Ok::<_, OriginalProducerErrorV5>(())
        })();
        if let Err(cause) = before {
            if let Ok(child) = self.original_held_mut_v5() {
                if child.failure().is_none() {
                    child.boundary = Some(cause);
                }
                child.stage = HeldStageV5::Closed;
            } else {
                self.original_ingress.retain_producer_failure_v5(cause);
            }
            return Progress::Closed;
        }
        let stage = match self.original_held_v5() {
            Ok(child) => child.stage,
            Err(_) => return Progress::Closed,
        };
        let (index, next, action) = match stage {
            HeldStageV5::Prepare => (
                0, HeldStageV5::CommitPreparation,
                self.prepare_original_held_checkpoint_v5(false),
            ),
            HeldStageV5::CommitPreparation => (
                1, HeldStageV5::Sign,
                self.append_original_held_checkpoint_v5(Append::HeldPrepared),
            ),
            HeldStageV5::Sign => (
                2, HeldStageV5::PrepareSigned,
                self.sign_original_held_checkpoint_v5(),
            ),
            HeldStageV5::PrepareSigned => (
                3, HeldStageV5::CommitSigned,
                self.prepare_original_held_checkpoint_v5(true),
            ),
            HeldStageV5::CommitSigned => (
                4, HeldStageV5::Stored,
                self.append_original_held_checkpoint_v5(Append::HeldStored),
            ),
            HeldStageV5::Stored => return Progress::HeldStored,
            HeldStageV5::Closed => return Progress::Closed,
        };
        // This sole infallible park precedes every later currentness bookend.
        if let Some(FixedProviderOwnerStateV1::HeldReadOnly(held)) = self.state.as_mut()
            && let Some(child) = held.original.as_mut().and_then(|original| original.producer.as_mut())
                .and_then(|producer| producer.original_completion.as_mut())
                .and_then(|completion| completion.held.as_mut())
        {
            child.actions[index] = Some(action);
        } else {
            if let Err(cause) = action {
                self.original_ingress.retain_producer_failure_v5(cause);
            }
            return Progress::Closed;
        }
        let postcheck = self.require_original_held_current_v5();
        let Ok(child) = self.original_held_mut_v5() else {
            if let Err(cause) = postcheck {
                self.original_ingress.retain_producer_failure_v5(cause);
            }
            return Progress::Closed;
        };
        if let Err(cause) = postcheck {
            if child.postcheck_debt.is_none() {
                child.postcheck_debt = Some(cause);
            }
        }
        if child.failure().is_some() {
            child.stage = HeldStageV5::Closed;
            Progress::Closed
        } else {
            child.stage = next;
            if next == HeldStageV5::Stored {
                Progress::HeldStored
            } else {
                Progress::Pending
            }
        }
    }

    fn prepare_original_held_checkpoint_v5(
        &mut self,
        signed: bool,
    ) -> Result<(), OriginalProducerErrorV5> {
        self.require_original_held_current_v5()?;
        let (_, acquire) = self.original_ingress.borrowed_pair_v5()?;
        let VerifiedProviderRequestV1::Acquire(verified) = acquire.verified() else {
            return Err(ProviderLedgerError::Equivocation.into());
        };
        let Some(FixedProviderOwnerStateV1::HeldReadOnly(held)) = self.state.as_mut() else {
            return Err(ProviderLedgerError::Unavailable.into());
        };
        let producer = held.original.as_mut().and_then(|original| original.producer.as_mut())
            .ok_or(ProviderLedgerError::Unavailable)?;
        let acquisition = producer.signed.as_ref().ok_or(ProviderLedgerError::Unavailable)?.request().claims().provider_acquisition().1;
        let history = self.hold_challenges.original_history_v5()?;
        let authority = self.journal.as_mut().ok_or(ProviderLedgerError::RuntimePoisoned)?
            .claim_source_original_native_v5(&history)?;
        let replay = authority.replayed_origins()?;
        let key = native_completion_key_v2(acquisition);
        let previous = SourceNativeHeldCompletionRecordV1::from_canonical_bytes(&key,
            replay.current_rows().get(&(RecordNamespace::SourceProviderAuthority, key.clone()))
                .ok_or(ProviderLedgerError::Unavailable)?)?;
        let expected_phase = if signed { 5 } else { 4 };
        if previous.suffix().phase() != expected_phase {
            return Err(ProviderLedgerError::Equivocation.into());
        }
        let selected = producer.selected_archive.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ProviderLedgerError::Unavailable)?;
        let completion_sequence = if signed {
            None
        } else {
            Some(authority.original_held_complete_cut_v5(
                producer.readback(Append::CompletionCommitted)?, acquisition,
            )?.frame_sequences().1)
        };
        let offer = producer.storage_offer.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
        let completion = producer.original_completion.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
        let child = completion.held.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
        let index = usize::from(signed);
        let spent = completion.spend.as_ref().and_then(StagedOriginalZfsHoldSpendV5::readback)
            .ok_or(ProviderLedgerError::Unavailable)?;
        if !signed {
            let expiry = completion.lease.as_ref().ok_or(ProviderLedgerError::Unavailable)?.validity().1;
            self.original_ingress.borrowed_clock_v5()?.revalidate(Some(expiry))?;
            child.source_cookie = Some(held.session.original_held_socket_cookie_v5());
            let source_cookie = *child.source_cookie.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(ProviderLedgerError::Unavailable)?;
            self.original_ingress.borrowed_clock_v5()?.revalidate(Some(expiry))?;
            child.storage_cookie = Some(offer.original_socket_cookie_v5());
            let storage_cookie = *child.storage_cookie.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(ProviderLedgerError::Unavailable)?;
            let (witness, artifact) = crate::ledger::native_held_completion::derive_provider_held_preparation_data_v5(
                replay.current_rows().iter().filter(|((namespace, _), _)| *namespace == RecordNamespace::SourceProviderAuthority)
                    .map(|((_, key), value)| (key.as_slice(), value.as_slice())),
                acquisition, spent, source_cookie, storage_cookie,
                completion_sequence.ok_or(ProviderLedgerError::Unavailable)?, history.current_prefix()?.1, selected.frame(),
            )?;
            let storage = previous.suffix().control(Kind::StorageHeld).ok_or(ProviderLedgerError::Unavailable)?;
            child.unsigned = Some(PreparedNativeHeldControlV1::new(
                Kind::ProviderHeld,
                selected.frame().fields().scope,
                storage.digest(),
                vec![
                    NativeHeldSectionV1::new(
                        Tag::Witness,
                        NativeHeldOwnerWitnessV1::Provider(witness).to_canonical_bytes()?,
                    )?,
                    NativeHeldSectionV1::new(Tag::StorageHeld, storage.to_canonical_bytes())?,
                    NativeHeldSectionV1::new(Tag::SourceArtifact, artifact.as_bytes().to_vec())?,
                ],
                NativeHeldSignerV1::SourceProvider(
                    verified.ingress_projection().ordered_signers()[3].clone(),
                ),
            )?);
        }
        let mut original = previous.original().clone();
        original.revision = original.revision.checked_add(1).ok_or(ProviderLedgerError::InvalidTransition("native revision exhausted"))?;
        let mut controls = previous.suffix().controls().to_vec();
        let prepared = if signed {
            controls.push(child.signatures.signed().ok_or(ProviderLedgerError::Unavailable)?.clone());
            None
        } else {
            child.unsigned.clone()
        };
        let next = SourceNativeHeldCompletionRecordV1::new(
            original,
            NativeHeldCompletionSuffixV1::new(
                Role::Provider, expected_phase + 1, previous.suffix().flight(), prepared, controls,
            )?,
        )?;
        if signed {
            child.phase6 = Some(next);
        } else {
            child.phase5 = Some(next);
        }
        let next = if signed { child.phase6.as_ref() } else { child.phase5.as_ref() }
            .ok_or(ProviderLedgerError::Unavailable)?;
        let bytes = next.to_canonical_bytes()?;
        storage_offer::retain_projection(
            &mut child.before[index], replay.current_rows(), None, authority.configured_limits(),
        )?;
        storage_offer::retain_projection(
            &mut child.after[index], replay.current_rows(), Some((&key, &bytes)), authority.configured_limits(),
        )?;
        let step = if signed { SourceNativeHeldStepV1::HeldStored } else { SourceNativeHeldStepV1::HeldPrepared };
        propose_native_held_transition_v1(
            child.before[index].iter().map(|(key, value)| (key.as_slice(), value.as_slice())),
            child.after[index].iter().map(|(key, value)| (key.as_slice(), value.as_slice())),
            acquisition, step, Some(spent),
        )?;
        let purpose: &[u8] = if signed { b"original-source-held-stored-v5" } else { b"original-source-held-prepared-v5" };
        let owner = owner_transaction_v5(purpose, vec![(key, Some(bytes))])?;
        let transaction = original_floor_transaction_v5(&authority, owner, acquisition)?;
        producer.park(if signed { Append::HeldStored } else { Append::HeldPrepared }, transaction)?;
        Ok(())
    }

    fn append_original_held_checkpoint_v5(
        &mut self,
        step: Append,
    ) -> Result<(), OriginalProducerErrorV5> {
        self.append_original_producer_step_v5(step)?;
        self.require_original_held_readback_v5(step)
    }

    fn require_original_held_readback_v5(
        &mut self,
        step: Append,
    ) -> Result<(), OriginalProducerErrorV5> {
        let Some(FixedProviderOwnerStateV1::HeldReadOnly(held)) = self.state.as_ref() else {
            return Err(ProviderLedgerError::Unavailable.into());
        };
        let producer = held.original.as_ref().and_then(|original| original.producer.as_ref())
            .ok_or(ProviderLedgerError::Unavailable)?;
        let child = producer.original_completion.as_ref().and_then(|completion| completion.held.as_ref())
            .ok_or(ProviderLedgerError::Unavailable)?;
        let expected = match step {
            Append::HeldPrepared => child.phase5.as_ref(),
            Append::HeldStored => child.phase6.as_ref(),
            _ => None,
        }.ok_or(ProviderLedgerError::Unavailable)?;
        let key = native_completion_key_v2(expected.original().acquisition_id);
        let readback = producer.readback(step)?;
        if readback.rows().get(&(RecordNamespace::SourceProviderAuthority, key)) != Some(&expected.to_canonical_bytes()?) {
            return Err(ProviderLedgerError::Equivocation.into());
        }
        let history = self.hold_challenges.original_history_v5()?;
        self.journal.as_mut().ok_or(ProviderLedgerError::RuntimePoisoned)?
            .claim_source_original_native_v5(&history)?.validate_readback(readback)?;
        Ok(())
    }

    fn sign_original_held_checkpoint_v5(&mut self) -> Result<(), OriginalProducerErrorV5> {
        self.require_original_held_current_v5()?;
        self.require_original_held_readback_v5(Append::HeldPrepared)?;
        let (root, acquire) = self.original_ingress.borrowed_pair_v5()?;
        let clock = self.original_ingress.borrowed_clock_v5()?;
        let (initial, _) = clock.original_sample_and_deadline();
        let expiry = self.original_held_expiry_v5()?;
        let deadline = clock.original_stage_deadline(expiry)?;
        let Some(FixedProviderOwnerStateV1::HeldReadOnly(held)) = self.state.as_mut() else {
            return Err(ProviderLedgerError::Unavailable.into());
        };
        let original = held.original.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
        let archive = original.history.archive.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
        let producer = original.producer.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
        let signed_request = producer.signed.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
        let issued = signed_request.request().claims().validity().0;
        let history = self.hold_challenges.original_history_v5()?;
        let authority = self.journal.as_mut().ok_or(ProviderLedgerError::RuntimePoisoned)?
            .claim_source_original_native_v5(&history)?;
        let (readback, completion, selected, offer) = producer.held_signing_parts_v5()?;
        let validity = (
            issued.max(completion.lease.as_ref().ok_or(ProviderLedgerError::Unavailable)?.validity().0),
            expiry,
        );
        let physical = completion.handoff.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ProviderLedgerError::Unavailable)?;
        let lease = completion.signatures.as_ref().and_then(OriginalProviderCompletionSignaturesV5::signed_lease)
            .ok_or(ProviderLedgerError::Unavailable)?;
        let child = completion.held.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
        let unsigned = child.unsigned.take().ok_or(ProviderLedgerError::Unavailable)?;
        // All fallible loans precede this nonallocating one-way DATA move.
        held.session.sign_original_held_v5(
            &authority, readback, root, acquire, physical, lease, archive, selected,
            offer.original_transport_v5(), unsigned, initial, deadline, validity, &mut child.signatures,
        );
        Ok(())
    }
}

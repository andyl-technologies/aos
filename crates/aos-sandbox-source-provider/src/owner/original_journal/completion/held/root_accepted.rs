//! Same-flight Root4 receipt and one unsigned phase7 relay preparation.
//!
//! The original Session, writers, physical mount and clock remain resident.
//! Root4 plus unsigned relay share one existing native transaction. This child
//! never signs/sends relay5 or supplies ACK, settlement, readiness or release.

use super::*;
use aos_sandbox_source_provider_protocol::native_held_completion::witness::{
    NativeHeldByteWitnessV1, NativeHeldRecordFamilyV1, native_held_record_byte_digest_v1,
};

#[derive(Clone, Copy, Eq, PartialEq)]
enum RootDispositionStageV5 {
    Receive,
    Prepare,
    Commit,
    Stored,
    Closed,
}

#[derive(Clone, Copy)]
enum RootDispositionObservationV5 {
    Receipt,
    Prepared,
}

#[derive(Clone, Copy)]
enum RootDispositionFirstFailureV5 {
    Boundary,
    Action(usize),
    Signatures,
    Postcheck,
}

pub(super) struct OriginalSourceRootDispositionV5 {
    stage: RootDispositionStageV5,
    relay: Option<PreparedNativeHeldControlV1>,
    phase7: Option<SourceNativeHeldCompletionRecordV1>,
    before: Vec<(Vec<u8>, Vec<u8>)>,
    after: Vec<(Vec<u8>, Vec<u8>)>,
    transaction: Option<aos_sandbox::JournalTransaction>,
    actions: [Option<Result<(), OriginalProducerErrorV5>>; 3],
    first: Option<RootDispositionFirstFailureV5>,
    boundary: Option<OriginalProducerErrorV5>,
    postcheck_debt: Option<OriginalProducerErrorV5>,
}

impl OriginalSourceRootDispositionV5 {
    fn pending() -> Self {
        Self {
            stage: RootDispositionStageV5::Receive,
            relay: None,
            phase7: None,
            before: Vec::new(),
            after: Vec::new(),
            transaction: None,
            actions: std::array::from_fn(|_| None),
            first: None,
            boundary: None,
            postcheck_debt: None,
        }
    }

    pub(super) fn phase7_record(&self) -> Option<&SourceNativeHeldCompletionRecordV1> {
        self.phase7.as_ref()
    }

    pub(super) fn relay_preparation(&self) -> Option<&PreparedNativeHeldControlV1> {
        self.relay.as_ref()
    }

    pub(super) fn failure<'owner>(
        &'owner self,
        signatures: &'owner OriginalProviderHeldSignaturesV5,
    ) -> Option<&'owner (dyn std::error::Error + 'static)> {
        match self.first {
            Some(RootDispositionFirstFailureV5::Boundary) => self.boundary.as_ref().map(|cause| cause as _),
            Some(RootDispositionFirstFailureV5::Action(index)) => self.actions[index].as_ref()
                .and_then(|action| action.as_ref().err()).map(|cause| cause as _),
            Some(RootDispositionFirstFailureV5::Signatures) => signatures.failure(),
            Some(RootDispositionFirstFailureV5::Postcheck) => self.postcheck_debt.as_ref().map(|cause| cause as _),
            None => signatures.failure(),
        }
    }
}

impl FixedProviderOwnerV1 {
    /// Advances the selected original delivery through retained Root4 and phase7.
    ///
    /// The same original clock and writers govern all three new crossings.
    /// Progress reports unsigned preparation only, not a relay or settlement.
    #[doc(hidden)]
    pub fn advance_original_native_root_disposition_v5(
        &mut self,
        publication: &[u8],
        rows: &[u8],
    ) -> Progress {
        if self.original_ingress.producer_closed_v5() {
            return Progress::Closed;
        }
        let mut guard = OriginalHeldClosureV5 {
            original: OriginalProducerClosureGuardV5 { owner: self, completed: false },
        };
        let installed = guard.original.owner.original_held_v5()
            .is_ok_and(|child| child.root_disposition.is_some());
        if !installed {
            match guard.original.owner.advance_original_native_delivery_v5(publication, rows) {
                Progress::CompleteSent => {}
                progress => {
                    guard.original.completed = progress != Progress::Closed;
                    return progress;
                }
            }
            // Both empty children are resident before the next fallible gate.
            // Only the actual successful same-Session delivery reaches here.
            if let Some(FixedProviderOwnerStateV1::HeldReadOnly(held)) = guard.original.owner.state.as_mut()
                && let Some(child) = held.original.as_mut()
                    .and_then(|original| original.producer.as_mut())
                    .and_then(|producer| producer.original_completion.as_mut())
                    .and_then(|completion| completion.held.as_mut())
            {
                child.root_disposition = Some(OriginalSourceRootDispositionV5::pending());
                held.session.begin_original_root_disposition_v5(&mut child.signatures);
            } else {
                guard.original.owner.original_ingress
                    .retain_producer_failure_v5(ProviderLedgerError::Unavailable.into());
                return Progress::Closed;
            }
        }

        let _crossing = OriginalCompletionCrossingV5;
        let progress = guard.original.owner.advance_original_root_disposition_inner_v5(publication, rows);
        guard.original.completed = progress != Progress::Closed;
        progress
    }

    fn original_root_disposition_mut_v5(
        &mut self,
    ) -> Result<&mut OriginalSourceRootDispositionV5, ProviderLedgerError> {
        self.original_held_mut_v5()?.root_disposition.as_mut()
            .ok_or(ProviderLedgerError::Unavailable)
    }

    fn advance_original_root_disposition_inner_v5(
        &mut self,
        publication: &[u8],
        rows: &[u8],
    ) -> Progress {
        let before = (|| {
            if self.original_ingress.borrowed_catalog_v1()? != rows {
                return Err(ProviderLedgerError::Equivocation.into());
            }
            let expected = self.original_ingress.borrowed_selection_v5()?.original_publication_projection().1;
            if publication.len() != super::super::super::super::CANONICAL_CATALOG_PUBLICATION_BYTES
                || ObjectDigest::from_bytes(sha2::Sha256::digest(publication).into()) != expected
            {
                return Err(ProviderLedgerError::ConfigurationMismatch.into());
            }
            self.require_original_held_current_v5()
        })();
        if let Err(cause) = before {
            // Never install a coarse upper cause ahead of a real child error.
            let has_cause = self.original_held_v5().is_ok_and(|child| child.failure().is_some());
            if let Ok(child) = self.original_root_disposition_mut_v5() {
                if !has_cause && child.first.is_none() {
                    child.boundary = Some(cause);
                    child.first = Some(RootDispositionFirstFailureV5::Boundary);
                } else if child.postcheck_debt.is_none() {
                    child.postcheck_debt = Some(cause);
                    if child.first.is_none() {
                        child.first = Some(RootDispositionFirstFailureV5::Signatures);
                    }
                }
                child.stage = RootDispositionStageV5::Closed;
            } else {
                self.original_ingress.retain_producer_failure_v5(cause);
            }
            return Progress::Closed;
        }
        if self.original_held_v5().is_ok_and(|child| child.failure().is_some()) {
            return Progress::Closed;
        }
        let stage = match self.original_root_disposition_mut_v5() {
            Ok(child) => child.stage,
            Err(_) => return Progress::Closed,
        };
        let (index, action) = match stage {
            RootDispositionStageV5::Receive => (
                0, self.observe_original_root_disposition_v5(RootDispositionObservationV5::Receipt).map(|_| ()),
            ),
            RootDispositionStageV5::Prepare => (1, self.prepare_original_root_disposition_v5()),
            RootDispositionStageV5::Commit => (
                2, self.append_original_producer_step_v5(Append::RootDispositionPrepared),
            ),
            RootDispositionStageV5::Stored => {
                let observation = self.require_original_held_readback_v5(Append::RootDispositionPrepared)
                    .and_then(|()| self.observe_original_root_disposition_v5(RootDispositionObservationV5::Prepared).map(|_| ()));
                if let Err(cause) = observation {
                    let lower_failed = self.original_held_v5()
                        .is_ok_and(|child| child.signatures.failure().is_some());
                    if let Ok(child) = self.original_root_disposition_mut_v5() {
                        if child.first.is_none() {
                            child.boundary = Some(cause);
                            child.first = Some(if lower_failed {
                                RootDispositionFirstFailureV5::Signatures
                            } else {
                                RootDispositionFirstFailureV5::Boundary
                            });
                        }
                        child.stage = RootDispositionStageV5::Closed;
                    }
                    return Progress::Closed;
                }
                return if self.original_held_v5().is_ok_and(|child| child.failure().is_none()) {
                    Progress::RootDispositionPrepared
                } else {
                    Progress::Closed
                };
            }
            RootDispositionStageV5::Closed => return Progress::Closed,
        };
        // The actual action is parked before the following currentness checks.
        let lower_failed = self.original_held_v5()
            .is_ok_and(|child| child.signatures.failure().is_some());
        if let Ok(child) = self.original_root_disposition_mut_v5() {
            if child.first.is_none() {
                if lower_failed {
                    child.first = Some(RootDispositionFirstFailureV5::Signatures);
                } else if action.is_err() {
                    child.first = Some(RootDispositionFirstFailureV5::Action(index));
                }
            }
            child.actions[index] = Some(action);
        } else {
            if let Err(cause) = action {
                self.original_ingress.retain_producer_failure_v5(cause);
            }
            return Progress::Closed;
        }
        let postcheck = self.require_original_held_current_v5().and_then(|()| {
            if stage == RootDispositionStageV5::Commit {
                self.require_original_held_readback_v5(Append::RootDispositionPrepared)?;
                self.observe_original_root_disposition_v5(RootDispositionObservationV5::Prepared)?;
            } else if stage == RootDispositionStageV5::Prepare {
                self.observe_original_root_disposition_v5(RootDispositionObservationV5::Receipt)?;
            }
            Ok(())
        });
        let has_cause = self.original_held_v5().is_ok_and(|child| child.failure().is_some());
        let received = self.original_held_v5().is_ok_and(|child| child.signatures.root_accepted().is_some());
        let Ok(child) = self.original_root_disposition_mut_v5() else {
            if let Err(cause) = postcheck {
                self.original_ingress.retain_producer_failure_v5(cause);
            }
            return Progress::Closed;
        };
        if let Err(cause) = postcheck {
            if child.postcheck_debt.is_none() {
                child.postcheck_debt = Some(cause);
                if child.first.is_none() {
                    child.first = Some(if has_cause {
                        RootDispositionFirstFailureV5::Signatures
                    } else {
                        RootDispositionFirstFailureV5::Postcheck
                    });
                }
            }
        }
        if has_cause || child.first.is_some() {
            child.stage = RootDispositionStageV5::Closed;
            Progress::Closed
        } else {
            child.stage = match stage {
                RootDispositionStageV5::Receive if received => RootDispositionStageV5::Prepare,
                RootDispositionStageV5::Receive => RootDispositionStageV5::Receive,
                RootDispositionStageV5::Prepare => RootDispositionStageV5::Commit,
                RootDispositionStageV5::Commit => RootDispositionStageV5::Stored,
                other => other,
            };
            if child.stage == RootDispositionStageV5::Stored {
                Progress::RootDispositionPrepared
            } else {
                Progress::Pending
            }
        }
    }

    pub(in crate::owner::original_journal) fn require_original_root_disposition_current_v5(
        &mut self,
    ) -> Result<(), OriginalProducerErrorV5> {
        self.require_original_held_current_v5()?;
        let prepared = self.original_source_producer_v5()?
            .root_disposition_readback_present_v5();
        let observation = if prepared {
            self.require_original_held_readback_v5(Append::RootDispositionPrepared)?;
            RootDispositionObservationV5::Prepared
        } else {
            RootDispositionObservationV5::Receipt
        };
        if self.observe_original_root_disposition_v5(observation)? {
            Ok(())
        } else {
            // The actual lower cause remains in the same signatures owner.
            Err(ProviderLedgerError::RuntimePoisoned.into())
        }
    }

    // Both observations use one closed borrowing recipe. Before7 it borrows the
    // old phase6 delivery cut; after7 it borrows only the actual append8 readback.
    fn observe_original_root_disposition_v5(
        &mut self,
        purpose: RootDispositionObservationV5,
    ) -> Result<bool, OriginalProducerErrorV5> {
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
        let (readback, completion, selected, offer) = match purpose {
            RootDispositionObservationV5::Receipt => producer.held_delivery_parts_v5()?,
            RootDispositionObservationV5::Prepared => producer.root_disposition_parts_v5()?,
        };
        let validity = (
            issued.max(completion.lease.as_ref().ok_or(ProviderLedgerError::Unavailable)?.validity().0), expiry,
        );
        let physical = completion.handoff.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ProviderLedgerError::Unavailable)?;
        let complete = completion.signatures.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
        let lease = complete.signed_lease().ok_or(ProviderLedgerError::Unavailable)?;
        let response = complete.response().ok_or(ProviderLedgerError::Unavailable)?;
        let child = completion.held.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
        Ok(match purpose {
            RootDispositionObservationV5::Receipt => held.session.receive_original_root_accepted_v5(
                &authority, readback, root, acquire, physical, lease, archive, selected,
                offer.original_transport_v5(), response, initial, deadline, validity, &mut child.signatures,
            ),
            RootDispositionObservationV5::Prepared => {
                let relay = child.root_disposition.as_ref().and_then(|child| child.relay.as_ref())
                    .ok_or(ProviderLedgerError::Unavailable)?;
                held.session.revalidate_original_root_disposition_v5(
                    &authority, readback, root, acquire, physical, lease, archive, selected,
                    offer.original_transport_v5(), response, relay, initial, deadline, validity, &mut child.signatures,
                )
            }
        })
    }

    fn prepare_original_root_disposition_v5(&mut self) -> Result<(), OriginalProducerErrorV5> {
        self.require_original_held_current_v5()?;
        if !self.observe_original_root_disposition_v5(RootDispositionObservationV5::Receipt)? {
            // The genuine lower failure, if any, remains in the signatures.
            return Ok(());
        }
        let Some(FixedProviderOwnerStateV1::HeldReadOnly(held)) = self.state.as_mut() else {
            return Err(ProviderLedgerError::Unavailable.into());
        };
        let producer = held.original.as_mut().and_then(|original| original.producer.as_mut())
            .ok_or(ProviderLedgerError::Unavailable)?;
        let acquisition = producer.signed.as_ref().ok_or(ProviderLedgerError::Unavailable)?
            .request().claims().provider_acquisition().1;
        let history = self.hold_challenges.original_history_v5()?;
        let authority = self.journal.as_mut().ok_or(ProviderLedgerError::RuntimePoisoned)?
            .claim_source_original_native_v5(&history)?;
        let replay = authority.replayed_origins()?;
        let key = native_completion_key_v2(acquisition);
        let previous = SourceNativeHeldCompletionRecordV1::from_canonical_bytes(&key,
            replay.current_rows().get(&(RecordNamespace::SourceProviderAuthority, key.clone()))
                .ok_or(ProviderLedgerError::Unavailable)?)?;
        if previous.suffix().phase() != 6 || previous.suffix().prepared().is_some() {
            return Err(ProviderLedgerError::Equivocation.into());
        }
        let (completion, destination) = producer.root_disposition_preparation_parts_v5()?;
        let spent = completion.spend.as_ref().and_then(StagedOriginalZfsHoldSpendV5::readback)
            .ok_or(ProviderLedgerError::Unavailable)?;
        let held_child = completion.held.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
        let signed = held_child.signatures.signed().ok_or(ProviderLedgerError::Unavailable)?;
        let root4 = held_child.signatures.root_accepted().ok_or(ProviderLedgerError::Unavailable)?;
        let child = held_child.root_disposition.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
        if child.relay.is_some() || child.phase7.is_some() || child.transaction.is_some() {
            return Err(ProviderLedgerError::InvalidTransition("original Root disposition already prepared").into());
        }
        let NativeHeldOwnerWitnessV1::Provider(mut witness) = NativeHeldOwnerWitnessV1::from_canonical_bytes(
            Role::Provider, signed.section(Tag::Witness).ok_or(ProviderLedgerError::Unavailable)?,
        )? else {
            return Err(ProviderLedgerError::Equivocation.into());
        };
        // Only canonical comparison DATA is copied. The original SignedHeld,
        // Root4 record/execution and all descriptor/error owners remain resident.
        for record in &mut witness.records {
            let value = if record.family() == NativeHeldRecordFamilyV1::Challenge {
                spent
            } else {
                replay.current_rows().get(&(RecordNamespace::SourceProviderAuthority, record.key().to_vec()))
                    .map(Vec::as_slice).ok_or(ProviderLedgerError::Unavailable)?
            };
            *record = NativeHeldByteWitnessV1::new(
                record.family(), record.key().to_vec(),
                native_held_record_byte_digest_v1(record.family(), record.key(), value)?,
            )?;
        }
        child.relay = Some(PreparedNativeHeldControlV1::new(
            Kind::ProviderRelay, *signed.scope(), root4.digest(),
            vec![
                NativeHeldSectionV1::new(Tag::Witness, NativeHeldOwnerWitnessV1::Provider(witness).to_canonical_bytes()?)?,
                NativeHeldSectionV1::new(Tag::RootDispositionControl, root4.to_canonical_bytes())?,
            ],
            signed.prepared().signer().clone(),
        )?);
        let mut original = previous.original().clone();
        original.revision = original.revision.checked_add(1)
            .ok_or(ProviderLedgerError::InvalidTransition("native revision exhausted"))?;
        let mut controls = previous.suffix().controls().to_vec();
        controls.push(root4.clone());
        child.phase7 = Some(SourceNativeHeldCompletionRecordV1::new(
            original,
            NativeHeldCompletionSuffixV1::new(Role::Provider, 7, previous.suffix().flight(), child.relay.clone(), controls)?,
        )?);
        let bytes = child.phase7.as_ref().ok_or(ProviderLedgerError::Unavailable)?.to_canonical_bytes()?;
        storage_offer::retain_projection(&mut child.before, replay.current_rows(), None, authority.configured_limits())?;
        storage_offer::retain_projection(&mut child.after, replay.current_rows(), Some((&key, &bytes)), authority.configured_limits())?;
        propose_native_held_transition_v1(
            child.before.iter().map(|(key, value)| (key.as_slice(), value.as_slice())),
            child.after.iter().map(|(key, value)| (key.as_slice(), value.as_slice())),
            acquisition, SourceNativeHeldStepV1::RootDispositionPrepared, Some(spent),
        )?;
        let owner = owner_transaction_v5(b"original-source-root-disposition-prepared-v5", vec![(key, Some(bytes))])?;
        child.transaction = Some(original_floor_transaction_v5(&authority, owner, acquisition)?);
        // Empty destination and resident input were checked before the SAME
        // allocation-free park. It preserves the input if destination refuses.
        super::super::super::PreparedSourceOriginalV5::park(
            &mut child.transaction, &mut None, destination,
        )?;
        Ok(())
    }
}

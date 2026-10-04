//! Same-original relay5 signing, signed phase7 storage and one local dispatch.
//!
//! The phase7 unsigned preparation is borrowed from the existing Root4 child.
//! This child owns only its later signing/stored/delivery observations and keeps
//! all original Session, writer, Storage and physical custody in the same graph.

use super::*;

#[derive(Clone, Copy, Eq, PartialEq)]
enum RelayStageV5 {
    Sign,
    Prepare,
    Commit,
    Send,
    Sent,
    Closed,
}

#[derive(Clone, Copy)]
enum RelayObservationV5 {
    Sign,
    Preparation,
    Delivery,
    Send,
}

#[derive(Clone, Copy)]
enum RelayFirstFailureV5 {
    Boundary,
    Action(usize),
    Signatures,
    Storage,
    Postcheck,
}

pub(super) struct OriginalSourceRelayV5 {
    stage: RelayStageV5,
    phase7: Option<SourceNativeHeldCompletionRecordV1>,
    encoded: Option<Vec<u8>>,
    before: Vec<(Vec<u8>, Vec<u8>)>,
    after: Vec<(Vec<u8>, Vec<u8>)>,
    owner_transaction: Option<aos_sandbox::JournalTransaction>,
    transaction: Option<aos_sandbox::JournalTransaction>,
    actions: [Option<Result<(), OriginalProducerErrorV5>>; 4],
    first: Option<RelayFirstFailureV5>,
    boundary: Option<OriginalProducerErrorV5>,
    postcheck_debt: Option<OriginalProducerErrorV5>,
}

impl OriginalSourceRelayV5 {
    fn pending() -> Self {
        Self {
            stage: RelayStageV5::Sign,
            phase7: None,
            encoded: None,
            before: Vec::new(),
            after: Vec::new(),
            owner_transaction: None,
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

    pub(super) fn failure<'owner>(
        &'owner self,
        signatures: &'owner OriginalProviderHeldSignaturesV5,
    ) -> Option<&'owner (dyn std::error::Error + 'static)> {
        match self.first {
            Some(RelayFirstFailureV5::Boundary) => self.boundary.as_ref().map(|cause| cause as _),
            Some(RelayFirstFailureV5::Action(index)) => self.actions[index].as_ref()
                .and_then(|action| action.as_ref().err()).map(|cause| cause as _),
            Some(RelayFirstFailureV5::Signatures) => signatures.failure(),
            // The public owner's diagnostic borrower resolves this marker
            // through the actual immutable Storage transport, not a proxy.
            Some(RelayFirstFailureV5::Storage) => None,
            Some(RelayFirstFailureV5::Postcheck) => self.postcheck_debt.as_ref().map(|cause| cause as _),
            None => signatures.failure(),
        }
    }
}

impl FixedProviderOwnerV1 {
    /// Borrows the chronological original relay cause without moving custody.
    ///
    /// A Storage first-cause marker resolves to the actual owning lower Err.
    /// Earlier validation and action causes retain their original precedence.
    #[must_use]
    #[doc(hidden)]
    pub fn original_relay_failure_v5(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Ok(producer) = self.original_source_producer_v5()
            && let Some(held) = producer.original_completion.as_ref().and_then(|completion| completion.held.as_ref())
            && let Some(relay) = &held.relay
        {
            if matches!(relay.first, Some(RelayFirstFailureV5::Storage)) {
                return producer.storage_offer.as_ref()?.original_transport_ref_v5().failure();
            }
            if let Some(cause) = relay.failure(&held.signatures) {
                return Some(cause);
            }
        }
        self.original_completion_failure_v5()
    }

    /// Advances the same installed original through signed relay5 and delivery.
    ///
    /// Local progress grants no ACK, settlement, interest retirement or drain.
    /// A failed original never reconnects, recaptures time or starts a new lane.
    #[doc(hidden)]
    pub fn advance_original_native_relay_v5(&mut self, publication: &[u8], rows: &[u8]) -> Progress {
        if self.original_ingress.producer_closed_v5() {
            return Progress::Closed;
        }
        let mut guard = OriginalHeldClosureV5 {
            original: OriginalProducerClosureGuardV5 { owner: self, completed: false },
        };
        let installed = guard.original.owner.original_held_v5()
            .is_ok_and(|child| child.relay.is_some());
        if !installed {
            match guard.original.owner.advance_original_native_root_disposition_v5(publication, rows) {
                Progress::RootDispositionPrepared => {}
                progress => {
                    guard.original.completed = progress != Progress::Closed;
                    return progress;
                }
            }
            // Install and arm both fixed children before the first new gate.
            // The same original Session and offered Storage transport supply
            // origin; empty progress DATA alone cannot construct either one.
            if let Some(FixedProviderOwnerStateV1::HeldReadOnly(held)) = guard.original.owner.state.as_mut()
                && let Some(producer) = held.original.as_mut().and_then(|original| original.producer.as_mut())
                && let Some(child) = producer.original_completion.as_mut().and_then(|completion| completion.held.as_mut())
            {
                child.relay = Some(OriginalSourceRelayV5::pending());
                if !held.session.begin_original_relay_v5(&mut child.signatures) {
                    if let Some(relay) = child.relay.as_mut() {
                        relay.first = Some(RelayFirstFailureV5::Signatures);
                        relay.stage = RelayStageV5::Closed;
                    }
                    return Progress::Closed;
                }
                let Some(offer) = producer.storage_offer.as_mut() else {
                    if let Some(relay) = child.relay.as_mut() {
                        relay.boundary = Some(ProviderLedgerError::Unavailable.into());
                        relay.first = Some(RelayFirstFailureV5::Boundary);
                        relay.stage = RelayStageV5::Closed;
                    }
                    return Progress::Closed;
                };
                if !offer.original_transport_v5().begin_original_relay_v5() {
                    if let Some(relay) = child.relay.as_mut() {
                        relay.first = Some(RelayFirstFailureV5::Storage);
                        relay.stage = RelayStageV5::Closed;
                    }
                    return Progress::Closed;
                }
            } else {
                guard.original.owner.original_ingress
                    .retain_producer_failure_v5(ProviderLedgerError::Unavailable.into());
                return Progress::Closed;
            }
        }
        let _crossing = OriginalCompletionCrossingV5;
        let progress = guard.original.owner.advance_original_relay_inner_v5(publication, rows);
        guard.original.completed = progress != Progress::Closed;
        progress
    }

    fn original_relay_mut_v5(&mut self) -> Result<&mut OriginalSourceRelayV5, ProviderLedgerError> {
        self.original_held_mut_v5()?.relay.as_mut().ok_or(ProviderLedgerError::Unavailable)
    }

    fn retain_original_relay_boundary_v5(&mut self, cause: OriginalProducerErrorV5) {
        let lower = self.original_relay_failure_v5().is_some();
        if let Ok(child) = self.original_relay_mut_v5() {
            if !lower && child.first.is_none() {
                child.boundary = Some(cause);
                child.first = Some(RelayFirstFailureV5::Boundary);
            } else if child.postcheck_debt.is_none() {
                child.postcheck_debt = Some(cause);
            }
            child.stage = RelayStageV5::Closed;
        } else {
            self.original_ingress.retain_producer_failure_v5(cause);
        }
    }

    fn advance_original_relay_inner_v5(&mut self, publication: &[u8], rows: &[u8]) -> Progress {
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
            self.require_original_relay_current_v5()
        })();
        if let Err(cause) = before {
            self.retain_original_relay_boundary_v5(cause);
            return Progress::Closed;
        }
        if self.original_relay_failure_v5().is_some() {
            return Progress::Closed;
        }
        let stage = match self.original_relay_mut_v5() {
            Ok(child) => child.stage,
            Err(_) => return Progress::Closed,
        };
        let (index, action) = match stage {
            RelayStageV5::Sign => (0, self.observe_original_relay_v5(RelayObservationV5::Sign).map(|_| ())),
            RelayStageV5::Prepare => (1, self.prepare_original_relay_stored_v5()),
            RelayStageV5::Commit => (2, self.append_original_producer_step_v5(Append::RelayStored)),
            RelayStageV5::Send => (3, self.observe_original_relay_v5(RelayObservationV5::Send).map(|_| ())),
            RelayStageV5::Sent => return Progress::RelaySent,
            RelayStageV5::Closed => return Progress::Closed,
        };

        // Native action results/first-cause markers are resident before any
        // upper Journal, authority, peer or clock postcheck can add debt.
        let lower = self.original_held_v5().is_ok_and(|child| child.signatures.failure().is_some());
        let storage_first = self.original_held_v5()
            .is_ok_and(|child| child.signatures.original_relay_storage_failed());
        if let Ok(child) = self.original_relay_mut_v5() {
            if child.first.is_none() {
                if storage_first {
                    child.first = Some(RelayFirstFailureV5::Storage);
                } else if lower {
                    child.first = Some(RelayFirstFailureV5::Signatures);
                } else if action.is_err() {
                    child.first = Some(RelayFirstFailureV5::Action(index));
                }
            }
            child.actions[index] = Some(action);
        } else {
            if let Err(cause) = action {
                self.original_ingress.retain_producer_failure_v5(cause);
            }
            return Progress::Closed;
        }
        let postcheck = self.require_original_relay_current_v5();
        let lower = self.original_relay_failure_v5().is_some();
        let sent = self.original_held_v5().is_ok_and(|child| child.signatures.original_relay_sent());
        let Ok(child) = self.original_relay_mut_v5() else {
            if let Err(cause) = postcheck {
                self.original_ingress.retain_producer_failure_v5(cause);
            }
            return Progress::Closed;
        };
        if let Err(cause) = postcheck {
            if child.postcheck_debt.is_none() {
                child.postcheck_debt = Some(cause);
                if child.first.is_none() {
                    child.first = Some(RelayFirstFailureV5::Postcheck);
                }
            }
        }
        if lower || child.first.is_some() {
            child.stage = RelayStageV5::Closed;
            return Progress::Closed;
        }
        child.stage = next_relay_stage_v5(stage, sent);
        match child.stage {
            RelayStageV5::Send => Progress::RelayStored,
            RelayStageV5::Sent => Progress::RelaySent,
            _ => Progress::Pending,
        }
    }

    /// Rechecks the actual unsigned or signed cut before the next crossing.
    ///
    /// # Errors
    ///
    /// Refuses stale original custody, changed readback, authority or clock.
    pub(in crate::owner::original_journal) fn require_original_relay_current_v5(
        &mut self,
    ) -> Result<(), OriginalProducerErrorV5> {
        self.require_original_held_current_v5()?;
        let stored = self.original_source_producer_v5()?.relay_readback_present_v5();
        let signed = self.original_held_v5()?.signatures.original_relay().is_some();
        if !stored && !signed {
            return self.require_original_root_disposition_current_v5();
        }
        // The actual append9 readback selects signed7 even after an endpoint
        // failure hides signed DATA. Never revisit stale unsigned append8.
        let (step, observation) = if stored {
            (Append::RelayStored, RelayObservationV5::Delivery)
        } else {
            (Append::RootDispositionPrepared, RelayObservationV5::Preparation)
        };
        self.require_original_held_readback_v5(step)?;
        if !self.observe_original_relay_v5(observation)? {
            return Err(ProviderLedgerError::RuntimePoisoned.into());
        }
        // Last after every potentially lengthy readback, archive and execution
        // observation. This samples the original guard; it cannot renew D.
        self.original_ingress.borrowed_clock_v5()?.revalidate(Some(self.original_held_expiry_v5()?))?;
        Ok(())
    }

    fn observe_original_relay_v5(&mut self, purpose: RelayObservationV5) -> Result<bool, OriginalProducerErrorV5> {
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
            RelayObservationV5::Sign | RelayObservationV5::Preparation => producer.root_disposition_parts_v5()?,
            RelayObservationV5::Delivery | RelayObservationV5::Send => producer.relay_delivery_parts_v5()?,
        };
        let validity = (issued.max(completion.lease.as_ref().ok_or(ProviderLedgerError::Unavailable)?.validity().0), expiry);
        let physical = completion.handoff.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ProviderLedgerError::Unavailable)?;
        let complete = completion.signatures.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
        let lease = complete.signed_lease().ok_or(ProviderLedgerError::Unavailable)?;
        let response = complete.response().ok_or(ProviderLedgerError::Unavailable)?;
        let child = completion.held.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
        let transport = offer.original_transport_v5();
        Ok(match purpose {
            RelayObservationV5::Sign => {
                let relay = child.root_disposition.as_ref()
                    .and_then(root_accepted::OriginalSourceRootDispositionV5::relay_preparation)
                    .ok_or(ProviderLedgerError::Unavailable)?;
                held.session.sign_original_relay_v5(
                    &authority, readback, root, acquire, physical, lease, archive, selected,
                    transport, response, relay, initial, deadline, validity, &mut child.signatures,
                )
            }
            RelayObservationV5::Preparation | RelayObservationV5::Delivery => {
                let step = match purpose {
                    RelayObservationV5::Preparation => SourceNativeHeldStepV1::RootDispositionPrepared,
                    _ => SourceNativeHeldStepV1::RelayStored,
                };
                held.session.revalidate_original_relay_v5(
                    &authority, readback, root, acquire, physical, lease, archive, selected,
                    transport, response, step, initial, deadline, validity, &mut child.signatures,
                )
            }
            RelayObservationV5::Send => held.session.send_original_relay_v5(
                &authority, readback, root, acquire, physical, lease, archive, selected,
                transport, response, initial, deadline, validity, &mut child.signatures,
            ),
        })
    }

    fn prepare_original_relay_stored_v5(&mut self) -> Result<(), OriginalProducerErrorV5> {
        self.require_original_relay_current_v5()?;
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
        let (completion, destination) = producer.relay_preparation_parts_v5()?;
        let spent = completion.spend.as_ref().and_then(StagedOriginalZfsHoldSpendV5::readback)
            .ok_or(ProviderLedgerError::Unavailable)?;
        let held_child = completion.held.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
        let signed = held_child.signatures.original_relay().ok_or(ProviderLedgerError::Unavailable)?;
        let child = held_child.relay.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
        if previous.suffix().phase() != 7 || previous.suffix().prepared() != Some(signed.prepared())
            || child.phase7.is_some() || child.owner_transaction.is_some() || child.transaction.is_some()
        {
            return Err(ProviderLedgerError::InvalidTransition("original relay is not an unsigned phase7 cut").into());
        }
        let mut original = previous.original().clone();
        original.revision = original.revision.checked_add(1)
            .ok_or(ProviderLedgerError::InvalidTransition("native revision exhausted"))?;
        let mut controls = previous.suffix().controls().to_vec();
        controls.push(signed.clone());
        child.phase7 = Some(SourceNativeHeldCompletionRecordV1::new(
            original,
            NativeHeldCompletionSuffixV1::new(Role::Provider, 7, previous.suffix().flight(), None, controls)?,
        )?);
        child.encoded = Some(child.phase7.as_ref().ok_or(ProviderLedgerError::Unavailable)?.to_canonical_bytes()?);
        let bytes = child.encoded.as_deref().ok_or(ProviderLedgerError::Unavailable)?;
        storage_offer::retain_projection(&mut child.before, replay.current_rows(), None, authority.configured_limits())?;
        storage_offer::retain_projection(&mut child.after, replay.current_rows(), Some((&key, bytes)), authority.configured_limits())?;
        propose_native_held_transition_v1(
            child.before.iter().map(|(key, value)| (key.as_slice(), value.as_slice())),
            child.after.iter().map(|(key, value)| (key.as_slice(), value.as_slice())),
            acquisition, SourceNativeHeldStepV1::RelayStored, Some(spent),
        )?;
        child.owner_transaction = Some(owner_transaction_v5(b"original-source-relay-stored-v5", vec![(key, Some(bytes.to_vec()))])?);
        // The existing consuming floor helper is reused. Its bounded DATA input
        // copy is not a physical owner; the original owner TX stays resident if
        // that unchanged lower helper refuses before returning the full TX.
        child.transaction = Some(original_floor_transaction_v5(
            &authority, child.owner_transaction.as_ref().ok_or(ProviderLedgerError::Unavailable)?.clone(), acquisition,
        )?);
        super::super::super::PreparedSourceOriginalV5::park(&mut child.transaction, &mut None, destination)?;
        Ok(())
    }
}

// This private progress function is DATA only. Its real caller first parks the
// action Result and accepts every original readback/authority/clock postcheck.
fn next_relay_stage_v5(stage: RelayStageV5, sent: bool) -> RelayStageV5 {
    match stage {
        RelayStageV5::Sign => RelayStageV5::Prepare,
        RelayStageV5::Prepare => RelayStageV5::Commit,
        RelayStageV5::Commit => RelayStageV5::Send,
        RelayStageV5::Send if sent => RelayStageV5::Sent,
        other => other,
    }
}

#[cfg(test)]
mod tests {
    //! UNRUN progress DATA only; no genuine owner or positive cut is fabricated.

    use super::*;

    #[test]
    fn signed_data_precedes_stored_cut_and_dispatch() {
        assert!(next_relay_stage_v5(RelayStageV5::Sign, false) == RelayStageV5::Prepare);
        assert!(next_relay_stage_v5(RelayStageV5::Prepare, false) == RelayStageV5::Commit);
        assert!(next_relay_stage_v5(RelayStageV5::Commit, false) == RelayStageV5::Send);
    }

    #[test]
    fn pending_dispatch_does_not_advance_or_reopen_closed_progress() {
        assert!(next_relay_stage_v5(RelayStageV5::Send, false) == RelayStageV5::Send);
        assert!(next_relay_stage_v5(RelayStageV5::Send, true) == RelayStageV5::Sent);
        assert!(next_relay_stage_v5(RelayStageV5::Closed, true) == RelayStageV5::Closed);
        assert!(next_relay_stage_v5(RelayStageV5::Sent, false) == RelayStageV5::Sent);
    }
}

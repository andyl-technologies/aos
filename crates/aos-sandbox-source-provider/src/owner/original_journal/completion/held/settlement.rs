//! Same-owner Storage6 admission, unsigned/signed Kind7 readback and dispatch.
//!
//! Three bounded native projections and whole action Results remain resident.
//! This driver ends at local Kind7 dispatch, not Root terminal recording,
//! physical retirement, cold recovery, funding or population Drain.

use super::*;

#[derive(Clone, Copy, Eq, PartialEq)]
enum SettlementStageV5 {
    Receive,
    PrepareReceived,
    CommitReceived,
    PrepareUnsigned,
    CommitUnsigned,
    Sign,
    PrepareSigned,
    CommitSigned,
    Send,
    Sent,
    Closed,
}

#[derive(Clone, Copy)]
enum SettlementObservationV5 {
    Receive,
    Current,
    Sign,
    Send,
}

#[derive(Clone, Copy)]
enum SettlementFirstFailureV5 {
    Boundary,
    Action(usize),
    Signatures,
    Storage,
    Postcheck(usize),
}

pub(super) struct OriginalSourceSettlementV5 {
    stage: SettlementStageV5,
    unsigned: Option<PreparedNativeHeldControlV1>,
    records: [Option<SourceNativeHeldCompletionRecordV1>; 3],
    encoded: [Option<Vec<u8>>; 3],
    before: [Vec<(Vec<u8>, Vec<u8>)>; 3],
    after: [Vec<(Vec<u8>, Vec<u8>)>; 3],
    owner_transactions: [Option<aos_sandbox::JournalTransaction>; 3],
    transactions: [Option<aos_sandbox::JournalTransaction>; 3],
    actions: [Option<Result<bool, OriginalProducerErrorV5>>; 9],
    first: Option<SettlementFirstFailureV5>,
    boundary: Option<OriginalProducerErrorV5>,
    postcheck_debt: Option<OriginalProducerErrorV5>,
    postchecks: [Option<Result<(), OriginalProducerErrorV5>>; 3],
}

fn settlement_index(step: Append) -> Option<usize> {
    match step {
        Append::StorageSettlementRecorded => Some(0),
        Append::ProviderSettledPrepared => Some(1),
        Append::ProviderSettledStored => Some(2),
        _ => None,
    }
}

fn settlement_step(step: Append) -> SourceNativeHeldStepV1 {
    match step {
        Append::StorageSettlementRecorded => SourceNativeHeldStepV1::StorageSettlementRecorded,
        Append::ProviderSettledPrepared => SourceNativeHeldStepV1::ProviderSettledPrepared,
        Append::ProviderSettledStored => SourceNativeHeldStepV1::ProviderSettledStored,
        // Only the fixed committed-slot selector supplies this old predecessor.
        _ => SourceNativeHeldStepV1::RelayStored,
    }
}

impl OriginalSourceSettlementV5 {
    fn pending() -> Self {
        Self {
            stage: SettlementStageV5::Receive,
            unsigned: None,
            records: std::array::from_fn(|_| None),
            encoded: std::array::from_fn(|_| None),
            before: std::array::from_fn(|_| Vec::new()),
            after: std::array::from_fn(|_| Vec::new()),
            owner_transactions: std::array::from_fn(|_| None),
            transactions: std::array::from_fn(|_| None),
            actions: std::array::from_fn(|_| None),
            first: None,
            boundary: None,
            postcheck_debt: None,
            postchecks: std::array::from_fn(|_| None),
        }
    }

    pub(super) fn record(&self, step: Append) -> Option<&SourceNativeHeldCompletionRecordV1> {
        self.records[settlement_index(step)?].as_ref()
    }

    fn failure<'a>(&'a self, signatures: &'a OriginalProviderHeldSignaturesV5) -> Option<&'a (dyn std::error::Error + 'static)> {
        match self.first {
            Some(SettlementFirstFailureV5::Boundary) => self.boundary.as_ref().map(|cause| cause as _),
            Some(SettlementFirstFailureV5::Action(index)) => self.actions[index].as_ref()?.as_ref().err().map(|cause| cause as _),
            Some(SettlementFirstFailureV5::Signatures) => signatures.original_settlement_failure_v5(),
            Some(SettlementFirstFailureV5::Storage) => None,
            Some(SettlementFirstFailureV5::Postcheck(index)) => self.postchecks[index].as_ref()?
                .as_ref().err().map(|cause| cause as _),
            None => None,
        }
    }
}

impl FixedProviderOwnerV1 {
    /// Borrows the first actual settlement cause from its original containing graph.
    #[must_use]
    #[doc(hidden)]
    pub fn original_settlement_failure_v5(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Ok(producer) = self.original_source_producer_v5()
            && let Some(held) = producer.original_completion.as_ref().and_then(|completion| completion.held.as_ref())
            && let Some(child) = &held.settlement {
            if matches!(child.first, Some(SettlementFirstFailureV5::Storage)) {
                return producer.storage_offer.as_ref()?.original_transport_ref_v5().failure();
            }
            if let Some(cause) = child.failure(&held.signatures) { return Some(cause); }
        }
        self.original_relay_failure_v5()
    }

    /// Advances the installed original through same-Storage receive and phase9.
    ///
    /// Each call crosses at most one fixed stage. Local transmission is not
    /// Root acceptance, terminal recording, physical retirement or readiness.
    #[doc(hidden)]
    pub fn advance_original_native_settlement_v5(&mut self, publication: &[u8], rows: &[u8]) -> Progress {
        if self.original_ingress.producer_closed_v5() { return Progress::Closed; }
        let mut guard = OriginalHeldClosureV5 {
            original: OriginalProducerClosureGuardV5 { owner: self, completed: false },
        };
        let installed = guard.original.owner.original_held_v5().is_ok_and(|held| held.settlement.is_some());
        if !installed {
            match guard.original.owner.advance_original_native_relay_v5(publication, rows) {
                Progress::RelaySent => {}
                progress => { guard.original.completed = progress != Progress::Closed; return progress; }
            }
            // Empty fixed reservoirs are resident before the first new gate.
            // Only the genuine old relay route can reach this installation.
            if let Some(FixedProviderOwnerStateV1::HeldReadOnly(held)) = guard.original.owner.state.as_mut()
                && let Some(producer) = held.original.as_mut().and_then(|original| original.producer.as_mut())
                && let Some(child) = producer.original_completion.as_mut().and_then(|completion| completion.held.as_mut()) {
                child.settlement = Some(OriginalSourceSettlementV5::pending());
                if !held.session.begin_original_settlement_v5(&mut child.signatures) {
                    if let Some(settlement) = child.settlement.as_mut() {
                        settlement.first = Some(SettlementFirstFailureV5::Signatures);
                        settlement.stage = SettlementStageV5::Closed;
                    }
                    return Progress::Closed;
                }
                let Some(offer) = producer.storage_offer.as_mut() else {
                    if let Some(settlement) = child.settlement.as_mut() {
                        settlement.boundary = Some(ProviderLedgerError::Unavailable.into());
                        settlement.first = Some(SettlementFirstFailureV5::Boundary);
                        settlement.stage = SettlementStageV5::Closed;
                    }
                    return Progress::Closed;
                };
                if !offer.original_transport_v5().begin_original_settlement_v5() {
                    if let Some(settlement) = child.settlement.as_mut() {
                        settlement.first = Some(SettlementFirstFailureV5::Storage);
                        settlement.stage = SettlementStageV5::Closed;
                    }
                    return Progress::Closed;
                }
            } else {
                guard.original.owner.original_ingress.retain_producer_failure_v5(ProviderLedgerError::Unavailable.into());
                return Progress::Closed;
            }
        }
        let _crossing = OriginalCompletionCrossingV5;
        let progress = guard.original.owner.advance_original_settlement_inner_v5(publication, rows);
        guard.original.completed = progress != Progress::Closed;
        progress
    }

    fn original_settlement_mut_v5(&mut self) -> Result<&mut OriginalSourceSettlementV5, ProviderLedgerError> {
        self.original_held_mut_v5()?.settlement.as_mut().ok_or(ProviderLedgerError::Unavailable)
    }

    fn retain_original_settlement_boundary_v5(&mut self, cause: OriginalProducerErrorV5) {
        let earlier = self.original_settlement_failure_v5().is_some();
        if let Ok(child) = self.original_settlement_mut_v5() {
            if !earlier && child.first.is_none() {
                child.boundary = Some(cause);
                child.first = Some(SettlementFirstFailureV5::Boundary);
            } else if child.postcheck_debt.is_none() { child.postcheck_debt = Some(cause); }
            child.stage = SettlementStageV5::Closed;
        } else { self.original_ingress.retain_producer_failure_v5(cause); }
    }

    fn advance_original_settlement_inner_v5(&mut self, publication: &[u8], rows: &[u8]) -> Progress {
        // Terminal entry neither retries nor overwrites a first-cause slot.
        let stage = match self.original_settlement_mut_v5() {
            Ok(child) => child.stage, Err(_) => return Progress::Closed,
        };
        if stage == SettlementStageV5::Closed { return Progress::Closed; }
        let before = (|| {
            if self.original_ingress.borrowed_catalog_v1()? != rows { return Err(ProviderLedgerError::Equivocation.into()); }
            let expected = self.original_ingress.borrowed_selection_v5()?.original_publication_projection().1;
            if publication.len() != super::super::super::super::CANONICAL_CATALOG_PUBLICATION_BYTES
                || ObjectDigest::from_bytes(sha2::Sha256::digest(publication).into()) != expected {
                return Err(ProviderLedgerError::ConfigurationMismatch.into());
            }
            self.require_original_settlement_current_v5()
        })();
        if let Err(cause) = before { self.retain_original_settlement_boundary_v5(cause); return Progress::Closed; }
        let (index, action) = match stage {
            SettlementStageV5::Receive => (0, self.observe_original_settlement_v5(SettlementObservationV5::Receive)),
            SettlementStageV5::PrepareReceived => (1, self.prepare_original_settlement_checkpoint_v5(Append::StorageSettlementRecorded).map(|()| true)),
            SettlementStageV5::CommitReceived => (2, self.append_original_producer_step_v5(Append::StorageSettlementRecorded).map(|()| true)),
            SettlementStageV5::PrepareUnsigned => (3, self.prepare_original_settlement_checkpoint_v5(Append::ProviderSettledPrepared).map(|()| true)),
            SettlementStageV5::CommitUnsigned => (4, self.append_original_producer_step_v5(Append::ProviderSettledPrepared).map(|()| true)),
            SettlementStageV5::Sign => (5, self.observe_original_settlement_v5(SettlementObservationV5::Sign)),
            SettlementStageV5::PrepareSigned => (6, self.prepare_original_settlement_checkpoint_v5(Append::ProviderSettledStored).map(|()| true)),
            SettlementStageV5::CommitSigned => (7, self.append_original_producer_step_v5(Append::ProviderSettledStored).map(|()| true)),
            SettlementStageV5::Send => (8, self.observe_original_settlement_v5(SettlementObservationV5::Send)),
            SettlementStageV5::Sent => return Progress::ProviderSettledSent,
            SettlementStageV5::Closed => return Progress::Closed,
        };
        let progressed = action.as_ref().is_ok_and(|progressed| *progressed);
        let signatures = self.original_held_v5().is_ok_and(|held| held.signatures.original_settlement_failure_v5().is_some());
        let storage = self.original_held_v5().is_ok_and(|held| held.signatures.original_settlement_storage_failed_v5());
        if let Ok(child) = self.original_settlement_mut_v5() {
            if child.first.is_none() {
                child.first = if storage { Some(SettlementFirstFailureV5::Storage) }
                    else if signatures { Some(SettlementFirstFailureV5::Signatures) }
                    else if action.is_err() { Some(SettlementFirstFailureV5::Action(index)) } else { None };
            }
            child.actions[index] = Some(action);
        } else {
            if let Err(cause) = action { self.original_ingress.retain_producer_failure_v5(cause); }
            return Progress::Closed;
        }
        // Native action custody precedes the independent owner/readback,
        // Root4/Session and final original-clock bookends, even on action Err.
        self.observe_original_settlement_postchecks_v5();
        let Ok(child) = self.original_settlement_mut_v5() else { return Progress::Closed; };
        if child.first.is_some() { child.stage = SettlementStageV5::Closed; return Progress::Closed; }
        if stage == SettlementStageV5::Receive && !progressed {
            // Clear only after the full parent readback/currentness/clock
            // postcheck, not merely after lower transport comparison DATA.
            let pending = (|| {
                let producer = self.original_source_producer_mut_v5()?;
                producer.storage_offer.as_mut().ok_or(ProviderLedgerError::Unavailable)?
                    .original_transport_v5().finish_original_settlement_pending_v5()?;
                Ok::<_, OriginalProducerErrorV5>(())
            })();
            if let Err(cause) = pending { self.retain_original_settlement_boundary_v5(cause); return Progress::Closed; }
        }
        let Ok(child) = self.original_settlement_mut_v5() else { return Progress::Closed; };
        child.stage = next_settlement_stage(stage, progressed);
        match child.stage {
            SettlementStageV5::PrepareUnsigned => Progress::StorageSettlementRecorded,
            SettlementStageV5::Sign => Progress::ProviderSettledPrepared,
            SettlementStageV5::Send => Progress::ProviderSettledStored,
            SettlementStageV5::Sent => Progress::ProviderSettledSent,
            _ => Progress::Pending,
        }
    }

    pub(in crate::owner::original_journal) fn require_original_settlement_current_v5(&mut self) -> Result<(), OriginalProducerErrorV5> {
        self.require_original_held_current_v5()?;
        let step = self.original_source_producer_v5()?.settlement_readback_step_v5();
        self.require_original_held_readback_v5(step)?;
        if !self.observe_original_settlement_v5(SettlementObservationV5::Current)? {
            return Err(ProviderLedgerError::RuntimePoisoned.into());
        }
        // The same original pair is last, after actual writer/physical owners.
        self.original_ingress.borrowed_clock_v5()?.revalidate(Some(self.original_held_expiry_v5()?))?;
        Ok(())
    }

    fn observe_original_settlement_postchecks_v5(&mut self) {
        let owner = (|| {
            self.require_original_held_current_v5()?;
            let step = self.original_source_producer_v5()?.settlement_readback_step_v5();
            self.require_original_held_readback_v5(step)
        })();
        if let Ok(child) = self.original_settlement_mut_v5() {
            if owner.is_err() && child.first.is_none() {
                child.first = Some(SettlementFirstFailureV5::Postcheck(0));
            }
            child.postchecks[0] = Some(owner);
        }

        // This uses the saved original cut directly; an earlier writer refusal
        // does not skip the independent genuine Root4 execution observation.
        let session = self.observe_original_settlement_v5(SettlementObservationV5::Current)
            .and_then(|current| if current { Ok(()) } else { Err(ProviderLedgerError::RuntimePoisoned.into()) });
        let signatures = self.original_held_v5()
            .is_ok_and(|held| held.signatures.original_settlement_failure_v5().is_some());
        let storage = self.original_held_v5()
            .is_ok_and(|held| held.signatures.original_settlement_storage_failed_v5());
        if let Ok(child) = self.original_settlement_mut_v5() {
            if session.is_err() && child.first.is_none() {
                child.first = Some(if storage { SettlementFirstFailureV5::Storage }
                    else if signatures { SettlementFirstFailureV5::Signatures }
                    else { SettlementFirstFailureV5::Postcheck(1) });
            }
            child.postchecks[1] = Some(session);
        }

        let clock = (|| {
            let expiry = self.original_held_expiry_v5()?;
            self.original_ingress.borrowed_clock_v5()?.revalidate(Some(expiry))?;
            Ok(())
        })();
        if let Ok(child) = self.original_settlement_mut_v5() {
            if clock.is_err() && child.first.is_none() {
                child.first = Some(SettlementFirstFailureV5::Postcheck(2));
            }
            child.postchecks[2] = Some(clock);
        }
    }

    fn observe_original_settlement_v5(&mut self, purpose: SettlementObservationV5) -> Result<bool, OriginalProducerErrorV5> {
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
        let step = producer.settlement_readback_step_v5();
        let issued = producer.signed.as_ref().ok_or(ProviderLedgerError::Unavailable)?.request().claims().validity().0;
        let history = self.hold_challenges.original_history_v5()?;
        let authority = self.journal.as_mut().ok_or(ProviderLedgerError::RuntimePoisoned)?.claim_source_original_native_v5(&history)?;
        let (readback, completion, selected, offer) = producer.settlement_parts_v5(step)?;
        let validity = (issued.max(completion.lease.as_ref().ok_or(ProviderLedgerError::Unavailable)?.validity().0), expiry);
        let physical = completion.handoff.as_ref().and_then(|result| result.as_ref().ok()).ok_or(ProviderLedgerError::Unavailable)?;
        let complete = completion.signatures.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
        let lease = complete.signed_lease().ok_or(ProviderLedgerError::Unavailable)?;
        let response = complete.response().ok_or(ProviderLedgerError::Unavailable)?;
        let child = completion.held.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
        let unsigned = child.settlement.as_ref().and_then(|settlement| settlement.unsigned.as_ref());
        let transport = offer.original_transport_v5();
        Ok(match purpose {
            SettlementObservationV5::Receive => held.session.receive_original_settlement_v5(
                &authority, readback, root, acquire, physical, lease, archive, selected, transport, response,
                initial, deadline, validity, &mut child.signatures),
            SettlementObservationV5::Sign => held.session.sign_original_settlement_v5(
                &authority, readback, root, acquire, physical, lease, archive, selected, transport, response,
                initial, deadline, validity, &mut child.signatures, unsigned.ok_or(ProviderLedgerError::Unavailable)?),
            SettlementObservationV5::Send => held.session.send_original_settlement_v5(
                &authority, readback, root, acquire, physical, lease, archive, selected, transport, response,
                initial, deadline, validity, &mut child.signatures),
            SettlementObservationV5::Current => held.session.revalidate_original_settlement_v5(
                &authority, readback, root, acquire, physical, lease, archive, selected, transport, response,
                initial, deadline, validity, &mut child.signatures, settlement_step(step), unsigned),
        })
    }

    fn prepare_original_settlement_checkpoint_v5(&mut self, step: Append) -> Result<(), OriginalProducerErrorV5> {
        self.require_original_settlement_current_v5()?;
        let (_, acquire) = self.original_ingress.borrowed_pair_v5()?;
        let VerifiedProviderRequestV1::Acquire(verified) = acquire.verified() else { return Err(ProviderLedgerError::Equivocation.into()); };
        let index = settlement_index(step).ok_or(ProviderLedgerError::Unavailable)?;
        let Some(FixedProviderOwnerStateV1::HeldReadOnly(held)) = self.state.as_mut() else { return Err(ProviderLedgerError::Unavailable.into()); };
        let producer = held.original.as_mut().and_then(|original| original.producer.as_mut()).ok_or(ProviderLedgerError::Unavailable)?;
        let acquisition = producer.signed.as_ref().ok_or(ProviderLedgerError::Unavailable)?.request().claims().provider_acquisition().1;
        let history = self.hold_challenges.original_history_v5()?;
        let authority = self.journal.as_mut().ok_or(ProviderLedgerError::RuntimePoisoned)?.claim_source_original_native_v5(&history)?;
        let replay = authority.replayed_origins()?;
        let key = native_completion_key_v2(acquisition);
        let previous = SourceNativeHeldCompletionRecordV1::from_canonical_bytes(&key,
            replay.current_rows().get(&(RecordNamespace::SourceProviderAuthority, key.clone())).ok_or(ProviderLedgerError::Unavailable)?)?;
        let completion_sequence = replay.cuts().last().ok_or(ProviderLedgerError::Unavailable)?.frame_sequences().1;
        let (completion, destination, selected) = producer.settlement_preparation_parts_v5(step)?;
        let spent = completion.spend.as_ref().and_then(StagedOriginalZfsHoldSpendV5::readback).ok_or(ProviderLedgerError::Unavailable)?;
        let held_child = completion.held.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
        let child = held_child.settlement.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
        if child.records[index].is_some() || child.owner_transactions[index].is_some() || child.transactions[index].is_some() {
            return Err(ProviderLedgerError::InvalidTransition("original settlement already prepared").into());
        }
        let mut controls = previous.suffix().controls().to_vec();
        let (phase, prepared) = match step {
            Append::StorageSettlementRecorded => {
                if previous.suffix().phase() != 7 || previous.suffix().prepared().is_some() { return Err(ProviderLedgerError::Equivocation.into()); }
                controls.push(held_child.signatures.original_storage_settlement_v5().ok_or(ProviderLedgerError::Unavailable)?.clone());
                (8, None)
            }
            Append::ProviderSettledPrepared => {
                if previous.suffix().phase() != 8 || previous.suffix().prepared().is_some() { return Err(ProviderLedgerError::Equivocation.into()); }
                let (witness, settlement) = crate::ledger::native_held_completion::derive_provider_settled_preparation_data_v5(
                    replay.current_rows().iter().filter(|((namespace, _), _)| *namespace == RecordNamespace::SourceProviderAuthority)
                        .map(|((_, key), value)| (key.as_slice(), value.as_slice())),
                    acquisition, spent,
                    *held_child.source_cookie.as_ref().and_then(|result| result.as_ref().ok()).ok_or(ProviderLedgerError::Unavailable)?,
                    *held_child.storage_cookie.as_ref().and_then(|result| result.as_ref().ok()).ok_or(ProviderLedgerError::Unavailable)?,
                    completion_sequence, history.current_prefix()?.1,
                    selected.frame(),
                )?;
                let storage6 = previous.suffix().control(Kind::StorageSettled).ok_or(ProviderLedgerError::Unavailable)?;
                child.unsigned = Some(PreparedNativeHeldControlV1::new(
                    Kind::ProviderSettled, selected.frame().fields().scope, storage6.digest(),
                    vec![
                        NativeHeldSectionV1::new(Tag::Witness, NativeHeldOwnerWitnessV1::Provider(witness).to_canonical_bytes()?)?,
                        NativeHeldSectionV1::new(Tag::Settlement, settlement.to_canonical_bytes()?.to_vec())?,
                    ],
                    NativeHeldSignerV1::SourceProvider(verified.ingress_projection().ordered_signers()[3].clone()),
                )?);
                (8, child.unsigned.clone())
            }
            Append::ProviderSettledStored => {
                let signed = held_child.signatures.original_provider_settlement_v5().ok_or(ProviderLedgerError::Unavailable)?;
                if previous.suffix().phase() != 8 || previous.suffix().prepared() != Some(signed.prepared()) { return Err(ProviderLedgerError::Equivocation.into()); }
                controls.push(signed.clone());
                (9, None)
            }
            _ => return Err(ProviderLedgerError::Unavailable.into()),
        };
        let mut original = previous.original().clone();
        original.revision = original.revision.checked_add(1).ok_or(ProviderLedgerError::InvalidTransition("native revision exhausted"))?;
        child.records[index] = Some(SourceNativeHeldCompletionRecordV1::new(original,
            NativeHeldCompletionSuffixV1::new(Role::Provider, phase, previous.suffix().flight(), prepared, controls)?)?);
        child.encoded[index] = Some(child.records[index].as_ref().ok_or(ProviderLedgerError::Unavailable)?.to_canonical_bytes()?);
        let bytes = child.encoded[index].as_deref().ok_or(ProviderLedgerError::Unavailable)?;
        storage_offer::retain_projection(&mut child.before[index], replay.current_rows(), None, authority.configured_limits())?;
        storage_offer::retain_projection(&mut child.after[index], replay.current_rows(), Some((&key, bytes)), authority.configured_limits())?;
        propose_native_held_transition_v1(
            child.before[index].iter().map(|(key, value)| (key.as_slice(), value.as_slice())),
            child.after[index].iter().map(|(key, value)| (key.as_slice(), value.as_slice())),
            acquisition, settlement_step(step), Some(spent),
        )?;
        let purpose: &[u8] = match step {
            Append::StorageSettlementRecorded => b"original-source-storage-settlement-v5",
            Append::ProviderSettledPrepared => b"original-source-settlement-prepared-v5",
            Append::ProviderSettledStored => b"original-source-settlement-stored-v5",
            _ => return Err(ProviderLedgerError::Unavailable.into()),
        };
        child.owner_transactions[index] = Some(owner_transaction_v5(purpose, vec![(key, Some(bytes.to_vec()))])?);
        child.transactions[index] = Some(original_floor_transaction_v5(&authority,
            child.owner_transactions[index].as_ref().ok_or(ProviderLedgerError::Unavailable)?.clone(), acquisition)?);
        super::super::super::PreparedSourceOriginalV5::park(&mut child.transactions[index], &mut None, destination)?;
        Ok(())
    }
}

fn next_settlement_stage(stage: SettlementStageV5, progressed: bool) -> SettlementStageV5 {
    use SettlementStageV5::*;
    match stage {
        Receive if progressed => PrepareReceived,
        PrepareReceived => CommitReceived,
        CommitReceived => PrepareUnsigned,
        PrepareUnsigned => CommitUnsigned,
        CommitUnsigned => Sign,
        Sign => PrepareSigned,
        PrepareSigned => CommitSigned,
        CommitSigned => Send,
        Send if progressed => Sent,
        other => other,
    }
}

#[cfg(test)]
mod tests {
    //! UNRUN progress DATA only; no owner, socket or protected cut is fabricated.

    use super::*;

    #[test]
    fn actual_unsigned_and_signed_commits_precede_signing_and_send() {
        assert!(next_settlement_stage(SettlementStageV5::CommitReceived, true) == SettlementStageV5::PrepareUnsigned);
        assert!(next_settlement_stage(SettlementStageV5::CommitUnsigned, true) == SettlementStageV5::Sign);
        assert!(next_settlement_stage(SettlementStageV5::CommitSigned, true) == SettlementStageV5::Send);
    }

    #[test]
    fn pending_receive_and_send_cannot_advance_or_reopen_closure() {
        assert!(next_settlement_stage(SettlementStageV5::Receive, false) == SettlementStageV5::Receive);
        assert!(next_settlement_stage(SettlementStageV5::Send, false) == SettlementStageV5::Send);
        assert!(next_settlement_stage(SettlementStageV5::Closed, true) == SettlementStageV5::Closed);
    }
}

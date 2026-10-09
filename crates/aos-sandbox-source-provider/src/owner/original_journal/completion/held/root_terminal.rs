//! Same-owner Root13 receipt and protected phase10 readback.
//!
//! One owner mutation and the Source5 successor use the existing full native
//! transaction engine. The remaining cleanup floor and all originals stay held.

use super::*;

#[derive(Clone, Copy, Eq, PartialEq)]
enum TerminalStageV5 {
    Receive,
    Prepare,
    Commit,
    Recorded,
    Closed,
}

#[derive(Clone, Copy)]
enum TerminalFirstFailureV5 {
    Boundary,
    Action(usize),
    Pending,
    Signatures,
    Postcheck(usize),
}

pub(super) struct OriginalSourceRootTerminalV5 {
    stage: TerminalStageV5,
    record: Option<SourceNativeHeldCompletionRecordV1>,
    encoded: Option<Vec<u8>>,
    before: Vec<(Vec<u8>, Vec<u8>)>,
    after: Vec<(Vec<u8>, Vec<u8>)>,
    owner_transaction: Option<aos_sandbox::JournalTransaction>,
    transaction: Option<aos_sandbox::JournalTransaction>,
    actions: [Option<Result<bool, OriginalProducerErrorV5>>; 3],
    pending: Option<Result<(), OriginalProducerErrorV5>>,
    first: Option<TerminalFirstFailureV5>,
    boundary: Option<OriginalProducerErrorV5>,
    postcheck_debt: Option<OriginalProducerErrorV5>,
    postchecks: [Option<Result<(), OriginalProducerErrorV5>>; 3],
}

impl OriginalSourceRootTerminalV5 {
    fn pending() -> Self {
        Self {
            stage: TerminalStageV5::Receive,
            record: None,
            encoded: None,
            before: Vec::new(),
            after: Vec::new(),
            owner_transaction: None,
            transaction: None,
            actions: std::array::from_fn(|_| None),
            pending: None,
            first: None,
            boundary: None,
            postcheck_debt: None,
            postchecks: std::array::from_fn(|_| None),
        }
    }

    pub(super) fn record(&self) -> Option<&SourceNativeHeldCompletionRecordV1> {
        self.record.as_ref()
    }

    fn failure<'a>(&'a self, signatures: &'a OriginalProviderHeldSignaturesV5)
        -> Option<&'a (dyn std::error::Error + 'static)>
    {
        let first = match self.first {
            Some(TerminalFirstFailureV5::Boundary) => self.boundary.as_ref().map(|cause| cause as _),
            Some(TerminalFirstFailureV5::Action(index)) => self.actions[index].as_ref()?.as_ref().err().map(|cause| cause as _),
            Some(TerminalFirstFailureV5::Pending) => self.pending.as_ref()?.as_ref().err().map(|cause| cause as _),
            Some(TerminalFirstFailureV5::Signatures) => signatures.original_root_terminal_failure_v5(),
            Some(TerminalFirstFailureV5::Postcheck(index)) => self.postchecks[index].as_ref()?.as_ref().err().map(|cause| cause as _),
            None => None,
        };
        first.or_else(|| self.postcheck_debt.as_ref().map(|cause| cause as _))
    }
}

impl FixedProviderOwnerV1 {
    /// Borrows the actual first terminal receipt cause before later debt.
    #[must_use]
    #[doc(hidden)]
    pub fn original_terminal_receipt_failure_v5(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Ok(held) = self.original_held_v5()
            && let Some(child) = &held.root_terminal
            && let Some(cause) = child.failure(&held.signatures)
        {
            return Some(cause);
        }
        self.original_settlement_failure_v5()
    }

    /// Advances the installed original from local Kind7 dispatch to phase10.
    ///
    /// This records Root13, not cleanup, retirement, a Storage ACK or Drain.
    #[doc(hidden)]
    pub fn advance_original_native_terminal_receipt_v5(
        &mut self, publication: &[u8], rows: &[u8],
    ) -> Progress {
        if self.original_ingress.producer_closed_v5() { return Progress::Closed; }
        let mut guard = OriginalHeldClosureV5 {
            original: OriginalProducerClosureGuardV5 { owner: self, completed: false },
        };
        let installed = guard.original.owner.original_held_v5()
            .is_ok_and(|held| held.root_terminal.is_some());
        if !installed {
            match guard.original.owner.advance_original_native_settlement_v5(publication, rows) {
                Progress::ProviderSettledSent => {}
                progress => {
                    guard.original.completed = progress != Progress::Closed;
                    return progress;
                }
            }

            // Only the genuine Sent checkpoint installs the empty resident
            // destination, before the first new purpose/currentness gate.
            let _crossing = OriginalCompletionCrossingV5;
            let begun = if let Some(FixedProviderOwnerStateV1::HeldReadOnly(held)) = guard.original.owner.state.as_mut()
                && let Some(child) = held.original.as_mut()
                    .and_then(|original| original.producer.as_mut())
                    .and_then(|producer| producer.original_completion.as_mut())
                    .and_then(|completion| completion.held.as_mut())
            {
                child.root_terminal = Some(OriginalSourceRootTerminalV5::pending());
                let begun = held.session.begin_original_root_terminal_v5(&mut child.signatures);
                if !begun {
                    if let Some(terminal) = child.root_terminal.as_mut() {
                        terminal.first = Some(TerminalFirstFailureV5::Signatures);
                        terminal.stage = TerminalStageV5::Closed;
                    }
                }
                begun
            } else {
                guard.original.owner.original_ingress
                    .retain_producer_failure_v5(ProviderLedgerError::Unavailable.into());
                false
            };
            if !begun {
                guard.original.owner.observe_original_root_terminal_postchecks_v5();
                return Progress::Closed;
            }
        }

        let _crossing = OriginalCompletionCrossingV5;
        let progress = guard.original.owner.advance_original_root_terminal_inner_v5(publication, rows);
        guard.original.completed = progress != Progress::Closed;
        progress
    }

    fn original_root_terminal_mut_v5(&mut self) -> Result<&mut OriginalSourceRootTerminalV5, ProviderLedgerError> {
        self.original_held_mut_v5()?.root_terminal.as_mut().ok_or(ProviderLedgerError::Unavailable)
    }

    fn retain_original_root_terminal_boundary_v5(&mut self, cause: OriginalProducerErrorV5) {
        let earlier = self.original_terminal_receipt_failure_v5().is_some();
        let signature_failure = self.original_held_v5()
            .is_ok_and(|held| held.signatures.original_root_terminal_failure_v5().is_some());
        if let Ok(child) = self.original_root_terminal_mut_v5() {
            if signature_failure && child.first.is_none() {
                child.first = Some(TerminalFirstFailureV5::Signatures);
                if child.postcheck_debt.is_none() { child.postcheck_debt = Some(cause); }
            } else if !earlier && child.first.is_none() {
                child.boundary = Some(cause);
                child.first = Some(TerminalFirstFailureV5::Boundary);
            } else if child.postcheck_debt.is_none() {
                child.postcheck_debt = Some(cause);
            }
            child.stage = TerminalStageV5::Closed;
        } else {
            self.original_ingress.retain_producer_failure_v5(cause);
        }
    }

    fn advance_original_root_terminal_inner_v5(&mut self, publication: &[u8], rows: &[u8]) -> Progress {
        let stage = match self.original_root_terminal_mut_v5() {
            Ok(child) => child.stage,
            Err(_) => return Progress::Closed,
        };
        if stage == TerminalStageV5::Closed { return Progress::Closed; }
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
            self.require_original_root_terminal_current_v5()
        })();
        if let Err(cause) = before {
            self.retain_original_root_terminal_boundary_v5(cause);
            self.observe_original_root_terminal_postchecks_v5();
            return Progress::Closed;
        }

        let (index, action) = match stage {
            TerminalStageV5::Receive => (0, self.observe_original_root_terminal_v5(true)),
            TerminalStageV5::Prepare => (1, self.prepare_original_root_terminal_checkpoint_v5().map(|()| true)),
            TerminalStageV5::Commit => (2, self.append_original_producer_step_v5(Append::RootTerminalRecorded).map(|()| true)),
            TerminalStageV5::Recorded => return Progress::RootTerminalRecorded,
            TerminalStageV5::Closed => return Progress::Closed,
        };
        let progressed = action.as_ref().is_ok_and(|progressed| *progressed);
        let signature_failure = self.original_held_v5()
            .is_ok_and(|held| held.signatures.original_root_terminal_failure_v5().is_some());
        if let Ok(child) = self.original_root_terminal_mut_v5() {
            if child.first.is_none() {
                child.first = if signature_failure { Some(TerminalFirstFailureV5::Signatures) }
                    else if action.is_err() { Some(TerminalFirstFailureV5::Action(index)) }
                    else { None };
            }
            child.actions[index] = Some(action);
        } else {
            if let Err(cause) = action { self.original_ingress.retain_producer_failure_v5(cause); }
            return Progress::Closed;
        }

        self.observe_original_root_terminal_postchecks_v5();
        if self.original_root_terminal_mut_v5().is_err()
            || self.original_terminal_receipt_failure_v5().is_some()
        {
            if let Ok(child) = self.original_root_terminal_mut_v5() { child.stage = TerminalStageV5::Closed; }
            return Progress::Closed;
        }

        if stage == TerminalStageV5::Receive && !progressed {
            let pending = (|| -> Result<(), OriginalProducerErrorV5> {
                let Some(FixedProviderOwnerStateV1::HeldReadOnly(held)) = self.state.as_mut() else {
                    return Err(ProviderLedgerError::Unavailable.into());
                };
                let child = held.original.as_mut().and_then(|original| original.producer.as_mut())
                    .and_then(|producer| producer.original_completion.as_mut())
                    .and_then(|completion| completion.held.as_mut())
                    .ok_or(ProviderLedgerError::Unavailable)?;
                if !held.session.finish_original_root_terminal_pending_v5(&mut child.signatures) {
                    return Err(ProviderLedgerError::RuntimePoisoned.into());
                }
                Ok(())
            })();
            let failed = pending.is_err();
            let signature_failure = self.original_held_v5()
                .is_ok_and(|held| held.signatures.original_root_terminal_failure_v5().is_some());
            if let Ok(child) = self.original_root_terminal_mut_v5() {
                child.pending = Some(pending);
            } else if let Err(cause) = pending {
                self.original_ingress.retain_producer_failure_v5(cause);
                return Progress::Closed;
            }
            if failed {
                if let Ok(child) = self.original_root_terminal_mut_v5() {
                    child.first = Some(if signature_failure { TerminalFirstFailureV5::Signatures }
                        else { TerminalFirstFailureV5::Pending });
                    child.stage = TerminalStageV5::Closed;
                }
                return Progress::Closed;
            }
        }
        let Ok(child) = self.original_root_terminal_mut_v5() else { return Progress::Closed; };
        child.stage = match stage {
            TerminalStageV5::Receive if progressed => TerminalStageV5::Prepare,
            TerminalStageV5::Prepare => TerminalStageV5::Commit,
            TerminalStageV5::Commit => TerminalStageV5::Recorded,
            other => other,
        };
        if child.stage == TerminalStageV5::Recorded {
            Progress::RootTerminalRecorded
        } else { Progress::Pending }
    }

    pub(in crate::owner::original_journal) fn require_original_root_terminal_current_v5(&mut self)
        -> Result<(), OriginalProducerErrorV5>
    {
        self.require_original_held_current_v5()?;
        let step = self.original_source_producer_v5()?.root_terminal_readback_step_v5();
        self.require_original_held_readback_v5(step)?;
        if !self.observe_original_root_terminal_v5(false)? {
            return Err(ProviderLedgerError::RuntimePoisoned.into());
        }
        self.original_ingress.borrowed_clock_v5()?.revalidate(Some(self.original_held_expiry_v5()?))?;
        Ok(())
    }

    fn observe_original_root_terminal_postchecks_v5(&mut self) {
        let owner = (|| {
            self.require_original_held_current_v5()?;
            let step = self.original_source_producer_v5()?.root_terminal_readback_step_v5();
            self.require_original_held_readback_v5(step)
        })();
        let owner_failed = owner.is_err();
        self.park_original_root_terminal_postcheck_v5(0, owner, false);

        // This independently observes both actual Root records even if the
        // writer refused. The final original clock is independently attempted.
        let session = self.observe_original_root_terminal_v5(false).and_then(|current| {
            if current { Ok(()) } else { Err(ProviderLedgerError::RuntimePoisoned.into()) }
        });
        let session_failed = session.is_err();
        let signature_failure = self.original_held_v5()
            .is_ok_and(|held| held.signatures.original_root_terminal_failure_v5().is_some());
        self.park_original_root_terminal_postcheck_v5(1, session, signature_failure);

        let negative = owner_failed || session_failed
            || self.original_terminal_receipt_failure_v5().is_some();
        if negative {
            // Failure may have closed ingress before the positive authority
            // borrower could reach the actual Root records. Observe each held
            // object independently; this void method can only end the purpose.
            if let Some(FixedProviderOwnerStateV1::HeldReadOnly(held)) = self.state.as_mut()
                && let Some(completion) = held.original.as_mut()
                    .and_then(|original| original.producer.as_mut())
                    .and_then(|producer| producer.original_completion.as_mut())
                && let Some(child) = completion.held.as_mut()
            {
                let physical = completion.handoff.as_ref().and_then(|result| result.as_ref().ok());
                held.session.observe_original_root_terminal_negative_v5(physical, &mut child.signatures);
            }
        }
        let clock = (|| {
            let expiry = self.original_held_expiry_v5()?;
            let clock = if negative { self.original_ingress.terminal_negative_clock_v5()? }
                else { self.original_ingress.borrowed_clock_v5()? };
            clock.revalidate(Some(expiry))?;
            Ok(())
        })();
        self.park_original_root_terminal_postcheck_v5(2, clock, false);
    }

    fn park_original_root_terminal_postcheck_v5(&mut self, index: usize,
        result: Result<(), OriginalProducerErrorV5>, signature_failure: bool,
    ) {
        if let Ok(child) = self.original_root_terminal_mut_v5() {
            if result.is_err() && child.first.is_none() {
                child.first = Some(if signature_failure { TerminalFirstFailureV5::Signatures }
                    else { TerminalFirstFailureV5::Postcheck(index) });
            }
            child.postchecks[index] = Some(result);
        } else if let Err(cause) = result {
            self.original_ingress.retain_producer_failure_v5(cause);
        }
    }

    fn observe_original_root_terminal_v5(&mut self, receiving: bool) -> Result<bool, OriginalProducerErrorV5> {
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
        let step = producer.root_terminal_readback_step_v5();
        let issued = producer.signed.as_ref().ok_or(ProviderLedgerError::Unavailable)?.request().claims().validity().0;
        let history = self.hold_challenges.original_history_v5()?;
        let authority = self.journal.as_mut().ok_or(ProviderLedgerError::RuntimePoisoned)?
            .claim_source_original_native_v5(&history)?;
        let (readback, completion, selected, offer) = producer.settlement_parts_v5(step)?;
        let validity = (issued.max(completion.lease.as_ref().ok_or(ProviderLedgerError::Unavailable)?.validity().0), expiry);
        let physical = completion.handoff.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ProviderLedgerError::Unavailable)?;
        let complete = completion.signatures.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
        let lease = complete.signed_lease().ok_or(ProviderLedgerError::Unavailable)?;
        let response = complete.response().ok_or(ProviderLedgerError::Unavailable)?;
        let child = completion.held.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
        let transport = offer.original_transport_v5();
        Ok(if receiving {
            held.session.receive_original_root_terminal_v5(&authority, readback, root, acquire, physical,
                lease, archive, selected, transport, response, initial, deadline, validity, &mut child.signatures)
        } else {
            let step = if step == Append::RootTerminalRecorded { SourceNativeHeldStepV1::RootTerminalRecorded }
                else { SourceNativeHeldStepV1::ProviderSettledStored };
            held.session.revalidate_original_root_terminal_v5(&authority, readback, root, acquire, physical,
                lease, archive, selected, transport, response, initial, deadline, validity, &mut child.signatures, step)
        })
    }

    fn prepare_original_root_terminal_checkpoint_v5(&mut self) -> Result<(), OriginalProducerErrorV5> {
        self.require_original_root_terminal_current_v5()?;
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
        let (completion, destination, _) = producer.settlement_preparation_parts_v5(Append::RootTerminalRecorded)?;
        let spent = completion.spend.as_ref().and_then(StagedOriginalZfsHoldSpendV5::readback)
            .ok_or(ProviderLedgerError::Unavailable)?;
        let held_child = completion.held.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
        let root13 = held_child.signatures.original_root_terminal_v5().ok_or(ProviderLedgerError::Unavailable)?;
        let child = held_child.root_terminal.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
        if child.record.is_some() || child.owner_transaction.is_some() || child.transaction.is_some()
            || previous.suffix().phase() != 9 || previous.suffix().prepared().is_some()
        {
            return Err(ProviderLedgerError::InvalidTransition("original terminal already prepared or wrong phase").into());
        }

        let mut original = previous.original().clone();
        original.revision = original.revision.checked_add(1)
            .ok_or(ProviderLedgerError::InvalidTransition("native revision exhausted"))?;
        let mut controls = previous.suffix().controls().to_vec();
        controls.push(root13.clone());
        child.record = Some(SourceNativeHeldCompletionRecordV1::new(original,
            NativeHeldCompletionSuffixV1::new(Role::Provider, 10, previous.suffix().flight(), None, controls)?)?);
        child.encoded = Some(child.record.as_ref().ok_or(ProviderLedgerError::Unavailable)?.to_canonical_bytes()?);
        let bytes = child.encoded.as_deref().ok_or(ProviderLedgerError::Unavailable)?;
        storage_offer::retain_projection(&mut child.before, replay.current_rows(), None, authority.configured_limits())?;
        storage_offer::retain_projection(&mut child.after, replay.current_rows(), Some((&key, bytes)), authority.configured_limits())?;
        propose_native_held_transition_v1(
            child.before.iter().map(|(key, value)| (key.as_slice(), value.as_slice())),
            child.after.iter().map(|(key, value)| (key.as_slice(), value.as_slice())),
            acquisition, SourceNativeHeldStepV1::RootTerminalRecorded, Some(spent),
        )?;
        child.owner_transaction = Some(owner_transaction_v5(
            b"original-source-root-terminal-v5", vec![(key, Some(bytes.to_vec()))])?);
        child.transaction = Some(original_floor_transaction_v5(&authority,
            child.owner_transaction.as_ref().ok_or(ProviderLedgerError::Unavailable)?.clone(), acquisition)?);
        super::super::super::PreparedSourceOriginalV5::park(&mut child.transaction, &mut None, destination)?;
        Ok(())
    }
}

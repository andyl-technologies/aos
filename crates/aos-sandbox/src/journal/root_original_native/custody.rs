//! One-shot preparation and physical capture for actual original Root appends.
//!
//! Candidates stay parked across canonical derivation and postchecks. Commit
//! retains the actual cut and transaction before cloning rows, and never exposes
//! partial capture as a protected readback. Drop only fails custody and poisons
//! a Journal if this invocation actually entered its append.

use super::*;

pub(super) struct ActualOriginalRootAppendV5 {
    snapshot: ProtectedJournalSnapshot,
    transaction: JournalTransaction,
    rows: Option<State>,
    pub(super) complete: Option<OriginalRootProtectedReadbackV5>,
    validated: bool,
}

pub(super) struct OriginalAppendInputV5<'candidate> {
    transaction: &'candidate JournalTransaction,
    snapshot: &'candidate ProtectedJournalSnapshot,
    attempt: [u8; 32],
    digest: [u8; 32],
    floor: &'candidate Option<OriginalRootCapacityRecordV5>,
    preflight_complete: bool,
    failed: &'candidate core::cell::Cell<bool>,
    attempted: &'candidate core::cell::Cell<bool>,
}

impl<'candidate> OriginalAppendInputV5<'candidate> {
    pub(super) fn borrow(candidate: &'candidate PreparedOriginalRootAppendV5) -> Self {
        Self {
            transaction: &candidate.transaction,
            snapshot: &candidate.snapshot,
            attempt: candidate.attempt,
            digest: candidate.digest,
            floor: &candidate.floor,
            preflight_complete: candidate.preflight_complete,
            failed: &candidate.failed,
            attempted: &candidate.attempted,
        }
    }
}

pub(super) struct PreparationBoundaryV5<'slot> {
    slot: &'slot mut Option<PreparedOriginalRootAppendV5>,
    succeeded: bool,
}

impl<'slot> PreparationBoundaryV5<'slot> {
    pub(super) fn new(slot: &'slot mut Option<PreparedOriginalRootAppendV5>) -> Self {
        Self {
            slot,
            succeeded: false,
        }
    }

    pub(super) fn run(
        &mut self,
        operation: impl FnOnce(&mut Option<PreparedOriginalRootAppendV5>) -> Result<(), JournalError>,
    ) -> Result<(), JournalError> {
        let result = operation(self.slot);
        self.succeeded = result.is_ok();

        result
    }
}

impl Drop for PreparationBoundaryV5<'_> {
    fn drop(&mut self) {
        if !self.succeeded {
            if let Some(candidate) = self.slot.as_ref() {
                candidate.failed.set(true);
            }
        }
    }
}

struct CommitBoundaryV5<'writer, 'journal, 'candidate> {
    writer: &'writer mut MountOriginalNativeJournalAuthorityV5<'journal>,
    failed: &'candidate core::cell::Cell<bool>,
    append_entered: bool,
    succeeded: bool,
}

impl Drop for CommitBoundaryV5<'_, '_, '_> {
    fn drop(&mut self) {
        if !self.succeeded {
            self.failed.set(true);
            if self.append_entered {
                self.writer.authority.journal.poisoned = true;
            }
        }
    }
}

impl PreparedOriginalRootAppendV5 {
    /// Borrows only a complete captured readback, never fresh physical currentness.
    ///
    /// # Errors
    ///
    /// Rejects failed, uncommitted, partial or unvalidated capture.
    pub fn readback(&self) -> Result<&OriginalRootProtectedReadbackV5, JournalError> {
        if self.failed.get() {
            return Err(invalid());
        }
        self.actual
            .as_ref()
            .filter(|actual| actual.validated)
            .and_then(|actual| actual.complete.as_ref())
            .ok_or_else(invalid)
    }

    /// Reports whether this exact candidate entered its one-shot append.
    #[must_use]
    pub fn attempted(&self) -> bool {
        self.attempted.get()
    }

    /// Reports permanent failure without releasing attempted bytes or readback.
    #[must_use]
    pub fn failed(&self) -> bool {
        self.failed.get()
    }

    /// Reports captured actual sequence DATA, including a failed partial readback.
    #[must_use]
    pub fn actual_sequence(&self) -> Option<u64> {
        self.actual.as_ref().map(|actual| actual.snapshot.sequence())
    }
}

impl MountOriginalNativeJournalAuthorityV5<'_> {
    fn initial_candidate_v5(
        &self,
        owners: &JournalTransaction,
        attempt: [u8; 32],
    ) -> PreparedOriginalRootAppendV5 {
        PreparedOriginalRootAppendV5 {
            transaction: owners.clone(),
            snapshot: self.authority.current_snapshot(),
            attempt,
            digest: [0; 32],
            floor: None,
            preflight_complete: false,
            failed: core::cell::Cell::new(false),
            attempted: core::cell::Cell::new(false),
            actual: None,
        }
    }

    /// Parks admission input and the complete coupled candidate before postchecks.
    ///
    /// # Errors
    ///
    /// Retains a failed candidate on occupied custody, invalid owners, currentness,
    /// physical sequence, funding or unchanged opened limits.
    #[doc(hidden)]
    pub fn prepare_admission_retaining_v5(
        &self,
        owners: &JournalTransaction,
        prepared: &PreparedNativeHeldControlV1,
        slot: &mut Option<PreparedOriginalRootAppendV5>,
    ) -> Result<(), JournalError> {
        PreparationBoundaryV5::new(slot).run(|slot| {
            if slot.is_some() {
                return Err(invalid());
            }
            let attempt = *prepared.scope().mount_attempt.as_bytes();
            *slot = Some(self.initial_candidate_v5(owners, attempt));
            self.current_graph()?;
            let (transaction, floor) = derive_admission(
                &self.authority.journal.state,
                owners,
                prepared.clone(),
                self.authority.journal.limits,
            )?;
            let candidate = slot.as_mut().ok_or_else(invalid)?;
            candidate.transaction = transaction;
            candidate.floor = Some(floor);
            validate_transaction(&candidate.transaction, self.authority.journal.limits)?;

            self.finish_preparation_v5(candidate)
        })
    }

    /// Parks a continuation before transfer, sequence and physical preflight checks.
    ///
    /// # Errors
    ///
    /// Retains the failed candidate for invalid original transfer or currentness.
    #[doc(hidden)]
    pub fn prepare_transition_retaining_v5(
        &self,
        owners: &JournalTransaction,
        attempt: [u8; 32],
        slot: &mut Option<PreparedOriginalRootAppendV5>,
    ) -> Result<(), JournalError> {
        PreparationBoundaryV5::new(slot).run(|slot| {
            if slot.is_some() {
                return Err(invalid());
            }
            *slot = Some(self.initial_candidate_v5(owners, attempt));
            self.current_graph()?;
            let (transaction, floor, old) = derive_continuation(
                &self.authority.journal.state,
                owners,
                attempt,
                self.authority.journal.limits,
            )?;
            let candidate = slot.as_mut().ok_or_else(invalid)?;
            candidate.transaction = transaction;
            candidate.floor = floor;
            validate_transfer(
                &candidate.transaction,
                &old,
                candidate.floor.as_ref(),
                self.authority.journal.limits,
            )?;
            let frames = u64::try_from(candidate.transaction.records().len())
                .map_err(|_| JournalError::SequenceExhausted)?
                .checked_add(2)
                .ok_or(JournalError::SequenceExhausted)?;
            let sequence = candidate
                .snapshot
                .sequence()
                .checked_add(frames)
                .ok_or(JournalError::SequenceExhausted)?;
            pending_v5::validate_pending_sequence(
                &self.authority.journal.state,
                &candidate.transaction,
                attempt,
                sequence,
            )?;

            self.finish_preparation_v5(candidate)
        })
    }

    /// Parks exact signed Root1 storage before any continuation postcheck.
    ///
    /// # Errors
    ///
    /// Retains any occupied or derived candidate when actual Root1/readback fails.
    #[doc(hidden)]
    pub fn prepare_root1_store_retaining_v5(
        &self,
        admission: &OriginalRootProtectedReadbackV5,
        signed: &SignedNativeHeldControlV1,
        slot: &mut Option<PreparedOriginalRootAppendV5>,
    ) -> Result<(), JournalError> {
        PreparationBoundaryV5::new(slot).run(|slot| {
            if slot.is_some() {
                return Err(invalid());
            }
            let owners = self.original_root1_store_owners(admission, signed)?;
            self.prepare_transition_retaining_v5(&owners, admission.attempt(), slot)
        })
    }

    fn finish_preparation_v5(
        &self,
        candidate: &mut PreparedOriginalRootAppendV5,
    ) -> Result<(), JournalError> {
        candidate.digest = authority_preflight_digest(std::slice::from_ref(&candidate.transaction));
        self.preflight(&candidate.transaction, candidate.attempt)?;
        self.validate_snapshot(&candidate.snapshot)?;
        candidate.preflight_complete = true;
        Ok(())
    }

    /// Appends once while retaining actual cut, rows and complete readback in place.
    ///
    /// # Errors
    ///
    /// Fails the candidate on any refusal. An entered append poisons the actual
    /// Journal on failure or unwind; rejecting historical reuse does not.
    #[doc(hidden)]
    pub fn commit_prepared_retaining_v5(
        &mut self,
        candidate: &mut PreparedOriginalRootAppendV5,
    ) -> Result<(), JournalError> {
        let PreparedOriginalRootAppendV5 {
            transaction,
            snapshot,
            attempt,
            digest,
            floor,
            preflight_complete,
            failed,
            attempted,
            actual,
        } = candidate;
        let input = OriginalAppendInputV5 {
            transaction,
            snapshot,
            attempt: *attempt,
            digest: *digest,
            floor,
            preflight_complete: *preflight_complete,
            failed,
            attempted,
        };
        self.commit_original_input_v5(input, actual)
    }

    pub(super) fn commit_original_input_v5(
        &mut self,
        input: OriginalAppendInputV5<'_>,
        actual: &mut Option<ActualOriginalRootAppendV5>,
    ) -> Result<(), JournalError> {
        let mut boundary = CommitBoundaryV5 {
            writer: self,
            failed: input.failed,
            append_entered: false,
            succeeded: false,
        };
        if input.failed.get()
            || input.attempted.get()
            || !input.preflight_complete
            || actual.is_some()
        {
            return Err(invalid());
        }

        let writer = &mut boundary.writer;
        writer.validate_snapshot(input.snapshot)?;
        if authority_preflight_digest(std::slice::from_ref(input.transaction)) != input.digest {
            return Err(invalid());
        }
        writer.preflight(input.transaction, input.attempt)?;
        let transaction = input.transaction.clone();

        input.attempted.set(true);
        boundary.append_entered = true;
        let _: CommitResult = writer.authority.journal.commit_with_cache_gate(
            input.transaction,
            None,
            true,
            false,
            false,
            false,
            false,
            SourceProjectAdmissionTransition::None,
            controller_source_genesis::ControllerSourceGenesisTransition::None,
            source_tree_genesis::SourceGenesisTransitionV1::None,
            RootSourceGenesisTransitionV1::None,
            Some(RootOwnerEdge::OriginalNative(input.attempt)),
            CacheMutationGateV1::Ordinary,
        )?;

        *actual = Some(ActualOriginalRootAppendV5 {
            snapshot: writer.authority.current_snapshot(),
            transaction,
            rows: None,
            complete: None,
            validated: false,
        });
        let actual = actual.as_mut().ok_or_else(invalid)?;
        actual.rows = Some(writer.authority.journal.state.clone());

        writer.require_current()?;
        if !writer.authority.journal.transaction_ids.contains(actual.transaction.id())
            || actual.transaction.records().iter().any(|record| {
                writer.authority.journal.get(record.namespace(), record.key()) != record.value()
            })
        {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        let rows = actual.rows.as_ref().ok_or_else(invalid)?;
        require_named_funding(rows, writer.authority.journal.limits)?;
        pending(rows, writer.authority.journal.limits)?;
        let checked = graph(rows)?;
        if checked.canonical_records() != writer.current_graph()?.canonical_records() {
            return Err(invalid());
        }
        actual.complete = Some(OriginalRootProtectedReadbackV5 {
            snapshot: actual.snapshot.clone(),
            graph: checked,
            floor: (*input.floor).clone(),
            attempt: input.attempt,
        });
        writer.validate_readback(actual.complete.as_ref().ok_or_else(invalid)?)?;
        actual.validated = true;
        boundary.succeeded = true;

        Ok(())
    }
}

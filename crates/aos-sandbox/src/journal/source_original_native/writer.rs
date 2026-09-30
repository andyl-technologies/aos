//! Same-held Source original writer and permanently retained attempted custody.
//!
//! Only exact existing owner edges plus the complete derived floor union pass.
//! The scoped writer owns physical membership, current opened headroom and
//! readback. Source independently authenticates archived/current configurations
//! and every retained signature before calling these private-owner operations.

use super::{
    SourceCapacityUnionComparisonDataV5, SourceOriginalAdmissionDataV5,
    SourceOriginalChallengeHistoryViewV5, SourceOriginalPhysicalCutV5, State, invalid,
    replay::SourceOriginalReplayCacheV5,
};
use super::super::{
    CacheMutationGateV1, FixedSourceProviderJournalHandoffV1, Journal, JournalError,
    JournalTransaction, ProtectedAuthorityScope, ProtectedJournalAuthority,
    ProtectedJournalSnapshot, RecordNamespace, RootOwnerEdge, RootSourceGenesisTransitionV1,
    SourceProjectAdmissionTransition, authority_preflight_digest, controller_source_genesis,
    source_tree_genesis,
};

/// Retains one exact attempted transaction and complete candidate before errors.
///
/// There is no public constructor, live original, signing or effect conversion.
/// Failed/attempted instances cannot be retried through another writer.
pub struct PreparedOriginalSourceAppendV5 {
    owners: JournalTransaction,
    snapshot: ProtectedJournalSnapshot,
    candidate: Option<SourceCapacityUnionComparisonDataV5>,
    prospective_origins: Option<SourceOriginalReplayCacheV5>,
    digest: Option<[u8; 32]>,
    preflight_complete: bool,
    attempted: bool,
    failed: bool,
}

impl PreparedOriginalSourceAppendV5 {
    /// Borrows retained exact transaction input even after failed preparation.
    pub fn transaction(&self) -> &JournalTransaction {
        &self.owners
    }

    /// Borrows prospective complete-union DATA, never physical admission proof.
    pub fn comparison(&self) -> Option<&SourceCapacityUnionComparisonDataV5> {
        self.candidate.as_ref()
    }

    /// Borrows prospective origin DATA for Source's separate authentication.
    pub fn prospective_origins(&self) -> Option<&[SourceOriginalAdmissionDataV5]> {
        self.prospective_origins.as_ref().map(SourceOriginalReplayCacheV5::origins)
    }

    /// Returns the actual historical row selected by the existing exact proposer.
    pub fn challenge_checkpoint(&self) -> Option<usize> {
        self.prospective_origins.as_ref()
            .and_then(SourceOriginalReplayCacheV5::prospective_challenge_checkpoint)
    }
}

/// Retains actual same-writer rows before readback decoding or installation.
pub struct OriginalSourceProtectedReadbackV5 {
    snapshot: ProtectedJournalSnapshot,
    rows: State,
    transaction: JournalTransaction,
    validated: bool,
}

/// Binds prospective archive metadata to one held append without proving commit.
pub struct SourceOriginalAppendSubjectV5 {
    identity: (u64, u64),
    transaction: [u8; 16],
    digest: [u8; 32],
    begin_sequence: u64,
    commit_sequence: u64,
    begin_offset: u64,
}

impl SourceOriginalAppendSubjectV5 {
    /// Returns the actual held file device and inode.
    pub const fn file_identity(&self) -> (u64, u64) {
        self.identity
    }

    /// Returns the prospective exact ordered transaction identity and digest.
    pub const fn transaction(&self) -> ([u8; 16], [u8; 32]) {
        (self.transaction, self.digest)
    }

    /// Returns the actual pre-append next frame sequence and file length.
    pub const fn prefix(&self) -> (u64, u64) {
        (self.begin_sequence, self.begin_offset)
    }

    /// Returns prospective begin/commit sequences from this exact bounded framing.
    pub const fn frame_sequences(&self) -> (u64, u64) {
        (self.begin_sequence, self.commit_sequence)
    }
}

impl OriginalSourceProtectedReadbackV5 {
    /// Borrows actual rows without granting Ready, signing or effect authority.
    pub fn rows(&self) -> &State {
        &self.rows
    }
}

/// Borrows actual uncompacted origins/cuts from the held physical replay owner.
pub struct SourceOriginalReplayViewV5<'writer> {
    journal: &'writer Journal,
}

impl SourceOriginalReplayViewV5<'_> {
    /// Borrows actual exact admission references from committed frames.
    pub fn origins(&self) -> &[SourceOriginalAdmissionDataV5] {
        self.journal.source_original_replay.origins()
    }

    /// Borrows actual committed transaction boundaries.
    pub fn cuts(&self) -> &[SourceOriginalPhysicalCutV5] {
        self.journal.source_original_replay.cuts()
    }

    /// Borrows the actual current complete namespace41/46 materialization.
    pub fn current_rows(&self) -> &State {
        &self.journal.state
    }
}

/// Holds the fixed provider writer and independently held challenge-history view.
pub struct SourceOriginalNativeJournalAuthorityV5<'journal, 'challenge> {
    authority: ProtectedJournalAuthority<'journal>,
    challenges: &'challenge SourceOriginalChallengeHistoryViewV5<'challenge>,
}

impl Journal {
    /// Reports an inert Source-history dependency without claiming replay closure.
    #[doc(hidden)]
    pub fn source_original_replay_required_v5(&self) -> bool {
        self.source_original_replay.has_dependencies() || super::replay::has_original_rows(&self.state)
    }

    /// Completes the SAME physical parser using actual separately held history.
    ///
    /// The raw Source-pending state is inert until this full closure succeeds.
    ///
    /// # Errors
    ///
    /// Rejects changed physical custody, missing/compacted original references,
    /// unsupported exact edges, canonical union/headroom or replay disagreement.
    #[doc(hidden)]
    pub fn complete_source_original_replay_v5(
        &mut self,
        challenges: &SourceOriginalChallengeHistoryViewV5<'_>,
    ) -> Result<(), JournalError> {
        require_fixed_location(self)?;
        challenges.validate_current()?;
        let mut replay = super::super::replay_with_source_original(
            &mut self.file, self.limits, Some(challenges),
        )?;
        if replay.source_original_replay.needs_closure()
            || replay.state != self.state
            || replay.next_sequence != self.next_sequence
            || replay.transaction_ids != self.transaction_ids
            || replay.durable_end != self.file.metadata()?.len()
        {
            return Err(JournalError::StaleAuthoritySnapshot);
        }

        replay.source_original_replay.retain_challenges(challenges)?;
        replay.source_original_replay.compare_cached(&self.state, None, self.limits)?;
        require_fixed_location(self)?;
        challenges.validate_current()?;
        self.source_original_replay = replay.source_original_replay;
        Ok(())
    }

    /// Claims only the named exact Source route with both physical owners held.
    ///
    /// # Errors
    ///
    /// Rejects pending replay, stale challenge/path/instance custody, foreign
    /// namespaces, canonical floor mismatch or unsupported complete owner state.
    #[doc(hidden)]
    pub fn claim_source_original_native_v5<'journal, 'challenge>(
        &'journal mut self,
        challenges: &'challenge SourceOriginalChallengeHistoryViewV5<'challenge>,
    ) -> Result<SourceOriginalNativeJournalAuthorityV5<'journal, 'challenge>, JournalError> {
        require_fixed(self)?;
        self.source_original_replay.validate_challenges(challenges)?;
        self.source_original_replay.compare_cached(&self.state, None, self.limits)?;
        Ok(SourceOriginalNativeJournalAuthorityV5 {
            authority: ProtectedJournalAuthority {
                journal: self,
                namespace: RecordNamespace::SourceProviderAuthority,
                scope: ProtectedAuthorityScope::SourceOriginalNativeV5,
            },
            challenges,
        })
    }
}

impl SourceOriginalNativeJournalAuthorityV5<'_, '_> {
    /// Returns the exact limits opened by this held Journal.
    pub fn configured_limits(&self) -> super::super::JournalLimits {
        self.authority.journal.limits
    }

    /// Binds archive metadata to the actual held prefix and ordered candidate.
    ///
    /// # Errors
    ///
    /// Rejects changed physical/challenge custody or invalid bounded transaction.
    pub fn archive_subject(
        &self,
        transaction: &JournalTransaction,
    ) -> Result<SourceOriginalAppendSubjectV5, JournalError> {
        self.require_current()?;
        super::super::validate_transaction(transaction, self.configured_limits())?;
        let identity = super::super::FileIdentity::of(&self.authority.journal.file)?;
        let mutation_frames = u64::try_from(transaction.records().len())
            .map_err(|_| JournalError::SequenceExhausted)?;
        let commit_sequence = self.authority.journal.next_sequence
            .checked_add(mutation_frames)
            .and_then(|sequence| sequence.checked_add(1))
            .ok_or(JournalError::SequenceExhausted)?;
        Ok(SourceOriginalAppendSubjectV5 {
            identity: (identity.device, identity.inode),
            transaction: *transaction.id(),
            digest: authority_preflight_digest(std::slice::from_ref(transaction)),
            begin_sequence: self.authority.journal.next_sequence,
            commit_sequence,
            begin_offset: identity.size,
        })
    }

    fn require_current(&self) -> Result<(), JournalError> {
        require_fixed(self.authority.journal)?;
        self.authority.journal.source_original_replay.validate_challenges(self.challenges)
    }

    /// Permanently closes this actual writer after a Source post-readback failure.
    ///
    /// This only revokes availability; it cannot mint or restore authority.
    pub fn poison_after_owner_failure(&mut self) {
        self.authority.journal.poisoned = true;
    }

    /// Borrows real physical origins/cuts after complete currentness checks.
    ///
    /// # Errors
    ///
    /// Rejects stale files, sequence, challenge view or pending replay.
    pub fn replayed_origins(&self) -> Result<SourceOriginalReplayViewV5<'_>, JournalError> {
        self.require_current()?;
        Ok(SourceOriginalReplayViewV5 { journal: self.authority.journal })
    }

    /// Lends an observation-only genuine fixed Security handoff.
    ///
    /// # Errors
    ///
    /// Rejects stale physical/challenge custody or unclosed replay.
    pub fn session_handoff(
        &self,
    ) -> Result<FixedSourceProviderJournalHandoffV1<'_, '_>, JournalError> {
        self.require_current()?;
        Ok(FixedSourceProviderJournalHandoffV1 {
            authority: &self.authority,
            sequence: self.authority.journal.next_sequence,
        })
    }

    /// Parks exact input in caller custody before any fallible validation.
    ///
    /// # Errors
    ///
    /// Rejects occupied custody, missing input, stale physical owners, incorrect
    /// exact owner/floor union or opened headroom. Failed input stays parked.
    pub fn prepare(
        &self,
        owners: &mut Option<JournalTransaction>,
        slot: &mut Option<PreparedOriginalSourceAppendV5>,
    ) -> Result<(), JournalError> {
        if let Some(existing) = slot.as_mut() {
            existing.failed = true;
            return Err(JournalError::InvalidTransaction);
        }
        let input = owners.take().ok_or(JournalError::InvalidTransaction)?;
        *slot = Some(PreparedOriginalSourceAppendV5 {
            owners: input,
            snapshot: self.authority.current_snapshot(),
            candidate: None,
            prospective_origins: None,
            digest: None,
            preflight_complete: false,
            attempted: false,
            failed: false,
        });

        let prepared = slot.as_mut().ok_or(JournalError::InvalidTransaction)?;
        let result = (|| {
            self.require_current()?;
            self.authority.validate_snapshot(&prepared.snapshot)?;
            let journal = &self.authority.journal;
            super::super::validate_transaction(&prepared.owners, journal.limits)?;
            let (origins, comparison) = journal.source_original_replay.preview_transaction(
                &journal.state, &prepared.owners, journal.limits,
            )?;
            prepared.prospective_origins = Some(origins);
            prepared.candidate = Some(comparison);
            self.preflight(prepared)?;
            prepared.digest = Some(authority_preflight_digest(std::slice::from_ref(
                &prepared.owners,
            )));
            prepared.preflight_complete = true;
            Ok(())
        })();
        if result.is_err() {
            prepared.failed = true;
        }
        result
    }

    /// Rechecks exact full-TX conservation, all opened ceilings and future NEXT.
    ///
    /// # Errors
    ///
    /// Rejects failed/attempted custody, changed candidate/snapshots or any
    /// actual current free-headroom/debt/overflow/sequence refusal.
    pub fn preflight(&self, prepared: &mut PreparedOriginalSourceAppendV5) -> Result<(), JournalError> {
        if prepared.failed || prepared.attempted {
            prepared.failed = true;
            return Err(JournalError::InvalidTransaction);
        }
        let result = (|| {
            self.require_current()?;
            self.authority.validate_snapshot(&prepared.snapshot)?;
            let journal = &self.authority.journal;
            let (_, actual) = journal.source_original_replay.preview_transaction(
                &journal.state, &prepared.owners, journal.limits,
            )?;
            let candidate = prepared.candidate.as_ref().ok_or(JournalError::InvalidTransaction)?;
            if actual.before() != candidate.before() || actual.after() != candidate.after() {
                return Err(JournalError::StaleAuthoritySnapshot);
            }
            journal.preflight_with_cache_gate(
                std::slice::from_ref(&prepared.owners),
                None,
                prepared.owners.records().iter().any(|record| {
                    record.namespace() == RecordNamespace::GlobalCapacityReservation
                }),
                false,
                None,
                None,
                None,
                Some(RootOwnerEdge::SourceOriginal),
                CacheMutationGateV1::Ordinary,
            )
        })();
        if result.is_err() {
            prepared.failed = true;
        }
        result
    }

    /// Attempts one append and parks real readback before all postchecks.
    ///
    /// # Errors
    ///
    /// Rejects failed/unprepared/repeated attempts or occupied readback. Every
    /// error retains input/candidate/pair, and ambiguous attempted outcomes poison.
    pub fn commit_prepared(
        &mut self,
        prepared: &mut PreparedOriginalSourceAppendV5,
        readback: &mut Option<OriginalSourceProtectedReadbackV5>,
    ) -> Result<(), JournalError> {
        if prepared.failed || prepared.attempted || !prepared.preflight_complete || readback.is_some() {
            prepared.failed = true;
            return Err(JournalError::InvalidTransaction);
        }
        let result = (|| {
            self.preflight(prepared)?;
            if prepared.digest != Some(authority_preflight_digest(std::slice::from_ref(
                &prepared.owners,
            ))) {
                return Err(JournalError::InvalidTransaction);
            }

            prepared.attempted = true;
            self.authority.journal.commit_with_cache_gate(
                &prepared.owners,
                None,
                prepared.owners.records().iter().any(|record| {
                    record.namespace() == RecordNamespace::GlobalCapacityReservation
                }),
                false,
                false,
                false,
                false,
                SourceProjectAdmissionTransition::None,
                controller_source_genesis::ControllerSourceGenesisTransition::None,
                source_tree_genesis::SourceGenesisTransitionV1::None,
                RootSourceGenesisTransitionV1::None,
                Some(RootOwnerEdge::SourceOriginal),
                CacheMutationGateV1::Ordinary,
            )?;
            *readback = Some(OriginalSourceProtectedReadbackV5 {
                snapshot: self.authority.current_snapshot(),
                rows: self.authority.journal.state.clone(),
                transaction: prepared.owners.clone(),
                validated: false,
            });

            self.authority.journal.complete_source_original_replay_v5(self.challenges)?;
            let actual = readback.as_mut().ok_or(JournalError::InvalidTransaction)?;
            self.validate_actual_rows(actual)?;
            actual.validated = true;
            Ok(())
        })();
        if result.is_err() {
            prepared.failed = true;
            if prepared.attempted {
                self.authority.journal.poisoned = true;
            }
        }
        result
    }

    fn validate_actual_rows(
        &self,
        actual: &OriginalSourceProtectedReadbackV5,
    ) -> Result<(), JournalError> {
        self.require_current()?;
        self.authority.validate_snapshot(&actual.snapshot)?;
        let journal = &self.authority.journal;
        if journal.state != actual.rows
            || !journal.transaction_ids.contains(actual.transaction.id())
            || actual.transaction.records().iter().any(|record| {
                journal.get(record.namespace(), record.key()) != record.value()
            })
        {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        journal.source_original_replay.compare_cached(&actual.rows, None, journal.limits)?;
        Ok(())
    }

    /// Rechecks actual current readback without minting effect or hot custody.
    ///
    /// # Errors
    ///
    /// Rejects unvalidated/substituted rows, stale owners or changed snapshots.
    pub fn validate_readback(
        &self,
        actual: &OriginalSourceProtectedReadbackV5,
    ) -> Result<(), JournalError> {
        if !actual.validated {
            return Err(JournalError::ProtectedBoundary);
        }
        self.validate_actual_rows(actual)
    }
}

pub(in crate::journal) fn require_fixed(journal: &Journal) -> Result<(), JournalError> {
    require_fixed_location(journal)?;
    if journal.source_original_replay.needs_closure() {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

fn require_fixed_location(journal: &Journal) -> Result<(), JournalError> {
    journal.ensure_protected_authority()?;
    journal.validate_held_root_owned_at("/var/lib/aos/source-provider", "provider.journal")?;
    if journal.committed_namespaces.iter().any(|namespace| {
        !matches!(namespace,
            RecordNamespace::SourceProviderAuthority | RecordNamespace::GlobalCapacityReservation)
    })
        || journal.state.keys().any(|(namespace, _)| {
            !matches!(namespace,
                RecordNamespace::SourceProviderAuthority | RecordNamespace::GlobalCapacityReservation)
        })
    {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

#[cfg(test)]
mod tests;

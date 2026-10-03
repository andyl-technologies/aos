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
use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_ledger::ledger::{
    native_completion::{OriginalSourceProvenanceV5, propose_original_source_applying_v5},
    native_held_completion::{
        SourceNativeHeldCompletionRecordV1, derive_original_source_continuations_v5,
    },
    source_capacity::derive_source_capacity_owner_data_v1,
};
use aos_sandbox_source_provider_protocol::SignedStorageNativeAcquireRequestV2;
use super::super::native_held::{
    NativeHeldCapacityPurposeV3, NativeHeldCapacityRequestV3, OriginalSourceCapacityRecordV5,
    OriginalSourceGeometryDataV5, derive_original_source_geometry_v5,
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
    original_native_signing_attempted: std::cell::Cell<bool>,
    original_completion_signing: std::cell::Cell<u8>,
    original_held_signing_attempted: std::cell::Cell<bool>,
}

enum OriginalHeldBasisPurposeV5<'control> {
    Preparation(&'control aos_sandbox_source_provider_protocol::native_held_completion::frame::PreparedNativeHeldControlV1),
    Delivery(&'control aos_sandbox_source_provider_protocol::native_held_completion::frame::SignedNativeHeldControlV1),
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
    /// Borrows the actual current phase-four physical cut, never a new admission.
    ///
    /// # Errors
    ///
    /// Rejects stale readback, an absent/ambiguous transaction or non-Complete phase.
    pub fn original_held_complete_cut_v5(
        &self,
        readback: &OriginalSourceProtectedReadbackV5,
        acquisition: ObjectDigest,
    ) -> Result<&SourceOriginalPhysicalCutV5, JournalError> {
        self.validate_readback(readback)?;
        let key = aos_sandbox_source_provider_ledger::ledger::native_completion::native_completion_key_v2(acquisition);
        let bytes = readback.rows.get(&(RecordNamespace::SourceProviderAuthority, key.clone()))
            .ok_or(invalid("original Held Complete missing"))?;
        let record = SourceNativeHeldCompletionRecordV1::from_canonical_bytes(&key, bytes)
            .map_err(|_| invalid("original Held Complete codec"))?;
        if record.suffix().phase() != 4
            || record.original().state != aos_sandbox_source_provider_ledger::ledger::native_completion::NativeAcquireCompletionStateV2::Active
        {
            return Err(invalid("original Held requires actual Complete"));
        }
        self.original_readback_cut_v5(readback)
    }

    fn original_readback_cut_v5(
        &self,
        readback: &OriginalSourceProtectedReadbackV5,
    ) -> Result<&SourceOriginalPhysicalCutV5, JournalError> {
        let mut cuts = self.authority.journal.source_original_replay.cuts().iter()
            .filter(|cut| cut.transaction_id() == readback.transaction.id());
        let cut = cuts.next().ok_or(invalid("original Held physical transaction missing"))?;
        if cuts.next().is_some() || cut.after_rows() != &readback.rows {
            return Err(invalid("original Held physical transaction changed"));
        }
        Ok(cut)
    }

    /// Checks unsigned Provider3 against its genuine current phase-five cut.
    ///
    /// # Errors
    ///
    /// Rejects foreign preparation, stale physical custody, missing full phase4
    /// before rows, changed Spent history or another original Applying lineage.
    pub fn original_held_signing_basis_v5(
        &self,
        readback: &OriginalSourceProtectedReadbackV5,
        acquisition: ObjectDigest,
        exact: &aos_sandbox_source_provider_protocol::native_held_completion::frame::PreparedNativeHeldControlV1,
    ) -> Result<&SourceOriginalAdmissionDataV5, JournalError> {
        self.original_held_basis_v5(
            readback, acquisition, OriginalHeldBasisPurposeV5::Preparation(exact),
        )
    }

    /// Borrows the actual current phase-six delivery basis without a send permit.
    ///
    /// # Errors
    ///
    /// Rejects stale physical custody, changed signed Held or a different
    /// Applying, Spent, phase-five preparation or Complete companion graph.
    pub fn original_held_delivery_basis_v5(
        &self,
        readback: &OriginalSourceProtectedReadbackV5,
        acquisition: ObjectDigest,
        signed: &aos_sandbox_source_provider_protocol::native_held_completion::frame::SignedNativeHeldControlV1,
    ) -> Result<&SourceOriginalAdmissionDataV5, JournalError> {
        self.original_held_basis_v5(
            readback, acquisition, OriginalHeldBasisPurposeV5::Delivery(signed),
        )
    }

    fn original_held_basis_v5(
        &self,
        readback: &OriginalSourceProtectedReadbackV5,
        acquisition: ObjectDigest,
        purpose: OriginalHeldBasisPurposeV5<'_>,
    ) -> Result<&SourceOriginalAdmissionDataV5, JournalError> {
        use aos_sandbox_source_provider_ledger::ledger::native_held_completion::{
            SourceNativeHeldStepV1, propose_native_held_transition_v1,
        };
        use aos_sandbox_source_provider_protocol::native_held_completion::NativeHeldControlKindV1;

        self.validate_readback(readback)?;
        let cut = self.original_readback_cut_v5(readback)?;
        let key = aos_sandbox_source_provider_ledger::ledger::native_completion::native_completion_key_v2(acquisition);
        let read = |rows: &State| {
            SourceNativeHeldCompletionRecordV1::from_canonical_bytes(
                &key, rows.get(&(RecordNamespace::SourceProviderAuthority, key.clone()))
                    .ok_or(invalid("original Held native missing"))?,
            ).map_err(|_| invalid("original Held native codec"))
        };
        let before = read(cut.before_rows())?;
        let after = read(cut.after_rows())?;
        let step = match purpose {
            OriginalHeldBasisPurposeV5::Preparation(exact) => {
                if before.suffix().phase() != 4 || after.suffix().phase() != 5
                    || after.suffix().prepared() != Some(exact)
                    || exact.kind() != NativeHeldControlKindV1::ProviderHeld
                {
                    return Err(invalid("original Held phase5 preparation changed"));
                }
                SourceNativeHeldStepV1::HeldPrepared
            }
            OriginalHeldBasisPurposeV5::Delivery(signed) => {
                if before.suffix().phase() != 5 || after.suffix().phase() != 6
                    || before.suffix().prepared() != Some(signed.prepared())
                    || after.suffix().prepared().is_some()
                    || after.suffix().control(NativeHeldControlKindV1::ProviderHeld) != Some(signed)
                    || signed.kind() != NativeHeldControlKindV1::ProviderHeld
                {
                    return Err(invalid("original Held phase6 delivery changed"));
                }
                SourceNativeHeldStepV1::HeldStored
            }
        };
        let checkpoints = self.challenges.retained_rows()?;
        let spent = checkpoints.get(cut.challenge_checkpoint()
            .ok_or(invalid("original Held Spent checkpoint missing"))?)
            .ok_or(invalid("original Held Spent checkpoint absent"))?;
        if checkpoints.iter().rev().find(|row| row.key() == spent.key())
            .is_none_or(|row| row.value() != spent.value())
        {
            return Err(invalid("original Held Spent changed"));
        }
        propose_native_held_transition_v1(
            super::owner_views(cut.before_rows()), super::owner_views(cut.after_rows()),
            acquisition, step, Some(spent.value()),
        ).map_err(|_| invalid("original Held complete before witness"))?;
        let origin = self.authority.journal.source_original_replay.origins().iter()
            .find(|origin| origin.admission_comparison().original().acquisition_id == acquisition)
            .ok_or(invalid("original Held Applying origin missing"))?;
        let provenance = origin.initial_floor().original_provenance().claims();
        if after.original().canonical_request.as_ref().map(|request| request.request().claims())
                != Some(&provenance.claims)
            || after.suffix().controls().first() != Some(&provenance.root_prepared)
        {
            return Err(invalid("original Held Applying association"));
        }
        self.validate_readback(readback)?;
        Ok(origin)
    }

    /// Ends the once-only phase-five purpose before any fallible basis check.
    ///
    /// # Errors
    ///
    /// Rejects a repeated attempt or anything except the same genuine phase5 cut.
    pub fn claim_original_held_signing_v5(
        &self,
        readback: &OriginalSourceProtectedReadbackV5,
        acquisition: ObjectDigest,
        exact: &aos_sandbox_source_provider_protocol::native_held_completion::frame::PreparedNativeHeldControlV1,
    ) -> Result<(), JournalError> {
        if readback.original_held_signing_attempted.replace(true) {
            return Err(invalid("original Held signing already attempted"));
        }
        self.original_held_signing_basis_v5(readback, acquisition, exact)?;
        Ok(())
    }

    /// Checks the remaining envelope on the actual phase-two cut before spend.
    ///
    /// This derives symbolic codec bounds, not future Spent rows, signatures,
    /// transactions or a portable capacity permit.
    ///
    /// # Errors
    ///
    /// Rejects a changed readback, missing original Issued history, an ambiguous
    /// Source5 floor or insufficient opened all-eight/NEXT headroom.
    pub fn require_original_completion_headroom_v5(
        &self,
        readback: &OriginalSourceProtectedReadbackV5,
        acquisition: ObjectDigest,
    ) -> Result<(), JournalError> {
        self.validate_readback(readback)?;
        let journal = &self.authority.journal;
        let key = aos_sandbox_source_provider_ledger::ledger::native_completion::
            native_completion_key_v2(acquisition);
        let bytes = readback.rows.get(&(RecordNamespace::SourceProviderAuthority, key.clone()))
            .ok_or(invalid("original Source phase2 readback missing"))?;
        let held = SourceNativeHeldCompletionRecordV1::from_canonical_bytes(&key, bytes)
            .map_err(|_| invalid("original Source phase2 readback codec"))?;
        if held.suffix().phase() != 2 {
            return Err(invalid("original Source completion headroom requires phase2"));
        }

        // The same parser validated this actual phase-one edge against Issued.
        // Compare its real historical checkpoint to the current last value;
        // never reconstruct Issued from Spent or duplicate the challenge codec.
        let checkpoints = self.challenges.retained_rows()?;
        let mut issued = None;
        for cut in journal.source_original_replay.cuts() {
            let Some(bytes) = cut.after_rows().get(&(
                RecordNamespace::SourceProviderAuthority, key.clone(),
            )) else { continue; };
            let record = SourceNativeHeldCompletionRecordV1::from_canonical_bytes(&key, bytes)
                .map_err(|_| invalid("original Source Issued cut codec"))?;
            if record.suffix().phase() == 1
                && record.original().canonical_request == held.original().canonical_request
                && let Some(index) = cut.challenge_checkpoint()
            {
                let checkpoint = checkpoints.get(index)
                    .ok_or(invalid("original Source Issued physical checkpoint missing"))?;
                if issued.replace(checkpoint).is_some() {
                    return Err(invalid("original Source Issued physical checkpoint ambiguous"));
                }
            }
        }
        let issued = issued.ok_or(invalid("original Source Issued physical checkpoint absent"))?;
        if checkpoints.iter().rev().find(|row| row.key() == issued.key())
            .is_none_or(|row| row.value() != issued.value())
        {
            return Err(invalid("original Source challenge already advanced"));
        }

        let origin = journal.source_original_replay.origins().iter()
            .find(|origin| origin.admission_comparison().original().acquisition_id == acquisition)
            .ok_or(invalid("original Source completion origin missing"))?;
        let mut selected = None;
        for family in super::super::capacity_reservation::family::canonical_reservations(&journal.state)? {
            if let super::super::capacity_reservation::family::CanonicalCapacityFamily::OriginalSource5(floor) = family
                && floor.original_provenance().claims().claims.provider_acquisition().1 == acquisition
                && selected.replace(floor).is_some()
            {
                return Err(invalid("original Source completion floor ambiguous"));
            }
        }
        let floor = selected.ok_or(invalid("original Source completion floor absent"))?;
        let continuations = derive_original_source_continuations_v5(
            journal.state.iter()
                .filter(|((namespace, _), _)| *namespace == RecordNamespace::SourceProviderAuthority)
                .map(|((_, key), value)| (key.as_slice(), value.as_slice())),
            Some(origin.admission_comparison()), floor.original_provenance(),
            floor.original_provenance().claims().configuration,
        ).map_err(|_| invalid("original Source completion continuations"))?;
        if continuations.prefix() != aos_sandbox_source_provider_ledger::ledger::native_held_completion::
            OriginalSourceContinuationPrefixV5::Held(2)
        {
            return Err(invalid("original Source completion continuation phase"));
        }
        derive_original_source_geometry_v5(journal, &floor, &continuations, None)?;
        self.validate_readback(readback)
    }

    /// Borrows the original admission from the actual durable Spent phase.
    ///
    /// # Errors
    ///
    /// Rejects changed physical rows/history, a foreign original request or any
    /// cut other than the same current phase-three readback.
    pub fn original_completion_signing_basis_v5(
        &self,
        readback: &OriginalSourceProtectedReadbackV5,
        acquisition: ObjectDigest,
    ) -> Result<&SourceOriginalAdmissionDataV5, JournalError> {
        self.validate_readback(readback)?;
        let key = aos_sandbox_source_provider_ledger::ledger::native_completion::
            native_completion_key_v2(acquisition);
        let bytes = readback.rows.get(&(RecordNamespace::SourceProviderAuthority, key.clone()))
            .ok_or(invalid("original Source phase3 readback missing"))?;
        let record = SourceNativeHeldCompletionRecordV1::from_canonical_bytes(&key, bytes)
            .map_err(|_| invalid("original Source phase3 readback codec"))?;
        let origin = self.authority.journal.source_original_replay.origins().iter()
            .find(|origin| origin.admission_comparison().original().acquisition_id == acquisition)
            .ok_or(invalid("original Source phase3 origin missing"))?;
        let provenance = origin.initial_floor().original_provenance().claims();
        if record.suffix().phase() != 3
            || record.original().canonical_request.as_ref().map(|request| request.request().claims())
                != Some(&provenance.claims)
            || record.suffix().controls().first() != Some(&provenance.root_prepared)
        {
            return Err(invalid("original Source phase3 signing association"));
        }
        Ok(origin)
    }

    /// Claims the once-only lease purpose on the real phase-three readback.
    ///
    /// # Errors
    ///
    /// Rejects stale phase-three custody or an out-of-order/repeated purpose.
    pub fn claim_original_completion_lease_v5(
        &self, readback: &OriginalSourceProtectedReadbackV5, acquisition: ObjectDigest,
    ) -> Result<(), JournalError> {
        self.claim_original_completion_purpose(readback, acquisition, 0, 1)
    }

    /// Claims receipt only after this readback's actual lease attempt.
    ///
    /// # Errors
    ///
    /// Rejects stale custody or an out-of-order/repeated purpose.
    pub fn claim_original_completion_receipt_v5(
        &self, readback: &OriginalSourceProtectedReadbackV5, acquisition: ObjectDigest,
    ) -> Result<(), JournalError> {
        self.claim_original_completion_purpose(readback, acquisition, 1, 2)
    }

    /// Claims status only after this readback's actual receipt attempt.
    ///
    /// # Errors
    ///
    /// Rejects stale custody or an out-of-order/repeated purpose.
    pub fn claim_original_completion_status_v5(
        &self, readback: &OriginalSourceProtectedReadbackV5, acquisition: ObjectDigest,
    ) -> Result<(), JournalError> {
        self.claim_original_completion_purpose(readback, acquisition, 2, 3)
    }

    fn claim_original_completion_purpose(
        &self, readback: &OriginalSourceProtectedReadbackV5, acquisition: ObjectDigest,
        expected: u8, next: u8,
    ) -> Result<(), JournalError> {
        self.original_completion_signing_basis_v5(readback, acquisition)?;
        // An invalid claim also ends this resident latch; revalidation cannot reset it.
        let actual = readback.original_completion_signing.replace(u8::MAX);
        if actual != expected {
            return Err(invalid("original Source completion signing purpose already attempted"));
        }
        readback.original_completion_signing.set(next);
        Ok(())
    }

    /// Derives initial Source5 DATA from the actual before cut and exact quartet.
    ///
    /// This measures the sole reducer's complete continuation envelope before
    /// constructing a floor. Returning DATA does not admit it: preparation still
    /// checks the full floor union, physical headroom and exact transaction CAS.
    ///
    /// # Errors
    ///
    /// Rejects stale custody, an invalid original quartet, incomplete geometry,
    /// changed bindings or insufficient actual opened headroom.
    pub fn derive_initial_original_floor_v5(
        &self,
        quartet: &JournalTransaction,
        provenance: &OriginalSourceProvenanceV5,
    ) -> Result<OriginalSourceCapacityRecordV5, JournalError> {
        self.require_current()?;
        let journal = &self.authority.journal;
        if quartet.records().len() != 4
            || quartet.records().iter().any(|record| {
                record.namespace() != RecordNamespace::SourceProviderAuthority
                    || record.value().is_none()
            })
            || journal.transaction_ids.contains(quartet.id())
        {
            return Err(invalid("original Source initial quartet shape"));
        }
        let owner_rows = || journal.state.iter()
            .filter(|((namespace, _), _)| *namespace == RecordNamespace::SourceProviderAuthority)
            .map(|((_, key), value)| (key.as_slice(), value.as_slice()));
        let proposal = propose_original_source_applying_v5(
            owner_rows(),
            quartet.records().iter().map(|record| (record.key(), record.value())),
            provenance,
            provenance.claims().configuration,
        ).map_err(|_| invalid("original Source initial owner proposal"))?;
        let comparison = proposal.admission_comparison()
            .map_err(|_| invalid("original Source initial comparison"))?;
        let mut after = owner_rows()
            .map(|(key, value)| (key.to_vec(), value.to_vec()))
            .collect::<std::collections::BTreeMap<_, _>>();
        for mutation in proposal.mutations() {
            after.insert(mutation.key().to_vec(), mutation.after().to_vec());
        }
        let after_rows = || after.iter().map(|(key, value)| (key.as_slice(), value.as_slice()));
        let continuation = derive_original_source_continuations_v5(
            after_rows(), Some(&comparison), provenance, provenance.claims().configuration,
        ).map_err(|_| invalid("original Source initial continuations"))?;
        let budgets = OriginalSourceGeometryDataV5::measure_initial_envelopes(
            &continuation, journal.limits,
        )?;

        // Reuse the existing dispatch-binding derivation, not another owner-ID hash.
        // These temporary ordinary bindings are DATA only; the actual admission
        // associates this original with Source5 through the complete union.
        let bindings = derive_source_capacity_owner_data_v1(after_rows(), &[])
            .map_err(|_| invalid("original Source initial binding derivation"))?;
        let binding = bindings.ordinary_bindings().iter()
            .find(|binding| binding.acquisition() == proposal.data().acquisition_id)
            .ok_or(invalid("original Source initial dispatch binding"))?
            .fields();
        let request = NativeHeldCapacityRequestV3 {
            purpose: NativeHeldCapacityPurposeV3::Provider,
            owner_id: binding.owner_id,
            owner_digest: binding.owner_digest,
            operation_id: binding.operation_id,
            artifact_digest: binding.artifact_digest,
            checkpoint_digest: binding.checkpoint_digest,
            chain_head_digest: binding.chain_head_digest,
            future_transactions: 20,
            terminal_records: budgets.terminal_records,
            terminal_bytes: budgets.terminal_bytes,
            poison_records: budgets.poison_records,
            poison_bytes: budgets.poison_bytes,
        };
        let floor = OriginalSourceCapacityRecordV5::new(
            request, *quartet.id(), budgets, provenance.clone(),
        )?;
        derive_original_source_geometry_v5(journal, &floor, &continuation, Some(&proposal))?;
        self.require_current()?;
        Ok(floor)
    }

    /// Derives the exact successor floor DATA from this actual owner's next carrier.
    ///
    /// # Errors
    ///
    /// Rejects stale custody, noncanonical floors or incomplete/foreign owner
    /// continuations. The subsequent full transaction still needs CAS/preflight.
    pub fn derive_original_floor_transfer_v5(
        &self,
        owner_transaction: &JournalTransaction,
        acquisition: ObjectDigest,
    ) -> Result<(OriginalSourceCapacityRecordV5, OriginalSourceCapacityRecordV5), JournalError> {
        self.require_current()?;
        let journal = &self.authority.journal;
        let origin = journal.source_original_replay.origins().iter()
            .find(|origin| origin.admission_comparison().original().acquisition_id == acquisition)
            .ok_or(invalid("original Source transfer origin missing"))?;
        let mut selected = None;
        for family in super::super::capacity_reservation::family::canonical_reservations(&journal.state)? {
            if let super::super::capacity_reservation::family::CanonicalCapacityFamily::OriginalSource5(floor)
                = family
                && floor.original_provenance().claims().claims.provider_acquisition().1 == acquisition
            {
                if selected.replace(floor).is_some() {
                    return Err(invalid("original Source transfer floor ambiguous"));
                }
            }
        }
        let floor = selected.ok_or(invalid("original Source transfer floor missing"))?;
        let mut owners = journal.state.iter()
            .filter(|((namespace, _), _)| *namespace == RecordNamespace::SourceProviderAuthority)
            .map(|((_, key), value)| (key.clone(), value.clone()))
            .collect::<std::collections::BTreeMap<_, _>>();
        for record in owner_transaction.records() {
            if record.namespace() != RecordNamespace::SourceProviderAuthority {
                return Err(invalid("original Source transfer foreign namespace"));
            }
            let value = record.value().ok_or(invalid("original Source transfer deletion"))?;
            owners.insert(record.key().to_vec(), value.to_vec());
        }
        let continuation = derive_original_source_continuations_v5(
            owners.iter().map(|(key, value)| (key.as_slice(), value.as_slice())),
            Some(origin.admission_comparison()),
            floor.original_provenance(),
            floor.original_provenance().claims().configuration,
        ).map_err(|_| invalid("original Source transfer continuation"))?;
        let geometry = OriginalSourceGeometryDataV5::measure_remaining(
            &floor, &continuation, journal.limits,
        )?;
        let successor = OriginalSourceCapacityRecordV5::new(
            geometry.remaining_request().ok_or(invalid("original Source transfer retired"))?,
            floor.admission_transaction_id(),
            floor.origin_budgets(),
            floor.original_provenance().clone(),
        )?;
        self.require_current()?;
        Ok((floor, successor))
    }

    /// Borrows the original admission only from this writer's current Applying readback.
    ///
    /// # Errors
    ///
    /// Rejects historical/caller-created cuts, changed rows, foreign acquisition
    /// or an advanced native carrier. This does not lend mutable Journal authority.
    pub fn original_signing_basis_v5(
        &self,
        readback: &OriginalSourceProtectedReadbackV5,
        acquisition: ObjectDigest,
    ) -> Result<&SourceOriginalAdmissionDataV5, JournalError> {
        self.validate_readback(readback)?;
        let origin = self.authority.journal.source_original_replay.origins().iter()
            .find(|origin| {
                origin.applying_transaction() == &readback.transaction
                    && origin.admission_comparison().original().acquisition_id == acquisition
            })
            .ok_or(invalid("original Source signing needs actual Applying readback"))?;
        if readback.rows.contains_key(&(
            RecordNamespace::SourceProviderAuthority,
            aos_sandbox_source_provider_ledger::ledger::native_completion::
                native_completion_key_v2(acquisition),
        )) {
            return Err(invalid("original Source signing carrier already present"));
        }
        Ok(origin)
    }

    /// Claims only the original native signing purpose on this opaque readback.
    ///
    /// # Errors
    ///
    /// Rejects a noncurrent Applying readback or a repeated signing attempt.
    pub fn claim_original_native_signing_v5(
        &self,
        readback: &OriginalSourceProtectedReadbackV5,
        acquisition: ObjectDigest,
    ) -> Result<(), JournalError> {
        self.original_signing_basis_v5(readback, acquisition)?;
        if readback.original_native_signing_attempted.replace(true) {
            return Err(invalid("original Source native signing already attempted"));
        }
        Ok(())
    }

    /// Requires this same writer's exact Requested readback before challenge issue.
    ///
    /// # Errors
    ///
    /// Rejects stale or foreign physical cuts, changed signed request or any
    /// prefix other than initial held Requested.
    pub fn require_original_requested_readback_v5(
        &self,
        readback: &OriginalSourceProtectedReadbackV5,
        signed: &SignedStorageNativeAcquireRequestV2,
    ) -> Result<(), JournalError> {
        self.validate_readback(readback)?;
        let acquisition = signed.request().claims().provider_acquisition().1;
        let key = aos_sandbox_source_provider_ledger::ledger::native_completion::
            native_completion_key_v2(acquisition);
        let bytes = readback.rows.get(&(RecordNamespace::SourceProviderAuthority, key.clone()))
            .ok_or(invalid("original Source Requested readback missing"))?;
        let record = SourceNativeHeldCompletionRecordV1::from_canonical_bytes(&key, bytes)
            .map_err(|_| invalid("original Source Requested readback codec"))?;
        if record.original().state != aos_sandbox_source_provider_ledger::ledger::
                native_completion::NativeAcquireCompletionStateV2::Requested
            || record.suffix().phase() != 0
            || record.original().canonical_request.as_ref() != Some(signed)
        {
            return Err(invalid("original Source Requested readback changed"));
        }
        Ok(())
    }

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
                original_native_signing_attempted: std::cell::Cell::new(false),
                original_completion_signing: std::cell::Cell::new(0),
                original_held_signing_attempted: std::cell::Cell::new(false),
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

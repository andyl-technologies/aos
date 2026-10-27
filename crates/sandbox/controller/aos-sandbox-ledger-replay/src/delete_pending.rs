//! Observes the current pending cut from the same complete paid native replay.
//!
//! No Controller position enters this owner. A reply can use only the actual
//! parser's last validated COMMIT at the exact captured file end and NEXT.

mod selected_commit;
pub use selected_commit::DeleteSelectedCommitReplayDataV3;

mod terminal;

mod predecessor;
pub use predecessor::{
    DeleteSourcePredecessorDataV2, DeleteSourcePredecessorReplayDataV2,
    DeleteSourceTreeDataErrorV1, DeleteSourceTreeDataV1, source_delete_tree_data_v1,
};

use aos_sandbox_broker::canonical_journal::{
    CanonicalCommitReadViewV1, CanonicalJournalMechanicalErrorV1 as JournalError,
    CanonicalReplayPrefixReadViewV1,
};
use aos_sandbox_model::RecordNamespace;
use aos_sandbox_protocol::domain_ledger::{
    delete_batch::{DeleteBatchViewV1, encode_native_commit_data_v1},
    delete_root::source_current::{
        SourceDeleteCurrentDataErrorV1, SourceDeleteCurrentQueryDataV1,
        source_delete_current_batch_digest_v1, SourceDeleteCurrentPurposeDataV3,
        source_delete_controller_committed_batch_digest_v3,
    },
};
use std::error::Error;
use aos_sandbox_protocol::domain_ledger::{
    lifecycle_auxiliary::{borrow_lifecycle_auxiliary_member_data_v1, LIFECYCLE_PROTECTED_KEY_PREFIX_V1,
        LifecycleAuxiliaryEnvelopeFormatV1},
    delete_batch::LifecycleDeleteBatchRecordViewDataV3,
    records::borrowed::borrow_protected_key_data_v1,
};

const AUXILIARY_KEY_BYTES: usize = LIFECYCLE_PROTECTED_KEY_PREFIX_V1.len() + 4 + 48;


/// Preserves the original last-pending codec and native comparison failures.
#[derive(Debug, thiserror::Error)]
pub enum PendingErrorV1 {
    #[error(transparent)]
    Data(#[from] SourceDeleteCurrentDataErrorV1),
    #[error(transparent)]
    Batch(#[from] aos_sandbox_protocol::domain_ledger::lifecycle_model::LifecycleModelError),
    #[error(transparent)]
    Native(#[from] JournalError),
    #[error(transparent)]
    Hold(#[from] aos_sandbox_protocol::domain_ledger::ProtectedHistoryDataErrorV1),
    /// The sole borrowed protected envelope decoder refused canonical DATA.
    #[error(transparent)]
    Envelope(#[from] aos_sandbox_protocol::domain_ledger::DomainLedgerDataError),
}

/// Retains the last matching canonical pending COMMIT and exact EOF comparison.
///
/// Supplied views and successful comparison are historical DATA. Actual Source
/// or Root callers retain their own parser, native posts, financial ownership
/// and role gate; this type cannot open a file or adopt a live native owner.
pub struct SourceDeletePendingReplayDataV1 {
    query: SourceDeleteCurrentQueryDataV1,
    purpose: SourceDeleteCurrentPurposeDataV3,
    auxiliary_key: Option<[u8; AUXILIARY_KEY_BYTES]>,
    planned_batch: Option<[u8; 32]>,
    proof: Option<[u8; 64]>,
    source_commitment_v2: Option<[u8; 32]>,
    source_predecessor_next_v2: Option<u64>,
    current: bool,
    result: Option<Result<(), PendingErrorV1>>,
    complete: bool,
    terminal: terminal::TerminalReplayDataV4,
}

impl SourceDeletePendingReplayDataV1 {
    /// Creates vacant query-bound historical comparison slots without native effects.
    pub fn new(query: SourceDeleteCurrentQueryDataV1) -> Self {
        Self::new_for_purpose_v3(query, SourceDeleteCurrentPurposeDataV3::Planned)
    }

    /// Creates only historical comparison slots for an explicit finite wire phase.
    ///
    /// ControllerCommitted observes canonical Batch2 and native EOF only; the
    /// caller's complete Domain reader must separately validate its Operation join.
    pub fn new_for_purpose_v3(query: SourceDeleteCurrentQueryDataV1,
        purpose: SourceDeleteCurrentPurposeDataV3) -> Self {
        Self {
            query, purpose, auxiliary_key: None, planned_batch: None,
            proof: None,
            source_commitment_v2: None,
            source_predecessor_next_v2: None,
            current: false,
            result: None,
            complete: false,
            terminal: Default::default(),
        }
    }

    /// Prices the selected observer's actual transient decoder before its commit hook.
    ///
    /// # Errors
    /// Refuses checked decoder geometry overflow. Malformed framing allocates no graph.
    pub fn commit_observation_receiving_demand_v3(&self, commit: &CanonicalCommitReadViewV1<'_>)
        -> Result<aos_sandbox_model::ResourceVector, JournalError>
    {
        self.observation_receiving_demand_v3(commit.transaction().records().iter()
            .filter_map(|record| record.value().map(|value| (record.namespace(), record.key(), value))),
            Some(commit.transaction().id()))
    }

    /// Prices the selected observer's current-row comparison before its EOF hook.
    ///
    /// # Errors
    /// Refuses checked decoder geometry overflow. Framing selection itself allocates nothing.
    pub fn prefix_observation_receiving_demand_v3(&self, prefix: &CanonicalReplayPrefixReadViewV1<'_>)
        -> Result<aos_sandbox_model::ResourceVector, JournalError>
    {
        self.observation_receiving_demand_v3(prefix.state().iter()
            .map(|((namespace,key),value)| (*namespace,key.as_slice(),value.as_slice())), None)
    }

    fn observation_receiving_demand_v3<'a>(&self,
        rows: impl Iterator<Item=(RecordNamespace, &'a [u8], &'a [u8])>, transaction: Option<&[u8;16]>)
        -> Result<aos_sandbox_model::ResourceVector, JournalError>
    {
        use aos_sandbox_protocol::domain_ledger::records::borrowed::DurableMemberFrameDataV1;
        use aos_sandbox_protocol::domain_ledger::lifecycle_auxiliary::{
            LIFECYCLE_PROTECTED_DOMAIN_V1, LIFECYCLE_PROTECTED_MAXIMUM_PAYLOAD_BYTES_V1};
        let mut peak = aos_sandbox_model::ResourceVector::ZERO;
        if self.purpose == SourceDeleteCurrentPurposeDataV3::Planned { return Ok(peak); }
        for (namespace,key,value) in rows {
            if namespace != RecordNamespace::DesiredState
                || !key.starts_with(LIFECYCLE_PROTECTED_KEY_PREFIX_V1) { continue; }
            let Ok((5, _)) = borrow_protected_key_data_v1(key, LIFECYCLE_PROTECTED_KEY_PREFIX_V1) else { continue; };
            let Ok(member) = DurableMemberFrameDataV1::decode(value,
                LIFECYCLE_PROTECTED_MAXIMUM_PAYLOAD_BYTES_V1, LIFECYCLE_PROTECTED_DOMAIN_V1) else { continue; };
            let Ok(frame) = borrow_lifecycle_auxiliary_member_data_v1(key, value,
                transaction.unwrap_or(&member.transaction_id)) else { continue; };
            if frame.kind != 6 { continue; }
            let Some(bytes) = frame.payload.len().checked_sub(72) else { continue; };
            // Malformed extents are rejected by the decoder before graph allocation.
            if !DeleteBatchViewV1::encoded_length_is_bounded_v1(bytes) { continue; }
            let invalid = || JournalError::JournalTooLarge;
            let memory = DeleteBatchViewV1::decode_receiving_bytes_v1(bytes).ok_or_else(invalid)?
                .checked_add(2 * std::mem::size_of::<LifecycleDeleteBatchRecordViewDataV3<'_>>())
                .and_then(|size| size.checked_add(2 * std::mem::size_of::<
                    aos_sandbox_protocol::domain_ledger::lifecycle_auxiliary::LifecycleAuxiliaryFrameDataV1<'_>>()))
                .and_then(|size| size.checked_add(2 * std::mem::size_of::<DurableMemberFrameDataV1<'_>>()))
                .and_then(|size| size.checked_add(2 * std::mem::size_of::<
                    aos_sandbox_protocol::domain_ledger::records::borrowed::ProtectedEnvelopeFrameDataV1<'_>>()))
                .and_then(|size| size.checked_add(2 * std::mem::size_of::<
                    aos_sandbox_protocol::domain_ledger::records::borrowed::ReducerFrameDataV1<'_>>()))
                .ok_or_else(invalid)?;
            let names = DeleteBatchViewV1::nested_decode_metadata_entries_v1(bytes).ok_or_else(invalid)?;
            let demand = aos_sandbox_model::ResourceVector::ZERO
                .with(aos_sandbox_model::ResourceDimension::MemoryBytes, u64::try_from(memory).map_err(|_| invalid())?)
                .with(aos_sandbox_model::ResourceDimension::MetadataEntries, u64::try_from(names).map_err(|_| invalid())?);
            // The observer drops pure transient graph models at each row boundary.
            peak = peak.componentwise_max(demand);
        }
        Ok(peak)
    }

    /// Prices this phase's decoder from the actual audited historical row ceiling.
    ///
    /// The existing native audit includes replaced/deleted rows. The enclosing
    /// extent only bounds DATA representation; it supplies no admission.
    ///
    /// # Errors
    /// Refuses checked byte or actual map/set-name overflow.
    pub fn captured_observation_receiving_demand_v3(&self, enclosing_bytes: usize)
        -> Result<aos_sandbox_model::ResourceVector, JournalError>
    {
        use aos_sandbox_protocol::domain_ledger::{lifecycle_auxiliary::LifecycleAuxiliaryFrameDataV1,
            records::borrowed::{DurableMemberFrameDataV1, ProtectedEnvelopeFrameDataV1, ReducerFrameDataV1}};
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
        if self.purpose == SourceDeleteCurrentPurposeDataV3::Planned { return Ok(ResourceVector::ZERO); }
        let invalid = || JournalError::JournalTooLarge;
        let memory = DeleteBatchViewV1::nested_decode_receiving_bytes_v1(enclosing_bytes).ok_or_else(invalid)?
            .checked_add(2 * std::mem::size_of::<LifecycleDeleteBatchRecordViewDataV3<'_>>())
            .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<LifecycleAuxiliaryFrameDataV1<'_>>()))
            .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<DurableMemberFrameDataV1<'_>>()))
            .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<ProtectedEnvelopeFrameDataV1<'_>>()))
            .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<ReducerFrameDataV1<'_>>()))
            .ok_or_else(invalid)?;
        let names = DeleteBatchViewV1::nested_decode_metadata_entries_v1(enclosing_bytes).ok_or_else(invalid)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(memory).map_err(|_| invalid())?)
            .with(D::MetadataEntries, u64::try_from(names).map_err(|_| invalid())?))
    }

    /// Observes the actual current canonical COMMIT without applying or parsing another transaction.
    ///
    /// # Errors
    /// Rejects reentry, malformed canonical pending DATA, mismatched query or incomplete native EOF.
    pub fn observe_commit(
        &mut self,
        commit: CanonicalCommitReadViewV1<'_>,
    ) -> Result<(), JournalError> {
        self.observe_commit_borrowed(&commit)
    }

    fn observe_commit_borrowed(
        &mut self,
        commit: &CanonicalCommitReadViewV1<'_>,
    ) -> Result<(), JournalError> {
        if self.failure().is_some() || self.complete {
            return Err(JournalError::ProtectedBoundary);
        }
        // Advancing the sole cursor means the preceding complete native and
        // semantic COMMIT already finished. Only inert last-cut DATA changes.
        self.current = false;
        self.auxiliary_key = None;
        self.planned_batch = None;
        self.proof = None;
        self.source_commitment_v2 = None;
        self.source_predecessor_next_v2 = None;
        self.result = Some((|| {
            let transaction = commit.transaction();
            if self.purpose == SourceDeleteCurrentPurposeDataV3::Terminal4 {
                self.current = self.terminal.observe_commit_v4(self.query, commit)?;
                if self.current {
                    self.proof = Some(encode_native_commit_data_v1(*transaction.id(),
                        commit.commit_sequence(), commit.coordinates().offset,
                        commit.commit_digest_data_v4().map_err(JournalError::from_ordinary_native_v1)?)?);
                }
                return Ok(());
            }
            if self.purpose == SourceDeleteCurrentPurposeDataV3::ControllerCommitted {
                return self.observe_controller_committed_data_v3(commit);
            }
            let Some(pending) = transaction.records().last().filter(|record| {
                record.namespace() == RecordNamespace::SourceDomainPolicyHold
                    && record.key() == crate::source_policy_hold::DELETE_PENDING_KEY
            }) else {
                return Ok(());
            };
            let Some(bytes) = pending.value() else {
                return Ok(());
            };
            let batch = DeleteBatchViewV1::decode(bytes)?;
            if transaction.id() != &self.query.operation
                || batch.operation().as_bytes() != &self.query.operation
                || batch.project().as_bytes() != &self.query.project
                || source_delete_current_batch_digest_v1(bytes)? != self.query.batch
            {
                return Ok(());
            }
            self.proof = Some(encode_native_commit_data_v1(
                *transaction.id(),
                commit.commit_sequence(),
                commit.coordinates().offset,
                commit.commit_digest_data_v4().map_err(JournalError::from_ordinary_native_v1)?,
            )?);
            self.source_commitment_v2 = batch.named_commitments_v2().map(|cuts| cuts.source);
            self.source_predecessor_next_v2 = batch.source_predecessor_next_sequence_v2();
            self.current = true;
            Ok(())
        })());
        if self.failure().is_none() {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    fn observe_controller_committed_data_v3(&mut self, commit: &CanonicalCommitReadViewV1<'_>)
        -> Result<(), PendingErrorV1>
    {
        let transaction = commit.transaction();
        for record in transaction.records().iter().filter(|record|
            record.namespace() == RecordNamespace::DesiredState
                && record.key().starts_with(LIFECYCLE_PROTECTED_KEY_PREFIX_V1))
        {
            let (kind, _) = borrow_protected_key_data_v1(record.key(), LIFECYCLE_PROTECTED_KEY_PREFIX_V1)?;
            if kind != 5 { continue; }
            let Some(value) = record.value() else { continue; };
            let frame = borrow_lifecycle_auxiliary_member_data_v1(record.key(), value, transaction.id())?;
            if frame.format != LifecycleAuxiliaryEnvelopeFormatV1::DeleteBatch || frame.kind != 6
                || frame.project.as_bytes() != &self.query.project
                || frame.operation.as_bytes() != &self.query.operation
            { continue; }
            let payload = LifecycleDeleteBatchRecordViewDataV3::decode(frame.payload)?;
            if payload.state != 2
                || source_delete_controller_committed_batch_digest_v3(frame.payload)? != self.query.batch
            { continue; }
            if self.current { return Err(SourceDeleteCurrentDataErrorV1::Association.into()); }
            self.auxiliary_key = Some(record.key().try_into()
                .map_err(|_| SourceDeleteCurrentDataErrorV1::Association)?);
            self.planned_batch = Some(source_delete_current_batch_digest_v1(payload.batch.bytes())?);
            self.proof = Some(encode_native_commit_data_v1(*transaction.id(),
                commit.commit_sequence(), commit.coordinates().offset,
                commit.commit_digest_data_v4().map_err(JournalError::from_ordinary_native_v1)?)?);
            self.current = true;
        }
        Ok(())
    }

    /// Checks that the last matching COMMIT is the exact captured EOF and current pending state.
    ///
    /// # Errors
    /// Rejects reentry, malformed canonical pending DATA, mismatched query or incomplete native EOF.
    pub fn finish_prefix(
        &mut self,
        prefix: CanonicalReplayPrefixReadViewV1<'_>,
        captured_end: u64,
    ) -> Result<(), JournalError> {
        if self.failure().is_some() || self.complete {
            return Err(JournalError::ProtectedBoundary);
        }
        self.result = Some((|| {
            let proof = self
                .proof
                .as_ref()
                .filter(|_| self.current)
                .ok_or(SourceDeleteCurrentDataErrorV1::Native)?;
            let sequence = u64::from_be_bytes(
                proof[48..56]
                    .try_into()
                    .map_err(|_| SourceDeleteCurrentDataErrorV1::Native)?,
            );
            let end = u64::from_be_bytes(
                proof[56..64]
                    .try_into()
                    .map_err(|_| SourceDeleteCurrentDataErrorV1::Native)?,
            );
            let actual = prefix.coordinates();
            if sequence.checked_add(1) != Some(actual.durable_next_sequence)
                || end != actual.durable_end
                || end != actual.offset
                || end != captured_end
            {
                return Err(SourceDeleteCurrentDataErrorV1::Native.into());
            }
            let state = prefix.state();
            if self.purpose == SourceDeleteCurrentPurposeDataV3::Terminal4 {
                return self.terminal.finish_prefix_v4(self.query, state);
            }
            let hold = crate::source_policy_hold::current_state(state)?;
            let bytes = state
                .get(&(
                    RecordNamespace::SourceDomainPolicyHold,
                    crate::source_policy_hold::DELETE_PENDING_KEY.to_vec(),
                ))
                .ok_or(SourceDeleteCurrentDataErrorV1::Association)?;
            if hold.delete_pending.is_none()
                || hold.q04_pending.is_some()
                || hold.v8_pending.is_some()
                || hold.hold.is_some_and(|hold| hold.is_held())
                || source_delete_current_batch_digest_v1(bytes)? != match self.purpose {
                    SourceDeleteCurrentPurposeDataV3::Planned => self.query.batch,
                    SourceDeleteCurrentPurposeDataV3::ControllerCommitted => self.planned_batch
                        .ok_or(SourceDeleteCurrentDataErrorV1::Association)?,
                    SourceDeleteCurrentPurposeDataV3::Terminal4 => return Err(SourceDeleteCurrentDataErrorV1::Association.into()),
                }
            {
                return Err(SourceDeleteCurrentDataErrorV1::Association.into());
            }
            if self.purpose == SourceDeleteCurrentPurposeDataV3::ControllerCommitted {
                let key = self.auxiliary_key.as_ref().ok_or(SourceDeleteCurrentDataErrorV1::Association)?;
                let value = state.get(&(RecordNamespace::DesiredState, key.to_vec()))
                    .ok_or(SourceDeleteCurrentDataErrorV1::Association)?;
                let transaction: [u8; 16] = proof[..16].try_into()
                    .map_err(|_| SourceDeleteCurrentDataErrorV1::Native)?;
                let frame = borrow_lifecycle_auxiliary_member_data_v1(key, value, &transaction)?;
                if source_delete_controller_committed_batch_digest_v3(frame.payload)? != self.query.batch {
                    return Err(SourceDeleteCurrentDataErrorV1::Association.into());
                }
            }
            Ok(())
        })());
        self.complete = matches!(self.result, Some(Ok(())));
        if self.complete {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    /// Borrows the completed query-bound native64 comparison as historical DATA.
    ///
    /// # Errors
    /// Rejects reentry, malformed canonical pending DATA, mismatched query or incomplete native EOF.
    pub fn proof(
        &self,
        query: SourceDeleteCurrentQueryDataV1,
    ) -> Result<[u8; 64], SourceDeleteCurrentDataErrorV1> {
        self.proof_for_purpose_v3(query, SourceDeleteCurrentPurposeDataV3::Planned)
    }

    /// Borrows the exact completed phase/query/native-EOF comparison as DATA.
    ///
    /// # Errors
    /// Refuses an incomplete observation, earlier failure or different phase/query.
    pub fn proof_for_purpose_v3(&self, query: SourceDeleteCurrentQueryDataV1,
        purpose: SourceDeleteCurrentPurposeDataV3) -> Result<[u8; 64], SourceDeleteCurrentDataErrorV1>
    {
        if !self.complete || self.failure().is_some() || self.query != query || self.purpose != purpose {
            return Err(SourceDeleteCurrentDataErrorV1::Native);
        }
        self.proof.ok_or(SourceDeleteCurrentDataErrorV1::Native)
    }

    /// Borrows the historical Batch2 COMMIT separately from terminal native EOF.
    ///
    /// # Errors
    /// Refuses an incomplete Terminal4 observation, changed query or missing Batch2.
    pub fn historical_controller_committed_native_data_v4(&self,
        query: SourceDeleteCurrentQueryDataV1) -> Result<[u8; 64], SourceDeleteCurrentDataErrorV1>
    {
        self.proof_for_purpose_v3(query, SourceDeleteCurrentPurposeDataV3::Terminal4)?;
        self.terminal.historical_batch_native_v4()
    }

    fn matched_current_native_v1(&self) -> Option<[u8; 64]> {
        if self.current && self.failure().is_none() {
            self.proof
        } else {
            None
        }
    }

    /// Borrows the retained original first comparison error without another observation.
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.result.as_ref()?.as_ref().err().map(|cause| cause as _)
    }
}

#[cfg(test)]
mod tests;

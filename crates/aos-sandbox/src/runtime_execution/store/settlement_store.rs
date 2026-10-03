//! Protected Host journal writes for the failed-Create lease coordinates.
//!
//! ```text
//! 'l' | execution:16 | stage:u8 => AOSCHL01
//! ```
//!
//! This store proves only that each stage is durable and follows the preceding
//! Host stage. It does not verify Controller signatures or grant a live lease;
//! the cross-owner caller must retain those checks while the owner lock is held.

use super::*;
use crate::journal::host_execution_fence::{KEY as HOST_FENCE_KEY, effect_cut_v1};

impl JournalRuntimeExecutionStoreV1<'_> {
    /// Runs one bounded action while the protected Host writer remains held.
    ///
    /// The action sees the exact Effect cut measured before it runs. A changed
    /// sequence or digest suppresses its result, even if the action succeeded.
    /// This local scope does not hold the Controller writer and cannot turn a
    /// signed response into a two-owner settlement barrier. A rejected result
    /// does not undo an action's effects; the caller must resolve ambiguity by
    /// cold protected readback rather than retrying with a new challenge.
    pub(crate) fn with_held_host_settlement_cut_v1<T>(
        &mut self,
        action: impl FnOnce(&mut Self, (u64, ObjectDigest)) -> Result<T, JournalRuntimeExecutionError>,
    ) -> Result<T, JournalRuntimeExecutionError> {
        let before = self.protected_host_settlement_cut_v1()?;
        let result = action(self, before);
        let after = self.protected_host_settlement_cut_v1()?;

        if before != after {
            return Err(JournalRuntimeExecutionError::RecordConflict);
        }
        result
    }

    /// Hashes the exact protected Effect replay and sequence under the writer claim.
    ///
    /// Authority records iterate in bytewise key order. Fixed-width scope and
    /// sequence fields precede length-framed key/value pairs and a final count;
    /// the held snapshot is checked again after iteration. This excludes other
    /// namespaces, tombstones, pre-compaction frames, HostState, and physical
    /// file names. It is not a full journal root or proof that a copied cut is
    /// still current after the claim is lost.
    pub(crate) fn protected_host_settlement_cut_v1(
        &self,
    ) -> Result<(u64, ObjectDigest), JournalRuntimeExecutionError> {
        let sequence = self.authority.snapshot()?.sequence();
        let cut = host_settlement_cut_from_authority_v1(
            &self.authority,
            self.store_binding,
            sequence,
            false,
        )?;
        Ok((sequence, cut))
    }

    /// Acquires a permanent, nonauthorizing Effect writer quarantine.
    ///
    /// The preliminary record and marker have already been validated by the
    /// owner. This method rechecks their exact protected bytes and the full
    /// pre-fence Effect cut before the only permitted fence append.
    #[allow(dead_code, reason = "cross-owner continuation remains closed")]
    pub(crate) fn acquire_host_execution_fence_v1(
        &mut self,
        preliminary: HostSettlementRecordV1,
        expected_epoch: u64,
        expected_cut: ObjectDigest,
    ) -> Result<HostExecutionFenceV1, JournalRuntimeExecutionError> {
        if preliminary.stage != HostSettlementStageV1::Preliminary
            || self.protected_host_settlement_cut_v1()? != (expected_epoch, expected_cut)
            || self.load_host_settlement_history_v1(preliminary.execution)?
                != [Some(preliminary), None, None]
            || self.authority.get(HOST_FENCE_KEY)?.is_some()
        {
            return Err(JournalRuntimeExecutionError::RecordConflict);
        }

        let fence = HostExecutionFenceV1 {
            store_binding: self.store_binding,
            execution: preliminary.execution,
            preliminary_digest: preliminary.digest(),
            pre_fence_epoch: expected_epoch,
            pre_fence_cut: expected_cut,
            commit_sequence: predicted_commit_sequence(expected_epoch, 1)?,
        };
        let bytes = fence.encode()?;
        let transaction = JournalTransaction::new(
            transaction_id(
                b"host-execution-fence",
                ObjectDigest::from_bytes(Sha256::digest(bytes).into()),
            ),
            vec![JournalRecord::put(
                RecordNamespace::Effect,
                HOST_FENCE_KEY.to_vec(),
                bytes.to_vec(),
            )],
        )?;

        // An append error is outcome-unknown; never retry under the old cut.
        let committed = self
            .authority
            .acquire_host_execution_fence_v1(fence, &transaction)
            .map_err(|_| JournalRuntimeExecutionError::SettlementOutcomeUnknown)?;
        if committed.commit_sequence != fence.commit_sequence
            || self
                .authority
                .get(HOST_FENCE_KEY)
                .map_err(|_| JournalRuntimeExecutionError::SettlementOutcomeUnknown)?
                != Some(bytes.as_slice())
        {
            return Err(JournalRuntimeExecutionError::SettlementOutcomeUnknown);
        }
        Ok(fence)
    }

    /// Returns a held fence only after checking its canonical protected bytes.
    #[allow(dead_code, reason = "cross-owner recovery remains closed")]
    pub(crate) fn load_host_execution_fence_v1(
        &self,
    ) -> Result<Option<HostExecutionFenceV1>, JournalRuntimeExecutionError> {
        self.authority
            .get(HOST_FENCE_KEY)?
            .map(|bytes| HostExecutionFenceV1::decode(bytes).map_err(Into::into))
            .transpose()
    }
}

/// Recomputes the same canonical Effect cut, excluding only the fence row when
/// validating the pre-acquisition coordinate on a cold replay.
pub(super) fn host_settlement_cut_from_authority_v1(
    authority: &ProtectedJournalAuthority<'_>,
    store_binding: ObjectDigest,
    sequence: u64,
    exclude_fence: bool,
) -> Result<ObjectDigest, JournalRuntimeExecutionError> {
    let snapshot = authority.snapshot()?;
    let cut = effect_cut_v1(authority.records()?, store_binding, sequence, exclude_fence)?;
    authority.validate_snapshot_for_effect(&snapshot)?;
    Ok(cut)
}

impl JournalRuntimeExecutionStoreV1<'_> {
    /// Predicts the one-record settlement append from the exact measured cut.
    pub(crate) fn next_host_settlement_sequence_v1(
        &self,
        expected_epoch: u64,
    ) -> Result<u64, JournalRuntimeExecutionError> {
        let snapshot = self.authority.snapshot()?;
        if snapshot.sequence() != expected_epoch {
            return Err(JournalRuntimeExecutionError::RecordConflict);
        }
        Ok(predicted_commit_sequence(expected_epoch, 1)?)
    }

    /// Checks for a forbidden orphan stage when no method-39 marker was found.
    pub(crate) fn has_host_settlement_stages_v1(
        &self,
        execution: ExecutionId,
    ) -> Result<bool, JournalRuntimeExecutionError> {
        for stage in [
            HostSettlementStageV1::Preliminary,
            HostSettlementStageV1::FloorSealed,
            HostSettlementStageV1::AckRetained,
        ] {
            if self.authority.get(&lease_key(execution, stage))?.is_some() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Loads and structurally rejoins all durable stages for one Host marker.
    ///
    /// An incomplete history is returned as-is. It never recreates a held
    /// cross-owner lease or turns a historical Controller claim into authority.
    pub(crate) fn load_host_settlement_history_v1(
        &self,
        execution: ExecutionId,
    ) -> Result<[Option<HostSettlementRecordV1>; 3], JournalRuntimeExecutionError> {
        let marker = self
            .load_host_no_apply_v1(execution)?
            .ok_or(JournalRuntimeExecutionError::MissingRecord)?;
        let mut stages = [None; 3];

        for (index, stage) in [
            HostSettlementStageV1::Preliminary,
            HostSettlementStageV1::FloorSealed,
            HostSettlementStageV1::AckRetained,
        ]
        .into_iter()
        .enumerate()
        {
            let key = lease_key(execution, stage);
            if let Some(bytes) = self.authority.get(&key)? {
                let record = HostSettlementRecordV1::decode_canonical(bytes)
                    .map_err(|_| JournalRuntimeExecutionError::CorruptRecord)?;
                if record.execution != execution || record.stage != stage {
                    return Err(JournalRuntimeExecutionError::CorruptRecord);
                }
                stages[index] = Some(record);
            }
        }

        validate_host_settlement_history(
            marker,
            stages[0],
            stages[1],
            stages[2],
            self.authority.snapshot()?.sequence(),
        )
        .map_err(|_| JournalRuntimeExecutionError::CorruptRecord)?;
        Ok(stages)
    }

    /// Appends a preliminary stage only from the unchanged protected Host cut.
    ///
    /// The archive digests in the record remain Controller assertions. This
    /// gate prevents a prepared stage from being committed after another Host
    /// effect or a competing settlement append advanced the writer sequence.
    pub(crate) fn commit_host_settlement_preliminary_v1(
        &mut self,
        record: HostSettlementRecordV1,
        expected_epoch: u64,
        expected_cut: ObjectDigest,
    ) -> Result<HostSettlementRecordV1, JournalRuntimeExecutionError> {
        if record.stage != HostSettlementStageV1::Preliminary
            || record.epoch != expected_epoch
            || record.pre_lease_cut != expected_cut
            || self.protected_host_settlement_cut_v1()? != (expected_epoch, expected_cut)
            || self.next_host_settlement_sequence_v1(expected_epoch)? != record.commit_sequence
            || self
                .load_host_settlement_history_v1(record.execution)?
                .iter()
                .any(Option::is_some)
        {
            return Err(JournalRuntimeExecutionError::RecordConflict);
        }

        self.append_host_settlement_stage_v1(record)
    }

    /// Appends exactly the next Host settlement stage under protected custody.
    ///
    /// This is a structural journal primitive, not a Controller-currentness
    /// verifier. The caller must establish the signed, held cross-owner claim
    /// before constructing `record`; merely loading this history is not enough.
    #[allow(dead_code, reason = "signed cross-owner lease bridge remains closed")]
    pub(crate) fn append_host_settlement_stage_v1(
        &mut self,
        record: HostSettlementRecordV1,
    ) -> Result<HostSettlementRecordV1, JournalRuntimeExecutionError> {
        let marker = self
            .load_host_no_apply_v1(record.execution)?
            .ok_or(JournalRuntimeExecutionError::MissingRecord)?;
        let mut stages = self.load_host_settlement_history_v1(record.execution)?;
        let index = match record.stage {
            HostSettlementStageV1::Preliminary => 0,
            HostSettlementStageV1::FloorSealed => 1,
            HostSettlementStageV1::AckRetained => 2,
        };
        if let Some(existing) = stages[index] {
            return if existing == record {
                Ok(existing)
            } else {
                Err(JournalRuntimeExecutionError::RecordConflict)
            };
        }

        let sequence = predicted_commit_sequence(self.authority.snapshot()?.sequence(), 1)?;
        if record.commit_sequence != sequence {
            return Err(JournalRuntimeExecutionError::RecordConflict);
        }
        stages[index] = Some(record);
        validate_host_settlement_history(marker, stages[0], stages[1], stages[2], sequence)
            .map_err(|_| JournalRuntimeExecutionError::RecordConflict)?;

        let key = lease_key(record.execution, record.stage);
        let bytes = record.encode_canonical();
        let transaction = JournalTransaction::new(
            transaction_id(b"host-create-failure-settlement", record.digest()),
            vec![JournalRecord::put(
                RecordNamespace::Effect,
                key.clone(),
                bytes.to_vec(),
            )],
        )?;
        let preflight = self
            .authority
            .preflight_transactions(std::slice::from_ref(&transaction))?;
        self.authority
            .validate_preflight_for_effect(&preflight, std::slice::from_ref(&transaction))?;

        // An append error is outcome-unknown. Reopening the protected journal
        // can classify the record, but cannot reconstitute the caller's lease.
        let committed = self
            .authority
            .commit(&transaction)
            .map_err(|_| JournalRuntimeExecutionError::SettlementOutcomeUnknown)?;
        if committed.commit_sequence != sequence
            || self
                .authority
                .get(&key)
                .map_err(|_| JournalRuntimeExecutionError::SettlementOutcomeUnknown)?
                != Some(bytes.as_slice())
        {
            return Err(JournalRuntimeExecutionError::SettlementOutcomeUnknown);
        }
        Ok(record)
    }
}

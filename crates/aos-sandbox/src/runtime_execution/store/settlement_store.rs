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

const HOST_SETTLEMENT_CUT_DOMAIN: &[u8] = b"aos.sandbox.host-settlement-protected-cut.v1\0";

impl JournalRuntimeExecutionStoreV1<'_> {
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
        let snapshot = self.authority.snapshot()?;
        let mut hash = Sha256::new()
            .chain_update(HOST_SETTLEMENT_CUT_DOMAIN)
            .chain_update([RecordNamespace::Effect as u8])
            .chain_update(self.store_binding.as_bytes())
            .chain_update(snapshot.sequence().to_be_bytes());
        let mut count = 0_u64;

        for (key, value) in self.authority.records()? {
            let key_len = u64::try_from(key.len())
                .map_err(|_| JournalRuntimeExecutionError::CorruptRecord)?;
            let value_len = u64::try_from(value.len())
                .map_err(|_| JournalRuntimeExecutionError::CorruptRecord)?;
            hash.update(key_len.to_be_bytes());
            hash.update(key);
            hash.update(value_len.to_be_bytes());
            hash.update(value);
            count = count
                .checked_add(1)
                .ok_or(JournalRuntimeExecutionError::CorruptRecord)?;
        }
        hash.update(count.to_be_bytes());
        self.authority.validate_snapshot_for_effect(&snapshot)?;

        Ok((
            snapshot.sequence(),
            ObjectDigest::from_bytes(hash.finalize().into()),
        ))
    }

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

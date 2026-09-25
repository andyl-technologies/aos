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

impl JournalRuntimeExecutionStoreV1<'_> {
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

//! Closes future Apply under the same actual Host execution-journal claim.
//!
//! An authenticated native Host caller must bind the accepted-Create source
//! and signed terminal request before entering this private writer. This code
//! observes the actual one-shot sets and protected admission/effect records;
//! absence is never inferred from packet DATA or a historical no-Apply reply.

use super::*;

/// Carries coordinates already checked by the actual current Host claim.
pub(in crate::runtime_execution) struct HostBeforeArgumentNoApplyIdentityV2 {
    pub(in crate::runtime_execution) source: BeforeArgumentNoApplySourceDataV2,
    pub(in crate::runtime_execution) terminal_request: [u8; 16],
    pub(in crate::runtime_execution) terminal_session: [u8; 32],
    pub(in crate::runtime_execution) signed_terminal_request: [u8; 32],
    pub(in crate::runtime_execution) runtime_handle: ObjectDigest,
}

impl JournalRuntimeExecutionStoreV1<'_> {
    pub(crate) fn has_host_no_apply_v2(
        &self,
        execution: ExecutionId,
    ) -> Result<bool, JournalRuntimeExecutionError> {
        let Some(bytes) = self.authority.get(&no_apply_key(execution))? else {
            return Ok(false);
        };
        match HostExecutionNoApplyRecordV2::decode_canonical(bytes)
            .map_err(|_| JournalRuntimeExecutionError::CorruptRecord)?
        {
            HostExecutionNoApplyRecordV2::AfterArgument(record) => {
                let fields = record.fields();
                if fields.execution_id != *execution.as_bytes()
                    || fields.execution_store_binding != *self.store_binding.as_bytes()
                {
                    return Err(JournalRuntimeExecutionError::CorruptRecord);
                }
            }
            HostExecutionNoApplyRecordV2::ClosedV2BeforeArgument(record) => {
                let fields = record.fields();
                if fields.source.fields().execution != *execution.as_bytes()
                    || fields.execution_store != *self.store_binding.as_bytes()
                {
                    return Err(JournalRuntimeExecutionError::CorruptRecord);
                }
            }
        }
        Ok(true)
    }

    pub(crate) fn load_before_argument_no_apply_v2(
        &self,
        execution: ExecutionId,
    ) -> Result<Option<ClosedBeforeArgumentNoApplyRecordV2>, JournalRuntimeExecutionError> {
        let Some(bytes) = self.authority.get(&no_apply_key(execution))? else {
            return Ok(None);
        };
        let record = match HostExecutionNoApplyRecordV2::decode_canonical(bytes)
            .map_err(|_| JournalRuntimeExecutionError::CorruptRecord)?
        {
            HostExecutionNoApplyRecordV2::ClosedV2BeforeArgument(record) => record,
            HostExecutionNoApplyRecordV2::AfterArgument(_) => {
                return Err(JournalRuntimeExecutionError::RecordConflict);
            }
        };
        let fields = record.fields();
        if fields.source.fields().execution != *execution.as_bytes()
            || fields.execution_store != *self.store_binding.as_bytes()
        {
            return Err(JournalRuntimeExecutionError::CorruptRecord);
        }
        Ok(Some(record))
    }

    fn require_before_argument_no_dispatch_v2(
        &self,
        source: BeforeArgumentNoApplySourceDataV2,
    ) -> Result<(), JournalRuntimeExecutionError> {
        let source = source.fields();
        let execution = ExecutionId::from_bytes(source.execution);
        if self.load_admission(execution)?.is_some()
            || self.authority.get(&terminal_key(execution))?.is_some()
        {
            return Err(JournalRuntimeExecutionError::RecordConflict);
        }

        for (key, value) in self.authority.records()? {
            if key.first() == Some(&EFFECT_KEY_PREFIX) && key.len() == 17 {
                let effect = decode_durable_execution_effect_v1(value)
                    .map_err(|_| JournalRuntimeExecutionError::CorruptRecord)?;
                if effect.admission().execution() == execution {
                    return Err(JournalRuntimeExecutionError::RecordConflict);
                }
            }
        }
        // These are the SAME live one-shot sets used by prepare_dispatch.
        // A missing referenced effect is uncertainty, never proof of absence.
        for operation in self
            .freshly_issued
            .iter()
            .chain(self.live_dispatches.iter())
        {
            let effect = self
                .load_effect(operation)?
                .ok_or(JournalRuntimeExecutionError::CorruptRecord)?;
            if effect.admission().execution() == execution {
                return Err(JournalRuntimeExecutionError::RecordConflict);
            }
        }
        if let Some(bytes) = self.authority.get(&host_output_key(execution))? {
            let correlation = HostOutputCorrelationV1::decode(bytes)
                .ok_or(JournalRuntimeExecutionError::CorruptRecord)?;
            if correlation.create_operation.as_bytes() != &source.create_operation
                || correlation.assignment_digest.as_bytes() != &source.assignment_digest
                || correlation.host_boot_id != source.host_boot
            {
                return Err(JournalRuntimeExecutionError::RecordConflict);
            }
        }
        Ok(())
    }

    pub(crate) fn commit_before_argument_no_apply_v2(
        &mut self,
        identity: &HostBeforeArgumentNoApplyIdentityV2,
    ) -> Result<ClosedBeforeArgumentNoApplyRecordV2, JournalRuntimeExecutionError> {
        self.require_before_argument_no_dispatch_v2(identity.source)?;
        let source = identity.source.fields();
        let execution = ExecutionId::from_bytes(source.execution);
        if let Some(record) = self.load_before_argument_no_apply_v2(execution)? {
            let fields = record.fields();
            return if fields.source == identity.source
                && fields.terminal_request == identity.terminal_request
                && fields.terminal_session == identity.terminal_session
                && fields.signed_terminal_request == identity.signed_terminal_request
                && fields.runtime_handle == *identity.runtime_handle.as_bytes()
            {
                Ok(record)
            } else {
                Err(JournalRuntimeExecutionError::RecordConflict)
            };
        }

        let snapshot = self.authority.snapshot()?;
        let (epoch, cut) = self.protected_host_settlement_cut_v1()?;
        if epoch != snapshot.sequence() {
            return Err(JournalRuntimeExecutionError::RecordConflict);
        }
        let sequence = predicted_commit_sequence(epoch, 1)?;
        let record =
            ClosedBeforeArgumentNoApplyRecordV2::new(ClosedBeforeArgumentNoApplyRecordFieldsV2 {
                source: identity.source,
                terminal_request: identity.terminal_request,
                terminal_session: identity.terminal_session,
                signed_terminal_request: identity.signed_terminal_request,
                runtime_handle: *identity.runtime_handle.as_bytes(),
                execution_store: *self.store_binding.as_bytes(),
                observed_preclose_cut: *cut.as_bytes(),
                observed_epoch: epoch,
                commit_sequence: sequence,
            })
            .map_err(|_| JournalRuntimeExecutionError::RecordConflict)?;
        let bytes = record.encode_canonical();
        let key = no_apply_key(execution);
        let digest = ObjectDigest::from_bytes(Sha256::digest(bytes).into());
        let transaction = JournalTransaction::new(
            transaction_id(b"host-before-argument-no-apply-v2", digest),
            vec![JournalRecord::put(
                RecordNamespace::Effect,
                key.clone(),
                bytes.to_vec(),
            )],
        )?;
        let preflight = self
            .authority
            .preflight_transactions(std::slice::from_ref(&transaction))?;
        self.require_before_argument_no_dispatch_v2(identity.source)?;
        self.authority.validate_snapshot_for_effect(&snapshot)?;
        self.authority
            .validate_preflight_for_effect(&preflight, std::slice::from_ref(&transaction))?;

        // This key is inspected by the existing admission/issue guards. Once
        // appended, the same Create can never acquire future Apply custody.
        let committed = self
            .authority
            .commit(&transaction)
            .map_err(|_| JournalRuntimeExecutionError::NoApplyOutcomeUnknown)?;
        if committed.commit_sequence != sequence
            || self
                .authority
                .get(&key)
                .map_err(|_| JournalRuntimeExecutionError::NoApplyOutcomeUnknown)?
                != Some(bytes.as_slice())
        {
            return Err(JournalRuntimeExecutionError::NoApplyOutcomeUnknown);
        }
        Ok(record)
    }
}

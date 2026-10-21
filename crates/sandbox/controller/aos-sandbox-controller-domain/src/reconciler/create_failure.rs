//! Closed Controller receipt for an exact Create failed-before-commit settlement.
//!
//! ```text
//! AOSCFB01 | version:u16be | reserved:2 | H-head:32 | signed-outcome:32 |
//! current-Host-cut:32 | AOSHNA01:384 | predecessor-revision:32 |
//! successor-revision:32 | successor-operation:32 | predecessor-sequence:u64be |
//! effect-attempt:u32be | wall-seconds:i64be |
//! SHA256(domain || preceding):32
//! ```
//!
//! ```text
//! AOSCFA01 | version:u16be | reserved:2 | Create-operation:16 |
//! Host-preliminary-head:32 | Controller-floor:32 | Controller-CAS:32 |
//! SHA256(domain || preceding):32
//! ```
//!
//! The receipt is a local transaction witness, not Host authorization. There
//! is deliberately no production constructor for its proof input until a
//! current signed 39/40 readback and anti-rollback cut can be supplied.

mod prepare;
mod observation;
pub(crate) use observation::{closed_create_failure_receiving_demand_from_observation_v2,
    plan_closed_create_failure_rows_from_observation_v2,
    validate_failed_create_operation_from_observation_v2};
use aos_sandbox_protocol::domain_ledger::create_failure::ClosedCreateFailurePlanDataV2;
use aos_sandbox_protocol::domain_ledger::create_failure::{CreateFailurePlanIdentityV2,
    AfterArgumentCreateFailureIdentityDataV1, PlannedCreateFailureV1};
pub(super) use aos_sandbox_protocol::domain_ledger::create_failure::has_special_receipt_data_v2;

use aos_sandbox_model::{ObjectDigest, OperationId};
use aos_sandbox_protocol::host_execution_no_apply::closed_controller::{
    CLOSED_CREATE_FAILURE_PREPARE_MAGIC_V2, ClosedCreateFailurePrepareDataV2,
};
use aos_sandbox_protocol::host_execution_no_apply::{
    HostExecutionNoApplyRecordV1,
    validate_controller_create_failure_ack_envelope_v1,
};
use sha2::{Digest as _, Sha256};

use crate::journal::{Journal, JournalRecord, RecordNamespace};
use crate::runtime_execution::no_apply_settlement::HostSettlementRecordV1;

use prepare::{CreateFailurePrepareV1, load_floor};

use super::{
    OperationRecord, OperationState, Reconciler, ReconcilerError, SingleNodeEffectExecutor,

};


const ACK_MAGIC: &[u8; 8] = b"AOSCFA01";
const ACK_DOMAIN: &[u8] = b"aos.sandbox.create-failure-settlement-ack.v1\0";
const ACK_VERSION: u16 = 1;
const ACK_BYTES: usize = 8 + 2 + 2 + 16 + 32 * 3 + 32;

/// Carries a joined H archive, signed Host outcome, and current Host cut.
///
/// Its fields cannot be constructed by production code until those three
/// owners have a typed currentness bridge. Merely decoding a Host marker is
/// intentionally insufficient.
#[allow(
    dead_code,
    reason = "production Host currentness bridge remains closed"
)]
#[derive(Clone, Copy)]
pub(crate) struct CreateFailureSettlementProofV1 {
    marker: HostExecutionNoApplyRecordV1,
    archive_head: ObjectDigest,
    signed_outcome: ObjectDigest,
    current_host_cut: ObjectDigest,
    host_lease_epoch: u64,
    host_lease_head: ObjectDigest,
}

impl CreateFailureSettlementProofV1 {
    #[cfg(test)]
    pub(super) fn into_receipt(
        self,
        predecessor_revision: ObjectDigest,
        successor_revision: ObjectDigest,
        successor_operation: ObjectDigest,
        predecessor_sequence: u64,
        effect_attempt: u32,
        wall_seconds: i64,
    ) -> aos_sandbox_protocol::domain_ledger::create_failure::CreateFailureReceiptV1 {
        aos_sandbox_protocol::domain_ledger::create_failure::CreateFailureReceiptV1 {
            marker: self.marker,
            archive_head: self.archive_head,
            signed_outcome: self.signed_outcome,
            current_host_cut: self.current_host_cut,
            predecessor_revision,
            successor_revision,
            successor_operation,
            predecessor_sequence,
            effect_attempt,
            wall_seconds,
        }
    }

    pub(super) const fn marker(&self) -> HostExecutionNoApplyRecordV1 {
        self.marker
    }

    #[cfg(test)]
    pub(super) fn test_only(marker: HostExecutionNoApplyRecordV1) -> Self {
        Self {
            marker,
            archive_head: ObjectDigest::from_bytes([0xa1; 32]),
            signed_outcome: ObjectDigest::from_bytes([0xa2; 32]),
            current_host_cut: ObjectDigest::from_bytes([0xa3; 32]),
            host_lease_epoch: 1,
            host_lease_head: ObjectDigest::from_bytes([0xa4; 32]),
        }
    }

    #[cfg(test)]
    pub(super) fn with_test_lease(mut self, head: ObjectDigest) -> Self {
        self.host_lease_head = head;
        self
    }

    #[cfg(test)]
    pub(super) fn with_test_lease_epoch(mut self, epoch: u64) -> Self {
        self.host_lease_epoch = epoch;
        self
    }
}

/// Retains a fresh held-Host proof only across one Controller prepare-to-CAS.
///
/// Cold replay of the durable floor never recreates this token. A future Host
/// bridge must reacquire the matching live lease before retrying preparation.
#[allow(dead_code, reason = "production Host lease bridge remains closed")]
pub(crate) struct PreparedCreateFailureSettlementV1 {
    operation_id: OperationId,
    proof: CreateFailureSettlementProofV1,
    floor: CreateFailurePrepareV1,
    wall_seconds: i64,
}

/// Names the exact durable Controller settlement for a later signed Host ACK.
///
/// This is a local CAS witness, not an authenticated Host message or permission
/// to retire H custody. It is minted only after the protected successor bytes
/// have been read back against the prepare floor.
#[allow(dead_code, reason = "signed cross-owner ACK transport remains closed")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ControllerCreateFailureSettlementAckV1 {
    pub(crate) operation_id: OperationId,
    pub(crate) host_lease_head: ObjectDigest,
    pub(crate) controller_floor: ObjectDigest,
    pub(crate) controller_cas: ObjectDigest,
}

impl ControllerCreateFailureSettlementAckV1 {
    fn from_floor(floor: CreateFailurePrepareV1) -> Self {
        Self {
            operation_id: floor.operation_id,
            host_lease_head: floor.host_lease_head,
            controller_floor: floor.digest(),
            controller_cas: floor.settled_cas_digest(),
        }
    }

    /// Encodes the exact Controller settlement for authenticated transport.
    ///
    /// The checksum detects noncanonical bytes; it is not a signature. Only
    /// the broker session's signed outcome can carry this across owners.
    pub(crate) fn encode_canonical(self) -> [u8; ACK_BYTES] {
        let mut bytes = [0; ACK_BYTES];
        bytes[..8].copy_from_slice(ACK_MAGIC);
        bytes[8..10].copy_from_slice(&ACK_VERSION.to_be_bytes());
        bytes[12..28].copy_from_slice(self.operation_id.as_bytes());
        bytes[28..60].copy_from_slice(self.host_lease_head.as_bytes());
        bytes[60..92].copy_from_slice(self.controller_floor.as_bytes());
        bytes[92..124].copy_from_slice(self.controller_cas.as_bytes());
        let checksum = Sha256::new()
            .chain_update(ACK_DOMAIN)
            .chain_update(&bytes[..ACK_BYTES - 32])
            .finalize();
        bytes[ACK_BYTES - 32..].copy_from_slice(&checksum);
        bytes
    }

    /// Decodes an exact ACK without claiming its signer or currentness.
    pub(crate) fn decode_canonical(bytes: &[u8]) -> Result<Self, ReconcilerError> {
        validate_controller_create_failure_ack_envelope_v1(bytes)
            .map_err(|_| invalid_settlement())?;
        let operation_id =
            OperationId::from_bytes(bytes[12..28].try_into().map_err(|_| invalid_settlement())?);
        let digest = |start: usize| -> Result<ObjectDigest, ReconcilerError> {
            let value: [u8; 32] = bytes[start..start + 32]
                .try_into()
                .map_err(|_| invalid_settlement())?;
            if value == [0; 32] {
                return Err(invalid_settlement());
            }
            Ok(ObjectDigest::from_bytes(value))
        };
        Ok(Self {
            operation_id,
            host_lease_head: digest(28)?,
            controller_floor: digest(60)?,
            controller_cas: digest(92)?,
        })
    }

    /// Checks a retained Host ACK against the Controller's durable CAS.
    ///
    /// The caller must supply a protected Host journal observation. This
    /// structural join does not turn that observation into a live lease.
    #[allow(dead_code, reason = "signed cross-owner ACK transport remains closed")]
    pub(crate) fn validate_host_retention(
        self,
        journal: &Journal,
        preliminary: HostSettlementRecordV1,
        sealed: HostSettlementRecordV1,
        retained: HostSettlementRecordV1,
        protected_host_sequence: u64,
    ) -> Result<(), ReconcilerError> {
        let floor = load_floor(journal, self.operation_id)?.ok_or_else(invalid_settlement)?;
        prepare::validate_settled_host_floor_join(
            journal,
            floor,
            preliminary,
            sealed,
            retained,
            protected_host_sequence,
        )?;
        if self != Self::from_floor(floor) {
            return Err(invalid_settlement());
        }
        Ok(())
    }
}






fn invalid_settlement() -> ReconcilerError {
    ReconcilerError::CorruptLedger("failed-Create settlement is not an exact three-record cut")
}

pub(super) fn has_prepare_floor(
    journal: &Journal,
    operation_id: OperationId,
) -> Result<bool, ReconcilerError> {
    if let Some(bytes) = journal.get(RecordNamespace::ControllerCreateFailurePrepare, operation_id.as_bytes()) {
        if bytes.starts_with(CLOSED_CREATE_FAILURE_PREPARE_MAGIC_V2) {
            ClosedCreateFailurePrepareDataV2::decode_canonical(operation_id.as_bytes(), bytes)
                .map_err(|_| invalid_settlement())?;
            return Ok(true);
        }
    }
    Ok(load_floor(journal, operation_id)?.is_some())
}



pub(super) fn validate_all_prepare_floors(journal: &Journal) -> Result<(), ReconcilerError> {
    prepare::validate_all_floors(journal)
}

#[cfg(test)]
pub(super) fn test_prepare_floor_digest(
    journal: &Journal,
    operation_id: OperationId,
) -> ObjectDigest {
    load_floor(journal, operation_id)
        .expect("protected prepare floor")
        .expect("prepared floor")
        .digest()
}

#[cfg(test)]
pub(super) fn test_historical_host_floor_join(
    journal: &Journal,
    operation_id: OperationId,
    preliminary: crate::runtime_execution::no_apply_settlement::HostSettlementRecordV1,
    sealed: crate::runtime_execution::no_apply_settlement::HostSettlementRecordV1,
    protected_host_sequence: u64,
) -> Result<(), ReconcilerError> {
    let floor = load_floor(journal, operation_id)?.ok_or_else(invalid_settlement)?;
    prepare::validate_historical_host_floor_join(
        floor,
        preliminary,
        sealed,
        protected_host_sequence,
    )
}







/// Validates the entire local cut on cold replay, including absence of a
/// special failed-Create receipt in every other operation state.
pub(super) fn validate_failed_create_operation(
    journal: &Journal,
    operation_id: OperationId,
    operation: OperationRecord,
) -> Result<(), ReconcilerError> {
    validate_failed_create_operation_from_observation_v2(
        crate::journal::historical_observation::HistoricalObservationV1::from_journal_v1(journal),
        operation_id, operation,
    )
}

impl<E: SingleNodeEffectExecutor> Reconciler<E> {
    /// Durably anchors one exact failed-Create CAS before its terminal write.
    ///
    /// A floor left by a crash quarantines the Applying operation. Repeating
    /// this call requires fresh held-Host proof; replaying the floor alone does
    /// not create the returned settlement token.
    ///
    /// # Errors
    ///
    /// Rejects a non-Create or changed preimage, a foreign Host identity or
    /// lease cut, a conflicting floor, or uncertain journal durability.
    #[allow(dead_code, reason = "production Host lease bridge remains closed")]
    pub(crate) fn prepare_create_failed_before_commit(
        &mut self,
        operation_id: OperationId,
        proof: CreateFailureSettlementProofV1,
        wall_seconds: i64,
    ) -> Result<PreparedCreateFailureSettlementV1, ReconcilerError> {
        let plan = self.plan_create_failure(operation_id, &proof, wall_seconds)?;
        let floor = prepare::from_plan(
            operation_id,
            &proof,
            wall_seconds,
            plan.predecessor,
            plan.successor,
        )?;
        match load_floor(&self.journal, operation_id)? {
            Some(existing) if existing == floor => {}
            Some(_) => return Err(invalid_settlement()),
            None => self.commit_records(vec![JournalRecord::put(
                RecordNamespace::ControllerCreateFailurePrepare,
                operation_id.into_bytes().to_vec(),
                floor.encode(),
            )])?,
        }
        if load_floor(&self.journal, operation_id)? != Some(floor) {
            return Err(invalid_settlement());
        }
        Ok(PreparedCreateFailureSettlementV1 {
            operation_id,
            proof,
            floor,
            wall_seconds,
        })
    }

    /// Commits only the three records bound by a prior Controller prepare.
    ///
    /// # Errors
    ///
    /// Rejects a changed protected preimage or floor, or uncertain durability.
    #[allow(dead_code, reason = "production Host lease bridge remains closed")]
    pub(crate) fn settle_create_failed_before_commit(
        &mut self,
        prepared: PreparedCreateFailureSettlementV1,
    ) -> Result<ControllerCreateFailureSettlementAckV1, ReconcilerError> {
        let plan = self.plan_create_failure(
            prepared.operation_id,
            &prepared.proof,
            prepared.wall_seconds,
        )?;
        let rebuilt = prepare::from_plan(
            prepared.operation_id,
            &prepared.proof,
            prepared.wall_seconds,
            plan.predecessor,
            plan.successor,
        )?;
        if rebuilt != prepared.floor
            || load_floor(&self.journal, prepared.operation_id)? != Some(prepared.floor)
        {
            return Err(invalid_settlement());
        }
        self.commit_records(plan.records.into())?;
        validate_failed_create_operation(&self.journal, prepared.operation_id, plan.operation)?;
        prepare::validate_all_floors(&self.journal)?;

        Ok(ControllerCreateFailureSettlementAckV1::from_floor(
            prepared.floor,
        ))
    }

    /// Recovers an exact local settlement coordinate after an ambiguous reply.
    ///
    /// A prepared but uncommitted floor returns `None`: recovery cannot infer
    /// a fresh Host lease from Controller history. A completed floor must join
    /// the exact three-record successor before this local ACK is reconstructed.
    ///
    /// # Errors
    ///
    /// Rejects missing protected authority, malformed floors, or any changed
    /// Effect, Operation, or projection bytes.
    #[allow(dead_code, reason = "signed cross-owner ACK transport remains closed")]
    pub(crate) fn recover_create_failure_settlement_ack_v1(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<ControllerCreateFailureSettlementAckV1>, ReconcilerError> {
        self.journal.ensure_protected_authority()?;
        let Some(floor) = load_floor(&self.journal, operation_id)? else {
            return if self.load_operation(operation_id)?.state()
                == OperationState::FailedBeforeCommit
            {
                Err(invalid_settlement())
            } else {
                Ok(None)
            };
        };
        prepare::validate_all_floors(&self.journal)?;
        let operation = self.load_operation(operation_id)?;
        match operation.state() {
            OperationState::Applying => Ok(None),
            OperationState::FailedBeforeCommit => {
                validate_failed_create_operation(&self.journal, operation_id, operation)?;
                Ok(Some(ControllerCreateFailureSettlementAckV1::from_floor(
                    floor,
                )))
            }
            _ => Err(invalid_settlement()),
        }
    }

    fn plan_create_failure(
        &mut self,
        operation_id: OperationId,
        proof: &CreateFailureSettlementProofV1,
        wall_seconds: i64,
    ) -> Result<PlannedCreateFailureV1, ReconcilerError> {
        let identity = CreateFailurePlanIdentityV2::AfterArgument(
            AfterArgumentCreateFailureIdentityDataV1 {
                marker: &proof.marker, archive_head: &proof.archive_head,
                signed_outcome: &proof.signed_outcome, current_host_cut: &proof.current_host_cut,
            },
        );
        identity.require_identity_data_v2()?;
        self.journal.ensure_protected_authority()?;
        self.ensure_ledger_validated()?;
        let historical = observation::historical_data_v2(
            crate::journal::historical_observation::HistoricalObservationV1::from_journal_v1(&self.journal),
        )?;
        aos_sandbox_protocol::domain_ledger::create_failure::plan_create_failure_rows_data_v2(
            &historical, operation_id, identity, wall_seconds,
        ).map_err(ReconcilerError::from)
    }


}

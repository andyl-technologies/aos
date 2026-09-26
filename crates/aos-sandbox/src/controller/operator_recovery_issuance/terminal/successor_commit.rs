//! Closed atomic Controller successor for a physically proved Storage Repair.
//!
//! The journal transaction advances an already accepted public Effect and
//! Operation with the exact predecessor archive, terminal receipt, desired
//! Sandbox projection, and protected recovery head. Storage remains a separate
//! owner: a future caller must hold a Storage-owned currentness fence through
//! this commit before the public Repair route may use it.

use aos_sandbox_core::{OperationId, ProjectId};
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1;
use buffa::Message as _;

use super::super::receipt::ProtectedStorageRepairReceiptVerifierV2;
use super::super::{
    CURRENT_HEAD_DOMAIN_V2, EVIDENCE_DOMAIN, OperatorRecoveryIssuanceErrorV1,
    ProtectedOperatorRecoverySignerV1, VERSION_DOMAIN, hash,
};
use super::issued_intent;
use super::ledger_receipt::BoundRepairLedgerReceiptV1;
use crate::controller::{operator_repair_successor_current_v1, recovery_current_key};
use crate::controller_query::CheckedSandboxResourceV1;
use crate::controller_service::public_projection::{
    PublicProjectionKindV1, PublicProjectionResourceV1, PublicProjectionStoreV1,
};
use crate::production_operation_compiler::repair_sandbox_successor_projection_v1;
use crate::reconciler::pending_operator_repair_ledger_v1;
use crate::{EffectReceipt, Journal, JournalRecord, JournalTransaction, RecordNamespace};

const TERMINAL_RECEIPT_PREFIX: &[u8] = b"storage-repair-terminal-v1/";
const COMMIT_DOMAIN: &[u8] = b"aos.sandbox.operator-repair-public-successor.v1\0";

/// Reports the outcome of an exact local terminal CAS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RepairSuccessorCommitOutcomeV1 {
    /// All successor records were made durable by this call.
    Committed,
    /// The exact successor was already durable.
    Replay,
    /// Persistence failed without a provable complete successor.
    Ambiguous,
}

/// Holds one fully prepared, still-closed terminal transaction.
#[allow(dead_code, reason = "public operator Repair route remains closed")]
pub(super) struct PreparedRepairSuccessorV1 {
    transaction: JournalTransaction,
    predecessor_sequence: u64,
    predecessor_current: Vec<u8>,
    predecessor_projection: Vec<u8>,
    predecessor_effect: Vec<u8>,
    predecessor_operation: Vec<u8>,
}

#[allow(dead_code, reason = "public operator Repair route remains closed")]
impl PreparedRepairSuccessorV1 {
    /// Prepares all six terminal rows from retained public and physical proof.
    ///
    /// The caller supplies a freshly challenged authenticated Storage inventory
    /// and a trusted Controller completion clock. Preparation does not keep
    /// Storage current across the subsequent journal commit.
    ///
    /// # Errors
    ///
    /// Rejects any missing, stale, or mismatched public admission, issuance,
    /// physical receipt, projection, proof, or protected predecessor head.
    pub(super) fn prepare(
        journal: &mut Journal,
        signer: &ProtectedOperatorRecoverySignerV1,
        owner: &ProtectedStorageRepairReceiptVerifierV2,
        operation_id: OperationId,
        storage_request_body: &[u8],
        fresh: &AuthenticatedBrokerMethodOutcomeV1,
        completion_wall_seconds: i64,
    ) -> Result<Self, OperatorRecoveryIssuanceErrorV1> {
        journal
            .ensure_protected_authority()
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        let (issued, intent) = issued_intent(journal, signer, operation_id)?;
        let pending = pending_operator_repair_ledger_v1(
            journal,
            operation_id,
            intent.target_id,
            issued.public_request_digest,
        )
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        let request = pending.request();
        let version_digest = hash(
            VERSION_DOMAIN,
            &[
                &(request.expected_resource_version().len() as u64).to_be_bytes(),
                request.expected_resource_version(),
            ],
        );
        let evidence_digest = hash(EVIDENCE_DOMAIN, &[&request.evidence().encode_to_vec()]);
        if intent.recovery_operation_id != *operation_id.as_bytes()
            || intent.project_id != *pending.context().project().as_bytes()
            || intent.principal_id != *pending.context().caller().as_bytes()
            || intent.request_digest != issued.public_request_digest
            || intent.expected_version_digest != version_digest
            || intent.evidence_digest != evidence_digest
        {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }

        let current_key = recovery_current_key(intent.target_id);
        let predecessor_current = journal
            .get(RecordNamespace::OperatorRecovery, &current_key)
            .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?
            .to_vec();
        if hash(CURRENT_HEAD_DOMAIN_V2, &[&predecessor_current]) != issued.current_head_digest {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
        let predecessor = PublicProjectionStoreV1::new(journal)
            .get(PublicProjectionKindV1::Sandbox, intent.target_id)
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?
            .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?;
        let PublicProjectionResourceV1::Sandbox(sandbox) = predecessor.resource() else {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        };
        if predecessor.project() != ProjectId::from_bytes(intent.project_id)
            || sandbox.resource_version != request.expected_resource_version()
            || intent.current_generation == 0
        {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
        let checked_predecessor = CheckedSandboxResourceV1::try_from(sandbox.clone())
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        let successor_projection = repair_sandbox_successor_projection_v1(
            &checked_predecessor,
            predecessor.project(),
            operation_id,
            issued.public_request_digest,
            request.expected_resource_version(),
            intent.current_generation,
        )
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        let successor = successor_projection
            .checked_record()
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        let PublicProjectionResourceV1::Sandbox(successor_sandbox) = successor.resource() else {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        };
        let checked_successor = CheckedSandboxResourceV1::try_from(successor_sandbox.clone())
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        let successor_current = operator_repair_successor_current_v1(
            &predecessor_current,
            &checked_predecessor,
            &checked_successor,
        )
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        let predecessor_projection = journal
            .get(
                RecordNamespace::DesiredState,
                successor_projection.desired_key(),
            )
            .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?
            .to_vec();
        let receipt = BoundRepairLedgerReceiptV1::from_current_verified_rows(
            journal,
            signer,
            owner,
            operation_id,
            storage_request_body,
            &predecessor_projection,
            &successor_projection,
            &successor_current,
            fresh,
        )?;
        let archive = receipt.prepare_predecessor_archive(
            journal,
            &successor_projection,
            issued.current_head_digest,
        )?;
        let ledger = pending
            .complete(
                EffectReceipt::new(receipt.encode().to_vec())
                    .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?,
                completion_wall_seconds,
            )
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        let predecessor_effect = journal
            .get(ledger[0].namespace(), ledger[0].key())
            .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?
            .to_vec();
        let predecessor_operation = journal
            .get(ledger[1].namespace(), ledger[1].key())
            .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?
            .to_vec();
        let terminal_key = [TERMINAL_RECEIPT_PREFIX, operation_id.as_bytes()].concat();
        if journal
            .get(RecordNamespace::OperatorRecovery, &terminal_key)
            .is_some()
        {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
        let receipt_bytes = receipt.encode();
        let digest = hash(COMMIT_DOMAIN, &[operation_id.as_bytes(), &receipt_bytes]);
        let transaction_id: [u8; 16] = digest[..16]
            .try_into()
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        let transaction = JournalTransaction::new(
            transaction_id,
            vec![
                archive,
                ledger[0].clone(),
                ledger[1].clone(),
                JournalRecord::put(
                    RecordNamespace::DesiredState,
                    successor_projection.desired_key().to_vec(),
                    successor_projection.desired_value().to_vec(),
                ),
                JournalRecord::put(
                    RecordNamespace::OperatorRecovery,
                    current_key,
                    successor_current,
                ),
                JournalRecord::put(
                    RecordNamespace::OperatorRecovery,
                    terminal_key,
                    receipt_bytes.to_vec(),
                ),
            ],
        )
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;

        Ok(Self {
            transaction,
            predecessor_sequence: journal.snapshot_sequence(),
            predecessor_current,
            predecessor_projection,
            predecessor_effect,
            predecessor_operation,
        })
    }

    /// Commits the exact successor or reports a locally ambiguous outcome.
    ///
    /// # Errors
    ///
    /// Rejects a stale predecessor or a partial, conflicting successor.
    pub(super) fn commit(
        &self,
        journal: &mut Journal,
    ) -> Result<RepairSuccessorCommitOutcomeV1, OperatorRecoveryIssuanceErrorV1> {
        journal
            .ensure_protected_authority()
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        if self.successor_matches(journal) {
            return Ok(RepairSuccessorCommitOutcomeV1::Replay);
        }
        if !self.predecessor_matches(journal) {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
        // Every copied Controller dependency must remain current, including
        // authorization and issuance rows outside the terminal write set.
        if journal.snapshot_sequence() != self.predecessor_sequence {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }

        let result = journal.commit(&self.transaction);
        if self.successor_matches(journal) && journal.ensure_protected_authority().is_ok() {
            return Ok(RepairSuccessorCommitOutcomeV1::Committed);
        }
        if result.is_err() {
            Ok(RepairSuccessorCommitOutcomeV1::Ambiguous)
        } else {
            Err(OperatorRecoveryIssuanceErrorV1::Binding)
        }
    }

    /// Resolves a post-commit uncertainty using only exact protected rows.
    ///
    /// # Errors
    ///
    /// Rejects any substituted or partial terminal row.
    pub(super) fn classify_ambiguous(
        &self,
        journal: &Journal,
    ) -> Result<RepairSuccessorCommitOutcomeV1, OperatorRecoveryIssuanceErrorV1> {
        if journal.ensure_protected_authority().is_err() {
            return Ok(RepairSuccessorCommitOutcomeV1::Ambiguous);
        }
        if self.successor_matches(journal) {
            Ok(RepairSuccessorCommitOutcomeV1::Replay)
        } else if self.predecessor_matches(journal)
            && journal.snapshot_sequence() == self.predecessor_sequence
        {
            Ok(RepairSuccessorCommitOutcomeV1::Ambiguous)
        } else {
            Err(OperatorRecoveryIssuanceErrorV1::Binding)
        }
    }

    fn successor_matches(&self, journal: &Journal) -> bool {
        self.transaction
            .records()
            .iter()
            .all(|record| journal.get(record.namespace(), record.key()) == record.value())
    }

    fn predecessor_matches(&self, journal: &Journal) -> bool {
        let records = self.transaction.records();
        journal.get(records[1].namespace(), records[1].key())
            == Some(self.predecessor_effect.as_slice())
            && journal.get(records[2].namespace(), records[2].key())
                == Some(self.predecessor_operation.as_slice())
            && journal.get(records[3].namespace(), records[3].key())
                == Some(self.predecessor_projection.as_slice())
            && journal.get(records[4].namespace(), records[4].key())
                == Some(self.predecessor_current.as_slice())
            && journal
                .get(records[0].namespace(), records[0].key())
                .is_none()
            && journal
                .get(records[5].namespace(), records[5].key())
                .is_none()
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;
    use crate::JournalLimits;

    fn open_journal(directory: &tempfile::TempDir) -> Journal {
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        Journal::open_protected_at_uid(
            directory.path(),
            "repair-successor.journal",
            JournalLimits::default(),
            rustix::process::getuid().as_raw(),
        )
        .unwrap()
        .0
    }

    fn seeded() -> (tempfile::TempDir, Journal, PreparedRepairSuccessorV1) {
        let directory = tempfile::tempdir().unwrap();
        let mut journal = open_journal(&directory);
        let operation_id = [7; 16];
        let effect_key = [operation_id.as_slice(), &[0; 4]].concat();
        let operation_key = operation_id.to_vec();
        let projection_key = b"sandbox-projection".to_vec();
        let current_key = recovery_current_key([8; 16]);
        let archive_key = b"repair-archive".to_vec();
        let receipt_key = b"repair-terminal-receipt".to_vec();
        let predecessor_effect = b"effect-pending".to_vec();
        let predecessor_operation = b"operation-applying".to_vec();
        let predecessor_projection = b"projection-before".to_vec();
        let predecessor_current = b"head-before".to_vec();
        journal
            .commit(
                &JournalTransaction::new(
                    [9; 16],
                    vec![
                        JournalRecord::put(
                            RecordNamespace::Effect,
                            effect_key.clone(),
                            predecessor_effect.clone(),
                        ),
                        JournalRecord::put(
                            RecordNamespace::Operation,
                            operation_key.clone(),
                            predecessor_operation.clone(),
                        ),
                        JournalRecord::put(
                            RecordNamespace::DesiredState,
                            projection_key.clone(),
                            predecessor_projection.clone(),
                        ),
                        JournalRecord::put(
                            RecordNamespace::OperatorRecovery,
                            current_key.clone(),
                            predecessor_current.clone(),
                        ),
                    ],
                )
                .unwrap(),
            )
            .unwrap();
        let transaction = JournalTransaction::new(
            [10; 16],
            vec![
                JournalRecord::put(RecordNamespace::OperatorRecovery, archive_key, vec![11]),
                JournalRecord::put(RecordNamespace::Effect, effect_key, vec![12]),
                JournalRecord::put(RecordNamespace::Operation, operation_key, vec![13]),
                JournalRecord::put(RecordNamespace::DesiredState, projection_key, vec![14]),
                JournalRecord::put(RecordNamespace::OperatorRecovery, current_key, vec![15]),
                JournalRecord::put(RecordNamespace::OperatorRecovery, receipt_key, vec![16]),
            ],
        )
        .unwrap();
        let prepared = PreparedRepairSuccessorV1 {
            transaction,
            predecessor_sequence: journal.snapshot_sequence(),
            predecessor_current,
            predecessor_projection,
            predecessor_effect,
            predecessor_operation,
        };
        (directory, journal, prepared)
    }

    #[test]
    fn successor_commits_all_six_rows_and_replays_after_reopen() {
        let (directory, mut journal, prepared) = seeded();
        let predecessor_sequence = journal.snapshot_sequence();
        assert_eq!(
            prepared.classify_ambiguous(&journal),
            Ok(RepairSuccessorCommitOutcomeV1::Ambiguous)
        );
        assert_eq!(
            prepared.commit(&mut journal),
            Ok(RepairSuccessorCommitOutcomeV1::Committed)
        );
        assert!(journal.snapshot_sequence() > predecessor_sequence);
        drop(journal);

        let mut reopened = open_journal(&directory);
        assert_eq!(
            prepared.classify_ambiguous(&reopened),
            Ok(RepairSuccessorCommitOutcomeV1::Replay)
        );
        assert_eq!(
            prepared.commit(&mut reopened),
            Ok(RepairSuccessorCommitOutcomeV1::Replay)
        );
        assert!(prepared.successor_matches(&reopened));
    }

    #[test]
    fn ambiguous_post_durable_error_resolves_only_exact_successor() {
        let (_directory, mut journal, prepared) = seeded();
        // Models an error returned after the complete journal transaction is
        // durable, before the caller receives its commit result.
        journal.commit(&prepared.transaction).unwrap();
        assert_eq!(
            prepared.classify_ambiguous(&journal),
            Ok(RepairSuccessorCommitOutcomeV1::Replay)
        );

        let operation = &prepared.transaction.records()[2];
        journal
            .commit(
                &JournalTransaction::new(
                    [17; 16],
                    vec![JournalRecord::put(
                        operation.namespace(),
                        operation.key().to_vec(),
                        b"substituted-operation".to_vec(),
                    )],
                )
                .unwrap(),
            )
            .unwrap();
        assert!(prepared.classify_ambiguous(&journal).is_err());
    }

    #[test]
    fn stale_predecessor_rejects_terminal_commit_without_partial_rows() {
        let (_directory, mut journal, prepared) = seeded();
        let current = &prepared.transaction.records()[4];
        journal
            .commit(
                &JournalTransaction::new(
                    [18; 16],
                    vec![JournalRecord::put(
                        current.namespace(),
                        current.key().to_vec(),
                        b"another-current-head".to_vec(),
                    )],
                )
                .unwrap(),
            )
            .unwrap();
        assert!(prepared.commit(&mut journal).is_err());
        assert!(
            journal
                .get(
                    prepared.transaction.records()[5].namespace(),
                    prepared.transaction.records()[5].key(),
                )
                .is_none()
        );
    }

    #[test]
    fn unrelated_controller_write_invalidates_prepared_dependency_snapshot() {
        let (_directory, mut journal, prepared) = seeded();
        journal
            .commit(
                &JournalTransaction::new(
                    [19; 16],
                    vec![JournalRecord::put(
                        RecordNamespace::PublicOperationAuthorization,
                        b"other-admission".to_vec(),
                        b"changed".to_vec(),
                    )],
                )
                .unwrap(),
            )
            .unwrap();

        assert!(prepared.predecessor_matches(&journal));
        assert!(prepared.commit(&mut journal).is_err());
        assert!(prepared.classify_ambiguous(&journal).is_err());
        assert!(
            journal
                .get(
                    prepared.transaction.records()[5].namespace(),
                    prepared.transaction.records()[5].key(),
                )
                .is_none()
        );
    }
}

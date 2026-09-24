//! Protected Storage evidence for a bounded operator workspace-pin repair.
//!
//! The sidecar commits the signed controller intent and a fresh, authenticated
//! dataset-present/pin-absent probe before Storage can dispatch its existing
//! repair worker. A completed Storage attempt and a fresh physical inventory
//! then produce a separately signed receipt. A pending sidecar survives a lost
//! worker or receipt response; it never authorizes a second repair attempt.
//! Version-one sidecar records are rejected on reopen. They are never
//! reinterpreted as version-two evidence after deployment rotation.
//!
//! ```text
//! AOSORSP2 | version:u16be=2 | phase:u8 | reserved:u8
//! probe-epoch:u32be | controller-key-generation:u64be
//! owner-key-generation:u64be | owner-id:16
//! signed-intent:364
//! storage-request-digest:32 | storage-transport-digest:32
//! storage-semantic-digest:32 | absence-probe-digest:32
//! workspace-handle:32 | repair-operation-id:16
//! before-catalog-generation:u64be | signed-evidence:308
//! signed-receipt:328
//! ```

use std::path::Path;

use aos_sandbox::{
    Journal, JournalError, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace,
};
use aos_sandbox_core::operator_recovery_effect::{
    OPERATOR_RECOVERY_EFFECT_INTENT_BYTES, OperatorRecoveryEffectActionV1,
    OperatorRecoveryEffectTargetV1, verify_operator_recovery_effect_intent_v1,
};
use aos_sandbox_core::operator_recovery_effect_v2::{
    OPERATOR_RECOVERY_EFFECT_EVIDENCE_BYTES_V2, OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES_V2,
    OperatorRecoveryEffectEvidenceV2, OperatorRecoveryEffectReceiptV2, evidence_digest_v2,
    sign_operator_recovery_effect_evidence_v2, sign_operator_recovery_effect_receipt_v2,
    verify_operator_recovery_effect_receipt_v2,
};
use aos_sandbox_protocol::semantics::storage_repair::CanonicalStorageRepairSemanticsV1;
use aos_sandbox_protocol::{MAXIMUM_RESPONSE_BYTES, decode_storage_resource_inventory_response};
use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest as _, Sha256};

use crate::broker::StorageAdmissionCoordinator;
use crate::pin_worker_runtime::FreshWorkspacePinRepairObservationV1;
use crate::workspace_pin::{WorkspacePinActionV1, WorkspacePinAttemptPhaseV1};
use crate::workspace_repair_admission::WorkspacePinRepairAdmissionProbeV1;

const MAGIC: &[u8; 8] = b"AOSORSP2";
const VERSION: u16 = 2;
const PENDING: u8 = 1;
const COMPLETE: u8 = 2;
const RECORD_BYTES: usize = 1232;
const MAXIMUM_PROBE_EPOCH: u32 = 4;
const REQUEST_DOMAIN: &[u8] = b"aos.sandbox.operator-storage-repair-request.v1\0";
const FENCE_DOMAIN: &[u8] = b"aos.sandbox.operator-storage-repair-fence.v1\0";
const BEFORE_DOMAIN: &[u8] = b"aos.sandbox.operator-storage-repair-before.v1\0";
const AFTER_DOMAIN: &[u8] = b"aos.sandbox.operator-storage-repair-after.v1\0";
pub(crate) const COMMIT_DOMAIN: &[u8] = b"aos.sandbox.operator-storage-repair-commit.v1\0";
const TERMINAL_DOMAIN: &[u8] = b"aos.sandbox.operator-storage-repair-terminal.v1\0";
const TX_DOMAIN: &[u8] = b"aos.sandbox.operator-storage-repair-transaction.v2\0";

/// Reports an unavailable or mismatched protected repair owner.
#[derive(Debug, thiserror::Error)]
pub enum StorageOperatorRecoveryErrorV1 {
    #[error("operator recovery sidecar journal failed closed: {0}")]
    Journal(#[from] JournalError),
    #[error("operator recovery evidence or binding is invalid")]
    Binding,
    #[error("operator recovery Storage attempt is not durably satisfied")]
    Pending,
}

/// Retains dedicated signing custody and the protected before-effect record.
pub struct StorageOperatorRecoveryOwnerV1 {
    journal: Journal,
    controller_key: VerifyingKey,
    controller_key_generation: u64,
    owner_key: SigningKey,
    owner_id: [u8; 16],
    owner_key_generation: u64,
}

/// Indicates whether a reservation is awaiting Storage or already completed.
pub(crate) enum StorageOperatorRecoveryReservationV2 {
    Pending,
    Complete(StorageOperatorRecoveryCompletionV2),
}

/// Returns separately signed owner evidence and its generation-bound receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StorageOperatorRecoveryCompletionV2 {
    pub(crate) signed_evidence: [u8; OPERATOR_RECOVERY_EFFECT_EVIDENCE_BYTES_V2],
    pub(crate) signed_receipt: [u8; OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES_V2],
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StoredRepairV2 {
    phase: u8,
    probe_epoch: u32,
    controller_key_generation: u64,
    owner_key_generation: u64,
    owner_id: [u8; 16],
    signed_intent: [u8; OPERATOR_RECOVERY_EFFECT_INTENT_BYTES],
    storage_request_digest: [u8; 32],
    storage_transport_digest: [u8; 32],
    storage_semantic_digest: [u8; 32],
    absence_probe_digest: [u8; 32],
    workspace_handle: [u8; 32],
    repair_operation_id: [u8; 16],
    before_catalog_generation: u64,
    signed_evidence: [u8; OPERATOR_RECOVERY_EFFECT_EVIDENCE_BYTES_V2],
    signed_receipt: [u8; OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES_V2],
}

enum StoredReservationDecisionV2 {
    Pending,
    Replace(StoredRepairV2),
    Complete(StorageOperatorRecoveryCompletionV2),
}

impl StorageOperatorRecoveryOwnerV1 {
    /// Selects only the effect named by an authenticated controller intent.
    ///
    /// A receipt-recovery query grants no new Storage effect authority and
    /// cannot substitute a caller-selected effect identity for the signature.
    ///
    /// # Errors
    ///
    /// Rejects an invalid signature or a non-Repair sandbox intent.
    pub(crate) fn effect_id_for_intent(
        &self,
        signed_intent: &[u8],
    ) -> Result<[u8; 32], StorageOperatorRecoveryErrorV1> {
        let intent = verify_operator_recovery_effect_intent_v1(signed_intent, &self.controller_key)
            .map_err(|_| StorageOperatorRecoveryErrorV1::Binding)?;
        if intent.action != OperatorRecoveryEffectActionV1::Repair
            || intent.target_kind != OperatorRecoveryEffectTargetV1::Sandbox
            || intent.attempt != 1
        {
            return Err(StorageOperatorRecoveryErrorV1::Binding);
        }
        Ok(intent.effect_id)
    }

    /// Requires an exact retained reservation before any receipt readback.
    ///
    /// # Errors
    ///
    /// Rejects absent, changed, or incompatible protected state.
    pub(crate) fn require_reserved_intent(
        &mut self,
        signed_intent: &[u8],
    ) -> Result<[u8; 32], StorageOperatorRecoveryErrorV1> {
        let effect_id = self.effect_id_for_intent(signed_intent)?;
        let authority = self
            .journal
            .claim_protected_authority(RecordNamespace::OperatorRecovery)?;
        let stored = StoredRepairV2::decode(
            authority
                .get(&effect_id)?
                .ok_or(StorageOperatorRecoveryErrorV1::Pending)?,
        )?;
        validate_stored(
            &stored,
            &effect_id,
            &self.controller_key,
            &self.owner_key.verifying_key(),
            self.owner_id,
            self.controller_key_generation,
            self.owner_key_generation,
        )?;
        if stored.signed_intent.as_slice() != signed_intent {
            return Err(StorageOperatorRecoveryErrorV1::Binding);
        }
        Ok(effect_id)
    }

    /// Binds a signed operator effect to the exact Storage request body.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid signature or a different request body.
    pub(crate) fn effect_id_for_request(
        &self,
        signed_intent: &[u8],
        storage_request_body: &[u8],
    ) -> Result<[u8; 32], StorageOperatorRecoveryErrorV1> {
        let intent = verify_operator_recovery_effect_intent_v1(signed_intent, &self.controller_key)
            .map_err(|_| StorageOperatorRecoveryErrorV1::Binding)?;
        if intent.effect_id != request_digest(storage_request_body) {
            return Err(StorageOperatorRecoveryErrorV1::Binding);
        }
        Ok(intent.effect_id)
    }

    /// Opens only a root-owned, exclusive, single-namespace receipt journal.
    ///
    /// # Errors
    ///
    /// Returns an error for unsafe journal custody, a rotated key generation,
    /// legacy or malformed retained state, or an invalid role-key configuration.
    pub fn open(
        directory: impl AsRef<Path>,
        name: &str,
        controller_key: VerifyingKey,
        controller_key_generation: u64,
        owner_key: SigningKey,
        owner_id: [u8; 16],
        owner_key_generation: u64,
    ) -> Result<Self, StorageOperatorRecoveryErrorV1> {
        if owner_id == [0; 16]
            || controller_key_generation == 0
            || owner_key_generation == 0
            || controller_key == owner_key.verifying_key()
        {
            return Err(StorageOperatorRecoveryErrorV1::Binding);
        }
        let limits = JournalLimits {
            maximum_journal_bytes: 16 * 1024 * 1024,
            maximum_record_bytes: 2048,
            maximum_key_bytes: 32,
            maximum_records_per_transaction: 1,
            maximum_transaction_bytes: 2048,
            maximum_transactions: 8192,
            maximum_materialized_bytes: 8 * 1024 * 1024,
            maximum_materialized_records: 4096,
        };
        let (mut journal, _) = Journal::open_protected_at(directory, name, limits)?;
        let authority = journal.claim_protected_authority(RecordNamespace::OperatorRecovery)?;
        for (key, value) in authority.records()? {
            let record = StoredRepairV2::decode(value)?;
            validate_stored(
                &record,
                key,
                &controller_key,
                &owner_key.verifying_key(),
                owner_id,
                controller_key_generation,
                owner_key_generation,
            )?;
        }
        Ok(Self {
            journal,
            controller_key,
            controller_key_generation,
            owner_key,
            owner_id,
            owner_key_generation,
        })
    }

    /// Durably reserves a fresh absence probe before the Storage repair effect.
    ///
    /// A reservation alone grants no Storage authority: the ordinary Storage
    /// broker must still authenticate its signed request and current fence.
    ///
    /// # Errors
    ///
    /// Returns an error for an unauthenticated or mismatched intent, stale
    /// observation, exhausted probe budget, or uncertain journal commit.
    pub(crate) fn reserve(
        &mut self,
        signed_intent: &[u8],
        storage_request_body: &[u8],
        semantics: &CanonicalStorageRepairSemanticsV1,
        probe: &WorkspacePinRepairAdmissionProbeV1,
        fresh: &FreshWorkspacePinRepairObservationV1,
    ) -> Result<StorageOperatorRecoveryReservationV2, StorageOperatorRecoveryErrorV1> {
        let intent = verify_operator_recovery_effect_intent_v1(signed_intent, &self.controller_key)
            .map_err(|_| StorageOperatorRecoveryErrorV1::Binding)?;
        let signed_intent: [u8; OPERATOR_RECOVERY_EFFECT_INTENT_BYTES] =
            signed_intent
                .try_into()
                .map_err(|_| StorageOperatorRecoveryErrorV1::Binding)?;
        if !fresh.matches_probe(probe)
            || intent.action != OperatorRecoveryEffectActionV1::Repair
            || intent.target_kind != OperatorRecoveryEffectTargetV1::Sandbox
            || intent.recovery_operation_id != semantics.operation_id()
            || intent.target_id != *semantics.fence().sandbox_id()
            || intent.current_generation != semantics.fence().desired_generation()
            || intent.effect_id != request_digest(storage_request_body)
            || intent.current_fence_digest != fence_digest(semantics)
            || probe.repair_operation_id() != semantics.operation_id()
            || probe.workspace_handle() != *semantics.storage_handle().as_bytes()
        {
            return Err(StorageOperatorRecoveryErrorV1::Binding);
        }

        let record = StoredRepairV2 {
            phase: PENDING,
            probe_epoch: 1,
            controller_key_generation: self.controller_key_generation,
            owner_key_generation: self.owner_key_generation,
            owner_id: self.owner_id,
            signed_intent,
            storage_request_digest: request_digest(storage_request_body),
            storage_transport_digest: Sha256::digest(storage_request_body).into(),
            storage_semantic_digest: *semantics.argument_commitment().digest().as_bytes(),
            absence_probe_digest: *probe.digest().as_bytes(),
            workspace_handle: probe.workspace_handle(),
            repair_operation_id: semantics.operation_id(),
            before_catalog_generation: probe.physical_catalog_head().generation(),
            signed_evidence: [0; OPERATOR_RECOVERY_EFFECT_EVIDENCE_BYTES_V2],
            signed_receipt: [0; OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES_V2],
        };
        self.reserve_record(&record)
    }

    /// Completes a reserved repair from Storage's durable attempt and fresh inventory.
    ///
    /// A lost response can call this again after restart. An uncertain sidecar
    /// commit returns an error and requires a protected reopen before replay.
    ///
    /// # Errors
    ///
    /// Returns an error when Storage has not durably completed the repair,
    /// physical inventory differs, or the receipt commit is uncertain.
    pub(crate) fn complete(
        &mut self,
        effect_id: [u8; 32],
        storage: &StorageAdmissionCoordinator,
        inventory_bytes: &[u8],
    ) -> Result<StorageOperatorRecoveryCompletionV2, StorageOperatorRecoveryErrorV1> {
        let authority = self
            .journal
            .claim_protected_authority(RecordNamespace::OperatorRecovery)?;
        let record = StoredRepairV2::decode(
            authority
                .get(&effect_id)?
                .ok_or(StorageOperatorRecoveryErrorV1::Pending)?,
        )?;
        validate_stored(
            &record,
            &effect_id,
            &self.controller_key,
            &self.owner_key.verifying_key(),
            self.owner_id,
            self.controller_key_generation,
            self.owner_key_generation,
        )?;
        let intent =
            verify_operator_recovery_effect_intent_v1(&record.signed_intent, &self.controller_key)
                .map_err(|_| StorageOperatorRecoveryErrorV1::Binding)?;
        let (repair, attempt, attempt_record) = storage
            .operator_recovery_satisfied_workspace_pin(record.repair_operation_id)
            .map_err(|_| StorageOperatorRecoveryErrorV1::Binding)?
            .ok_or(StorageOperatorRecoveryErrorV1::Pending)?;
        let inventory =
            decode_storage_resource_inventory_response(inventory_bytes, MAXIMUM_RESPONSE_BYTES)
                .map_err(|_| StorageOperatorRecoveryErrorV1::Binding)?;
        let workspace = inventory
            .workspaces()
            .iter()
            .find(|workspace| workspace.workspace_handle() == &record.workspace_handle)
            .ok_or(StorageOperatorRecoveryErrorV1::Pending)?;
        let pin = attempt
            .satisfied_pin()
            .ok_or(StorageOperatorRecoveryErrorV1::Pending)?;
        if repair.repair_operation_id() != record.repair_operation_id
            || repair.request_digest().as_bytes() != &record.storage_transport_digest
            || repair.semantic_commitment().as_bytes() != &record.storage_semantic_digest
            || repair.repair_attempt_id() != attempt.attempt_id()
            || repair.workspace_handle() != record.workspace_handle
            || attempt.action() != WorkspacePinActionV1::Ensure
            || attempt.phase() != WorkspacePinAttemptPhaseV1::Satisfied
            || attempt.effect_operation_id() != record.repair_operation_id
            || attempt.workspace_handle() != record.workspace_handle
            || attempt.operation_fence_digest() != repair.operation_fence_digest()
            || attempt.effect_assignment_digest() != repair.repair_assignment_digest()
            || workspace.fence().sandbox_id() != &intent.target_id
            || workspace.fence().desired_generation() != intent.current_generation
            || workspace.fence().assignment_digest() != repair.repair_assignment_digest().as_bytes()
            || workspace.creation_operation_id() != &attempt.creation_operation_id()
            || workspace.dataset_guid() != attempt.dataset_guid()
            || workspace.resource_kernel_boot_id() != &pin.kernel_boot_id()
            || workspace.root_device() != pin.root_device()
            || workspace.root_inode() != pin.root_inode()
            || inventory.catalog_generation() < record.before_catalog_generation
        {
            return Err(StorageOperatorRecoveryErrorV1::Binding);
        }

        let before_inventory_digest = hash(
            BEFORE_DOMAIN,
            &[&record.absence_probe_digest, b"dataset-exact/pin-absent"],
        );
        let after_inventory_digest = hash(AFTER_DOMAIN, &[inventory_bytes]);
        let effect_commit_digest = hash(COMMIT_DOMAIN, &[&attempt_record]);
        let resulting_version = *workspace.resource_digest();
        let terminal_result_digest = hash(
            TERMINAL_DOMAIN,
            &[
                &intent
                    .digest()
                    .map_err(|_| StorageOperatorRecoveryErrorV1::Binding)?,
                &after_inventory_digest,
                &resulting_version,
                &effect_commit_digest,
            ],
        );
        let evidence = OperatorRecoveryEffectEvidenceV2 {
            intent_digest: intent
                .digest()
                .map_err(|_| StorageOperatorRecoveryErrorV1::Binding)?,
            owner_id: self.owner_id,
            owner_key_generation: self.owner_key_generation,
            probe_epoch: record.probe_epoch,
            absence_probe_digest: record.absence_probe_digest,
            before_catalog_generation: record.before_catalog_generation,
            before_inventory_digest,
            effect_commit_digest,
            after_inventory_digest,
            resulting_version,
            after_catalog_generation: inventory.catalog_generation(),
        };
        let signed_evidence = sign_operator_recovery_effect_evidence_v2(&evidence, &self.owner_key)
            .map_err(|_| StorageOperatorRecoveryErrorV1::Binding)?;
        let receipt = OperatorRecoveryEffectReceiptV2 {
            intent_digest: evidence.intent_digest,
            owner_id: self.owner_id,
            owner_key_generation: self.owner_key_generation,
            signed_evidence_digest: evidence_digest_v2(&signed_evidence),
            before_inventory_digest,
            after_inventory_digest,
            resulting_version,
            terminal_result_digest,
            effect_commit_digest,
            owner_generation: inventory.catalog_generation(),
        };
        let signed_receipt = sign_operator_recovery_effect_receipt_v2(&receipt, &self.owner_key)
            .map_err(|_| StorageOperatorRecoveryErrorV1::Binding)?;
        let completion = StorageOperatorRecoveryCompletionV2 {
            signed_evidence,
            signed_receipt,
        };
        if record.phase == COMPLETE {
            return if completion.signed_evidence == record.signed_evidence
                && completion.signed_receipt == record.signed_receipt
            {
                Ok(completion)
            } else {
                Err(StorageOperatorRecoveryErrorV1::Binding)
            };
        }
        let completed = StoredRepairV2 {
            phase: COMPLETE,
            signed_evidence,
            signed_receipt,
            ..record
        };
        commit_record(&mut self.journal, &completed)?;
        Ok(completion)
    }

    fn reserve_record(
        &mut self,
        record: &StoredRepairV2,
    ) -> Result<StorageOperatorRecoveryReservationV2, StorageOperatorRecoveryErrorV1> {
        let intent =
            verify_operator_recovery_effect_intent_v1(&record.signed_intent, &self.controller_key)
                .map_err(|_| StorageOperatorRecoveryErrorV1::Binding)?;
        let authority = self
            .journal
            .claim_protected_authority(RecordNamespace::OperatorRecovery)?;
        if let Some(existing) = authority.get(&intent.effect_id)? {
            let existing = StoredRepairV2::decode(existing)?;
            validate_stored(
                &existing,
                &intent.effect_id,
                &self.controller_key,
                &self.owner_key.verifying_key(),
                self.owner_id,
                self.controller_key_generation,
                self.owner_key_generation,
            )?;
            return match classify_reservation(&existing, record)? {
                StoredReservationDecisionV2::Pending => {
                    Ok(StorageOperatorRecoveryReservationV2::Pending)
                }
                StoredReservationDecisionV2::Replace(replacement) => {
                    commit_record(&mut self.journal, &replacement)?;
                    Ok(StorageOperatorRecoveryReservationV2::Pending)
                }
                StoredReservationDecisionV2::Complete(receipt) => {
                    Ok(StorageOperatorRecoveryReservationV2::Complete(receipt))
                }
            };
        }
        commit_record(&mut self.journal, record)?;
        Ok(StorageOperatorRecoveryReservationV2::Pending)
    }
}

fn classify_reservation(
    existing: &StoredRepairV2,
    requested: &StoredRepairV2,
) -> Result<StoredReservationDecisionV2, StorageOperatorRecoveryErrorV1> {
    if existing.phase == COMPLETE {
        let pending = StoredRepairV2 {
            phase: PENDING,
            probe_epoch: 1,
            signed_evidence: [0; OPERATOR_RECOVERY_EFFECT_EVIDENCE_BYTES_V2],
            signed_receipt: [0; OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES_V2],
            ..existing.clone()
        };
        return if &pending == requested {
            Ok(StoredReservationDecisionV2::Complete(
                StorageOperatorRecoveryCompletionV2 {
                    signed_evidence: existing.signed_evidence,
                    signed_receipt: existing.signed_receipt,
                },
            ))
        } else {
            Err(StorageOperatorRecoveryErrorV1::Binding)
        };
    }

    let same_probe = StoredRepairV2 {
        probe_epoch: 1,
        ..existing.clone()
    };
    if &same_probe == requested {
        return Ok(StoredReservationDecisionV2::Pending);
    }

    // The caller reached this path only after Storage confirmed no durable
    // repair intent. A fresh absence observation may replace the unconsumed
    // probe, with a bounded journaled epoch.
    let next_epoch = existing
        .probe_epoch
        .checked_add(1)
        .filter(|epoch| *epoch <= MAXIMUM_PROBE_EPOCH)
        .ok_or(StorageOperatorRecoveryErrorV1::Binding)?;
    let replacement = StoredRepairV2 {
        probe_epoch: next_epoch,
        ..requested.clone()
    };
    let same_binding = StoredRepairV2 {
        absence_probe_digest: replacement.absence_probe_digest,
        before_catalog_generation: replacement.before_catalog_generation,
        probe_epoch: replacement.probe_epoch,
        ..existing.clone()
    };
    if same_binding != replacement {
        return Err(StorageOperatorRecoveryErrorV1::Binding);
    }
    Ok(StoredReservationDecisionV2::Replace(replacement))
}

fn validate_stored(
    record: &StoredRepairV2,
    key: &[u8],
    controller_key: &VerifyingKey,
    owner_key: &VerifyingKey,
    owner_id: [u8; 16],
    controller_key_generation: u64,
    owner_key_generation: u64,
) -> Result<(), StorageOperatorRecoveryErrorV1> {
    let intent = verify_operator_recovery_effect_intent_v1(&record.signed_intent, controller_key)
        .map_err(|_| StorageOperatorRecoveryErrorV1::Binding)?;
    if key != intent.effect_id
        || intent.action != OperatorRecoveryEffectActionV1::Repair
        || intent.target_kind != OperatorRecoveryEffectTargetV1::Sandbox
        || record.owner_id != owner_id
        || record.controller_key_generation != controller_key_generation
        || record.owner_key_generation != owner_key_generation
        || !(1..=MAXIMUM_PROBE_EPOCH).contains(&record.probe_epoch)
        || record.storage_request_digest != intent.effect_id
        || record.storage_transport_digest == [0; 32]
        || record.storage_semantic_digest == [0; 32]
        || record.repair_operation_id != intent.recovery_operation_id
        || record.before_catalog_generation == 0
        || record.absence_probe_digest == [0; 32]
        || record.workspace_handle == [0; 32]
    {
        return Err(StorageOperatorRecoveryErrorV1::Binding);
    }
    match record.phase {
        PENDING
            if record.signed_evidence == [0; OPERATOR_RECOVERY_EFFECT_EVIDENCE_BYTES_V2]
                && record.signed_receipt == [0; OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES_V2] =>
        {
            Ok(())
        }
        COMPLETE => {
            let terminal_digest: [u8; 32] = record.signed_receipt[192..224]
                .try_into()
                .map_err(|_| StorageOperatorRecoveryErrorV1::Binding)?;
            let (receipt, evidence) = verify_operator_recovery_effect_receipt_v2(
                &record.signed_receipt,
                &record.signed_evidence,
                owner_key,
                &intent,
                owner_id,
                owner_key_generation,
                terminal_digest,
            )
            .map_err(|_| StorageOperatorRecoveryErrorV1::Binding)?;
            let before = hash(
                BEFORE_DOMAIN,
                &[&record.absence_probe_digest, b"dataset-exact/pin-absent"],
            );
            let expected_terminal = hash(
                TERMINAL_DOMAIN,
                &[
                    &intent
                        .digest()
                        .map_err(|_| StorageOperatorRecoveryErrorV1::Binding)?,
                    &evidence.after_inventory_digest,
                    &evidence.resulting_version,
                    &evidence.effect_commit_digest,
                ],
            );
            if receipt.before_inventory_digest != before
                || evidence.probe_epoch != record.probe_epoch
                || evidence.absence_probe_digest != record.absence_probe_digest
                || evidence.before_catalog_generation != record.before_catalog_generation
                || receipt.terminal_result_digest != expected_terminal
                || receipt.owner_generation < record.before_catalog_generation
            {
                return Err(StorageOperatorRecoveryErrorV1::Binding);
            }
            Ok(())
        }
        _ => Err(StorageOperatorRecoveryErrorV1::Binding),
    }
}

fn commit_record(
    journal: &mut Journal,
    record: &StoredRepairV2,
) -> Result<(), StorageOperatorRecoveryErrorV1> {
    let controller_key_effect_id: [u8; 32] = record.storage_request_digest;
    let phase = [record.phase];
    let tx_digest = hash(
        TX_DOMAIN,
        &[
            &controller_key_effect_id,
            &phase,
            &record.probe_epoch.to_be_bytes(),
        ],
    );
    let transaction_id: [u8; 16] = tx_digest[..16]
        .try_into()
        .map_err(|_| StorageOperatorRecoveryErrorV1::Binding)?;
    let transaction = JournalTransaction::new(
        transaction_id,
        vec![JournalRecord::put(
            RecordNamespace::OperatorRecovery,
            controller_key_effect_id.to_vec(),
            record.encode(),
        )],
    )?;
    journal
        .claim_protected_authority(RecordNamespace::OperatorRecovery)?
        .commit(&transaction)?;
    Ok(())
}

impl StoredRepairV2 {
    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(RECORD_BYTES);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_be_bytes());
        bytes.extend_from_slice(&[self.phase, 0]);
        bytes.extend_from_slice(&self.probe_epoch.to_be_bytes());
        bytes.extend_from_slice(&self.controller_key_generation.to_be_bytes());
        bytes.extend_from_slice(&self.owner_key_generation.to_be_bytes());
        bytes.extend_from_slice(&self.owner_id);
        bytes.extend_from_slice(&self.signed_intent);
        bytes.extend_from_slice(&self.storage_request_digest);
        bytes.extend_from_slice(&self.storage_transport_digest);
        bytes.extend_from_slice(&self.storage_semantic_digest);
        bytes.extend_from_slice(&self.absence_probe_digest);
        bytes.extend_from_slice(&self.workspace_handle);
        bytes.extend_from_slice(&self.repair_operation_id);
        bytes.extend_from_slice(&self.before_catalog_generation.to_be_bytes());
        bytes.extend_from_slice(&self.signed_evidence);
        bytes.extend_from_slice(&self.signed_receipt);
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, StorageOperatorRecoveryErrorV1> {
        if bytes.len() != RECORD_BYTES
            || &bytes[..8] != MAGIC
            || bytes[8..10] != VERSION.to_be_bytes()
            || bytes[11] != 0
        {
            return Err(StorageOperatorRecoveryErrorV1::Binding);
        }
        let mut cursor = 12;
        let mut take = |length: usize| {
            let start = cursor;
            cursor += length;
            &bytes[start..cursor]
        };
        let probe_epoch = u32::from_be_bytes(
            take(4)
                .try_into()
                .map_err(|_| StorageOperatorRecoveryErrorV1::Binding)?,
        );
        let controller_key_generation = u64::from_be_bytes(
            take(8)
                .try_into()
                .map_err(|_| StorageOperatorRecoveryErrorV1::Binding)?,
        );
        let owner_key_generation = u64::from_be_bytes(
            take(8)
                .try_into()
                .map_err(|_| StorageOperatorRecoveryErrorV1::Binding)?,
        );
        let owner_id = take(16)
            .try_into()
            .map_err(|_| StorageOperatorRecoveryErrorV1::Binding)?;
        let signed_intent = take(OPERATOR_RECOVERY_EFFECT_INTENT_BYTES)
            .try_into()
            .map_err(|_| StorageOperatorRecoveryErrorV1::Binding)?;
        let storage_request_digest = take(32)
            .try_into()
            .map_err(|_| StorageOperatorRecoveryErrorV1::Binding)?;
        let storage_transport_digest = take(32)
            .try_into()
            .map_err(|_| StorageOperatorRecoveryErrorV1::Binding)?;
        let storage_semantic_digest = take(32)
            .try_into()
            .map_err(|_| StorageOperatorRecoveryErrorV1::Binding)?;
        let absence_probe_digest = take(32)
            .try_into()
            .map_err(|_| StorageOperatorRecoveryErrorV1::Binding)?;
        let workspace_handle = take(32)
            .try_into()
            .map_err(|_| StorageOperatorRecoveryErrorV1::Binding)?;
        let repair_operation_id = take(16)
            .try_into()
            .map_err(|_| StorageOperatorRecoveryErrorV1::Binding)?;
        let before_catalog_generation = u64::from_be_bytes(
            take(8)
                .try_into()
                .map_err(|_| StorageOperatorRecoveryErrorV1::Binding)?,
        );
        let signed_evidence = take(OPERATOR_RECOVERY_EFFECT_EVIDENCE_BYTES_V2)
            .try_into()
            .map_err(|_| StorageOperatorRecoveryErrorV1::Binding)?;
        let signed_receipt = take(OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES_V2)
            .try_into()
            .map_err(|_| StorageOperatorRecoveryErrorV1::Binding)?;
        Ok(Self {
            phase: bytes[10],
            probe_epoch,
            controller_key_generation,
            owner_key_generation,
            owner_id,
            signed_intent,
            storage_request_digest,
            storage_transport_digest,
            storage_semantic_digest,
            absence_probe_digest,
            workspace_handle,
            repair_operation_id,
            before_catalog_generation,
            signed_evidence,
            signed_receipt,
        })
    }
}

fn request_digest(body: &[u8]) -> [u8; 32] {
    hash(REQUEST_DOMAIN, &[body])
}

fn fence_digest(semantics: &CanonicalStorageRepairSemanticsV1) -> [u8; 32] {
    let fence = semantics.fence();
    hash(
        FENCE_DOMAIN,
        &[
            fence.sandbox_id(),
            fence.incarnation_id(),
            &fence.assignment_epoch().to_be_bytes(),
            &fence.desired_generation().to_be_bytes(),
            fence.assignment_digest(),
        ],
    )
}

fn hash(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_core::operator_recovery_effect::{
        OperatorRecoveryEffectIntentV1, sign_operator_recovery_effect_intent_v1,
    };

    fn sample() -> (StoredRepairV2, SigningKey, SigningKey) {
        let controller_key = SigningKey::from_bytes(&[1; 32]);
        let owner_key = SigningKey::from_bytes(&[2; 32]);
        let intent = OperatorRecoveryEffectIntentV1 {
            recovery_operation_id: [1; 16],
            target_id: [2; 16],
            action: OperatorRecoveryEffectActionV1::Repair,
            target_kind: OperatorRecoveryEffectTargetV1::Sandbox,
            principal_id: [3; 16],
            project_id: [4; 16],
            capability_id: [5; 16],
            expected_version_digest: [6; 32],
            evidence_digest: [7; 32],
            request_digest: [8; 32],
            authorization_digest: [9; 32],
            current_fence_digest: [10; 32],
            effect_id: [11; 32],
            attempt: 1,
            current_generation: 5,
        };
        let record = StoredRepairV2 {
            phase: PENDING,
            probe_epoch: 1,
            controller_key_generation: 1,
            owner_key_generation: 1,
            owner_id: [12; 16],
            signed_intent: sign_operator_recovery_effect_intent_v1(&intent, &controller_key)
                .expect("valid intent"),
            storage_request_digest: intent.effect_id,
            storage_transport_digest: [13; 32],
            storage_semantic_digest: [14; 32],
            absence_probe_digest: [15; 32],
            workspace_handle: [16; 32],
            repair_operation_id: intent.recovery_operation_id,
            before_catalog_generation: 2,
            signed_evidence: [0; OPERATOR_RECOVERY_EFFECT_EVIDENCE_BYTES_V2],
            signed_receipt: [0; OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES_V2],
        };
        (record, controller_key, owner_key)
    }

    #[test]
    fn sidecar_rejects_cross_role_and_altered_pending_custody() {
        let (record, controller_key, owner_key) = sample();
        let encoded = record.encode();
        assert_eq!(encoded.len(), RECORD_BYTES);
        assert_eq!(
            StoredRepairV2::decode(&encoded).expect("canonical record"),
            record
        );
        let check = |record: &StoredRepairV2| {
            validate_stored(
                record,
                &record.storage_request_digest,
                &controller_key.verifying_key(),
                &owner_key.verifying_key(),
                [12; 16],
                1,
                1,
            )
        };
        assert!(check(&record).is_ok());

        let mut altered = encoded.clone();
        altered[11] = 1;
        assert!(StoredRepairV2::decode(&altered).is_err());
        altered = encoded.clone();
        altered[10] = COMPLETE;
        assert!(check(&StoredRepairV2::decode(&altered).expect("well-framed")).is_err());
        altered = encoded.clone();
        altered[..8].copy_from_slice(b"AOSORSP1");
        assert!(StoredRepairV2::decode(&altered).is_err());
        let mut wrong_owner = record.clone();
        wrong_owner.owner_id = [17; 16];
        assert!(check(&wrong_owner).is_err());
        let mut wrong_request = record.clone();
        wrong_request.storage_request_digest = [18; 32];
        assert!(check(&wrong_request).is_err());
        let mut wrong_signature = record.clone();
        wrong_signature.signed_intent[100] ^= 1;
        assert!(check(&wrong_signature).is_err());
        assert!(
            validate_stored(
                &record,
                &record.storage_request_digest,
                &owner_key.verifying_key(),
                &controller_key.verifying_key(),
                [12; 16],
                1,
                1,
            )
            .is_err()
        );
    }

    #[test]
    fn completed_sidecar_requires_signed_probe_and_generation_binding() {
        let (mut record, controller_key, owner_key) = sample();
        let intent = verify_operator_recovery_effect_intent_v1(
            &record.signed_intent,
            &controller_key.verifying_key(),
        )
        .expect("intent");
        let before_inventory_digest = hash(
            BEFORE_DOMAIN,
            &[&record.absence_probe_digest, b"dataset-exact/pin-absent"],
        );
        let evidence = OperatorRecoveryEffectEvidenceV2 {
            intent_digest: intent.digest().expect("digest"),
            owner_id: record.owner_id,
            owner_key_generation: record.owner_key_generation,
            probe_epoch: record.probe_epoch,
            absence_probe_digest: record.absence_probe_digest,
            before_catalog_generation: record.before_catalog_generation,
            before_inventory_digest,
            effect_commit_digest: [22; 32],
            after_inventory_digest: [19; 32],
            resulting_version: [20; 32],
            after_catalog_generation: 3,
        };
        record.signed_evidence =
            sign_operator_recovery_effect_evidence_v2(&evidence, &owner_key).expect("evidence");
        let terminal = hash(
            TERMINAL_DOMAIN,
            &[
                &evidence.intent_digest,
                &evidence.after_inventory_digest,
                &evidence.resulting_version,
                &evidence.effect_commit_digest,
            ],
        );
        let receipt = OperatorRecoveryEffectReceiptV2 {
            intent_digest: evidence.intent_digest,
            owner_id: record.owner_id,
            owner_key_generation: record.owner_key_generation,
            signed_evidence_digest: evidence_digest_v2(&record.signed_evidence),
            before_inventory_digest,
            after_inventory_digest: evidence.after_inventory_digest,
            resulting_version: evidence.resulting_version,
            terminal_result_digest: terminal,
            effect_commit_digest: evidence.effect_commit_digest,
            owner_generation: 3,
        };
        record.phase = COMPLETE;
        record.signed_receipt =
            sign_operator_recovery_effect_receipt_v2(&receipt, &owner_key).expect("receipt");
        let check = |record: &StoredRepairV2| {
            validate_stored(
                record,
                &record.storage_request_digest,
                &controller_key.verifying_key(),
                &owner_key.verifying_key(),
                [12; 16],
                1,
                1,
            )
        };
        assert!(check(&record).is_ok());
        let cold = StoredRepairV2::decode(&record.encode()).expect("cold evidence record");
        assert!(check(&cold).is_ok());
        let original_request = StoredRepairV2 {
            phase: PENDING,
            probe_epoch: 1,
            signed_evidence: [0; OPERATOR_RECOVERY_EFFECT_EVIDENCE_BYTES_V2],
            signed_receipt: [0; OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES_V2],
            ..cold.clone()
        };
        assert!(matches!(
            classify_reservation(&cold, &original_request),
            Ok(StoredReservationDecisionV2::Complete(_))
        ));
        let mut changed_probe = original_request;
        changed_probe.absence_probe_digest = [24; 32];
        assert!(classify_reservation(&cold, &changed_probe).is_err());

        let mut altered = record.clone();
        altered.absence_probe_digest = [23; 32];
        assert!(check(&altered).is_err());
        altered = record.clone();
        altered.before_catalog_generation = 4;
        assert!(check(&altered).is_err());
        altered = record.clone();
        altered.signed_receipt[200] ^= 1;
        assert!(check(&altered).is_err());
        altered = record.clone();
        altered.signed_evidence[200] ^= 1;
        assert!(check(&altered).is_err());
        assert!(
            validate_stored(
                &record,
                &record.storage_request_digest,
                &controller_key.verifying_key(),
                &owner_key.verifying_key(),
                [12; 16],
                1,
                2,
            )
            .is_err()
        );
    }

    #[test]
    fn pending_probe_replacement_is_bounded_and_preserves_request_binding() {
        let (existing, _, _) = sample();
        let mut fresh = existing.clone();
        fresh.absence_probe_digest = [23; 32];
        fresh.before_catalog_generation += 1;

        assert!(matches!(
            classify_reservation(&existing, &existing),
            Ok(StoredReservationDecisionV2::Pending)
        ));
        let StoredReservationDecisionV2::Replace(replacement) =
            classify_reservation(&existing, &fresh).expect("fresh absence probe")
        else {
            panic!("a new probe must be durably reserved");
        };
        assert_eq!(replacement.probe_epoch, 2);
        assert_eq!(replacement.absence_probe_digest, fresh.absence_probe_digest);

        let mut substituted = fresh.clone();
        substituted.storage_transport_digest = [24; 32];
        assert!(classify_reservation(&existing, &substituted).is_err());
        substituted = fresh;
        substituted.repair_operation_id = [25; 16];
        assert!(classify_reservation(&existing, &substituted).is_err());

        let exhausted = StoredRepairV2 {
            probe_epoch: MAXIMUM_PROBE_EPOCH,
            ..existing
        };
        let mut next = exhausted.clone();
        next.absence_probe_digest = [26; 32];
        next.probe_epoch = 1;
        assert!(classify_reservation(&exhausted, &next).is_err());
    }
}

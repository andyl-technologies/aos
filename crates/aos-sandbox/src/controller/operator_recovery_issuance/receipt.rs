//! Protected custody for a Storage owner's repair receipt.
//!
//! Receipt custody is deliberately not public operation completion. Storage's
//! signed receipt proves its own retained repair result, but the controller
//! still needs independently read pre-effect probe and effect-commit evidence
//! before it can satisfy the stronger terminal-currentness contract.
//!
//! ```text
//! operator-recovery-storage-owner-key-v1:
//! AOSORSK1 | version:u16be=1 | reserved[6]=0 | owner-id[16]
//! owner-key-generation:u64be | ed25519-public[32]
//!
//! storage-repair-receipt-v2/<operation-id[16]>:
//! AOSORR02 | operation-id[16] | owner-id[16]
//! owner-key-generation:u64be | signed-receipt[288]
//! ```

use aos_proto::aos::sandbox::local::v1::RepairStorageWorkspacePinRequest;
use aos_sandbox_core::OperationId;
use aos_sandbox_core::operator_recovery_effect::{
    OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES, OperatorRecoveryEffectIntentV1,
    verify_operator_recovery_effect_intent_v1, verify_operator_recovery_effect_receipt_v1,
};
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodResultV1,
};
use aos_sandbox_protocol::{MAXIMUM_RESPONSE_BYTES, decode_storage_resource_inventory_response};
use buffa::Message as _;
use ed25519_dalek::VerifyingKey;

use super::{
    CURRENT_HEAD_DOMAIN_V2, OperatorRecoveryIssuanceErrorV1, ProtectedOperatorRecoverySignerV1,
    StorageRepairIssuanceV2, hash, issuance_key_v2,
};
use crate::controller::{
    ActivatedOperationCompiler, NodeController, SingleNodeEffectExecutor, recovery_current_key,
};
use crate::lifecycle::LifecycleAuthenticatedStorageInventoryV1;
use crate::public_api_session::PinnedOperatorRecoveryKeyV1;
use crate::{Journal, JournalRecord, JournalTransaction, RecordNamespace};

const OWNER_KEY_MAGIC: &[u8; 8] = b"AOSORSK1";
const OWNER_KEY_BYTES: usize = 72;
const RECEIPT_MAGIC_V2: &[u8; 8] = b"AOSORR02";
const RECEIPT_PREFIX_V2: &[u8] = b"storage-repair-receipt-v2/";
const RECEIPT_BYTES_V2: usize = 48 + OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES;
const AFTER_DOMAIN: &[u8] = b"aos.sandbox.operator-storage-repair-after.v1\0";
const TERMINAL_DOMAIN: &[u8] = b"aos.sandbox.operator-storage-repair-terminal.v1\0";
const RECEIPT_COMMIT_DOMAIN_V2: &[u8] = b"aos.sandbox.operator-storage-repair-receipt.v2\0";

/// Pins the Storage owner's independent public key and generation.
pub(crate) struct ProtectedStorageRepairReceiptVerifierV2 {
    credential: PinnedOperatorRecoveryKeyV1,
    pin: StorageOwnerPinV2,
}

#[derive(Clone, Copy)]
struct StorageOwnerPinV2 {
    owner_id: [u8; 16],
    key_generation: u64,
    verifier: VerifyingKey,
}

impl ProtectedStorageRepairReceiptVerifierV2 {
    /// Opens the fixed Storage owner trust pin from systemd credentials.
    ///
    /// # Errors
    ///
    /// Rejects absent or replaced custody, malformed key bytes, or key reuse
    /// with the controller's distinct recovery signer.
    #[allow(dead_code, reason = "operator receipt transport is not installed")]
    pub(crate) fn from_systemd_credentials(
        controller_key: &VerifyingKey,
    ) -> Result<Self, OperatorRecoveryIssuanceErrorV1> {
        let credential = PinnedOperatorRecoveryKeyV1::load_storage_owner_public()
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Key)?;
        let (owner_id, key_generation, verifier) = decode_owner_key(credential.bytes())?;
        if &verifier == controller_key {
            return Err(OperatorRecoveryIssuanceErrorV1::Key);
        }
        Ok(Self {
            credential,
            pin: StorageOwnerPinV2 {
                owner_id,
                key_generation,
                verifier,
            },
        })
    }

    fn recheck(&self) -> Result<(), OperatorRecoveryIssuanceErrorV1> {
        self.credential
            .recheck()
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Key)
    }
}

fn decode_owner_key(
    bytes: &[u8],
) -> Result<([u8; 16], u64, VerifyingKey), OperatorRecoveryIssuanceErrorV1> {
    let bytes: &[u8; OWNER_KEY_BYTES] = bytes
        .try_into()
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Key)?;
    if &bytes[..8] != OWNER_KEY_MAGIC
        || bytes[8..10] != 1_u16.to_be_bytes()
        || bytes[10..16] != [0; 6]
    {
        return Err(OperatorRecoveryIssuanceErrorV1::Key);
    }
    let owner_id: [u8; 16] = bytes[16..32]
        .try_into()
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Key)?;
    let key_generation = u64::from_be_bytes(
        bytes[32..40]
            .try_into()
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Key)?,
    );
    let public: [u8; 32] = bytes[40..72]
        .try_into()
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Key)?;
    let verifier =
        VerifyingKey::from_bytes(&public).map_err(|_| OperatorRecoveryIssuanceErrorV1::Key)?;
    if owner_id == [0; 16] || key_generation == 0 || public == [0; 32] {
        return Err(OperatorRecoveryIssuanceErrorV1::Key);
    }
    Ok((owner_id, key_generation, verifier))
}

impl<C, E> NodeController<C, E>
where
    C: ActivatedOperationCompiler,
    E: SingleNodeEffectExecutor,
{
    /// Retains an authenticated owner's exact completed repair receipt.
    ///
    /// This does not complete the public operation or advance its current head.
    /// The current accepted request and issuance must still be unchanged, and
    /// the post-effect inventory must arrive as an authenticated Storage
    /// client-received outcome. Before-effect and commit evidence remain a
    /// separate terminal barrier.
    ///
    /// # Errors
    ///
    /// Rejects stale issuance, changed current head, rotated role keys,
    /// mismatched signed receipt, nonphysical inventory, or uncertain commit.
    #[allow(dead_code, reason = "operator receipt transport is not installed")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn retain_storage_repair_receipt_v2(
        &mut self,
        signer: &ProtectedOperatorRecoverySignerV1,
        owner: &ProtectedStorageRepairReceiptVerifierV2,
        operation_id: OperationId,
        storage_request_body: &[u8],
        after: &AuthenticatedBrokerMethodOutcomeV1,
        signed_receipt: &[u8],
    ) -> Result<(), OperatorRecoveryIssuanceErrorV1> {
        signer
            .credential
            .recheck()
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Key)?;
        owner.recheck()?;
        let journal = self.reconciler.journal_mut();
        journal
            .ensure_protected_authority()
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        let key = issuance_key_v2(*operation_id.as_bytes());
        let issued = StorageRepairIssuanceV2::decode(
            &key,
            journal
                .get(RecordNamespace::OperatorRecovery, &key)
                .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?,
            signer.verifier(),
            signer.key_id(),
            signer.generation(),
        )?;
        let intent =
            verify_operator_recovery_effect_intent_v1(&issued.signed_intent, signer.verifier())
                .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        let current = journal
            .get(
                RecordNamespace::OperatorRecovery,
                &recovery_current_key(intent.target_id),
            )
            .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?;
        if hash(CURRENT_HEAD_DOMAIN_V2, &[current]) != issued.current_head_digest {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }

        let after_body = authenticated_after_body(after)?;
        validate_physical_after(
            &intent,
            storage_request_body,
            after_body,
            signed_receipt,
            &owner.pin,
        )?;
        let packet: [u8; OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES] = signed_receipt
            .try_into()
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        reserve_receipt(journal, &intent, &packet, &owner.pin)?;
        signer
            .credential
            .recheck()
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Key)?;
        owner.recheck()
    }
}

fn authenticated_after_body(
    after: &AuthenticatedBrokerMethodOutcomeV1,
) -> Result<&[u8], OperatorRecoveryIssuanceErrorV1> {
    let inventory = LifecycleAuthenticatedStorageInventoryV1::from_authenticated_outcome(after)
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    if inventory.source_version() != 3 {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    }
    let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = after.result() else {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    };
    Ok(exact_body)
}

fn validate_physical_after(
    intent: &OperatorRecoveryEffectIntentV1,
    storage_request_body: &[u8],
    after_body: &[u8],
    signed_receipt: &[u8],
    owner: &StorageOwnerPinV2,
) -> Result<(), OperatorRecoveryIssuanceErrorV1> {
    if hash(super::REQUEST_DOMAIN, &[storage_request_body]) != intent.effect_id {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    }
    let request = RepairStorageWorkspacePinRequest::decode_from_slice(storage_request_body)
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    if request.encode_to_vec() != storage_request_body
        || request.operation_id.as_slice() != intent.recovery_operation_id
        || request.storage_handle.len() != 32
    {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    }
    let fence = request
        .fence
        .as_option()
        .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?;
    let fence_digest = hash(
        super::FENCE_DOMAIN,
        &[
            &fence.sandbox_id,
            &fence.incarnation_id,
            &fence.assignment_epoch.to_be_bytes(),
            &fence.desired_generation.to_be_bytes(),
            &fence.assignment_digest,
        ],
    );
    if fence.sandbox_id.as_slice() != intent.target_id
        || fence.desired_generation != intent.current_generation
        || fence_digest != intent.current_fence_digest
    {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    }
    let inventory = decode_storage_resource_inventory_response(after_body, MAXIMUM_RESPONSE_BYTES)
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    let mut matching = inventory
        .workspaces()
        .iter()
        .filter(|workspace| workspace.workspace_handle().as_slice() == request.storage_handle);
    let workspace = matching
        .next()
        .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?;
    if matching.next().is_some()
        || workspace.fence().sandbox_id().as_slice() != fence.sandbox_id
        || workspace.fence().incarnation_id().as_slice() != fence.incarnation_id
        || workspace.fence().assignment_epoch() != fence.assignment_epoch
        || workspace.fence().desired_generation() != fence.desired_generation
        || workspace.fence().assignment_digest().as_slice() != fence.assignment_digest
    {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    }
    let terminal_digest: [u8; 32] = signed_receipt
        .get(152..184)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?;
    let receipt = verify_operator_recovery_effect_receipt_v1(
        signed_receipt,
        &owner.verifier,
        intent,
        terminal_digest,
    )
    .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    let expected_after = hash(AFTER_DOMAIN, &[after_body]);
    let expected_terminal = hash(
        TERMINAL_DOMAIN,
        &[
            &intent
                .digest()
                .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?,
            &expected_after,
            workspace.resource_digest(),
            &receipt.effect_commit_digest,
        ],
    );
    if receipt.owner_id != owner.owner_id
        || receipt.owner_generation != inventory.catalog_generation()
        || receipt.after_inventory_digest != expected_after
        || receipt.resulting_version != *workspace.resource_digest()
        || receipt.terminal_result_digest != expected_terminal
    {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StoredReceiptV2 {
    operation_id: [u8; 16],
    owner_id: [u8; 16],
    owner_key_generation: u64,
    signed_receipt: [u8; OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES],
}

impl StoredReceiptV2 {
    fn encode(&self) -> [u8; RECEIPT_BYTES_V2] {
        let mut bytes = [0; RECEIPT_BYTES_V2];
        bytes[..8].copy_from_slice(RECEIPT_MAGIC_V2);
        bytes[8..24].copy_from_slice(&self.operation_id);
        bytes[24..40].copy_from_slice(&self.owner_id);
        bytes[40..48].copy_from_slice(&self.owner_key_generation.to_be_bytes());
        bytes[48..].copy_from_slice(&self.signed_receipt);
        bytes
    }

    fn decode(
        key: &[u8],
        bytes: &[u8],
        intent: &OperatorRecoveryEffectIntentV1,
        owner: &StorageOwnerPinV2,
    ) -> Result<Self, OperatorRecoveryIssuanceErrorV1> {
        if bytes.len() != RECEIPT_BYTES_V2 || bytes.get(..8) != Some(RECEIPT_MAGIC_V2.as_slice()) {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
        let operation_id: [u8; 16] = bytes[8..24]
            .try_into()
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        let owner_id: [u8; 16] = bytes[24..40]
            .try_into()
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        let owner_key_generation = u64::from_be_bytes(
            bytes[40..48]
                .try_into()
                .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?,
        );
        let signed_receipt: [u8; OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES] =
            bytes[48..]
                .try_into()
                .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        let terminal_digest: [u8; 32] = signed_receipt[152..184]
            .try_into()
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        let receipt = verify_operator_recovery_effect_receipt_v1(
            &signed_receipt,
            &owner.verifier,
            intent,
            terminal_digest,
        )
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        let expected_terminal = hash(
            TERMINAL_DOMAIN,
            &[
                &intent
                    .digest()
                    .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?,
                &receipt.after_inventory_digest,
                &receipt.resulting_version,
                &receipt.effect_commit_digest,
            ],
        );
        if key != receipt_key(operation_id)
            || operation_id != intent.recovery_operation_id
            || owner_id != owner.owner_id
            || owner_key_generation != owner.key_generation
            || receipt.owner_id != owner_id
            || receipt.terminal_result_digest != expected_terminal
        {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
        Ok(Self {
            operation_id,
            owner_id,
            owner_key_generation,
            signed_receipt,
        })
    }
}

fn receipt_key(operation_id: [u8; 16]) -> Vec<u8> {
    [RECEIPT_PREFIX_V2, operation_id.as_slice()].concat()
}

fn reserve_receipt(
    journal: &mut Journal,
    intent: &OperatorRecoveryEffectIntentV1,
    signed_receipt: &[u8; OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES],
    owner: &StorageOwnerPinV2,
) -> Result<(), OperatorRecoveryIssuanceErrorV1> {
    journal
        .ensure_protected_authority()
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    let key = receipt_key(intent.recovery_operation_id);
    let record = StoredReceiptV2 {
        operation_id: intent.recovery_operation_id,
        owner_id: owner.owner_id,
        owner_key_generation: owner.key_generation,
        signed_receipt: *signed_receipt,
    };
    let encoded = record.encode();
    StoredReceiptV2::decode(&key, &encoded, intent, owner)?;
    if let Some(existing) = journal.get(RecordNamespace::OperatorRecovery, &key) {
        StoredReceiptV2::decode(&key, existing, intent, owner)?;
        return if existing == encoded {
            Ok(())
        } else {
            Err(OperatorRecoveryIssuanceErrorV1::Binding)
        };
    }
    let digest = hash(RECEIPT_COMMIT_DOMAIN_V2, &[&intent.recovery_operation_id]);
    let transaction_id: [u8; 16] = digest[..16]
        .try_into()
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    let transaction = JournalTransaction::new(
        transaction_id,
        vec![JournalRecord::put(
            RecordNamespace::OperatorRecovery,
            key.clone(),
            encoded.to_vec(),
        )],
    )
    .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    let _ = journal.commit(&transaction);
    if journal.get(RecordNamespace::OperatorRecovery, &key) != Some(encoded.as_slice()) {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    }
    journal
        .ensure_protected_authority()
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    use aos_sandbox_core::operator_recovery_effect::{
        OperatorRecoveryEffectActionV1, OperatorRecoveryEffectReceiptV1,
        OperatorRecoveryEffectTargetV1, sign_operator_recovery_effect_receipt_v1,
    };
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::JournalLimits;

    fn intent() -> OperatorRecoveryEffectIntentV1 {
        OperatorRecoveryEffectIntentV1 {
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
            current_generation: 12,
        }
    }

    fn signed_receipt(
        intent: &OperatorRecoveryEffectIntentV1,
        key: &SigningKey,
        commit: [u8; 32],
    ) -> [u8; OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES] {
        let after = hash(AFTER_DOMAIN, &[b"complete-after-inventory"]);
        let version = [13; 32];
        let terminal = hash(
            TERMINAL_DOMAIN,
            &[&intent.digest().unwrap(), &after, &version, &commit],
        );
        let receipt = OperatorRecoveryEffectReceiptV1 {
            intent_digest: intent.digest().unwrap(),
            owner_id: [14; 16],
            before_inventory_digest: [15; 32],
            after_inventory_digest: after,
            resulting_version: version,
            terminal_result_digest: terminal,
            effect_commit_digest: commit,
            owner_generation: 16,
        };
        sign_operator_recovery_effect_receipt_v1(&receipt, key).unwrap()
    }

    fn protected_journal() -> (tempfile::TempDir, Journal) {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let uid = fs::metadata(directory.path()).unwrap().uid();
        let (journal, _) = Journal::open_protected_at_uid(
            directory.path(),
            "operator-repair-receipts.journal",
            JournalLimits::default(),
            uid,
        )
        .unwrap();
        (directory, journal)
    }

    #[test]
    fn owner_public_pin_rejects_role_and_generation_substitution() {
        let key = SigningKey::from_bytes(&[17; 32]);
        let mut record = [0; OWNER_KEY_BYTES];
        record[..8].copy_from_slice(OWNER_KEY_MAGIC);
        record[8..10].copy_from_slice(&1_u16.to_be_bytes());
        record[16..32].copy_from_slice(&[14; 16]);
        record[32..40].copy_from_slice(&18_u64.to_be_bytes());
        record[40..72].copy_from_slice(&key.verifying_key().to_bytes());
        assert_eq!(decode_owner_key(&record).unwrap().0, [14; 16]);

        for offset in [0, 8, 10, 16, 32, 40] {
            let mut invalid = record;
            match offset {
                16 => invalid[16..32].fill(0),
                32 => invalid[32..40].fill(0),
                40 => invalid[40..72].fill(0),
                _ => invalid[offset] ^= 1,
            }
            assert!(decode_owner_key(&invalid).is_err(), "offset {offset}");
        }
    }

    #[test]
    fn receipt_custody_recovers_exact_packet_but_rejects_conflict_and_rotation() {
        let (directory, mut journal) = protected_journal();
        let signing_key = SigningKey::from_bytes(&[17; 32]);
        let pin = StorageOwnerPinV2 {
            owner_id: [14; 16],
            key_generation: 18,
            verifier: signing_key.verifying_key(),
        };
        let intent = intent();
        let first = signed_receipt(&intent, &signing_key, [19; 32]);
        assert_eq!(reserve_receipt(&mut journal, &intent, &first, &pin), Ok(()));
        assert_eq!(reserve_receipt(&mut journal, &intent, &first, &pin), Ok(()));

        let other = signed_receipt(&intent, &signing_key, [20; 32]);
        assert_eq!(
            reserve_receipt(&mut journal, &intent, &other, &pin),
            Err(OperatorRecoveryIssuanceErrorV1::Binding)
        );
        let rotated = StorageOwnerPinV2 {
            key_generation: 19,
            ..pin
        };
        assert_eq!(
            reserve_receipt(&mut journal, &intent, &first, &rotated),
            Err(OperatorRecoveryIssuanceErrorV1::Binding)
        );
        let mut changed_intent = intent;
        changed_intent.effect_id = [21; 32];
        assert_eq!(
            reserve_receipt(&mut journal, &changed_intent, &first, &pin),
            Err(OperatorRecoveryIssuanceErrorV1::Binding)
        );
        let mut altered_signature = first;
        altered_signature[OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES - 1] ^= 1;
        assert_eq!(
            reserve_receipt(&mut journal, &intent, &altered_signature, &pin),
            Err(OperatorRecoveryIssuanceErrorV1::Binding)
        );

        drop(journal);
        let uid = fs::metadata(directory.path()).unwrap().uid();
        let (mut reopened, _) = Journal::open_protected_at_uid(
            directory.path(),
            "operator-repair-receipts.journal",
            JournalLimits::default(),
            uid,
        )
        .unwrap();
        assert_eq!(
            reserve_receipt(&mut reopened, &intent, &first, &pin),
            Ok(())
        );
    }
}

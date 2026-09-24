//! Protected custody for a Storage owner's repair receipt.
//!
//! Receipt custody is deliberately not public operation completion. Storage's
//! signed receipt and separate owner evidence prove Storage's retained result,
//! but the controller still needs independently authenticated pre-effect,
//! commit, and post-inventory sources for terminal currentness.
//!
//! ```text
//! operator-recovery-storage-owner-key-v1:
//! AOSORSK1 | version:u16be=1 | reserved[6]=0 | owner-id[16]
//! owner-key-generation:u64be | ed25519-public[32]
//!
//! storage-repair-receipt-v3/<operation-id[16]>:
//! AOSOCR03 | operation-id[16] | owner-id[16]
//! owner-key-generation:u64be | signed-evidence[308]
//! signed-receipt[328]
//! ```

use aos_proto::aos::sandbox::local::v1::{
    InventoryStorageResourcesResponse, RepairStorageWorkspacePinRequest,
};
use aos_sandbox_core::OperationId;
use aos_sandbox_core::operator_recovery_effect::{
    OperatorRecoveryEffectIntentV1, verify_operator_recovery_effect_intent_v1,
};
use aos_sandbox_core::operator_recovery_effect_v2::{
    OPERATOR_RECOVERY_EFFECT_EVIDENCE_BYTES_V2, OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES_V2,
    verify_operator_recovery_effect_receipt_v2,
};
use aos_sandbox_core::operator_recovery_probe_attestation::verify_operator_recovery_probe_attestation_v1;
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodResultV1,
};
use aos_sandbox_protocol::{MAXIMUM_RESPONSE_BYTES, decode_storage_resource_inventory_response};
use buffa::Message as _;
use ed25519_dalek::VerifyingKey;
use sha2::{Digest as _, Sha256};

use super::before::{self, StoredBeforeV1};
use super::probe_challenge::{self, ProbeStageV1};
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
const RECEIPT_MAGIC_V3: &[u8; 8] = b"AOSOCR03";
const LEGACY_RECEIPT_PREFIX_V2: &[u8] = b"storage-repair-receipt-v2/";
const RECEIPT_PREFIX_V3: &[u8] = b"storage-repair-receipt-v3/";
const RECEIPT_BYTES_V3: usize =
    48 + OPERATOR_RECOVERY_EFFECT_EVIDENCE_BYTES_V2 + OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES_V2;
const BEFORE_DOMAIN: &[u8] = b"aos.sandbox.operator-storage-repair-before.v1\0";
const AFTER_DOMAIN: &[u8] = b"aos.sandbox.operator-storage-repair-after.v1\0";
const TERMINAL_DOMAIN: &[u8] = b"aos.sandbox.operator-storage-repair-terminal.v1\0";
const RECEIPT_COMMIT_DOMAIN_V3: &[u8] = b"aos.sandbox.operator-storage-repair-receipt.v3\0";

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

    pub(super) fn recheck(&self) -> Result<(), OperatorRecoveryIssuanceErrorV1> {
        self.credential
            .recheck()
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Key)
    }

    /// Authenticates the exact pre-effect probe returned before execution.
    pub(super) fn verify_wire_probe(
        &self,
        intent: &OperatorRecoveryEffectIntentV1,
        storage_request_body: &[u8],
        before_catalog_generation: u64,
        packet: &[u8],
    ) -> Result<(), OperatorRecoveryIssuanceErrorV1> {
        self.recheck()?;
        let epoch = u32::from_be_bytes(
            packet
                .get(64..68)
                .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?
                .try_into()
                .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?,
        );
        let verified = verify_operator_recovery_probe_attestation_v1(
            packet,
            &self.pin.verifier,
            self.pin.owner_id,
            self.pin.key_generation,
            intent.effect_id,
            epoch,
        )
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        let request = RepairStorageWorkspacePinRequest::decode_from_slice(storage_request_body)
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        let fence = request
            .fence
            .as_option()
            .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?;
        let request_id = request
            .header
            .as_option()
            .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?
            .request_id
            .as_slice();
        let digest: [u8; 32] = Sha256::digest(storage_request_body).into();
        if request.encode_to_vec() != storage_request_body
            || verified.repair_request_id().as_slice() != request_id
            || verified.repair_operation_id() != intent.recovery_operation_id
            || request.operation_id != intent.recovery_operation_id
            || verified.storage_request_digest() != digest
            || verified.workspace_handle().as_slice() != request.storage_handle
            || verified.assignment_digest().as_slice() != fence.assignment_digest
            || fence.sandbox_id != intent.target_id
            || fence.desired_generation != intent.current_generation
            || verified.catalog_generation() != before_catalog_generation
        {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
        self.recheck()
    }

    /// Authenticates a wire receipt without treating it as terminal currentness.
    pub(super) fn verify_wire_receipt(
        &self,
        intent: &OperatorRecoveryEffectIntentV1,
        evidence_packet: &[u8],
        receipt_packet: &[u8],
    ) -> Result<(), OperatorRecoveryIssuanceErrorV1> {
        self.recheck()?;
        let terminal_digest: [u8; 32] = receipt_packet
            .get(192..224)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?;
        let (receipt, evidence) = verify_operator_recovery_effect_receipt_v2(
            receipt_packet,
            evidence_packet,
            &self.pin.verifier,
            intent,
            self.pin.owner_id,
            self.pin.key_generation,
            terminal_digest,
        )
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        let expected_terminal = hash(
            TERMINAL_DOMAIN,
            &[
                &intent
                    .digest()
                    .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?,
                &evidence.after_inventory_digest,
                &evidence.resulting_version,
                &evidence.effect_commit_digest,
            ],
        );
        if evidence.before_inventory_digest
            != hash(
                BEFORE_DOMAIN,
                &[&evidence.absence_probe_digest, b"dataset-exact/pin-absent"],
            )
            || receipt.terminal_result_digest != expected_terminal
        {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
        self.recheck()
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
    pub(crate) fn retain_storage_repair_receipt_v3(
        &mut self,
        signer: &ProtectedOperatorRecoverySignerV1,
        owner: &ProtectedStorageRepairReceiptVerifierV2,
        operation_id: OperationId,
        storage_request_body: &[u8],
        before: &AuthenticatedBrokerMethodOutcomeV1,
        after: &AuthenticatedBrokerMethodOutcomeV1,
        signed_probe_attestation: &[u8],
        signed_evidence: &[u8],
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

        let retained_before = before::read(journal, &issued, intent.effect_id)?;
        retained_before.matches_outcome(before)?;
        let pair_digest = hash(
            b"aos.sandbox.operator-storage-repair-signed-pair.v2\0",
            &[signed_evidence, signed_receipt],
        );
        probe_challenge::read(
            journal,
            &issued,
            intent.effect_id,
            ProbeStageV1::After,
            pair_digest,
        )?
        .matches_outcome(after)?;
        let before_body = authenticated_after_body(before)?;
        let after_body = authenticated_after_body(after)?;
        validate_physical_after(
            &intent,
            storage_request_body,
            before,
            before_body,
            &retained_before,
            after,
            after_body,
            signed_probe_attestation,
            signed_evidence,
            signed_receipt,
            &owner.pin,
        )?;
        let evidence_packet: [u8; OPERATOR_RECOVERY_EFFECT_EVIDENCE_BYTES_V2] = signed_evidence
            .try_into()
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        let receipt_packet: [u8; OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES_V2] = signed_receipt
            .try_into()
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        reserve_receipt(
            journal,
            &intent,
            &evidence_packet,
            &receipt_packet,
            &owner.pin,
        )?;
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
    before: &AuthenticatedBrokerMethodOutcomeV1,
    before_body: &[u8],
    retained_before: &StoredBeforeV1,
    after: &AuthenticatedBrokerMethodOutcomeV1,
    after_body: &[u8],
    signed_probe_attestation: &[u8],
    signed_evidence: &[u8],
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
    let before_inventory =
        decode_storage_resource_inventory_response(before_body, MAXIMUM_RESPONSE_BYTES)
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    let inventory = decode_storage_resource_inventory_response(after_body, MAXIMUM_RESPONSE_BYTES)
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    if before.request().session_binding() != retained_before.session_binding()
        || after.request().session_binding() != retained_before.session_binding()
        || after.request().client_sequence() <= retained_before.client_sequence()
        || after.broker_sequence() <= retained_before.broker_sequence()
        || inventory.catalog_generation() < before_inventory.catalog_generation()
        || before_inventory
            .workspaces()
            .iter()
            .any(|workspace| workspace.workspace_handle().as_slice() == request.storage_handle)
        || before_inventory
            .operator_repair_commits()
            .iter()
            .any(|commit| commit.operation_id() == &intent.recovery_operation_id)
    {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    }
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
        .get(192..224)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?;
    let (receipt, evidence) = verify_operator_recovery_effect_receipt_v2(
        signed_receipt,
        signed_evidence,
        &owner.verifier,
        intent,
        owner.owner_id,
        owner.key_generation,
        terminal_digest,
    )
    .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    let attestation = verify_operator_recovery_probe_attestation_v1(
        signed_probe_attestation,
        &owner.verifier,
        owner.owner_id,
        owner.key_generation,
        intent.effect_id,
        evidence.probe_epoch,
    )
    .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    let request_digest: [u8; 32] = Sha256::digest(storage_request_body).into();
    let request_id = request
        .header
        .as_option()
        .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?
        .request_id
        .as_slice();
    if attestation.probe_digest() != evidence.absence_probe_digest
        || attestation.repair_request_id().as_slice() != request_id
        || attestation.repair_operation_id() != intent.recovery_operation_id
        || attestation.storage_request_digest() != request_digest
        || attestation.assignment_digest().as_slice() != fence.assignment_digest
        || attestation.workspace_handle().as_slice() != request.storage_handle
        || attestation.catalog_generation() != retained_before.catalog_generation()
        || attestation.catalog_generation() != evidence.before_catalog_generation
        || attestation.dataset_guid() != workspace.dataset_guid()
    {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    }
    let expected_after = hash(AFTER_DOMAIN, &[&core_storage_inventory(after_body)?]);
    let mut matching_commits = inventory
        .operator_repair_commits()
        .iter()
        .filter(|commit| commit.operation_id() == &intent.recovery_operation_id);
    let commit = matching_commits
        .next()
        .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?;
    if matching_commits.next().is_some()
        || commit.workspace_handle().as_slice() != request.storage_handle
        || commit.request_digest() != &request_digest
        || commit.effect_commit_digest() != &evidence.effect_commit_digest
    {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    }
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
    if receipt.owner_generation != inventory.catalog_generation()
        || receipt.after_inventory_digest != expected_after
        || receipt.resulting_version != *workspace.resource_digest()
        || receipt.terminal_result_digest != expected_terminal
        || evidence.before_inventory_digest
            != hash(
                BEFORE_DOMAIN,
                &[&evidence.absence_probe_digest, b"dataset-exact/pin-absent"],
            )
        || evidence.before_catalog_generation > inventory.catalog_generation()
        || evidence.before_catalog_generation != retained_before.catalog_generation()
    {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    }
    Ok(())
}

fn core_storage_inventory(signed_body: &[u8]) -> Result<Vec<u8>, OperatorRecoveryIssuanceErrorV1> {
    let mut inventory = InventoryStorageResourcesResponse::decode_from_slice(signed_body)
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    if inventory.encode_to_vec() != signed_body {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    }
    // The installed service adds guest-root publication proof after the
    // runtime's owner receipt readback. Remove only that optional extension;
    // all physical workspace, catalog, and Repair commit rows remain exact.
    for workspace in &mut inventory.workspaces {
        workspace.guest_root_publication_proof.clear();
    }
    let core = inventory.encode_to_vec();
    decode_storage_resource_inventory_response(&core, MAXIMUM_RESPONSE_BYTES)
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    Ok(core)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StoredReceiptV3 {
    operation_id: [u8; 16],
    owner_id: [u8; 16],
    owner_key_generation: u64,
    signed_evidence: [u8; OPERATOR_RECOVERY_EFFECT_EVIDENCE_BYTES_V2],
    signed_receipt: [u8; OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES_V2],
}

impl StoredReceiptV3 {
    fn encode(&self) -> [u8; RECEIPT_BYTES_V3] {
        let mut bytes = [0; RECEIPT_BYTES_V3];
        bytes[..8].copy_from_slice(RECEIPT_MAGIC_V3);
        bytes[8..24].copy_from_slice(&self.operation_id);
        bytes[24..40].copy_from_slice(&self.owner_id);
        bytes[40..48].copy_from_slice(&self.owner_key_generation.to_be_bytes());
        bytes[48..48 + OPERATOR_RECOVERY_EFFECT_EVIDENCE_BYTES_V2]
            .copy_from_slice(&self.signed_evidence);
        bytes[48 + OPERATOR_RECOVERY_EFFECT_EVIDENCE_BYTES_V2..]
            .copy_from_slice(&self.signed_receipt);
        bytes
    }

    fn decode(
        key: &[u8],
        bytes: &[u8],
        intent: &OperatorRecoveryEffectIntentV1,
        owner: &StorageOwnerPinV2,
    ) -> Result<Self, OperatorRecoveryIssuanceErrorV1> {
        if bytes.len() != RECEIPT_BYTES_V3 || bytes.get(..8) != Some(RECEIPT_MAGIC_V3.as_slice()) {
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
        let signed_evidence: [u8; OPERATOR_RECOVERY_EFFECT_EVIDENCE_BYTES_V2] = bytes
            [48..48 + OPERATOR_RECOVERY_EFFECT_EVIDENCE_BYTES_V2]
            .try_into()
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        let signed_receipt: [u8; OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES_V2] = bytes
            [48 + OPERATOR_RECOVERY_EFFECT_EVIDENCE_BYTES_V2..]
            .try_into()
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        let terminal_digest: [u8; 32] = signed_receipt[192..224]
            .try_into()
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        let (receipt, evidence) = verify_operator_recovery_effect_receipt_v2(
            &signed_receipt,
            &signed_evidence,
            &owner.verifier,
            intent,
            owner.owner_id,
            owner.key_generation,
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
            || receipt.terminal_result_digest != expected_terminal
            || evidence.before_inventory_digest
                != hash(
                    BEFORE_DOMAIN,
                    &[&evidence.absence_probe_digest, b"dataset-exact/pin-absent"],
                )
        {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
        Ok(Self {
            operation_id,
            owner_id,
            owner_key_generation,
            signed_evidence,
            signed_receipt,
        })
    }
}

fn receipt_key(operation_id: [u8; 16]) -> Vec<u8> {
    [RECEIPT_PREFIX_V3, operation_id.as_slice()].concat()
}

fn reserve_receipt(
    journal: &mut Journal,
    intent: &OperatorRecoveryEffectIntentV1,
    signed_evidence: &[u8; OPERATOR_RECOVERY_EFFECT_EVIDENCE_BYTES_V2],
    signed_receipt: &[u8; OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES_V2],
    owner: &StorageOwnerPinV2,
) -> Result<(), OperatorRecoveryIssuanceErrorV1> {
    journal
        .ensure_protected_authority()
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    let legacy_key = [
        LEGACY_RECEIPT_PREFIX_V2,
        intent.recovery_operation_id.as_slice(),
    ]
    .concat();
    if journal
        .get(RecordNamespace::OperatorRecovery, &legacy_key)
        .is_some()
    {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    }
    let key = receipt_key(intent.recovery_operation_id);
    let record = StoredReceiptV3 {
        operation_id: intent.recovery_operation_id,
        owner_id: owner.owner_id,
        owner_key_generation: owner.key_generation,
        signed_evidence: *signed_evidence,
        signed_receipt: *signed_receipt,
    };
    let encoded = record.encode();
    StoredReceiptV3::decode(&key, &encoded, intent, owner)?;
    if let Some(existing) = journal.get(RecordNamespace::OperatorRecovery, &key) {
        StoredReceiptV3::decode(&key, existing, intent, owner)?;
        return if existing == encoded {
            Ok(())
        } else {
            Err(OperatorRecoveryIssuanceErrorV1::Binding)
        };
    }
    let digest = hash(RECEIPT_COMMIT_DOMAIN_V3, &[&intent.recovery_operation_id]);
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
        OperatorRecoveryEffectActionV1, OperatorRecoveryEffectTargetV1,
    };
    use aos_sandbox_core::operator_recovery_effect_v2::{
        OperatorRecoveryEffectEvidenceV2, OperatorRecoveryEffectReceiptV2, evidence_digest_v2,
        sign_operator_recovery_effect_evidence_v2, sign_operator_recovery_effect_receipt_v2,
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

    fn signed_completion(
        intent: &OperatorRecoveryEffectIntentV1,
        key: &SigningKey,
        commit: [u8; 32],
    ) -> (
        [u8; OPERATOR_RECOVERY_EFFECT_EVIDENCE_BYTES_V2],
        [u8; OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES_V2],
    ) {
        let after = hash(AFTER_DOMAIN, &[b"complete-after-inventory"]);
        let before = hash(BEFORE_DOMAIN, &[&[23; 32], b"dataset-exact/pin-absent"]);
        let version = [13; 32];
        let terminal = hash(
            TERMINAL_DOMAIN,
            &[&intent.digest().unwrap(), &after, &version, &commit],
        );
        let evidence = OperatorRecoveryEffectEvidenceV2 {
            intent_digest: intent.digest().unwrap(),
            owner_id: [14; 16],
            owner_key_generation: 18,
            probe_epoch: 1,
            absence_probe_digest: [23; 32],
            before_catalog_generation: 15,
            before_inventory_digest: before,
            effect_commit_digest: commit,
            after_inventory_digest: after,
            resulting_version: version,
            after_catalog_generation: 16,
        };
        let signed_evidence = sign_operator_recovery_effect_evidence_v2(&evidence, key).unwrap();
        let receipt = OperatorRecoveryEffectReceiptV2 {
            intent_digest: evidence.intent_digest,
            owner_id: evidence.owner_id,
            owner_key_generation: evidence.owner_key_generation,
            signed_evidence_digest: evidence_digest_v2(&signed_evidence),
            before_inventory_digest: evidence.before_inventory_digest,
            after_inventory_digest: evidence.after_inventory_digest,
            resulting_version: evidence.resulting_version,
            terminal_result_digest: terminal,
            effect_commit_digest: commit,
            owner_generation: 16,
        };
        (
            signed_evidence,
            sign_operator_recovery_effect_receipt_v2(&receipt, key).unwrap(),
        )
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
        let first = signed_completion(&intent, &signing_key, [19; 32]);
        assert_eq!(
            reserve_receipt(&mut journal, &intent, &first.0, &first.1, &pin),
            Ok(())
        );
        assert_eq!(
            reserve_receipt(&mut journal, &intent, &first.0, &first.1, &pin),
            Ok(())
        );

        let other = signed_completion(&intent, &signing_key, [20; 32]);
        assert_eq!(
            reserve_receipt(&mut journal, &intent, &other.0, &other.1, &pin),
            Err(OperatorRecoveryIssuanceErrorV1::Binding)
        );
        let rotated = StorageOwnerPinV2 {
            key_generation: 19,
            ..pin
        };
        assert_eq!(
            reserve_receipt(&mut journal, &intent, &first.0, &first.1, &rotated),
            Err(OperatorRecoveryIssuanceErrorV1::Binding)
        );
        let mut changed_intent = intent;
        changed_intent.effect_id = [21; 32];
        assert_eq!(
            reserve_receipt(&mut journal, &changed_intent, &first.0, &first.1, &pin),
            Err(OperatorRecoveryIssuanceErrorV1::Binding)
        );
        let mut altered_signature = first.1;
        altered_signature[OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES_V2 - 1] ^= 1;
        assert_eq!(
            reserve_receipt(&mut journal, &intent, &first.0, &altered_signature, &pin),
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
            reserve_receipt(&mut reopened, &intent, &first.0, &first.1, &pin),
            Ok(())
        );

        let legacy_key = [
            LEGACY_RECEIPT_PREFIX_V2,
            intent.recovery_operation_id.as_slice(),
        ]
        .concat();
        let legacy = JournalTransaction::new(
            [44; 16],
            vec![JournalRecord::put(
                RecordNamespace::OperatorRecovery,
                legacy_key,
                b"old-format-custody".to_vec(),
            )],
        )
        .unwrap();
        reopened.commit(&legacy).unwrap();
        assert_eq!(
            reserve_receipt(&mut reopened, &intent, &first.0, &first.1, &pin),
            Err(OperatorRecoveryIssuanceErrorV1::Binding)
        );
    }
}

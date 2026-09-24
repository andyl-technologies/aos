//! Protected controller signing and exact Storage repair request binding.
//!
//! This module has no public admission route. A protected selector joins an
//! accepted public operation to one row of authenticated physical Storage
//! inventory and the exact Storage request before signing. Issuance is recorded
//! separately from legacy recovery IDs. The signer rechecks its fixed systemd
//! credential before and after every signature.
//!
//! ```text
//! operator-recovery-controller-key-v1:
//! AOSORCK1 | version:u16be=1 | reserved[6]=0 | key-id[16]
//! key-generation:u64be | ed25519-public[32] | ed25519-seed[32]
//!
//! storage-repair-v2/<operation-id[16]>:
//! AOSORV02 | operation-id[16] | public-request-digest[32]
//! current-head-digest[32] | inventory-commitment[32] | inventory-head[32]
//! inventory-generation:u64be | controller-key-id[16]
//! controller-key-generation:u64be | signed-intent[364]
//! ```

use aos_proto::aos::sandbox::v1::{OperatorRecoveryAction, OperatorRecoveryRequest};
use aos_sandbox_core::operator_recovery_effect::{
    OPERATOR_RECOVERY_EFFECT_INTENT_BYTES, OperatorRecoveryEffectActionV1,
    OperatorRecoveryEffectIntentV1, OperatorRecoveryEffectTargetV1,
    sign_operator_recovery_effect_intent_v1, verify_operator_recovery_effect_intent_v1,
};
use aos_sandbox_core::{
    CapabilityId, ObjectDigest, OperationId, ResourceId, ResourceKind, Selector,
};
use aos_sandbox_protocol::semantics::storage_repair::CanonicalStorageRepairSemanticsV1;
use aos_sandbox_protocol::{PeerCredentials, PeerPolicy};
use buffa::Message as _;
use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use super::{
    ActivatedOperationCompiler, NodeController, OperatorRecoveryRequestV1, PublicApiAuditMethodV1,
    SingleNodeEffectExecutor, decode_recovery_current, recovery_current_key,
    validate_recovery_current,
};
use crate::cli_model::{DormantSandboxRequestKindV1, PublicMutationRequestV1};
use crate::lifecycle::{
    LifecycleAuthenticatedStorageInventoryV1, LifecycleResourceV1, LifecycleStorageInventoryKindV1,
};
use crate::public_api_session::{PinnedOperatorRecoveryKeyV1, PublicApiPeer};
use crate::{
    IdempotencyKey, IdempotencyOutcome, Journal, JournalRecord, JournalTransaction, RecordNamespace,
};

const KEY_MAGIC: &[u8; 8] = b"AOSORCK1";
const KEY_VERSION: u16 = 1;
const KEY_BYTES: usize = 104;
const REQUEST_DOMAIN: &[u8] = b"aos.sandbox.operator-storage-repair-request.v1\0";
const FENCE_DOMAIN: &[u8] = b"aos.sandbox.operator-storage-repair-fence.v1\0";
const VERSION_DOMAIN: &[u8] = b"aos.sandbox.operator-recovery-expected-version.v1\0";
const EVIDENCE_DOMAIN: &[u8] = b"aos.sandbox.operator-recovery-evidence.v1\0";
const AUTHORIZATION_DOMAIN: &[u8] = b"aos.sandbox.operator-recovery-authorization.v1\0";
const ISSUANCE_MAGIC_V2: &[u8; 8] = b"AOSORV02";
const ISSUANCE_PREFIX_V2: &[u8] = b"storage-repair-v2/";
const ISSUANCE_COMMIT_DOMAIN_V2: &[u8] = b"aos.sandbox.operator-storage-repair-issuance.v2\0";
const CURRENT_HEAD_DOMAIN_V2: &[u8] = b"aos.sandbox.operator-storage-repair-current-head.v2\0";
const ISSUANCE_BYTES_V2: usize = 184 + OPERATOR_RECOVERY_EFFECT_INTENT_BYTES;

mod receipt;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum OperatorRecoveryIssuanceErrorV1 {
    #[error("protected operator recovery signing key is unavailable")]
    Key,
    #[error("operator repair authorization, issuance, or Storage binding is invalid")]
    Binding,
}

/// Holds the dedicated controller key without exposing its signing seed.
pub(crate) struct ProtectedOperatorRecoverySignerV1 {
    credential: PinnedOperatorRecoveryKeyV1,
    key_id: [u8; 16],
    generation: u64,
    verifier: VerifyingKey,
    seed: Zeroizing<[u8; 32]>,
}

impl ProtectedOperatorRecoverySignerV1 {
    /// Opens the fixed protected key and checks its independent Storage trust pin.
    pub(crate) fn from_systemd_credentials(
        storage_owner_key: &VerifyingKey,
    ) -> Result<Self, OperatorRecoveryIssuanceErrorV1> {
        let credential = PinnedOperatorRecoveryKeyV1::load()
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Key)?;
        let (key_id, generation, verifier, seed) = decode_key(credential.bytes())?;
        if &verifier == storage_owner_key {
            return Err(OperatorRecoveryIssuanceErrorV1::Key);
        }
        Ok(Self {
            credential,
            key_id,
            generation,
            verifier,
            seed,
        })
    }

    /// Returns the key that Storage must pin independently of its owner key.
    pub(crate) const fn verifier(&self) -> &VerifyingKey {
        &self.verifier
    }

    /// Returns the key generation that Storage must retain with its sidecar.
    pub(crate) const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the fixed nonzero controller recovery key identity.
    pub(crate) const fn key_id(&self) -> [u8; 16] {
        self.key_id
    }

    fn sign(
        &self,
        intent: &OperatorRecoveryEffectIntentV1,
    ) -> Result<[u8; OPERATOR_RECOVERY_EFFECT_INTENT_BYTES], OperatorRecoveryIssuanceErrorV1> {
        self.credential
            .recheck()
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Key)?;
        let signing_key = SigningKey::from_bytes(&self.seed);
        let packet = sign_operator_recovery_effect_intent_v1(intent, &signing_key)
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        self.credential
            .recheck()
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Key)?;
        Ok(packet)
    }
}

fn decode_key(
    bytes: &[u8],
) -> Result<([u8; 16], u64, VerifyingKey, Zeroizing<[u8; 32]>), OperatorRecoveryIssuanceErrorV1> {
    let bytes: &[u8; KEY_BYTES] = bytes
        .try_into()
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Key)?;
    if &bytes[..8] != KEY_MAGIC
        || bytes[8..10] != KEY_VERSION.to_be_bytes()
        || bytes[10..16] != [0; 6]
    {
        return Err(OperatorRecoveryIssuanceErrorV1::Key);
    }
    let key_id: [u8; 16] = bytes[16..32]
        .try_into()
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Key)?;
    let generation = u64::from_be_bytes(
        bytes[32..40]
            .try_into()
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Key)?,
    );
    let public: [u8; 32] = bytes[40..72]
        .try_into()
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Key)?;
    let seed = Zeroizing::new(
        bytes[72..104]
            .try_into()
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Key)?,
    );
    let verifier =
        VerifyingKey::from_bytes(&public).map_err(|_| OperatorRecoveryIssuanceErrorV1::Key)?;
    if key_id == [0; 16]
        || generation == 0
        || *seed == [0; 32]
        || SigningKey::from_bytes(&seed).verifying_key() != verifier
    {
        return Err(OperatorRecoveryIssuanceErrorV1::Key);
    }
    Ok((key_id, generation, verifier, seed))
}

/// Selects the unique protected physical workspace for a public repair.
pub(crate) struct ProtectedStorageRepairSelectionV1 {
    operation_id: OperationId,
    sandbox_id: [u8; 16],
    desired_generation: u64,
    workspace_handle: [u8; 32],
    current_fence_digest: [u8; 32],
    inventory_commitment: ObjectDigest,
    inventory_head: ObjectDigest,
    inventory_generation: u64,
}

impl ProtectedStorageRepairSelectionV1 {
    /// Selects one dataset row from a complete authenticated Storage inventory.
    ///
    /// # Errors
    ///
    /// Rejects a legacy catalog, absent or ambiguous workspace, a mismatched
    /// operation or assignment fence, or an invalid protected generation.
    fn from_authenticated_inventory(
        inventory: &LifecycleAuthenticatedStorageInventoryV1,
        operation_id: OperationId,
        sandbox_id: [u8; 16],
        desired_generation: u64,
        semantics: &CanonicalStorageRepairSemanticsV1,
    ) -> Result<Self, OperatorRecoveryIssuanceErrorV1> {
        let fence = semantics.fence();
        if inventory.source_version() != 3
            || inventory.generation() == 0
            || inventory.head().as_bytes() == &[0; 32]
            || operation_id.as_bytes() == &[0; 16]
            || sandbox_id == [0; 16]
            || desired_generation == 0
            || semantics.operation_id() != *operation_id.as_bytes()
            || fence.sandbox_id() != &sandbox_id
            || fence.desired_generation() != desired_generation
        {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
        let resource =
            LifecycleResourceV1::Sandbox(aos_sandbox_core::SandboxId::from_bytes(sandbox_id));
        let mut matching = inventory.entries().iter().filter(|entry| {
            entry.kind() == LifecycleStorageInventoryKindV1::Dataset && entry.resource() == resource
        });
        let workspace = matching
            .next()
            .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?;
        if matching.next().is_some()
            || workspace.effect_subject().as_bytes() != semantics.storage_handle().as_bytes()
        {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
        Ok(Self {
            operation_id,
            sandbox_id,
            desired_generation,
            workspace_handle: *workspace.effect_subject().as_bytes(),
            current_fence_digest: storage_fence_digest(semantics),
            inventory_commitment: inventory.commitment(),
            inventory_head: inventory.head(),
            inventory_generation: inventory.generation(),
        })
    }
}

impl<C, E> NodeController<C, E>
where
    C: ActivatedOperationCompiler,
    E: SingleNodeEffectExecutor,
{
    /// Reserves a version-2 Storage repair intent under an accepted public operation.
    ///
    /// The public compiler still rejects Repair. When that compiler gains a
    /// protected selector and authenticated Storage transport, this method
    /// requires their accepted operation and signed complete inventory before
    /// returning any signed packet. The Storage broker separately authenticates
    /// its plan, lease, current assignment, and fresh absent-pin probe.
    ///
    /// # Errors
    ///
    /// Rejects absent or changed public admission, stale authorization or
    /// current head, ambiguous Storage selection, or uncertain journal commit.
    #[allow(dead_code, reason = "public Storage repair transport is not installed")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn reserve_storage_repair_intent_v2(
        &mut self,
        signer: &ProtectedOperatorRecoverySignerV1,
        public_peer: &PublicApiPeer,
        capability_id: CapabilityId,
        public_operation_id: OperationId,
        canonical_public_request: &[u8],
        public_request_body: &[u8],
        storage_request_body: &[u8],
        storage_peer: PeerCredentials,
        storage_policy: PeerPolicy,
        now_boottime_nanoseconds: u64,
        inventory: &LifecycleAuthenticatedStorageInventoryV1,
    ) -> Result<[u8; OPERATOR_RECOVERY_EFFECT_INTENT_BYTES], OperatorRecoveryIssuanceErrorV1> {
        let public_digest = self
            .checked_public_request_digest(public_peer, canonical_public_request)
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        let envelope = PublicMutationRequestV1::decode(canonical_public_request)
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        let DormantSandboxRequestKindV1::OperatorRecover(enveloped) = envelope
            .decode_validated_kind()
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?
        else {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        };
        let request = decode_public_request(public_request_body)?;
        if envelope.method() != PublicApiAuditMethodV1::OperatorRecover
            || envelope.protobuf_body() != public_request_body
            || request
                != OperatorRecoveryRequestV1::try_from(enveloped)
                    .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?
            || request.action() != OperatorRecoveryAction::OPERATOR_RECOVERY_ACTION_REPAIR as i32
        {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
        let journal = self.reconciler.journal_mut();
        journal
            .ensure_protected_authority()
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        let idempotency = IdempotencyKey::new(request.idempotency_key().to_vec())
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        if journal.check_idempotency(&idempotency, public_digest)
            != IdempotencyOutcome::Replay(public_operation_id)
            || !crate::reconciler::public_operation_resource_from_journal_v1(
                journal,
                public_operation_id,
            )
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?
            .is_some_and(|operation| operation.method == "operator.recover")
        {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
        let current_bytes = journal
            .get(
                RecordNamespace::OperatorRecovery,
                &recovery_current_key(request.resource_id()),
            )
            .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?
            .to_vec();
        let current = decode_recovery_current(&current_bytes)
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        validate_recovery_current(&request, &current_bytes)
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        if current.kind != 1 {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }

        let selector = Selector::Resource {
            resource: ResourceId::from_bytes(request.resource_id()),
        };
        let authorized = super::authorize_public_operator_recovery_v1(
            journal,
            public_peer,
            capability_id,
            ResourceKind::Sandbox,
            selector,
            public_request_body,
        )
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        let provenance = authorized.provenance();
        let (principal, authorization, _, canonical_request, _) = provenance.commitments();
        if principal.digest().as_bytes() == &[0; 32] {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
        let semantics = CanonicalStorageRepairSemanticsV1::decode(
            storage_request_body,
            storage_peer,
            storage_policy,
            now_boottime_nanoseconds,
        )
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        let selected = ProtectedStorageRepairSelectionV1::from_authenticated_inventory(
            inventory,
            public_operation_id,
            request.resource_id(),
            current.desired_generation,
            &semantics,
        )?;
        let authorization_digest = hash(
            AUTHORIZATION_DOMAIN,
            &[
                authorization.digest().as_bytes(),
                canonical_request.digest().as_bytes(),
                capability_id.as_bytes(),
                &authorized.policy_generation().to_be_bytes(),
                &authorized.accepted_wall_seconds().to_be_bytes(),
            ],
        );
        let intent = map_storage_repair_intent(
            &request,
            public_peer,
            capability_id,
            public_digest,
            authorization_digest,
            &semantics,
            storage_request_body,
            &selected,
        )?;
        let packet = signer.sign(&intent)?;
        reserve_issued_storage_repair_v2(
            journal,
            signer.verifier(),
            signer.key_id(),
            signer.generation(),
            &intent,
            &selected,
            public_digest,
            &current_bytes,
            &packet,
        )?;
        public_peer
            .recheck()
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        Ok(packet)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StorageRepairIssuanceV2 {
    operation_id: [u8; 16],
    public_request_digest: [u8; 32],
    current_head_digest: [u8; 32],
    inventory_commitment: [u8; 32],
    inventory_head: [u8; 32],
    inventory_generation: u64,
    controller_key_id: [u8; 16],
    controller_key_generation: u64,
    signed_intent: [u8; OPERATOR_RECOVERY_EFFECT_INTENT_BYTES],
}

impl StorageRepairIssuanceV2 {
    fn encode(&self) -> [u8; ISSUANCE_BYTES_V2] {
        let mut bytes = [0; ISSUANCE_BYTES_V2];
        let mut cursor = 0;
        let inventory_generation = self.inventory_generation.to_be_bytes();
        let controller_key_generation = self.controller_key_generation.to_be_bytes();
        for field in [
            ISSUANCE_MAGIC_V2.as_slice(),
            self.operation_id.as_slice(),
            self.public_request_digest.as_slice(),
            self.current_head_digest.as_slice(),
            self.inventory_commitment.as_slice(),
            self.inventory_head.as_slice(),
            inventory_generation.as_slice(),
            self.controller_key_id.as_slice(),
            controller_key_generation.as_slice(),
            self.signed_intent.as_slice(),
        ] {
            bytes[cursor..cursor + field.len()].copy_from_slice(field);
            cursor += field.len();
        }
        bytes
    }

    fn decode(
        key: &[u8],
        bytes: &[u8],
        controller_key: &VerifyingKey,
        key_id: [u8; 16],
        key_generation: u64,
    ) -> Result<Self, OperatorRecoveryIssuanceErrorV1> {
        if bytes.len() != ISSUANCE_BYTES_V2 || bytes.get(..8) != Some(ISSUANCE_MAGIC_V2.as_slice())
        {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
        let record = Self {
            operation_id: take_array(bytes, 8)?,
            public_request_digest: take_array(bytes, 24)?,
            current_head_digest: take_array(bytes, 56)?,
            inventory_commitment: take_array(bytes, 88)?,
            inventory_head: take_array(bytes, 120)?,
            inventory_generation: u64::from_be_bytes(take_array(bytes, 152)?),
            controller_key_id: take_array(bytes, 160)?,
            controller_key_generation: u64::from_be_bytes(take_array(bytes, 176)?),
            signed_intent: take_array(bytes, 184)?,
        };
        let intent =
            verify_operator_recovery_effect_intent_v1(&record.signed_intent, controller_key)
                .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        if key != issuance_key_v2(record.operation_id)
            || record.controller_key_id != key_id
            || record.controller_key_generation != key_generation
            || record.operation_id == [0; 16]
            || record.public_request_digest == [0; 32]
            || record.current_head_digest == [0; 32]
            || record.inventory_commitment == [0; 32]
            || record.inventory_head == [0; 32]
            || record.inventory_generation == 0
            || intent.recovery_operation_id != record.operation_id
            || intent.request_digest != record.public_request_digest
            || intent.action != OperatorRecoveryEffectActionV1::Repair
            || intent.target_kind != OperatorRecoveryEffectTargetV1::Sandbox
            || intent.attempt != 1
            || record.encode().as_slice() != bytes
        {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
        Ok(record)
    }
}

fn take_array<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], OperatorRecoveryIssuanceErrorV1> {
    bytes
        .get(offset..offset + N)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)
}

fn issuance_key_v2(operation_id: [u8; 16]) -> Vec<u8> {
    [ISSUANCE_PREFIX_V2, operation_id.as_slice()].concat()
}

#[allow(clippy::too_many_arguments)]
fn reserve_issued_storage_repair_v2(
    journal: &mut Journal,
    controller_key: &VerifyingKey,
    key_id: [u8; 16],
    key_generation: u64,
    intent: &OperatorRecoveryEffectIntentV1,
    selected: &ProtectedStorageRepairSelectionV1,
    public_request_digest: [u8; 32],
    current_head: &[u8],
    signed_intent: &[u8; OPERATOR_RECOVERY_EFFECT_INTENT_BYTES],
) -> Result<(), OperatorRecoveryIssuanceErrorV1> {
    journal
        .ensure_protected_authority()
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    let key = issuance_key_v2(intent.recovery_operation_id);
    let record = StorageRepairIssuanceV2 {
        operation_id: intent.recovery_operation_id,
        public_request_digest,
        current_head_digest: hash(CURRENT_HEAD_DOMAIN_V2, &[current_head]),
        inventory_commitment: *selected.inventory_commitment.as_bytes(),
        inventory_head: *selected.inventory_head.as_bytes(),
        inventory_generation: selected.inventory_generation,
        controller_key_id: key_id,
        controller_key_generation: key_generation,
        signed_intent: *signed_intent,
    };
    let encoded = record.encode();
    StorageRepairIssuanceV2::decode(&key, &encoded, controller_key, key_id, key_generation)?;

    // A corrupt or foreign v2 row poisons issuance before any new signature
    // can be released. Legacy AOSORI1 idempotency rows are a distinct format.
    for (stored_key, stored) in journal.records(RecordNamespace::OperatorRecovery) {
        if stored_key.starts_with(ISSUANCE_PREFIX_V2) {
            StorageRepairIssuanceV2::decode(
                stored_key,
                stored,
                controller_key,
                key_id,
                key_generation,
            )?;
        }
    }
    if let Some(existing) = journal.get(RecordNamespace::OperatorRecovery, &key) {
        return if existing == encoded {
            Ok(())
        } else {
            Err(OperatorRecoveryIssuanceErrorV1::Binding)
        };
    }
    let digest = hash(
        ISSUANCE_COMMIT_DOMAIN_V2,
        &[&intent.recovery_operation_id, &intent.effect_id],
    );
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
    let committed = journal.commit(&transaction).is_ok();
    if journal.get(RecordNamespace::OperatorRecovery, &key) != Some(encoded.as_slice()) {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    }
    // Exact readback resolves a lost acknowledgment. No second attempt or
    // substituted packet is authorized by the same operation identity.
    if !committed {
        journal
            .ensure_protected_authority()
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    }
    Ok(())
}

fn decode_public_request(
    body: &[u8],
) -> Result<OperatorRecoveryRequestV1, OperatorRecoveryIssuanceErrorV1> {
    let proto = OperatorRecoveryRequest::decode_from_slice(body)
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    if proto.encode_to_vec() != body {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    }
    OperatorRecoveryRequestV1::try_from(proto).map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)
}

#[allow(clippy::too_many_arguments)]
fn map_storage_repair_intent(
    request: &OperatorRecoveryRequestV1,
    public_peer: &PublicApiPeer,
    capability_id: CapabilityId,
    request_digest: [u8; 32],
    authorization_digest: [u8; 32],
    semantics: &CanonicalStorageRepairSemanticsV1,
    storage_request_body: &[u8],
    selected: &ProtectedStorageRepairSelectionV1,
) -> Result<OperatorRecoveryEffectIntentV1, OperatorRecoveryIssuanceErrorV1> {
    let fence = semantics.fence();
    let actual_fence_digest = storage_fence_digest(semantics);
    let storage_effect_id = hash(REQUEST_DOMAIN, &[storage_request_body]);
    if request.action() != OperatorRecoveryAction::OPERATOR_RECOVERY_ACTION_REPAIR as i32
        || selected.operation_id.as_bytes() != &semantics.operation_id()
        || selected.sandbox_id != request.resource_id()
        || selected.sandbox_id != *fence.sandbox_id()
        || selected.desired_generation != fence.desired_generation()
        || selected.workspace_handle != *semantics.storage_handle().as_bytes()
        || selected.current_fence_digest != actual_fence_digest
        || request_digest == [0; 32]
        || authorization_digest == [0; 32]
    {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    }
    let version_digest = hash(
        VERSION_DOMAIN,
        &[
            &(request.expected_resource_version().len() as u64).to_be_bytes(),
            request.expected_resource_version(),
        ],
    );
    let evidence_digest = hash(EVIDENCE_DOMAIN, &[&request.evidence().encode_to_vec()]);
    let intent = OperatorRecoveryEffectIntentV1 {
        recovery_operation_id: *selected.operation_id.as_bytes(),
        target_id: request.resource_id(),
        action: OperatorRecoveryEffectActionV1::Repair,
        target_kind: OperatorRecoveryEffectTargetV1::Sandbox,
        principal_id: *public_peer.principal().as_bytes(),
        project_id: *public_peer.project().as_bytes(),
        capability_id: *capability_id.as_bytes(),
        expected_version_digest: version_digest,
        evidence_digest,
        request_digest,
        authorization_digest,
        current_fence_digest: actual_fence_digest,
        effect_id: storage_effect_id,
        attempt: 1,
        current_generation: selected.desired_generation,
    };
    intent
        .validate()
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    Ok(intent)
}

fn storage_fence_digest(semantics: &CanonicalStorageRepairSemanticsV1) -> [u8; 32] {
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
    let mut digest = Sha256::new();
    digest.update(domain);
    for part in parts {
        digest.update(part);
    }
    digest.finalize().into()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    use crate::JournalLimits;

    use super::*;

    fn key_record() -> [u8; KEY_BYTES] {
        let seed = [7; 32];
        let mut bytes = [0; KEY_BYTES];
        bytes[..8].copy_from_slice(KEY_MAGIC);
        bytes[8..10].copy_from_slice(&KEY_VERSION.to_be_bytes());
        bytes[16..32].copy_from_slice(&[1; 16]);
        bytes[32..40].copy_from_slice(&1_u64.to_be_bytes());
        bytes[40..72].copy_from_slice(&SigningKey::from_bytes(&seed).verifying_key().to_bytes());
        bytes[72..104].copy_from_slice(&seed);
        bytes
    }

    #[test]
    fn dedicated_key_record_rejects_all_identity_and_secret_substitutions() {
        let valid = key_record();
        assert!(decode_key(&valid).is_ok());

        for position in [0, 8, 10, 16, 32, 40, 72] {
            let mut changed = valid;
            changed[position] ^= 1;
            if position == 16 || position == 32 {
                // Nonzero key identity and generation are intentionally rotatable.
                assert!(decode_key(&changed).is_ok());
            } else {
                assert!(decode_key(&changed).is_err(), "changed byte {position}");
            }
        }
        for field in [16..32, 32..40, 72..104] {
            let mut changed = valid;
            changed[field].fill(0);
            assert!(decode_key(&changed).is_err());
        }
    }

    #[test]
    fn exact_storage_body_changes_effect_identity() {
        let first = hash(REQUEST_DOMAIN, &[b"repair-body-a"]);
        let second = hash(REQUEST_DOMAIN, &[b"repair-body-b"]);
        assert_ne!(first, second);
        let dormant_effect_id = hash(
            b"aos.sandbox.operator-recovery-effect.v1\0",
            &[b"repair-body-a"],
        );
        assert_ne!(first, dormant_effect_id);
    }

    fn repair_intent() -> OperatorRecoveryEffectIntentV1 {
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
            effect_id: hash(REQUEST_DOMAIN, &[b"exact-storage-request"]),
            attempt: 1,
            current_generation: 11,
        }
    }

    fn repair_selection() -> ProtectedStorageRepairSelectionV1 {
        ProtectedStorageRepairSelectionV1 {
            operation_id: OperationId::from_bytes([1; 16]),
            sandbox_id: [2; 16],
            desired_generation: 11,
            workspace_handle: [12; 32],
            current_fence_digest: [10; 32],
            inventory_commitment: ObjectDigest::from_bytes([13; 32]),
            inventory_head: ObjectDigest::from_bytes([14; 32]),
            inventory_generation: 15,
        }
    }

    fn protected_journal() -> (tempfile::TempDir, Journal) {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let uid = fs::metadata(directory.path()).unwrap().uid();
        let (journal, _) = Journal::open_protected_at_uid(
            directory.path(),
            "operator-repair.journal",
            JournalLimits::default(),
            uid,
        )
        .unwrap();
        (directory, journal)
    }

    #[test]
    fn v2_issuance_replays_only_exact_public_and_current_heads() {
        let (directory, mut journal) = protected_journal();
        let signer = SigningKey::from_bytes(&[7; 32]);
        let verifier = signer.verifying_key();
        let intent = repair_intent();
        let selection = repair_selection();
        let packet = sign_operator_recovery_effect_intent_v1(&intent, &signer).unwrap();

        let reserve = |journal: &mut Journal, public_digest, current_head: &[u8]| {
            reserve_issued_storage_repair_v2(
                journal,
                &verifier,
                [16; 16],
                17,
                &intent,
                &selection,
                public_digest,
                current_head,
                &packet,
            )
        };
        assert_eq!(
            reserve(&mut journal, intent.request_digest, b"current-a"),
            Ok(())
        );
        assert_eq!(
            reserve(&mut journal, intent.request_digest, b"current-a"),
            Ok(())
        );
        assert_eq!(
            reserve(&mut journal, intent.request_digest, b"current-b"),
            Err(OperatorRecoveryIssuanceErrorV1::Binding)
        );
        assert_eq!(
            reserve(&mut journal, [18; 32], b"current-a"),
            Err(OperatorRecoveryIssuanceErrorV1::Binding)
        );

        let key = issuance_key_v2(intent.recovery_operation_id);
        let saved = journal
            .get(RecordNamespace::OperatorRecovery, &key)
            .unwrap()
            .to_vec();
        assert!(StorageRepairIssuanceV2::decode(&key, &saved, &verifier, [16; 16], 17).is_ok());
        assert_eq!(saved.len(), ISSUANCE_BYTES_V2);

        drop(journal);
        let uid = fs::metadata(directory.path()).unwrap().uid();
        let (reopened, _) = Journal::open_protected_at_uid(
            directory.path(),
            "operator-repair.journal",
            JournalLimits::default(),
            uid,
        )
        .unwrap();
        assert_eq!(
            reopened.get(RecordNamespace::OperatorRecovery, &key),
            Some(saved.as_slice())
        );
    }

    #[test]
    fn v2_decoder_rejects_legacy_magic_and_signed_packet_substitution() {
        let signer = SigningKey::from_bytes(&[7; 32]);
        let verifier = signer.verifying_key();
        let intent = repair_intent();
        let packet = sign_operator_recovery_effect_intent_v1(&intent, &signer).unwrap();
        let key = issuance_key_v2(intent.recovery_operation_id);
        let record = StorageRepairIssuanceV2 {
            operation_id: intent.recovery_operation_id,
            public_request_digest: intent.request_digest,
            current_head_digest: [19; 32],
            inventory_commitment: [13; 32],
            inventory_head: [14; 32],
            inventory_generation: 15,
            controller_key_id: [16; 16],
            controller_key_generation: 17,
            signed_intent: packet,
        };
        let valid = record.encode();
        assert!(StorageRepairIssuanceV2::decode(&key, &valid, &verifier, [16; 16], 17).is_ok());

        let mut legacy = valid;
        legacy[..8].copy_from_slice(b"AOSORI1\0");
        assert!(StorageRepairIssuanceV2::decode(&key, &legacy, &verifier, [16; 16], 17).is_err());

        let mut altered_packet = valid;
        altered_packet[ISSUANCE_BYTES_V2 - 1] ^= 1;
        assert!(
            StorageRepairIssuanceV2::decode(&key, &altered_packet, &verifier, [16; 16], 17)
                .is_err()
        );
    }
}

//! Protected controller signing and exact Storage repair request binding.
//!
//! This module has no public admission route. A future protected workspace
//! selector must construct [`ProtectedStorageRepairSelectionV1`] from current
//! assignment and workspace state before the controller can sign an effect.
//! The signer itself is a separate fixed systemd credential and rechecks its
//! inode and bytes for every signature.
//!
//! ```text
//! operator-recovery-controller-key-v1:
//! AOSORCK1 | version:u16be=1 | reserved[6]=0 | key-id[16]
//! key-generation:u64be | ed25519-public[32] | ed25519-seed[32]
//! ```

use aos_proto::aos::sandbox::v1::{OperatorRecoveryAction, OperatorRecoveryRequest};
use aos_sandbox_core::operator_recovery_effect::{
    OPERATOR_RECOVERY_EFFECT_INTENT_BYTES, OperatorRecoveryEffectActionV1,
    OperatorRecoveryEffectIntentV1, OperatorRecoveryEffectTargetV1,
    sign_operator_recovery_effect_intent_v1,
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
    DormantOperatorRecoveryEffectHandoffV1, DormantOperatorRecoveryOwnerV1,
    OperatorRecoveryRequestV1, decode_recovery_current, validate_recovery_current,
};
use crate::public_api_session::{PinnedOperatorRecoveryKeyV1, PublicApiPeer};

const KEY_MAGIC: &[u8; 8] = b"AOSORCK1";
const KEY_VERSION: u16 = 1;
const KEY_BYTES: usize = 104;
const REQUEST_DOMAIN: &[u8] = b"aos.sandbox.operator-storage-repair-request.v1\0";
const FENCE_DOMAIN: &[u8] = b"aos.sandbox.operator-storage-repair-fence.v1\0";
const VERSION_DOMAIN: &[u8] = b"aos.sandbox.operator-recovery-expected-version.v1\0";
const EVIDENCE_DOMAIN: &[u8] = b"aos.sandbox.operator-recovery-evidence.v1\0";
const AUTHORIZATION_DOMAIN: &[u8] = b"aos.sandbox.operator-recovery-authorization.v1\0";

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

/// A future protected selector must prove this one workspace and operation.
///
/// No constructor exists while the controller lacks an authenticated current
/// workspace inventory. Its private fields prevent a public request or a
/// caller-selected Storage handle from becoming signing authority.
#[allow(dead_code, reason = "protected workspace selection is not installed")]
pub(crate) struct ProtectedStorageRepairSelectionV1 {
    operation_id: OperationId,
    sandbox_id: [u8; 16],
    desired_generation: u64,
    workspace_handle: [u8; 32],
    current_fence_digest: [u8; 32],
}

impl DormantOperatorRecoveryOwnerV1<'_> {
    /// Signs only a durably issued Repair with fresh public authorization and
    /// a previously selected protected workspace and Storage fence.
    ///
    /// # Errors
    ///
    /// Rejects changed journal state, stale public authority, noncanonical
    /// request bytes, a different Storage repair target, or changed key custody.
    #[allow(dead_code, reason = "protected workspace selection is not installed")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn issue_storage_repair_intent(
        &mut self,
        signer: &ProtectedOperatorRecoverySignerV1,
        handoff: &DormantOperatorRecoveryEffectHandoffV1,
        public_peer: &PublicApiPeer,
        capability_id: CapabilityId,
        public_request_body: &[u8],
        storage_request_body: &[u8],
        storage_peer: PeerCredentials,
        storage_policy: PeerPolicy,
        now_boottime_nanoseconds: u64,
        selected: &ProtectedStorageRepairSelectionV1,
    ) -> Result<[u8; OPERATOR_RECOVERY_EFFECT_INTENT_BYTES], OperatorRecoveryIssuanceErrorV1> {
        self.recheck_effect_handoff(handoff)
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        let request = decode_public_request(public_request_body)?;
        if request != handoff.issued.request {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
        let current = decode_recovery_current(&handoff.issued.current)
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        validate_recovery_current(&request, &handoff.issued.current)
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        if current.kind != 1
            || request.action() != OperatorRecoveryAction::OPERATOR_RECOVERY_ACTION_REPAIR as i32
        {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }

        let selector = Selector::Resource {
            resource: ResourceId::from_bytes(request.resource_id()),
        };
        let authorized = super::authorize_public_operator_recovery_v1(
            self.journal,
            public_peer,
            capability_id,
            ResourceKind::Sandbox,
            selector,
            public_request_body,
        )
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        let provenance = authorized.provenance();
        let (principal, authorization, _, canonical_request, _) = provenance.commitments();
        if principal.digest() != handoff.issued.principal
            || public_peer.principal().as_bytes() == &[0; 16]
        {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
        let semantics = CanonicalStorageRepairSemanticsV1::decode(
            storage_request_body,
            storage_peer,
            storage_policy,
            now_boottime_nanoseconds,
        )
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
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
            handoff,
            &request,
            public_peer,
            capability_id,
            *canonical_request.digest().as_bytes(),
            authorization_digest,
            &semantics,
            storage_request_body,
            selected,
        )?;
        self.recheck_effect_handoff(handoff)
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        let packet = signer.sign(&intent)?;
        self.recheck_effect_handoff(handoff)
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        Ok(packet)
    }
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
    handoff: &DormantOperatorRecoveryEffectHandoffV1,
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
    let actual_fence_digest = hash(
        FENCE_DOMAIN,
        &[
            fence.sandbox_id(),
            fence.incarnation_id(),
            &fence.assignment_epoch().to_be_bytes(),
            &fence.desired_generation().to_be_bytes(),
            fence.assignment_digest(),
        ],
    );
    let storage_effect_id =
        checked_storage_effect_id(handoff.issued.effect_id, storage_request_body)?;
    if request.action() != OperatorRecoveryAction::OPERATOR_RECOVERY_ACTION_REPAIR as i32
        || selected.operation_id.as_bytes() != &semantics.operation_id()
        || selected.sandbox_id != request.resource_id()
        || selected.sandbox_id != *fence.sandbox_id()
        || selected.desired_generation != handoff.issued.current_generation
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
        attempt: handoff.issued.attempt,
        current_generation: handoff.issued.current_generation,
    };
    intent
        .validate()
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    Ok(intent)
}

fn checked_storage_effect_id(
    durable_effect_id: ObjectDigest,
    storage_request_body: &[u8],
) -> Result<[u8; 32], OperatorRecoveryIssuanceErrorV1> {
    let storage_effect_id = hash(REQUEST_DOMAIN, &[storage_request_body]);
    // The signed intent cannot substitute Storage's request identity for the
    // protected issuance identity. The dormant owner currently derives a
    // different ID, so this gate stays closed until that owner is migrated.
    if durable_effect_id.as_bytes() != &storage_effect_id {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    }
    Ok(storage_effect_id)
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
        assert_eq!(
            checked_storage_effect_id(ObjectDigest::from_bytes(first), b"repair-body-a"),
            Ok(first)
        );
        assert_eq!(
            checked_storage_effect_id(ObjectDigest::from_bytes(first), b"repair-body-b"),
            Err(OperatorRecoveryIssuanceErrorV1::Binding)
        );
        let dormant_effect_id = hash(
            b"aos.sandbox.operator-recovery-effect.v1\0",
            &[b"repair-body-a"],
        );
        assert_eq!(
            checked_storage_effect_id(
                ObjectDigest::from_bytes(dormant_effect_id),
                b"repair-body-a"
            ),
            Err(OperatorRecoveryIssuanceErrorV1::Binding)
        );
    }
}

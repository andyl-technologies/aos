//! Release-evidence envelopes signed through the configured external signer.
//!
//! Qualification reviews, completion approvals, and fitness attestations are
//! `aos.hub.signed-release-evidence/v1` envelopes: an Ed25519 signature by a
//! release-evidence key over the domain-separated digest of the canonical
//! payload. The porcelain obtains that signature from `[signer] executable`
//! with a raw-payload request (the pattern static surfaces use for receipts)
//! and verifies the finished envelope before returning it.
//!
//! The request names the artifact kind (`qualification-review`,
//! `completion-receipt`, or `fitness-attestation`) so provider policy can
//! audit what it signs. The core accepts exactly the kinds in
//! `aos_release::signing::RELEASE_EVIDENCE_ARTIFACT_KINDS`, which also lists
//! `profile-override` for override envelopes signed outside the porcelain.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Result, bail};
use aos_release::canonical;
use aos_release::digest::Sha256Digest;
use aos_release::receipt::{
    RECEIPT_SIGNATURE_DOMAIN, SIGNED_RECEIPT, SignedReceiptEnvelope, verify_signed_receipt_with_key,
};
use aos_release::signing::{
    SIGNING_REQUEST_DOMAIN, SignatureAlgorithm, SignerRole, SigningContext, SigningOperation,
    SigningRequest, TrustedEd25519Key,
};
use serde::Serialize;

use super::super::capture;
use super::super::config::{MaintainerConfig, RoleKey};
use super::super::signer::ExternalSigner;

/// Request identity fields of one release-evidence signature.
pub(super) struct EvidenceScope<'a> {
    /// Registry the evidence belongs to.
    pub(super) registry: &'a str,
    /// Release (or fitness exercise) identity bound by the request.
    pub(super) release_id: &'a str,
    /// Plan digest, or the identity the evidence binds when no plan applies.
    pub(super) plan_digest: Sha256Digest,
    /// Final manifest digest, when one exists.
    pub(super) manifest_digest: Option<Sha256Digest>,
    /// Provider policy revision of the release-evidence role.
    pub(super) provider_revision: &'a str,
    /// Restricted operator policy digest the provider approves under.
    pub(super) approval_policy_digest: Sha256Digest,
    /// Closed artifact kind named in the request context.
    pub(super) artifact_kind: &'a str,
}

/// Signs `payload` as a release-evidence envelope with `key`.
///
/// # Errors
/// Returns an error when the public key cannot be read, the signer rejects
/// or fails the request, or the returned signature does not verify over the
/// exact envelope.
pub(super) async fn sign<T: Serialize>(
    config: &MaintainerConfig,
    key: &RoleKey,
    scope: &EvidenceScope<'_>,
    payload: &T,
) -> Result<Vec<u8>> {
    let trusted = TrustedEd25519Key::from_encoded(
        &key.key_id,
        &capture::control_file(&key.public_key, "release-evidence public key")?,
    )?;
    let canonical_payload = canonical::to_vec(payload)?;
    let digest = Sha256Digest::separated(RECEIPT_SIGNATURE_DOMAIN, &canonical_payload);
    let nonce = hex::encode(rand::random::<[u8; 32]>());
    let request = SigningRequest {
        schema_version: SIGNING_REQUEST_DOMAIN.to_owned(),
        request_id: format!("{}-{}", scope.artifact_kind, &nonce[..24]),
        nonce,
        registry: scope.registry.to_owned(),
        release_id: scope.release_id.to_owned(),
        plan_digest: scope.plan_digest,
        manifest_digest: scope.manifest_digest,
        role: SignerRole::ReleaseEvidence,
        key_id: key.key_id.clone(),
        provider_revision: scope.provider_revision.to_owned(),
        algorithm: SignatureAlgorithm::Ed25519Payload,
        operation: SigningOperation::SignPayload,
        context: SigningContext::Payload {
            artifact_kind: scope.artifact_kind.to_owned(),
        },
        payload_digest: Sha256Digest::of_bytes(digest.as_bytes()),
        approval_policy_digest: scope.approval_policy_digest,
    };
    let signer = ExternalSigner::new(config.signer.executable.clone(), config.signer.timeout())?;
    let response = signer
        .sign_ed25519_payload(
            &request,
            digest.as_bytes(),
            &trusted,
            &key.verification_identity,
        )
        .await?;

    let envelope = SignedReceiptEnvelope {
        schema_version: SIGNED_RECEIPT.to_owned(),
        key_id: key.key_id.clone(),
        payload: serde_json::to_value(payload)?,
        signature_base64: response.signature_base64,
    };
    let bytes = canonical::to_vec(&envelope)?;
    let keys = BTreeMap::from([(key.key_id.clone(), trusted.public_key)]);
    let (_, verified): (String, serde_json::Value) = verify_signed_receipt_with_key(&bytes, &keys)?;
    if verified != serde_json::to_value(payload)? {
        bail!("release-evidence signer changed the signed payload");
    }
    Ok(bytes)
}

/// Returns the release-evidence key `[reviewer]` names, with its provider identity.
///
/// The reviewer key must be one of the configured release-evidence role keys
/// so its verification identity is pinned by the same table the plan froze.
///
/// # Errors
/// Returns an error when `[reviewer]` is absent, names a key the
/// release-evidence role does not list, or points at a different public key.
pub(super) fn reviewer_key(config: &MaintainerConfig) -> Result<RoleKey> {
    let reviewer = config
        .reviewer
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("maintainer configuration has no [reviewer] key"))?;
    let key = super::keys::find(config, SignerRole::ReleaseEvidence, &reviewer.key_id)?;
    if !same_file(&key.public_key, &reviewer.public_key) {
        bail!(
            "[reviewer] public key differs from release-evidence key {}",
            reviewer.key_id
        );
    }
    Ok(key)
}

fn same_file(left: &Path, right: &Path) -> bool {
    left == right
        || matches!(
            (std::fs::canonicalize(left), std::fs::canonicalize(right)),
            (Ok(left), Ok(right)) if left == right
        )
}

//! Deployment-owned signing and qualification-verification port.
//!
//! The Hub database stores only public signed envelopes. Deployment shells
//! provide this port from restricted runtime configuration or an external KMS;
//! release RPCs fail closed when it is absent.

use std::collections::BTreeMap;

use anyhow::{bail, Context as _, Result};
use aos_release::receipt::{ChannelReceiptV1, PublicationReceiptV1, QualificationReceiptV1};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::backend::BackendBounds;

/// Canonical public evidence returned by a deployment signing authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedReleaseEvidence {
    /// SHA-256 identity of the complete canonical signed envelope.
    pub digest: String,
    /// Complete canonical signed envelope encoded as UTF-8 JSON.
    pub envelope_json: String,
}

/// Restricted deployment authority for release receipts.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait ReleaseEvidenceAuthority: BackendBounds {
    /// Returns the immutable identity of the deployment using this authority.
    fn deployment_id(&self) -> &str;

    /// Issues an environment publication receipt.
    ///
    /// # Errors
    ///
    /// Returns an error when provider policy rejects the payload or signing
    /// fails. Implementations must return canonical JSON and its exact digest.
    async fn issue_publication(
        &self,
        receipt: &PublicationReceiptV1,
    ) -> Result<SignedReleaseEvidence>;

    /// Verifies externally signed qualification evidence against pinned policy.
    ///
    /// # Errors
    ///
    /// Returns an error for an untrusted authority, invalid signature, or an
    /// envelope that does not contain the exact receipt.
    async fn verify_qualification(
        &self,
        receipt: &QualificationReceiptV1,
        envelope_json: &str,
    ) -> Result<()>;

    /// Issues a compare-and-swap channel receipt.
    ///
    /// # Errors
    ///
    /// Returns an error when provider policy rejects the operation or signing
    /// fails. Implementations must return canonical JSON and its exact digest.
    async fn issue_channel(&self, receipt: &ChannelReceiptV1) -> Result<SignedReleaseEvidence>;
}

const SIGNED_RECEIPT_V1: &str = "aos.hub.signed-release-evidence/v1";
const RECEIPT_SIGNATURE_DOMAIN: &str = "aos.hub.release-evidence-signature/v1";

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SignedReceiptEnvelope {
    schema_version: String,
    key_id: String,
    payload: serde_json::Value,
    signature_base64: String,
}

/// In-process Ed25519 adapter over deployment-injected secret material.
///
/// The adapter signs only closed receipt structs; it is not a generic content
/// signing oracle. Release-content and qualification keys remain public-only.
pub struct Ed25519ReleaseEvidenceAuthority {
    deployment_id: String,
    key_id: String,
    signing_key: SigningKey,
    qualification_keys: BTreeMap<String, VerifyingKey>,
}

impl Ed25519ReleaseEvidenceAuthority {
    /// Builds an authority from one receipt key and pinned qualification keys.
    ///
    /// # Errors
    ///
    /// Returns an error unless the signing seed and every public key are exact
    /// 32-byte standard-base64 Ed25519 material and identities are non-empty.
    pub fn from_base64(
        deployment_id: impl Into<String>,
        key_id: impl Into<String>,
        signing_seed_base64: &str,
        qualification_keys_base64: BTreeMap<String, String>,
    ) -> Result<Self> {
        let deployment_id = deployment_id.into();
        let key_id = key_id.into();
        if deployment_id.is_empty() || key_id.is_empty() {
            bail!("release evidence deployment and key identities are required");
        }
        let seed = decode_key(signing_seed_base64, "release receipt signing seed")?;
        let signing_key = SigningKey::from_bytes(&seed);
        let mut qualification_keys = BTreeMap::new();
        for (qualifier_id, encoded) in qualification_keys_base64 {
            if qualifier_id.is_empty() {
                bail!("qualification key id is empty");
            }
            let bytes = decode_key(&encoded, "qualification public key")?;
            let key =
                VerifyingKey::from_bytes(&bytes).context("parsing qualification public key")?;
            qualification_keys.insert(qualifier_id, key);
        }
        Ok(Self {
            deployment_id,
            key_id,
            signing_key,
            qualification_keys,
        })
    }

    fn issue<T: Serialize>(&self, payload: &T) -> Result<SignedReleaseEvidence> {
        let payload_bytes = aos_release::canonical::to_vec(payload)?;
        let digest =
            aos_release::digest::Sha256Digest::separated(RECEIPT_SIGNATURE_DOMAIN, &payload_bytes);
        let signature = self.signing_key.sign(digest.as_bytes());
        let envelope = SignedReceiptEnvelope {
            schema_version: SIGNED_RECEIPT_V1.into(),
            key_id: self.key_id.clone(),
            payload: serde_json::from_slice(&payload_bytes)?,
            signature_base64: STANDARD.encode(signature.to_bytes()),
        };
        let bytes = aos_release::canonical::to_vec(&envelope)?;
        Ok(SignedReleaseEvidence {
            digest: aos_release::digest::Sha256Digest::of_bytes(&bytes).to_string(),
            envelope_json: String::from_utf8(bytes).context("encoding signed release evidence")?,
        })
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl ReleaseEvidenceAuthority for Ed25519ReleaseEvidenceAuthority {
    fn deployment_id(&self) -> &str {
        &self.deployment_id
    }

    async fn issue_publication(
        &self,
        receipt: &PublicationReceiptV1,
    ) -> Result<SignedReleaseEvidence> {
        receipt.validate()?;
        self.issue(receipt)
    }

    async fn verify_qualification(
        &self,
        receipt: &QualificationReceiptV1,
        envelope_json: &str,
    ) -> Result<()> {
        receipt.validate()?;
        let envelope: SignedReceiptEnvelope =
            aos_release::canonical::from_slice(envelope_json.as_bytes(), "qualification envelope")?;
        if envelope.schema_version != SIGNED_RECEIPT_V1
            || aos_release::canonical::to_vec(&envelope)? != envelope_json.as_bytes()
            || aos_release::canonical::to_vec(&envelope.payload)?
                != aos_release::canonical::to_vec(receipt)?
        {
            bail!("qualification envelope is noncanonical or has the wrong payload");
        }
        let key = self
            .qualification_keys
            .get(&envelope.key_id)
            .context("qualification signer is not trusted")?;
        let signature_bytes = STANDARD
            .decode(&envelope.signature_base64)
            .context("decoding qualification signature")?;
        let signature =
            Signature::from_slice(&signature_bytes).context("parsing qualification signature")?;
        let payload = aos_release::canonical::to_vec(receipt)?;
        let digest =
            aos_release::digest::Sha256Digest::separated(RECEIPT_SIGNATURE_DOMAIN, payload);
        key.verify(digest.as_bytes(), &signature)
            .context("verifying qualification signature")
    }

    async fn issue_channel(&self, receipt: &ChannelReceiptV1) -> Result<SignedReleaseEvidence> {
        receipt.validate()?;
        self.issue(receipt)
    }
}

fn decode_key(encoded: &str, label: &str) -> Result<[u8; 32]> {
    STANDARD
        .decode(encoded)
        .with_context(|| format!("decoding {label}"))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("{label} must be exactly 32 bytes"))
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use aos_release::digest::Sha256Digest;
    use aos_release::evidence::GateResult;

    fn authority() -> Ed25519ReleaseEvidenceAuthority {
        let seed = [7_u8; 32];
        let public = SigningKey::from_bytes(&seed).verifying_key();
        Ed25519ReleaseEvidenceAuthority::from_base64(
            "staging-deployment",
            "hub-receipt",
            &STANDARD.encode(seed),
            BTreeMap::from([("qualifier".into(), STANDARD.encode(public.as_bytes()))]),
        )
        .unwrap()
    }

    fn qualification() -> QualificationReceiptV1 {
        QualificationReceiptV1 {
            schema_version: "aos.release.qualification-receipt/v1".into(),
            staging_receipt_digest: Sha256Digest::of_bytes(b"staging"),
            manifest_digest: Sha256Digest::of_bytes(b"manifest"),
            policy_id: "production-policy-v1".into(),
            policy_digest: Sha256Digest::of_bytes(b"policy"),
            result: GateResult::Passed,
            report_digest: Sha256Digest::of_bytes(b"report"),
            authority_id: "qualifier".into(),
            nonce: "a".repeat(64),
            qualified_at: "2026-03-01T00:00:00Z".into(),
        }
    }

    #[tokio::test]
    async fn qualification_envelope_is_canonical_and_signature_bound() {
        let authority = authority();
        let receipt = qualification();
        let mut envelope: SignedReceiptEnvelope =
            serde_json::from_str(&authority.issue(&receipt).unwrap().envelope_json).unwrap();
        envelope.key_id = "qualifier".into();
        let payload = aos_release::canonical::to_vec(&receipt).unwrap();
        let digest = Sha256Digest::separated(RECEIPT_SIGNATURE_DOMAIN, payload);
        envelope.signature_base64 =
            STANDARD.encode(authority.signing_key.sign(digest.as_bytes()).to_bytes());
        let envelope =
            String::from_utf8(aos_release::canonical::to_vec(&envelope).unwrap()).unwrap();

        authority
            .verify_qualification(&receipt, &envelope)
            .await
            .unwrap();
        let mut changed = receipt;
        changed.report_digest = Sha256Digest::of_bytes(b"changed");
        assert!(authority
            .verify_qualification(&changed, &envelope)
            .await
            .is_err());
    }
}

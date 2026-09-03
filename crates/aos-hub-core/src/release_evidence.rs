//! Deployment-owned signing and qualification-verification port.
//!
//! The Hub database stores only public signed envelopes. Deployment shells
//! provide this port from restricted runtime configuration or an external KMS;
//! release RPCs fail closed when it is absent.

use std::collections::BTreeMap;

use anyhow::{bail, Context as _, Result};
use aos_release::receipt::{
    verify_signed_receipt_with_key, ChannelReceiptV1, PublicationReceiptV1, QualificationReceiptV1,
};
use aos_release::receipt::{SignedReceiptEnvelopeV1, RECEIPT_SIGNATURE_DOMAIN, SIGNED_RECEIPT_V1};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use serde::Serialize;

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

    /// Verifies a publication receipt issued by a trusted Hub deployment.
    ///
    /// # Errors
    ///
    /// Returns an error for an untrusted deployment key, invalid signature, or
    /// an envelope that does not contain the exact receipt.
    async fn verify_publication(
        &self,
        receipt: &PublicationReceiptV1,
        envelope_json: &str,
    ) -> Result<()>;

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

/// In-process Ed25519 adapter over deployment-injected secret material.
///
/// The adapter signs only closed receipt structs; it is not a generic content
/// signing oracle. Release-content and qualification keys remain public-only.
pub struct Ed25519ReleaseEvidenceAuthority {
    deployment_id: String,
    publication_key_id: String,
    publication_signing_key: SigningKey,
    channel_key_id: String,
    channel_signing_key: SigningKey,
    publication_keys: BTreeMap<String, [u8; 32]>,
    qualification_keys: BTreeMap<String, [u8; 32]>,
}

impl Ed25519ReleaseEvidenceAuthority {
    /// Builds an authority from one receipt key and role-separated trust roots.
    ///
    /// # Errors
    ///
    /// Returns an error unless the signing seed and every publication or
    /// qualification public key are exact 32-byte standard-base64 Ed25519
    /// material and identities are non-empty.
    pub fn from_base64(
        deployment_id: impl Into<String>,
        publication_key_id: impl Into<String>,
        publication_signing_seed_base64: &str,
        channel_key_id: impl Into<String>,
        channel_signing_seed_base64: &str,
        publication_keys_base64: BTreeMap<String, String>,
        qualification_keys_base64: BTreeMap<String, String>,
    ) -> Result<Self> {
        let deployment_id = deployment_id.into();
        let publication_key_id = publication_key_id.into();
        let channel_key_id = channel_key_id.into();
        if deployment_id.is_empty() || publication_key_id.is_empty() || channel_key_id.is_empty() {
            bail!("release evidence deployment and role key identities are required");
        }
        if publication_key_id == channel_key_id {
            bail!("publication and channel receipt key identities must differ");
        }
        let publication_seed = decode_key(
            publication_signing_seed_base64,
            "publication receipt signing seed",
        )?;
        let publication_signing_key = SigningKey::from_bytes(&publication_seed);
        let channel_seed = decode_key(channel_signing_seed_base64, "channel receipt signing seed")?;
        let channel_signing_key = SigningKey::from_bytes(&channel_seed);
        if publication_signing_key.verifying_key() == channel_signing_key.verifying_key() {
            bail!("publication and channel receipt keys must use different material");
        }
        let publication_keys = decode_public_keys(
            publication_keys_base64,
            "publication",
            "publication public key",
        )?;
        let qualification_keys = decode_public_keys(
            qualification_keys_base64,
            "qualification",
            "qualification public key",
        )?;
        Ok(Self {
            deployment_id,
            publication_key_id,
            publication_signing_key,
            channel_key_id,
            channel_signing_key,
            publication_keys,
            qualification_keys,
        })
    }

    fn issue<T: Serialize>(
        &self,
        payload: &T,
        key_id: &str,
        signing_key: &SigningKey,
    ) -> Result<SignedReleaseEvidence> {
        let payload_bytes = aos_release::canonical::to_vec(payload)?;
        let digest =
            aos_release::digest::Sha256Digest::separated(RECEIPT_SIGNATURE_DOMAIN, &payload_bytes);
        let signature = signing_key.sign(digest.as_bytes());
        let envelope = SignedReceiptEnvelopeV1 {
            schema_version: SIGNED_RECEIPT_V1.into(),
            key_id: key_id.into(),
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
        self.issue(
            receipt,
            &self.publication_key_id,
            &self.publication_signing_key,
        )
    }

    async fn verify_publication(
        &self,
        receipt: &PublicationReceiptV1,
        envelope_json: &str,
    ) -> Result<()> {
        receipt.validate()?;
        let (_, verified): (String, PublicationReceiptV1) =
            verify_signed_receipt_with_key(envelope_json.as_bytes(), &self.publication_keys)?;
        if &verified != receipt {
            bail!("publication envelope has the wrong payload");
        }
        Ok(())
    }

    async fn verify_qualification(
        &self,
        receipt: &QualificationReceiptV1,
        envelope_json: &str,
    ) -> Result<()> {
        receipt.validate()?;
        let (key_id, verified): (String, QualificationReceiptV1) =
            verify_signed_receipt_with_key(envelope_json.as_bytes(), &self.qualification_keys)?;
        if &verified != receipt {
            bail!("qualification envelope has the wrong payload");
        }
        if key_id != receipt.authority_id {
            bail!("qualification authority does not match the signing key id");
        }
        Ok(())
    }

    async fn issue_channel(&self, receipt: &ChannelReceiptV1) -> Result<SignedReleaseEvidence> {
        receipt.validate()?;
        self.issue(receipt, &self.channel_key_id, &self.channel_signing_key)
    }
}

fn decode_key(encoded: &str, label: &str) -> Result<[u8; 32]> {
    STANDARD
        .decode(encoded)
        .with_context(|| format!("decoding {label}"))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("{label} must be exactly 32 bytes"))
}

fn decode_public_keys(
    encoded_keys: BTreeMap<String, String>,
    role: &str,
    label: &str,
) -> Result<BTreeMap<String, [u8; 32]>> {
    encoded_keys
        .into_iter()
        .map(|(key_id, encoded)| {
            if key_id.is_empty() {
                bail!("{role} key id is empty");
            }
            let bytes = decode_key(&encoded, label)?;
            VerifyingKey::from_bytes(&bytes).with_context(|| format!("parsing {label}"))?;
            Ok((key_id, bytes))
        })
        .collect()
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use aos_release::digest::Sha256Digest;
    use aos_release::evidence::GateResult;

    fn authority() -> Ed25519ReleaseEvidenceAuthority {
        let seed = [7_u8; 32];
        let channel_seed = [8_u8; 32];
        let public = SigningKey::from_bytes(&seed).verifying_key();
        Ed25519ReleaseEvidenceAuthority::from_base64(
            "staging-deployment",
            "hub-receipt",
            &STANDARD.encode(seed),
            "channel-receipt",
            &STANDARD.encode(channel_seed),
            BTreeMap::from([("hub-receipt".into(), STANDARD.encode(public.as_bytes()))]),
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

    fn publication() -> PublicationReceiptV1 {
        PublicationReceiptV1 {
            schema_version: aos_release::receipt::PUBLICATION_RECEIPT_V1.into(),
            environment: aos_release::receipt::HubEnvironment::Staging,
            deployment_id: "staging-deployment".into(),
            registry: aos_release::CANONICAL_REGISTRY.into(),
            release_id: "2026.03.0".into(),
            manifest_digest: Sha256Digest::of_bytes(b"manifest"),
            bundle_digest: Sha256Digest::of_bytes(b"bundle"),
            operation_id: "publication-operation".into(),
            staging_receipt_digest: None,
            committed_at: "2026-03-01T00:00:00Z".into(),
        }
    }

    #[tokio::test]
    async fn publication_envelope_uses_only_publication_trust_roots() {
        let authority = authority();
        let receipt = publication();
        let envelope = authority
            .issue(
                &receipt,
                &authority.publication_key_id,
                &authority.publication_signing_key,
            )
            .unwrap()
            .envelope_json;
        authority
            .verify_publication(&receipt, &envelope)
            .await
            .unwrap();

        let mut role_confused: SignedReceiptEnvelopeV1 = serde_json::from_str(&envelope).unwrap();
        role_confused.key_id = "qualifier".into();
        let payload = aos_release::canonical::to_vec(&receipt).unwrap();
        let digest = Sha256Digest::separated(RECEIPT_SIGNATURE_DOMAIN, payload);
        role_confused.signature_base64 = STANDARD.encode(
            authority
                .publication_signing_key
                .sign(digest.as_bytes())
                .to_bytes(),
        );
        let role_confused =
            String::from_utf8(aos_release::canonical::to_vec(&role_confused).unwrap()).unwrap();
        assert!(authority
            .verify_publication(&receipt, &role_confused)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn channel_receipts_use_the_distinct_channel_key() {
        let authority = authority();
        let receipt = ChannelReceiptV1 {
            schema_version: "aos.release.channel-receipt/v1".into(),
            channel: "edge".into(),
            first_partition: 0,
            last_partition: 31,
            prior_generation: 0,
            new_generation: 1,
            manifest_digest: Sha256Digest::of_bytes(b"manifest"),
            production_receipt_digest: Sha256Digest::of_bytes(b"production"),
            committed_at: "2026-03-01T00:00:00Z".into(),
        };
        let signed = authority.issue_channel(&receipt).await.unwrap();
        let envelope: SignedReceiptEnvelopeV1 = serde_json::from_str(&signed.envelope_json).unwrap();
        assert_eq!(envelope.key_id, "channel-receipt");
        assert_ne!(envelope.key_id, authority.publication_key_id);
    }

    #[test]
    fn authority_rejects_reused_publication_and_channel_material() {
        let seed = STANDARD.encode([7_u8; 32]);
        assert!(
            Ed25519ReleaseEvidenceAuthority::from_base64(
                "deployment",
                "publication-key",
                &seed,
                "channel-key",
                &seed,
                BTreeMap::new(),
                BTreeMap::new(),
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn qualification_envelope_is_canonical_and_signature_bound() {
        let authority = authority();
        let receipt = qualification();
        let mut envelope: SignedReceiptEnvelopeV1 = serde_json::from_str(
            &authority
                .issue(
                    &receipt,
                    &authority.publication_key_id,
                    &authority.publication_signing_key,
                )
                .unwrap()
                .envelope_json,
        )
        .unwrap();
        envelope.key_id = "qualifier".into();
        let payload = aos_release::canonical::to_vec(&receipt).unwrap();
        let digest = Sha256Digest::separated(RECEIPT_SIGNATURE_DOMAIN, payload);
        envelope.signature_base64 = STANDARD.encode(
            authority
                .publication_signing_key
                .sign(digest.as_bytes())
                .to_bytes(),
        );
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

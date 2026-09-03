//! Exact staging, qualification, production, and channel receipts.

use std::collections::BTreeMap;

use anyhow::{Context as _, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::CANONICAL_REGISTRY;
use crate::artifact::require_identifier;
use crate::digest::Sha256Digest;
use crate::evidence::GateResult;

/// Schema for an exact Hub publication receipt.
pub const PUBLICATION_RECEIPT_V1: &str = "aos.release.publication-receipt/v1";
/// Schema for a canonical signed Hub evidence envelope.
pub const SIGNED_RECEIPT_V1: &str = "aos.hub.signed-release-evidence/v1";
/// Signature domain for canonical Hub evidence payloads.
pub const RECEIPT_SIGNATURE_DOMAIN: &str = "aos.hub.release-evidence-signature/v1";
/// Schema for the independently approved release-completion decision.
pub const COMPLETION_RECEIPT_V1: &str = "aos.release.completion-receipt/v1";

/// Canonical Ed25519 envelope for a release evidence payload.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedReceiptEnvelopeV1 {
    /// Exact envelope schema identifier.
    pub schema_version: String,
    /// Pinned public key identity.
    pub key_id: String,
    /// Canonical receipt payload.
    pub payload: serde_json::Value,
    /// Standard-base64 Ed25519 signature.
    pub signature_base64: String,
}

/// Verifies and decodes a canonical signed receipt envelope.
///
/// # Errors
///
/// Returns an error for noncanonical JSON, unknown keys, malformed payloads or
/// signatures, or a failed domain-separated Ed25519 verification.
pub fn verify_signed_receipt<T>(
    envelope_bytes: &[u8],
    trusted_keys: &BTreeMap<String, [u8; 32]>,
) -> Result<T>
where
    T: DeserializeOwned + Serialize,
{
    verify_signed_receipt_with_key(envelope_bytes, trusted_keys).map(|(_, receipt)| receipt)
}

/// Verifies and decodes a canonical signed receipt envelope with its key id.
///
/// This variant lets callers bind a receipt-level authority identity to the
/// exact key selected by the envelope without reparsing security-sensitive
/// bytes.
///
/// # Errors
///
/// Returns an error for noncanonical JSON, unknown keys, malformed payloads or
/// signatures, or a failed domain-separated Ed25519 verification.
pub fn verify_signed_receipt_with_key<T>(
    envelope_bytes: &[u8],
    trusted_keys: &BTreeMap<String, [u8; 32]>,
) -> Result<(String, T)>
where
    T: DeserializeOwned + Serialize,
{
    let envelope: SignedReceiptEnvelopeV1 =
        crate::canonical::from_slice(envelope_bytes, "signed release receipt")?;
    if envelope.schema_version != SIGNED_RECEIPT_V1
        || crate::canonical::to_vec(&envelope)? != envelope_bytes
    {
        bail!("signed release receipt is noncanonical or has an unsupported schema");
    }
    let payload = crate::canonical::to_vec(&envelope.payload)?;
    let receipt: T = crate::canonical::from_slice(&payload, "release receipt payload")?;
    if crate::canonical::to_vec(&receipt)? != payload {
        bail!("signed release receipt payload is noncanonical");
    }
    let public = trusted_keys
        .get(&envelope.key_id)
        .context("release receipt signer is not trusted")?;
    let key = VerifyingKey::from_bytes(public).context("parsing release receipt public key")?;
    let signature = Signature::from_slice(
        &STANDARD
            .decode(&envelope.signature_base64)
            .context("decoding release receipt signature")?,
    )
    .context("parsing release receipt signature")?;
    let digest = Sha256Digest::separated(RECEIPT_SIGNATURE_DOMAIN, payload);
    key.verify(digest.as_bytes(), &signature)
        .context("verifying release receipt signature")?;
    Ok((envelope.key_id, receipt))
}

/// Isolated Hub environment named by a publication receipt.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum HubEnvironment {
    /// Qualification deployment.
    Staging,
    /// Consumer-facing deployment.
    Production,
}

/// Immutable receipt for committing a closed bundle to one Hub environment.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationReceiptV1 {
    /// Exact receipt schema identifier.
    pub schema_version: String,
    /// Isolated environment that admitted the bundle.
    pub environment: HubEnvironment,
    /// Exact deployment identity verified by the client and Hub.
    pub deployment_id: String,
    /// Canonical registry identity.
    pub registry: String,
    /// Immutable release identity.
    pub release_id: String,
    /// Final manifest identity.
    pub manifest_digest: Sha256Digest,
    /// Closed bundle identity.
    pub bundle_digest: Sha256Digest,
    /// Hub-side publication operation id.
    pub operation_id: String,
    /// Prior staging receipt required for promoted imports.
    pub staging_receipt_digest: Option<Sha256Digest>,
    /// RFC 3339 UTC commit time supplied by the Hub.
    pub committed_at: String,
}

impl PublicationReceiptV1 {
    /// Validates environment-specific receipt shape.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed identifiers, an empty timestamp, a
    /// staging receipt that claims promotion, or a production receipt without
    /// staging continuity.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != PUBLICATION_RECEIPT_V1 {
            bail!("unsupported publication receipt schema");
        }
        require_identifier(&self.deployment_id, "Hub deployment id")?;
        require_identifier(&self.release_id, "release id")?;
        require_identifier(&self.operation_id, "Hub operation id")?;
        if self.registry != CANONICAL_REGISTRY {
            bail!("publication receipt names a noncanonical registry");
        }
        if !self.committed_at.ends_with('Z')
            || humantime::parse_rfc3339(&self.committed_at).is_err()
        {
            bail!("publication receipt timestamp must be RFC 3339 UTC");
        }
        match (self.environment, self.staging_receipt_digest) {
            (HubEnvironment::Staging, None) | (HubEnvironment::Production, Some(_)) => Ok(()),
            (HubEnvironment::Staging, Some(_)) => {
                bail!("staging receipt cannot claim production promotion")
            }
            (HubEnvironment::Production, None) => {
                bail!("production receipt requires exact staging continuity")
            }
        }
    }
}

/// Signed qualification over exact staged public bytes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationReceiptV1 {
    /// Exact receipt schema identifier.
    pub schema_version: String,
    /// Digest of the staging publication receipt.
    pub staging_receipt_digest: Sha256Digest,
    /// Final release-manifest identity.
    pub manifest_digest: Sha256Digest,
    /// Versioned qualification policy identity.
    pub policy_id: String,
    /// Digest of exact qualification policy bytes.
    pub policy_digest: Sha256Digest,
    /// Public qualification result.
    pub result: GateResult,
    /// Digest of the complete public qualification report.
    pub report_digest: Sha256Digest,
    /// Public qualification authority identity.
    pub authority_id: String,
    /// Nonce supplied by the release coordinator.
    pub nonce: String,
    /// RFC 3339 UTC completion time.
    pub qualified_at: String,
}

impl QualificationReceiptV1 {
    /// Validates qualification identity, policy, result, nonce, and time.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported schema, malformed identity or
    /// nonce, a non-passing gate, or a non-UTC timestamp.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != "aos.release.qualification-receipt/v1" {
            bail!("unsupported qualification receipt schema");
        }
        require_identifier(&self.policy_id, "qualification policy id")?;
        require_identifier(&self.authority_id, "qualification authority id")?;
        if self.nonce.len() != 64
            || !self
                .nonce
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            bail!("qualification nonce must be 32 bytes of lowercase hexadecimal");
        }
        if self.result != GateResult::Passed {
            bail!("qualification receipt is not passing");
        }
        if !self.qualified_at.ends_with('Z')
            || humantime::parse_rfc3339(&self.qualified_at).is_err()
        {
            bail!("qualification timestamp must be RFC 3339 UTC");
        }
        Ok(())
    }
}

/// Compare-and-swap receipt for one signed channel partition operation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelReceiptV1 {
    /// Exact receipt schema identifier.
    pub schema_version: String,
    /// Channel name: `edge`, `candidate`, or `stable`.
    pub channel: String,
    /// Inclusive first partition changed.
    pub first_partition: u16,
    /// Inclusive final partition changed.
    pub last_partition: u16,
    /// Expected prior channel generation.
    pub prior_generation: u64,
    /// New channel generation.
    pub new_generation: u64,
    /// Release manifest now named by the changed partitions.
    pub manifest_digest: Sha256Digest,
    /// Exact production receipt authorizing discovery.
    pub production_receipt_digest: Sha256Digest,
    /// RFC 3339 UTC operation time.
    pub committed_at: String,
}

impl ChannelReceiptV1 {
    /// Validates channel, partition, and generation monotonicity.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown channel, a partition outside `0..=255`,
    /// a reversed range, a non-incrementing generation, an unsupported schema,
    /// or an empty timestamp.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != "aos.release.channel-receipt/v1" {
            bail!("unsupported channel receipt schema");
        }
        if !matches!(self.channel.as_str(), "edge" | "candidate" | "stable") {
            bail!("unknown release channel: {}", self.channel);
        }
        if self.first_partition > self.last_partition || self.last_partition > 255 {
            bail!("channel partition range must be within 0..=255");
        }
        if self.new_generation != self.prior_generation.saturating_add(1) {
            bail!("channel generation must increase by exactly one");
        }
        if self.committed_at.trim().is_empty() {
            bail!("channel receipt timestamp cannot be empty");
        }
        Ok(())
    }
}

/// Retention and handoff decision required to complete a channel rollout.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompletionReceiptV1 {
    /// Exact completion schema identifier.
    pub schema_version: String,
    /// Immutable release identity.
    pub release_id: String,
    /// Frozen release-plan identity.
    pub plan_digest: Sha256Digest,
    /// Final release-manifest identity.
    pub manifest_digest: Sha256Digest,
    /// Production publication receipt authorizing discovery.
    pub production_receipt_digest: Sha256Digest,
    /// Sorted identities of every planned channel operation receipt.
    pub channel_receipt_digests: Vec<Sha256Digest>,
    /// Versioned retention policy frozen in the plan.
    pub retention_policy_id: String,
    /// Exact frozen retention-policy digest.
    pub retention_policy_digest: Sha256Digest,
    /// Whether all required corresponding source remains retained.
    pub corresponding_source_retained: bool,
    /// Whether ownership, monitoring, and recovery handoff is complete.
    pub operational_handoff_complete: bool,
    /// Public release-evidence authority identity.
    pub authority_id: String,
    /// RFC 3339 UTC decision time.
    pub completed_at: String,
}

impl CompletionReceiptV1 {
    /// Validates the closed completion decision independently of a plan.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported schema, malformed identities,
    /// missing or unordered channel evidence, a failed retention/handoff
    /// decision, or a non-UTC completion time.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != COMPLETION_RECEIPT_V1 {
            bail!("unsupported release completion receipt schema");
        }
        require_identifier(&self.release_id, "completion release id")?;
        require_identifier(&self.retention_policy_id, "completion retention policy id")?;
        require_identifier(&self.authority_id, "completion authority id")?;
        if self.channel_receipt_digests.is_empty()
            || self
                .channel_receipt_digests
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            bail!("completion channel receipt digests must be nonempty, unique, and sorted");
        }
        if !self.corresponding_source_retained || !self.operational_handoff_complete {
            bail!("release completion retention and handoff must both pass");
        }
        if !self.completed_at.ends_with('Z')
            || humantime::parse_rfc3339(&self.completed_at).is_err()
        {
            bail!("release completion timestamp must be RFC 3339 UTC");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};

    #[test]
    fn signed_receipt_verification_rejects_payload_changes() {
        let key = SigningKey::from_bytes(&[9_u8; 32]);
        let receipt = ChannelReceiptV1 {
            schema_version: "aos.release.channel-receipt/v1".into(),
            channel: "edge".into(),
            first_partition: 0,
            last_partition: 3,
            prior_generation: 0,
            new_generation: 1,
            manifest_digest: Sha256Digest::of_bytes(b"manifest"),
            production_receipt_digest: Sha256Digest::of_bytes(b"production"),
            committed_at: "2026-03-01T00:00:00Z".into(),
        };
        let payload = crate::canonical::to_vec(&receipt).unwrap();
        let digest = Sha256Digest::separated(RECEIPT_SIGNATURE_DOMAIN, &payload);
        let envelope = SignedReceiptEnvelopeV1 {
            schema_version: SIGNED_RECEIPT_V1.into(),
            key_id: "receipt-key".into(),
            payload: serde_json::from_slice(&payload).unwrap(),
            signature_base64: STANDARD.encode(key.sign(digest.as_bytes()).to_bytes()),
        };
        let bytes = crate::canonical::to_vec(&envelope).unwrap();
        let keys = BTreeMap::from([("receipt-key".into(), key.verifying_key().to_bytes())]);
        let verified: ChannelReceiptV1 = verify_signed_receipt(&bytes, &keys).unwrap();
        assert_eq!(verified, receipt);

        let mut changed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        changed["payload"]["last_partition"] = serde_json::json!(4);
        let changed = crate::canonical::to_vec(&changed).unwrap();
        assert!(verify_signed_receipt::<ChannelReceiptV1>(&changed, &keys).is_err());
    }

    #[test]
    fn completion_receipt_requires_sorted_rollout_and_passing_handoff() {
        let first = Sha256Digest::of_bytes("first");
        let second = Sha256Digest::of_bytes("second");
        let mut digests = vec![first, second];
        digests.sort();
        let mut receipt = CompletionReceiptV1 {
            schema_version: COMPLETION_RECEIPT_V1.into(),
            release_id: "release-2026-09".into(),
            plan_digest: Sha256Digest::of_bytes("plan"),
            manifest_digest: Sha256Digest::of_bytes("manifest"),
            production_receipt_digest: Sha256Digest::of_bytes("production"),
            channel_receipt_digests: digests,
            retention_policy_id: "retention-v1".into(),
            retention_policy_digest: Sha256Digest::of_bytes("retention"),
            corresponding_source_retained: true,
            operational_handoff_complete: true,
            authority_id: "release-evidence".into(),
            completed_at: "2026-09-03T00:00:00Z".into(),
        };
        assert!(receipt.validate().is_ok());
        receipt.channel_receipt_digests.reverse();
        assert!(receipt.validate().is_err());
        receipt.channel_receipt_digests.sort();
        receipt.operational_handoff_complete = false;
        assert!(receipt.validate().is_err());
    }
}

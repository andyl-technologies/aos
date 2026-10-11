//! Exact publication, qualification, channel, and completion receipts.
//!
//! Publication and channel receipts ([`PublicationReceipt`],
//! [`ChannelReceipt`]) have one surface-neutral shape: Hub deployments sign
//! them with their receipt key and static surfaces sign them with the plan's
//! `surface-receipt` role.

use std::collections::BTreeMap;

use anyhow::{Context as _, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::artifact::require_identifier;
use crate::digest::Sha256Digest;
use crate::evidence::GateResult;
use crate::registry::registry_policy;

pub mod historical;
mod surface;

pub use historical::{
    ChannelReceiptV1, PublicationReceiptV1, QualificationReceiptV1,
    SIGNED_RECEIPT_V1, SignedReceiptEnvelopeV1,
};

pub use surface::{CHANNEL_RECEIPT, ChannelReceipt, PUBLICATION_RECEIPT, PublicationReceipt};

/// Schema for an independently authorized aggregate qualification decision.
pub const QUALIFICATION_RECEIPT: &str = "aos.release.qualification-receipt/v1";
/// Schema for a canonical signed Hub evidence envelope.
pub const SIGNED_RECEIPT: &str = "aos.hub.signed-release-evidence/v1";
/// Signature domain for canonical Hub evidence payloads.
pub const RECEIPT_SIGNATURE_DOMAIN: &str = "aos.hub.release-evidence-signature/v1";
/// Schema for the independently approved release-completion decision.
pub const COMPLETION_RECEIPT: &str = "aos.release.completion-receipt/v1";
/// Schema for an explicitly approved empty Hub registry bootstrap.
pub const REGISTRY_BOOTSTRAP_INTENT: &str = "aos.release.registry-bootstrap-intent/v1";

/// Canonical Ed25519 envelope for a release evidence payload.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedReceiptEnvelope {
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
    let envelope: SignedReceiptEnvelope =
        crate::canonical::from_slice(envelope_bytes, "signed release receipt")?;
    if envelope.schema_version != SIGNED_RECEIPT
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

/// Isolated Hub environment named by a registry bootstrap intent.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum HubEnvironment {
    /// Qualification deployment.
    Staging,
    /// Consumer-facing deployment.
    Production,
}

/// Signed intent authorizing the first exact registry base in one Hub.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryBootstrapIntent {
    /// Exact bootstrap schema identifier.
    pub schema_version: String,
    /// Isolated Hub environment receiving the base.
    pub environment: HubEnvironment,
    /// Deployment identity frozen by the release plan.
    pub deployment_id: String,
    /// Canonical registry identity.
    pub registry: String,
    /// Exact signed registry commit installed as the empty release base.
    pub base_commit: String,
    /// Frozen release-plan identity requesting the bootstrap.
    pub plan_digest: Sha256Digest,
    /// Public approving authority identity.
    pub authority_id: String,
    /// RFC 3339 UTC approval time.
    pub approved_at: String,
}

impl RegistryBootstrapIntent {
    /// Validates the closed bootstrap intent independently of a plan.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported schema, malformed identities,
    /// noncanonical registry or commit identity, or non-UTC approval time.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != REGISTRY_BOOTSTRAP_INTENT {
            bail!("unsupported registry bootstrap intent schema");
        }
        require_identifier(&self.deployment_id, "bootstrap deployment id")?;
        require_identifier(&self.authority_id, "bootstrap authority id")?;
        registry_policy(&self.registry)?;
        if !matches!(self.base_commit.len(), 40 | 64)
            || !self
                .base_commit
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            bail!("registry bootstrap commit is not lowercase Git hex");
        }
        if !self.approved_at.ends_with('Z') || humantime::parse_rfc3339(&self.approved_at).is_err()
        {
            bail!("registry bootstrap approval time must be RFC 3339 UTC");
        }
        Ok(())
    }
}

/// Signed qualification over exact staged public bytes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationReceipt {
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

impl QualificationReceipt {
    /// Validates qualification identity, policy, result, nonce, and time.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported schema, malformed identity or
    /// nonce, a non-passing gate, or a non-UTC timestamp.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != QUALIFICATION_RECEIPT {
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

/// Retention and handoff decision required to complete a channel rollout.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompletionReceipt {
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
    /// Digest of the exact rolling journal head authorized for completion.
    pub prior_journal_entry_digest: Sha256Digest,
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

impl CompletionReceipt {
    /// Validates the closed completion decision independently of a plan.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported schema, malformed identities,
    /// missing or unordered channel evidence, a failed retention/handoff
    /// decision, or a non-UTC completion time.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != COMPLETION_RECEIPT {
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

    fn channel_receipt(channel: &str) -> ChannelReceipt {
        ChannelReceipt {
            schema_version: CHANNEL_RECEIPT.into(),
            destination: format!("production/{channel}"),
            channel: channel.into(),
            ring: 1,
            first_partition: 0,
            last_partition: 3,
            prior_generation: 0,
            new_generation: 1,
            manifest_digest: Sha256Digest::of_bytes(b"manifest"),
            publication_receipt_digest: Sha256Digest::of_bytes(b"production"),
            surface_kind: crate::plan::SurfaceKind::Hub,
            surface_identity: "hub-production".into(),
            committed_at: "2026-03-01T00:00:00Z".into(),
        }
    }

    #[test]
    fn signed_receipt_verification_rejects_payload_changes() {
        let key = SigningKey::from_bytes(&[9_u8; 32]);
        let receipt = channel_receipt("edge");
        let payload = crate::canonical::to_vec(&receipt).unwrap();
        let digest = Sha256Digest::separated(RECEIPT_SIGNATURE_DOMAIN, &payload);
        let envelope = SignedReceiptEnvelope {
            schema_version: SIGNED_RECEIPT.into(),
            key_id: "receipt-key".into(),
            payload: serde_json::from_slice(&payload).unwrap(),
            signature_base64: STANDARD.encode(key.sign(digest.as_bytes()).to_bytes()),
        };
        let bytes = crate::canonical::to_vec(&envelope).unwrap();
        let keys = BTreeMap::from([("receipt-key".into(), key.verifying_key().to_bytes())]);
        let verified: ChannelReceipt = verify_signed_receipt(&bytes, &keys).unwrap();
        assert_eq!(verified, receipt);

        let mut changed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        changed["payload"]["last_partition"] = serde_json::json!(4);
        let changed = crate::canonical::to_vec(&changed).unwrap();
        assert!(verify_signed_receipt::<ChannelReceipt>(&changed, &keys).is_err());
    }

    #[test]
    fn completion_receipt_requires_sorted_rollout_and_passing_handoff() {
        let first = Sha256Digest::of_bytes("first");
        let second = Sha256Digest::of_bytes("second");
        let mut digests = vec![first, second];
        digests.sort();
        let mut receipt = CompletionReceipt {
            schema_version: COMPLETION_RECEIPT.into(),
            release_id: "release-2026-09".into(),
            plan_digest: Sha256Digest::of_bytes("plan"),
            manifest_digest: Sha256Digest::of_bytes("manifest"),
            production_receipt_digest: Sha256Digest::of_bytes("production"),
            channel_receipt_digests: digests,
            prior_journal_entry_digest: Sha256Digest::of_bytes("journal-head"),
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

    #[test]
    fn registry_bootstrap_intent_is_environment_and_commit_bound() {
        let mut intent = RegistryBootstrapIntent {
            schema_version: REGISTRY_BOOTSTRAP_INTENT.into(),
            environment: HubEnvironment::Staging,
            deployment_id: "staging-2026-09".into(),
            registry: crate::registry::MAIN_REGISTRY.into(),
            base_commit: "a".repeat(40),
            plan_digest: Sha256Digest::of_bytes("plan"),
            authority_id: "release-evidence".into(),
            approved_at: "2026-09-03T00:00:00Z".into(),
        };
        assert!(intent.validate().is_ok());
        intent.base_commit = "A".repeat(40);
        assert!(intent.validate().is_err());
    }

    #[test]
    fn channel_receipts_accept_per_train_channels_by_kind() {
        let receipt = channel_receipt("stable-2026.3");
        assert!(receipt.validate().is_ok());
        assert!(channel_receipt("nightly").validate().is_err());
    }

    #[test]
    fn surface_receipts_bind_the_plan() -> anyhow::Result<()> {
        let (plan, _) = crate::verify::tests::qualification_fixture()?;
        let staging = PublicationReceipt {
            schema_version: PUBLICATION_RECEIPT.into(),
            destination: "staging/stable".into(),
            surface_role: crate::plan::SurfaceRole::Staging,
            surface_kind: crate::plan::SurfaceKind::Hub,
            surface_identity: "hub-staging-v1".into(),
            registry: plan.registry.clone(),
            release_id: plan.release_id.clone(),
            manifest_digest: Sha256Digest::of_bytes("manifest"),
            bundle_digest: Sha256Digest::of_bytes("bundle"),
            operation_id: "publish-1".into(),
            predecessor_receipt_digest: None,
            committed_at: "2026-09-03T00:00:00Z".into(),
        };
        staging.validate_for(&plan)?;
        let mut misrouted = staging.clone();
        misrouted.destination = "production/stable".into();
        assert!(misrouted.validate().is_err());

        let mut production = staging;
        production.destination = "production/stable".into();
        production.surface_role = crate::plan::SurfaceRole::Production;
        production.surface_identity = "hub-production-v1".into();
        assert!(
            production.validate().is_err(),
            "production needs continuity"
        );
        production.predecessor_receipt_digest = Some(Sha256Digest::of_bytes("staging receipt"));
        production.validate_for(&plan)?;
        let mut elsewhere = production.clone();
        elsewhere.surface_identity = "hub-other".into();
        assert!(elsewhere.validate_for(&plan).is_err());
        let mut static_kind = production;
        static_kind.surface_kind = crate::plan::SurfaceKind::Static;
        assert!(static_kind.validate_for(&plan).is_err());

        let destination = plan.destination("production/stable")?;
        let mut channel = channel_receipt("stable");
        channel.ring = 2;
        channel.first_partition = 4;
        channel.last_partition = 31;
        channel.prior_generation = 1;
        channel.new_generation = 2;
        channel.surface_identity = "hub-production-v1".into();
        channel.validate_for(destination)?;
        let mut wrong_ring = channel.clone();
        wrong_ring.ring = 1;
        assert!(wrong_ring.validate_for(destination).is_err());
        let mut wrong_channel = channel;
        wrong_channel.channel = "candidate".into();
        assert!(wrong_channel.validate().is_err());
        Ok(())
    }
}

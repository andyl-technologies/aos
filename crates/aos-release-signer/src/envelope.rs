//! Signed release-evidence envelopes for operator approvals.
//!
//! Registry bootstrap intents, qualification review receipts, and completion
//! approvals travel as `aos.hub.signed-release-evidence/v1` envelopes whose
//! Ed25519 signature covers the canonical payload under the receipt domain.
//! This module produces such envelopes from a canonical payload file using a
//! configured Ed25519 key.

use anyhow::{Context as _, Result, bail};
use aos_release::canonical;
use aos_release::digest::Sha256Digest;
use aos_release::receipt::{RECEIPT_SIGNATURE_DOMAIN, SIGNED_RECEIPT_V1, SignedReceiptEnvelopeV1};
use base64::Engine as _;
use ed25519_dalek::Signer as _;

use crate::config::SignerConfigV1;
use crate::keys::LoadedKey;

/// Signs one canonical payload into a canonical evidence envelope.
///
/// # Errors
///
/// Returns an error when the payload is not canonical JSON, the key is not
/// configured, or the key is not Ed25519 material.
pub fn sign_evidence(config: &SignerConfigV1, key_id: &str, payload: &[u8]) -> Result<Vec<u8>> {
    let value = canonical::require_canonical(payload, "evidence payload")?;
    let entry = config
        .key(key_id)
        .with_context(|| format!("key {key_id} is not configured"))?;
    let LoadedKey::Ed25519(key) = LoadedKey::load(&entry.material)? else {
        bail!("evidence envelopes require an Ed25519 key");
    };

    let digest = Sha256Digest::separated(RECEIPT_SIGNATURE_DOMAIN, payload);
    let envelope = SignedReceiptEnvelopeV1 {
        schema_version: SIGNED_RECEIPT_V1.to_owned(),
        key_id: key_id.to_owned(),
        payload: value,
        signature_base64: base64::engine::general_purpose::STANDARD
            .encode(key.sign(digest.as_bytes()).to_bytes()),
    };
    canonical::to_vec(&envelope)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use aos_release::receipt::verify_signed_receipt_with_key;
    use aos_release::signing::SignerRole;
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::config::{CONFIG_SCHEMA_V1, KeyEntry, KeyMaterial, ToolPaths};
    use crate::keys::tests::write_ed25519_pem;

    #[test]
    fn envelopes_verify_with_the_release_evidence_key() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let seed = [21_u8; 32];
        let path = write_ed25519_pem(dir.path(), seed);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let config = SignerConfigV1 {
            schema_version: CONFIG_SCHEMA_V1.into(),
            provider_revision: "test-provider-v1".into(),
            registries: vec!["andyl/testing".into()],
            tools: ToolPaths::default(),
            keys: vec![KeyEntry {
                key_id: "evidence-v1".into(),
                roles: vec![SignerRole::ReleaseEvidence],
                verification_identity: "evidence-v1".into(),
                material: KeyMaterial::Ed25519Pkcs8Pem { private_key: path },
            }],
        };
        let payload = canonical::to_vec(&serde_json::json!({"b": 1, "a": "x"})).unwrap();

        let envelope = sign_evidence(&config, "evidence-v1", &payload).unwrap();

        let keys = BTreeMap::from([(
            "evidence-v1".to_owned(),
            SigningKey::from_bytes(&seed).verifying_key().to_bytes(),
        )]);
        let (key_id, verified): (String, serde_json::Value) =
            verify_signed_receipt_with_key(&envelope, &keys).unwrap();
        assert_eq!(key_id, "evidence-v1");
        assert_eq!(verified, serde_json::json!({"a": "x", "b": 1}));
        assert!(sign_evidence(&config, "evidence-v1", b"{\"b\":1,\"a\":2}").is_err());
    }
}

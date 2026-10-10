//! Creates DSSE provenance through independently verified signing adapters.
//!
//! The producer signs the exact shared pre-authentication encoding; native
//! consumers verify the resulting envelope through `aos_registry_client`.

use anyhow::{Context, Result, bail};
use aos_registry_format::provenance::{DSSE_PAYLOAD_TYPE, DsseEnvelope, DsseSignature, dsse_pae};
use async_trait::async_trait;
use base64::Engine as _;

/// A verified, ASCII-armored SSHSIG returned by a provenance signing adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProvenanceSignature {
    /// Public roster key id used for the signature.
    pub key_id: String,
    /// Stable provider audit operation id.
    pub provider_operation_id: String,
    /// ASCII-armored OpenSSH SSHSIG bytes.
    pub armored_signature: String,
}

/// Signs exact DSSE pre-authentication encoding bytes without exposing keys.
#[async_trait]
pub trait ProvenanceSigner: Send {
    /// Returns the preauthenticated roster key id used in statement metadata.
    fn key_id(&self) -> &str;

    /// Returns the independently pinned roster trust line when externally backed.
    fn trusted_key_line(&self) -> Option<&str> {
        None
    }

    /// Signs `payload` in the package-provenance SSHSIG namespace.
    ///
    /// Implementations must independently verify the returned signature and
    /// all provider-policy bindings before returning it.
    ///
    /// # Errors
    ///
    /// Returns an error when provider policy, request binding, or signature
    /// verification fails.
    async fn sign_provenance(&mut self, payload: &[u8]) -> Result<ProvenanceSignature>;
}

/// Signs a statement through a keyless provenance adapter and emits DSSE JSONL.
///
/// The adapter sees the exact DSSE PAE bytes, not merely the decoded statement.
/// Its response must repeat the selected roster key id and contain canonical
/// SSHSIG armor. This function does not accept or resolve a private-key path.
///
/// # Errors
///
/// Returns an error when serialization, external signing, response binding,
/// or envelope serialization fails.
pub async fn sign_statement_dsse_jsonl_external(
    statement: &serde_json::Value,
    signer: &mut dyn ProvenanceSigner,
) -> Result<String> {
    let key_id = signer.key_id().to_string();
    if key_id.is_empty() {
        bail!("package provenance DSSE key id cannot be empty");
    }
    let payload =
        serde_json::to_vec(statement).context("serializing package provenance statement")?;
    let pae = dsse_pae(DSSE_PAYLOAD_TYPE, &payload);
    let signature = signer.sign_provenance(&pae).await?;
    if signature.key_id != key_id
        || signature.provider_operation_id.is_empty()
        || !signature
            .armored_signature
            .starts_with("-----BEGIN SSH SIGNATURE-----\n")
        || !signature
            .armored_signature
            .ends_with("-----END SSH SIGNATURE-----\n")
    {
        bail!("package provenance signer returned an unbound or malformed response");
    }
    let envelope = DsseEnvelope {
        payload_type: DSSE_PAYLOAD_TYPE.to_string(),
        payload: base64::engine::general_purpose::STANDARD.encode(&payload),
        signatures: vec![DsseSignature {
            key_id,
            sig: base64::engine::general_purpose::STANDARD
                .encode(signature.armored_signature.as_bytes()),
        }],
    };
    let mut jsonl =
        serde_json::to_string(&envelope).context("serializing package provenance DSSE envelope")?;
    jsonl.push('\n');
    Ok(jsonl)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_registry_client::provenance::{TrustedProvenanceKey, verify_statement_dsse_jsonl};
    use aos_registry_format::provenance::DSSE_SIGNATURE_NAMESPACE;

    struct ExternalTestSigner {
        private_key: std::path::PathBuf,
        trusted_key: String,
        key_id: String,
    }

    #[async_trait]
    impl ProvenanceSigner for ExternalTestSigner {
        fn key_id(&self) -> &str {
            &self.key_id
        }

        fn trusted_key_line(&self) -> Option<&str> {
            Some(&self.trusted_key)
        }

        async fn sign_provenance(&mut self, payload: &[u8]) -> Result<ProvenanceSignature> {
            Ok(ProvenanceSignature {
                key_id: self.key_id.clone(),
                provider_operation_id: "test-operation".to_string(),
                armored_signature: crate::security::sign_payload_signature(
                    &self.private_key,
                    DSSE_SIGNATURE_NAMESPACE,
                    payload,
                )?,
            })
        }
    }

    #[tokio::test]
    async fn external_signer_emits_verifiable_dsse_envelope() {
        let temp = tempfile::TempDir::new().unwrap();
        let key = crate::sshkey::Ed25519Keypair::from_seed([42; 32]);
        let private_key = temp.path().join("builder_ed25519");
        std::fs::write(&private_key, key.to_openssh_private_key("registry")).unwrap();
        let trusted_key = key.trust_key_line("registry");
        let key_id = "builder-key";
        let statement = serde_json::json!({"_type": "https://in-toto.io/Statement/v1"});
        let mut signer = ExternalTestSigner {
            private_key,
            trusted_key: trusted_key.clone(),
            key_id: key_id.to_string(),
        };

        let jsonl = sign_statement_dsse_jsonl_external(&statement, &mut signer)
            .await
            .unwrap();
        let (verified, verified_key_id) = verify_statement_dsse_jsonl(
            &jsonl,
            &[TrustedProvenanceKey {
                key_id: key_id.to_string(),
                key: trusted_key,
                retired_before_sequence: None,
            }],
        )
        .unwrap();

        assert_eq!(verified, statement);
        assert_eq!(verified_key_id, key_id);
    }
}

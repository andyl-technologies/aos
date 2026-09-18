//! Request authorization and signature dispatch.
//!
//! One request is authorized only when its provider revision, registry,
//! key id, and role all match the configuration and the payload reproduces
//! the request's declared digest. The signature mechanism is then selected
//! from the request algorithm and the configured key material; every other
//! combination is refused.

use anyhow::{Context as _, Result, bail};
use aos_release::canonical;
use aos_release::digest::Sha256Digest;
use aos_release::signing::{
    SignatureAlgorithm, SignatureResponseV1, SigningContext, SigningOperation, SigningRequestV1,
    verify_response_binding,
};
use base64::Engine as _;
use ed25519_dalek::Signer as _;
use rsa::RsaPrivateKey;
use rsa::signature::SignatureEncoding as _;
use sha2::Sha256;
use ssh_key::{HashAlg, LineEnding};

use crate::config::SignerConfigV1;
use crate::exchange::ExchangeRequest;
use crate::image;
use crate::keys::LoadedKey;

/// Exact response schema identifier expected by the coordinator.
pub const RESPONSE_SCHEMA_V1: &str = "aos.release.signature-response/v1";

/// SSHSIG namespace for Git commit and tag objects.
const GIT_SSHSIG_NAMESPACE: &str = "git";

/// SSHSIG namespace for package provenance DSSE envelopes.
///
/// This must equal `aos_package::provenance::DSSE_SIGNATURE_NAMESPACE`; the
/// literal is repeated here so the adapter does not link the package manager.
const PROVENANCE_SSHSIG_NAMESPACE: &str = "aos-package-provenance-dsse-v1";

/// A verified response together with any transformed output bytes.
pub struct SignedExchange {
    /// Response the coordinator verifies against its pinned public material.
    pub response: SignatureResponseV1,
    /// Signed artifact bytes for transforming operations; empty otherwise.
    pub output: Vec<u8>,
}

/// Authorizes one request against the configuration and produces its signature.
///
/// # Errors
///
/// Returns an error for a noncanonical or invalid request, a payload that does
/// not match the request digest, an unknown provider revision, registry, key,
/// or role, key material that cannot serve the requested algorithm, or a
/// failed external tool.
pub fn sign_exchange(
    config: &SignerConfigV1,
    exchange: &ExchangeRequest,
) -> Result<SignedExchange> {
    let request: SigningRequestV1 = canonical::from_slice(&exchange.request, "signing request")?;
    request.validate()?;
    if canonical::to_vec(&request)? != exchange.request {
        bail!("signing request is not canonical JSON");
    }
    request.verify_payload_bytes(&exchange.payload)?;
    authorize(config, &request)?;

    let entry = config
        .key(&request.key_id)
        .context("signing request names an unconfigured key")?;
    let key = LoadedKey::load(&entry.material)?;
    let (signature_base64, output) = produce(config, &request, &key, &exchange.payload)?;

    let output_digest = (!output.is_empty()).then(|| Sha256Digest::of_bytes(&output));
    let response = SignatureResponseV1 {
        schema_version: RESPONSE_SCHEMA_V1.to_owned(),
        request_digest: request.digest()?,
        role: request.role,
        key_id: request.key_id.clone(),
        provider_revision: request.provider_revision.clone(),
        algorithm: request.algorithm,
        provider_operation_id: format!("file-signer-{}", request.request_id.replace('/', "-")),
        verification_identity: entry.verification_identity.clone(),
        verification_material_digest: key.verification_material_digest()?,
        output_digest,
        signature_base64,
    };
    // The coordinator applies the same binding check; failing here keeps a
    // malformed response from ever reaching standard output.
    verify_response_binding(&request, &response)?;
    Ok(SignedExchange { response, output })
}

/// Rejects requests outside the configured provider, registry, and role policy.
fn authorize(config: &SignerConfigV1, request: &SigningRequestV1) -> Result<()> {
    if request.provider_revision != config.provider_revision {
        bail!(
            "signing request names provider revision {} but this adapter is {}",
            request.provider_revision,
            config.provider_revision
        );
    }
    if !config.registries.contains(&request.registry) {
        bail!(
            "this adapter does not sign for registry {}",
            request.registry
        );
    }
    let entry = config
        .key(&request.key_id)
        .with_context(|| format!("key {} is not configured", request.key_id))?;
    if !entry.roles.contains(&request.role) {
        bail!(
            "key {} is not authorized for role {:?}",
            request.key_id,
            request.role
        );
    }
    Ok(())
}

/// Produces the detached signature or transformed output for one request.
fn produce(
    config: &SignerConfigV1,
    request: &SigningRequestV1,
    key: &LoadedKey,
    payload: &[u8],
) -> Result<(String, Vec<u8>)> {
    let encode = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
    let detached = |signature: String| Ok((signature, Vec::new()));
    let transformed = |output: Vec<u8>| Ok((String::new(), output));

    match (request.algorithm, request.operation, key) {
        (SignatureAlgorithm::Ed25519, SigningOperation::SignPayload, LoadedKey::Ed25519(key)) => {
            let digest = request.digest()?;
            detached(encode(&key.sign(digest.as_bytes()).to_bytes()))
        }
        (
            SignatureAlgorithm::Ed25519Payload,
            SigningOperation::SignPayload,
            LoadedKey::Ed25519(key),
        ) => detached(encode(&key.sign(payload).to_bytes())),
        (SignatureAlgorithm::SshsigEd25519, _, LoadedKey::Openssh { key, .. }) => {
            let namespace = sshsig_namespace(request)?;
            let signature = key
                .sign(namespace, HashAlg::Sha512, payload)
                .context("creating SSHSIG signature")?;
            let armored = signature
                .to_pem(LineEnding::LF)
                .context("encoding SSHSIG signature")?;
            detached(encode(armored.as_bytes()))
        }
        (
            SignatureAlgorithm::PublicKeySha256,
            SigningOperation::SignPayload,
            LoadedKey::Rsa { key, .. },
        ) => detached(encode(&rsa_sha256_sign(key, payload))),
        (
            SignatureAlgorithm::Authenticode,
            SigningOperation::SignPe,
            LoadedKey::Rsa {
                private_key_path,
                public_path,
                certificate: true,
                ..
            },
        ) => transformed(image::sign_pe(
            config.tool("sbsign")?,
            private_key_path,
            public_path,
            payload,
        )?),
        (
            SignatureAlgorithm::KernelModule,
            SigningOperation::SignKernelModule,
            LoadedKey::Rsa {
                private_key_path,
                public_path,
                certificate: true,
                ..
            },
        ) => transformed(image::sign_kernel_module(
            config.tool("openssl")?,
            private_key_path,
            public_path,
            payload,
        )?),
        (
            SignatureAlgorithm::PcrPolicy,
            SigningOperation::SignPcrPolicy,
            LoadedKey::Rsa { key, .. },
        ) => transformed(image::sign_pcr_policy(key, payload)?),
        _ => bail!(
            "key {} cannot perform {:?} with {:?}",
            request.key_id,
            request.operation,
            request.algorithm
        ),
    }
}

/// Selects the SSHSIG namespace the coordinator verifies for this context.
fn sshsig_namespace(request: &SigningRequestV1) -> Result<&'static str> {
    match (&request.context, request.operation) {
        (SigningContext::Git { .. }, SigningOperation::SignGitObject) => Ok(GIT_SSHSIG_NAMESPACE),
        (SigningContext::Payload { artifact_kind }, SigningOperation::SignPayload)
            if artifact_kind == "package-provenance-dsse" =>
        {
            Ok(PROVENANCE_SSHSIG_NAMESPACE)
        }
        _ => bail!("SSHSIG signing is limited to Git objects and package provenance"),
    }
}

/// Signs bytes with RSA PKCS#1 v1.5 over SHA-256, matching `openssl dgst -sha256 -sign`.
pub(crate) fn rsa_sha256_sign(key: &RsaPrivateKey, payload: &[u8]) -> Vec<u8> {
    let signing_key = rsa::pkcs1v15::SigningKey::<Sha256>::new(key.clone());
    signing_key.sign(payload).to_vec()
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use aos_release::signing::{
        SIGNING_REQUEST_DOMAIN, SignerRole, TrustedEd25519Key, verify_ed25519_response,
    };
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::config::{CONFIG_SCHEMA_V1, KeyEntry, KeyMaterial, ToolPaths};
    use crate::keys::tests::{write_ed25519_pem, write_openssh_key};

    const SEED: [u8; 32] = [11_u8; 32];

    fn request(role: SignerRole, key_id: &str, payload: &[u8]) -> SigningRequestV1 {
        SigningRequestV1 {
            schema_version: SIGNING_REQUEST_DOMAIN.into(),
            request_id: "test/request-1".into(),
            nonce: "ab".repeat(32),
            registry: "andyl/testing".into(),
            release_id: "release-1".into(),
            plan_digest: Sha256Digest::of_bytes("plan"),
            manifest_digest: None,
            role,
            key_id: key_id.into(),
            provider_revision: "test-provider-v1".into(),
            algorithm: SignatureAlgorithm::Ed25519,
            operation: SigningOperation::SignPayload,
            context: SigningContext::Payload {
                artifact_kind: "evidence".into(),
            },
            payload_digest: Sha256Digest::of_bytes(payload),
            approval_policy_digest: Sha256Digest::of_bytes("approval"),
        }
    }

    fn config(dir: &Path) -> SignerConfigV1 {
        let ed25519 = write_ed25519_pem(dir, SEED);
        let (openssh, blob) = write_openssh_key(dir, [12_u8; 32]);
        for path in [&ed25519, &openssh] {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        SignerConfigV1 {
            schema_version: CONFIG_SCHEMA_V1.into(),
            provider_revision: "test-provider-v1".into(),
            registries: vec!["andyl/testing".into()],
            tools: ToolPaths::default(),
            keys: vec![
                KeyEntry {
                    key_id: "evidence-v1".into(),
                    roles: vec![SignerRole::ReleaseEvidence, SignerRole::Qualification],
                    verification_identity: "evidence-authority".into(),
                    material: KeyMaterial::Ed25519Pkcs8Pem {
                        private_key: ed25519,
                    },
                },
                KeyEntry {
                    key_id: "registry-v1".into(),
                    roles: vec![SignerRole::Registry],
                    verification_identity: "registry-authority".into(),
                    material: KeyMaterial::OpensshEd25519 {
                        private_key: openssh,
                        trust_line: format!("test:Ed25519:{blob}"),
                    },
                },
            ],
        }
    }

    fn exchange(request: &SigningRequestV1, payload: &[u8]) -> ExchangeRequest {
        ExchangeRequest {
            request: canonical::to_vec(request).unwrap(),
            payload: payload.to_vec(),
        }
    }

    #[test]
    fn detached_ed25519_responses_verify_against_the_public_key() {
        let dir = tempfile::tempdir().unwrap();
        let config = config(dir.path());
        let payload = b"canonical evidence";
        let request = request(SignerRole::ReleaseEvidence, "evidence-v1", payload);

        let signed = sign_exchange(&config, &exchange(&request, payload)).unwrap();

        assert!(signed.output.is_empty());
        assert_eq!(signed.response.verification_identity, "evidence-authority");
        let trusted = TrustedEd25519Key {
            key_id: "evidence-v1".into(),
            public_key: SigningKey::from_bytes(&SEED).verifying_key().to_bytes(),
        };
        verify_ed25519_response(&request, &signed.response, &trusted).unwrap();
    }

    #[test]
    fn raw_payload_mode_signs_exact_payload_bytes() {
        use ed25519_dalek::Verifier as _;

        let dir = tempfile::tempdir().unwrap();
        let config = config(dir.path());
        let payload = b"sha256:0000";
        let mut request = request(SignerRole::Qualification, "evidence-v1", payload);
        request.algorithm = SignatureAlgorithm::Ed25519Payload;
        request.context = SigningContext::Payload {
            artifact_kind: "qualification-receipt-digest".into(),
        };

        let signed = sign_exchange(&config, &exchange(&request, payload)).unwrap();

        let signature = base64::engine::general_purpose::STANDARD
            .decode(&signed.response.signature_base64)
            .unwrap();
        let signature = ed25519_dalek::Signature::from_slice(&signature).unwrap();
        SigningKey::from_bytes(&SEED)
            .verifying_key()
            .verify(payload, &signature)
            .unwrap();
    }

    #[test]
    fn sshsig_git_signatures_verify_in_the_git_namespace() {
        let dir = tempfile::tempdir().unwrap();
        let config = config(dir.path());
        let payload = b"tree 0000\nauthor a\n";
        let mut request = request(SignerRole::Registry, "registry-v1", payload);
        request.algorithm = SignatureAlgorithm::SshsigEd25519;
        request.operation = SigningOperation::SignGitObject;
        request.context = SigningContext::Git {
            object_kind: "commit".into(),
        };

        let signed = sign_exchange(&config, &exchange(&request, payload)).unwrap();

        let armored = base64::engine::general_purpose::STANDARD
            .decode(&signed.response.signature_base64)
            .unwrap();
        let signature = ssh_key::SshSig::from_pem(&armored).unwrap();
        let KeyMaterial::OpensshEd25519 { trust_line, .. } = &config.keys[1].material else {
            panic!("expected OpenSSH material");
        };
        let blob = trust_line.rsplit(':').next().unwrap();
        let public = ssh_key::PublicKey::from_openssh(&format!("ssh-ed25519 {blob}")).unwrap();
        public.verify("git", payload, &signature).unwrap();
        assert_eq!(
            signed.response.verification_material_digest,
            Sha256Digest::of_bytes(trust_line.as_bytes())
        );
    }

    #[test]
    fn refuses_foreign_registries_roles_and_changed_payloads() {
        let dir = tempfile::tempdir().unwrap();
        let config = config(dir.path());
        let payload = b"payload";

        let mut foreign = request(SignerRole::ReleaseEvidence, "evidence-v1", payload);
        foreign.registry = "andyl/main".into();
        assert!(sign_exchange(&config, &exchange(&foreign, payload)).is_err());

        let wrong_role = request(SignerRole::TufRoot, "evidence-v1", payload);
        assert!(sign_exchange(&config, &exchange(&wrong_role, payload)).is_err());

        let mut revision = request(SignerRole::ReleaseEvidence, "evidence-v1", payload);
        revision.provider_revision = "other-provider".into();
        assert!(sign_exchange(&config, &exchange(&revision, payload)).is_err());

        let request = request(SignerRole::ReleaseEvidence, "evidence-v1", payload);
        assert!(sign_exchange(&config, &exchange(&request, b"changed")).is_err());
    }
}

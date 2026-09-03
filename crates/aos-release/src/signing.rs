//! Role-bound signing requests, responses, and public-key verification.
//!
//! Providers receive a canonical request rather than an arbitrary pathname or
//! command line. The response repeats the request digest and signer role so it
//! cannot be replayed across releases, registries, roles, or operations.

use anyhow::{Context as _, Result, bail};
use base64::Engine as _;
use ed25519_dalek::pkcs8::DecodePublicKey as _;
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::CANONICAL_REGISTRY;
use crate::artifact::require_identifier;
use crate::digest::Sha256Digest;
use crate::platform::Platform;

/// Signature domain for canonical release signing requests.
pub const SIGNING_REQUEST_DOMAIN: &str = "aos.release.signing-request/v1";

/// Independent authorities used by release construction and publication.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SignerRole {
    /// Registry commit and tag authority.
    Registry,
    /// Nix cache narinfo authority.
    Cache,
    /// Stable delegated release authority.
    TufStable,
    /// Candidate delegated release authority.
    TufCandidate,
    /// Edge delegated release authority.
    TufEdge,
    /// TUF root authority.
    TufRoot,
    /// TUF top-level targets authority.
    TufTargets,
    /// TUF snapshot authority.
    TufSnapshot,
    /// Restricted online TUF timestamp authority.
    TufTimestamp,
    /// Secure Boot db Authenticode authority.
    SecureBootDb,
    /// Kernel module-signing authority.
    KernelModule,
    /// Measured-boot PCR policy authority.
    PcrPolicy,
    /// Provenance DSSE authority.
    Provenance,
    /// Release manifest and journal evidence authority.
    ReleaseEvidence,
    /// Signed channel-operation authority.
    Channel,
}

/// Supported signature mechanisms at the release-contract boundary.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SignatureAlgorithm {
    /// Ed25519 over a domain-separated request digest.
    Ed25519,
    /// Authenticode signing performed by an external provider.
    Authenticode,
    /// Linux kernel module signature performed by an external provider.
    KernelModule,
    /// systemd measured-boot PCR policy signed by an external provider.
    PcrPolicy,
    /// OpenSSH SSHSIG Ed25519 signature.
    SshsigEd25519,
}

/// Operation authorized by one narrow signing request.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SigningOperation {
    /// Signs canonical release metadata or evidence.
    SignPayload,
    /// Signs one PE/COFF executable with Authenticode.
    SignPe,
    /// Signs one Linux kernel module.
    SignKernelModule,
    /// Signs a PCR policy digest.
    SignPcrPolicy,
    /// Signs one Git commit or tag with SSHSIG.
    SignGitObject,
}

/// Operation-specific policy context bound into one signing request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum SigningContext {
    /// Target-independent canonical metadata or evidence.
    Payload {
        /// Closed metadata or evidence kind understood by provider policy.
        artifact_kind: String,
    },
    /// One PE/COFF input authorized for Authenticode finalization.
    Pe {
        /// Linux target whose firmware consumes the result.
        platform: Platform,
        /// System variant containing the PE input.
        system_variant: String,
        /// PE machine value encoded as lowercase hexadecimal.
        pe_machine: String,
        /// Monotonic SBAT generation carried by the final PE image.
        sbat_generation: u64,
        /// Closed PE purpose, such as `uki`, `recovery-uki`, or `bootloader`.
        artifact_kind: String,
    },
    /// One loadable kernel module input.
    KernelModule {
        /// Linux target whose kernel loads the module.
        platform: Platform,
        /// System variant containing the module.
        system_variant: String,
        /// Kernel release whose module ABI is authorized.
        kernel_release: String,
        /// Relative module identity from the unsigned assembly manifest.
        module_id: String,
    },
    /// One measured-boot PCR policy payload.
    PcrPolicy {
        /// Linux target whose TPM policy consumes the signature.
        platform: Platform,
        /// System variant containing the measured boot chain.
        system_variant: String,
        /// Sorted, unique PCR indices selected by policy.
        pcrs: Vec<u8>,
    },
    /// One independently versioned TUF metadata role.
    Tuf {
        /// Exact metadata role name.
        metadata_role: String,
        /// Monotonic metadata version.
        metadata_version: u64,
    },
    /// One signed Git object in the canonical registry transaction.
    Git {
        /// Closed Git object kind: `commit` or `tag`.
        object_kind: String,
    },
    /// One compare-and-swap channel partition operation.
    Channel {
        /// Closed channel name.
        channel: String,
        /// Inclusive first rollout partition.
        first_partition: u16,
        /// Inclusive final rollout partition.
        last_partition: u16,
        /// Exact expected prior channel generation.
        prior_generation: u64,
    },
}

/// Threshold and allowed-key policy for one signer role.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignerRequirement {
    /// Independent role governed by this requirement.
    pub role: SignerRole,
    /// Stable public key ids eligible for the role.
    pub key_ids: Vec<String>,
    /// Minimum distinct allowed keys required.
    pub threshold: u16,
    /// Exact provider policy revision frozen by the plan.
    pub provider_revision: String,
}

impl SignerRequirement {
    /// Validates the role's threshold and key roster.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty, duplicate, or invalid key id, an invalid
    /// provider revision, or a zero/unattainable threshold.
    pub fn validate(&self) -> Result<()> {
        if self.key_ids.is_empty()
            || usize::from(self.threshold) > self.key_ids.len()
            || self.threshold == 0
        {
            bail!("signer threshold must be nonzero and attainable");
        }
        for key_id in &self.key_ids {
            require_identifier(key_id, "signer key id")?;
        }
        let mut keys = self.key_ids.clone();
        keys.sort();
        if keys.windows(2).any(|pair| pair[0] == pair[1]) {
            bail!("signer requirement contains a duplicate key id");
        }
        require_identifier(&self.provider_revision, "provider revision")
    }
}

/// Canonical, policy-bound request sent to an external signing adapter.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SigningRequestV1 {
    /// Exact request schema identifier.
    pub schema_version: String,
    /// Unique request id retained in the signed journal.
    pub request_id: String,
    /// Unpredictable anti-replay nonce encoded as lowercase hexadecimal.
    pub nonce: String,
    /// Canonical registry identity.
    pub registry: String,
    /// Immutable release id.
    pub release_id: String,
    /// Frozen release-plan digest.
    pub plan_digest: Sha256Digest,
    /// Final release-manifest digest when known.
    pub manifest_digest: Option<Sha256Digest>,
    /// Independent requested signer role.
    pub role: SignerRole,
    /// Exact public key id requested.
    pub key_id: String,
    /// Exact provider policy revision.
    pub provider_revision: String,
    /// Required signature mechanism.
    pub algorithm: SignatureAlgorithm,
    /// Narrow requested operation.
    pub operation: SigningOperation,
    /// Closed operation-specific authorization context.
    pub context: SigningContext,
    /// Exact payload or unsigned-artifact digest.
    pub payload_digest: Sha256Digest,
    /// Digest of the approval and operator policy applied to this request.
    pub approval_policy_digest: Sha256Digest,
}

impl SigningRequestV1 {
    /// Validates the complete signer-facing policy boundary.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported schema, malformed identity or
    /// nonce, noncanonical registry, incompatible algorithm and operation, or
    /// missing/unexpected platform context.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != SIGNING_REQUEST_DOMAIN {
            bail!("unsupported signing request schema");
        }
        require_identifier(&self.request_id, "signing request id")?;
        require_identifier(&self.release_id, "release id")?;
        require_identifier(&self.key_id, "signer key id")?;
        require_identifier(&self.provider_revision, "provider revision")?;
        if self.registry != CANONICAL_REGISTRY {
            bail!("canonical signing requests require registry {CANONICAL_REGISTRY}");
        }
        if self.nonce.len() != 64
            || !self
                .nonce
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            bail!("signing request nonce must be 32 bytes of lowercase hexadecimal");
        }
        let operation_matches = matches!(
            (self.algorithm, self.operation),
            (SignatureAlgorithm::Ed25519, SigningOperation::SignPayload)
                | (SignatureAlgorithm::Ed25519, SigningOperation::SignPcrPolicy)
                | (SignatureAlgorithm::Authenticode, SigningOperation::SignPe)
                | (
                    SignatureAlgorithm::KernelModule,
                    SigningOperation::SignKernelModule
                )
                | (
                    SignatureAlgorithm::PcrPolicy,
                    SigningOperation::SignPcrPolicy
                )
                | (
                    SignatureAlgorithm::SshsigEd25519,
                    SigningOperation::SignGitObject
                )
        );
        if !operation_matches {
            bail!("signature algorithm is incompatible with the requested operation");
        }
        self.context.validate(self.role, self.operation)
    }

    /// Computes the digest external signers authorize.
    ///
    /// # Errors
    ///
    /// Returns an error when the request is invalid or cannot be represented as
    /// canonical JSON.
    pub fn digest(&self) -> Result<Sha256Digest> {
        self.validate()?;
        Sha256Digest::of_canonical(SIGNING_REQUEST_DOMAIN, self)
    }
}

/// Public result returned by an external signing adapter.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureResponseV1 {
    /// Exact response schema identifier.
    pub schema_version: String,
    /// Digest of the complete canonical signing request.
    pub request_digest: Sha256Digest,
    /// Role actually applied by the provider.
    pub role: SignerRole,
    /// Public key id actually applied by the provider.
    pub key_id: String,
    /// Provider policy revision actually applied.
    pub provider_revision: String,
    /// Signature mechanism actually applied.
    pub algorithm: SignatureAlgorithm,
    /// Provider operation id used for audit and reconciliation.
    pub provider_operation_id: String,
    /// Public key or certificate identity independently pinned by the caller.
    pub verification_identity: String,
    /// Digest of provider-supplied public verification material or certificate chain.
    pub verification_material_digest: Sha256Digest,
    /// Exact signed-artifact digest for transforming signing operations.
    pub output_digest: Option<Sha256Digest>,
    /// Base64 signature for detached-signature mechanisms.
    pub signature_base64: String,
}

impl SigningContext {
    fn validate(&self, role: SignerRole, operation: SigningOperation) -> Result<()> {
        match (self, operation) {
            (Self::Payload { artifact_kind }, SigningOperation::SignPayload) => {
                require_identifier(artifact_kind, "signing artifact kind")?;
            }
            (
                Self::Pe {
                    platform,
                    system_variant,
                    pe_machine,
                    artifact_kind,
                    ..
                },
                SigningOperation::SignPe,
            ) => {
                require_linux_platform(*platform)?;
                require_identifier(system_variant, "signing system variant")?;
                require_identifier(artifact_kind, "signing artifact kind")?;
                if pe_machine.len() != 4
                    || !pe_machine
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                {
                    bail!("PE machine must be four lowercase hexadecimal characters");
                }
                if role != SignerRole::SecureBootDb {
                    bail!("PE signing requires the Secure Boot db role");
                }
            }
            (
                Self::KernelModule {
                    platform,
                    system_variant,
                    kernel_release,
                    module_id,
                },
                SigningOperation::SignKernelModule,
            ) => {
                require_linux_platform(*platform)?;
                require_identifier(system_variant, "signing system variant")?;
                require_identifier(kernel_release, "kernel release")?;
                require_identifier(module_id, "kernel module id")?;
                if role != SignerRole::KernelModule {
                    bail!("kernel-module signing requires the kernel-module role");
                }
            }
            (
                Self::PcrPolicy {
                    platform,
                    system_variant,
                    pcrs,
                },
                SigningOperation::SignPcrPolicy,
            ) => {
                require_linux_platform(*platform)?;
                require_identifier(system_variant, "signing system variant")?;
                if pcrs.is_empty() || pcrs.iter().any(|pcr| *pcr > 23) {
                    bail!("PCR policy must select indices within 0..=23");
                }
                if pcrs.windows(2).any(|pair| pair[0] >= pair[1]) {
                    bail!("PCR policy indices must be sorted and unique");
                }
                if role != SignerRole::PcrPolicy {
                    bail!("PCR policy signing requires the PCR policy role");
                }
            }
            (
                Self::Tuf {
                    metadata_role,
                    metadata_version,
                },
                SigningOperation::SignPayload,
            ) => {
                require_identifier(metadata_role, "TUF metadata role")?;
                if *metadata_version == 0 {
                    bail!("TUF metadata version must be nonzero");
                }
                let expected = match metadata_role.as_str() {
                    "root" => SignerRole::TufRoot,
                    "targets" => SignerRole::TufTargets,
                    "snapshot" => SignerRole::TufSnapshot,
                    "timestamp" => SignerRole::TufTimestamp,
                    "stable" => SignerRole::TufStable,
                    "candidate" => SignerRole::TufCandidate,
                    "edge" => SignerRole::TufEdge,
                    _ => bail!("unknown TUF metadata role"),
                };
                if role != expected {
                    bail!("TUF metadata role does not match signer authority");
                }
            }
            (Self::Git { object_kind }, SigningOperation::SignGitObject) => {
                if !matches!(object_kind.as_str(), "commit" | "tag") {
                    bail!("Git signing object kind must be commit or tag");
                }
                if role != SignerRole::Registry {
                    bail!("Git object signing requires the registry role");
                }
            }
            (
                Self::Channel {
                    channel,
                    first_partition,
                    last_partition,
                    ..
                },
                SigningOperation::SignPayload,
            ) => {
                if !matches!(channel.as_str(), "edge" | "candidate" | "stable") {
                    bail!("unknown release channel");
                }
                if first_partition > last_partition || *last_partition > 255 {
                    bail!("channel partition range must be within 0..=255");
                }
                if role != SignerRole::Channel {
                    bail!("channel signing requires the channel role");
                }
            }
            _ => bail!("signing context is incompatible with the requested operation"),
        }
        Ok(())
    }
}

fn require_linux_platform(platform: Platform) -> Result<()> {
    if !platform.supports_images() {
        bail!("boot signing operations require a Linux platform");
    }
    Ok(())
}

/// One externally supplied trusted Ed25519 public key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedEd25519Key {
    /// Stable key id used by signer policies.
    pub key_id: String,
    /// Exact 32-byte Ed25519 public key.
    pub public_key: [u8; 32],
}

impl TrustedEd25519Key {
    /// Parses raw, lowercase hexadecimal, base64, or PKCS#8 PEM public bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid key id, unsupported encoding, wrong
    /// length, malformed DER, or a value that is not an Ed25519 public key.
    pub fn from_encoded(key_id: impl Into<String>, encoded: &[u8]) -> Result<Self> {
        let key_id = key_id.into();
        require_identifier(&key_id, "trusted key id")?;
        let public_key = parse_public_key(encoded)?;
        Ok(Self { key_id, public_key })
    }
}

fn parse_public_key(encoded: &[u8]) -> Result<[u8; 32]> {
    if encoded.len() == 32 {
        return encoded
            .try_into()
            .map_err(|_| anyhow::anyhow!("Ed25519 public key must contain 32 bytes"));
    }
    let text = std::str::from_utf8(encoded)
        .context("Ed25519 public key is neither raw bytes nor UTF-8")?
        .trim();
    if text.starts_with("-----BEGIN PUBLIC KEY-----") {
        let body: String = text
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .map(str::trim)
            .collect();
        let der = base64::engine::general_purpose::STANDARD
            .decode(body)
            .context("decoding Ed25519 public-key PEM")?;
        let key =
            VerifyingKey::from_public_key_der(&der).context("parsing Ed25519 public-key PEM")?;
        return Ok(key.to_bytes());
    }
    if text.len() == 64
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        let mut bytes = [0_u8; 32];
        for (index, chunk) in text.as_bytes().chunks_exact(2).enumerate() {
            let pair = std::str::from_utf8(chunk).context("decoding public-key hex")?;
            bytes[index] = u8::from_str_radix(pair, 16).context("decoding public-key hex")?;
        }
        VerifyingKey::from_bytes(&bytes).context("parsing Ed25519 public key")?;
        return Ok(bytes);
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(text)
        .context("decoding Ed25519 public-key base64")?;
    let bytes: [u8; 32] = decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("Ed25519 public key must contain 32 bytes"))?;
    VerifyingKey::from_bytes(&bytes).context("parsing Ed25519 public key")?;
    Ok(bytes)
}

/// Verifies an Ed25519 response against its complete request.
///
/// # Errors
///
/// Returns an error for any request-binding mismatch, wrong key, malformed
/// base64, malformed signature, or invalid signature.
pub fn verify_ed25519_response(
    request: &SigningRequestV1,
    response: &SignatureResponseV1,
    trusted_key: &TrustedEd25519Key,
) -> Result<()> {
    verify_response_binding(request, response)?;
    if response.key_id != trusted_key.key_id || response.algorithm != SignatureAlgorithm::Ed25519 {
        bail!("signature response does not match its trusted Ed25519 key");
    }
    if response.output_digest.is_some() {
        bail!("detached Ed25519 response cannot claim a transformed output");
    }

    let bytes = base64::engine::general_purpose::STANDARD
        .decode(&response.signature_base64)
        .context("decoding Ed25519 signature")?;
    let signature = Signature::from_slice(&bytes).context("parsing Ed25519 signature")?;
    let key = VerifyingKey::from_bytes(&trusted_key.public_key)
        .context("parsing trusted Ed25519 public key")?;
    key.verify(response.request_digest.as_bytes(), &signature)
        .context("verifying Ed25519 signing response")
}

/// Verifies the non-cryptographic request/response binding shared by adapters.
///
/// This check does not establish authenticity. Callers must additionally
/// verify the returned signature or transformed artifact against independently
/// pinned public material before accepting a response.
///
/// # Errors
///
/// Returns an error for a malformed request or response, a request-digest,
/// role, key, provider-revision, or algorithm mismatch, or missing public
/// verification identity.
pub fn verify_response_binding(
    request: &SigningRequestV1,
    response: &SignatureResponseV1,
) -> Result<()> {
    if response.schema_version != "aos.release.signature-response/v1" {
        bail!("unsupported signature response schema");
    }
    if response.request_digest != request.digest()?
        || response.role != request.role
        || response.key_id != request.key_id
        || response.provider_revision != request.provider_revision
        || response.algorithm != request.algorithm
    {
        bail!("signature response does not match its request");
    }
    require_identifier(&response.provider_operation_id, "provider operation id")?;
    require_identifier(&response.verification_identity, "verification identity")?;

    let transforms_artifact = matches!(
        request.operation,
        SigningOperation::SignPe
            | SigningOperation::SignKernelModule
            | SigningOperation::SignPcrPolicy
    );
    if transforms_artifact != response.output_digest.is_some() {
        bail!("signature response has missing or unexpected transformed output digest");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> SigningRequestV1 {
        SigningRequestV1 {
            schema_version: SIGNING_REQUEST_DOMAIN.to_owned(),
            request_id: "request-1".to_owned(),
            nonce: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
            registry: CANONICAL_REGISTRY.to_owned(),
            release_id: "release-2026.09.03".to_owned(),
            plan_digest: Sha256Digest::of_bytes("plan"),
            manifest_digest: Some(Sha256Digest::of_bytes("manifest")),
            role: SignerRole::ReleaseEvidence,
            key_id: "release-key-1".to_owned(),
            provider_revision: "provider-v1".to_owned(),
            algorithm: SignatureAlgorithm::Ed25519,
            operation: SigningOperation::SignPayload,
            context: SigningContext::Payload {
                artifact_kind: "release-manifest".to_owned(),
            },
            payload_digest: Sha256Digest::of_bytes("payload"),
            approval_policy_digest: Sha256Digest::of_bytes("approval"),
        }
    }

    #[test]
    fn request_rejects_weak_nonce_and_algorithm_confusion() {
        let mut weak_nonce = request();
        weak_nonce.nonce = "0123456789abcdef".to_owned();
        assert!(weak_nonce.validate().is_err());

        let mut confused = request();
        confused.algorithm = SignatureAlgorithm::Authenticode;
        assert!(confused.validate().is_err());
    }

    #[test]
    fn boot_operations_require_linux_platform_context() {
        let mut request = request();
        request.role = SignerRole::SecureBootDb;
        request.algorithm = SignatureAlgorithm::Authenticode;
        request.operation = SigningOperation::SignPe;
        assert!(request.validate().is_err());

        request.context = SigningContext::Pe {
            platform: Platform::Aarch64Darwin,
            system_variant: "production".to_owned(),
            pe_machine: "aa64".to_owned(),
            sbat_generation: 1,
            artifact_kind: "uki".to_owned(),
        };
        assert!(request.validate().is_err());

        request.context = SigningContext::Pe {
            platform: Platform::Aarch64Linux,
            system_variant: "production".to_owned(),
            pe_machine: "aa64".to_owned(),
            sbat_generation: 1,
            artifact_kind: "uki".to_owned(),
        };
        assert!(request.validate().is_ok());
    }

    #[test]
    fn role_specific_context_cannot_be_replayed() {
        let mut request = request();
        request.role = SignerRole::TufTimestamp;
        request.context = SigningContext::Tuf {
            metadata_role: "stable".to_owned(),
            metadata_version: 9,
        };
        assert!(request.validate().is_err());

        request.role = SignerRole::TufStable;
        assert!(request.validate().is_ok());
    }
}

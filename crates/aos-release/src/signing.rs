//! Role-bound signing requests, responses, and public-key verification.
//!
//! Providers receive a canonical request rather than an arbitrary pathname or
//! command line. The response repeats the request digest and signer role so it
//! cannot be replayed across releases, registries, roles, or operations.

use anyhow::{Context as _, Result, bail};
use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};

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
    /// Platform when the signed object is platform-specific.
    pub platform: Option<Platform>,
    /// Artifact kind or metadata role expected by the provider policy.
    pub artifact_kind: Option<String>,
    /// Exact payload or unsigned-artifact digest.
    pub payload_digest: Sha256Digest,
    /// Digest of the approval and operator policy applied to this request.
    pub approval_policy_digest: Sha256Digest,
}

impl SigningRequestV1 {
    /// Computes the digest external signers authorize.
    ///
    /// # Errors
    ///
    /// Returns an error when this request cannot be represented as canonical
    /// JSON.
    pub fn digest(&self) -> Result<Sha256Digest> {
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
    /// Base64 signature for detached-signature mechanisms.
    pub signature_base64: String,
}

/// One externally supplied trusted Ed25519 public key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedEd25519Key {
    /// Stable key id used by signer policies.
    pub key_id: String,
    /// Exact 32-byte Ed25519 public key.
    pub public_key: [u8; 32],
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
    if response.schema_version != "aos.release.signature-response/v1" {
        bail!("unsupported signature response schema");
    }
    if response.request_digest != request.digest()?
        || response.role != request.role
        || response.key_id != request.key_id
        || response.key_id != trusted_key.key_id
        || response.provider_revision != request.provider_revision
        || response.algorithm != request.algorithm
        || response.algorithm != SignatureAlgorithm::Ed25519
    {
        bail!("signature response does not match its request and trusted key");
    }
    require_identifier(&response.provider_operation_id, "provider operation id")?;

    let bytes = base64::engine::general_purpose::STANDARD
        .decode(&response.signature_base64)
        .context("decoding Ed25519 signature")?;
    let signature = Signature::from_slice(&bytes).context("parsing Ed25519 signature")?;
    let key = VerifyingKey::from_bytes(&trusted_key.public_key)
        .context("parsing trusted Ed25519 public key")?;
    key.verify(response.request_digest.as_bytes(), &signature)
        .context("verifying Ed25519 signing response")
}

//! Closed canonical lease wire format and externally pinned Ed25519 keys.

use anyhow::{ensure, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::storage_authority::{
    canonical_digest, control::StorageAuthorityPublication, ApproveStorageAuthorityAlias,
    CreatePhysicalStorageAuthority, StorageAuthorityAdmissionState,
};

/// Maximum canonical envelope size, checked before parsing.
pub const MAX_EPOCH_LEASE_BYTES: usize = 32 * 1024;

const DOMAIN: &[u8] = b"aos.external-authority-epoch-lease.v1\0";

/// Nonnegative signed-64-bit integer encoded as a canonical decimal string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct LeaseInteger(i64);

impl LeaseInteger {
    /// Constructs a lossless counter or Unix-second timestamp.
    ///
    /// # Errors
    /// Returns an error for a negative value.
    pub fn new(value: i64) -> Result<Self> {
        ensure!(value >= 0, "negative lease integer");
        Ok(Self(value))
    }

    /// Returns the exact native value.
    pub fn get(self) -> i64 {
        self.0
    }
}

impl TryFrom<String> for LeaseInteger {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self> {
        let parsed = value.parse::<i64>()?;
        ensure!(parsed.to_string() == value, "noncanonical lease integer");
        Self::new(parsed)
    }
}

impl From<LeaseInteger> for String {
    fn from(value: LeaseInteger) -> Self {
        value.0.to_string()
    }
}

/// Single attested provider-credential purpose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeasePurpose {
    /// Read-only metadata and object reads.
    Read,
    /// Bounded prefix inventory with its own attested credential.
    List,
    /// Guarded writes and multipart session management.
    Write,
    /// Separately reviewed conditional deletion.
    Delete,
}

impl LeasePurpose {
    fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::List => "list",
            Self::Write => "write",
            Self::Delete => "delete",
        }
    }
}

/// Closed effect vocabulary, with no arbitrary code or provider commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseEffect {
    /// Exact metadata observation.
    Head,
    /// Bounded object read.
    Read,
    /// Bounded prefix inventory.
    List,
    /// Guarded visible object replacement.
    Put,
    /// Guarded multipart session creation.
    MultipartCreate,
    /// Exact guarded multipart part upload.
    MultipartPart,
    /// Guarded visible multipart completion.
    MultipartComplete,
    /// Guarded incomplete-session removal.
    MultipartAbort,
    /// Guarded conditional deletion with a separate reviewed action.
    ConditionalDelete,
}

impl LeaseEffect {
    fn purpose(self) -> LeasePurpose {
        match self {
            Self::Head | Self::Read => LeasePurpose::Read,
            Self::List => LeasePurpose::List,
            Self::ConditionalDelete => LeasePurpose::Delete,
            _ => LeasePurpose::Write,
        }
    }
}

/// Exact immutable binding projection with lossless wire counters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseAssociation {
    /// Reviewed association identity.
    pub association_id: String,
    /// Approved address alias identity.
    pub alias_id: String,
    /// Exact logical binding ID.
    pub binding_id: LeaseInteger,
    /// Immutable logical binding identity.
    pub binding_stable_id: String,
    /// Exact resource version.
    pub binding_resource_version: LeaseInteger,
    /// Exact writer revision.
    pub binding_write_revision: LeaseInteger,
    /// Canonical binding prefix.
    pub binding_prefix: String,
}

/// Single exact selected credential member, containing no raw secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseCredential {
    /// Owning association.
    pub association_id: String,
    /// Single credential purpose.
    pub purpose: LeasePurpose,
    /// Exact credential generation.
    pub generation: LeaseInteger,
    /// Immutable secret-version locator.
    pub secret_version_ref: String,
    /// Exact credential commitment.
    pub credential_fingerprint: String,
}

/// Exact authority/address/binding/credential cohort from a publication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseCohort {
    /// Permanent creation facts, including qualification ceiling.
    pub authority: CreatePhysicalStorageAuthority,
    /// Configured immutable executor.
    pub executor_identity: String,
    /// Exact admitted epoch.
    pub admission_generation: LeaseInteger,
    /// Exact admission-decision digest.
    pub admission_digest: String,
    /// Digest of the entire exact publication.
    pub publication_digest: String,
    /// Exact approved address and equivalence facts.
    pub alias: ApproveStorageAuthorityAlias,
    /// Exact binding association.
    pub association: LeaseAssociation,
    /// Exact single-purpose credential.
    pub credential: LeaseCredential,
    /// Exact exclusivity attestation identity.
    pub attestation_id: String,
    /// Exact attested prefix.
    pub attestation_prefix: String,
    /// Exact exclusive evidence expiry, independently projected by the verifier.
    pub attestation_valid_until: LeaseInteger,
    /// Narrowed canonical prefix including the binding prefix.
    pub admitted_prefix: String,
    /// Strictly sorted unique allowed effects.
    pub allowed_effects: Vec<LeaseEffect>,
}

impl LeaseCohort {
    /// Selects an exact admitted cohort from trusted publication inputs.
    ///
    /// Structural validation establishes neither live freshness nor provider
    /// exclusivity; actual issuer integration must separately establish both.
    ///
    /// # Errors
    /// Returns an error for denied/malformed publication, missing membership,
    /// malformed prefix, or effects outside the selected credential purpose.
    pub fn from_publication(
        publication: &StorageAuthorityPublication,
        executor: &str,
        association_id: &str,
        purpose: LeasePurpose,
        admitted_prefix: &str,
        allowed_effects: Vec<LeaseEffect>,
    ) -> Result<Self> {
        publication.validate(&publication.authority.guard_namespace_id, executor)?;
        ensure!(
            publication.admission.state == StorageAuthorityAdmissionState::Admitted,
            "authority is denied"
        );
        ensure!(
            publication
                .admission
                .association_ids
                .iter()
                .any(|id| id == association_id),
            "association is not admitted"
        );
        let association = publication
            .associations
            .iter()
            .find(|item| item.association_id == association_id)
            .ok_or_else(|| anyhow::anyhow!("missing association"))?;
        let attestation = publication
            .attestation
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing attestation"))?;
        let credential = attestation
            .credentials
            .iter()
            .find(|item| item.association_id == association_id && item.purpose == purpose.as_str())
            .ok_or_else(|| anyhow::anyhow!("missing purpose credential"))?;
        let alias = publication
            .aliases
            .iter()
            .find(|item| item.alias_id == association.alias_id)
            .ok_or_else(|| anyhow::anyhow!("missing alias"))?;

        let cohort = Self {
            authority: publication.authority.clone(),
            executor_identity: executor.to_owned(),
            admission_generation: LeaseInteger::new(publication.generation)?,
            admission_digest: publication.digest.clone(),
            publication_digest: canonical_digest(publication)?,
            alias: alias.clone(),
            association: LeaseAssociation {
                association_id: association.association_id.clone(),
                alias_id: association.alias_id.clone(),
                binding_id: LeaseInteger::new(association.binding_id)?,
                binding_stable_id: association.binding_stable_id.clone(),
                binding_resource_version: LeaseInteger::new(association.binding_resource_version)?,
                binding_write_revision: LeaseInteger::new(association.binding_write_revision)?,
                binding_prefix: association.binding_prefix.clone(),
            },
            credential: LeaseCredential {
                association_id: credential.association_id.clone(),
                purpose,
                generation: LeaseInteger::new(credential.generation)?,
                secret_version_ref: credential.secret_version_ref.clone(),
                credential_fingerprint: credential.credential_fingerprint.clone(),
            },
            attestation_id: attestation.attestation_id.clone(),
            attestation_prefix: attestation.managed_prefix.clone(),
            attestation_valid_until: LeaseInteger::new(attestation.valid_until)?,
            admitted_prefix: admitted_prefix.to_owned(),
            allowed_effects,
        };
        cohort.validate()?;
        Ok(cohort)
    }

    pub(super) fn validate(&self) -> Result<()> {
        self.authority.validate()?;
        key(&self.executor_identity, 255)?;
        ensure!(
            self.admission_generation.get() > 0
                && self.admission_generation.get()
                    <= crate::storage_authority::control::MAX_AUTHORITY_GENERATION,
            "invalid admission generation"
        );
        digest(&self.admission_digest)?;
        digest(&self.publication_digest)?;
        self.alias.spec.validate()?;
        key(&self.alias.alias_id, 64)?;
        digest(&self.alias.equivalence_evidence_digest)?;
        ensure!(
            self.alias.authority_id == self.authority.authority_id
                && self.alias.alias_id == self.association.alias_id,
            "alias mismatch"
        );
        key(&self.association.association_id, 64)?;
        key(&self.association.binding_stable_id, 255)?;
        ensure!(
            self.association.binding_id.get() > 0
                && self.association.binding_resource_version.get() > 0
                && self.association.binding_write_revision.get() > 0,
            "invalid binding counters"
        );
        ensure!(
            self.credential.association_id == self.association.association_id
                && self.credential.generation.get() > 0,
            "credential association mismatch"
        );
        key(&self.credential.secret_version_ref, 255)?;
        digest(&self.credential.credential_fingerprint)?;
        key(&self.attestation_id, 64)?;
        for value in [
            &self.association.binding_prefix,
            &self.attestation_prefix,
            &self.admitted_prefix,
        ] {
            prefix(value, 512)?;
        }
        ensure!(
            contains(&self.admitted_prefix, &self.association.binding_prefix)
                && contains(&self.admitted_prefix, &self.attestation_prefix)
                && contains(
                    &self.attestation_prefix,
                    &self.authority.qualified_managed_prefix
                ),
            "lease prefix exceeds reviewed scope"
        );
        ensure!(
            !self.allowed_effects.is_empty()
                && self.allowed_effects.len() <= 9
                && self
                    .allowed_effects
                    .windows(2)
                    .all(|pair| pair[0] < pair[1])
                && self
                    .allowed_effects
                    .iter()
                    .all(|effect| effect.purpose() == self.credential.purpose),
            "invalid effect scope"
        );
        Ok(())
    }
}

/// Explicit reviewed lifetime and clock bounds, with no default policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseTimingProfile {
    /// Stable reviewed profile identity.
    pub profile_id: String,
    /// Commitment to lifetime/clock qualification evidence.
    pub review_digest: String,
    /// Positive maximum lifetime in seconds.
    pub maximum_lifetime: LeaseInteger,
    /// Maximum qualified absolute clock uncertainty in seconds.
    pub maximum_clock_uncertainty: LeaseInteger,
}

impl LeaseTimingProfile {
    /// Validates finite explicit bounds without proving qualification.
    ///
    /// # Errors
    /// Returns an error for malformed identity/evidence or zero lifetime.
    pub fn validate(&self) -> Result<()> {
        key(&self.profile_id, 255)?;
        digest(&self.review_digest)?;
        ensure!(self.maximum_lifetime.get() > 0, "zero lifetime");
        Ok(())
    }
}

/// Closed canonical signed payload with exact integer strings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpochLeasePayload {
    /// Protocol version, currently one.
    pub protocol_version: u8,
    /// Identifier of the independently configured verifier key.
    pub issuer_key_id: String,
    /// Exact authority and execution cohort.
    pub cohort: LeaseCohort,
    /// Exact reviewed profile.
    pub timing_profile: LeaseTimingProfile,
    /// Observed issuance Unix-second timestamp.
    pub issued_at: LeaseInteger,
    /// Exclusive admission expiry, never provider settlement.
    pub not_after: LeaseInteger,
    /// Authority-wide sequence retained across epochs.
    pub lease_sequence: LeaseInteger,
}

impl EpochLeasePayload {
    pub(super) fn validate(&self) -> Result<()> {
        ensure!(self.protocol_version == 1, "unsupported lease version");
        key(&self.issuer_key_id, 255)?;
        self.cohort.validate()?;
        self.timing_profile.validate()?;
        let lifetime = self
            .not_after
            .get()
            .checked_sub(self.issued_at.get())
            .ok_or_else(|| anyhow::anyhow!("lifetime overflow"))?;
        ensure!(
            lifetime > 0
                && lifetime <= self.timing_profile.maximum_lifetime.get()
                && self.lease_sequence.get() > 0
                && self.not_after <= self.cohort.attestation_valid_until,
            "invalid lifetime or sequence"
        );
        Ok(())
    }

    /// Computes the exact payload commitment for local fork/replay floors.
    ///
    /// # Errors
    /// Returns an error for invalid payload or serialization failure.
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        canonical_digest(self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    payload: EpochLeasePayload,
    signature: String,
}

/// Issuer-only signer with redacted debug and no secret serialization/accessor.
pub struct EpochLeaseSigningKey {
    key_id: String,
    key: SigningKey,
}

impl std::fmt::Debug for EpochLeaseSigningKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EpochLeaseSigningKey")
            .field("key_id", &self.key_id)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl EpochLeaseSigningKey {
    /// Loads issuer-only secret material from the trusted deployment seam.
    ///
    /// # Errors
    /// Returns an error for malformed configured key identity.
    pub fn from_bytes(key_id: String, secret: &[u8; 32]) -> Result<Self> {
        key(&key_id, 255)?;
        Ok(Self {
            key_id,
            key: SigningKey::from_bytes(secret),
        })
    }

    pub(super) fn key_id(&self) -> &str {
        &self.key_id
    }

    pub(super) fn sign_domain(&self, domain: &[u8], bytes: &[u8]) -> String {
        let mut message = domain.to_vec();
        message.extend_from_slice(bytes);
        hex::encode(self.key.sign(&message).to_bytes())
    }

    pub(super) fn sign(&self, payload: EpochLeasePayload) -> Result<Vec<u8>> {
        payload.validate()?;
        ensure!(payload.issuer_key_id == self.key_id, "issuer key mismatch");
        let signature = hex::encode(self.key.sign(&message(&payload)?).to_bytes());
        let bytes = serde_json::to_vec(&Envelope { payload, signature })?;
        ensure!(
            bytes.len() <= MAX_EPOCH_LEASE_BYTES,
            "lease envelope too large"
        );
        Ok(bytes)
    }
}

/// Ed25519 verifier pinned independently of envelopes and archived publications.
#[derive(Debug, Clone)]
pub struct EpochLeaseVerifier {
    key_id: String,
    key: VerifyingKey,
}

impl EpochLeaseVerifier {
    /// Loads the executor's externally configured issuer trust anchor.
    ///
    /// # Errors
    /// Returns an error for malformed key identity or invalid public key bytes.
    pub fn from_bytes(key_id: String, public: &[u8; 32]) -> Result<Self> {
        key(&key_id, 255)?;
        Ok(Self {
            key_id,
            key: VerifyingKey::from_bytes(public)?,
        })
    }

    pub(super) fn verify_domain(
        &self,
        key_id: &str,
        domain: &[u8],
        bytes: &[u8],
        signature: &str,
    ) -> Result<()> {
        ensure!(key_id == self.key_id, "untrusted issuer key");
        ensure!(
            signature.len() == 128
                && signature
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalid canonical signature"
        );
        let mut message = domain.to_vec();
        message.extend_from_slice(bytes);
        self.key
            .verify_strict(&message, &Signature::from_slice(&hex::decode(signature)?)?)?;
        Ok(())
    }

    pub(super) fn verify(&self, bytes: &[u8]) -> Result<EpochLeasePayload> {
        ensure!(
            bytes.len() <= MAX_EPOCH_LEASE_BYTES,
            "lease envelope too large"
        );
        let envelope: Envelope = serde_json::from_slice(bytes)?;
        ensure!(
            serde_json::to_vec(&envelope)? == bytes,
            "noncanonical lease envelope"
        );
        envelope.payload.validate()?;
        ensure!(
            envelope.payload.issuer_key_id == self.key_id,
            "untrusted issuer identity"
        );
        ensure!(
            envelope.signature.len() == 128
                && envelope
                    .signature
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "invalid canonical signature"
        );
        let signature = Signature::from_slice(&hex::decode(envelope.signature)?)?;
        self.key
            .verify_strict(&message(&envelope.payload)?, &signature)?;
        Ok(envelope.payload)
    }
}

fn message(payload: &EpochLeasePayload) -> Result<Vec<u8>> {
    let mut bytes = DOMAIN.to_vec();
    bytes.extend(serde_json::to_vec(payload)?);
    ensure!(
        bytes.len() <= MAX_EPOCH_LEASE_BYTES - 256,
        "lease payload too large"
    );
    Ok(bytes)
}

pub(super) fn key(value: &str, maximum: usize) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= maximum
            && value.trim() == value
            && !value.chars().any(char::is_control),
        "invalid bounded identity"
    );
    Ok(())
}

pub(super) fn digest(value: &str) -> Result<()> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "invalid canonical digest"
    );
    Ok(())
}

pub(super) fn prefix(value: &str, maximum: usize) -> Result<()> {
    ensure!(
        value.len() <= maximum
            && value.trim() == value
            && !value.chars().any(char::is_control)
            && !value.contains('\\')
            && (value.is_empty()
                || value
                    .split('/')
                    .all(|part| !part.is_empty() && part != "." && part != "..")),
        "invalid canonical object prefix"
    );
    Ok(())
}

pub(super) fn contains(value: &str, base: &str) -> bool {
    base.is_empty()
        || value == base
        || value
            .strip_prefix(base)
            .is_some_and(|tail| tail.starts_with('/'))
}

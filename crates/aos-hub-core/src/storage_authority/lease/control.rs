//! Bounded live issuer control and independently pinned signed acknowledgments.
//!
//! Installation is an irreversible resource reservation outside Hub SQL. The
//! issuer persists publication, journal and generation receipt together. Neither
//! a registry receipt nor an issuance acknowledgment settles provider effects.
//!
//! ```json
//! {"protocol_version":1,"nonce":"<64 lowercase hex>","operation":{"kind":"current"}}
//! ```
//! This abbreviated example omits the required installation and bounded time.

use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};

use super::wire::{digest, key};
use super::{
    EpochLeaseIssuerJournal, EpochLeaseSigningKey, EpochLeaseVerifier, LeaseCohort, LeaseInteger,
};
use crate::storage_authority::{
    canonical_digest,
    control::{StorageAuthorityDeniedTransition, StorageAuthorityPublication},
    CreatePhysicalStorageAuthority,
};
use crate::storage_work::StorageWorkKey;

/// Bound checked before parsing any live issuer message.
pub const MAX_ISSUER_CONTROL_BYTES: usize = 1024 * 1024 - 512;
/// Dedicated live issuer endpoint; it grants no provider dispatch.
pub const ISSUER_CONTROL_PATH: &str = "/_aos/storage-authority/issuer/v1";
const REQUEST_DOMAIN: &[u8] = b"aos.external-authority-issuer-request.v1\0";
const REPLY_DOMAIN: &[u8] = b"aos.external-authority-issuer-reply.v1\0";
const DENIAL_DOMAIN: &[u8] = b"aos.external-authority-issuer-denial.v1\0";

/// Immutable issuer resource attachment, never recreated from Hub SQL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerInstallation {
    /// On-disk/resource format, currently one.
    pub format_version: u8,
    /// Complete permanent authority and qualification ceiling.
    pub authority: CreatePhysicalStorageAuthority,
    /// Operator-retained issuer namespace or private volume identity.
    pub issuer_resource_id: String,
    /// Dedicated immutable issuer deployment/service identity.
    pub runtime_identity: String,
    /// Independently configured storage executor.
    pub executor_identity: String,
}

impl IssuerInstallation {
    /// Validates immutable structural facts, without proving resource novelty.
    ///
    /// # Errors
    /// Returns an error for unsupported format or malformed domain identities.
    pub fn validate(&self) -> Result<()> {
        ensure!(self.format_version == 1, "unsupported issuer installation");
        self.authority.validate()?;
        key(&self.issuer_resource_id, 255)?;
        key(&self.runtime_identity, 255)?;
        key(&self.executor_identity, 255)
    }
}

/// Exact append-only generation commitment, retained beyond SQL reset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerPublicationReceipt {
    /// Lossless publication generation.
    pub generation: LeaseInteger,
    /// Reviewed admission commitment.
    pub admission_digest: String,
    /// Commitment of the entire installed publication.
    pub publication_digest: String,
}

impl IssuerPublicationReceipt {
    /// Projects an exact publication into its immutable generation receipt.
    ///
    /// # Errors
    /// Returns an error for invalid generation or serialization failure.
    pub fn from_publication(publication: &StorageAuthorityPublication) -> Result<Self> {
        Ok(Self {
            generation: LeaseInteger::new(publication.generation)?,
            admission_digest: publication.digest.clone(),
            publication_digest: canonical_digest(publication)?,
        })
    }

    /// Checks the receipt against the exact structurally valid publication.
    ///
    /// # Errors
    /// Returns an error for any changed commitment.
    pub fn validate(&self, publication: &StorageAuthorityPublication) -> Result<()> {
        ensure!(
            *self == Self::from_publication(publication)?,
            "issuer receipt differs"
        );
        digest(&self.admission_digest)?;
        digest(&self.publication_digest)
    }
}

/// Atomic durable issuer head; sequence and expiry survive publication changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerLiveState {
    /// Immutable independently configured installation.
    pub installation: IssuerInstallation,
    /// Exact retained current publication.
    pub publication: StorageAuthorityPublication,
    /// Issuance/revocation history under the same live gate.
    pub journal: EpochLeaseIssuerJournal,
}

impl IssuerLiveState {
    /// Checks exact persisted cross-record identity and commitments.
    ///
    /// This is structural validation, not a freshness or durability assertion.
    ///
    /// # Errors
    /// Returns an error for corrupt state or mismatched installation/head.
    pub fn validate(&self) -> Result<()> {
        self.installation.validate()?;
        self.journal.validate()?;
        self.publication.validate(
            &self.installation.authority.guard_namespace_id,
            &self.installation.executor_identity,
        )?;
        ensure!(
            self.publication.authority == self.installation.authority
                && self.journal.authority == self.installation.authority
                && self.journal.executor_identity == self.installation.executor_identity,
            "issuer permanent identity differs"
        );
        ensure!(
            self.journal.generation.get() == self.publication.generation
                && self.journal.admission_digest == self.publication.digest
                && self.journal.publication_digest == canonical_digest(&self.publication)?
                && self.journal.state == self.publication.admission.state,
            "issuer publication commitment differs"
        );
        Ok(())
    }
}

/// Compact signed live head; renewal never returns the publication member bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerHead {
    /// Exact permanent issuer resource and audience.
    pub installation: IssuerInstallation,
    /// Current epoch, full publication commitment and retained issuance history.
    pub journal: EpochLeaseIssuerJournal,
}

impl IssuerHead {
    /// Checks the compact head's immutable domain and structural history.
    ///
    /// # Errors
    /// Returns an error for malformed or cross-domain state.
    pub fn validate(&self) -> Result<()> {
        self.installation.validate()?;
        self.journal.validate()?;
        ensure!(
            self.installation.authority == self.journal.authority
                && self.installation.executor_identity == self.journal.executor_identity,
            "issuer head identity differs"
        );
        Ok(())
    }
}

impl IssuerLiveState {
    /// Projects a validated state into its bounded metadata-only signed head.
    ///
    /// # Errors
    /// Returns an error for corrupt persisted state.
    pub fn head(&self) -> Result<IssuerHead> {
        self.validate()?;
        Ok(IssuerHead {
            installation: self.installation.clone(),
            journal: self.journal.clone(),
        })
    }
}

/// Closed metadata-only operation accepted by the dedicated live issuer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "input",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum IssuerOperation {
    /// Installs the first publication after permanent registry reservation.
    Install(StorageAuthorityPublication),
    /// Advances an exact retained predecessor.
    Publish(StorageAuthorityPublication),
    /// Stops issuance across undelivered SQL history using a live exact CAS.
    Deny(StorageAuthorityDeniedTransition),
    /// Retrieves current issuer state, never provider readiness.
    Current,
    /// Requests one bounded cohort token.
    Issue {
        /// Exact immutable execution projection.
        cohort: LeaseCohort,
        /// Requested expiry, clamped by the explicitly configured issuer policy.
        requested_not_after: LeaseInteger,
    },
}

/// Fresh bounded request authenticated independently of signed responses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerRequest {
    /// Wire version, currently one.
    pub protocol_version: u8,
    /// Exact immutable audience/resource.
    pub installation: IssuerInstallation,
    /// Fresh 256-bit random request correlation.
    pub nonce: String,
    /// Caller-observed request time.
    pub issued_at: LeaseInteger,
    /// Exclusive short request deadline, no longer than thirty seconds.
    pub expires_at: LeaseInteger,
    /// Closed operation.
    pub operation: IssuerOperation,
}

impl IssuerRequest {
    /// Parses only bounded canonical bytes; duplicate and unknown fields fail.
    ///
    /// # Errors
    /// Returns an error for excessive, malformed or noncanonical input.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_ISSUER_CONTROL_BYTES,
            "issuer request exceeds bound"
        );
        let request: Self = serde_json::from_slice(bytes)?;
        ensure!(
            serde_json::to_vec(&request)? == bytes,
            "noncanonical issuer request"
        );
        Ok(request)
    }

    /// Returns the canonical request commitment used by issuer replies.
    ///
    /// # Errors
    /// Returns an error if serialization fails.
    pub fn digest(&self) -> Result<String> {
        canonical_digest(self)
    }

    /// Checks the external audience and fresh request window.
    ///
    /// # Errors
    /// Returns an error for audience changes, malformed correlation or expired time.
    pub fn validate(&self, expected: &IssuerInstallation, now: i64) -> Result<()> {
        self.installation.validate()?;
        ensure!(
            self.protocol_version == 1 && &self.installation == expected,
            "issuer audience differs"
        );
        digest(&self.nonce)?;
        let lifetime = self
            .expires_at
            .get()
            .checked_sub(self.issued_at.get())
            .ok_or_else(|| anyhow::anyhow!("request time overflow"))?;
        ensure!(
            lifetime > 0
                && lifetime <= 30
                && self.issued_at.get() <= now
                && now < self.expires_at.get(),
            "issuer request is stale"
        );
        Ok(())
    }
}

/// Metadata acknowledgment signed with the configured issuer-only Ed25519 key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerReply {
    /// Wire version.
    pub protocol_version: u8,
    /// Externally pinned signing key ID.
    pub issuer_key_id: String,
    /// Exact immutable resource/audience.
    pub installation: IssuerInstallation,
    /// Fresh request nonce.
    pub nonce: String,
    /// Exact canonical request digest.
    pub request_digest: String,
    /// Current live state after acknowledged durable persistence.
    pub current: IssuerHead,
    /// Immutable receipt for applied control, including exact old replays.
    pub applied: Option<IssuerPublicationReceipt>,
    /// Canonical epoch token, present only for successful issuance.
    pub lease: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplyEnvelope {
    payload: IssuerReply,
    signature: String,
}

/// Signs one bounded metadata reply in the distinct issuance or denial domain.
///
/// The caller must establish actual durable current-state provenance first.
///
/// # Errors
/// Returns an error for mismatched key/audience or oversized serialization.
pub fn sign_issuer_reply(
    signer: &EpochLeaseSigningKey,
    request: &IssuerRequest,
    reply: IssuerReply,
) -> Result<Vec<u8>> {
    validate_reply(request, &reply)?;
    ensure!(
        reply.issuer_key_id == signer.key_id(),
        "issuer signing identity differs"
    );
    let payload = serde_json::to_vec(&reply)?;
    ensure!(
        payload.len() <= MAX_ISSUER_CONTROL_BYTES - 256,
        "issuer reply exceeds bound"
    );
    let signature = signer.sign_domain(reply_domain(request), &payload);
    Ok(serde_json::to_vec(&ReplyEnvelope {
        payload: reply,
        signature,
    })?)
}

/// Verifies a bounded correlated reply using an external Ed25519 trust anchor.
///
/// # Errors
/// Returns an error for signature/domain/correlation/structural failures.
pub fn verify_issuer_reply(
    verifier: &EpochLeaseVerifier,
    request: &IssuerRequest,
    bytes: &[u8],
) -> Result<IssuerReply> {
    ensure!(
        bytes.len() <= MAX_ISSUER_CONTROL_BYTES,
        "issuer reply exceeds bound"
    );
    let envelope: ReplyEnvelope = serde_json::from_slice(bytes)?;
    ensure!(
        serde_json::to_vec(&envelope)? == bytes,
        "noncanonical issuer reply"
    );
    validate_reply(request, &envelope.payload)?;
    verifier.verify_domain(
        &envelope.payload.issuer_key_id,
        reply_domain(request),
        &serde_json::to_vec(&envelope.payload)?,
        &envelope.signature,
    )?;
    if let Some(lease) = &envelope.payload.lease {
        let payload = verifier.verify(lease.as_bytes())?;
        let IssuerOperation::Issue {
            cohort,
            requested_not_after,
        } = &request.operation
        else {
            anyhow::bail!("unexpected token");
        };
        ensure!(
            &payload.cohort == cohort
                && payload.cohort.authority == envelope.payload.current.installation.authority
                && payload.cohort.executor_identity
                    == envelope.payload.current.journal.executor_identity
                && payload.cohort.admission_generation
                    == envelope.payload.current.journal.generation
                && payload.cohort.admission_digest
                    == envelope.payload.current.journal.admission_digest
                && payload.cohort.publication_digest
                    == envelope.payload.current.journal.publication_digest
                && envelope.payload.current.journal.state
                    == crate::storage_authority::StorageAuthorityAdmissionState::Admitted
                && payload.not_after <= envelope.payload.current.journal.largest_issued_expiry
                && payload.timing_profile == envelope.payload.current.journal.policy.timing_profile
                && payload.lease_sequence == envelope.payload.current.journal.last_sequence
                && payload.not_after <= *requested_not_after,
            "issuer token projection differs"
        );
    }
    Ok(envelope.payload)
}

/// Verifies a correlated reply, then checks its deadline and token at fresh time.
///
/// The observer runs after all authenticated reply and token parsing/verification.
/// It must return an independently qualified conservative interval with durable
/// rollback continuity; configuration or cached time establishes no provenance.
/// Request deadlines and inner token expiry use the interval's upper bound. No
/// asynchronous operation follows that observation in this helper. This proves
/// neither object admission nor provider readiness; dispatch retains its exact
/// snapshot, cohort, permanent floor and pending-effect requirements.
///
/// # Errors
/// Returns an error for any ordinary reply/signature failure, failed or rolled-back
/// observation, excessive uncertainty, expired request or expired inner token.
pub fn verify_issuer_reply_at_time(
    verifier: &EpochLeaseVerifier,
    request: &IssuerRequest,
    bytes: &[u8],
    observe_clock: impl FnOnce() -> Result<super::LeaseClock>,
) -> Result<IssuerReply> {
    let reply = verify_issuer_reply(verifier, request, bytes)?;
    let payload = reply
        .lease
        .as_ref()
        .map(|lease| verifier.verify(lease.as_bytes()))
        .transpose()?;
    let clock = observe_clock()?;
    let (_, latest) = clock.bounds(
        &reply.current.journal.policy.timing_profile,
        reply.current.journal.clock_floor,
    )?;
    request.validate(&reply.installation, latest)?;
    if let Some(payload) = payload {
        super::state::validate_time(&payload, reply.current.journal.clock_floor, clock)?;
    }
    Ok(reply)
}

/// Authenticates exact bounded request bytes in the dedicated request domain.
///
/// # Errors
/// Returns an error for an oversized message or invalid configured key.
pub fn sign_issuer_request(key: &StorageWorkKey, bytes: &[u8]) -> Result<String> {
    ensure!(
        bytes.len() <= MAX_ISSUER_CONTROL_BYTES,
        "issuer request exceeds bound"
    );
    let mut input = REQUEST_DOMAIN.to_vec();
    input.extend_from_slice(bytes);
    Ok(key.sign_body(&input)?)
}

/// Verifies request authentication before parsing or durable storage access.
///
/// # Errors
/// Returns an error for excessive input, wrong domain or invalid signature.
pub fn verify_issuer_request(key: &StorageWorkKey, signature: &str, bytes: &[u8]) -> Result<()> {
    ensure!(
        signature.len() == 64
            && signature
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "issuer authentication tag is not canonical"
    );
    ensure!(
        bytes.len() <= MAX_ISSUER_CONTROL_BYTES,
        "issuer request exceeds bound"
    );
    let mut input = REQUEST_DOMAIN.to_vec();
    input.extend_from_slice(bytes);
    Ok(key.verify_body(signature, &input)?)
}

fn reply_domain(request: &IssuerRequest) -> &'static [u8] {
    if matches!(request.operation, IssuerOperation::Deny(_)) {
        DENIAL_DOMAIN
    } else {
        REPLY_DOMAIN
    }
}

fn validate_reply(request: &IssuerRequest, reply: &IssuerReply) -> Result<()> {
    reply.current.validate()?;
    ensure!(
        reply.protocol_version == 1
            && reply.installation == request.installation
            && reply.current.installation == request.installation
            && reply.nonce == request.nonce
            && reply.request_digest == canonical_digest(request)?,
        "issuer reply correlation differs"
    );
    ensure!(
        reply.lease.is_some() == matches!(request.operation, IssuerOperation::Issue { .. }),
        "issuer reply token shape differs"
    );
    ensure!(
        reply.applied.is_some()
            == matches!(
                request.operation,
                IssuerOperation::Install(_)
                    | IssuerOperation::Publish(_)
                    | IssuerOperation::Deny(_)
            ),
        "issuer control acknowledgment shape differs"
    );
    if let Some(receipt) = &reply.applied {
        let publication = match &request.operation {
            IssuerOperation::Install(p) | IssuerOperation::Publish(p) => p,
            IssuerOperation::Deny(t) => &t.publication,
            _ => anyhow::bail!("unexpected applied receipt"),
        };
        receipt.validate(publication)?;
        ensure!(
            reply.current.journal.generation >= receipt.generation,
            "issuer head behind receipt"
        );
        if reply.current.journal.generation == receipt.generation {
            ensure!(
                reply.current.journal.admission_digest == receipt.admission_digest
                    && reply.current.journal.publication_digest == receipt.publication_digest,
                "same-generation head contradicts receipt"
            );
        }
    }
    Ok(())
}

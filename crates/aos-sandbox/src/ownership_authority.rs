//! Exclusive ownership-lease acquisition boundary.
//!
//! The controller supplies immutable assignment identity and a bounded maximum
//! duration. Only the authority chooses lease generation, validity interval,
//! clock-skew allowance, and renewal nonce. A response remains explicitly
//! unverified until [`OwnershipAuthorityVerifier`] proves its canonical
//! signature, assignment, node, liveness, duration, and renewal fence.
//!
//! The future remote protocol may carry the fixed claim bytes directly:
//!
//! ```text
//! AOSOCLM1 || version:u16be || action:u8 || reserved:5 || request-id:16 ||
//! sandbox:16 || incarnation:16 || epoch:u64be || assignment-digest:32 ||
//! node:16 || desired-generation:u64be || expected-generation:u64be ||
//! expected-lease-digest:32 || requested-maximum-seconds:u64be
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use aos_sandbox_core::format::{decode_signature, encode_signature};
use aos_sandbox_core::model::KeyReference;
use aos_sandbox_core::{
    BrokerAssignment, DecodeLimits, DesiredGeneration, DurableHistoricalWallClockInstant,
    HistoricalOwnershipLeaseExpectation, IncarnationId, LeaseAssignment, NodeId, ObjectDigest,
    OwnershipLease, OwnershipLeaseTrustAnchor, RawPairedClockSample, SandboxId,
    VerifiedOwnershipLease, authenticate_historical_ownership_lease, verify_ownership_lease,
};
use sha2::{Digest as _, Sha256};

use crate::journal::{
    Journal, JournalError, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace,
    RecoveryReport,
};

const CLAIM_MAGIC: &[u8; 8] = b"AOSOCLM1";
const CLAIM_VERSION: u16 = 1;
const CLAIM_BYTES: usize = 176;
const CLAIM_DIGEST_DOMAIN: &[u8] = b"aos-sandbox-ownership-claim-v1\0";
const MAXIMUM_REQUESTED_DURATION_SECONDS: u64 = 86_400;
const MAXIMUM_LEASE_BYTES: usize = 64 * 1024;
const MAXIMUM_SIGNATURE_BYTES: usize = 64 * 1024;
const DURABLE_ENTRY_MAGIC: &[u8; 8] = b"AOSOWNE1";
const DURABLE_CURRENT_MAGIC: &[u8; 8] = b"AOSOWNC1";
const DURABLE_FORMAT_VERSION: u16 = 1;
const DURABLE_ENTRY_PREFIX: &[u8] = b"ownership-entry-v1:";
const DURABLE_CURRENT_PREFIX: &[u8] = b"ownership-current-v1:";
const MAXIMUM_DURABLE_ENTRY_BYTES: usize = 132 * 1024;
const MAXIMUM_DURABLE_ENTRIES: usize = 256;
const MAXIMUM_DURABLE_CURRENT_POINTERS: usize = MAXIMUM_DURABLE_ENTRIES;
const MAXIMUM_DURABLE_RECORDS: usize = MAXIMUM_DURABLE_ENTRIES + MAXIMUM_DURABLE_CURRENT_POINTERS;
const MAXIMUM_DURABLE_KEY_BYTES: usize = 64;
// The fixed entry envelope is 322 bytes plus a bounded 255-byte stable key ID.
const MAXIMUM_DURABLE_INTENT_BYTES: usize = 577;
const MAXIMUM_DURABLE_INTENT_RECORD_BYTES: usize =
    7 + MAXIMUM_DURABLE_KEY_BYTES + MAXIMUM_DURABLE_INTENT_BYTES;
const MAXIMUM_DURABLE_RECORD_BYTES: usize =
    MAXIMUM_DURABLE_ENTRY_BYTES + MAXIMUM_DURABLE_KEY_BYTES + 7;
const MAXIMUM_DURABLE_CURRENT_BYTES: usize = 8 + 2 + 16 + 8 + 32;
const MAXIMUM_DURABLE_MATERIALIZED_BYTES: usize = MAXIMUM_DURABLE_ENTRIES
    * (MAXIMUM_DURABLE_KEY_BYTES + MAXIMUM_DURABLE_ENTRY_BYTES)
    + MAXIMUM_DURABLE_CURRENT_POINTERS
        * (MAXIMUM_DURABLE_KEY_BYTES + MAXIMUM_DURABLE_CURRENT_BYTES);
// One file header plus, for every admitted request, a worst-case one-record
// intent transaction and worst-case two-record completion transaction. The
// constants include every 72-byte frame header plus begin/commit payloads.
const MAXIMUM_DURABLE_JOURNAL_BYTES: u64 = 72
    + MAXIMUM_DURABLE_ENTRIES as u64
        * (MAXIMUM_DURABLE_INTENT_RECORD_BYTES as u64
            + MAXIMUM_DURABLE_RECORD_BYTES as u64
            + MAXIMUM_DURABLE_KEY_BYTES as u64
            + 657);
const MAXIMUM_DURABLE_TRANSACTIONS: usize = MAXIMUM_DURABLE_ENTRIES * 2;
const BEGIN_TRANSACTION_DOMAIN: &[u8] = b"aos-sandbox-ownership-intent-transaction-v1\0";
const COMPLETION_TRANSACTION_DOMAIN: &[u8] = b"aos-sandbox-ownership-completion-transaction-v1\0";

/// Selects a first acquisition or compare-and-swap renewal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnershipClaimAction {
    /// Acquires an assignment that has no prior lease in this authority domain.
    Acquire,
    /// Renews exactly the currently fenced lease.
    Renew,
}

impl OwnershipClaimAction {
    const fn code(self) -> u8 {
        match self {
            Self::Acquire => 1,
            Self::Renew => 2,
        }
    }

    fn from_code(value: u8) -> Result<Self, OwnershipClaimError> {
        match value {
            1 => Ok(Self::Acquire),
            2 => Ok(Self::Renew),
            _ => Err(OwnershipClaimError::InvalidEncoding),
        }
    }
}

/// Identifies the exact prior lease a renewal must replace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExpectedOwnershipLease {
    generation: u64,
    digest: ObjectDigest,
}

impl ExpectedOwnershipLease {
    /// Constructs a non-sentinel compare-and-swap fence.
    ///
    /// # Errors
    ///
    /// Returns [`OwnershipClaimError::InvalidExpectedLease`] for generation
    /// zero or the all-zero digest.
    pub fn new(generation: u64, digest: ObjectDigest) -> Result<Self, OwnershipClaimError> {
        if generation == 0 || digest.as_bytes() == &[0; 32] {
            Err(OwnershipClaimError::InvalidExpectedLease)
        } else {
            Ok(Self { generation, digest })
        }
    }

    /// Returns the expected current lease generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Returns the expected current signed-lease digest.
    #[must_use]
    pub const fn digest(self) -> ObjectDigest {
        self.digest
    }
}

/// Carries one canonical linearizable ownership acquire or renew claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnershipClaimV1 {
    action: OwnershipClaimAction,
    request_id: [u8; 16],
    assignment: LeaseAssignment,
    desired_generation: DesiredGeneration,
    node: NodeId,
    expected_prior: Option<ExpectedOwnershipLease>,
    requested_maximum_seconds: u64,
    canonical_bytes: [u8; CLAIM_BYTES],
    digest: ObjectDigest,
}

impl OwnershipClaimV1 {
    /// Constructs a first-acquisition claim without issuer-controlled facts.
    ///
    /// # Errors
    ///
    /// Returns [`OwnershipClaimError`] for a zero request or node identity, or
    /// a zero/oversized maximum duration.
    pub fn acquire(
        request_id: [u8; 16],
        assignment: LeaseAssignment,
        desired_generation: DesiredGeneration,
        node: NodeId,
        requested_maximum_seconds: u64,
    ) -> Result<Self, OwnershipClaimError> {
        Self::new(
            OwnershipClaimAction::Acquire,
            request_id,
            assignment,
            desired_generation,
            node,
            None,
            requested_maximum_seconds,
        )
    }

    /// Constructs a renewal claim fenced to one exact prior signed lease.
    ///
    /// # Errors
    ///
    /// Returns [`OwnershipClaimError`] for a zero request or node identity, a
    /// zero/oversized maximum duration, or a sentinel expected-prior fence.
    pub fn renew(
        request_id: [u8; 16],
        assignment: LeaseAssignment,
        desired_generation: DesiredGeneration,
        node: NodeId,
        expected_prior: ExpectedOwnershipLease,
        requested_maximum_seconds: u64,
    ) -> Result<Self, OwnershipClaimError> {
        Self::new(
            OwnershipClaimAction::Renew,
            request_id,
            assignment,
            desired_generation,
            node,
            Some(expected_prior),
            requested_maximum_seconds,
        )
    }

    /// Decodes the exact fixed-width service representation.
    ///
    /// # Errors
    ///
    /// Returns [`OwnershipClaimError`] for wrong framing, reserved bytes,
    /// unknown actions, sentinels, or inconsistent action/prior fields.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, OwnershipClaimError> {
        if bytes.len() != CLAIM_BYTES {
            return Err(OwnershipClaimError::InvalidEncoding);
        }
        let mut cursor = 0;
        if take::<8>(bytes, &mut cursor)? != *CLAIM_MAGIC
            || u16::from_be_bytes(take::<2>(bytes, &mut cursor)?) != CLAIM_VERSION
        {
            return Err(OwnershipClaimError::InvalidEncoding);
        }
        let action = OwnershipClaimAction::from_code(take::<1>(bytes, &mut cursor)?[0])?;
        if take::<5>(bytes, &mut cursor)? != [0; 5] {
            return Err(OwnershipClaimError::InvalidEncoding);
        }
        let request_id = take::<16>(bytes, &mut cursor)?;
        let assignment = LeaseAssignment::new(
            SandboxId::from_bytes(take::<16>(bytes, &mut cursor)?),
            IncarnationId::from_bytes(take::<16>(bytes, &mut cursor)?),
            aos_sandbox_core::AssignmentEpoch::new(u64::from_be_bytes(take::<8>(
                bytes,
                &mut cursor,
            )?)),
            ObjectDigest::from_bytes(take::<32>(bytes, &mut cursor)?),
        )
        .map_err(|_| OwnershipClaimError::InvalidEncoding)?;
        let node = NodeId::from_bytes(take::<16>(bytes, &mut cursor)?);
        let desired_generation =
            DesiredGeneration::new(u64::from_be_bytes(take::<8>(bytes, &mut cursor)?));
        let expected_generation = u64::from_be_bytes(take::<8>(bytes, &mut cursor)?);
        let expected_digest = ObjectDigest::from_bytes(take::<32>(bytes, &mut cursor)?);
        let requested_maximum_seconds = u64::from_be_bytes(take::<8>(bytes, &mut cursor)?);
        if cursor != bytes.len() {
            return Err(OwnershipClaimError::InvalidEncoding);
        }
        let expected_prior = match action {
            OwnershipClaimAction::Acquire
                if expected_generation == 0 && expected_digest.as_bytes() == &[0; 32] =>
            {
                None
            }
            OwnershipClaimAction::Renew => Some(ExpectedOwnershipLease::new(
                expected_generation,
                expected_digest,
            )?),
            OwnershipClaimAction::Acquire => return Err(OwnershipClaimError::InvalidExpectedLease),
        };
        Self::new(
            action,
            request_id,
            assignment,
            desired_generation,
            node,
            expected_prior,
            requested_maximum_seconds,
        )
    }

    fn new(
        action: OwnershipClaimAction,
        request_id: [u8; 16],
        assignment: LeaseAssignment,
        desired_generation: DesiredGeneration,
        node: NodeId,
        expected_prior: Option<ExpectedOwnershipLease>,
        requested_maximum_seconds: u64,
    ) -> Result<Self, OwnershipClaimError> {
        if request_id == [0; 16]
            || node.as_bytes() == &[0; 16]
            || desired_generation.get() == 0
            || requested_maximum_seconds == 0
            || requested_maximum_seconds > MAXIMUM_REQUESTED_DURATION_SECONDS
            || (action == OwnershipClaimAction::Acquire) != expected_prior.is_none()
        {
            return Err(OwnershipClaimError::InvalidClaim);
        }
        let canonical_bytes = encode_claim(
            action,
            request_id,
            assignment,
            desired_generation,
            node,
            expected_prior,
            requested_maximum_seconds,
        );
        let digest = claim_digest(&canonical_bytes);
        Ok(Self {
            action,
            request_id,
            assignment,
            desired_generation,
            node,
            expected_prior,
            requested_maximum_seconds,
            canonical_bytes,
            digest,
        })
    }

    /// Returns whether this claim acquires or renews ownership.
    #[must_use]
    pub const fn action(&self) -> OwnershipClaimAction {
        self.action
    }

    /// Returns the stable idempotency identity for the authority transaction.
    #[must_use]
    pub const fn request_id(&self) -> &[u8; 16] {
        &self.request_id
    }

    /// Returns immutable assignment semantics.
    #[must_use]
    pub const fn assignment(&self) -> LeaseAssignment {
        self.assignment
    }

    /// Returns the desired generation used when constructing broker fences.
    #[must_use]
    pub const fn desired_generation(&self) -> DesiredGeneration {
        self.desired_generation
    }

    /// Returns the sole node requesting exclusive ownership.
    #[must_use]
    pub const fn node(&self) -> NodeId {
        self.node
    }

    /// Returns the exact prior lease required by a renewal.
    #[must_use]
    pub const fn expected_prior(&self) -> Option<ExpectedOwnershipLease> {
        self.expected_prior
    }

    /// Returns the maximum lease interval the controller will accept.
    #[must_use]
    pub const fn requested_maximum_seconds(&self) -> u64 {
        self.requested_maximum_seconds
    }

    /// Returns the exact fixed-width future service request bytes.
    #[must_use]
    pub const fn canonical_bytes(&self) -> &[u8; CLAIM_BYTES] {
        &self.canonical_bytes
    }

    /// Returns the domain-separated idempotency digest of the complete claim.
    #[must_use]
    pub const fn digest(&self) -> ObjectDigest {
        self.digest
    }

    fn broker_assignment(&self) -> Result<BrokerAssignment, OwnershipLeaseAcquisitionError> {
        BrokerAssignment::new(
            self.assignment.sandbox(),
            self.assignment.incarnation(),
            self.assignment.epoch(),
            self.desired_generation,
            self.assignment.digest(),
        )
        .map_err(|_| OwnershipLeaseAcquisitionError::InvalidIssuerResponse)
    }
}

/// Reports malformed ownership claims before they cross an authority boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum OwnershipClaimError {
    /// A required field is a sentinel, duration is out of bounds, or action shape is invalid.
    #[error("ownership claim fields are invalid")]
    InvalidClaim,
    /// The fixed-width representation has wrong magic, version, size, or reserved bytes.
    #[error("ownership claim encoding is invalid")]
    InvalidEncoding,
    /// A renewal prior is absent or sentinel, or acquire unexpectedly supplies one.
    #[error("ownership claim expected-prior lease is invalid")]
    InvalidExpectedLease,
}

/// Carries exact issuer response bytes without claiming authenticity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnverifiedOwnershipLeaseResponse {
    lease: Vec<u8>,
    signature: Vec<u8>,
}

impl UnverifiedOwnershipLeaseResponse {
    /// Adopts bounded response bytes from an authority transport.
    ///
    /// This performs no signature or semantic verification.
    ///
    /// # Errors
    ///
    /// Returns [`OwnershipLeaseAcquisitionError::InvalidIssuerResponse`] for
    /// empty or oversized fields.
    pub fn from_transport(
        lease: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<Self, OwnershipLeaseAcquisitionError> {
        if lease.is_empty()
            || lease.len() > MAXIMUM_LEASE_BYTES
            || signature.is_empty()
            || signature.len() > MAXIMUM_SIGNATURE_BYTES
        {
            return Err(OwnershipLeaseAcquisitionError::InvalidIssuerResponse);
        }
        Ok(Self { lease, signature })
    }
}

/// Acquires ownership through a linearizable authority transaction.
///
/// Implementations must bind `request_id` to the complete claim digest. Exact
/// replay returns the original response; reuse with different bytes fails.
/// Acquire is expected-absence CAS, while renew is exact generation/digest CAS.
pub trait OwnershipAuthority {
    /// Acquires an assignment whose authoritative lease is absent.
    ///
    /// # Errors
    ///
    /// Returns [`OwnershipAuthorityError`] for conflict, idempotency misuse,
    /// unavailable linearizable state, or transport failure.
    fn acquire(
        &mut self,
        claim: &OwnershipClaimV1,
    ) -> Result<UnverifiedOwnershipLeaseResponse, OwnershipAuthorityError>;

    /// Renews exactly the lease named by the claim's prior fence.
    ///
    /// # Errors
    ///
    /// Returns [`OwnershipAuthorityError`] for stale CAS state, idempotency
    /// misuse, unavailable linearizable state, or transport failure.
    fn renew(
        &mut self,
        claim: &OwnershipClaimV1,
    ) -> Result<UnverifiedOwnershipLeaseResponse, OwnershipAuthorityError>;
}

/// Classifies authority transaction failures without backend-specific detail.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum OwnershipAuthorityError {
    /// Expected absence failed because another current lease owns the assignment.
    #[error("ownership assignment already has a current lease")]
    AlreadyOwned,
    /// Renewal did not name the authority's exact current generation and digest.
    #[error("ownership renewal compare-and-swap fence is stale")]
    StaleExpectedPrior,
    /// One request identity was reused with different canonical claim bytes.
    #[error("ownership request identity is bound to another claim")]
    IdempotencyConflict,
    /// Linearizable authority state could not be reached.
    #[error("ownership authority is unavailable")]
    Unavailable,
    /// The selected transport or authority implementation failed safely.
    #[error("ownership authority transaction failed")]
    Internal,
}

/// Verifies issuer responses against one protected authority generation.
pub struct OwnershipAuthorityVerifier {
    anchor: OwnershipLeaseTrustAnchor,
    authority: KeyReference,
}

impl OwnershipAuthorityVerifier {
    /// Pins the trust anchor and exact ownership-authority key generation.
    #[must_use]
    pub const fn new(anchor: OwnershipLeaseTrustAnchor, authority: KeyReference) -> Self {
        Self { anchor, authority }
    }

    /// Performs expected-absence acquisition and verifies the returned lease.
    ///
    /// # Errors
    ///
    /// Returns [`OwnershipLeaseAcquisitionError`] for a wrong claim action,
    /// authority transaction failure, malformed or forged response, context
    /// substitution, expiry, excessive interval, or invalid generation.
    pub fn acquire<A: OwnershipAuthority>(
        &self,
        authority: &mut A,
        claim: &OwnershipClaimV1,
        clock: &RawPairedClockSample,
    ) -> Result<SignedOwnershipLease, OwnershipLeaseAcquisitionError> {
        if claim.action != OwnershipClaimAction::Acquire {
            return Err(OwnershipLeaseAcquisitionError::WrongClaimAction);
        }
        let response = authority.acquire(claim)?;
        self.verify_response(claim, response, clock)
    }

    /// Performs exact compare-and-swap renewal and verifies the returned lease.
    ///
    /// # Errors
    ///
    /// Returns [`OwnershipLeaseAcquisitionError`] for a wrong claim action,
    /// authority transaction failure, malformed or forged response, context
    /// substitution, expiry, excessive interval, or non-advancing generation.
    pub fn renew<A: OwnershipAuthority>(
        &self,
        authority: &mut A,
        claim: &OwnershipClaimV1,
        clock: &RawPairedClockSample,
    ) -> Result<SignedOwnershipLease, OwnershipLeaseAcquisitionError> {
        if claim.action != OwnershipClaimAction::Renew {
            return Err(OwnershipLeaseAcquisitionError::WrongClaimAction);
        }
        let response = authority.renew(claim)?;
        self.verify_response(claim, response, clock)
    }

    fn verify_response(
        &self,
        claim: &OwnershipClaimV1,
        response: UnverifiedOwnershipLeaseResponse,
        clock: &RawPairedClockSample,
    ) -> Result<SignedOwnershipLease, OwnershipLeaseAcquisitionError> {
        let signature = decode_signature(&response.signature, response_limits())
            .map_err(|_| OwnershipLeaseAcquisitionError::InvalidIssuerResponse)?;
        if encode_signature(&signature) != response.signature {
            return Err(OwnershipLeaseAcquisitionError::InvalidIssuerResponse);
        }
        let verified = verify_ownership_lease(
            &response.lease,
            &signature,
            &self.anchor,
            aos_sandbox_core::OwnershipLeaseExpectation {
                assignment: claim.broker_assignment()?,
                node: claim.node,
                ownership_authority: &self.authority,
                clock,
            },
            response_limits(),
        )
        .map_err(|_| OwnershipLeaseAcquisitionError::InvalidIssuerResponse)?;
        validate_verified_response(claim, &verified)?;

        Ok(SignedOwnershipLease {
            canonical_lease: response.lease,
            canonical_signature: response.signature,
            generation: verified.lease().lease_generation(),
            digest: verified.lease_digest(),
            assignment: verified.lease().assignment(),
            node: verified.lease().node(),
            authority_issued_seconds: verified.lease().authority_issued_seconds(),
            authority_expires_seconds: verified.lease().authority_expires_seconds(),
            maximum_clock_skew_seconds: verified.lease().maximum_clock_skew_seconds(),
            renewal_nonce: *verified.lease().renewal_nonce(),
            signer: signature.statement().signer().clone(),
        })
    }
}

/// Owns one fully verified signed ownership lease suitable for durable publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedOwnershipLease {
    canonical_lease: Vec<u8>,
    canonical_signature: Vec<u8>,
    generation: u64,
    digest: ObjectDigest,
    assignment: LeaseAssignment,
    node: NodeId,
    authority_issued_seconds: i64,
    authority_expires_seconds: i64,
    maximum_clock_skew_seconds: u64,
    renewal_nonce: [u8; 16],
    signer: KeyReference,
}

impl SignedOwnershipLease {
    #[cfg(test)]
    pub(crate) fn from_test_artifacts(
        lease: aos_sandbox_core::OwnershipLease,
        canonical_signature: Vec<u8>,
    ) -> Self {
        let canonical_lease = aos_sandbox_core::format::encode_ownership_lease(&lease);
        let media_type = aos_sandbox_core::MediaType::new(
            aos_sandbox_core::PortableMediaType::OwnershipLease
                .as_str()
                .to_owned(),
        )
        .unwrap_or_else(|error| panic!("test lease media type failed: {error}"));
        let digest = aos_sandbox_core::descriptor_for_bytes(media_type, &canonical_lease).digest();
        let signature = aos_sandbox_core::format::decode_signature(
            &canonical_signature,
            aos_sandbox_core::DecodeLimits::default(),
        )
        .unwrap_or_else(|error| panic!("test lease signature failed: {error}"));
        Self {
            canonical_lease,
            canonical_signature,
            generation: lease.lease_generation(),
            digest,
            assignment: lease.assignment(),
            node: lease.node(),
            authority_issued_seconds: lease.authority_issued_seconds(),
            authority_expires_seconds: lease.authority_expires_seconds(),
            maximum_clock_skew_seconds: lease.maximum_clock_skew_seconds(),
            renewal_nonce: *lease.renewal_nonce(),
            signer: signature.statement().signer().clone(),
        }
    }

    /// Returns exact canonical ownership-lease bytes.
    #[must_use]
    pub fn canonical_lease(&self) -> &[u8] {
        &self.canonical_lease
    }

    /// Returns exact canonical detached-signature bytes.
    #[must_use]
    pub fn canonical_signature(&self) -> &[u8] {
        &self.canonical_signature
    }

    /// Returns the issuer-chosen monotonic lease generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the exact signed-lease descriptor digest.
    #[must_use]
    pub const fn digest(&self) -> ObjectDigest {
        self.digest
    }

    /// Returns the immutable assignment semantics.
    #[must_use]
    pub const fn assignment(&self) -> LeaseAssignment {
        self.assignment
    }

    /// Returns the sole owning node.
    #[must_use]
    pub const fn node(&self) -> NodeId {
        self.node
    }

    /// Returns the issuer-chosen inclusive authority start.
    #[must_use]
    pub const fn authority_issued_seconds(&self) -> i64 {
        self.authority_issued_seconds
    }

    /// Returns the issuer-chosen exclusive authority expiry.
    #[must_use]
    pub const fn authority_expires_seconds(&self) -> i64 {
        self.authority_expires_seconds
    }

    /// Returns the issuer-chosen maximum admitted clock skew.
    #[must_use]
    pub const fn maximum_clock_skew_seconds(&self) -> u64 {
        self.maximum_clock_skew_seconds
    }

    /// Returns the issuer-chosen renewal nonce.
    #[must_use]
    pub const fn renewal_nonce(&self) -> &[u8; 16] {
        &self.renewal_nonce
    }

    /// Returns the exact ownership-authority key generation that signed the lease.
    #[must_use]
    pub const fn signer(&self) -> &KeyReference {
        &self.signer
    }

    /// Returns the exact fence required by the next renewal.
    #[must_use]
    pub const fn expected_renewal_fence(&self) -> ExpectedOwnershipLease {
        ExpectedOwnershipLease {
            generation: self.generation,
            digest: self.digest,
        }
    }
}

/// Reports a rejected authority response before it can become current.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum OwnershipLeaseAcquisitionError {
    /// The selected trait method does not match the canonical claim action.
    #[error("ownership claim action does not match the authority method")]
    WrongClaimAction,
    /// The authority transaction failed before returning verifiable bytes.
    #[error("ownership authority rejected the transaction: {0}")]
    Authority(#[from] OwnershipAuthorityError),
    /// Response bytes, signature, context, liveness, duration, or generation are invalid.
    #[error("ownership authority returned an invalid lease")]
    InvalidIssuerResponse,
}

fn validate_verified_response(
    claim: &OwnershipClaimV1,
    verified: &VerifiedOwnershipLease,
) -> Result<(), OwnershipLeaseAcquisitionError> {
    let lease = verified.lease();
    let duration = lease
        .authority_expires_seconds()
        .checked_sub(lease.authority_issued_seconds())
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(OwnershipLeaseAcquisitionError::InvalidIssuerResponse)?;
    if duration > claim.requested_maximum_seconds {
        return Err(OwnershipLeaseAcquisitionError::InvalidIssuerResponse);
    }
    match claim.expected_prior {
        None => {}
        Some(expected) if lease.lease_generation() > expected.generation => {}
        Some(_) => return Err(OwnershipLeaseAcquisitionError::InvalidIssuerResponse),
    }
    Ok(())
}

fn response_limits() -> DecodeLimits {
    DecodeLimits {
        maximum_bytes: MAXIMUM_SIGNATURE_BYTES.max(MAXIMUM_LEASE_BYTES),
        maximum_collection_items: 64,
        maximum_total_items: 512,
        maximum_byte_string_bytes: 1024,
        maximum_text_bytes: 255,
        maximum_depth: 16,
    }
}

/// Reports durable ownership-authority state or recovery failure.
#[derive(Debug, thiserror::Error)]
pub enum DurableOwnershipAuthorityError {
    /// Protected journal opening, replay, or commit failed.
    #[error("durable ownership journal failed: {0}")]
    Journal(#[from] JournalError),
    /// Durable records do not form one authenticated linear ownership chain.
    #[error("durable ownership authority state is malformed or inconsistent")]
    CorruptState,
    /// The request identity is already bound to another claim.
    #[error("durable ownership request identity is bound to another claim")]
    IdempotencyConflict,
    /// Acquire or renewal does not match the durable current state.
    #[error("durable ownership compare-and-swap precondition failed")]
    CompareAndSwapConflict,
    /// No unsigned durable intent exists for the requested operation.
    #[error("durable ownership intent was not found")]
    IntentNotFound,
    /// Issuance or cryptographic live verification failed.
    #[error("ownership lease issuance failed: {0}")]
    Acquisition(#[from] OwnershipLeaseAcquisitionError),
    /// The protected paired-clock source could not provide a sample.
    #[error("protected ownership clock is unavailable")]
    ProtectedClockUnavailable(#[from] ProtectedOwnershipClockError),
    /// The fixed authority-generation epoch has no capacity for another request.
    #[error("durable ownership authority epoch capacity is exhausted")]
    ResourceExhausted,
}

/// Reports failure to sample the protected paired clock without backend detail.
///
/// Production adapters should map device, service, and transport failures to
/// this opaque value rather than exposing their implementation through the
/// authority state-machine API.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("protected paired clock is unavailable")]
pub struct ProtectedOwnershipClockError;

/// Describes durable admission of one ownership claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DurableOwnershipBeginOutcome {
    /// An unsigned intent is durable and may be completed explicitly.
    Pending,
    /// The exact completed request was replayed without contacting the issuer.
    Replay(Box<SignedOwnershipLease>),
}

#[derive(Clone, Debug)]
enum DurableEntryState {
    Intent,
    Completed {
        accepted_wall_seconds: i64,
        lease: Box<SignedOwnershipLease>,
    },
}

#[derive(Clone, Debug)]
struct DurableOwnershipEntry {
    claim: OwnershipClaimV1,
    state: DurableEntryState,
}

/// Owns one protected, crash-recoverable ownership authority journal.
///
/// The store is an authority state machine, not a broker. Historical proofs
/// rebuild its lease chain but never become current execution permission.
/// Issuance is explicitly split: [`Self::begin`] commits an unsigned intent;
/// [`Self::complete`] contacts an [`OwnershipAuthority`] whose trait contract
/// guarantees exact response replay for the canonical request ID and digest.
/// Recovery never contacts that issuer, so a dangling intent remains durable
/// and non-authorizing until an operator or controller explicitly resumes it.
/// The protected journal is dedicated to this owner; recovery rejects records
/// from other subsystems rather than sharing a writable journal namespace.
///
/// The current trait has no release, expiry retirement, or transfer operation.
/// Consequently a completed assignment remains owned for CAS purposes even
/// after expiry, and cross-assignment transfer is intentionally incomplete.
/// One journal is also pinned to exactly one authority key generation. Key
/// rotation requires an explicit authenticated migration into a new journal;
/// opening old mixed-generation history with a new verifier fails closed.
pub struct DurableOwnershipAuthority {
    journal: Journal,
    verifier: OwnershipAuthorityVerifier,
    entries: BTreeMap<[u8; 16], DurableOwnershipEntry>,
    current: BTreeMap<SandboxId, SignedOwnershipLease>,
}

impl DurableOwnershipAuthority {
    /// Opens root-only protected authority state and authenticates its full history.
    ///
    /// This authority owns fixed, non-configurable replay and materialization
    /// ceilings. In particular, callers cannot expand hostile-input bounds by
    /// supplying permissive generic journal limits.
    ///
    /// # Errors
    ///
    /// Returns [`DurableOwnershipAuthorityError`] if protected storage cannot
    /// be opened or if any durable record is malformed, unauthenticated,
    /// forked, stale, equivocal, disconnected, or inconsistent with its unique
    /// current pointer.
    pub fn open_protected(
        directory: impl AsRef<Path>,
        name: &str,
        verifier: OwnershipAuthorityVerifier,
    ) -> Result<(Self, RecoveryReport), DurableOwnershipAuthorityError> {
        let (journal, report) =
            Journal::open_protected_at(directory, name, ownership_journal_limits())?;
        let store = Self::from_journal(journal, verifier)?;
        Ok((store, report))
    }

    fn from_journal(
        journal: Journal,
        verifier: OwnershipAuthorityVerifier,
    ) -> Result<Self, DurableOwnershipAuthorityError> {
        let (entries, current) = recover_durable_ownership(&journal, &verifier)?;
        Ok(Self {
            journal,
            verifier,
            entries,
            current,
        })
    }

    /// Durably records one unsigned acquire or renew intent.
    ///
    /// This method never contacts an issuer. Exact completed replay returns
    /// the original verified response; exact pending replay remains pending.
    ///
    /// # Errors
    ///
    /// Returns [`DurableOwnershipAuthorityError::IdempotencyConflict`] when a
    /// request ID is rebound, or
    /// [`DurableOwnershipAuthorityError::CompareAndSwapConflict`] when acquire
    /// is not expected-absence or renew does not name the exact current fence.
    /// Returns [`DurableOwnershipAuthorityError::ResourceExhausted`] before
    /// writing an intent when the fixed epoch request capacity is exhausted.
    pub fn begin(
        &mut self,
        claim: &OwnershipClaimV1,
    ) -> Result<DurableOwnershipBeginOutcome, DurableOwnershipAuthorityError> {
        if let Some(existing) = self.entries.get(claim.request_id()) {
            if existing.claim != *claim {
                return Err(DurableOwnershipAuthorityError::IdempotencyConflict);
            }
            return Ok(match &existing.state {
                DurableEntryState::Intent => DurableOwnershipBeginOutcome::Pending,
                DurableEntryState::Completed { lease, .. } => {
                    DurableOwnershipBeginOutcome::Replay(lease.clone())
                }
            });
        }
        // The fixed journal limits reserve a worst-case completion transaction
        // for every admitted intent. Refusing the (N + 1)th request before its
        // intent is durable prevents successful external issuance from ever
        // becoming permanently uncommittable due to local capacity.
        if self.entries.len() >= MAXIMUM_DURABLE_ENTRIES {
            return Err(DurableOwnershipAuthorityError::ResourceExhausted);
        }
        let sandbox = claim.assignment().sandbox();
        if self.entries.values().any(|entry| {
            entry.claim.assignment().sandbox() == sandbox
                && matches!(entry.state, DurableEntryState::Intent)
        }) {
            return Err(DurableOwnershipAuthorityError::CompareAndSwapConflict);
        }
        match claim.action() {
            OwnershipClaimAction::Acquire if self.current.contains_key(&sandbox) => {
                return Err(DurableOwnershipAuthorityError::CompareAndSwapConflict);
            }
            OwnershipClaimAction::Acquire => {}
            OwnershipClaimAction::Renew => {
                let current = self
                    .current
                    .get(&sandbox)
                    .ok_or(DurableOwnershipAuthorityError::CompareAndSwapConflict)?;
                if current.assignment() != claim.assignment()
                    || current.node() != claim.node()
                    || Some(current.expected_renewal_fence()) != claim.expected_prior()
                {
                    return Err(DurableOwnershipAuthorityError::CompareAndSwapConflict);
                }
            }
        }
        let entry = DurableOwnershipEntry {
            claim: claim.clone(),
            state: DurableEntryState::Intent,
        };
        let record = JournalRecord::put(
            RecordNamespace::Operation,
            durable_entry_key(claim.request_id()),
            encode_durable_entry(&entry, &self.verifier.authority),
        );
        let transaction =
            JournalTransaction::new(begin_transaction_id(*claim.request_id()), vec![record])?;
        self.journal.commit(&transaction)?;
        self.entries.insert(*claim.request_id(), entry);
        Ok(DurableOwnershipBeginOutcome::Pending)
    }

    /// Completes or explicitly resumes one durable unsigned intent.
    ///
    /// The issuer is called only after the exact intent is durable. Calling
    /// this method after a crash is safe only because [`OwnershipAuthority`]
    /// requires exact idempotent response replay for request ID plus claim
    /// digest. The response is live-verified before one transaction atomically
    /// commits both completed entry and current pointer.
    /// `protected_clock` must read a protected paired clock when called. It is
    /// deliberately invoked after the issuer returns, preventing stale
    /// pre-request time from admitting a response that expired in transit.
    ///
    /// # Errors
    ///
    /// Returns [`DurableOwnershipAuthorityError`] for a missing intent,
    /// authority failure, unavailable protected clock, malicious response,
    /// stale post-issuance CAS state, or journal commit failure.
    pub fn complete<A, C>(
        &mut self,
        request_id: [u8; 16],
        issuer: &mut A,
        protected_clock: &mut C,
    ) -> Result<SignedOwnershipLease, DurableOwnershipAuthorityError>
    where
        A: OwnershipAuthority,
        C: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        let entry = self
            .entries
            .get(&request_id)
            .cloned()
            .ok_or(DurableOwnershipAuthorityError::IntentNotFound)?;
        if let DurableEntryState::Completed { lease, .. } = entry.state {
            return Ok(*lease);
        }
        let claim = entry.claim;
        validate_claim_against_current(&claim, &self.current)?;
        let response = match claim.action() {
            OwnershipClaimAction::Acquire => issuer.acquire(&claim),
            OwnershipClaimAction::Renew => issuer.renew(&claim),
        };
        let response = response.map_err(OwnershipLeaseAcquisitionError::Authority)?;
        // The protected clock is sampled only after the possibly blocking
        // issuer call, so an already-expired response cannot be recorded using
        // stale pre-call time. This sample is advisory input to live signature
        // verification, not a transferable clock capability.
        let clock = protected_clock()?;
        let lease = self.verifier.verify_response(&claim, response, &clock)?;
        validate_claim_against_current(&claim, &self.current)?;
        let completed = DurableOwnershipEntry {
            claim: claim.clone(),
            state: DurableEntryState::Completed {
                accepted_wall_seconds: clock.wall_seconds(),
                lease: Box::new(lease.clone()),
            },
        };
        let current_record = encode_current_pointer(request_id, &lease);
        let records = vec![
            JournalRecord::put(
                RecordNamespace::Operation,
                durable_entry_key(&request_id),
                encode_durable_entry(&completed, &self.verifier.authority),
            ),
            JournalRecord::put(
                RecordNamespace::DesiredState,
                durable_current_key(lease.assignment().sandbox()),
                current_record,
            ),
        ];
        let transaction = JournalTransaction::new(completion_transaction_id(request_id), records)?;
        self.journal.commit(&transaction)?;
        self.entries.insert(request_id, completed);
        self.current
            .insert(lease.assignment().sandbox(), lease.clone());
        Ok(lease)
    }

    /// Returns the unique state-machine head for one sandbox, if completed.
    ///
    /// The returned signed bytes carry no present-liveness or broker-effect
    /// proof. In particular, a head reconstructed historically may be expired
    /// and must pass the normal live broker verification path before use.
    #[must_use]
    pub fn current(&self, sandbox: SandboxId) -> Option<&SignedOwnershipLease> {
        self.current.get(&sandbox)
    }

    /// Returns whether one request is a durable unsigned intent.
    #[must_use]
    pub fn is_pending(&self, request_id: &[u8; 16]) -> bool {
        self.entries
            .get(request_id)
            .is_some_and(|entry| matches!(entry.state, DurableEntryState::Intent))
    }
}

fn ownership_journal_limits() -> JournalLimits {
    JournalLimits {
        maximum_journal_bytes: MAXIMUM_DURABLE_JOURNAL_BYTES,
        maximum_record_bytes: MAXIMUM_DURABLE_RECORD_BYTES,
        maximum_key_bytes: MAXIMUM_DURABLE_KEY_BYTES,
        maximum_records_per_transaction: 2,
        maximum_transaction_bytes: MAXIMUM_DURABLE_RECORD_BYTES * 2,
        maximum_transactions: MAXIMUM_DURABLE_TRANSACTIONS,
        maximum_materialized_bytes: MAXIMUM_DURABLE_MATERIALIZED_BYTES,
        maximum_materialized_records: MAXIMUM_DURABLE_RECORDS,
    }
}

fn validate_claim_against_current(
    claim: &OwnershipClaimV1,
    current: &BTreeMap<SandboxId, SignedOwnershipLease>,
) -> Result<(), DurableOwnershipAuthorityError> {
    let existing = current.get(&claim.assignment().sandbox());
    match (claim.action(), existing) {
        (OwnershipClaimAction::Acquire, None) => Ok(()),
        (OwnershipClaimAction::Renew, Some(lease))
            if lease.assignment() == claim.assignment()
                && lease.node() == claim.node()
                && Some(lease.expected_renewal_fence()) == claim.expected_prior() =>
        {
            Ok(())
        }
        _ => Err(DurableOwnershipAuthorityError::CompareAndSwapConflict),
    }
}

fn durable_entry_key(request_id: &[u8; 16]) -> Vec<u8> {
    let mut key = Vec::with_capacity(DURABLE_ENTRY_PREFIX.len() + request_id.len());
    key.extend_from_slice(DURABLE_ENTRY_PREFIX);
    key.extend_from_slice(request_id);
    key
}

fn durable_current_key(sandbox: SandboxId) -> Vec<u8> {
    let mut key = Vec::with_capacity(DURABLE_CURRENT_PREFIX.len() + 16);
    key.extend_from_slice(DURABLE_CURRENT_PREFIX);
    key.extend_from_slice(sandbox.as_bytes());
    key
}

fn completion_transaction_id(request_id: [u8; 16]) -> [u8; 16] {
    ownership_transaction_id(COMPLETION_TRANSACTION_DOMAIN, request_id)
}

fn begin_transaction_id(request_id: [u8; 16]) -> [u8; 16] {
    ownership_transaction_id(BEGIN_TRANSACTION_DOMAIN, request_id)
}

fn ownership_transaction_id(domain: &[u8], request_id: [u8; 16]) -> [u8; 16] {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(request_id);
    let mut id = [0; 16];
    id.copy_from_slice(&digest.finalize()[..16]);
    // Journal transaction IDs reserve all-zero. Fixing one bit avoids a
    // probabilistic invalid output without admitting caller-selected bytes.
    id[0] |= 0x80;
    id
}

fn encode_durable_entry(entry: &DurableOwnershipEntry, authority: &KeyReference) -> Vec<u8> {
    let key_id = authority.stable_key_id().as_str().as_bytes();
    let response_bytes = match &entry.state {
        DurableEntryState::Intent => 0,
        DurableEntryState::Completed { lease, .. } => {
            lease.canonical_lease().len() + lease.canonical_signature().len()
        }
    };
    let mut bytes = Vec::with_capacity(328 + key_id.len() + response_bytes);
    bytes.extend_from_slice(DURABLE_ENTRY_MAGIC);
    bytes.extend_from_slice(&DURABLE_FORMAT_VERSION.to_be_bytes());
    bytes.push(match entry.state {
        DurableEntryState::Intent => 1,
        DurableEntryState::Completed { .. } => 2,
    });
    bytes.extend_from_slice(&[0; 5]);
    bytes.extend_from_slice(&(key_id.len() as u16).to_be_bytes());
    bytes.extend_from_slice(key_id);
    bytes.extend_from_slice(&authority.generation().to_be_bytes());
    bytes.extend_from_slice(authority.public_key_sha256().as_bytes());
    bytes.extend_from_slice(entry.claim.canonical_bytes());
    bytes.extend_from_slice(entry.claim.digest().as_bytes());
    match &entry.state {
        DurableEntryState::Intent => {
            bytes.extend_from_slice(&[0; 8 + 8 + 32 + 4 + 4]);
        }
        DurableEntryState::Completed {
            accepted_wall_seconds,
            lease,
        } => {
            bytes.extend_from_slice(&accepted_wall_seconds.to_be_bytes());
            bytes.extend_from_slice(&lease.generation().to_be_bytes());
            bytes.extend_from_slice(lease.digest().as_bytes());
            bytes.extend_from_slice(&(lease.canonical_lease().len() as u32).to_be_bytes());
            bytes.extend_from_slice(&(lease.canonical_signature().len() as u32).to_be_bytes());
            bytes.extend_from_slice(lease.canonical_lease());
            bytes.extend_from_slice(lease.canonical_signature());
        }
    }
    debug_assert!(bytes.len() <= MAXIMUM_DURABLE_ENTRY_BYTES);
    bytes
}

fn decode_durable_entry(
    key: &[u8],
    bytes: &[u8],
    verifier: &OwnershipAuthorityVerifier,
) -> Result<DurableOwnershipEntry, DurableOwnershipAuthorityError> {
    if key.len() != DURABLE_ENTRY_PREFIX.len() + 16
        || !key.starts_with(DURABLE_ENTRY_PREFIX)
        || bytes.len() > MAXIMUM_DURABLE_ENTRY_BYTES
    {
        return Err(DurableOwnershipAuthorityError::CorruptState);
    }
    let request_id: [u8; 16] = key[DURABLE_ENTRY_PREFIX.len()..]
        .try_into()
        .map_err(|_| DurableOwnershipAuthorityError::CorruptState)?;
    let mut cursor = 0;
    if durable_take::<8>(bytes, &mut cursor)? != *DURABLE_ENTRY_MAGIC
        || u16::from_be_bytes(durable_take::<2>(bytes, &mut cursor)?) != DURABLE_FORMAT_VERSION
    {
        return Err(DurableOwnershipAuthorityError::CorruptState);
    }
    let status = durable_take::<1>(bytes, &mut cursor)?[0];
    if durable_take::<5>(bytes, &mut cursor)? != [0; 5] {
        return Err(DurableOwnershipAuthorityError::CorruptState);
    }
    let key_id_length = usize::from(u16::from_be_bytes(durable_take::<2>(bytes, &mut cursor)?));
    if key_id_length == 0 || key_id_length > 255 {
        return Err(DurableOwnershipAuthorityError::CorruptState);
    }
    let key_id = durable_slice(bytes, &mut cursor, key_id_length)?;
    let authority_generation = u64::from_be_bytes(durable_take::<8>(bytes, &mut cursor)?);
    let authority_fingerprint = ObjectDigest::from_bytes(durable_take::<32>(bytes, &mut cursor)?);
    if key_id != verifier.authority.stable_key_id().as_str().as_bytes()
        || authority_generation != verifier.authority.generation()
        || authority_fingerprint != verifier.authority.public_key_sha256()
    {
        return Err(DurableOwnershipAuthorityError::CorruptState);
    }
    let claim_bytes = durable_take::<CLAIM_BYTES>(bytes, &mut cursor)?;
    let claim = OwnershipClaimV1::from_canonical_bytes(&claim_bytes)
        .map_err(|_| DurableOwnershipAuthorityError::CorruptState)?;
    let persisted_claim_digest = ObjectDigest::from_bytes(durable_take::<32>(bytes, &mut cursor)?);
    if claim.request_id() != &request_id || persisted_claim_digest != claim.digest() {
        return Err(DurableOwnershipAuthorityError::CorruptState);
    }
    let accepted_wall_seconds = i64::from_be_bytes(durable_take::<8>(bytes, &mut cursor)?);
    let response_generation = u64::from_be_bytes(durable_take::<8>(bytes, &mut cursor)?);
    let response_digest = ObjectDigest::from_bytes(durable_take::<32>(bytes, &mut cursor)?);
    let lease_length = usize::try_from(u32::from_be_bytes(durable_take::<4>(bytes, &mut cursor)?))
        .map_err(|_| DurableOwnershipAuthorityError::CorruptState)?;
    let signature_length =
        usize::try_from(u32::from_be_bytes(durable_take::<4>(bytes, &mut cursor)?))
            .map_err(|_| DurableOwnershipAuthorityError::CorruptState)?;
    if status == 1 {
        if accepted_wall_seconds != 0
            || response_generation != 0
            || response_digest.as_bytes() != &[0; 32]
            || lease_length != 0
            || signature_length != 0
            || cursor != bytes.len()
        {
            return Err(DurableOwnershipAuthorityError::CorruptState);
        }
        return Ok(DurableOwnershipEntry {
            claim,
            state: DurableEntryState::Intent,
        });
    }
    if status != 2
        || response_generation == 0
        || response_digest.as_bytes() == &[0; 32]
        || lease_length == 0
        || lease_length > MAXIMUM_LEASE_BYTES
        || signature_length == 0
        || signature_length > MAXIMUM_SIGNATURE_BYTES
        || lease_length
            .checked_add(signature_length)
            .and_then(|length| cursor.checked_add(length))
            != Some(bytes.len())
    {
        return Err(DurableOwnershipAuthorityError::CorruptState);
    }
    let lease_bytes = durable_slice(bytes, &mut cursor, lease_length)?;
    let signature_bytes = durable_slice(bytes, &mut cursor, signature_length)?;
    let proof = authenticate_historical_ownership_lease(
        lease_bytes,
        signature_bytes,
        &verifier.anchor,
        HistoricalOwnershipLeaseExpectation {
            assignment: claim
                .broker_assignment()
                .map_err(|_| DurableOwnershipAuthorityError::CorruptState)?,
            node: claim.node(),
            ownership_authority: &verifier.authority,
            lease_generation: response_generation,
            lease_digest: response_digest,
            accepted_at: DurableHistoricalWallClockInstant::from_authenticated_record(
                accepted_wall_seconds,
            ),
        },
        response_limits(),
    )
    .map_err(|_| DurableOwnershipAuthorityError::CorruptState)?;
    validate_recovered_lease(&claim, proof.lease())?;
    let lease = SignedOwnershipLease {
        canonical_lease: proof.canonical_lease().to_vec(),
        canonical_signature: proof.canonical_signature().to_vec(),
        generation: proof.lease().lease_generation(),
        digest: proof.lease_digest(),
        assignment: proof.lease().assignment(),
        node: proof.lease().node(),
        authority_issued_seconds: proof.lease().authority_issued_seconds(),
        authority_expires_seconds: proof.lease().authority_expires_seconds(),
        maximum_clock_skew_seconds: proof.lease().maximum_clock_skew_seconds(),
        renewal_nonce: *proof.lease().renewal_nonce(),
        signer: proof.authority().clone(),
    };
    Ok(DurableOwnershipEntry {
        claim,
        state: DurableEntryState::Completed {
            accepted_wall_seconds,
            lease: Box::new(lease),
        },
    })
}

fn validate_recovered_lease(
    claim: &OwnershipClaimV1,
    lease: &OwnershipLease,
) -> Result<(), DurableOwnershipAuthorityError> {
    let duration = lease
        .authority_expires_seconds()
        .checked_sub(lease.authority_issued_seconds())
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(DurableOwnershipAuthorityError::CorruptState)?;
    if duration > claim.requested_maximum_seconds() {
        return Err(DurableOwnershipAuthorityError::CorruptState);
    }
    Ok(())
}

fn encode_current_pointer(request_id: [u8; 16], lease: &SignedOwnershipLease) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(66);
    bytes.extend_from_slice(DURABLE_CURRENT_MAGIC);
    bytes.extend_from_slice(&DURABLE_FORMAT_VERSION.to_be_bytes());
    bytes.extend_from_slice(&request_id);
    bytes.extend_from_slice(&lease.generation().to_be_bytes());
    bytes.extend_from_slice(lease.digest().as_bytes());
    bytes
}

fn decode_current_pointer(
    key: &[u8],
    bytes: &[u8],
) -> Result<(SandboxId, [u8; 16], u64, ObjectDigest), DurableOwnershipAuthorityError> {
    if key.len() != DURABLE_CURRENT_PREFIX.len() + 16
        || !key.starts_with(DURABLE_CURRENT_PREFIX)
        || bytes.len() != 66
    {
        return Err(DurableOwnershipAuthorityError::CorruptState);
    }
    let sandbox = SandboxId::from_bytes(
        key[DURABLE_CURRENT_PREFIX.len()..]
            .try_into()
            .map_err(|_| DurableOwnershipAuthorityError::CorruptState)?,
    );
    let mut cursor = 0;
    if durable_take::<8>(bytes, &mut cursor)? != *DURABLE_CURRENT_MAGIC
        || u16::from_be_bytes(durable_take::<2>(bytes, &mut cursor)?) != DURABLE_FORMAT_VERSION
    {
        return Err(DurableOwnershipAuthorityError::CorruptState);
    }
    let request_id = durable_take::<16>(bytes, &mut cursor)?;
    let generation = u64::from_be_bytes(durable_take::<8>(bytes, &mut cursor)?);
    let digest = ObjectDigest::from_bytes(durable_take::<32>(bytes, &mut cursor)?);
    if sandbox.as_bytes() == &[0; 16]
        || request_id == [0; 16]
        || generation == 0
        || digest.as_bytes() == &[0; 32]
        || cursor != bytes.len()
    {
        return Err(DurableOwnershipAuthorityError::CorruptState);
    }
    Ok((sandbox, request_id, generation, digest))
}

type RecoveredOwnershipState = (
    BTreeMap<[u8; 16], DurableOwnershipEntry>,
    BTreeMap<SandboxId, SignedOwnershipLease>,
);

fn recover_durable_ownership(
    journal: &Journal,
    verifier: &OwnershipAuthorityVerifier,
) -> Result<RecoveredOwnershipState, DurableOwnershipAuthorityError> {
    let mut entries = BTreeMap::new();
    for (key, value) in journal.records(RecordNamespace::Operation) {
        if entries.len() >= MAXIMUM_DURABLE_ENTRIES {
            return Err(DurableOwnershipAuthorityError::CorruptState);
        }
        if !key.starts_with(DURABLE_ENTRY_PREFIX) {
            return Err(DurableOwnershipAuthorityError::CorruptState);
        }
        let entry = decode_durable_entry(key, value, verifier)?;
        if entries.insert(*entry.claim.request_id(), entry).is_some() {
            return Err(DurableOwnershipAuthorityError::CorruptState);
        }
    }
    let mut pointers = BTreeMap::new();
    for (key, value) in journal.records(RecordNamespace::DesiredState) {
        if pointers.len() >= MAXIMUM_DURABLE_CURRENT_POINTERS {
            return Err(DurableOwnershipAuthorityError::CorruptState);
        }
        if !key.starts_with(DURABLE_CURRENT_PREFIX) {
            return Err(DurableOwnershipAuthorityError::CorruptState);
        }
        let (sandbox, request, generation, digest) = decode_current_pointer(key, value)?;
        if pointers
            .insert(sandbox, (request, generation, digest))
            .is_some()
        {
            return Err(DurableOwnershipAuthorityError::CorruptState);
        }
    }
    if journal.records(RecordNamespace::Effect).next().is_some()
        || journal
            .records(RecordNamespace::Idempotency)
            .next()
            .is_some()
    {
        return Err(DurableOwnershipAuthorityError::CorruptState);
    }
    let mut grouped = BTreeMap::<SandboxId, Vec<_>>::new();
    for (request, entry) in &entries {
        grouped
            .entry(entry.claim.assignment().sandbox())
            .or_default()
            .push((request, entry));
    }
    if pointers
        .keys()
        .any(|sandbox| !grouped.contains_key(sandbox))
    {
        return Err(DurableOwnershipAuthorityError::CorruptState);
    }
    let mut current = BTreeMap::new();
    for (sandbox, scoped) in grouped {
        recover_sandbox_chain(sandbox, &scoped, &entries, &pointers, &mut current)?;
    }
    Ok((entries, current))
}

fn recover_sandbox_chain(
    sandbox: SandboxId,
    scoped: &[(&[u8; 16], &DurableOwnershipEntry)],
    entries: &BTreeMap<[u8; 16], DurableOwnershipEntry>,
    pointers: &BTreeMap<SandboxId, ([u8; 16], u64, ObjectDigest)>,
    current: &mut BTreeMap<SandboxId, SignedOwnershipLease>,
) -> Result<(), DurableOwnershipAuthorityError> {
    let pending: Vec<_> = scoped
        .iter()
        .filter(|(_, entry)| matches!(entry.state, DurableEntryState::Intent))
        .collect();
    if pending.len() > 1 {
        return Err(DurableOwnershipAuthorityError::CorruptState);
    }
    let completed: Vec<_> = scoped
        .iter()
        .filter_map(|(request, entry)| match &entry.state {
            DurableEntryState::Intent => None,
            DurableEntryState::Completed { lease, .. } => Some((*request, entry, lease)),
        })
        .collect();
    if completed.is_empty() {
        if pointers.contains_key(&sandbox)
            || pending
                .first()
                .is_some_and(|(_, entry)| entry.claim.action() != OwnershipClaimAction::Acquire)
        {
            return Err(DurableOwnershipAuthorityError::CorruptState);
        }
        return Ok(());
    }
    let roots: Vec<_> = completed
        .iter()
        .filter(|(_, entry, _)| entry.claim.action() == OwnershipClaimAction::Acquire)
        .collect();
    if roots.len() != 1 {
        return Err(DurableOwnershipAuthorityError::CorruptState);
    }
    let mut by_fence = BTreeMap::new();
    for (request, _, lease) in &completed {
        let fence = (lease.generation(), *lease.digest().as_bytes());
        if by_fence.insert(fence, **request).is_some() {
            return Err(DurableOwnershipAuthorityError::CorruptState);
        }
    }
    let mut children = BTreeMap::new();
    for (request, entry, lease) in &completed {
        if entry.claim.action() == OwnershipClaimAction::Renew {
            let prior = entry
                .claim
                .expected_prior()
                .ok_or(DurableOwnershipAuthorityError::CorruptState)?;
            let predecessor = by_fence
                .get(&(prior.generation(), *prior.digest().as_bytes()))
                .ok_or(DurableOwnershipAuthorityError::CorruptState)?;
            let predecessor_entry = entries
                .get(predecessor)
                .ok_or(DurableOwnershipAuthorityError::CorruptState)?;
            let DurableEntryState::Completed {
                lease: predecessor_lease,
                ..
            } = &predecessor_entry.state
            else {
                return Err(DurableOwnershipAuthorityError::CorruptState);
            };
            if lease.generation() <= predecessor_lease.generation()
                || lease.assignment() != predecessor_lease.assignment()
                || lease.node() != predecessor_lease.node()
                || children.insert(*predecessor, **request).is_some()
            {
                return Err(DurableOwnershipAuthorityError::CorruptState);
            }
        }
    }
    let mut visited = BTreeSet::new();
    let mut head_request = *roots[0].0;
    loop {
        if !visited.insert(head_request) {
            return Err(DurableOwnershipAuthorityError::CorruptState);
        }
        match children.get(&head_request) {
            Some(next) => head_request = *next,
            None => break,
        }
    }
    if visited.len() != completed.len() {
        return Err(DurableOwnershipAuthorityError::CorruptState);
    }
    let head = entries
        .get(&head_request)
        .ok_or(DurableOwnershipAuthorityError::CorruptState)?;
    let DurableEntryState::Completed {
        lease: head_lease, ..
    } = &head.state
    else {
        return Err(DurableOwnershipAuthorityError::CorruptState);
    };
    if pointers.get(&sandbox) != Some(&(head_request, head_lease.generation(), head_lease.digest()))
    {
        return Err(DurableOwnershipAuthorityError::CorruptState);
    }
    if let Some((_, pending_entry)) = pending.first() {
        validate_claim_against_current(
            &pending_entry.claim,
            &BTreeMap::from([(sandbox, head_lease.as_ref().clone())]),
        )
        .map_err(|_| DurableOwnershipAuthorityError::CorruptState)?;
    }
    current.insert(sandbox, head_lease.as_ref().clone());
    Ok(())
}

fn durable_take<const N: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], DurableOwnershipAuthorityError> {
    durable_slice(bytes, cursor, N)?
        .try_into()
        .map_err(|_| DurableOwnershipAuthorityError::CorruptState)
}

fn durable_slice<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    length: usize,
) -> Result<&'a [u8], DurableOwnershipAuthorityError> {
    let end = cursor
        .checked_add(length)
        .ok_or(DurableOwnershipAuthorityError::CorruptState)?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(DurableOwnershipAuthorityError::CorruptState)?;
    *cursor = end;
    Ok(value)
}

fn encode_claim(
    action: OwnershipClaimAction,
    request_id: [u8; 16],
    assignment: LeaseAssignment,
    desired_generation: DesiredGeneration,
    node: NodeId,
    expected_prior: Option<ExpectedOwnershipLease>,
    requested_maximum_seconds: u64,
) -> [u8; CLAIM_BYTES] {
    let mut bytes = [0_u8; CLAIM_BYTES];
    let mut cursor = 0;
    append(&mut bytes, &mut cursor, CLAIM_MAGIC);
    append(&mut bytes, &mut cursor, &CLAIM_VERSION.to_be_bytes());
    append(&mut bytes, &mut cursor, &[action.code()]);
    append(&mut bytes, &mut cursor, &[0; 5]);
    append(&mut bytes, &mut cursor, &request_id);
    append(&mut bytes, &mut cursor, assignment.sandbox().as_bytes());
    append(&mut bytes, &mut cursor, assignment.incarnation().as_bytes());
    append(
        &mut bytes,
        &mut cursor,
        &assignment.epoch().get().to_be_bytes(),
    );
    append(&mut bytes, &mut cursor, assignment.digest().as_bytes());
    append(&mut bytes, &mut cursor, node.as_bytes());
    append(
        &mut bytes,
        &mut cursor,
        &desired_generation.get().to_be_bytes(),
    );
    match expected_prior {
        Some(expected) => {
            append(&mut bytes, &mut cursor, &expected.generation.to_be_bytes());
            append(&mut bytes, &mut cursor, expected.digest.as_bytes());
        }
        None => {
            append(&mut bytes, &mut cursor, &[0; 8]);
            append(&mut bytes, &mut cursor, &[0; 32]);
        }
    }
    append(
        &mut bytes,
        &mut cursor,
        &requested_maximum_seconds.to_be_bytes(),
    );
    debug_assert_eq!(cursor, CLAIM_BYTES);
    bytes
}

fn append<const N: usize>(target: &mut [u8; CLAIM_BYTES], cursor: &mut usize, value: &[u8; N]) {
    let end = *cursor + N;
    target[*cursor..end].copy_from_slice(value);
    *cursor = end;
}

fn take<const N: usize>(bytes: &[u8], cursor: &mut usize) -> Result<[u8; N], OwnershipClaimError> {
    let end = cursor
        .checked_add(N)
        .ok_or(OwnershipClaimError::InvalidEncoding)?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(OwnershipClaimError::InvalidEncoding)?;
    *cursor = end;
    value
        .try_into()
        .map_err(|_| OwnershipClaimError::InvalidEncoding)
}

fn claim_digest(bytes: &[u8; CLAIM_BYTES]) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(CLAIM_DIGEST_DOMAIN);
    digest.update(bytes);
    ObjectDigest::from_bytes(digest.finalize().into())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::cell::Cell;
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::rc::Rc;

    use aos_sandbox_core::format::{encode_ownership_lease, encode_signature, encode_trust_policy};
    use aos_sandbox_core::model::{
        KeyUsage, SignaturePurpose, SignatureStatement, StableKeyId, TrustPolicy,
    };
    use aos_sandbox_core::{
        AssignmentEpoch, MediaType, OwnershipLease, PortableMediaType, RawClockProvenance,
        TrustScopeId, descriptor_for_bytes, sign_statement,
    };
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::journal::IdempotencyKey;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "aos-sandbox-ownership-{label}-{}-{}",
                std::process::id(),
                aos_sandbox_core::OperationId::new()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn journal(&self) -> PathBuf {
            self.0.join("authority.journal")
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct TestAuthority {
        signing_key: SigningKey,
        authority: KeyReference,
        scope: TrustScopeId,
        policy_descriptor: aos_sandbox_core::ObjectDescriptor,
        requests: BTreeMap<[u8; 16], (ObjectDigest, UnverifiedOwnershipLeaseResponse)>,
        current: Option<(LeaseAssignment, NodeId, u64, ObjectDigest)>,
        now_seconds: i64,
        duration_seconds: i64,
        generation_increment: u64,
        override_assignment: Option<LeaseAssignment>,
        override_node: Option<NodeId>,
    }

    impl TestAuthority {
        fn issue(
            &mut self,
            claim: &OwnershipClaimV1,
            generation: u64,
        ) -> Result<UnverifiedOwnershipLeaseResponse, OwnershipAuthorityError> {
            if let Some((digest, response)) = self.requests.get(claim.request_id()) {
                return if *digest == claim.digest() {
                    Ok(response.clone())
                } else {
                    Err(OwnershipAuthorityError::IdempotencyConflict)
                };
            }
            let assignment = self.override_assignment.unwrap_or(claim.assignment);
            let node = self.override_node.unwrap_or(claim.node);
            let nonce_byte = claim.request_id[0].wrapping_add(generation as u8).max(1);
            let lease = OwnershipLease::new(
                assignment,
                node,
                generation,
                self.now_seconds - 10,
                self.now_seconds - 10 + self.duration_seconds,
                5,
                [nonce_byte; 16],
            )
            .map_err(|_| OwnershipAuthorityError::Internal)?;
            let lease_bytes = encode_ownership_lease(&lease);
            let descriptor = descriptor_for_bytes(
                MediaType::new(PortableMediaType::OwnershipLease.as_str().to_owned())
                    .map_err(|_| OwnershipAuthorityError::Internal)?,
                &lease_bytes,
            );
            let statement = SignatureStatement::new(
                descriptor.clone(),
                self.scope,
                self.authority.clone(),
                SignaturePurpose::OwnershipLease,
                lease.authority_issued_seconds(),
                Some(lease.authority_expires_seconds()),
                self.policy_descriptor.clone(),
            )
            .map_err(|_| OwnershipAuthorityError::Internal)?;
            let signature = sign_statement(statement, &self.signing_key)
                .map_err(|_| OwnershipAuthorityError::Internal)?;
            let response = UnverifiedOwnershipLeaseResponse::from_transport(
                lease_bytes,
                encode_signature(&signature),
            )
            .map_err(|_| OwnershipAuthorityError::Internal)?;
            self.requests
                .insert(claim.request_id, (claim.digest, response.clone()));
            self.current = Some((assignment, node, generation, descriptor.digest()));
            Ok(response)
        }
    }

    impl OwnershipAuthority for TestAuthority {
        fn acquire(
            &mut self,
            claim: &OwnershipClaimV1,
        ) -> Result<UnverifiedOwnershipLeaseResponse, OwnershipAuthorityError> {
            if claim.action != OwnershipClaimAction::Acquire {
                return Err(OwnershipAuthorityError::Internal);
            }
            if let Some((digest, response)) = self.requests.get(claim.request_id()) {
                return if *digest == claim.digest() {
                    Ok(response.clone())
                } else {
                    Err(OwnershipAuthorityError::IdempotencyConflict)
                };
            }
            if self.current.is_some() {
                return Err(OwnershipAuthorityError::AlreadyOwned);
            }
            self.issue(claim, 7)
        }

        fn renew(
            &mut self,
            claim: &OwnershipClaimV1,
        ) -> Result<UnverifiedOwnershipLeaseResponse, OwnershipAuthorityError> {
            if claim.action != OwnershipClaimAction::Renew {
                return Err(OwnershipAuthorityError::Internal);
            }
            if let Some((digest, response)) = self.requests.get(claim.request_id()) {
                return if *digest == claim.digest() {
                    Ok(response.clone())
                } else {
                    Err(OwnershipAuthorityError::IdempotencyConflict)
                };
            }
            let Some((assignment, node, generation, digest)) = self.current else {
                return Err(OwnershipAuthorityError::StaleExpectedPrior);
            };
            if assignment != claim.assignment
                || node != claim.node
                || claim.expected_prior != Some(ExpectedOwnershipLease { generation, digest })
            {
                return Err(OwnershipAuthorityError::StaleExpectedPrior);
            }
            let next = generation
                .checked_add(self.generation_increment)
                .ok_or(OwnershipAuthorityError::Internal)?;
            self.issue(claim, next)
        }
    }

    struct Fixture {
        authority: TestAuthority,
        verifier: OwnershipAuthorityVerifier,
        clock: RawPairedClockSample,
    }

    fn fixture(key_byte: u8) -> Fixture {
        let signing_key = SigningKey::from_bytes(&[key_byte; 32]);
        let public_key = signing_key.verifying_key().to_bytes();
        let authority = KeyReference::new(
            StableKeyId::new(format!("ownership-authority-{key_byte}"))
                .unwrap_or_else(|error| panic!("test key ID failed: {error}")),
            3,
            ObjectDigest::from_bytes(Sha256::digest(public_key).into()),
            KeyUsage::OwnershipLease,
        );
        let scope = TrustScopeId::from_bytes([41; 16]);
        let policy = TrustPolicy::new(
            scope,
            SignaturePurpose::OwnershipLease,
            vec![authority.clone()],
            Vec::new(),
        )
        .unwrap_or_else(|error| panic!("test policy failed: {error}"));
        let policy_bytes = encode_trust_policy(&policy);
        let policy_descriptor = descriptor_for_bytes(
            MediaType::new(PortableMediaType::TrustPolicy.as_str().to_owned())
                .unwrap_or_else(|error| panic!("test media type failed: {error}")),
            &policy_bytes,
        );
        let anchor = OwnershipLeaseTrustAnchor::from_trusted_configuration(
            policy_bytes,
            policy_descriptor.clone(),
            scope,
            authority.clone(),
            public_key,
            DecodeLimits::default(),
        )
        .unwrap_or_else(|error| panic!("test anchor failed: {error}"));
        let clock = test_clock(150);
        Fixture {
            authority: TestAuthority {
                signing_key,
                authority: authority.clone(),
                scope,
                policy_descriptor,
                requests: BTreeMap::new(),
                current: None,
                now_seconds: 150,
                duration_seconds: 40,
                generation_increment: 2,
                override_assignment: None,
                override_node: None,
            },
            verifier: OwnershipAuthorityVerifier::new(anchor, authority),
            clock,
        }
    }

    fn test_clock(wall_seconds: i64) -> RawPairedClockSample {
        RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted(*b"test-owner-clock")
                .unwrap_or_else(|error| panic!("test provenance failed: {error}")),
            [42; 16],
            wall_seconds,
            10_000_000_000,
        )
        .unwrap_or_else(|error| panic!("test clock failed: {error}"))
    }

    fn assignment(byte: u8) -> LeaseAssignment {
        LeaseAssignment::new(
            SandboxId::from_bytes([byte; 16]),
            IncarnationId::from_bytes([byte + 1; 16]),
            AssignmentEpoch::new(5),
            ObjectDigest::from_bytes([byte + 2; 32]),
        )
        .unwrap_or_else(|error| panic!("test assignment failed: {error}"))
    }

    fn indexed_assignment(index: u16) -> LeaseAssignment {
        let mut sandbox = [0; 16];
        sandbox[..2].copy_from_slice(&index.to_be_bytes());
        let mut incarnation = [0; 16];
        incarnation[..2].copy_from_slice(&index.saturating_add(1).to_be_bytes());
        let mut manifest = [0; 32];
        manifest[..2].copy_from_slice(&index.saturating_add(2).to_be_bytes());
        LeaseAssignment::new(
            SandboxId::from_bytes(sandbox),
            IncarnationId::from_bytes(incarnation),
            AssignmentEpoch::new(5),
            ObjectDigest::from_bytes(manifest),
        )
        .unwrap_or_else(|error| panic!("indexed test assignment failed: {error}"))
    }

    fn acquire_claim(request: u8) -> OwnershipClaimV1 {
        OwnershipClaimV1::acquire(
            [request; 16],
            assignment(1),
            DesiredGeneration::new(6),
            NodeId::from_bytes([4; 16]),
            60,
        )
        .unwrap_or_else(|error| panic!("test claim failed: {error}"))
    }

    fn open_test_store(
        path: &Path,
        key_byte: u8,
    ) -> Result<DurableOwnershipAuthority, DurableOwnershipAuthorityError> {
        let (journal, _) = Journal::open(path, JournalLimits::default())?;
        DurableOwnershipAuthority::from_journal(journal, fixture(key_byte).verifier)
    }

    fn renewal_claim(request: u8, prior: &SignedOwnershipLease) -> OwnershipClaimV1 {
        OwnershipClaimV1::renew(
            [request; 16],
            prior.assignment(),
            DesiredGeneration::new(6),
            prior.node(),
            prior.expected_renewal_fence(),
            60,
        )
        .unwrap_or_else(|error| panic!("test renewal claim failed: {error}"))
    }

    fn completed_entry(
        claim: OwnershipClaimV1,
        lease: SignedOwnershipLease,
        accepted_wall_seconds: i64,
    ) -> DurableOwnershipEntry {
        DurableOwnershipEntry {
            claim,
            state: DurableEntryState::Completed {
                accepted_wall_seconds,
                lease: Box::new(lease),
            },
        }
    }

    fn to_hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;

        let mut encoded = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            write!(&mut encoded, "{byte:02x}")
                .unwrap_or_else(|error| panic!("test hex encoding failed: {error}"));
        }
        encoded
    }

    #[test]
    fn claim_encoding_is_fixed_canonical_and_substitution_bound() {
        let claim = acquire_claim(5);
        assert_eq!(claim.canonical_bytes().len(), CLAIM_BYTES);
        assert_eq!(
            to_hex(claim.canonical_bytes()),
            "414f534f434c4d3100010100000000000505050505050505050505050505050501010101010101010101010101010101020202020202020202020202020202020000000000000005030303030303030303030303030303030303030303030303030303030303030304040404040404040404040404040404000000000000000600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003c"
        );
        assert_eq!(
            to_hex(claim.digest().as_bytes()),
            "621b3094bf91a148412e2debb10c168318b4375e40a2e7164d3076f222ca25e4"
        );
        assert_eq!(
            OwnershipClaimV1::from_canonical_bytes(claim.canonical_bytes())
                .unwrap_or_else(|error| panic!("test claim decode failed: {error}")),
            claim
        );
        let changed = OwnershipClaimV1::acquire(
            [6; 16],
            claim.assignment,
            claim.desired_generation,
            claim.node,
            claim.requested_maximum_seconds,
        )
        .unwrap_or_else(|error| panic!("test changed claim failed: {error}"));
        assert_ne!(claim.digest(), changed.digest());

        let mut reserved = *claim.canonical_bytes();
        reserved[11] = 1;
        assert_eq!(
            OwnershipClaimV1::from_canonical_bytes(&reserved),
            Err(OwnershipClaimError::InvalidEncoding)
        );
    }

    #[test]
    fn acquire_is_exclusive_and_exact_request_replay_is_idempotent() {
        let mut fixture = fixture(17);
        let claim = acquire_claim(5);
        let first = fixture
            .verifier
            .acquire(&mut fixture.authority, &claim, &fixture.clock)
            .unwrap_or_else(|error| panic!("test acquire failed: {error}"));
        let replay = fixture
            .verifier
            .acquire(&mut fixture.authority, &claim, &fixture.clock)
            .unwrap_or_else(|error| panic!("test replay failed: {error}"));
        assert_eq!(first, replay);
        assert_eq!(first.generation(), 7);
        assert_ne!(first.renewal_nonce(), &[0; 16]);
        assert_eq!(first.authority_issued_seconds(), 140);
        assert_eq!(first.authority_expires_seconds(), 180);

        assert_eq!(
            fixture
                .verifier
                .acquire(&mut fixture.authority, &acquire_claim(6), &fixture.clock,),
            Err(OwnershipLeaseAcquisitionError::Authority(
                OwnershipAuthorityError::AlreadyOwned
            ))
        );
    }

    #[test]
    fn renew_is_exact_cas_and_changes_only_lease_facts() {
        let mut fixture = fixture(18);
        let old = fixture
            .verifier
            .acquire(&mut fixture.authority, &acquire_claim(5), &fixture.clock)
            .unwrap_or_else(|error| panic!("test acquire failed: {error}"));
        fixture.authority.now_seconds = 160;
        let renew = OwnershipClaimV1::renew(
            [7; 16],
            old.assignment(),
            DesiredGeneration::new(6),
            old.node(),
            old.expected_renewal_fence(),
            60,
        )
        .unwrap_or_else(|error| panic!("test renewal claim failed: {error}"));
        let renewal_clock = test_clock(160);
        let renewed = fixture
            .verifier
            .renew(&mut fixture.authority, &renew, &renewal_clock)
            .unwrap_or_else(|error| panic!("test renewal failed: {error}"));

        assert_eq!(renewed.assignment(), old.assignment());
        assert_eq!(renewed.node(), old.node());
        assert!(renewed.generation() > old.generation());
        assert_ne!(renewed.digest(), old.digest());
        assert_ne!(renewed.renewal_nonce(), old.renewal_nonce());

        let stale = OwnershipClaimV1::renew(
            [8; 16],
            old.assignment(),
            DesiredGeneration::new(6),
            old.node(),
            old.expected_renewal_fence(),
            60,
        )
        .unwrap_or_else(|error| panic!("test stale claim failed: {error}"));
        assert_eq!(
            fixture
                .verifier
                .renew(&mut fixture.authority, &stale, &renewal_clock),
            Err(OwnershipLeaseAcquisitionError::Authority(
                OwnershipAuthorityError::StaleExpectedPrior
            ))
        );
    }

    #[test]
    fn verifier_rejects_context_expiry_duration_generation_and_signature_attacks() {
        for attack in 0..5 {
            let mut fixture = fixture(19);
            match attack {
                0 => fixture.authority.override_node = Some(NodeId::from_bytes([99; 16])),
                1 => fixture.authority.override_assignment = Some(assignment(51)),
                2 => fixture.authority.now_seconds = 50,
                3 => fixture.authority.duration_seconds = 100,
                _ => {}
            }
            let claim = acquire_claim(5);
            let response = fixture
                .authority
                .acquire(&claim)
                .unwrap_or_else(|error| panic!("test raw acquire failed: {error}"));
            let response = if attack == 4 {
                let mut signature = response.signature;
                let last = signature.len() - 1;
                signature[last] ^= 1;
                UnverifiedOwnershipLeaseResponse::from_transport(response.lease, signature)
                    .unwrap_or_else(|error| panic!("test tamper response failed: {error}"))
            } else {
                response
            };
            assert_eq!(
                fixture
                    .verifier
                    .verify_response(&claim, response, &fixture.clock),
                Err(OwnershipLeaseAcquisitionError::InvalidIssuerResponse)
            );
        }

        let mut fixture = fixture(20);
        let old = fixture
            .verifier
            .acquire(&mut fixture.authority, &acquire_claim(5), &fixture.clock)
            .unwrap_or_else(|error| panic!("test acquire failed: {error}"));
        fixture.authority.generation_increment = 0;
        let claim = OwnershipClaimV1::renew(
            [9; 16],
            old.assignment(),
            DesiredGeneration::new(6),
            old.node(),
            old.expected_renewal_fence(),
            60,
        )
        .unwrap_or_else(|error| panic!("test renew claim failed: {error}"));
        assert_eq!(
            fixture
                .verifier
                .renew(&mut fixture.authority, &claim, &fixture.clock),
            Err(OwnershipLeaseAcquisitionError::InvalidIssuerResponse)
        );
    }

    #[test]
    fn trust_generation_substitution_is_rejected() {
        let mut issuer = fixture(21);
        let verifier = fixture(22).verifier;
        let claim = acquire_claim(5);
        assert_eq!(
            verifier.acquire(&mut issuer.authority, &claim, &issuer.clock),
            Err(OwnershipLeaseAcquisitionError::InvalidIssuerResponse)
        );
    }

    #[test]
    fn request_id_reuse_with_different_claim_is_rejected() {
        let mut fixture = fixture(23);
        let claim = acquire_claim(5);
        fixture
            .verifier
            .acquire(&mut fixture.authority, &claim, &fixture.clock)
            .unwrap_or_else(|error| panic!("test acquire failed: {error}"));
        let changed = OwnershipClaimV1::acquire(
            *claim.request_id(),
            claim.assignment(),
            claim.desired_generation(),
            claim.node(),
            59,
        )
        .unwrap_or_else(|error| panic!("test changed claim failed: {error}"));
        assert_eq!(
            fixture
                .verifier
                .acquire(&mut fixture.authority, &changed, &fixture.clock),
            Err(OwnershipLeaseAcquisitionError::Authority(
                OwnershipAuthorityError::IdempotencyConflict
            ))
        );
    }

    #[test]
    fn durable_intent_restart_and_signed_before_commit_crash_replay_safely() {
        let directory = TestDirectory::new("durable-crash");
        let path = directory.journal();
        let Fixture {
            mut authority,
            verifier,
            clock,
        } = fixture(31);
        let (journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        let mut store = DurableOwnershipAuthority::from_journal(journal, verifier).unwrap();
        let claim = acquire_claim(5);
        assert_eq!(
            store.begin(&claim).unwrap(),
            DurableOwnershipBeginOutcome::Pending
        );
        assert!(authority.requests.is_empty());
        assert!(store.current(claim.assignment().sandbox()).is_none());
        drop(store);

        let store = open_test_store(&path, 31).unwrap();
        assert!(store.is_pending(claim.request_id()));
        let issued_before_commit = authority.acquire(&claim).unwrap();
        drop(store);

        let mut store = open_test_store(&path, 31).unwrap();
        let completed = store
            .complete(*claim.request_id(), &mut authority, &mut || Ok(clock))
            .unwrap();
        assert_eq!(completed.canonical_lease(), issued_before_commit.lease);
        assert_eq!(
            completed.canonical_signature(),
            issued_before_commit.signature
        );
        drop(store);

        assert!(matches!(
            open_test_store(&path, 30),
            Err(DurableOwnershipAuthorityError::CorruptState)
        ));

        let mut store = open_test_store(&path, 31).unwrap();
        assert_eq!(
            store.begin(&claim).unwrap(),
            DurableOwnershipBeginOutcome::Replay(Box::new(completed.clone()))
        );
        assert_eq!(
            store.current(claim.assignment().sandbox()),
            Some(&completed)
        );
        let rebound = OwnershipClaimV1::acquire(
            *claim.request_id(),
            claim.assignment(),
            claim.desired_generation(),
            claim.node(),
            59,
        )
        .unwrap();
        assert!(matches!(
            store.begin(&rebound),
            Err(DurableOwnershipAuthorityError::IdempotencyConflict)
        ));
        assert!(matches!(
            store.begin(&acquire_claim(6)),
            Err(DurableOwnershipAuthorityError::CompareAndSwapConflict)
        ));
    }

    #[test]
    fn durable_renewal_chain_recovers_expired_history_and_rejects_stale_cas() {
        let directory = TestDirectory::new("durable-renewal");
        let path = directory.journal();
        let Fixture {
            mut authority,
            verifier,
            clock,
        } = fixture(32);
        let (journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        let mut store = DurableOwnershipAuthority::from_journal(journal, verifier).unwrap();
        let acquire = acquire_claim(5);
        store.begin(&acquire).unwrap();
        let old = store
            .complete(*acquire.request_id(), &mut authority, &mut || Ok(clock))
            .unwrap();
        let renew = renewal_claim(7, &old);
        store.begin(&renew).unwrap();
        authority.now_seconds = 160;
        let renewed = store
            .complete(*renew.request_id(), &mut authority, &mut || {
                Ok(test_clock(160))
            })
            .unwrap();
        assert!(renewed.generation() > old.generation());
        let stale = renewal_claim(8, &old);
        assert!(matches!(
            store.begin(&stale),
            Err(DurableOwnershipAuthorityError::CompareAndSwapConflict)
        ));
        drop(store);

        // Recovery deliberately has no current wall-clock input; both signed
        // intervals may be expired now, but their durable acceptance instants
        // still authenticate the chain without producing broker authority.
        let store = open_test_store(&path, 32).unwrap();
        assert_eq!(
            store.current(acquire.assignment().sandbox()),
            Some(&renewed)
        );
    }

    #[test]
    fn distinct_sandboxes_recover_independent_acquired_and_renewed_heads() {
        let directory = TestDirectory::new("independent-sandbox-chains");
        let path = directory.journal();
        let verifier = fixture(45).verifier;
        let mut issuer_a = fixture(45).authority;
        let mut issuer_b = fixture(45).authority;
        let (journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        let mut store = DurableOwnershipAuthority::from_journal(journal, verifier).unwrap();
        let acquire_a = OwnershipClaimV1::acquire(
            [10; 16],
            assignment(10),
            DesiredGeneration::new(6),
            NodeId::from_bytes([50; 16]),
            60,
        )
        .unwrap();
        let acquire_b = OwnershipClaimV1::acquire(
            [20; 16],
            assignment(20),
            DesiredGeneration::new(6),
            NodeId::from_bytes([51; 16]),
            60,
        )
        .unwrap();

        store.begin(&acquire_a).unwrap();
        let acquired_a = store
            .complete(*acquire_a.request_id(), &mut issuer_a, &mut || {
                Ok(test_clock(150))
            })
            .unwrap();
        store.begin(&acquire_b).unwrap();
        let acquired_b = store
            .complete(*acquire_b.request_id(), &mut issuer_b, &mut || {
                Ok(test_clock(150))
            })
            .unwrap();
        let renew_a = renewal_claim(11, &acquired_a);
        let renew_b = renewal_claim(21, &acquired_b);
        issuer_a.now_seconds = 160;
        issuer_b.now_seconds = 170;
        store.begin(&renew_b).unwrap();
        let renewed_b = store
            .complete(*renew_b.request_id(), &mut issuer_b, &mut || {
                Ok(test_clock(170))
            })
            .unwrap();
        store.begin(&renew_a).unwrap();
        let renewed_a = store
            .complete(*renew_a.request_id(), &mut issuer_a, &mut || {
                Ok(test_clock(160))
            })
            .unwrap();
        drop(store);

        let reopened = open_test_store(&path, 45).unwrap();
        assert_eq!(
            reopened.current(acquire_a.assignment().sandbox()),
            Some(&renewed_a)
        );
        assert_eq!(
            reopened.current(acquire_b.assignment().sandbox()),
            Some(&renewed_b)
        );
        assert_ne!(renewed_a.digest(), renewed_b.digest());
    }

    #[test]
    fn cross_sandbox_current_pointer_substitution_fails_recovery_closed() {
        for attack in 0..3_u8 {
            let directory = TestDirectory::new(&format!("pointer-substitution-{attack}"));
            let path = directory.journal();
            let verifier = fixture(46 + attack).verifier;
            let mut issuer_a = fixture(46 + attack).authority;
            let mut issuer_b = fixture(46 + attack).authority;
            let (journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
            let mut store = DurableOwnershipAuthority::from_journal(journal, verifier).unwrap();
            let claim_a = OwnershipClaimV1::acquire(
                [10; 16],
                assignment(10),
                DesiredGeneration::new(6),
                NodeId::from_bytes([50; 16]),
                60,
            )
            .unwrap();
            let claim_b = OwnershipClaimV1::acquire(
                [20; 16],
                assignment(20),
                DesiredGeneration::new(6),
                NodeId::from_bytes([51; 16]),
                60,
            )
            .unwrap();
            store.begin(&claim_a).unwrap();
            let lease_a = store
                .complete(*claim_a.request_id(), &mut issuer_a, &mut || {
                    Ok(test_clock(150))
                })
                .unwrap();
            store.begin(&claim_b).unwrap();
            let lease_b = store
                .complete(*claim_b.request_id(), &mut issuer_b, &mut || {
                    Ok(test_clock(150))
                })
                .unwrap();
            drop(store);

            let key_a = durable_current_key(claim_a.assignment().sandbox());
            let key_b = durable_current_key(claim_b.assignment().sandbox());
            let records = match attack {
                0 => vec![JournalRecord::delete(RecordNamespace::DesiredState, key_a)],
                1 => vec![JournalRecord::put(
                    RecordNamespace::DesiredState,
                    key_a,
                    encode_current_pointer(*claim_b.request_id(), &lease_b),
                )],
                _ => vec![
                    JournalRecord::put(
                        RecordNamespace::DesiredState,
                        key_a,
                        encode_current_pointer(*claim_b.request_id(), &lease_b),
                    ),
                    JournalRecord::put(
                        RecordNamespace::DesiredState,
                        key_b,
                        encode_current_pointer(*claim_a.request_id(), &lease_a),
                    ),
                ],
            };
            let (mut journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
            journal
                .commit(&JournalTransaction::new([100 + attack; 16], records).unwrap())
                .unwrap();
            drop(journal);

            assert!(matches!(
                open_test_store(&path, 46 + attack),
                Err(DurableOwnershipAuthorityError::CorruptState)
            ));
        }
    }

    #[test]
    fn durable_recovery_rejects_duplicate_roots_and_forks() {
        let directory = TestDirectory::new("durable-roots");
        let path = directory.journal();
        let Fixture {
            mut authority,
            verifier,
            clock,
        } = fixture(33);
        let (journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        let mut store = DurableOwnershipAuthority::from_journal(journal, verifier).unwrap();
        let first_claim = acquire_claim(5);
        store.begin(&first_claim).unwrap();
        store
            .complete(*first_claim.request_id(), &mut authority, &mut || Ok(clock))
            .unwrap();
        drop(store);

        let mut second = fixture(33);
        let second_claim = acquire_claim(6);
        let second_lease = second
            .verifier
            .acquire(&mut second.authority, &second_claim, &second.clock)
            .unwrap();
        let entry = completed_entry(second_claim.clone(), second_lease, 150);
        let (mut journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        journal
            .commit(
                &JournalTransaction::new(
                    [90; 16],
                    vec![JournalRecord::put(
                        RecordNamespace::Operation,
                        durable_entry_key(second_claim.request_id()),
                        encode_durable_entry(&entry, &second.verifier.authority),
                    )],
                )
                .unwrap(),
            )
            .unwrap();
        drop(journal);
        assert!(matches!(
            open_test_store(&path, 33),
            Err(DurableOwnershipAuthorityError::CorruptState)
        ));

        let directory = TestDirectory::new("durable-fork");
        let path = directory.journal();
        let mut base = fixture(34);
        let (journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        let mut store = DurableOwnershipAuthority::from_journal(journal, base.verifier).unwrap();
        let root_claim = acquire_claim(5);
        store.begin(&root_claim).unwrap();
        let root = store
            .complete(*root_claim.request_id(), &mut base.authority, &mut || {
                Ok(base.clock)
            })
            .unwrap();
        drop(store);
        let mut journal = Journal::open(&path, JournalLimits::default()).unwrap().0;
        for (request, transaction) in [(7, 91), (8, 92)] {
            let mut branch = fixture(34);
            branch.authority.current = Some((
                root.assignment(),
                root.node(),
                root.generation(),
                root.digest(),
            ));
            let claim = renewal_claim(request, &root);
            let lease = branch
                .verifier
                .renew(&mut branch.authority, &claim, &branch.clock)
                .unwrap();
            let entry = completed_entry(claim.clone(), lease, 150);
            journal
                .commit(
                    &JournalTransaction::new(
                        [transaction; 16],
                        vec![JournalRecord::put(
                            RecordNamespace::Operation,
                            durable_entry_key(claim.request_id()),
                            encode_durable_entry(&entry, &branch.verifier.authority),
                        )],
                    )
                    .unwrap(),
                )
                .unwrap();
        }
        drop(journal);
        assert!(matches!(
            open_test_store(&path, 34),
            Err(DurableOwnershipAuthorityError::CorruptState)
        ));
    }

    #[test]
    fn durable_recovery_rejects_broken_predecessor_rollback_and_tamper() {
        for attack in 0..4 {
            let directory = TestDirectory::new(&format!("durable-chain-attack-{attack}"));
            let path = directory.journal();
            let mut base = fixture(35 + attack);
            let (journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
            let mut store =
                DurableOwnershipAuthority::from_journal(journal, base.verifier).unwrap();
            let root_claim = acquire_claim(5);
            store.begin(&root_claim).unwrap();
            let root = store
                .complete(*root_claim.request_id(), &mut base.authority, &mut || {
                    Ok(base.clock)
                })
                .unwrap();
            drop(store);

            let mut branch = fixture(35 + attack);
            let claim = if attack == 0 {
                OwnershipClaimV1::renew(
                    [7; 16],
                    root.assignment(),
                    DesiredGeneration::new(6),
                    root.node(),
                    ExpectedOwnershipLease::new(99, ObjectDigest::from_bytes([99; 32])).unwrap(),
                    60,
                )
                .unwrap()
            } else {
                renewal_claim(7, &root)
            };
            let raw = branch
                .authority
                .issue(
                    &claim,
                    match attack {
                        1 => root.generation(),
                        2 => root.generation() - 1,
                        _ => root.generation() + 2,
                    },
                )
                .unwrap();
            let lease = aos_sandbox_core::format::decode_ownership_lease(
                &raw.lease,
                DecodeLimits::default(),
            )
            .unwrap();
            let signed = SignedOwnershipLease::from_test_artifacts(lease, raw.signature);
            let entry = completed_entry(claim.clone(), signed, 150);
            let mut encoded = encode_durable_entry(&entry, &branch.authority.authority);
            if attack == 3 {
                let last = encoded.len() - 1;
                encoded[last] ^= 1;
            }
            let (mut journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
            journal
                .commit(
                    &JournalTransaction::new(
                        [93; 16],
                        vec![JournalRecord::put(
                            RecordNamespace::Operation,
                            durable_entry_key(claim.request_id()),
                            encoded,
                        )],
                    )
                    .unwrap(),
                )
                .unwrap();
            drop(journal);
            assert!(matches!(
                open_test_store(&path, 35 + attack),
                Err(DurableOwnershipAuthorityError::CorruptState)
            ));
        }
    }

    #[test]
    fn durable_recovery_rejects_oversized_record_before_decode() {
        let directory = TestDirectory::new("durable-oversized");
        let path = directory.journal();
        let (mut journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        journal
            .commit(
                &JournalTransaction::new(
                    [94; 16],
                    vec![JournalRecord::put(
                        RecordNamespace::Operation,
                        durable_entry_key(&[5; 16]),
                        vec![0; MAXIMUM_DURABLE_ENTRY_BYTES + 1],
                    )],
                )
                .unwrap(),
            )
            .unwrap();
        drop(journal);
        assert!(matches!(
            open_test_store(&path, 39),
            Err(DurableOwnershipAuthorityError::CorruptState)
        ));
    }

    #[test]
    fn transaction_domains_prevent_caller_selected_begin_completion_collision() {
        fn exercise(completion_first: bool, key_byte: u8) {
            let directory = TestDirectory::new(if completion_first {
                "transaction-domain-completion-first"
            } else {
                "transaction-domain-begin-first"
            });
            let path = directory.journal();
            let Fixture {
                mut authority,
                verifier,
                clock,
            } = fixture(key_byte);
            let (journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
            let mut store = DurableOwnershipAuthority::from_journal(journal, verifier).unwrap();
            let claim_a = acquire_claim(5);
            let request_b = completion_transaction_id(*claim_a.request_id());
            let claim_b = OwnershipClaimV1::acquire(
                request_b,
                assignment(20),
                DesiredGeneration::new(6),
                NodeId::from_bytes([44; 16]),
                60,
            )
            .unwrap();

            assert_ne!(
                begin_transaction_id(request_b),
                completion_transaction_id(*claim_a.request_id())
            );
            if !completion_first {
                assert_eq!(
                    store.begin(&claim_b).unwrap(),
                    DurableOwnershipBeginOutcome::Pending
                );
            }
            store.begin(&claim_a).unwrap();
            store
                .complete(*claim_a.request_id(), &mut authority, &mut || Ok(clock))
                .unwrap();
            if completion_first {
                assert_eq!(
                    store.begin(&claim_b).unwrap(),
                    DurableOwnershipBeginOutcome::Pending
                );
            }
        }

        exercise(true, 40);
        exercise(false, 41);
    }

    #[test]
    fn completion_samples_protected_clock_after_issuer_round_trip() {
        struct AdvancingAuthority {
            inner: TestAuthority,
            wall: Rc<Cell<i64>>,
        }

        impl OwnershipAuthority for AdvancingAuthority {
            fn acquire(
                &mut self,
                claim: &OwnershipClaimV1,
            ) -> Result<UnverifiedOwnershipLeaseResponse, OwnershipAuthorityError> {
                let response = self.inner.acquire(claim)?;
                self.wall.set(300);
                Ok(response)
            }

            fn renew(
                &mut self,
                claim: &OwnershipClaimV1,
            ) -> Result<UnverifiedOwnershipLeaseResponse, OwnershipAuthorityError> {
                self.inner.renew(claim)
            }
        }

        let directory = TestDirectory::new("post-issuer-clock");
        let path = directory.journal();
        let fixture = fixture(42);
        let wall = Rc::new(Cell::new(150));
        let mut authority = AdvancingAuthority {
            inner: fixture.authority,
            wall: Rc::clone(&wall),
        };
        let (journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        let mut store = DurableOwnershipAuthority::from_journal(journal, fixture.verifier).unwrap();
        let claim = acquire_claim(5);
        store.begin(&claim).unwrap();
        let result = store.complete(*claim.request_id(), &mut authority, &mut || {
            Ok(test_clock(wall.get()))
        });

        assert!(matches!(
            result,
            Err(DurableOwnershipAuthorityError::Acquisition(
                OwnershipLeaseAcquisitionError::InvalidIssuerResponse
            ))
        ));
        assert!(store.is_pending(claim.request_id()));
        assert!(store.current(claim.assignment().sandbox()).is_none());
    }

    #[test]
    fn protected_clock_failure_preserves_intent_for_exact_resume() {
        let directory = TestDirectory::new("clock-failure-resume");
        let path = directory.journal();
        let Fixture {
            mut authority,
            verifier,
            ..
        } = fixture(50);
        let (journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        let mut store = DurableOwnershipAuthority::from_journal(journal, verifier).unwrap();
        let claim = acquire_claim(5);
        store.begin(&claim).unwrap();

        let failed = store.complete(*claim.request_id(), &mut authority, &mut || {
            Err(ProtectedOwnershipClockError)
        });
        assert!(matches!(
            failed,
            Err(DurableOwnershipAuthorityError::ProtectedClockUnavailable(
                ProtectedOwnershipClockError
            ))
        ));
        assert_eq!(authority.requests.len(), 1);
        assert!(store.is_pending(claim.request_id()));
        assert!(store.current(claim.assignment().sandbox()).is_none());
        drop(store);

        let mut store = open_test_store(&path, 50).unwrap();
        assert!(store.is_pending(claim.request_id()));
        assert!(store.current(claim.assignment().sandbox()).is_none());
        let completed = store
            .complete(*claim.request_id(), &mut authority, &mut || {
                Ok(test_clock(160))
            })
            .unwrap();
        assert_eq!(authority.requests.len(), 1);
        assert!(!store.is_pending(claim.request_id()));
        assert_eq!(
            store.current(claim.assignment().sandbox()),
            Some(&completed)
        );
    }

    #[test]
    fn fixed_epoch_limits_reserve_every_admitted_intent_completion() {
        let limits = ownership_journal_limits();
        assert_eq!(limits.maximum_transactions, MAXIMUM_DURABLE_ENTRIES * 2);
        assert_eq!(limits.maximum_records_per_transaction, 2);
        assert_eq!(limits.maximum_materialized_records, MAXIMUM_DURABLE_RECORDS);
        assert!(limits.maximum_journal_bytes < JournalLimits::default().maximum_journal_bytes);
        assert!(limits.maximum_journal_bytes < 40 * 1024 * 1024);

        let fixture = fixture(43);
        let claim = acquire_claim(5);
        let response = fixture
            .authority
            .requests
            .get(claim.request_id())
            .map(|(_, response)| response.clone());
        assert!(response.is_none());
        let maximal = SignedOwnershipLease {
            canonical_lease: vec![0; MAXIMUM_LEASE_BYTES],
            canonical_signature: vec![0; MAXIMUM_SIGNATURE_BYTES],
            generation: 1,
            digest: ObjectDigest::from_bytes([1; 32]),
            assignment: claim.assignment(),
            node: claim.node(),
            authority_issued_seconds: 100,
            authority_expires_seconds: 200,
            maximum_clock_skew_seconds: 5,
            renewal_nonce: [1; 16],
            signer: fixture.verifier.authority.clone(),
        };
        let entry = completed_entry(claim, maximal.clone(), 150);
        let entry_bytes = encode_durable_entry(&entry, &fixture.verifier.authority);
        let entry_record_bytes = 7 + durable_entry_key(&[1; 16]).len() + entry_bytes.len();
        let current_bytes = encode_current_pointer([1; 16], &maximal);
        let current_record_bytes =
            7 + durable_current_key(maximal.assignment().sandbox()).len() + current_bytes.len();
        assert!(entry_record_bytes <= limits.maximum_record_bytes);
        assert!(entry_record_bytes + current_record_bytes <= limits.maximum_transaction_bytes);
        let intent = DurableOwnershipEntry {
            claim: entry.claim.clone(),
            state: DurableEntryState::Intent,
        };
        assert!(
            encode_durable_entry(&intent, &fixture.verifier.authority).len()
                <= MAXIMUM_DURABLE_INTENT_BYTES
        );

        let directory = TestDirectory::new("epoch-capacity");
        let path = directory.journal();
        let (journal, _) = Journal::open(&path, ownership_journal_limits()).unwrap();
        let mut store = DurableOwnershipAuthority::from_journal(journal, fixture.verifier).unwrap();
        for index in 1..=MAXIMUM_DURABLE_ENTRIES as u16 {
            let mut request = [0; 16];
            request[..2].copy_from_slice(&index.to_be_bytes());
            let claim = OwnershipClaimV1::acquire(
                request,
                indexed_assignment(index),
                DesiredGeneration::new(6),
                NodeId::from_bytes([44; 16]),
                60,
            )
            .unwrap();
            assert_eq!(
                store.begin(&claim).unwrap(),
                DurableOwnershipBeginOutcome::Pending
            );
        }
        let rejected = OwnershipClaimV1::acquire(
            [77; 16],
            assignment(77),
            DesiredGeneration::new(6),
            NodeId::from_bytes([44; 16]),
            60,
        )
        .unwrap();
        assert!(matches!(
            store.begin(&rejected),
            Err(DurableOwnershipAuthorityError::ResourceExhausted)
        ));
        drop(store);
        assert!(open_test_store(&path, 43).is_ok());
    }

    #[test]
    fn recovery_rejects_all_foreign_owned_namespaces() {
        for case in 0..4_u8 {
            let directory = TestDirectory::new(&format!("foreign-namespace-{case}"));
            let path = directory.journal();
            let record = match case {
                0 => JournalRecord::put(
                    RecordNamespace::Operation,
                    b"foreign-operation".to_vec(),
                    vec![1],
                ),
                1 => JournalRecord::put(
                    RecordNamespace::DesiredState,
                    b"foreign-desired".to_vec(),
                    vec![1],
                ),
                2 => {
                    JournalRecord::put(RecordNamespace::Effect, b"foreign-effect".to_vec(), vec![1])
                }
                _ => JournalRecord::idempotency(
                    &IdempotencyKey::new(b"foreign-idempotency".to_vec()).unwrap(),
                    [1; 32],
                    aos_sandbox_core::OperationId::from_bytes([2; 16]),
                ),
            };
            let (mut journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
            journal
                .commit(&JournalTransaction::new([case + 1; 16], vec![record]).unwrap())
                .unwrap();
            drop(journal);

            assert!(matches!(
                open_test_store(&path, 44),
                Err(DurableOwnershipAuthorityError::CorruptState)
            ));
        }
    }

    #[test]
    fn malformed_signature_response_is_rejected_before_verification() {
        assert_eq!(
            UnverifiedOwnershipLeaseResponse::from_transport(
                vec![1],
                vec![0; MAXIMUM_SIGNATURE_BYTES + 1],
            ),
            Err(OwnershipLeaseAcquisitionError::InvalidIssuerResponse)
        );
    }
}

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

use aos_sandbox_core::format::{decode_signature, encode_signature};
use aos_sandbox_core::model::KeyReference;
use aos_sandbox_core::{
    BrokerAssignment, DecodeLimits, DesiredGeneration, IncarnationId, LeaseAssignment, NodeId,
    ObjectDigest, OwnershipLeaseTrustAnchor, RawPairedClockSample, SandboxId,
    VerifiedOwnershipLease, verify_ownership_lease,
};
use sha2::{Digest as _, Sha256};

const CLAIM_MAGIC: &[u8; 8] = b"AOSOCLM1";
const CLAIM_VERSION: u16 = 1;
const CLAIM_BYTES: usize = 176;
const CLAIM_DIGEST_DOMAIN: &[u8] = b"aos-sandbox-ownership-claim-v1\0";
const MAXIMUM_REQUESTED_DURATION_SECONDS: u64 = 86_400;
const MAXIMUM_LEASE_BYTES: usize = 64 * 1024;
const MAXIMUM_SIGNATURE_BYTES: usize = 64 * 1024;

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
}

impl SignedOwnershipLease {
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
    use std::collections::BTreeMap;

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

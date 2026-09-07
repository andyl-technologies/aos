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
//!
//! Transaction receipts use a separate fixed canonical domain:
//!
//! ```text
//! AOSOTR1\0 || receipt-version:u16be || protocol-code:u16be ||
//! protocol-major:u16be || protocol-minor:u16be || action:u8 || reserved:7 ||
//! authority-key-id-length:u16be || authority-key-id || authority-generation:u64be ||
//! authority-public-key-sha256:32 || request-id:16 || claim-digest:32 ||
//! lease-size:u64be || lease-digest:32
//! ```
//!
//! [`protocol`] defines the bounded transport-neutral V1 transaction
//! semantics. It intentionally defines no socket framing or remote carrier.
//! Protocol 1.1 adds same-owner assignment advancement as action 3. Existing
//! acquire/renew encodings remain byte-exact; advance receipts alone require
//! protocol minor 1, and 1.0 sessions cannot admit the new action.

pub mod protocol;

use aos_sandbox_core::format::{decode_signature, encode_signature};
use aos_sandbox_core::model::{KeyReference, KeyUsage, StableKeyId};
use aos_sandbox_core::{
    BrokerAssignment, DecodeLimits, DesiredGeneration, DurableHistoricalWallClockInstant,
    HistoricalOwnershipLeaseExpectation, IncarnationId, LeaseAssignment, MediaType, NodeId,
    ObjectDescriptor, ObjectDigest, OwnershipLease, OwnershipLeaseTrustAnchor, PortableMediaType,
    RawPairedClockSample, SandboxId, authenticate_historical_ownership_lease, descriptor_for_bytes,
    verify_ownership_lease, verify_ownership_transaction_receipt_signature,
};
use sha2::{Digest as _, Sha256};

const CLAIM_MAGIC: &[u8; 8] = b"AOSOCLM1";
const CLAIM_VERSION: u16 = 1;
/// Exact byte length of a canonical V1 ownership claim.
pub const CLAIM_BYTES: usize = 176;
const CLAIM_DIGEST_DOMAIN: &[u8] = b"aos-sandbox-ownership-claim-v1\0";
/// Largest lease duration that a portable V1 claim may request.
pub const MAXIMUM_REQUESTED_DURATION_SECONDS: u64 = 86_400;
/// Largest canonical ownership lease accepted from an authority.
pub const MAXIMUM_LEASE_BYTES: usize = 64 * 1024;
/// Largest canonical detached lease signature accepted from an authority.
pub const MAXIMUM_SIGNATURE_BYTES: usize = 64 * 1024;
/// Largest canonical ownership transaction receipt accepted from an authority.
pub const MAXIMUM_RECEIPT_BYTES: usize = 1024;
const RECEIPT_MAGIC: &[u8; 8] = b"AOSOTR1\0";
const RECEIPT_VERSION: u16 = 1;
const RECEIPT_PROTOCOL_CODE: u16 = 1;
const RECEIPT_PROTOCOL_MAJOR: u16 = 1;
const RECEIPT_FIXED_BYTES: usize = 154;

/// Selects acquisition, exact renewal, or a same-owner assignment advance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnershipClaimAction {
    /// Acquires an assignment that has no prior lease in this authority domain.
    Acquire,
    /// Renews exactly the currently fenced lease.
    Renew,
    /// Advances desired assignment semantics on the same node, incarnation, and epoch.
    ///
    /// Protocol 1.1 requires an exact prior lease fence, a strictly greater
    /// desired generation, and a different assignment digest. This is not
    /// ownership transfer and does not admit another node or incarnation.
    Advance,
}

impl OwnershipClaimAction {
    const fn code(self) -> u8 {
        match self {
            Self::Acquire => 1,
            Self::Renew => 2,
            Self::Advance => 3,
        }
    }

    fn from_code(value: u8) -> Result<Self, OwnershipClaimError> {
        match value {
            1 => Ok(Self::Acquire),
            2 => Ok(Self::Renew),
            3 => Ok(Self::Advance),
            _ => Err(OwnershipClaimError::InvalidEncoding),
        }
    }

    /// Returns the earliest protocol version that admits this action.
    #[must_use]
    pub const fn minimum_protocol_version(self) -> aos_sandbox_core::ProtocolVersion {
        aos_sandbox_core::ProtocolVersion::new(
            1,
            match self {
                Self::Acquire | Self::Renew => 0,
                Self::Advance => 1,
            },
        )
    }
}

/// Identifies the exact prior lease a renewal or advancement must replace.
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

/// Carries one canonical linearizable ownership claim.
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

    /// Constructs an exact-fence same-owner assignment advance.
    ///
    /// The authority must compare this proposal with its current signed
    /// transaction: node, sandbox, incarnation, and epoch remain equal;
    /// desired generation strictly increases and assignment digest changes.
    /// The claim alone does not prove those preconditions or grant authority.
    /// A protocol 1.0 session cannot submit or resume this action.
    ///
    /// # Errors
    ///
    /// Returns [`OwnershipClaimError`] for sentinel identities or generations,
    /// an invalid prior fence, or a zero/oversized maximum duration.
    pub fn advance(
        request_id: [u8; 16],
        assignment: LeaseAssignment,
        desired_generation: DesiredGeneration,
        node: NodeId,
        expected_prior: ExpectedOwnershipLease,
        requested_maximum_seconds: u64,
    ) -> Result<Self, OwnershipClaimError> {
        Self::new(
            OwnershipClaimAction::Advance,
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
            OwnershipClaimAction::Renew | OwnershipClaimAction::Advance => Some(
                ExpectedOwnershipLease::new(expected_generation, expected_digest)?,
            ),
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

    /// Returns the immutable ownership transaction action.
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

    /// Returns the exact prior lease required by renewal or advancement.
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

/// Binds one immutable authority operation to its exact issued lease object.
///
/// The receipt is signed with the ownership-authority key under the existing
/// ownership-lease trust policy, but uses its own registered subject media
/// type. It deliberately omits session correlation: Begin, completion, and
/// query may all replay the same durable receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnershipTransactionReceiptV1 {
    authority: KeyReference,
    action: OwnershipClaimAction,
    request_id: [u8; 16],
    claim_digest: ObjectDigest,
    lease_descriptor: ObjectDescriptor,
    canonical_bytes: Vec<u8>,
}

impl OwnershipTransactionReceiptV1 {
    /// Constructs the canonical receipt for a claim and exact lease bytes.
    ///
    /// # Errors
    ///
    /// Returns [`OwnershipReceiptError`] for an invalid authority generation,
    /// unexpected key usage, sentinel fingerprint, or impossible registered
    /// media type.
    pub fn new(
        authority: KeyReference,
        claim: &OwnershipClaimV1,
        canonical_lease: &[u8],
    ) -> Result<Self, OwnershipReceiptError> {
        if authority.generation() == 0
            || authority.public_key_sha256().as_bytes() == &[0; 32]
            || authority.usage() != KeyUsage::OwnershipLease
        {
            return Err(OwnershipReceiptError::InvalidAuthority);
        }
        let lease_media = MediaType::new(PortableMediaType::OwnershipLease.as_str().to_owned())
            .map_err(|_| OwnershipReceiptError::InvalidEncoding)?;
        let lease_descriptor = descriptor_for_bytes(lease_media, canonical_lease);
        let canonical_bytes = encode_receipt(
            &authority,
            claim.action(),
            *claim.request_id(),
            claim.digest(),
            &lease_descriptor,
        );
        if canonical_bytes.len() > MAXIMUM_RECEIPT_BYTES {
            return Err(OwnershipReceiptError::InvalidEncoding);
        }
        Ok(Self {
            authority,
            action: claim.action(),
            request_id: *claim.request_id(),
            claim_digest: claim.digest(),
            lease_descriptor,
            canonical_bytes,
        })
    }

    /// Decodes one exact canonical receipt.
    ///
    /// # Errors
    ///
    /// Returns [`OwnershipReceiptError`] for wrong framing, versions, reserved
    /// bytes, invalid UTF-8 or key identity, unknown action, sentinels,
    /// trailing bytes, or non-canonical encoding.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, OwnershipReceiptError> {
        if bytes.len() > MAXIMUM_RECEIPT_BYTES || bytes.len() < RECEIPT_FIXED_BYTES + 1 {
            return Err(OwnershipReceiptError::InvalidEncoding);
        }
        let mut cursor = 0;
        if receipt_take::<8>(bytes, &mut cursor)? != *RECEIPT_MAGIC
            || u16::from_be_bytes(receipt_take::<2>(bytes, &mut cursor)?) != RECEIPT_VERSION
            || u16::from_be_bytes(receipt_take::<2>(bytes, &mut cursor)?) != RECEIPT_PROTOCOL_CODE
            || u16::from_be_bytes(receipt_take::<2>(bytes, &mut cursor)?) != RECEIPT_PROTOCOL_MAJOR
        {
            return Err(OwnershipReceiptError::InvalidEncoding);
        }
        let protocol_minor = u16::from_be_bytes(receipt_take::<2>(bytes, &mut cursor)?);
        let action = OwnershipClaimAction::from_code(receipt_take::<1>(bytes, &mut cursor)?[0])
            .map_err(|_| OwnershipReceiptError::InvalidEncoding)?;
        if protocol_minor != action.minimum_protocol_version().minor()
            || receipt_take::<7>(bytes, &mut cursor)? != [0; 7]
        {
            return Err(OwnershipReceiptError::InvalidEncoding);
        }
        let key_id_length = usize::from(u16::from_be_bytes(receipt_take::<2>(bytes, &mut cursor)?));
        if key_id_length == 0 || key_id_length > 255 {
            return Err(OwnershipReceiptError::InvalidEncoding);
        }
        let key_id = std::str::from_utf8(receipt_slice(bytes, &mut cursor, key_id_length)?)
            .map_err(|_| OwnershipReceiptError::InvalidEncoding)?;
        let authority = KeyReference::new(
            StableKeyId::new(key_id.to_owned())
                .map_err(|_| OwnershipReceiptError::InvalidEncoding)?,
            u64::from_be_bytes(receipt_take::<8>(bytes, &mut cursor)?),
            ObjectDigest::from_bytes(receipt_take::<32>(bytes, &mut cursor)?),
            KeyUsage::OwnershipLease,
        );
        let request_id = receipt_take::<16>(bytes, &mut cursor)?;
        let claim_digest = ObjectDigest::from_bytes(receipt_take::<32>(bytes, &mut cursor)?);
        let lease_size = u64::from_be_bytes(receipt_take::<8>(bytes, &mut cursor)?);
        let lease_digest = ObjectDigest::from_bytes(receipt_take::<32>(bytes, &mut cursor)?);
        if cursor != bytes.len()
            || authority.generation() == 0
            || authority.public_key_sha256().as_bytes() == &[0; 32]
            || request_id == [0; 16]
            || claim_digest.as_bytes() == &[0; 32]
            || lease_size == 0
            || lease_digest.as_bytes() == &[0; 32]
        {
            return Err(OwnershipReceiptError::InvalidEncoding);
        }
        let lease_descriptor = ObjectDescriptor::new(
            MediaType::new(PortableMediaType::OwnershipLease.as_str().to_owned())
                .map_err(|_| OwnershipReceiptError::InvalidEncoding)?,
            lease_digest,
            lease_size,
        );
        let canonical_bytes = encode_receipt(
            &authority,
            action,
            request_id,
            claim_digest,
            &lease_descriptor,
        );
        if canonical_bytes != bytes {
            return Err(OwnershipReceiptError::InvalidEncoding);
        }
        Ok(Self {
            authority,
            action,
            request_id,
            claim_digest,
            lease_descriptor,
            canonical_bytes,
        })
    }

    /// Verifies every receipt field against a claim, authority, and lease.
    ///
    /// # Errors
    ///
    /// Returns [`OwnershipReceiptError::ContextMismatch`] for any operation,
    /// request, claim, key-generation, or lease-descriptor substitution.
    pub fn verify_context(
        &self,
        authority: &KeyReference,
        claim: &OwnershipClaimV1,
        canonical_lease: &[u8],
    ) -> Result<(), OwnershipReceiptError> {
        let lease_media = MediaType::new(PortableMediaType::OwnershipLease.as_str().to_owned())
            .map_err(|_| OwnershipReceiptError::InvalidEncoding)?;
        if &self.authority != authority
            || self.action != claim.action()
            || self.request_id != *claim.request_id()
            || self.claim_digest != claim.digest()
            || self.lease_descriptor != descriptor_for_bytes(lease_media, canonical_lease)
        {
            return Err(OwnershipReceiptError::ContextMismatch);
        }
        Ok(())
    }

    /// Returns the exact canonical receipt bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    /// Returns the immutable authority key generation named by the receipt.
    #[must_use]
    pub const fn authority(&self) -> &KeyReference {
        &self.authority
    }

    /// Returns the immutable acquire or renew action.
    #[must_use]
    pub const fn action(&self) -> OwnershipClaimAction {
        self.action
    }

    /// Returns the stable idempotency request identity.
    #[must_use]
    pub const fn request_id(&self) -> &[u8; 16] {
        &self.request_id
    }

    /// Returns the domain-separated digest of the complete canonical claim.
    #[must_use]
    pub const fn claim_digest(&self) -> ObjectDigest {
        self.claim_digest
    }

    /// Returns the exact descriptor of the issued canonical lease.
    #[must_use]
    pub const fn lease_descriptor(&self) -> &ObjectDescriptor {
        &self.lease_descriptor
    }
}

/// Reports invalid canonical transaction receipts or context substitution.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum OwnershipReceiptError {
    /// The key is not a nonzero ownership-lease authority generation.
    #[error("ownership transaction receipt authority is invalid")]
    InvalidAuthority,
    /// Framing, registry values, bounds, sentinels, or canonical bytes are invalid.
    #[error("ownership transaction receipt encoding is invalid")]
    InvalidEncoding,
    /// The receipt does not bind the expected authority, claim, action, or lease.
    #[error("ownership transaction receipt context does not match")]
    ContextMismatch,
}

/// Carries exact issuer response bytes without claiming authenticity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnverifiedOwnershipLeaseResponse {
    lease: Vec<u8>,
    signature: Vec<u8>,
    receipt: Vec<u8>,
    receipt_signature: Vec<u8>,
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
        receipt: Vec<u8>,
        receipt_signature: Vec<u8>,
    ) -> Result<Self, OwnershipLeaseAcquisitionError> {
        if lease.is_empty()
            || lease.len() > MAXIMUM_LEASE_BYTES
            || signature.is_empty()
            || signature.len() > MAXIMUM_SIGNATURE_BYTES
            || receipt.is_empty()
            || receipt.len() > MAXIMUM_RECEIPT_BYTES
            || receipt_signature.is_empty()
            || receipt_signature.len() > MAXIMUM_SIGNATURE_BYTES
        {
            return Err(OwnershipLeaseAcquisitionError::InvalidIssuerResponse);
        }
        Ok(Self {
            lease,
            signature,
            receipt,
            receipt_signature,
        })
    }

    /// Returns the exact unverified canonical lease bytes.
    #[must_use]
    pub fn lease(&self) -> &[u8] {
        &self.lease
    }

    /// Returns the exact unverified canonical signature bytes.
    #[must_use]
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// Returns the exact unverified canonical transaction receipt bytes.
    #[must_use]
    pub fn receipt(&self) -> &[u8] {
        &self.receipt
    }

    /// Returns the exact unverified canonical receipt signature bytes.
    #[must_use]
    pub fn receipt_signature(&self) -> &[u8] {
        &self.receipt_signature
    }
}

/// Acquires ownership through a linearizable authority transaction.
///
/// Implementations must bind `request_id` to the complete claim digest. Exact
/// replay returns the original response; reuse with different bytes fails.
/// Acquire is expected-absence CAS. Renewal and same-owner advancement are
/// exact generation/digest CAS with distinct semantic transition rules.
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

    /// Advances assignment semantics without changing the exclusive owner.
    ///
    /// Exact generation/digest CAS is mandatory. Node, sandbox, incarnation,
    /// and assignment epoch must remain equal, desired generation must increase,
    /// and assignment digest must change. The issued lease generation must
    /// advance. This method cannot implement migration or reuse renewal to
    /// bypass its unchanged-semantics contract. Exact replay returns the
    /// original four artifacts, including the protocol 1.1 receipt.
    ///
    /// # Errors
    ///
    /// Returns [`OwnershipAuthorityError`] for stale or invalid prior state,
    /// idempotency misuse, unavailable linearizable state, or transport failure.
    fn advance(
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
    /// Renewal or advancement did not match the exact prior state and transition.
    #[error("ownership compare-and-swap fence is stale")]
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

    /// Returns the exact pinned ownership-authority key generation.
    #[must_use]
    pub const fn authority(&self) -> &KeyReference {
        &self.authority
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

    /// Performs same-owner assignment advancement and verifies its artifacts.
    ///
    /// The authority enforces the prior-state transition; this method verifies
    /// that the response signs exactly the proposed claim and a newer lease.
    ///
    /// # Errors
    ///
    /// Returns [`OwnershipLeaseAcquisitionError`] for a wrong action, authority
    /// failure, invalid signatures or context, expiry, excessive interval, or
    /// non-advancing lease generation.
    pub fn advance<A: OwnershipAuthority>(
        &self,
        authority: &mut A,
        claim: &OwnershipClaimV1,
        clock: &RawPairedClockSample,
    ) -> Result<SignedOwnershipLease, OwnershipLeaseAcquisitionError> {
        if claim.action != OwnershipClaimAction::Advance {
            return Err(OwnershipLeaseAcquisitionError::WrongClaimAction);
        }
        let response = authority.advance(claim)?;
        self.verify_response(claim, response, clock)
    }

    /// Verifies exact transport bytes against a claim and caller-supplied clock sample.
    ///
    /// This is the verifier entry point for a durable transaction manager that
    /// separates intent persistence from issuer contact.
    ///
    /// # Errors
    ///
    /// Returns [`OwnershipLeaseAcquisitionError`] for malformed or forged
    /// response bytes, context substitution, expiry, excessive duration, or a
    /// non-advancing renewal generation.
    pub fn verify_response(
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
        validate_verified_response(claim, verified.lease())?;

        let receipt = OwnershipTransactionReceiptV1::from_canonical_bytes(&response.receipt)
            .map_err(|_| OwnershipLeaseAcquisitionError::InvalidIssuerResponse)?;
        receipt
            .verify_context(&self.authority, claim, &response.lease)
            .map_err(|_| OwnershipLeaseAcquisitionError::InvalidIssuerResponse)?;
        let receipt_signature = decode_signature(&response.receipt_signature, response_limits())
            .map_err(|_| OwnershipLeaseAcquisitionError::InvalidIssuerResponse)?;
        if encode_signature(&receipt_signature) != response.receipt_signature {
            return Err(OwnershipLeaseAcquisitionError::InvalidIssuerResponse);
        }
        verify_ownership_transaction_receipt_signature(
            receipt.canonical_bytes(),
            &receipt_signature,
            &self.anchor,
            verified.lease().authority_issued_seconds(),
            verified.lease().authority_expires_seconds(),
            clock.wall_seconds(),
            response_limits(),
        )
        .map_err(|_| OwnershipLeaseAcquisitionError::InvalidIssuerResponse)?;

        Ok(SignedOwnershipLease {
            canonical_lease: response.lease,
            canonical_signature: response.signature,
            canonical_receipt: response.receipt,
            canonical_receipt_signature: response.receipt_signature,
            generation: verified.lease().lease_generation(),
            digest: verified.lease_digest(),
            assignment: verified.lease().assignment(),
            desired_generation: claim.desired_generation(),
            node: verified.lease().node(),
            authority_issued_seconds: verified.lease().authority_issued_seconds(),
            authority_expires_seconds: verified.lease().authority_expires_seconds(),
            maximum_clock_skew_seconds: verified.lease().maximum_clock_skew_seconds(),
            renewal_nonce: *verified.lease().renewal_nonce(),
            signer: signature.statement().signer().clone(),
        })
    }

    /// Authenticates a response at an integrity-protected historical instant.
    ///
    /// This reconstructs a state-machine result, not present execution
    /// authority. Callers must still perform effect-boundary verification with
    /// a protected clock before using the returned artifacts for an effect.
    ///
    /// # Errors
    ///
    /// Returns [`OwnershipLeaseAcquisitionError::InvalidIssuerResponse`] when
    /// the response, signature, authority generation, claim binding, recorded
    /// generation or digest, historical validity, or duration is invalid.
    pub fn authenticate_historical_response(
        &self,
        claim: &OwnershipClaimV1,
        response: UnverifiedOwnershipLeaseResponse,
        accepted_wall_seconds: i64,
        expected_generation: u64,
        expected_digest: ObjectDigest,
    ) -> Result<RecoveredOwnershipLease, OwnershipLeaseAcquisitionError> {
        let proof = authenticate_historical_ownership_lease(
            &response.lease,
            &response.signature,
            &self.anchor,
            HistoricalOwnershipLeaseExpectation {
                assignment: claim.broker_assignment()?,
                node: claim.node(),
                ownership_authority: &self.authority,
                lease_generation: expected_generation,
                lease_digest: expected_digest,
                accepted_at: DurableHistoricalWallClockInstant::from_authenticated_record(
                    accepted_wall_seconds,
                ),
            },
            response_limits(),
        )
        .map_err(|_| OwnershipLeaseAcquisitionError::InvalidIssuerResponse)?;
        validate_verified_response(claim, proof.lease())?;

        let receipt = OwnershipTransactionReceiptV1::from_canonical_bytes(&response.receipt)
            .map_err(|_| OwnershipLeaseAcquisitionError::InvalidIssuerResponse)?;
        receipt
            .verify_context(&self.authority, claim, &response.lease)
            .map_err(|_| OwnershipLeaseAcquisitionError::InvalidIssuerResponse)?;
        let receipt_signature = decode_signature(&response.receipt_signature, response_limits())
            .map_err(|_| OwnershipLeaseAcquisitionError::InvalidIssuerResponse)?;
        if encode_signature(&receipt_signature) != response.receipt_signature {
            return Err(OwnershipLeaseAcquisitionError::InvalidIssuerResponse);
        }
        verify_ownership_transaction_receipt_signature(
            receipt.canonical_bytes(),
            &receipt_signature,
            &self.anchor,
            proof.lease().authority_issued_seconds(),
            proof.lease().authority_expires_seconds(),
            accepted_wall_seconds,
            response_limits(),
        )
        .map_err(|_| OwnershipLeaseAcquisitionError::InvalidIssuerResponse)?;

        Ok(RecoveredOwnershipLease {
            canonical_lease: response.lease,
            canonical_signature: response.signature,
            canonical_receipt: response.receipt,
            canonical_receipt_signature: response.receipt_signature,
            generation: proof.lease().lease_generation(),
            digest: proof.lease_digest(),
            assignment: proof.lease().assignment(),
            desired_generation: claim.desired_generation(),
            node: proof.lease().node(),
            authority_issued_seconds: proof.lease().authority_issued_seconds(),
            authority_expires_seconds: proof.lease().authority_expires_seconds(),
            maximum_clock_skew_seconds: proof.lease().maximum_clock_skew_seconds(),
            renewal_nonce: *proof.lease().renewal_nonce(),
            signer: proof.authority().clone(),
        })
    }
}

/// Owns authenticated issuer artifacts checked against a caller-supplied clock sample.
///
/// The sample is not a protected clock capability, so this type does not by
/// itself authorize an effect. Effect boundaries must perform their own
/// protected-clock, assignment, policy, and broker checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedOwnershipLease {
    canonical_lease: Vec<u8>,
    canonical_signature: Vec<u8>,
    canonical_receipt: Vec<u8>,
    canonical_receipt_signature: Vec<u8>,
    generation: u64,
    digest: ObjectDigest,
    assignment: LeaseAssignment,
    desired_generation: DesiredGeneration,
    node: NodeId,
    authority_issued_seconds: i64,
    authority_expires_seconds: i64,
    maximum_clock_skew_seconds: u64,
    renewal_nonce: [u8; 16],
    signer: KeyReference,
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

    /// Returns exact canonical ownership-transaction receipt bytes.
    #[must_use]
    pub fn canonical_receipt(&self) -> &[u8] {
        &self.canonical_receipt
    }

    /// Returns exact canonical detached receipt-signature bytes.
    #[must_use]
    pub fn canonical_receipt_signature(&self) -> &[u8] {
        &self.canonical_receipt_signature
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

    /// Returns the desired generation authenticated by the signed claim receipt.
    #[must_use]
    pub const fn desired_generation(&self) -> DesiredGeneration {
        self.desired_generation
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

    /// Reconstructs the exact four issuer artifacts for transport or persistence.
    #[must_use]
    pub fn exact_response(&self) -> UnverifiedOwnershipLeaseResponse {
        UnverifiedOwnershipLeaseResponse {
            lease: self.canonical_lease.clone(),
            signature: self.canonical_signature.clone(),
            receipt: self.canonical_receipt.clone(),
            receipt_signature: self.canonical_receipt_signature.clone(),
        }
    }

    /// Converts authenticated artifacts to the explicitly non-authorizing durable form.
    #[must_use]
    pub fn into_recovered(self) -> RecoveredOwnershipLease {
        RecoveredOwnershipLease {
            canonical_lease: self.canonical_lease,
            canonical_signature: self.canonical_signature,
            canonical_receipt: self.canonical_receipt,
            canonical_receipt_signature: self.canonical_receipt_signature,
            generation: self.generation,
            digest: self.digest,
            assignment: self.assignment,
            desired_generation: self.desired_generation,
            node: self.node,
            authority_issued_seconds: self.authority_issued_seconds,
            authority_expires_seconds: self.authority_expires_seconds,
            maximum_clock_skew_seconds: self.maximum_clock_skew_seconds,
            renewal_nonce: self.renewal_nonce,
            signer: self.signer,
        }
    }
}

/// Owns authenticated historical artifacts without conveying present authority.
///
/// This type is intentionally nominally distinct from [`SignedOwnershipLease`].
/// It may describe an expired completion recovered from durable state and has
/// no conversion into an effect-authorizing capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveredOwnershipLease {
    canonical_lease: Vec<u8>,
    canonical_signature: Vec<u8>,
    canonical_receipt: Vec<u8>,
    canonical_receipt_signature: Vec<u8>,
    generation: u64,
    digest: ObjectDigest,
    assignment: LeaseAssignment,
    desired_generation: DesiredGeneration,
    node: NodeId,
    authority_issued_seconds: i64,
    authority_expires_seconds: i64,
    maximum_clock_skew_seconds: u64,
    renewal_nonce: [u8; 16],
    signer: KeyReference,
}

impl RecoveredOwnershipLease {
    /// Returns the exact four issuer artifacts.
    #[must_use]
    pub fn exact_response(&self) -> UnverifiedOwnershipLeaseResponse {
        UnverifiedOwnershipLeaseResponse {
            lease: self.canonical_lease.clone(),
            signature: self.canonical_signature.clone(),
            receipt: self.canonical_receipt.clone(),
            receipt_signature: self.canonical_receipt_signature.clone(),
        }
    }

    /// Returns exact canonical ownership-lease bytes.
    #[must_use]
    pub fn canonical_lease(&self) -> &[u8] {
        &self.canonical_lease
    }
    /// Returns exact canonical detached lease-signature bytes.
    #[must_use]
    pub fn canonical_signature(&self) -> &[u8] {
        &self.canonical_signature
    }
    /// Returns exact canonical ownership-transaction receipt bytes.
    #[must_use]
    pub fn canonical_receipt(&self) -> &[u8] {
        &self.canonical_receipt
    }
    /// Returns exact canonical detached receipt-signature bytes.
    #[must_use]
    pub fn canonical_receipt_signature(&self) -> &[u8] {
        &self.canonical_receipt_signature
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
    /// Returns the desired generation authenticated by the historical receipt.
    #[must_use]
    pub const fn desired_generation(&self) -> DesiredGeneration {
        self.desired_generation
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
    /// Returns the exact ownership-authority key generation that signed the artifacts.
    #[must_use]
    pub const fn signer(&self) -> &KeyReference {
        &self.signer
    }
    /// Returns the exact fence required by a subsequent renewal.
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
    lease: &OwnershipLease,
) -> Result<(), OwnershipLeaseAcquisitionError> {
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

fn encode_receipt(
    authority: &KeyReference,
    action: OwnershipClaimAction,
    request_id: [u8; 16],
    claim_digest: ObjectDigest,
    lease_descriptor: &ObjectDescriptor,
) -> Vec<u8> {
    let key_id = authority.stable_key_id().as_str().as_bytes();
    let mut bytes = Vec::with_capacity(RECEIPT_FIXED_BYTES + key_id.len());
    bytes.extend_from_slice(RECEIPT_MAGIC);
    bytes.extend_from_slice(&RECEIPT_VERSION.to_be_bytes());
    bytes.extend_from_slice(&RECEIPT_PROTOCOL_CODE.to_be_bytes());
    bytes.extend_from_slice(&RECEIPT_PROTOCOL_MAJOR.to_be_bytes());
    bytes.extend_from_slice(&action.minimum_protocol_version().minor().to_be_bytes());
    bytes.push(action.code());
    bytes.extend_from_slice(&[0; 7]);
    bytes.extend_from_slice(&(key_id.len() as u16).to_be_bytes());
    bytes.extend_from_slice(key_id);
    bytes.extend_from_slice(&authority.generation().to_be_bytes());
    bytes.extend_from_slice(authority.public_key_sha256().as_bytes());
    bytes.extend_from_slice(&request_id);
    bytes.extend_from_slice(claim_digest.as_bytes());
    bytes.extend_from_slice(&lease_descriptor.encoded_size().to_be_bytes());
    bytes.extend_from_slice(lease_descriptor.digest().as_bytes());
    bytes
}

fn receipt_take<const N: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], OwnershipReceiptError> {
    receipt_slice(bytes, cursor, N)?
        .try_into()
        .map_err(|_| OwnershipReceiptError::InvalidEncoding)
}

fn receipt_slice<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    length: usize,
) -> Result<&'a [u8], OwnershipReceiptError> {
    let end = cursor
        .checked_add(length)
        .ok_or(OwnershipReceiptError::InvalidEncoding)?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(OwnershipReceiptError::InvalidEncoding)?;
    *cursor = end;
    Ok(value)
}

//! Signed ownership leases and node-local fail-stop deadline derivation.
//!
//! Portable leases contain authority-wall-clock facts only. After signature
//! verification, a node subtracts the declared maximum skew and the fixed v1
//! safety margin from the remaining authority interval, converts that duration
//! to a local `CLOCK_BOOTTIME` deadline, and persists [`LocalLeaseRecord`]. A
//! reboot invalidates that record. [`BrokerAdmissionIntersection`] is
//! deliberately non-authorizing because this effect-free crate cannot attest
//! that the receiving broker atomically persisted and consumed a request.

use crate::broker_authorization::{
    BrokerAssignment, BrokerGrantTarget, BrokerVerb, MatchedBrokerRequest,
};
use crate::format::{
    CanonicalCborError, DecodeLimits, decode_ownership_lease, decode_trust_policy,
    descriptor_for_bytes,
};
use crate::model::{KeyReference, KeyUsage, Signature, SignaturePurpose};
use crate::{
    AssignmentEpoch, IncarnationId, NodeId, ObjectDescriptor, ObjectDigest, RegistryError,
    SandboxId, SignatureVerificationError, TrustScopeId, verify_signature,
};

/// Fixed v1 guard removed from every locally derived lease duration.
pub const LEASE_SAFETY_MARGIN_SECONDS: u64 = 5;
/// Maximum v1 disagreement between elapsed wall time and `CLOCK_BOOTTIME`.
pub const CLOCK_PAIR_TOLERANCE_NANOSECONDS: u64 = 2_000_000_000;
const NANOSECONDS_PER_SECOND: u64 = 1_000_000_000;

/// Labels an untrusted paired-clock reader configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawClockProvenance([u8; 16]);

impl RawClockProvenance {
    /// Labels the source of a raw, explicitly non-authorizing clock reading.
    ///
    /// # Errors
    ///
    /// Returns [`OwnershipLeaseVerificationError::InvalidClockSample`] for the
    /// reserved zero identity.
    pub fn new_untrusted(identity: [u8; 16]) -> Result<Self, OwnershipLeaseVerificationError> {
        if identity == [0; 16] {
            Err(OwnershipLeaseVerificationError::InvalidClockSample)
        } else {
            Ok(Self(identity))
        }
    }

    /// Returns the stable reader-configuration identity.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 16] {
        self.0
    }
}

/// Pairs caller-supplied wall time with BOOTTIME and host boot identity.
///
/// This public raw type claims no production trust. A platform broker must
/// create it directly from one protected adapter read and must not accept its
/// fields from an RPC peer. Private fields prevent replacement after creation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawPairedClockSample {
    provenance: RawClockProvenance,
    host_boot_id: [u8; 16],
    wall_seconds: i64,
    boottime_nanoseconds: u64,
}

impl RawPairedClockSample {
    /// Constructs one raw, explicitly non-authorizing paired-clock observation.
    ///
    /// # Errors
    ///
    /// Returns [`OwnershipLeaseVerificationError::InvalidClockSample`] for a
    /// zero boot identity.
    pub fn new_untrusted(
        provenance: RawClockProvenance,
        host_boot_id: [u8; 16],
        wall_seconds: i64,
        boottime_nanoseconds: u64,
    ) -> Result<Self, OwnershipLeaseVerificationError> {
        if host_boot_id == [0; 16] {
            return Err(OwnershipLeaseVerificationError::InvalidClockSample);
        }
        Ok(Self {
            provenance,
            host_boot_id,
            wall_seconds,
            boottime_nanoseconds,
        })
    }

    /// Returns the reader configuration that produced this paired sample.
    #[must_use]
    pub const fn provenance(self) -> RawClockProvenance {
        self.provenance
    }

    /// Returns the host boot identity paired with both clocks.
    #[must_use]
    pub const fn host_boot_id(self) -> [u8; 16] {
        self.host_boot_id
    }
    /// Returns the paired Unix wall-clock second.
    #[must_use]
    pub const fn wall_seconds(self) -> i64 {
        self.wall_seconds
    }
    /// Returns the paired `CLOCK_BOOTTIME` nanoseconds.
    #[must_use]
    pub const fn boottime_nanoseconds(self) -> u64 {
        self.boottime_nanoseconds
    }
}

/// Identifies assignment semantics retained across lease renewal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LeaseAssignment {
    sandbox: SandboxId,
    incarnation: IncarnationId,
    epoch: AssignmentEpoch,
    digest: ObjectDigest,
}

impl LeaseAssignment {
    /// Constructs a non-sentinel lease assignment.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidOwnershipLease::Unspecified`] for any zero identity,
    /// epoch, or digest.
    pub fn new(
        sandbox: SandboxId,
        incarnation: IncarnationId,
        epoch: AssignmentEpoch,
        digest: ObjectDigest,
    ) -> Result<Self, InvalidOwnershipLease> {
        if sandbox.as_bytes() == &[0; 16]
            || incarnation.as_bytes() == &[0; 16]
            || epoch.get() == 0
            || digest.as_bytes() == &[0; 32]
        {
            return Err(InvalidOwnershipLease::Unspecified);
        }
        Ok(Self {
            sandbox,
            incarnation,
            epoch,
            digest,
        })
    }

    /// Returns the logical sandbox.
    #[must_use]
    pub const fn sandbox(self) -> SandboxId {
        self.sandbox
    }
    /// Returns the runtime incarnation.
    #[must_use]
    pub const fn incarnation(self) -> IncarnationId {
        self.incarnation
    }
    /// Returns the assignment epoch.
    #[must_use]
    pub const fn epoch(self) -> AssignmentEpoch {
        self.epoch
    }
    /// Returns the immutable assignment digest.
    #[must_use]
    pub const fn digest(self) -> ObjectDigest {
        self.digest
    }

    fn matches_broker_assignment(self, assignment: BrokerAssignment) -> bool {
        self.sandbox == assignment.sandbox()
            && self.incarnation == assignment.incarnation()
            && self.epoch == assignment.epoch()
            && self.digest == assignment.digest()
    }
}

/// Stores one canonical authority-wall-clock ownership lease.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnershipLease {
    assignment: LeaseAssignment,
    node: NodeId,
    lease_generation: u64,
    authority_issued_seconds: i64,
    authority_expires_seconds: i64,
    maximum_clock_skew_seconds: u64,
    renewal_nonce: [u8; 16],
}

/// Reports malformed ownership lease semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InvalidOwnershipLease {
    /// A required identity, generation, digest, or nonce is a sentinel.
    #[error("ownership lease contains an unspecified identity or generation")]
    Unspecified,
    /// The interval cannot contain its declared skew and safety guard.
    #[error("ownership lease has an invalid authority interval")]
    InvalidInterval,
}

impl OwnershipLease {
    /// Constructs a complete portable ownership lease.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidOwnershipLease`] for sentinels or a validity interval
    /// too short for maximum skew plus the fixed safety margin.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        assignment: LeaseAssignment,
        node: NodeId,
        lease_generation: u64,
        authority_issued_seconds: i64,
        authority_expires_seconds: i64,
        maximum_clock_skew_seconds: u64,
        renewal_nonce: [u8; 16],
    ) -> Result<Self, InvalidOwnershipLease> {
        if node.as_bytes() == &[0; 16] || lease_generation == 0 || renewal_nonce == [0; 16] {
            return Err(InvalidOwnershipLease::Unspecified);
        }
        let guard = maximum_clock_skew_seconds
            .checked_add(LEASE_SAFETY_MARGIN_SECONDS)
            .and_then(|value| i64::try_from(value).ok())
            .ok_or(InvalidOwnershipLease::InvalidInterval)?;
        if authority_expires_seconds
            .checked_sub(authority_issued_seconds)
            .is_none_or(|duration| duration <= guard)
        {
            return Err(InvalidOwnershipLease::InvalidInterval);
        }
        Ok(Self {
            assignment,
            node,
            lease_generation,
            authority_issued_seconds,
            authority_expires_seconds,
            maximum_clock_skew_seconds,
            renewal_nonce,
        })
    }

    /// Returns the immutable assignment semantics.
    #[must_use]
    pub const fn assignment(&self) -> LeaseAssignment {
        self.assignment
    }
    /// Returns the owning node.
    #[must_use]
    pub const fn node(&self) -> NodeId {
        self.node
    }
    /// Returns the monotonic lease generation.
    #[must_use]
    pub const fn lease_generation(&self) -> u64 {
        self.lease_generation
    }
    /// Returns the inclusive authority issue second.
    #[must_use]
    pub const fn authority_issued_seconds(&self) -> i64 {
        self.authority_issued_seconds
    }
    /// Returns the exclusive authority expiry second.
    #[must_use]
    pub const fn authority_expires_seconds(&self) -> i64 {
        self.authority_expires_seconds
    }
    /// Returns the maximum admitted authority-clock skew.
    #[must_use]
    pub const fn maximum_clock_skew_seconds(&self) -> u64 {
        self.maximum_clock_skew_seconds
    }
    /// Returns the renewal nonce.
    #[must_use]
    pub const fn renewal_nonce(&self) -> &[u8; 16] {
        &self.renewal_nonce
    }
}

/// Pins the exact ownership-authority trust generation.
#[derive(Debug)]
pub struct OwnershipLeaseTrustAnchor {
    canonical_policy: Vec<u8>,
    policy_descriptor: ObjectDescriptor,
    trust_scope: TrustScopeId,
    authority: KeyReference,
    public_key: [u8; 32],
}

impl OwnershipLeaseTrustAnchor {
    /// Constructs an anchor from protected local configuration.
    ///
    /// # Errors
    ///
    /// Returns [`OwnershipLeaseVerificationError::InvalidTrustAnchor`] unless
    /// policy bytes, descriptor, scope, purpose, key, and fingerprint agree.
    pub fn from_trusted_configuration(
        canonical_policy: Vec<u8>,
        policy_descriptor: ObjectDescriptor,
        trust_scope: TrustScopeId,
        authority: KeyReference,
        public_key: [u8; 32],
        limits: DecodeLimits,
    ) -> Result<Self, OwnershipLeaseVerificationError> {
        use sha2::{Digest as _, Sha256};

        let policy = decode_trust_policy(&canonical_policy, limits)?;
        crate::validate_required_features(policy.required_features())?;
        crate::validate_descriptor_role(
            crate::DescriptorRole::SignatureVerificationPolicy,
            &policy_descriptor,
        )?;
        let computed =
            descriptor_for_bytes(policy_descriptor.media_type().clone(), &canonical_policy);
        if computed != policy_descriptor
            || policy.trust_scope() != trust_scope
            || policy.purpose() != SignaturePurpose::OwnershipLease
            || !policy.allowed_keys().contains(&authority)
            || authority.usage() != KeyUsage::OwnershipLease
            || authority.generation() == 0
            || authority.public_key_sha256()
                != ObjectDigest::from_bytes(Sha256::digest(public_key).into())
        {
            return Err(OwnershipLeaseVerificationError::InvalidTrustAnchor);
        }
        Ok(Self {
            canonical_policy,
            policy_descriptor,
            trust_scope,
            authority,
            public_key,
        })
    }
}

/// Supplies local facts signed lease authority must match.
///
/// The raw clock sample carries no trust claim. Production brokers must source
/// it directly from their protected platform adapter, never request bytes.
#[derive(Clone, Copy, Debug)]
pub struct OwnershipLeaseExpectation<'a> {
    /// Assignment already accepted by the broker session.
    pub assignment: BrokerAssignment,
    /// Local node identity.
    pub node: NodeId,
    /// Authority generation committed by the verified plan.
    pub ownership_authority: &'a KeyReference,
    /// Atomic wall/BOOTTIME/boot observation from the trusted clock adapter.
    pub clock: &'a RawPairedClockSample,
}

/// Identifies a wall-clock instant recovered from authenticated durable state.
///
/// Construction does not authenticate the instant. The caller must only use a
/// value that was committed with, and integrity-bound to, the historical
/// authority record being recovered. This type deliberately carries no
/// BOOTTIME or current-liveness claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurableHistoricalWallClockInstant {
    wall_seconds: i64,
}

impl DurableHistoricalWallClockInstant {
    /// Marks a wall-clock second obtained from an authenticated durable record.
    ///
    /// The caller is responsible for establishing the record's authenticity
    /// before construction. This function performs no clock or provenance
    /// validation and its result grants no live authority.
    #[must_use]
    pub const fn from_authenticated_record(wall_seconds: i64) -> Self {
        Self { wall_seconds }
    }

    /// Returns the historical Unix second.
    #[must_use]
    pub const fn wall_seconds(self) -> i64 {
        self.wall_seconds
    }
}

/// Supplies exact durable context for historical lease authentication.
#[derive(Clone, Copy, Debug)]
pub struct HistoricalOwnershipLeaseExpectation<'a> {
    /// Assignment recorded by the durable authority state machine.
    pub assignment: BrokerAssignment,
    /// Node recorded by the durable authority state machine.
    pub node: NodeId,
    /// Exact authority key generation recorded for the lease.
    pub ownership_authority: &'a KeyReference,
    /// Exact monotonic lease generation recorded for this chain entry.
    pub lease_generation: u64,
    /// Exact canonical lease digest recorded for this chain entry.
    pub lease_digest: ObjectDigest,
    /// Authenticated historical instant at which the lease was accepted.
    pub accepted_at: DurableHistoricalWallClockInstant,
}

/// Reports lease verification, local fencing, or intersection failure.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum OwnershipLeaseVerificationError {
    /// Canonical lease or trust-policy decoding failed.
    #[error("invalid canonical ownership authority object: {0}")]
    Canonical(#[from] CanonicalCborError),
    /// Detached signature verification failed.
    #[error("ownership lease signature verification failed: {0}")]
    Signature(#[from] SignatureVerificationError),
    /// Registry validation failed.
    #[error("ownership lease registry validation failed: {0}")]
    Registry(#[from] RegistryError),
    /// Protected trust configuration is inconsistent.
    #[error("invalid ownership lease trust anchor")]
    InvalidTrustAnchor,
    /// Signature statement does not bind the lease bytes and validity.
    #[error("ownership lease signature statement does not match the lease")]
    SignatureStatementMismatch,
    /// Assignment, node, or authority key was substituted.
    #[error("ownership lease does not match broker authority context")]
    ContextMismatch,
    /// Conservative authority-wall-clock validation found no live interval.
    #[error("ownership lease is not conservatively live")]
    AuthorityExpired,
    /// BOOTTIME deadline arithmetic overflowed.
    #[error("ownership lease local deadline overflowed")]
    DeadlineOverflow,
    /// A lower lease generation was presented.
    #[error("ownership lease generation is stale")]
    StaleLease,
    /// Equal generation carries different signed semantics.
    #[error("equal ownership lease generation carries conflicting semantics")]
    LeaseEquivocation,
    /// Renewal changed immutable assignment semantics.
    #[error("ownership lease renewal changed assignment semantics")]
    RenewalAssignmentMismatch,
    /// A local deadline belongs to another host boot.
    #[error("local ownership lease record belongs to another host boot")]
    BootMismatch,
    /// The local BOOTTIME deadline is no longer current.
    #[error("local ownership lease BOOTTIME deadline is not current")]
    LocalDeadlineExpired,
    /// The broker plan is no longer current.
    #[error("broker authorization plan is no longer current")]
    PlanExpired,
    /// Request identity or digest is unspecified or mismatched.
    #[error("broker request identity or digest does not match")]
    RequestMismatch,
    /// The supplied local record is not the exact verified lease fence.
    #[error("local lease record does not match the verified lease")]
    LocalRecordMismatch,
    /// A paired-clock sample carries a reserved identity.
    #[error("paired clock sample is invalid")]
    InvalidClockSample,
    /// A later sample comes from another adapter provenance or host boot.
    #[error("paired clock provenance or boot identity changed")]
    ClockProvenanceMismatch,
    /// Either clock moved backwards relative to signature verification.
    #[error("paired wall or BOOTTIME clock moved backwards")]
    ClockRollback,
    /// Paired elapsed wall time and BOOTTIME diverged beyond the v1 tolerance.
    #[error("paired wall and BOOTTIME clocks diverged")]
    ClockDivergence,
    /// Durable historical context does not match the canonical lease record.
    #[error("historical ownership lease does not match its durable record")]
    HistoricalRecordMismatch,
    /// The historical instant's full skew envelope is outside signed validity.
    #[error("historical ownership lease was not skew-safely valid at its acceptance instant")]
    HistoricalInstantOutsideSafeValidity,
}

/// Proves a lease signature and liveness relative to a supplied raw clock.
///
/// This type is intentionally not `Clone` and is not effect authority; the
/// caller remains responsible for the platform provenance of the raw sample.
#[derive(Debug)]
pub struct VerifiedOwnershipLease {
    lease: OwnershipLease,
    authority: KeyReference,
    lease_digest: ObjectDigest,
    verification_clock: RawPairedClockSample,
}

/// Proves only that a lease was authentic at one durable historical instant.
///
/// This proof can rebuild an authority state-machine history after restart. It
/// is intentionally a different type from [`VerifiedOwnershipLease`], carries
/// no BOOTTIME deadline, and must never authorize current broker admission or
/// effects. The trust theorem assumes [`DurableHistoricalWallClockInstant`]
/// came from a previously authenticated durable record bound to these exact
/// lease and signature bytes.
///
/// ```compile_fail
/// use aos_sandbox_core::{
///     NonAuthorizingHistoricalOwnershipLease, RawPairedClockSample,
///     prepare_local_lease_record,
/// };
///
/// fn recover_only(
///     proof: &NonAuthorizingHistoricalOwnershipLease,
///     clock: &RawPairedClockSample,
/// ) {
///     let _ = prepare_local_lease_record(None, proof, clock);
/// }
/// ```
#[derive(Debug)]
pub struct NonAuthorizingHistoricalOwnershipLease {
    lease: OwnershipLease,
    authority: KeyReference,
    lease_digest: ObjectDigest,
    accepted_at: DurableHistoricalWallClockInstant,
    canonical_lease: Vec<u8>,
    canonical_signature: Vec<u8>,
}

impl NonAuthorizingHistoricalOwnershipLease {
    /// Returns the historically authenticated lease semantics.
    #[must_use]
    pub const fn lease(&self) -> &OwnershipLease {
        &self.lease
    }

    /// Returns the exact historical authority key generation.
    #[must_use]
    pub const fn authority(&self) -> &KeyReference {
        &self.authority
    }

    /// Returns the descriptor digest of the exact canonical lease bytes.
    #[must_use]
    pub const fn lease_digest(&self) -> ObjectDigest {
        self.lease_digest
    }

    /// Returns the authenticated historical acceptance instant.
    #[must_use]
    pub const fn accepted_at(&self) -> DurableHistoricalWallClockInstant {
        self.accepted_at
    }

    /// Returns the exact canonical ownership-lease bytes.
    #[must_use]
    pub fn canonical_lease(&self) -> &[u8] {
        &self.canonical_lease
    }

    /// Returns the exact canonical detached-signature bytes.
    #[must_use]
    pub fn canonical_signature(&self) -> &[u8] {
        &self.canonical_signature
    }
}

impl VerifiedOwnershipLease {
    /// Returns the authenticated lease.
    #[must_use]
    pub const fn lease(&self) -> &OwnershipLease {
        &self.lease
    }
    /// Returns the exact authenticated authority generation.
    #[must_use]
    pub const fn authority(&self) -> &KeyReference {
        &self.authority
    }
    /// Returns the exact signed lease digest.
    #[must_use]
    pub const fn lease_digest(&self) -> ObjectDigest {
        self.lease_digest
    }
}

/// Verifies canonical lease bytes and detached authority signature.
///
/// # Errors
///
/// Rejects any signature, authority, assignment, node, or conservative
/// authority-wall-clock mismatch.
pub fn verify_ownership_lease(
    canonical_lease: &[u8],
    signature: &Signature,
    anchor: &OwnershipLeaseTrustAnchor,
    expectation: OwnershipLeaseExpectation<'_>,
    limits: DecodeLimits,
) -> Result<VerifiedOwnershipLease, OwnershipLeaseVerificationError> {
    let lease = decode_ownership_lease(canonical_lease, limits)?;
    let descriptor = descriptor_for_bytes(
        crate::MediaType::new(crate::PortableMediaType::OwnershipLease.as_str().to_owned())
            .map_err(|error| CanonicalCborError::InvalidSemantics {
                object: "ownership lease media type",
                message: error.to_string(),
            })?,
        canonical_lease,
    );
    let statement = signature.statement();
    if statement.subject() != &descriptor
        || statement.purpose() != SignaturePurpose::OwnershipLease
        || statement.signer() != &anchor.authority
        || statement.verification_policy() != &anchor.policy_descriptor
        || statement.trust_scope() != anchor.trust_scope
        || statement.issued_seconds() != lease.authority_issued_seconds()
        || statement.expires_seconds() != Some(lease.authority_expires_seconds())
    {
        return Err(OwnershipLeaseVerificationError::SignatureStatementMismatch);
    }
    verify_signature(
        signature,
        &anchor.canonical_policy,
        &anchor.public_key,
        expectation.clock.wall_seconds,
        limits,
    )?;
    if !lease
        .assignment()
        .matches_broker_assignment(expectation.assignment)
        || lease.node() != expectation.node
        || statement.signer() != expectation.ownership_authority
    {
        return Err(OwnershipLeaseVerificationError::ContextMismatch);
    }
    let skew = i64::try_from(lease.maximum_clock_skew_seconds())
        .map_err(|_| OwnershipLeaseVerificationError::AuthorityExpired)?;
    let earliest = expectation
        .clock
        .wall_seconds
        .checked_sub(skew)
        .ok_or(OwnershipLeaseVerificationError::AuthorityExpired)?;
    let latest = expectation
        .clock
        .wall_seconds
        .checked_add(skew)
        .ok_or(OwnershipLeaseVerificationError::AuthorityExpired)?;
    if earliest < lease.authority_issued_seconds() || latest >= lease.authority_expires_seconds() {
        return Err(OwnershipLeaseVerificationError::AuthorityExpired);
    }
    Ok(VerifiedOwnershipLease {
        lease,
        authority: anchor.authority.clone(),
        lease_digest: descriptor.digest(),
        verification_clock: *expectation.clock,
    })
}

/// Verifies a transaction-receipt signature under the ownership trust anchor.
///
/// This helper exposes no trust-policy bytes or public-key material. It accepts
/// only the registered ownership transaction-receipt media type, the exact
/// pinned authority generation, and a signature statement whose validity is
/// identical to the lease interval supplied by the caller. Receipt semantic
/// decoding remains the portable ownership protocol's responsibility.
///
/// # Errors
///
/// Rejects descriptor, purpose, authority generation, trust scope, policy,
/// validity interval, current verification time, or Ed25519 signature
/// substitution.
pub fn verify_ownership_transaction_receipt_signature(
    canonical_receipt: &[u8],
    signature: &Signature,
    anchor: &OwnershipLeaseTrustAnchor,
    authority_issued_seconds: i64,
    authority_expires_seconds: i64,
    verification_wall_seconds: i64,
    limits: DecodeLimits,
) -> Result<(), OwnershipLeaseVerificationError> {
    let descriptor = descriptor_for_bytes(
        crate::MediaType::new(
            crate::PortableMediaType::OwnershipTransactionReceipt
                .as_str()
                .to_owned(),
        )
        .map_err(|error| CanonicalCborError::InvalidSemantics {
            object: "ownership transaction receipt media type",
            message: error.to_string(),
        })?,
        canonical_receipt,
    );
    let statement = signature.statement();
    if statement.subject() != &descriptor
        || statement.purpose() != SignaturePurpose::OwnershipLease
        || statement.signer() != &anchor.authority
        || statement.verification_policy() != &anchor.policy_descriptor
        || statement.trust_scope() != anchor.trust_scope
        || statement.issued_seconds() != authority_issued_seconds
        || statement.expires_seconds() != Some(authority_expires_seconds)
    {
        return Err(OwnershipLeaseVerificationError::SignatureStatementMismatch);
    }
    verify_signature(
        signature,
        &anchor.canonical_policy,
        &anchor.public_key,
        verification_wall_seconds,
        limits,
    )?;
    Ok(())
}

/// Authenticates a persisted lease at its durable historical acceptance time.
///
/// Both inputs must be the exact canonical bytes stored by the authority state
/// machine. Successful authentication proves that the configured historical
/// trust generation signed those lease bytes and that the supplied durable
/// acceptance instant's full clock-skew envelope fell inside the signed
/// interval. It does not prove that the lease is live now and cannot be used
/// by APIs requiring [`VerifiedOwnershipLease`].
///
/// The caller must establish that `expectation.accepted_at` came from a
/// previously authenticated durable record integrity-bound to this chain
/// entry. Supplying the current wall clock or an unauthenticated persisted
/// timestamp violates this function's recovery theorem.
///
/// This function authenticates one record only. A durable authority backend
/// must separately prove that it selected the trust anchor active for this
/// historical entry and enforce acquire/renew chain order, exact predecessor
/// fences, and a unique current head during recovery.
///
/// # Errors
///
/// Rejects non-canonical lease or signature bytes, descriptor or signature
/// substitution, trust scope/purpose/key-generation mismatch, invalid Ed25519
/// signatures, assignment/node/generation/digest mismatch, or a historical
/// acceptance instant whose conservative skew envelope is outside the signed
/// validity interval.
pub fn authenticate_historical_ownership_lease(
    canonical_lease: &[u8],
    canonical_signature: &[u8],
    anchor: &OwnershipLeaseTrustAnchor,
    expectation: HistoricalOwnershipLeaseExpectation<'_>,
    limits: DecodeLimits,
) -> Result<NonAuthorizingHistoricalOwnershipLease, OwnershipLeaseVerificationError> {
    let lease = decode_ownership_lease(canonical_lease, limits)?;
    let signature = crate::format::decode_signature(canonical_signature, limits)?;
    let descriptor = descriptor_for_bytes(
        crate::MediaType::new(crate::PortableMediaType::OwnershipLease.as_str().to_owned())
            .map_err(|error| CanonicalCborError::InvalidSemantics {
                object: "ownership lease media type",
                message: error.to_string(),
            })?,
        canonical_lease,
    );
    let statement = signature.statement();
    if statement.subject() != &descriptor
        || statement.purpose() != SignaturePurpose::OwnershipLease
        || statement.signer() != &anchor.authority
        || statement.verification_policy() != &anchor.policy_descriptor
        || statement.trust_scope() != anchor.trust_scope
        || statement.issued_seconds() != lease.authority_issued_seconds()
        || statement.expires_seconds() != Some(lease.authority_expires_seconds())
    {
        return Err(OwnershipLeaseVerificationError::SignatureStatementMismatch);
    }
    if !lease
        .assignment()
        .matches_broker_assignment(expectation.assignment)
        || lease.node() != expectation.node
        || statement.signer() != expectation.ownership_authority
        || lease.lease_generation() != expectation.lease_generation
        || descriptor.digest() != expectation.lease_digest
    {
        return Err(OwnershipLeaseVerificationError::HistoricalRecordMismatch);
    }
    let accepted_at = expectation.accepted_at.wall_seconds();
    let skew = i64::try_from(lease.maximum_clock_skew_seconds())
        .map_err(|_| OwnershipLeaseVerificationError::HistoricalInstantOutsideSafeValidity)?;
    let earliest = accepted_at
        .checked_sub(skew)
        .ok_or(OwnershipLeaseVerificationError::HistoricalInstantOutsideSafeValidity)?;
    let latest = accepted_at
        .checked_add(skew)
        .ok_or(OwnershipLeaseVerificationError::HistoricalInstantOutsideSafeValidity)?;
    if earliest < lease.authority_issued_seconds() || latest >= lease.authority_expires_seconds() {
        return Err(OwnershipLeaseVerificationError::HistoricalInstantOutsideSafeValidity);
    }
    verify_signature(
        &signature,
        &anchor.canonical_policy,
        &anchor.public_key,
        accepted_at,
        limits,
    )?;
    Ok(NonAuthorizingHistoricalOwnershipLease {
        lease,
        authority: anchor.authority.clone(),
        lease_digest: descriptor.digest(),
        accepted_at: expectation.accepted_at,
        canonical_lease: canonical_lease.to_vec(),
        canonical_signature: canonical_signature.to_vec(),
    })
}

/// Stores a node-local lease fence intended for authenticated persistence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalLeaseRecord {
    assignment: LeaseAssignment,
    node: NodeId,
    lease_generation: u64,
    lease_digest: ObjectDigest,
    renewal_nonce: [u8; 16],
    authority_expires_seconds: i64,
    clock_provenance: [u8; 16],
    host_boot_id: [u8; 16],
    fail_stop_boottime_nanoseconds: u64,
    integrity_digest: ObjectDigest,
}

impl LocalLeaseRecord {
    /// Returns immutable assignment semantics.
    #[must_use]
    pub const fn assignment(&self) -> LeaseAssignment {
        self.assignment
    }
    /// Returns the node named by the accepted lease.
    #[must_use]
    pub const fn node(&self) -> NodeId {
        self.node
    }
    /// Returns the highest accepted lease generation.
    #[must_use]
    pub const fn lease_generation(&self) -> u64 {
        self.lease_generation
    }
    /// Returns the highest accepted signed lease digest.
    #[must_use]
    pub const fn lease_digest(&self) -> ObjectDigest {
        self.lease_digest
    }
    /// Returns the accepted renewal nonce.
    #[must_use]
    pub const fn renewal_nonce(&self) -> &[u8; 16] {
        &self.renewal_nonce
    }
    /// Returns authority expiry retained for recovery.
    #[must_use]
    pub const fn authority_expires_seconds(&self) -> i64 {
        self.authority_expires_seconds
    }
    /// Returns the raw clock-source provenance bound during derivation.
    #[must_use]
    pub const fn clock_provenance(&self) -> &[u8; 16] {
        &self.clock_provenance
    }
    /// Returns the boot identity under which the deadline was derived.
    #[must_use]
    pub const fn host_boot_id(&self) -> &[u8; 16] {
        &self.host_boot_id
    }
    /// Returns the exclusive local BOOTTIME deadline.
    #[must_use]
    pub const fn fail_stop_boottime_nanoseconds(&self) -> u64 {
        self.fail_stop_boottime_nanoseconds
    }
}

const LOCAL_LEASE_RECORD_MAGIC: &[u8; 8] = b"AOSLLR\0\0";
const LOCAL_LEASE_RECORD_VERSION: u16 = 1;
const LOCAL_LEASE_RECORD_BYTES: usize = 234;
const LOCAL_LEASE_INTEGRITY_DOMAIN: &[u8] = b"aos-local-lease-record-integrity-v1\0";

/// Reports invalid bounded node-local lease-record bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum LocalLeaseRecordCodecError {
    /// The byte length, magic, or version differs from the fixed v1 format.
    #[error("invalid node-local lease record framing")]
    InvalidFraming,
    /// A decoded field uses a reserved sentinel or invalid lease semantics.
    #[error("invalid node-local lease record semantics")]
    InvalidSemantics,
}

/// Encodes the fixed-width versioned node-local lease record.
///
/// This is a local persistence format, not a portable media type or authority
/// object. Its exact v1 size is bounded to 234 bytes. The embedded SHA-256
/// detects corruption but is not a MAC; adversarial storage requires the
/// broker journal's node-local keyed authentication before this record is used.
#[must_use]
pub fn encode_local_lease_record(record: &LocalLeaseRecord) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(LOCAL_LEASE_RECORD_BYTES);
    bytes.extend_from_slice(LOCAL_LEASE_RECORD_MAGIC);
    bytes.extend_from_slice(&LOCAL_LEASE_RECORD_VERSION.to_be_bytes());
    bytes.extend_from_slice(record.assignment.sandbox().as_bytes());
    bytes.extend_from_slice(record.assignment.incarnation().as_bytes());
    bytes.extend_from_slice(&record.assignment.epoch().get().to_be_bytes());
    bytes.extend_from_slice(record.assignment.digest().as_bytes());
    bytes.extend_from_slice(record.node.as_bytes());
    bytes.extend_from_slice(&record.lease_generation.to_be_bytes());
    bytes.extend_from_slice(record.lease_digest.as_bytes());
    bytes.extend_from_slice(&record.renewal_nonce);
    bytes.extend_from_slice(&record.authority_expires_seconds.to_be_bytes());
    bytes.extend_from_slice(&record.clock_provenance);
    bytes.extend_from_slice(&record.host_boot_id);
    bytes.extend_from_slice(&record.fail_stop_boottime_nanoseconds.to_be_bytes());
    bytes.extend_from_slice(record.integrity_digest.as_bytes());
    bytes
}

/// Decodes and validates one exact node-local lease record.
///
/// # Errors
///
/// Returns [`LocalLeaseRecordCodecError`] for any wrong size, magic, version,
/// trailing data, sentinel, or semantically invalid field.
pub fn decode_local_lease_record(
    bytes: &[u8],
) -> Result<LocalLeaseRecord, LocalLeaseRecordCodecError> {
    if bytes.len() != LOCAL_LEASE_RECORD_BYTES {
        return Err(LocalLeaseRecordCodecError::InvalidFraming);
    }
    let mut cursor = 0;
    if take_local::<8>(bytes, &mut cursor)? != *LOCAL_LEASE_RECORD_MAGIC
        || u16::from_be_bytes(take_local::<2>(bytes, &mut cursor)?) != LOCAL_LEASE_RECORD_VERSION
    {
        return Err(LocalLeaseRecordCodecError::InvalidFraming);
    }
    let assignment = LeaseAssignment::new(
        SandboxId::from_bytes(take_local::<16>(bytes, &mut cursor)?),
        IncarnationId::from_bytes(take_local::<16>(bytes, &mut cursor)?),
        AssignmentEpoch::new(u64::from_be_bytes(take_local::<8>(bytes, &mut cursor)?)),
        ObjectDigest::from_bytes(take_local::<32>(bytes, &mut cursor)?),
    )
    .map_err(|_| LocalLeaseRecordCodecError::InvalidSemantics)?;
    let node = NodeId::from_bytes(take_local::<16>(bytes, &mut cursor)?);
    let lease_generation = u64::from_be_bytes(take_local::<8>(bytes, &mut cursor)?);
    let lease_digest = ObjectDigest::from_bytes(take_local::<32>(bytes, &mut cursor)?);
    let renewal_nonce = take_local::<16>(bytes, &mut cursor)?;
    let authority_expires_seconds = i64::from_be_bytes(take_local::<8>(bytes, &mut cursor)?);
    let clock_provenance = take_local::<16>(bytes, &mut cursor)?;
    let host_boot_id = take_local::<16>(bytes, &mut cursor)?;
    let fail_stop_boottime_nanoseconds = u64::from_be_bytes(take_local::<8>(bytes, &mut cursor)?);
    let integrity_digest = ObjectDigest::from_bytes(take_local::<32>(bytes, &mut cursor)?);
    if cursor != bytes.len()
        || node.as_bytes() == &[0; 16]
        || lease_generation == 0
        || lease_digest.as_bytes() == &[0; 32]
        || renewal_nonce == [0; 16]
        || clock_provenance == [0; 16]
        || host_boot_id == [0; 16]
        || fail_stop_boottime_nanoseconds == 0
    {
        return Err(LocalLeaseRecordCodecError::InvalidSemantics);
    }
    let record = LocalLeaseRecord {
        assignment,
        node,
        lease_generation,
        lease_digest,
        renewal_nonce,
        authority_expires_seconds,
        clock_provenance,
        host_boot_id,
        fail_stop_boottime_nanoseconds,
        integrity_digest,
    };
    if integrity_digest != local_record_integrity(&record) {
        return Err(LocalLeaseRecordCodecError::InvalidSemantics);
    }
    Ok(record)
}

fn local_record_integrity(record: &LocalLeaseRecord) -> ObjectDigest {
    use sha2::{Digest as _, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(LOCAL_LEASE_INTEGRITY_DOMAIN);
    hasher.update(record.assignment.sandbox().as_bytes());
    hasher.update(record.assignment.incarnation().as_bytes());
    hasher.update(record.assignment.epoch().get().to_be_bytes());
    hasher.update(record.assignment.digest().as_bytes());
    hasher.update(record.node.as_bytes());
    hasher.update(record.lease_generation.to_be_bytes());
    hasher.update(record.lease_digest.as_bytes());
    hasher.update(record.renewal_nonce);
    hasher.update(record.authority_expires_seconds.to_be_bytes());
    hasher.update(record.clock_provenance);
    hasher.update(record.host_boot_id);
    hasher.update(record.fail_stop_boottime_nanoseconds.to_be_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}

fn take_local<const N: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], LocalLeaseRecordCodecError> {
    let end = cursor
        .checked_add(N)
        .ok_or(LocalLeaseRecordCodecError::InvalidFraming)?;
    let source = bytes
        .get(*cursor..end)
        .ok_or(LocalLeaseRecordCodecError::InvalidFraming)?;
    let mut value = [0; N];
    value.copy_from_slice(source);
    *cursor = end;
    Ok(value)
}

/// Reports whether lease fencing advances or exactly replays durable state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeaseFenceOutcome {
    /// A newer generation replaces the durable record.
    Advanced,
    /// The exact highest lease is re-derived for the current boot.
    Replay,
}

/// Carries a candidate record that is not yet durable authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingLocalLeaseRecord {
    /// Candidate that the persistence layer must atomically store.
    pub record: LocalLeaseRecord,
    /// Comparison outcome against prior durable state.
    pub outcome: LeaseFenceOutcome,
}

/// Validates lease ordering and derives a conservative local deadline.
///
/// # Errors
///
/// Rejects stale generations, equal-generation equivocation,
/// assignment-changing renewal, exhausted time, or arithmetic overflow.
pub fn prepare_local_lease_record(
    prior: Option<&LocalLeaseRecord>,
    verified: &VerifiedOwnershipLease,
    later_clock: &RawPairedClockSample,
) -> Result<PendingLocalLeaseRecord, OwnershipLeaseVerificationError> {
    let lease = verified.lease();
    validate_later_clock(verified.verification_clock, *later_clock)?;
    let outcome = match prior {
        None => LeaseFenceOutcome::Advanced,
        Some(current) if lease.lease_generation() < current.lease_generation => {
            return Err(OwnershipLeaseVerificationError::StaleLease);
        }
        Some(current) if lease.lease_generation() == current.lease_generation => {
            if current.assignment != lease.assignment()
                || current.node != lease.node()
                || current.lease_digest != verified.lease_digest()
                || current.renewal_nonce != *lease.renewal_nonce()
            {
                return Err(OwnershipLeaseVerificationError::LeaseEquivocation);
            }
            if current.clock_provenance != verified.verification_clock.provenance.0
                || current.host_boot_id != later_clock.host_boot_id
                || later_clock.boottime_nanoseconds >= current.fail_stop_boottime_nanoseconds
                || current.integrity_digest != local_record_integrity(current)
            {
                return Err(OwnershipLeaseVerificationError::LocalRecordMismatch);
            }
            return Ok(PendingLocalLeaseRecord {
                record: current.clone(),
                outcome: LeaseFenceOutcome::Replay,
            });
        }
        Some(current) => {
            if current.assignment != lease.assignment() || current.node != lease.node() {
                return Err(OwnershipLeaseVerificationError::RenewalAssignmentMismatch);
            }
            LeaseFenceOutcome::Advanced
        }
    };
    let guard = lease
        .maximum_clock_skew_seconds()
        .checked_add(LEASE_SAFETY_MARGIN_SECONDS)
        .and_then(|value| i64::try_from(value).ok())
        .ok_or(OwnershipLeaseVerificationError::DeadlineOverflow)?;
    let remaining = lease
        .authority_expires_seconds()
        .checked_sub(guard)
        .and_then(|end| end.checked_sub(verified.verification_clock.wall_seconds))
        .filter(|seconds| *seconds > 0)
        .ok_or(OwnershipLeaseVerificationError::AuthorityExpired)?;
    let duration = u64::try_from(remaining)
        .ok()
        .and_then(|seconds| seconds.checked_mul(NANOSECONDS_PER_SECOND))
        .ok_or(OwnershipLeaseVerificationError::DeadlineOverflow)?;
    let deadline = verified
        .verification_clock
        .boottime_nanoseconds
        .checked_add(duration)
        .ok_or(OwnershipLeaseVerificationError::DeadlineOverflow)?;
    if later_clock.boottime_nanoseconds >= deadline {
        return Err(OwnershipLeaseVerificationError::LocalDeadlineExpired);
    }
    Ok(PendingLocalLeaseRecord {
        record: {
            let mut record = LocalLeaseRecord {
                assignment: lease.assignment(),
                node: lease.node(),
                lease_generation: lease.lease_generation(),
                lease_digest: verified.lease_digest(),
                renewal_nonce: *lease.renewal_nonce(),
                authority_expires_seconds: lease.authority_expires_seconds(),
                clock_provenance: later_clock.provenance.0,
                host_boot_id: later_clock.host_boot_id,
                fail_stop_boottime_nanoseconds: deadline,
                integrity_digest: ObjectDigest::from_bytes([0; 32]),
            };
            record.integrity_digest = local_record_integrity(&record);
            record
        },
        outcome,
    })
}

fn validate_later_clock(
    initial: RawPairedClockSample,
    later: RawPairedClockSample,
) -> Result<(), OwnershipLeaseVerificationError> {
    if initial.provenance != later.provenance {
        return Err(OwnershipLeaseVerificationError::ClockProvenanceMismatch);
    }
    if initial.host_boot_id != later.host_boot_id {
        return Err(OwnershipLeaseVerificationError::BootMismatch);
    }
    let wall_elapsed = later
        .wall_seconds
        .checked_sub(initial.wall_seconds)
        .and_then(|seconds| u64::try_from(seconds).ok())
        .and_then(|seconds| seconds.checked_mul(NANOSECONDS_PER_SECOND))
        .ok_or(OwnershipLeaseVerificationError::ClockRollback)?;
    let boottime_elapsed = later
        .boottime_nanoseconds
        .checked_sub(initial.boottime_nanoseconds)
        .ok_or(OwnershipLeaseVerificationError::ClockRollback)?;
    if wall_elapsed.abs_diff(boottime_elapsed) > CLOCK_PAIR_TOLERANCE_NANOSECONDS {
        return Err(OwnershipLeaseVerificationError::ClockDivergence);
    }
    Ok(())
}

/// Carries an exact but explicitly non-authorizing broker intersection.
///
/// Exact operation, target, commitment, and ceilings are retained so a later
/// durable broker transaction cannot reinterpret the intersection. This type
/// is not `Clone`, but durable request-ID consumption is still required.
#[derive(Debug)]
pub struct BrokerAdmissionIntersection {
    request_id: [u8; 16],
    request_digest: ObjectDigest,
    plan_digest: ObjectDigest,
    lease_digest: ObjectDigest,
    verb: BrokerVerb,
    target: BrokerGrantTarget,
    maximum_request_bytes: u32,
    maximum_descriptors: u16,
    plan_expires_seconds: i64,
    authority_expires_seconds: i64,
    host_boot_id: [u8; 16],
    fail_stop_boottime_nanoseconds: u64,
}

impl BrokerAdmissionIntersection {
    /// Returns the exact request ID to persist and consume.
    #[must_use]
    pub const fn request_id(&self) -> &[u8; 16] {
        &self.request_id
    }
    /// Returns the exact request semantic digest.
    #[must_use]
    pub const fn request_digest(&self) -> ObjectDigest {
        self.request_digest
    }
    /// Returns the verified plan digest.
    #[must_use]
    pub const fn plan_digest(&self) -> ObjectDigest {
        self.plan_digest
    }
    /// Returns the verified lease digest.
    #[must_use]
    pub const fn lease_digest(&self) -> ObjectDigest {
        self.lease_digest
    }
    /// Returns the exact closed broker verb.
    #[must_use]
    pub const fn verb(&self) -> BrokerVerb {
        self.verb
    }
    /// Returns the exact broker grant target.
    #[must_use]
    pub const fn target(&self) -> BrokerGrantTarget {
        self.target
    }
    /// Returns the signed request-body ceiling.
    #[must_use]
    pub const fn maximum_request_bytes(&self) -> u32 {
        self.maximum_request_bytes
    }
    /// Returns the signed descriptor-count ceiling.
    #[must_use]
    pub const fn maximum_descriptors(&self) -> u16 {
        self.maximum_descriptors
    }
    /// Returns the exclusive plan wall-clock expiry for immediate rechecking.
    #[must_use]
    pub const fn plan_expires_seconds(&self) -> i64 {
        self.plan_expires_seconds
    }
    /// Returns the authority expiry retained by the local lease record.
    #[must_use]
    pub const fn authority_expires_seconds(&self) -> i64 {
        self.authority_expires_seconds
    }
    /// Returns the host boot identity for immediate rechecking.
    #[must_use]
    pub const fn host_boot_id(&self) -> &[u8; 16] {
        &self.host_boot_id
    }
    /// Returns the exclusive local BOOTTIME deadline for immediate rechecking.
    #[must_use]
    pub const fn fail_stop_boottime_nanoseconds(&self) -> u64 {
        self.fail_stop_boottime_nanoseconds
    }
}

/// Intersects a current plan/request with a verified, locally fenced lease.
///
/// Success remains non-authorizing until the broker atomically persists and
/// consumes these exact fields in its fence and idempotency transaction.
///
/// # Errors
///
/// Rejects expired plans, boot/deadline divergence, lease-record substitution,
/// authority/context mismatch, and request identity substitution.
#[allow(clippy::too_many_arguments)]
pub fn intersect_broker_admission(
    matched: MatchedBrokerRequest<'_>,
    verified_lease: &VerifiedOwnershipLease,
    local_record: &LocalLeaseRecord,
    current_clock: &RawPairedClockSample,
    request_id: [u8; 16],
    request_digest: ObjectDigest,
) -> Result<BrokerAdmissionIntersection, OwnershipLeaseVerificationError> {
    let plan = matched.verified_plan();
    let lease = verified_lease.lease();
    validate_later_clock(verified_lease.verification_clock, *current_clock)?;
    if current_clock.wall_seconds < plan.plan().issued_seconds()
        || current_clock.wall_seconds >= plan.plan().expires_seconds()
    {
        return Err(OwnershipLeaseVerificationError::PlanExpired);
    }
    if request_id == [0; 16]
        || request_digest.as_bytes() == &[0; 32]
        || matched.grant().argument_commitment().digest() != request_digest
    {
        return Err(OwnershipLeaseVerificationError::RequestMismatch);
    }
    if !lease
        .assignment()
        .matches_broker_assignment(plan.plan().assignment())
        || lease.node() != plan.plan().node()
        || verified_lease.authority() != plan.plan().ownership_authority()
    {
        return Err(OwnershipLeaseVerificationError::ContextMismatch);
    }
    if local_record.host_boot_id != current_clock.host_boot_id {
        return Err(OwnershipLeaseVerificationError::BootMismatch);
    }
    if local_record.clock_provenance != current_clock.provenance.0
        || local_record.integrity_digest != local_record_integrity(local_record)
    {
        return Err(OwnershipLeaseVerificationError::LocalRecordMismatch);
    }
    if current_clock.boottime_nanoseconds >= local_record.fail_stop_boottime_nanoseconds {
        return Err(OwnershipLeaseVerificationError::LocalDeadlineExpired);
    }
    if local_record.assignment != lease.assignment()
        || local_record.node != lease.node()
        || local_record.lease_generation != lease.lease_generation()
        || local_record.lease_digest != verified_lease.lease_digest()
        || local_record.renewal_nonce != *lease.renewal_nonce()
        || local_record.authority_expires_seconds != lease.authority_expires_seconds()
    {
        return Err(OwnershipLeaseVerificationError::LocalRecordMismatch);
    }
    let grant = matched.grant();
    Ok(BrokerAdmissionIntersection {
        request_id,
        request_digest,
        plan_digest: matched.plan_digest(),
        lease_digest: verified_lease.lease_digest(),
        verb: grant.verb(),
        target: grant.target(),
        maximum_request_bytes: grant.maximum_request_bytes(),
        maximum_descriptors: grant.maximum_descriptors(),
        plan_expires_seconds: plan.plan().expires_seconds(),
        authority_expires_seconds: local_record.authority_expires_seconds,
        host_boot_id: local_record.host_boot_id,
        fail_stop_boottime_nanoseconds: local_record.fail_stop_boottime_nanoseconds,
    })
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use sha2::{Digest as _, Sha256};

    use super::*;
    use crate::broker_authorization::{
        BrokerArgumentCommitment, BrokerAudience, BrokerAuthorizationPlan, BrokerGrant,
        BrokerPlanRequest, VerifiedBrokerPlan,
    };
    use crate::format::{encode_ownership_lease, encode_signature, encode_trust_policy};
    use crate::model::{SignatureBytes, SignatureStatement, StableKeyId, TrustPolicy};
    use crate::{
        DesiredGeneration, MediaType, PortableMediaType, ProtocolId, ProtocolVersion,
        RevocationScopeId, sign_statement,
    };

    struct Fixture {
        bytes: Vec<u8>,
        signature: Signature,
        anchor: OwnershipLeaseTrustAnchor,
        assignment: BrokerAssignment,
        node: NodeId,
        authority: KeyReference,
        lease: OwnershipLease,
    }

    fn fixture(generation: u64, assignment_byte: u8, nonce_byte: u8) -> Fixture {
        fixture_with_interval(generation, assignment_byte, nonce_byte, 100, 200, 10)
    }

    fn fixture_with_interval(
        generation: u64,
        assignment_byte: u8,
        nonce_byte: u8,
        issued_seconds: i64,
        expires_seconds: i64,
        maximum_clock_skew_seconds: u64,
    ) -> Fixture {
        let signing_key = SigningKey::from_bytes(&[31; 32]);
        let authority = KeyReference::new(
            StableKeyId::new("ownership-authority".to_owned())
                .unwrap_or_else(|error| panic!("test key ID failed: {error}")),
            4,
            ObjectDigest::from_bytes(Sha256::digest(signing_key.verifying_key().as_bytes()).into()),
            KeyUsage::OwnershipLease,
        );
        let assignment = BrokerAssignment::new(
            SandboxId::from_bytes([1; 16]),
            IncarnationId::from_bytes([2; 16]),
            AssignmentEpoch::new(3),
            DesiredGeneration::new(4),
            ObjectDigest::from_bytes([assignment_byte; 32]),
        )
        .unwrap_or_else(|error| panic!("test assignment failed: {error}"));
        let lease_assignment = LeaseAssignment::new(
            assignment.sandbox(),
            assignment.incarnation(),
            assignment.epoch(),
            assignment.digest(),
        )
        .unwrap_or_else(|error| panic!("test lease assignment failed: {error}"));
        let node = NodeId::from_bytes([6; 16]);
        let lease = OwnershipLease::new(
            lease_assignment,
            node,
            generation,
            issued_seconds,
            expires_seconds,
            maximum_clock_skew_seconds,
            [nonce_byte; 16],
        )
        .unwrap_or_else(|error| panic!("test lease failed: {error}"));
        let bytes = encode_ownership_lease(&lease);
        let lease_descriptor = descriptor_for_bytes(
            MediaType::new(PortableMediaType::OwnershipLease.as_str().to_owned())
                .unwrap_or_else(|error| panic!("test media type failed: {error}")),
            &bytes,
        );
        let scope = TrustScopeId::from_bytes([10; 16]);
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
        let statement = SignatureStatement::new(
            lease_descriptor,
            scope,
            authority.clone(),
            SignaturePurpose::OwnershipLease,
            issued_seconds,
            Some(expires_seconds),
            policy_descriptor.clone(),
        )
        .unwrap_or_else(|error| panic!("test statement failed: {error}"));
        let signature = sign_statement(statement, &signing_key)
            .unwrap_or_else(|error| panic!("test signature failed: {error}"));
        let anchor = OwnershipLeaseTrustAnchor::from_trusted_configuration(
            policy_bytes,
            policy_descriptor,
            scope,
            authority.clone(),
            signing_key.verifying_key().to_bytes(),
            DecodeLimits::default(),
        )
        .unwrap_or_else(|error| panic!("test anchor failed: {error}"));
        Fixture {
            bytes,
            signature,
            anchor,
            assignment,
            node,
            authority,
            lease,
        }
    }

    fn verify(fixture: &Fixture) -> VerifiedOwnershipLease {
        let clock = clock(150, 1_000, 8, 20);
        verify_at(fixture, &clock)
    }

    fn verify_at(fixture: &Fixture, clock: &RawPairedClockSample) -> VerifiedOwnershipLease {
        verify_ownership_lease(
            &fixture.bytes,
            &fixture.signature,
            &fixture.anchor,
            OwnershipLeaseExpectation {
                assignment: fixture.assignment,
                node: fixture.node,
                ownership_authority: &fixture.authority,
                clock,
            },
            DecodeLimits::default(),
        )
        .unwrap_or_else(|error| panic!("valid lease verification failed: {error}"))
    }

    fn clock(wall: i64, boottime: u64, boot: u8, provenance: u8) -> RawPairedClockSample {
        RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted([provenance; 16])
                .unwrap_or_else(|error| panic!("test provenance failed: {error}")),
            [boot; 16],
            wall,
            boottime,
        )
        .unwrap_or_else(|error| panic!("test clock failed: {error}"))
    }

    fn historical_expectation(
        fixture: &Fixture,
        accepted_at: i64,
    ) -> HistoricalOwnershipLeaseExpectation<'_> {
        HistoricalOwnershipLeaseExpectation {
            assignment: fixture.assignment,
            node: fixture.node,
            ownership_authority: &fixture.authority,
            lease_generation: fixture.lease.lease_generation(),
            lease_digest: descriptor_for_bytes(
                MediaType::new(PortableMediaType::OwnershipLease.as_str().to_owned())
                    .unwrap_or_else(|error| panic!("test media type failed: {error}")),
                &fixture.bytes,
            )
            .digest(),
            accepted_at: DurableHistoricalWallClockInstant::from_authenticated_record(accepted_at),
        }
    }

    #[test]
    fn historical_authentication_accepts_valid_now_expired_record() {
        let fixture = fixture(7, 5, 9);
        let simulated_current_wall = 10_000;
        assert!(simulated_current_wall >= fixture.lease.authority_expires_seconds());
        let signature_bytes = encode_signature(&fixture.signature);
        let proof = authenticate_historical_ownership_lease(
            &fixture.bytes,
            &signature_bytes,
            &fixture.anchor,
            historical_expectation(&fixture, 150),
            DecodeLimits::default(),
        )
        .unwrap_or_else(|error| panic!("historical authentication failed: {error}"));
        assert_eq!(proof.lease(), &fixture.lease);
        assert_eq!(proof.canonical_lease(), fixture.bytes);
        assert_eq!(proof.canonical_signature(), signature_bytes);
        assert_eq!(proof.accepted_at().wall_seconds(), 150);
    }

    #[test]
    fn historical_authentication_rejects_forged_rebound_and_noncanonical_bytes() {
        let original = fixture(7, 5, 9);
        let mut forged_signature = encode_signature(&original.signature);
        let last = forged_signature
            .last_mut()
            .unwrap_or_else(|| panic!("canonical signature unexpectedly empty"));
        *last ^= 1;
        assert!(
            authenticate_historical_ownership_lease(
                &original.bytes,
                &forged_signature,
                &original.anchor,
                historical_expectation(&original, 150),
                DecodeLimits::default(),
            )
            .is_err()
        );

        let rebound = fixture(7, 8, 9);
        assert!(matches!(
            authenticate_historical_ownership_lease(
                &rebound.bytes,
                &encode_signature(&original.signature),
                &original.anchor,
                historical_expectation(&rebound, 150),
                DecodeLimits::default(),
            ),
            Err(OwnershipLeaseVerificationError::SignatureStatementMismatch)
        ));

        let mut noncanonical = encode_signature(&original.signature);
        noncanonical.push(0);
        assert!(matches!(
            authenticate_historical_ownership_lease(
                &original.bytes,
                &noncanonical,
                &original.anchor,
                historical_expectation(&original, 150),
                DecodeLimits::default(),
            ),
            Err(OwnershipLeaseVerificationError::Canonical(_))
        ));

        let mut noncanonical_lease = original.bytes.clone();
        noncanonical_lease.push(0);
        assert!(matches!(
            authenticate_historical_ownership_lease(
                &noncanonical_lease,
                &encode_signature(&original.signature),
                &original.anchor,
                historical_expectation(&original, 150),
                DecodeLimits::default(),
            ),
            Err(OwnershipLeaseVerificationError::Canonical(_))
        ));
        let restrictive_limits = DecodeLimits {
            maximum_bytes: 1,
            ..DecodeLimits::default()
        };
        assert!(matches!(
            authenticate_historical_ownership_lease(
                &original.bytes,
                &encode_signature(&original.signature),
                &original.anchor,
                historical_expectation(&original, 150),
                restrictive_limits,
            ),
            Err(OwnershipLeaseVerificationError::Canonical(_))
        ));

        let mut wrong_assignment = historical_expectation(&original, 150);
        wrong_assignment.assignment = rebound.assignment;
        assert!(matches!(
            authenticate_historical_ownership_lease(
                &original.bytes,
                &encode_signature(&original.signature),
                &original.anchor,
                wrong_assignment,
                DecodeLimits::default(),
            ),
            Err(OwnershipLeaseVerificationError::HistoricalRecordMismatch)
        ));
        let mut wrong_node = historical_expectation(&original, 150);
        wrong_node.node = NodeId::from_bytes([0x66; 16]);
        assert!(matches!(
            authenticate_historical_ownership_lease(
                &original.bytes,
                &encode_signature(&original.signature),
                &original.anchor,
                wrong_node,
                DecodeLimits::default(),
            ),
            Err(OwnershipLeaseVerificationError::HistoricalRecordMismatch)
        ));
    }

    #[test]
    fn historical_authentication_rejects_wrong_instant_anchor_generation_and_purpose() {
        let fixture = fixture_with_interval(7, 5, 9, 100, 200, 5);
        let signature_bytes = encode_signature(&fixture.signature);
        for outside in [104, 195] {
            assert!(matches!(
                authenticate_historical_ownership_lease(
                    &fixture.bytes,
                    &signature_bytes,
                    &fixture.anchor,
                    historical_expectation(&fixture, outside),
                    DecodeLimits::default(),
                ),
                Err(OwnershipLeaseVerificationError::HistoricalInstantOutsideSafeValidity)
            ));
        }
        for safe_boundary in [105, 194] {
            authenticate_historical_ownership_lease(
                &fixture.bytes,
                &signature_bytes,
                &fixture.anchor,
                historical_expectation(&fixture, safe_boundary),
                DecodeLimits::default(),
            )
            .unwrap_or_else(|error| panic!("safe historical boundary rejected: {error}"));
        }

        let mut wrong_generation = historical_expectation(&fixture, 150);
        wrong_generation.lease_generation += 1;
        assert!(matches!(
            authenticate_historical_ownership_lease(
                &fixture.bytes,
                &signature_bytes,
                &fixture.anchor,
                wrong_generation,
                DecodeLimits::default(),
            ),
            Err(OwnershipLeaseVerificationError::HistoricalRecordMismatch)
        ));
        let mut wrong_digest = historical_expectation(&fixture, 150);
        wrong_digest.lease_digest = ObjectDigest::from_bytes([0x55; 32]);
        assert!(matches!(
            authenticate_historical_ownership_lease(
                &fixture.bytes,
                &signature_bytes,
                &fixture.anchor,
                wrong_digest,
                DecodeLimits::default(),
            ),
            Err(OwnershipLeaseVerificationError::HistoricalRecordMismatch)
        ));
        let wrong_authority = KeyReference::new(
            fixture.authority.stable_key_id().clone(),
            fixture.authority.generation() + 1,
            fixture.authority.public_key_sha256(),
            KeyUsage::OwnershipLease,
        );
        let mut wrong_authority_expectation = historical_expectation(&fixture, 150);
        wrong_authority_expectation.ownership_authority = &wrong_authority;
        assert!(matches!(
            authenticate_historical_ownership_lease(
                &fixture.bytes,
                &signature_bytes,
                &fixture.anchor,
                wrong_authority_expectation,
                DecodeLimits::default(),
            ),
            Err(OwnershipLeaseVerificationError::HistoricalRecordMismatch)
        ));

        let other_key = SigningKey::from_bytes(&[47; 32]);
        let other_authority = KeyReference::new(
            StableKeyId::new("other-ownership-authority".to_owned())
                .unwrap_or_else(|error| panic!("test key ID failed: {error}")),
            1,
            ObjectDigest::from_bytes(Sha256::digest(other_key.verifying_key().as_bytes()).into()),
            KeyUsage::OwnershipLease,
        );
        let scope = fixture.signature.statement().trust_scope();
        let other_scope = TrustScopeId::from_bytes([0x77; 16]);
        let other_policy = TrustPolicy::new(
            other_scope,
            SignaturePurpose::OwnershipLease,
            vec![other_authority.clone()],
            Vec::new(),
        )
        .unwrap_or_else(|error| panic!("test policy failed: {error}"));
        let other_policy_bytes = encode_trust_policy(&other_policy);
        let other_policy_descriptor = descriptor_for_bytes(
            MediaType::new(PortableMediaType::TrustPolicy.as_str().to_owned())
                .unwrap_or_else(|error| panic!("test media type failed: {error}")),
            &other_policy_bytes,
        );
        let other_anchor = OwnershipLeaseTrustAnchor::from_trusted_configuration(
            other_policy_bytes,
            other_policy_descriptor,
            other_scope,
            other_authority,
            other_key.verifying_key().to_bytes(),
            DecodeLimits::default(),
        )
        .unwrap_or_else(|error| panic!("test anchor failed: {error}"));
        assert!(
            authenticate_historical_ownership_lease(
                &fixture.bytes,
                &signature_bytes,
                &other_anchor,
                historical_expectation(&fixture, 150),
                DecodeLimits::default(),
            )
            .is_err()
        );

        let wrong_purpose_key = KeyReference::new(
            fixture.authority.stable_key_id().clone(),
            fixture.authority.generation(),
            fixture.authority.public_key_sha256(),
            KeyUsage::BrokerAuthorization,
        );
        let wrong_purpose_statement = SignatureStatement::new(
            fixture.signature.statement().subject().clone(),
            scope,
            wrong_purpose_key,
            SignaturePurpose::BrokerAuthorization,
            100,
            Some(200),
            fixture.signature.statement().verification_policy().clone(),
        )
        .unwrap_or_else(|error| panic!("wrong-purpose statement failed: {error}"));
        let wrong_purpose_signature =
            Signature::new(wrong_purpose_statement, SignatureBytes::new([1; 64]));
        assert!(
            authenticate_historical_ownership_lease(
                &fixture.bytes,
                &encode_signature(&wrong_purpose_signature),
                &fixture.anchor,
                historical_expectation(&fixture, 150),
                DecodeLimits::default(),
            )
            .is_err()
        );
    }

    #[test]
    fn historical_safe_interval_rejects_checked_arithmetic_edges() {
        let underflow = fixture_with_interval(7, 5, 9, i64::MIN, i64::MIN + 100, 5);
        assert!(matches!(
            authenticate_historical_ownership_lease(
                &underflow.bytes,
                &encode_signature(&underflow.signature),
                &underflow.anchor,
                historical_expectation(&underflow, i64::MIN + 4),
                DecodeLimits::default(),
            ),
            Err(OwnershipLeaseVerificationError::HistoricalInstantOutsideSafeValidity)
        ));

        let overflow = fixture_with_interval(7, 5, 9, i64::MAX - 100, i64::MAX, 5);
        assert!(matches!(
            authenticate_historical_ownership_lease(
                &overflow.bytes,
                &encode_signature(&overflow.signature),
                &overflow.anchor,
                historical_expectation(&overflow, i64::MAX - 4),
                DecodeLimits::default(),
            ),
            Err(OwnershipLeaseVerificationError::HistoricalInstantOutsideSafeValidity)
        ));
    }

    fn plan(fixture: &Fixture, expires_seconds: i64) -> VerifiedBrokerPlan {
        let plan = BrokerAuthorizationPlan::new(
            BrokerAudience::Mount,
            ProtocolId::MountBroker,
            ProtocolVersion::new(1, 0),
            fixture.assignment,
            fixture.node,
            fixture.authority.clone(),
            vec![
                BrokerGrant::new(
                    BrokerVerb::MountCreate,
                    BrokerGrantTarget::Assignment,
                    BrokerArgumentCommitment::from_digest(ObjectDigest::from_bytes([12; 32]))
                        .unwrap_or_else(|error| panic!("test commitment failed: {error}")),
                    4_096,
                    0,
                )
                .unwrap_or_else(|error| panic!("test grant failed: {error}")),
            ],
            ObjectDigest::from_bytes([13; 32]),
            RevocationScopeId::from_bytes([14; 16]),
            100,
            expires_seconds,
            Vec::new(),
        )
        .unwrap_or_else(|error| panic!("test plan failed: {error}"));
        VerifiedBrokerPlan::from_test_plan(plan)
    }

    fn matched(plan: &VerifiedBrokerPlan) -> MatchedBrokerRequest<'_> {
        plan.match_request(BrokerPlanRequest {
            verb: BrokerVerb::MountCreate,
            target: BrokerGrantTarget::Assignment,
            argument_commitment: BrokerArgumentCommitment::from_digest(ObjectDigest::from_bytes(
                [12; 32],
            ))
            .unwrap_or_else(|error| panic!("test commitment failed: {error}")),
            request_bytes: 100,
            descriptor_count: 0,
        })
        .unwrap_or_else(|error| panic!("test match failed: {error}"))
    }

    #[test]
    fn ownership_lease_matches_normative_golden_and_rejects_trailing_data() {
        const GOLDEN: &str = "880184500101010101010101010101010101010150020202020202020202020202020202020358200505050505050505050505050505050505050505050505050505050505050505500606060606060606060606060606060607186418c80a5009090909090909090909090909090909";
        let fixture = fixture(7, 5, 9);
        assert_eq!(hex::encode(&fixture.bytes), GOLDEN);
        assert_eq!(
            decode_ownership_lease(&fixture.bytes, DecodeLimits::default()),
            Ok(fixture.lease)
        );
        let mut trailing = fixture.bytes;
        trailing.push(0);
        assert!(decode_ownership_lease(&trailing, DecodeLimits::default()).is_err());

        let mut zero_generation =
            hex::decode(GOLDEN).unwrap_or_else(|error| panic!("golden hex failed: {error}"));
        let generation_offset = zero_generation
            .iter()
            .position(|byte| *byte == 7)
            .unwrap_or_else(|| panic!("golden generation byte missing"));
        zero_generation[generation_offset] = 0;
        assert!(decode_ownership_lease(&zero_generation, DecodeLimits::default()).is_err());

        let mut zero_nonce =
            hex::decode(GOLDEN).unwrap_or_else(|error| panic!("golden hex failed: {error}"));
        let nonce_start = zero_nonce.len().saturating_sub(16);
        zero_nonce[nonce_start..].fill(0);
        assert!(decode_ownership_lease(&zero_nonce, DecodeLimits::default()).is_err());
    }

    #[test]
    fn signature_tamper_and_authority_substitution_fail_closed() {
        let fixture = fixture(7, 5, 9);
        let verification_clock = clock(150, 1_000, 8, 20);
        let mut tampered = fixture.bytes.clone();
        let last = tampered.len().saturating_sub(1);
        tampered[last] ^= 1;
        assert!(
            verify_ownership_lease(
                &tampered,
                &fixture.signature,
                &fixture.anchor,
                OwnershipLeaseExpectation {
                    assignment: fixture.assignment,
                    node: fixture.node,
                    ownership_authority: &fixture.authority,
                    clock: &verification_clock,
                },
                DecodeLimits::default(),
            )
            .is_err()
        );

        let substitute = KeyReference::new(
            StableKeyId::new("substitute".to_owned())
                .unwrap_or_else(|error| panic!("test key ID failed: {error}")),
            fixture.authority.generation(),
            fixture.authority.public_key_sha256(),
            KeyUsage::OwnershipLease,
        );
        assert!(matches!(
            verify_ownership_lease(
                &fixture.bytes,
                &fixture.signature,
                &fixture.anchor,
                OwnershipLeaseExpectation {
                    assignment: fixture.assignment,
                    node: fixture.node,
                    ownership_authority: &substitute,
                    clock: &verification_clock,
                },
                DecodeLimits::default(),
            ),
            Err(OwnershipLeaseVerificationError::ContextMismatch)
        ));
    }

    #[test]
    fn skew_and_margin_derive_conservative_boottime_deadline() {
        let fixture = fixture(7, 5, 9);
        let verified = verify(&fixture);
        let pending = prepare_local_lease_record(None, &verified, &clock(150, 1_000, 8, 20))
            .unwrap_or_else(|error| panic!("deadline derivation failed: {error}"));
        assert_eq!(pending.outcome, LeaseFenceOutcome::Advanced);
        assert_eq!(
            pending.record.fail_stop_boottime_nanoseconds(),
            35_000_001_000
        );
        assert_eq!(pending.record.authority_expires_seconds(), 200);
        assert!(matches!(
            prepare_local_lease_record(None, &verified, &clock(149, 1_000, 8, 20)),
            Err(OwnershipLeaseVerificationError::ClockRollback)
        ));
        assert!(matches!(
            prepare_local_lease_record(None, &verified, &clock(151, 10_000_001_000, 8, 20)),
            Err(OwnershipLeaseVerificationError::ClockDivergence)
        ));
        assert!(matches!(
            prepare_local_lease_record(None, &verified, &clock(150, 5_000_001_000, 8, 20)),
            Err(OwnershipLeaseVerificationError::ClockDivergence)
        ));
        assert!(matches!(
            prepare_local_lease_record(None, &verified, &clock(150, 999, 8, 20)),
            Err(OwnershipLeaseVerificationError::ClockRollback)
        ));
        assert!(matches!(
            prepare_local_lease_record(None, &verified, &clock(150, 1_000, 8, 21)),
            Err(OwnershipLeaseVerificationError::ClockProvenanceMismatch)
        ));
        assert!(matches!(
            prepare_local_lease_record(None, &verified, &clock(185, 35_000_001_000, 8, 20)),
            Err(OwnershipLeaseVerificationError::LocalDeadlineExpired)
        ));
    }

    #[test]
    fn lease_fence_rejects_equal_equivocation_stale_and_assignment_changing_renewal() {
        let base = fixture(7, 5, 9);
        let base_verified = verify(&base);
        let prior = prepare_local_lease_record(None, &base_verified, &clock(150, 1_000, 8, 20))
            .unwrap_or_else(|error| panic!("base fence failed: {error}"))
            .record;

        let equivocation = fixture(7, 5, 10);
        assert!(matches!(
            prepare_local_lease_record(
                Some(&prior),
                &verify(&equivocation),
                &clock(150, 1_000, 8, 20)
            ),
            Err(OwnershipLeaseVerificationError::LeaseEquivocation)
        ));
        let stale = fixture(6, 5, 8);
        assert!(matches!(
            prepare_local_lease_record(Some(&prior), &verify(&stale), &clock(150, 1_000, 8, 20)),
            Err(OwnershipLeaseVerificationError::StaleLease)
        ));
        let changed = fixture(8, 11, 11);
        assert!(matches!(
            prepare_local_lease_record(Some(&prior), &verify(&changed), &clock(150, 1_000, 8, 20)),
            Err(OwnershipLeaseVerificationError::RenewalAssignmentMismatch)
        ));

        let replay_clock = clock(151, 1_000_001_000, 8, 20);
        let replay_verified = verify_at(&base, &replay_clock);
        let replay = prepare_local_lease_record(Some(&prior), &replay_verified, &replay_clock)
            .unwrap_or_else(|error| panic!("exact replay failed: {error}"));
        assert_eq!(replay.outcome, LeaseFenceOutcome::Replay);
        assert_eq!(replay.record, prior);
    }

    #[test]
    fn broker_intersection_rechecks_reboot_plan_and_monotonic_deadline() {
        let fixture = fixture(7, 5, 9);
        let verified = verify(&fixture);
        let record = prepare_local_lease_record(None, &verified, &clock(150, 1_000, 8, 20))
            .unwrap_or_else(|error| panic!("fence failed: {error}"))
            .record;
        let live_plan = plan(&fixture, 190);
        assert!(matches!(
            intersect_broker_admission(
                matched(&live_plan),
                &verified,
                &record,
                &clock(151, 1_000_002_000, 7, 20),
                [15; 16],
                ObjectDigest::from_bytes([12; 32]),
            ),
            Err(OwnershipLeaseVerificationError::BootMismatch)
        ));

        let expired_plan = plan(&fixture, 140);
        assert!(matches!(
            intersect_broker_admission(
                matched(&expired_plan),
                &verified,
                &record,
                &clock(150, 2_000, 8, 20),
                [15; 16],
                ObjectDigest::from_bytes([12; 32]),
            ),
            Err(OwnershipLeaseVerificationError::PlanExpired)
        ));
        assert!(matches!(
            intersect_broker_admission(
                matched(&live_plan),
                &verified,
                &record,
                &clock(185, record.fail_stop_boottime_nanoseconds(), 8, 20),
                [15; 16],
                ObjectDigest::from_bytes([12; 32]),
            ),
            Err(OwnershipLeaseVerificationError::LocalDeadlineExpired)
        ));
    }

    #[test]
    fn intersection_retains_exact_operation_shape_but_is_not_effect_authority() {
        let fixture = fixture(7, 5, 9);
        let verified = verify(&fixture);
        let pending = prepare_local_lease_record(None, &verified, &clock(150, 1_000, 8, 20))
            .unwrap_or_else(|error| panic!("fence failed: {error}"));
        let plan = plan(&fixture, 190);
        let intersection = intersect_broker_admission(
            matched(&plan),
            &verified,
            &pending.record,
            &clock(150, 2_000, 8, 20),
            [15; 16],
            ObjectDigest::from_bytes([12; 32]),
        )
        .unwrap_or_else(|error| panic!("intersection failed: {error}"));
        assert_eq!(intersection.verb(), BrokerVerb::MountCreate);
        assert_eq!(intersection.target(), BrokerGrantTarget::Assignment);
        assert_eq!(intersection.maximum_request_bytes(), 4_096);
        assert_eq!(intersection.maximum_descriptors(), 0);
        assert_eq!(intersection.plan_expires_seconds(), 190);
        assert_eq!(intersection.authority_expires_seconds(), 200);
        assert_eq!(intersection.host_boot_id(), &[8; 16]);
        assert_eq!(
            intersection.fail_stop_boottime_nanoseconds(),
            pending.record.fail_stop_boottime_nanoseconds()
        );

        assert!(matches!(
            intersect_broker_admission(
                matched(&plan),
                &verified,
                &pending.record,
                &clock(150, 2_000, 8, 20),
                [15; 16],
                ObjectDigest::from_bytes([16; 32]),
            ),
            Err(OwnershipLeaseVerificationError::RequestMismatch)
        ));
    }

    #[test]
    fn local_lease_record_codec_is_fixed_bounded_and_fail_closed() {
        let fixture = fixture(7, 5, 9);
        let verified = verify(&fixture);
        let record = prepare_local_lease_record(None, &verified, &clock(150, 1_000, 8, 20))
            .unwrap_or_else(|error| panic!("fence failed: {error}"))
            .record;
        let bytes = encode_local_lease_record(&record);
        assert_eq!(bytes.len(), LOCAL_LEASE_RECORD_BYTES);
        assert_eq!(
            hex::encode(&bytes),
            "414f534c4c520000000101010101010101010101010101010101020202020202020202020202020202020000000000000003050505050505050505050505050505050505050505050505050505050505050506060606060606060606060606060606000000000000000750eaa2c31b835f37356d5208fd40899bbbb3b0f08bcfdbf257bab78e32b7adb60909090909090909090909090909090900000000000000c81414141414141414141414141414141408080808080808080808080808080808000000082629a1e858e97bc412c719f27e387e104300c6082338a6cf4bfac5d9adc0dcacb7a633d7"
        );
        assert_eq!(decode_local_lease_record(&bytes), Ok(record));

        let mut wrong_version = bytes.clone();
        wrong_version[9] = 2;
        assert_eq!(
            decode_local_lease_record(&wrong_version),
            Err(LocalLeaseRecordCodecError::InvalidFraming)
        );
        let mut zero_generation = bytes.clone();
        zero_generation[98..106].fill(0);
        assert_eq!(
            decode_local_lease_record(&zero_generation),
            Err(LocalLeaseRecordCodecError::InvalidSemantics)
        );
        let mut raised_deadline = bytes.clone();
        raised_deadline[201] ^= 1;
        assert_eq!(
            decode_local_lease_record(&raised_deadline),
            Err(LocalLeaseRecordCodecError::InvalidSemantics)
        );
        let mut trailing = bytes;
        trailing.push(0);
        assert_eq!(
            decode_local_lease_record(&trailing),
            Err(LocalLeaseRecordCodecError::InvalidFraming)
        );
    }
}

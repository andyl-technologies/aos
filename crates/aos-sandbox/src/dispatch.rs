//! Builds lease-independent broker templates and lease-bound dispatch attempts.
//!
//! A [`BrokerDispatchTemplateV1`] freezes a signed plan, closed method,
//! deadline-free protobuf body, descriptor roles, and portable semantic grant.
//! A [`BrokerDispatchAttemptV1`] later injects one local BOOTTIME deadline and
//! attaches one independently verified ownership lease. This split permits a
//! lease renewal to reuse immutable operation semantics without reusing stale
//! lease authority or an old local-clock value.
//!
//! These controller artifacts are non-authorizing. In particular, a semantic
//! identity supplied by the controller does not prove that hostile protobuf
//! bytes have that meaning, and [`RawPairedClockSample`] is explicitly an
//! untrusted advisory observation. The privileged broker must decode the body,
//! recompute semantics against its trusted catalog, verify both signatures,
//! sample its protected local clock, and durably admit all fences before any
//! effect.

use aos_proto::aos::sandbox::local::v1::{BrokerDescriptorRole, BrokerMethod};
use aos_sandbox_core::{
    BrokerArgumentCommitment, BrokerAuthorizationPlan, BrokerGrantTarget, BrokerVerb,
    LEASE_SAFETY_MARGIN_SECONDS, ObjectDigest, ProtocolId, RawPairedClockSample,
};
use aos_sandbox_protocol::{
    AuthorizationArtifactBytes, MAXIMUM_PACKET_DESCRIPTORS, MAXIMUM_REQUEST_BYTES,
    ProtocolValidationError, encode_authorized_request_envelope,
};
use sha2::{Digest as _, Sha256};

use crate::SignedBrokerPlan;
#[cfg(test)]
use crate::SignedOwnershipLease;
use crate::publication::{RecoveredBrokerDispatchTemplateV1, RecoveredOwnershipLeaseV1};

const TEMPLATE_DOMAIN: &[u8] = b"aos.sandbox.broker-dispatch-template.v1\0";
const SEMANTIC_IDENTITY_DOMAIN: &[u8] = b"aos.sandbox.broker-semantic-identity.v1\0";
const MAXIMUM_DEADLINE_FIELD_BYTES: usize = 11;
const NANOS_PER_SECOND: u64 = 1_000_000_000;

/// Names the controller-asserted portable grant for one immutable request.
///
/// This value carries no proof that a protobuf body has these semantics. It is
/// an immutable dispatch correlation value; the privileged broker independently
/// derives and compares the authoritative semantic identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrokerDispatchSemanticIdentityV1 {
    verb: BrokerVerb,
    target: BrokerGrantTarget,
    argument_commitment: BrokerArgumentCommitment,
}

impl BrokerDispatchSemanticIdentityV1 {
    /// Constructs an identity returned by a protocol semantic compiler.
    ///
    /// Construction is non-authorizing because this type cannot prove the
    /// provenance of its three values.
    #[must_use]
    pub const fn new(
        verb: BrokerVerb,
        target: BrokerGrantTarget,
        argument_commitment: BrokerArgumentCommitment,
    ) -> Self {
        Self {
            verb,
            target,
            argument_commitment,
        }
    }

    /// Returns the exact semantic verb.
    #[must_use]
    pub const fn verb(self) -> BrokerVerb {
        self.verb
    }

    /// Returns the assignment or resource target.
    #[must_use]
    pub const fn target(self) -> BrokerGrantTarget {
        self.target
    }

    /// Returns the canonical typed argument commitment.
    #[must_use]
    pub const fn argument_commitment(self) -> BrokerArgumentCommitment {
        self.argument_commitment
    }
}

/// Freezes one reusable, non-authorizing operation without lease or clock facts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerDispatchTemplateV1 {
    signed_plan: SignedBrokerPlan,
    method: BrokerMethod,
    body_without_deadline: Vec<u8>,
    descriptor_roles: Vec<BrokerDescriptorRole>,
    semantics: BrokerDispatchSemanticIdentityV1,
    digest: ObjectDigest,
}

impl BrokerDispatchTemplateV1 {
    /// Constructs a byte-exact immutable dispatch template.
    ///
    /// `body_without_deadline` must be a protobuf request whose field 1 is its
    /// common header and whose header omits field 5. An attempt injects that
    /// deadline field without decoding or rewriting any other body bytes.
    /// `semantics` should come from the corresponding portable protocol
    /// compiler. This constructor only proves that the asserted identity occurs
    /// in the signed plan; it deliberately cannot prove the body has that
    /// meaning because catalog-resolved semantics remain broker-owned. The
    /// receiving broker must decode and independently recompute it.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerDispatchTemplateError`] when method, protocol,
    /// semantics, body framing, descriptors, or signed grant bounds differ.
    pub fn new(
        signed_plan: SignedBrokerPlan,
        method: BrokerMethod,
        body_without_deadline: Vec<u8>,
        descriptor_roles: Vec<BrokerDescriptorRole>,
        semantics: BrokerDispatchSemanticIdentityV1,
    ) -> Result<Self, BrokerDispatchTemplateError> {
        validate_method(&signed_plan, method)?;
        validate_descriptor_roles(&descriptor_roles)?;

        let maximum_body = body_without_deadline
            .len()
            .checked_add(MAXIMUM_DEADLINE_FIELD_BYTES)
            .ok_or(BrokerDispatchTemplateError::BodyTooLarge)?;
        if maximum_body > MAXIMUM_REQUEST_BYTES {
            return Err(BrokerDispatchTemplateError::BodyTooLarge);
        }
        locate_deadline_free_header(&body_without_deadline)?;
        let request_bytes =
            u32::try_from(maximum_body).map_err(|_| BrokerDispatchTemplateError::BodyTooLarge)?;
        let descriptor_count = u16::try_from(descriptor_roles.len())
            .map_err(|_| BrokerDispatchTemplateError::DescriptorTable)?;
        match_plan_grant(
            signed_plan.plan(),
            semantics,
            request_bytes,
            descriptor_count,
        )?;

        let digest = template_digest(
            &signed_plan,
            method,
            &body_without_deadline,
            &descriptor_roles,
            semantics,
        );
        Ok(Self {
            signed_plan,
            method,
            body_without_deadline,
            descriptor_roles,
            semantics,
            digest,
        })
    }

    /// Returns the stable digest of every immutable template component.
    #[must_use]
    pub const fn digest(&self) -> ObjectDigest {
        self.digest
    }

    /// Returns the exact signed broker plan.
    #[must_use]
    pub const fn signed_plan(&self) -> &SignedBrokerPlan {
        &self.signed_plan
    }

    /// Returns the exact closed broker method.
    #[must_use]
    pub const fn method(&self) -> BrokerMethod {
        self.method
    }

    /// Returns the deadline-free request body bytes.
    #[must_use]
    pub fn body_without_deadline(&self) -> &[u8] {
        &self.body_without_deadline
    }

    /// Returns ancillary descriptor roles in exact descriptor order.
    #[must_use]
    pub fn descriptor_roles(&self) -> &[BrokerDescriptorRole] {
        &self.descriptor_roles
    }

    /// Returns the portable operation semantics matched by the plan.
    #[must_use]
    pub const fn semantics(&self) -> BrokerDispatchSemanticIdentityV1 {
        self.semantics
    }
}

/// Owns one exact, non-authorizing packet attenuated to a lease and deadline.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerDispatchAttemptV1 {
    template_digest: ObjectDigest,
    lease_digest: ObjectDigest,
    lease_generation: u64,
    deadline_boottime_nanoseconds: u64,
    body: Vec<u8>,
    packet: Vec<u8>,
}

impl BrokerDispatchAttemptV1 {
    /// Binds a template to one current lease and advisory local deadline.
    ///
    /// `clock` is a [`RawPairedClockSample`], not protected broker evidence. Its
    /// only purpose here is to shorten the controller's attempt window. The
    /// resulting packet gains authority only if the receiving broker verifies
    /// the signed lease with its own protected paired clock and durably admits
    /// assignment, plan, lease-generation, and request fences.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerDispatchAttemptError`] for assignment or node
    /// substitution, expired plan/lease authority, an unsafe deadline, wire
    /// overflow, or failure to preserve the template's signed grant bounds.
    #[cfg(test)]
    pub(crate) fn new(
        template: &BrokerDispatchTemplateV1,
        lease: &SignedOwnershipLease,
        deadline_boottime_nanoseconds: u64,
        clock: RawPairedClockSample,
    ) -> Result<Self, BrokerDispatchAttemptError> {
        validate_context(template, lease)?;
        let plan = template.signed_plan.plan();
        if clock.wall_seconds() < plan.issued_seconds()
            || clock.wall_seconds() >= plan.expires_seconds()
        {
            return Err(BrokerDispatchAttemptError::PlanExpired);
        }
        let maximum_deadline = conservative_lease_deadline(lease, clock)?;
        if deadline_boottime_nanoseconds <= clock.boottime_nanoseconds()
            || deadline_boottime_nanoseconds > maximum_deadline
        {
            return Err(BrokerDispatchAttemptError::UnsafeDeadline);
        }

        let body = inject_deadline(
            &template.body_without_deadline,
            deadline_boottime_nanoseconds,
        )?;
        let request_bytes =
            u32::try_from(body.len()).map_err(|_| BrokerDispatchAttemptError::BodyTooLarge)?;
        let descriptor_count = u16::try_from(template.descriptor_roles.len())
            .map_err(|_| BrokerDispatchAttemptError::BodyTooLarge)?;
        match_plan_grant(
            template.signed_plan.plan(),
            template.semantics,
            request_bytes,
            descriptor_count,
        )
        .map_err(|_| BrokerDispatchAttemptError::PlanGrantMismatch)?;

        let packet = encode_authorized_request_envelope(
            plan.protocol(),
            template.method,
            &body,
            &template.descriptor_roles,
            AuthorizationArtifactBytes {
                broker_plan: template.signed_plan.canonical_plan(),
                broker_plan_signature: template.signed_plan.canonical_signature(),
                ownership_lease: lease.canonical_lease(),
                ownership_lease_signature: lease.canonical_signature(),
            },
        )?;
        Ok(Self {
            template_digest: template.digest,
            lease_digest: lease.digest(),
            lease_generation: lease.generation(),
            deadline_boottime_nanoseconds,
            body,
            packet,
        })
    }

    /// Builds an attempt from artifacts recovered together as current.
    ///
    /// This crate-private path is reachable only through the publication store,
    /// which selects the template from one exact current bundle. Recovery does
    /// not re-establish signature trust, so the resulting packet remains
    /// non-authorizing input that the privileged broker must fully verify.
    pub(crate) fn from_recovered_current(
        template: &RecoveredBrokerDispatchTemplateV1,
        lease: &RecoveredOwnershipLeaseV1,
        deadline_boottime_nanoseconds: u64,
        clock: RawPairedClockSample,
    ) -> Result<Self, BrokerDispatchAttemptError> {
        Self::from_recovered_current_at(
            template,
            lease,
            deadline_boottime_nanoseconds,
            clock.wall_seconds(),
            clock.boottime_nanoseconds(),
        )
    }

    pub(crate) fn from_recovered_current_at(
        template: &RecoveredBrokerDispatchTemplateV1,
        lease: &RecoveredOwnershipLeaseV1,
        deadline_boottime_nanoseconds: u64,
        wall_seconds: i64,
        boottime_nanoseconds: u64,
    ) -> Result<Self, BrokerDispatchAttemptError> {
        let plan = template.plan();
        let recovered_lease = lease.lease();
        if plan.assignment().sandbox() != recovered_lease.assignment().sandbox()
            || plan.assignment().incarnation() != recovered_lease.assignment().incarnation()
            || plan.assignment().epoch() != recovered_lease.assignment().epoch()
            || plan.assignment().digest() != recovered_lease.assignment().digest()
            || plan.node() != recovered_lease.node()
        {
            return Err(BrokerDispatchAttemptError::LeaseContextMismatch);
        }
        if wall_seconds < plan.issued_seconds() || wall_seconds >= plan.expires_seconds() {
            return Err(BrokerDispatchAttemptError::PlanExpired);
        }
        let maximum_deadline = conservative_lease_deadline_scalar_fields(
            recovered_lease.authority_issued_seconds(),
            recovered_lease.authority_expires_seconds(),
            recovered_lease.maximum_clock_skew_seconds(),
            wall_seconds,
            boottime_nanoseconds,
        )?;
        if deadline_boottime_nanoseconds <= boottime_nanoseconds
            || deadline_boottime_nanoseconds > maximum_deadline
        {
            return Err(BrokerDispatchAttemptError::UnsafeDeadline);
        }

        let body = inject_deadline(
            template.body_without_deadline(),
            deadline_boottime_nanoseconds,
        )?;
        let request_bytes =
            u32::try_from(body.len()).map_err(|_| BrokerDispatchAttemptError::BodyTooLarge)?;
        let descriptor_count = u16::try_from(template.descriptor_roles().len())
            .map_err(|_| BrokerDispatchAttemptError::BodyTooLarge)?;
        match_plan_grant(plan, template.semantics(), request_bytes, descriptor_count)
            .map_err(|_| BrokerDispatchAttemptError::PlanGrantMismatch)?;

        let packet = encode_authorized_request_envelope(
            plan.protocol(),
            template.method(),
            &body,
            template.descriptor_roles(),
            AuthorizationArtifactBytes {
                broker_plan: template.canonical_plan(),
                broker_plan_signature: template.canonical_plan_signature(),
                ownership_lease: lease.canonical_lease(),
                ownership_lease_signature: lease.canonical_signature(),
            },
        )?;
        Ok(Self {
            template_digest: template.digest(),
            lease_digest: lease.digest(),
            lease_generation: recovered_lease.lease_generation(),
            deadline_boottime_nanoseconds,
            body,
            packet,
        })
    }

    /// Returns the immutable template digest used for this attempt.
    #[must_use]
    pub const fn template_digest(&self) -> ObjectDigest {
        self.template_digest
    }

    /// Returns the exact signed lease digest used for this attempt.
    #[must_use]
    pub const fn lease_digest(&self) -> ObjectDigest {
        self.lease_digest
    }

    /// Returns the issuer-chosen lease generation used for this attempt.
    #[must_use]
    pub const fn lease_generation(&self) -> u64 {
        self.lease_generation
    }

    /// Returns the conservative attempt-local BOOTTIME deadline.
    #[must_use]
    pub const fn deadline_boottime_nanoseconds(&self) -> u64 {
        self.deadline_boottime_nanoseconds
    }

    /// Returns the exact protobuf body with the attempt deadline injected.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Returns the exact non-authorizing broker packet ready for transport.
    #[must_use]
    pub fn packet(&self) -> &[u8] {
        &self.packet
    }

    pub(crate) fn from_durable_parts(
        template_digest: ObjectDigest,
        lease_digest: ObjectDigest,
        lease_generation: u64,
        deadline_boottime_nanoseconds: u64,
        body: Vec<u8>,
        packet: Vec<u8>,
    ) -> Self {
        Self {
            template_digest,
            lease_digest,
            lease_generation,
            deadline_boottime_nanoseconds,
            body,
            packet,
        }
    }
}

/// Reports invalid immutable template input.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum BrokerDispatchTemplateError {
    /// Method is not an effect method for the signed audience and protocol.
    #[error("broker method does not match the signed audience and protocol")]
    MethodMismatch,
    /// Protobuf body has no unique deadline-free common header.
    #[error("broker request body is not a deadline-free V1 body")]
    InvalidBody,
    /// Body cannot remain within the fixed packet allocation ceiling.
    #[error("broker request body exceeds the fixed V1 bound")]
    BodyTooLarge,
    /// Descriptor roles are oversized, unspecified, or repeated.
    #[error("broker descriptor role table is invalid")]
    DescriptorTable,
    /// Portable request semantics or bounds are not present in the plan.
    #[error("broker request is not committed by the signed plan")]
    PlanGrantMismatch,
}

/// Reports a rejected lease-bound dispatch attempt.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum BrokerDispatchAttemptError {
    /// Lease assignment or node differs from the immutable plan.
    #[error("ownership lease does not match the dispatch template")]
    LeaseContextMismatch,
    /// Broker plan is not current at the local paired-clock observation.
    #[error("broker plan is outside its validity interval")]
    PlanExpired,
    /// Lease is not live after skew and safety-margin attenuation.
    #[error("ownership lease is outside its conservative validity interval")]
    LeaseExpired,
    /// Requested BOOTTIME deadline is elapsed or exceeds lease authority.
    #[error("attempt deadline exceeds conservative lease authority")]
    UnsafeDeadline,
    /// Deadline injection or the resulting body exceeded a fixed bound.
    #[error("attempt body exceeds the fixed V1 bound")]
    BodyTooLarge,
    /// Request no longer matches the immutable signed grant.
    #[error("attempt request is not committed by the signed plan")]
    PlanGrantMismatch,
    /// Exact envelope encoding rejected one bounded component.
    #[error("broker envelope encoding failed: {0}")]
    Protocol(#[from] ProtocolValidationError),
}

fn validate_method(
    signed_plan: &SignedBrokerPlan,
    method: BrokerMethod,
) -> Result<(), BrokerDispatchTemplateError> {
    let expected = match signed_plan.plan().protocol() {
        ProtocolId::HostBroker => BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME,
        ProtocolId::MountBroker => BrokerMethod::BROKER_METHOD_MOUNT_APPLY,
        ProtocolId::StorageBroker => BrokerMethod::BROKER_METHOD_STORAGE_APPLY,
        ProtocolId::NetworkBroker => BrokerMethod::BROKER_METHOD_NETWORK_APPLY,
        _ => return Err(BrokerDispatchTemplateError::MethodMismatch),
    };
    if method != expected
        || signed_plan.plan().audience().protocol() != signed_plan.plan().protocol()
    {
        return Err(BrokerDispatchTemplateError::MethodMismatch);
    }
    Ok(())
}

fn validate_descriptor_roles(
    roles: &[BrokerDescriptorRole],
) -> Result<(), BrokerDispatchTemplateError> {
    if roles.len() > MAXIMUM_PACKET_DESCRIPTORS {
        return Err(BrokerDispatchTemplateError::DescriptorTable);
    }
    for (index, role) in roles.iter().copied().enumerate() {
        if role == BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_UNSPECIFIED
            || roles[..index].contains(&role)
        {
            return Err(BrokerDispatchTemplateError::DescriptorTable);
        }
    }
    Ok(())
}

fn match_plan_grant(
    plan: &BrokerAuthorizationPlan,
    semantics: BrokerDispatchSemanticIdentityV1,
    request_bytes: u32,
    descriptor_count: u16,
) -> Result<(), BrokerDispatchTemplateError> {
    let matched = plan.grants().iter().any(|grant| {
        grant.verb() == semantics.verb
            && grant.target() == semantics.target
            && grant.argument_commitment() == semantics.argument_commitment
            && request_bytes <= grant.maximum_request_bytes()
            && descriptor_count <= grant.maximum_descriptors()
    });
    if matched {
        Ok(())
    } else {
        Err(BrokerDispatchTemplateError::PlanGrantMismatch)
    }
}

#[cfg(test)]
fn validate_context(
    template: &BrokerDispatchTemplateV1,
    lease: &SignedOwnershipLease,
) -> Result<(), BrokerDispatchAttemptError> {
    let assignment = template.signed_plan.plan().assignment();
    let lease_assignment = lease.assignment();
    if assignment.sandbox() != lease_assignment.sandbox()
        || assignment.incarnation() != lease_assignment.incarnation()
        || assignment.epoch() != lease_assignment.epoch()
        || assignment.digest() != lease_assignment.digest()
        || template.signed_plan.plan().node() != lease.node()
        || template.signed_plan.plan().ownership_authority() != lease.signer()
    {
        return Err(BrokerDispatchAttemptError::LeaseContextMismatch);
    }
    Ok(())
}

#[cfg(test)]
fn conservative_lease_deadline(
    lease: &SignedOwnershipLease,
    clock: RawPairedClockSample,
) -> Result<u64, BrokerDispatchAttemptError> {
    conservative_lease_deadline_fields(
        lease.authority_issued_seconds(),
        lease.authority_expires_seconds(),
        lease.maximum_clock_skew_seconds(),
        clock,
    )
}

#[cfg(test)]
fn conservative_lease_deadline_fields(
    authority_issued_seconds: i64,
    authority_expires_seconds: i64,
    maximum_clock_skew_seconds: u64,
    clock: RawPairedClockSample,
) -> Result<u64, BrokerDispatchAttemptError> {
    conservative_lease_deadline_scalar_fields(
        authority_issued_seconds,
        authority_expires_seconds,
        maximum_clock_skew_seconds,
        clock.wall_seconds(),
        clock.boottime_nanoseconds(),
    )
}

fn conservative_lease_deadline_scalar_fields(
    authority_issued_seconds: i64,
    authority_expires_seconds: i64,
    maximum_clock_skew_seconds: u64,
    wall_seconds: i64,
    boottime_nanoseconds: u64,
) -> Result<u64, BrokerDispatchAttemptError> {
    let skew = i64::try_from(maximum_clock_skew_seconds)
        .map_err(|_| BrokerDispatchAttemptError::LeaseExpired)?;
    let earliest = wall_seconds
        .checked_sub(skew)
        .ok_or(BrokerDispatchAttemptError::LeaseExpired)?;
    if earliest < authority_issued_seconds {
        return Err(BrokerDispatchAttemptError::LeaseExpired);
    }
    let guard = maximum_clock_skew_seconds
        .checked_add(LEASE_SAFETY_MARGIN_SECONDS)
        .and_then(|value| i64::try_from(value).ok())
        .ok_or(BrokerDispatchAttemptError::LeaseExpired)?;
    let remaining = authority_expires_seconds
        .checked_sub(guard)
        .and_then(|end| end.checked_sub(wall_seconds))
        .filter(|remaining| *remaining > 0)
        .and_then(|remaining| u64::try_from(remaining).ok())
        .and_then(|remaining| remaining.checked_mul(NANOS_PER_SECOND))
        .ok_or(BrokerDispatchAttemptError::LeaseExpired)?;
    boottime_nanoseconds
        .checked_add(remaining)
        .ok_or(BrokerDispatchAttemptError::LeaseExpired)
}

fn template_digest(
    signed_plan: &SignedBrokerPlan,
    method: BrokerMethod,
    body: &[u8],
    roles: &[BrokerDescriptorRole],
    semantics: BrokerDispatchSemanticIdentityV1,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(TEMPLATE_DOMAIN);
    digest.update(signed_plan.digest().as_bytes());
    digest.update(
        u64::try_from(signed_plan.canonical_signature().len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    digest.update(signed_plan.canonical_signature());
    digest.update((method as i32).to_be_bytes());
    digest.update(semantics.verb.get().to_be_bytes());
    encode_target(&mut digest, semantics.target);
    digest.update(semantics.argument_commitment.digest().as_bytes());
    digest.update(u64::try_from(body.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(body);
    digest.update(u16::try_from(roles.len()).unwrap_or(u16::MAX).to_be_bytes());
    for role in roles {
        digest.update((*role as i32).to_be_bytes());
    }
    ObjectDigest::from_bytes(digest.finalize().into())
}

pub(crate) fn semantic_identity_digest(
    semantics: BrokerDispatchSemanticIdentityV1,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(SEMANTIC_IDENTITY_DOMAIN);
    digest.update(semantics.verb.get().to_be_bytes());
    encode_target(&mut digest, semantics.target);
    digest.update(semantics.argument_commitment.digest().as_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn encode_target(digest: &mut Sha256, target: BrokerGrantTarget) {
    match target {
        BrokerGrantTarget::Assignment => digest.update([1]),
        BrokerGrantTarget::Resource(handle) => {
            digest.update([2]);
            digest.update(handle.as_bytes());
        }
        BrokerGrantTarget::ResourcePair {
            previous,
            successor,
        } => {
            digest.update([3]);
            digest.update(previous.as_bytes());
            digest.update(successor.as_bytes());
        }
    }
}

fn locate_deadline_free_header(body: &[u8]) -> Result<(usize, usize), BrokerDispatchTemplateError> {
    if body.first() != Some(&0x0a) {
        return Err(BrokerDispatchTemplateError::InvalidBody);
    }
    let (length, length_bytes) = decode_varint(&body[1..])?;
    let start = 1_usize
        .checked_add(length_bytes)
        .ok_or(BrokerDispatchTemplateError::InvalidBody)?;
    let length = usize::try_from(length).map_err(|_| BrokerDispatchTemplateError::InvalidBody)?;
    let end = start
        .checked_add(length)
        .filter(|end| *end <= body.len())
        .ok_or(BrokerDispatchTemplateError::InvalidBody)?;
    validate_header_fields(&body[start..end])?;
    validate_remaining_body_fields(&body[end..])?;
    Ok((start, end))
}

pub(crate) fn validate_durable_deadline_free_body(body: &[u8]) -> bool {
    body.len()
        .checked_add(MAXIMUM_DEADLINE_FIELD_BYTES)
        .is_some_and(|size| size <= MAXIMUM_REQUEST_BYTES)
        && locate_deadline_free_header(body).is_ok()
}

fn validate_remaining_body_fields(bytes: &[u8]) -> Result<(), BrokerDispatchTemplateError> {
    let mut cursor = 0;
    while cursor < bytes.len() {
        let (key, key_bytes) = decode_varint(&bytes[cursor..])?;
        if key >> 3 == 0 || key >> 3 == 1 {
            return Err(BrokerDispatchTemplateError::InvalidBody);
        }
        cursor = cursor
            .checked_add(key_bytes)
            .ok_or(BrokerDispatchTemplateError::InvalidBody)?;
        cursor = skip_wire_value(bytes, cursor, key & 7)?;
    }
    Ok(())
}

fn validate_header_fields(header: &[u8]) -> Result<(), BrokerDispatchTemplateError> {
    let mut cursor = 0;
    while cursor < header.len() {
        let (key, key_bytes) = decode_varint(&header[cursor..])?;
        cursor = cursor
            .checked_add(key_bytes)
            .ok_or(BrokerDispatchTemplateError::InvalidBody)?;
        if key >> 3 == 0 || key >> 3 == 5 {
            return Err(BrokerDispatchTemplateError::InvalidBody);
        }
        cursor = skip_wire_value(header, cursor, key & 7)?;
    }
    Ok(())
}

fn skip_wire_value(
    bytes: &[u8],
    cursor: usize,
    wire: u64,
) -> Result<usize, BrokerDispatchTemplateError> {
    match wire {
        0 => decode_varint(&bytes[cursor..])?
            .1
            .checked_add(cursor)
            .ok_or(BrokerDispatchTemplateError::InvalidBody),
        1 => cursor
            .checked_add(8)
            .filter(|end| *end <= bytes.len())
            .ok_or(BrokerDispatchTemplateError::InvalidBody),
        2 => {
            let (length, length_bytes) = decode_varint(&bytes[cursor..])?;
            cursor
                .checked_add(length_bytes)
                .and_then(|start| start.checked_add(usize::try_from(length).ok()?))
                .filter(|end| *end <= bytes.len())
                .ok_or(BrokerDispatchTemplateError::InvalidBody)
        }
        5 => cursor
            .checked_add(4)
            .filter(|end| *end <= bytes.len())
            .ok_or(BrokerDispatchTemplateError::InvalidBody),
        _ => Err(BrokerDispatchTemplateError::InvalidBody),
    }
}

fn inject_deadline(body: &[u8], deadline: u64) -> Result<Vec<u8>, BrokerDispatchAttemptError> {
    let (header_start, header_end) =
        locate_deadline_free_header(body).map_err(|_| BrokerDispatchAttemptError::BodyTooLarge)?;
    let mut deadline_bytes = [0_u8; 10];
    let deadline_length = encode_varint(deadline, &mut deadline_bytes);
    let header_length = header_end - header_start;
    let new_header_length = header_length
        .checked_add(1 + deadline_length)
        .ok_or(BrokerDispatchAttemptError::BodyTooLarge)?;
    let mut header_length_bytes = [0_u8; 10];
    let header_length_count = encode_varint(
        u64::try_from(new_header_length).map_err(|_| BrokerDispatchAttemptError::BodyTooLarge)?,
        &mut header_length_bytes,
    );
    let capacity = body
        .len()
        .checked_add(MAXIMUM_DEADLINE_FIELD_BYTES)
        .ok_or(BrokerDispatchAttemptError::BodyTooLarge)?;
    let mut result = Vec::with_capacity(capacity);
    result.push(0x0a);
    result.extend_from_slice(&header_length_bytes[..header_length_count]);
    result.extend_from_slice(&body[header_start..header_end]);
    result.push(0x28);
    result.extend_from_slice(&deadline_bytes[..deadline_length]);
    result.extend_from_slice(&body[header_end..]);
    Ok(result)
}

fn decode_varint(bytes: &[u8]) -> Result<(u64, usize), BrokerDispatchTemplateError> {
    let mut value = 0_u64;
    for (index, byte) in bytes.iter().copied().take(10).enumerate() {
        let shift =
            u32::try_from(index * 7).map_err(|_| BrokerDispatchTemplateError::InvalidBody)?;
        if index == 9 && byte > 1 {
            return Err(BrokerDispatchTemplateError::InvalidBody);
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            if index > 0 && byte == 0 {
                return Err(BrokerDispatchTemplateError::InvalidBody);
            }
            return Ok((value, index + 1));
        }
    }
    Err(BrokerDispatchTemplateError::InvalidBody)
}

fn encode_varint(mut value: u64, output: &mut [u8; 10]) -> usize {
    let mut index = 0;
    loop {
        output[index] = (value as u8) & 0x7f;
        value >>= 7;
        if value == 0 {
            return index + 1;
        }
        output[index] |= 0x80;
        index += 1;
    }
}

#[cfg(test)]
mod tests {
    use aos_sandbox_core::format::{encode_ownership_lease, encode_signature, encode_trust_policy};
    use aos_sandbox_core::model::{
        KeyReference, KeyUsage, SignaturePurpose, SignatureStatement, StableKeyId, TrustPolicy,
    };
    use aos_sandbox_core::{
        AssignmentEpoch, BrokerAssignment, BrokerAudience, BrokerGrant, DecodeLimits,
        DesiredGeneration, IncarnationId, LeaseAssignment, MediaType, NodeId, OwnershipLease,
        OwnershipLeaseTrustAnchor, PortableMediaType, ProtocolVersion, RevocationScopeId,
        SandboxId, TrustScopeId, descriptor_for_bytes, sign_statement,
    };
    use aos_sandbox_protocol::decode_request_envelope;
    use ed25519_dalek::SigningKey;

    use crate::{
        BrokerPlanPreparation, OwnershipAuthorityVerifier, OwnershipClaimV1,
        OwnershipTransactionReceiptV1, ReturnedSignature, SigningAuthority,
        UnverifiedOwnershipLeaseResponse,
    };

    use super::*;

    struct Fixture {
        template: BrokerDispatchTemplateV1,
        assignment: BrokerAssignment,
        node: NodeId,
        lease_key: SigningKey,
        lease_authority: KeyReference,
        lease_scope: TrustScopeId,
        lease_policy_descriptor: aos_sandbox_core::ObjectDescriptor,
        lease_verifier: OwnershipAuthorityVerifier,
    }

    fn key_reference(name: &str, usage: KeyUsage, key: &SigningKey) -> KeyReference {
        KeyReference::new(
            StableKeyId::new(name.to_owned())
                .unwrap_or_else(|error| panic!("test key ID failed: {error}")),
            1,
            ObjectDigest::from_bytes(Sha256::digest(key.verifying_key().as_bytes()).into()),
            usage,
        )
    }

    fn signing_authority(key: &SigningKey) -> SigningAuthority {
        let signer = key_reference("controller", KeyUsage::BrokerAuthorization, key);
        let scope = TrustScopeId::from_bytes([21; 16]);
        let policy = TrustPolicy::new(
            scope,
            SignaturePurpose::BrokerAuthorization,
            vec![signer.clone()],
            Vec::new(),
        )
        .unwrap_or_else(|error| panic!("test policy failed: {error}"));
        let canonical_policy = encode_trust_policy(&policy);
        let media_type = MediaType::new(PortableMediaType::TrustPolicy.as_str().to_owned())
            .unwrap_or_else(|error| panic!("test media type failed: {error}"));
        let descriptor = descriptor_for_bytes(media_type, &canonical_policy);
        SigningAuthority::new(
            canonical_policy,
            descriptor,
            scope,
            signer,
            key.verifying_key().to_bytes(),
            SignaturePurpose::BrokerAuthorization,
            aos_sandbox_core::DecodeLimits::default(),
        )
        .unwrap_or_else(|error| panic!("test authority failed: {error}"))
    }

    fn fixture() -> Fixture {
        let key = SigningKey::from_bytes(&[42; 32]);
        let lease_key = SigningKey::from_bytes(&[43; 32]);
        let lease_authority =
            key_reference("ownership-authority", KeyUsage::OwnershipLease, &lease_key);
        let assignment = BrokerAssignment::new(
            SandboxId::from_bytes([1; 16]),
            IncarnationId::from_bytes([2; 16]),
            AssignmentEpoch::new(3),
            DesiredGeneration::new(4),
            ObjectDigest::from_bytes([5; 32]),
        )
        .unwrap_or_else(|error| panic!("test assignment failed: {error}"));
        let node = NodeId::from_bytes([6; 16]);
        let commitment = BrokerArgumentCommitment::for_canonical_bytes(b"mount-create");
        let semantics = BrokerDispatchSemanticIdentityV1::new(
            BrokerVerb::MountCreate,
            BrokerGrantTarget::Assignment,
            commitment,
        );
        let plan = aos_sandbox_core::BrokerAuthorizationPlan::new(
            BrokerAudience::Mount,
            ProtocolId::MountBroker,
            ProtocolVersion::new(1, 0),
            assignment,
            node,
            lease_authority.clone(),
            vec![
                BrokerGrant::new(
                    semantics.verb(),
                    semantics.target(),
                    semantics.argument_commitment(),
                    4096,
                    2,
                )
                .unwrap_or_else(|error| panic!("test grant failed: {error}")),
            ],
            ObjectDigest::from_bytes([8; 32]),
            RevocationScopeId::from_bytes([9; 16]),
            100,
            200,
            Vec::new(),
        )
        .unwrap_or_else(|error| panic!("test plan failed: {error}"));
        let preparation = BrokerPlanPreparation::new(plan, signing_authority(&key))
            .unwrap_or_else(|error| panic!("test preparation failed: {error}"));
        let signature = sign_statement(preparation.signing_request().statement().clone(), &key)
            .unwrap_or_else(|error| panic!("test signing failed: {error}"));
        let lease_scope = TrustScopeId::from_bytes([31; 16]);
        let lease_policy = TrustPolicy::new(
            lease_scope,
            SignaturePurpose::OwnershipLease,
            vec![lease_authority.clone()],
            Vec::new(),
        )
        .unwrap_or_else(|error| panic!("test lease policy failed: {error}"));
        let lease_policy_bytes = encode_trust_policy(&lease_policy);
        let lease_policy_descriptor = descriptor_for_bytes(
            MediaType::new(PortableMediaType::TrustPolicy.as_str().to_owned())
                .unwrap_or_else(|error| panic!("test policy media type failed: {error}")),
            &lease_policy_bytes,
        );
        let lease_anchor = OwnershipLeaseTrustAnchor::from_trusted_configuration(
            lease_policy_bytes,
            lease_policy_descriptor.clone(),
            lease_scope,
            lease_authority.clone(),
            lease_key.verifying_key().to_bytes(),
            DecodeLimits::default(),
        )
        .unwrap_or_else(|error| panic!("test lease anchor failed: {error}"));
        let lease_verifier = OwnershipAuthorityVerifier::new(lease_anchor, lease_authority.clone());
        let signed_plan = preparation
            .complete(ReturnedSignature::Bytes(signature.signature()), 150)
            .unwrap_or_else(|error| panic!("test completion failed: {error}"));

        // Field 1 is a deadline-free common header; field 2 stands for the
        // remainder of the method body and must survive injection byte-exactly.
        let body = vec![0x0a, 0x02, 0x08, 0x01, 0x12, 0x02, 0xaa, 0xbb];
        let template = BrokerDispatchTemplateV1::new(
            signed_plan,
            BrokerMethod::BROKER_METHOD_MOUNT_APPLY,
            body,
            vec![BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_TARGET_ROOT],
            semantics,
        )
        .unwrap_or_else(|error| panic!("test template failed: {error}"));
        Fixture {
            template,
            assignment,
            node,
            lease_key,
            lease_authority,
            lease_scope,
            lease_policy_descriptor,
            lease_verifier,
        }
    }

    fn lease_for(
        fixture: &Fixture,
        assignment: BrokerAssignment,
        node: NodeId,
        generation: u64,
        expiry: i64,
    ) -> SignedOwnershipLease {
        let lease_assignment = LeaseAssignment::new(
            assignment.sandbox(),
            assignment.incarnation(),
            assignment.epoch(),
            assignment.digest(),
        )
        .unwrap_or_else(|error| panic!("test lease assignment failed: {error}"));
        let lease = OwnershipLease::new(
            lease_assignment,
            node,
            generation,
            110,
            expiry,
            5,
            [u8::try_from(generation).unwrap_or(u8::MAX); 16],
        )
        .unwrap_or_else(|error| panic!("test lease failed: {error}"));
        let lease_bytes = encode_ownership_lease(&lease);
        let lease_descriptor = descriptor_for_bytes(
            MediaType::new(PortableMediaType::OwnershipLease.as_str().to_owned())
                .unwrap_or_else(|error| panic!("test lease media type failed: {error}")),
            &lease_bytes,
        );
        let lease_statement = SignatureStatement::new(
            lease_descriptor,
            fixture.lease_scope,
            fixture.lease_authority.clone(),
            SignaturePurpose::OwnershipLease,
            110,
            Some(expiry),
            fixture.lease_policy_descriptor.clone(),
        )
        .unwrap_or_else(|error| panic!("test lease statement failed: {error}"));
        let lease_signature = sign_statement(lease_statement, &fixture.lease_key)
            .unwrap_or_else(|error| panic!("test lease signature failed: {error}"));
        let claim = OwnershipClaimV1::acquire(
            [u8::try_from(generation).unwrap_or(u8::MAX).max(1); 16],
            lease_assignment,
            assignment.desired_generation(),
            node,
            100,
        )
        .unwrap_or_else(|error| panic!("test ownership claim failed: {error}"));
        let receipt = OwnershipTransactionReceiptV1::new(
            fixture.lease_authority.clone(),
            &claim,
            &lease_bytes,
        )
        .unwrap_or_else(|error| panic!("test ownership receipt failed: {error}"));
        let receipt_descriptor = descriptor_for_bytes(
            MediaType::new(
                PortableMediaType::OwnershipTransactionReceipt
                    .as_str()
                    .to_owned(),
            )
            .unwrap_or_else(|error| panic!("test receipt media type failed: {error}")),
            receipt.canonical_bytes(),
        );
        let receipt_statement = SignatureStatement::new(
            receipt_descriptor,
            fixture.lease_scope,
            fixture.lease_authority.clone(),
            SignaturePurpose::OwnershipLease,
            110,
            Some(expiry),
            fixture.lease_policy_descriptor.clone(),
        )
        .unwrap_or_else(|error| panic!("test receipt statement failed: {error}"));
        let receipt_signature = sign_statement(receipt_statement, &fixture.lease_key)
            .unwrap_or_else(|error| panic!("test receipt signature failed: {error}"));
        let response = UnverifiedOwnershipLeaseResponse::from_transport(
            lease_bytes,
            encode_signature(&lease_signature),
            receipt.canonical_bytes().to_vec(),
            encode_signature(&receipt_signature),
        )
        .unwrap_or_else(|error| panic!("test response failed: {error}"));
        fixture
            .lease_verifier
            .verify_response(&claim, response, &clock(150, 1_000))
            .unwrap_or_else(|error| panic!("test response verification failed: {error}"))
    }

    fn lease(fixture: &Fixture, generation: u64, expiry: i64) -> SignedOwnershipLease {
        lease_for(
            fixture,
            fixture.assignment,
            fixture.node,
            generation,
            expiry,
        )
    }

    fn clock(wall: i64, boottime: u64) -> RawPairedClockSample {
        RawPairedClockSample::new_untrusted(
            aos_sandbox_core::RawClockProvenance::new_untrusted([7; 16])
                .unwrap_or_else(|error| panic!("test provenance failed: {error}")),
            [8; 16],
            wall,
            boottime,
        )
        .unwrap_or_else(|error| panic!("test clock failed: {error}"))
    }

    #[test]
    fn renewal_reuses_template_but_binds_exact_lease_artifacts() {
        let fixture = fixture();
        let first = lease(&fixture, 1, 190);
        let renewed = lease(&fixture, 2, 195);
        let attempt_one =
            BrokerDispatchAttemptV1::new(&fixture.template, &first, 2_000, clock(150, 1_000))
                .unwrap_or_else(|error| panic!("first attempt failed: {error}"));
        let attempt_two =
            BrokerDispatchAttemptV1::new(&fixture.template, &renewed, 3_000, clock(150, 1_000))
                .unwrap_or_else(|error| panic!("renewed attempt failed: {error}"));

        assert_eq!(attempt_one.template_digest(), attempt_two.template_digest());
        assert_ne!(attempt_one.lease_digest(), attempt_two.lease_digest());
        assert_ne!(attempt_one.packet(), attempt_two.packet());
        assert_eq!(
            fixture.template.body_without_deadline(),
            [0x0a, 0x02, 0x08, 0x01, 0x12, 0x02, 0xaa, 0xbb]
        );
        assert_eq!(
            &attempt_one.body()[..6],
            [0x0a, 0x05, 0x08, 0x01, 0x28, 0xd0]
        );
        assert!(attempt_one.body().ends_with(&[0x12, 0x02, 0xaa, 0xbb]));
    }

    #[test]
    fn packet_preserves_all_four_canonical_authority_artifacts() {
        let fixture = fixture();
        let lease = lease(&fixture, 1, 190);
        let attempt =
            BrokerDispatchAttemptV1::new(&fixture.template, &lease, 2_000, clock(150, 1_000))
                .unwrap_or_else(|error| panic!("attempt failed: {error}"));
        let decoded = decode_request_envelope(attempt.packet(), ProtocolId::MountBroker, 1)
            .unwrap_or_else(|error| panic!("packet decode failed: {error}"));
        let artifacts = decoded
            .authorization()
            .unwrap_or_else(|| panic!("missing artifacts"));
        assert_eq!(
            artifacts.broker_plan(),
            fixture.template.signed_plan().canonical_plan()
        );
        assert_eq!(
            artifacts.broker_plan_signature(),
            fixture.template.signed_plan().canonical_signature()
        );
        assert_eq!(artifacts.ownership_lease(), lease.canonical_lease());
        assert_eq!(
            artifacts.ownership_lease_signature(),
            lease.canonical_signature()
        );
        assert_eq!(decoded.body(), attempt.body());
    }

    #[test]
    fn substitutions_change_identity_or_fail_closed() {
        let fixture = fixture();
        let body_changed = BrokerDispatchTemplateV1::new(
            fixture.template.signed_plan().clone(),
            fixture.template.method(),
            vec![0x0a, 0x02, 0x08, 0x01, 0x12, 0x01, 0xcc],
            fixture.template.descriptor_roles().to_vec(),
            fixture.template.semantics(),
        )
        .unwrap_or_else(|error| panic!("changed-body template failed: {error}"));
        let roles_changed = BrokerDispatchTemplateV1::new(
            fixture.template.signed_plan().clone(),
            fixture.template.method(),
            fixture.template.body_without_deadline().to_vec(),
            Vec::new(),
            fixture.template.semantics(),
        )
        .unwrap_or_else(|error| panic!("changed-roles template failed: {error}"));
        assert_ne!(body_changed.digest(), fixture.template.digest());
        assert_ne!(roles_changed.digest(), fixture.template.digest());

        assert_eq!(
            BrokerDispatchTemplateV1::new(
                fixture.template.signed_plan().clone(),
                BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME,
                fixture.template.body_without_deadline().to_vec(),
                fixture.template.descriptor_roles().to_vec(),
                fixture.template.semantics(),
            ),
            Err(BrokerDispatchTemplateError::MethodMismatch)
        );
        let wrong_semantics = BrokerDispatchSemanticIdentityV1::new(
            BrokerVerb::MountInstall,
            BrokerGrantTarget::Resource(
                aos_sandbox_core::BrokerResourceHandle::from_bytes([44; 32])
                    .unwrap_or_else(|error| panic!("test handle failed: {error}")),
            ),
            fixture.template.semantics().argument_commitment(),
        );
        assert_eq!(
            BrokerDispatchTemplateV1::new(
                fixture.template.signed_plan().clone(),
                fixture.template.method(),
                fixture.template.body_without_deadline().to_vec(),
                fixture.template.descriptor_roles().to_vec(),
                wrong_semantics,
            ),
            Err(BrokerDispatchTemplateError::PlanGrantMismatch)
        );
    }

    #[test]
    fn template_does_not_misrepresent_controller_semantics_as_body_proof() {
        let fixture = fixture();
        // This is valid generic protobuf framing but not a valid ApplyMount
        // request. Construction may freeze it and correlate the controller's
        // asserted grant, but only broker-side typed decoding can reject it.
        let hostile_body = vec![0x0a, 0x02, 0x08, 0x01, 0x12, 0x01, 0xff];
        let template = BrokerDispatchTemplateV1::new(
            fixture.template.signed_plan().clone(),
            fixture.template.method(),
            hostile_body.clone(),
            fixture.template.descriptor_roles().to_vec(),
            fixture.template.semantics(),
        )
        .unwrap_or_else(|error| panic!("non-authorizing template failed: {error}"));

        assert_eq!(template.body_without_deadline(), hostile_body);
        assert_ne!(template.digest(), fixture.template.digest());
    }

    #[test]
    fn lease_context_expiry_and_deadline_are_fail_closed() {
        let base = fixture();
        let current = lease(&base, 1, 190);
        assert_eq!(
            BrokerDispatchAttemptV1::new(&base.template, &current, 1_000, clock(150, 1_000)),
            Err(BrokerDispatchAttemptError::UnsafeDeadline)
        );
        assert_eq!(
            BrokerDispatchAttemptV1::new(
                &base.template,
                &current,
                40_000_001_001,
                clock(150, 1_000),
            ),
            Err(BrokerDispatchAttemptError::UnsafeDeadline)
        );
        assert_eq!(
            BrokerDispatchAttemptV1::new(&base.template, &current, 2_000, clock(185, 1_000)),
            Err(BrokerDispatchAttemptError::LeaseExpired)
        );
        assert_eq!(
            BrokerDispatchAttemptV1::new(&base.template, &current, 2_000, clock(200, 1_000)),
            Err(BrokerDispatchAttemptError::PlanExpired)
        );

        let other = Fixture {
            node: NodeId::from_bytes([99; 16]),
            ..fixture()
        };
        let wrong_node = lease(&other, 1, 190);
        assert_eq!(
            BrokerDispatchAttemptV1::new(&base.template, &wrong_node, 2_000, clock(150, 1_000),),
            Err(BrokerDispatchAttemptError::LeaseContextMismatch)
        );

        let other_assignment = LeaseAssignment::new(
            SandboxId::from_bytes([98; 16]),
            base.assignment.incarnation(),
            base.assignment.epoch(),
            base.assignment.digest(),
        )
        .unwrap_or_else(|error| panic!("test other assignment failed: {error}"));
        let other_assignment = BrokerAssignment::new(
            other_assignment.sandbox(),
            other_assignment.incarnation(),
            other_assignment.epoch(),
            base.assignment.desired_generation(),
            other_assignment.digest(),
        )
        .unwrap_or_else(|error| panic!("test broker assignment failed: {error}"));
        let wrong_assignment = lease_for(&base, other_assignment, base.node, 1, 190);
        assert_eq!(
            BrokerDispatchAttemptV1::new(
                &base.template,
                &wrong_assignment,
                2_000,
                clock(150, 1_000),
            ),
            Err(BrokerDispatchAttemptError::LeaseContextMismatch)
        );
    }

    #[test]
    fn template_enforces_deadline_absence_and_fixed_bounds() {
        let fixture = fixture();
        assert_eq!(
            BrokerDispatchTemplateV1::new(
                fixture.template.signed_plan().clone(),
                fixture.template.method(),
                vec![0x0a, 0x02, 0x28, 0x01],
                Vec::new(),
                fixture.template.semantics(),
            ),
            Err(BrokerDispatchTemplateError::InvalidBody)
        );
        assert_eq!(
            BrokerDispatchTemplateV1::new(
                fixture.template.signed_plan().clone(),
                fixture.template.method(),
                vec![0x0a, 0x02, 0x08, 0x01, 0x0a, 0x02, 0x28, 0x01],
                Vec::new(),
                fixture.template.semantics(),
            ),
            Err(BrokerDispatchTemplateError::InvalidBody)
        );
        assert_eq!(
            BrokerDispatchTemplateV1::new(
                fixture.template.signed_plan().clone(),
                fixture.template.method(),
                fixture.template.body_without_deadline().to_vec(),
                vec![BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_TARGET_ROOT; 2],
                fixture.template.semantics(),
            ),
            Err(BrokerDispatchTemplateError::DescriptorTable)
        );
        let mut oversized = vec![0x0a, 0x02, 0x08, 0x01];
        oversized.resize(MAXIMUM_REQUEST_BYTES, 0);
        assert_eq!(
            BrokerDispatchTemplateV1::new(
                fixture.template.signed_plan().clone(),
                fixture.template.method(),
                oversized,
                Vec::new(),
                fixture.template.semantics(),
            ),
            Err(BrokerDispatchTemplateError::BodyTooLarge)
        );
    }
}

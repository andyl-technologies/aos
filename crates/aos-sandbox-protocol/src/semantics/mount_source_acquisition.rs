//! Canonical portable authority semantics for Mount source acquisition.
//!
//! These semantics form a nonauthorizing plan-match tuple for the validated,
//! deadline-independent meaning of an Acquire or Release request. Possession
//! of the tuple or its digest grants nothing; signed-plan, ownership-lease,
//! protected-currentness, and durable-before-I/O checks remain separate.
//!
//! Portable [`aos_sandbox_core::ObjectDescriptor`] values remain committed
//! inside the prospective Create template and source binding. No ancillary
//! Unix descriptors, descriptor roles or numbers, kernel identities, or
//! kernel objects enter this representation. Request IDs, response bounds,
//! deadlines, envelopes, provider routing, and provider sessions are likewise
//! absent.
//!
//! Every field uses `tag:u8 || length:u32be || value[length]`, fields occur
//! exactly once in increasing tag order, all integer values are fixed-width
//! big-endian, and the Boolean is one byte (`0` or `1`). The complete sequence
//! is at most 8 KiB. The action tag selects one of two closed layouts:
//!
//! ```text
//! Shared tags:
//!    1 magic[8] = "AOSMSQ01"
//!    2 version:u16be = 1
//!    3 action:u8 = Acquire(1) | Release(2)
//!    4 sandbox-id[16]
//!    5 incarnation-id[16]
//!    6 assignment-epoch:u64be
//!    7 desired-generation:u64be
//!    8 assignment-digest[32]
//!
//! Acquire-only tags:
//!    9 prospective-Create:AOSMSEM1
//!   10 prospective-Create-digest[32]
//!   11 canonical-source-binding
//!   12 source-binding-digest[32]
//!   13 requested-lease-seconds:u64be
//!   14 maximum-submounts:u32be
//!   15 kernel-coupled:u8
//!
//! Release-only tags:
//!    9 acquisition-id[32]
//!   10 expected-revision:u64be
//!   11 expected-record-digest[32]
//! ```
//!
//! Version 1 fixes the magic, tag meanings, widths, action codes, ordering,
//! and 8 KiB ceiling. Any incompatible change requires a new semantic format
//! version while retaining V1 plan matching for already admitted work.

use aos_sandbox_core::{
    BrokerArgumentCommitment, BrokerGrantTarget, BrokerResourceHandle, BrokerVerb,
};

use crate::{
    ValidatedAcquireMountSourceRequest, ValidatedAssignmentFence,
    ValidatedReleaseMountSourceAcquisitionRequest,
};

pub use crate::mount_source_acquisition::{
    LiveValidatedAcquireMountSourceRequest, LiveValidatedReleaseMountSourceAcquisitionRequest,
};

const FORMAT_MAGIC: &[u8; 8] = b"AOSMSQ01";
const FORMAT_VERSION: u16 = 1;
const MAXIMUM_CANONICAL_BYTES: usize = 8 * 1024;

/// Reports a source-acquisition request without one canonical grant meaning.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum MountSourceAcquisitionSemanticError {
    /// The request cannot name its required assignment or resource target.
    #[error("Mount source-acquisition target semantics are invalid")]
    InvalidTarget,
    /// The canonical representation exceeded its fixed bound.
    #[error("Mount source-acquisition canonical semantics exceed the V1 bound")]
    EncodingTooLarge,
}

/// Carries exact canonical semantics and a nonauthorizing plan-match tuple.
///
/// The verb, target, and commitment are inputs to later signed authority
/// verification. This value alone is never effect authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalMountSourceAcquisitionSemanticsV1 {
    bytes: Vec<u8>,
    commitment: BrokerArgumentCommitment,
    verb: BrokerVerb,
    target: BrokerGrantTarget,
}

impl CanonicalMountSourceAcquisitionSemanticsV1 {
    /// Returns the exact portable bytes committed by the argument digest.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the domain-separated broker argument commitment.
    #[must_use]
    pub const fn commitment(&self) -> BrokerArgumentCommitment {
        self.commitment
    }

    /// Returns the closed Mount source-acquisition semantic verb.
    #[must_use]
    pub const fn verb(&self) -> BrokerVerb {
        self.verb
    }

    /// Returns the assignment or exact acquisition-resource grant target.
    #[must_use]
    pub const fn target(&self) -> BrokerGrantTarget {
        self.target
    }
}

/// Canonicalizes one validated Mount source Acquire request for plan matching.
///
/// The assignment-wide grant commits the exact pre-catalog Create template,
/// canonical logical source binding, and requested provider bounds. It does
/// not commit the outer request header or any provider-selected state.
///
/// # Errors
///
/// Returns [`MountSourceAcquisitionSemanticError`] if the canonical encoding
/// exceeds its fixed V1 bound.
pub fn canonical_acquire_mount_source_semantics_v1(
    request: &ValidatedAcquireMountSourceRequest,
) -> Result<CanonicalMountSourceAcquisitionSemanticsV1, MountSourceAcquisitionSemanticError> {
    let mut encoder = Encoder::new();
    encode_prefix(&mut encoder, 1, request.fence())?;
    encoder.field(9, request.prospective_mount_template())?;
    encoder.field(10, request.prospective_mount_template_digest().as_bytes())?;

    let source_binding = request.source_binding().canonical_bytes();
    encoder.field(11, &source_binding)?;
    encoder.field(12, request.source_binding().digest().as_bytes())?;
    encoder.field(13, &request.requested_lease_seconds().to_be_bytes())?;
    encoder.field(14, &request.requested_maximum_submounts().to_be_bytes())?;
    encoder.field(15, &[u8::from(request.kernel_coupled())])?;

    Ok(CanonicalMountSourceAcquisitionSemanticsV1::new(
        encoder.finish(),
        BrokerVerb::MountAcquireSource,
        BrokerGrantTarget::Assignment,
    ))
}

/// Canonicalizes one validated Mount source Release request for plan matching.
///
/// The resource-scoped grant commits the current teardown fence and the exact
/// predecessor revision and record digest. It cannot redirect provider state
/// or release a different acquisition.
///
/// # Errors
///
/// Returns [`MountSourceAcquisitionSemanticError`] if the acquisition ID
/// cannot name a resource or the encoding exceeds its fixed V1 bound.
pub fn canonical_release_mount_source_acquisition_semantics_v1(
    request: &ValidatedReleaseMountSourceAcquisitionRequest,
) -> Result<CanonicalMountSourceAcquisitionSemanticsV1, MountSourceAcquisitionSemanticError> {
    let acquisition_id = *request.acquisition_id().as_bytes();
    let resource = BrokerResourceHandle::from_bytes(acquisition_id)
        .map_err(|_| MountSourceAcquisitionSemanticError::InvalidTarget)?;

    let mut encoder = Encoder::new();
    encode_prefix(&mut encoder, 2, request.fence())?;
    encoder.field(9, &acquisition_id)?;
    encoder.field(10, &request.expected_revision().to_be_bytes())?;
    encoder.field(11, request.expected_record_digest().as_bytes())?;

    Ok(CanonicalMountSourceAcquisitionSemanticsV1::new(
        encoder.finish(),
        BrokerVerb::MountReleaseSourceAcquisition,
        BrokerGrantTarget::Resource(resource),
    ))
}

impl CanonicalMountSourceAcquisitionSemanticsV1 {
    fn new(bytes: Vec<u8>, verb: BrokerVerb, target: BrokerGrantTarget) -> Self {
        Self {
            commitment: BrokerArgumentCommitment::for_canonical_bytes(&bytes),
            bytes,
            verb,
            target,
        }
    }
}

fn encode_prefix(
    encoder: &mut Encoder,
    action_code: u8,
    fence: &ValidatedAssignmentFence,
) -> Result<(), MountSourceAcquisitionSemanticError> {
    encoder.field(1, FORMAT_MAGIC)?;
    encoder.field(2, &FORMAT_VERSION.to_be_bytes())?;
    encoder.field(3, &[action_code])?;
    encoder.field(4, fence.sandbox_id())?;
    encoder.field(5, fence.incarnation_id())?;
    encoder.field(6, &fence.assignment_epoch().to_be_bytes())?;
    encoder.field(7, &fence.desired_generation().to_be_bytes())?;
    encoder.field(8, fence.assignment_digest())
}

struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    fn new() -> Self {
        Self {
            bytes: Vec::with_capacity(3 * 1024),
        }
    }

    fn field(&mut self, tag: u8, value: &[u8]) -> Result<(), MountSourceAcquisitionSemanticError> {
        let length = u32::try_from(value.len())
            .map_err(|_| MountSourceAcquisitionSemanticError::EncodingTooLarge)?;
        let next = self
            .bytes
            .len()
            .checked_add(5)
            .and_then(|size| size.checked_add(value.len()))
            .filter(|size| *size <= MAXIMUM_CANONICAL_BYTES)
            .ok_or(MountSourceAcquisitionSemanticError::EncodingTooLarge)?;
        self.bytes.reserve(next - self.bytes.len());
        self.bytes.push(tag);
        self.bytes.extend_from_slice(&length.to_be_bytes());
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

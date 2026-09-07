//! Canonical portable authority semantics for destination-slot effects.
//!
//! The signed commitment includes only validated portable identities and the
//! immutable specification descriptor. Canonical specification bytes remain
//! bound by that descriptor but are not duplicated into the plan grant.

use aos_proto::aos::sandbox::local::v1::DestinationSlotAction;
use aos_sandbox_core::{
    BrokerArgumentCommitment, BrokerGrantTarget, BrokerResourceHandle, BrokerVerb,
};

use crate::mount_destination_slot::ValidatedDestinationSlotRequest;

const FORMAT_MAGIC: &[u8; 8] = b"AOSDSEM1";
const FORMAT_VERSION: u16 = 1;
const MAXIMUM_CANONICAL_BYTES: usize = 1024;

/// Reports a destination-slot request without one canonical grant meaning.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DestinationSlotSemanticError {
    /// The action or generation-fenced target is invalid.
    #[error("destination-slot action target semantics are invalid")]
    InvalidTarget,
    /// The canonical representation exceeded its fixed bound.
    #[error("destination-slot canonical semantics exceed the V1 bound")]
    EncodingTooLarge,
}

/// Carries exact canonical semantics and the resulting signed grant tuple.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalDestinationSlotSemanticsV1 {
    bytes: Vec<u8>,
    commitment: BrokerArgumentCommitment,
    verb: BrokerVerb,
    target: BrokerGrantTarget,
}

impl CanonicalDestinationSlotSemanticsV1 {
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

    /// Returns the closed destination-slot semantic verb.
    #[must_use]
    pub const fn verb(&self) -> BrokerVerb {
        self.verb
    }

    /// Returns the assignment or exact ready-resource grant target.
    #[must_use]
    pub const fn target(&self) -> BrokerGrantTarget {
        self.target
    }
}

/// Canonicalizes one validated destination-slot request for plan matching.
///
/// # Errors
///
/// Returns [`DestinationSlotSemanticError`] for an invalid action/target shape
/// or an internal canonical encoding bound violation.
pub fn canonical_destination_slot_semantics_v1(
    request: &ValidatedDestinationSlotRequest,
) -> Result<CanonicalDestinationSlotSemanticsV1, DestinationSlotSemanticError> {
    let (verb, target, action_code) = action_semantics(request)?;
    let descriptor = request.sandbox_spec();

    let mut encoder = Encoder::new();
    encoder.field(1, FORMAT_MAGIC)?;
    encoder.field(2, &FORMAT_VERSION.to_be_bytes())?;
    encoder.field(3, &[action_code])?;
    encoder.field(4, request.fence().sandbox_id())?;
    encoder.field(5, request.fence().incarnation_id())?;
    encoder.field(6, &request.fence().assignment_epoch().to_be_bytes())?;
    encoder.field(7, &request.fence().desired_generation().to_be_bytes())?;
    encoder.field(8, request.fence().assignment_digest())?;
    encoder.field(9, &request.namespace_generation().to_be_bytes())?;
    encoder.field(10, request.destination_slot_id())?;
    encoder.descriptor(11, descriptor)?;
    encoder.field(
        12,
        request
            .expected_resource_digest()
            .map_or(&[][..], <[u8; 32]>::as_slice),
    )?;
    encoder.field(13, &[u8::from(request.resource_fence().is_some())])?;
    if let Some(resource_fence) = request.resource_fence() {
        encoder.field(14, resource_fence.sandbox_id())?;
        encoder.field(15, resource_fence.incarnation_id())?;
        encoder.field(16, &resource_fence.assignment_epoch().to_be_bytes())?;
        encoder.field(17, &resource_fence.desired_generation().to_be_bytes())?;
        encoder.field(18, resource_fence.assignment_digest())?;
    }
    let bytes = encoder.finish();

    Ok(CanonicalDestinationSlotSemanticsV1 {
        commitment: BrokerArgumentCommitment::for_canonical_bytes(&bytes),
        bytes,
        verb,
        target,
    })
}

fn action_semantics(
    request: &ValidatedDestinationSlotRequest,
) -> Result<(BrokerVerb, BrokerGrantTarget, u8), DestinationSlotSemanticError> {
    match request.action() {
        DestinationSlotAction::DESTINATION_SLOT_ACTION_MATERIALIZE => Ok((
            BrokerVerb::MountMaterializeDestinationSlot,
            BrokerGrantTarget::Assignment,
            1,
        )),
        DestinationSlotAction::DESTINATION_SLOT_ACTION_REAP => {
            let resource = request
                .expected_resource_digest()
                .copied()
                .ok_or(DestinationSlotSemanticError::InvalidTarget)
                .and_then(|digest| {
                    BrokerResourceHandle::from_bytes(digest)
                        .map_err(|_| DestinationSlotSemanticError::InvalidTarget)
                })?;
            Ok((
                BrokerVerb::MountReapDestinationSlot,
                BrokerGrantTarget::Resource(resource),
                2,
            ))
        }
        DestinationSlotAction::DESTINATION_SLOT_ACTION_REMATERIALIZE => {
            let resource = request
                .expected_resource_digest()
                .copied()
                .ok_or(DestinationSlotSemanticError::InvalidTarget)
                .and_then(|digest| {
                    BrokerResourceHandle::from_bytes(digest)
                        .map_err(|_| DestinationSlotSemanticError::InvalidTarget)
                })?;
            Ok((
                BrokerVerb::MountRematerializeDestinationSlot,
                BrokerGrantTarget::Resource(resource),
                3,
            ))
        }
        DestinationSlotAction::DESTINATION_SLOT_ACTION_UNSPECIFIED => {
            Err(DestinationSlotSemanticError::InvalidTarget)
        }
    }
}

struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    fn new() -> Self {
        Self {
            bytes: Vec::with_capacity(384),
        }
    }

    fn field(&mut self, tag: u8, value: &[u8]) -> Result<(), DestinationSlotSemanticError> {
        let length = u32::try_from(value.len())
            .map_err(|_| DestinationSlotSemanticError::EncodingTooLarge)?;
        let next = self
            .bytes
            .len()
            .checked_add(5)
            .and_then(|size| size.checked_add(value.len()))
            .filter(|size| *size <= MAXIMUM_CANONICAL_BYTES)
            .ok_or(DestinationSlotSemanticError::EncodingTooLarge)?;
        self.bytes.reserve(next - self.bytes.len());
        self.bytes.push(tag);
        self.bytes.extend_from_slice(&length.to_be_bytes());
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn descriptor(
        &mut self,
        tag: u8,
        descriptor: &aos_sandbox_core::ObjectDescriptor,
    ) -> Result<(), DestinationSlotSemanticError> {
        let media_type = descriptor.media_type().as_str().as_bytes();
        let media_length = u16::try_from(media_type.len())
            .map_err(|_| DestinationSlotSemanticError::EncodingTooLarge)?;
        let mut value = Vec::with_capacity(2 + media_type.len() + 40);
        value.extend_from_slice(&media_length.to_be_bytes());
        value.extend_from_slice(media_type);
        value.extend_from_slice(descriptor.digest().as_bytes());
        value.extend_from_slice(&descriptor.encoded_size().to_be_bytes());
        self.field(tag, &value)
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

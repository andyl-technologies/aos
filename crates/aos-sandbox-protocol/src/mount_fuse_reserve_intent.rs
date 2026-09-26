//! Validates the dormant FUSE 3.0 Controller desired-state cut.
//!
//! The request embeds one exact canonical v2 Attachment intent and names its
//! protected record, namespace allocation, and Host payload scope:
//!
//! ```text
//! RequestHeader(3.0) | AssignmentFence | AttachmentIntent(CBOR v2, FUSE) |
//! AOSATD02 digest | namespace target generation/allocation digest |
//! deterministic runtime handle | Host payload-scope handle
//! ```
//!
//! Decoding these fields proves only internal consistency. The Controller must
//! independently sign a FUSE-specific grant from current protected state, and
//! Mount must independently join a fresh Host scope and its own slot inventory
//! before any reservation write. This module does neither.

use aos_proto::aos::sandbox::local::v1::{Audience, ReserveFuseWorkerIntentRequestV1};
use aos_sandbox_core::model::{AttachmentIntent, AttachmentPresentation};
use aos_sandbox_core::{DecodeLimits, ProtocolId, decode_attachment_intent_v2};
use buffa::Message as _;

use crate::payload_scope::validate_runtime_handle;
use crate::{
    MAXIMUM_REQUEST_BYTES, PeerCredentials, PeerPolicy, ProtocolValidationError,
    ValidatedAssignmentFence, ValidatedHeader, exact_nonzero, validate_fence,
    validate_request_header, validate_request_header_static,
};

const MAXIMUM_INTENT_BYTES: usize = 768 * 1024;

/// Retains a structurally checked FUSE intent candidate without effect authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedFuseReserveIntentRequestV1 {
    header: ValidatedHeader,
    fence: ValidatedAssignmentFence,
    intent: AttachmentIntent,
    desired_record_digest: [u8; 32],
    namespace_target_generation: u64,
    namespace_allocation_digest: [u8; 32],
    runtime_handle: [u8; 32],
    payload_scope_handle: [u8; 32],
}

impl ValidatedFuseReserveIntentRequestV1 {
    /// Returns the peer-checked FUSE 3.0 request header.
    #[must_use]
    pub const fn header(&self) -> &ValidatedHeader {
        &self.header
    }

    /// Returns the nominated immutable Host assignment fence.
    #[must_use]
    pub const fn fence(&self) -> &ValidatedAssignmentFence {
        &self.fence
    }

    /// Returns the exact canonical v2 FUSE attachment semantics.
    #[must_use]
    pub const fn intent(&self) -> &AttachmentIntent {
        &self.intent
    }

    /// Returns the claimed digest of the current protected AOSATD02 record.
    #[must_use]
    pub const fn desired_record_digest(&self) -> &[u8; 32] {
        &self.desired_record_digest
    }

    /// Returns the Controller-nominated consumer namespace generation.
    #[must_use]
    pub const fn namespace_target_generation(&self) -> u64 {
        self.namespace_target_generation
    }

    /// Returns the claimed protected namespace-allocation digest.
    #[must_use]
    pub const fn namespace_allocation_digest(&self) -> &[u8; 32] {
        &self.namespace_allocation_digest
    }

    /// Returns the deterministic Host runtime handle for the assignment fence.
    #[must_use]
    pub const fn runtime_handle(&self) -> &[u8; 32] {
        &self.runtime_handle
    }

    /// Returns the claimed Host-retained payload-scope handle.
    #[must_use]
    pub const fn payload_scope_handle(&self) -> &[u8; 32] {
        &self.payload_scope_handle
    }
}

/// Decodes a fresh, bounded FUSE 3.0 Controller intent candidate.
///
/// The result is not a signed desired-state cut, Host scope proof, or Mount
/// authorization. No descriptor or worker identity is admitted here.
///
/// # Errors
///
/// Rejects malformed or oversized protobuf/CBOR, unknown fields, a wrong
/// audience or version, expired header, native/v1 attachment, sentinel
/// identities, and inconsistent assignment or namespace references.
pub fn decode_fuse_reserve_intent_request_v1(
    bytes: &[u8],
    peer: PeerCredentials,
    policy: PeerPolicy,
    now_boottime_nanoseconds: u64,
) -> Result<ValidatedFuseReserveIntentRequestV1, ProtocolValidationError> {
    decode_request(bytes, peer, policy, Some(now_boottime_nanoseconds))
}

/// Decodes a byte-exact historical request without renewing its deadline.
///
/// The caller must first prove protected authenticated-session custody of the
/// original bytes. This structural replay decoder cannot authorize new work.
///
/// # Errors
///
/// Rejects the static malformed-field and cross-binding cases described by
/// [`decode_fuse_reserve_intent_request_v1`], including an absent deadline.
pub fn decode_fuse_reserve_intent_request_for_protected_replay_v1(
    bytes: &[u8],
    peer: PeerCredentials,
    policy: PeerPolicy,
) -> Result<ValidatedFuseReserveIntentRequestV1, ProtocolValidationError> {
    decode_request(bytes, peer, policy, None)
}

fn decode_request(
    bytes: &[u8],
    peer: PeerCredentials,
    policy: PeerPolicy,
    now_boottime_nanoseconds: Option<u64>,
) -> Result<ValidatedFuseReserveIntentRequestV1, ProtocolValidationError> {
    if bytes.len() > MAXIMUM_REQUEST_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    if policy.audience != Audience::AUDIENCE_NODE_CONTROLLER {
        return Err(ProtocolValidationError::MethodMismatch);
    }

    let request = ReserveFuseWorkerIntentRequestV1::decode_from_slice(bytes)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !request.__buffa_unknown_fields.is_empty() {
        return Err(ProtocolValidationError::UnknownFields);
    }
    let header = request
        .header
        .as_option()
        .ok_or(ProtocolValidationError::MissingField("header"))?;
    let header = match now_boottime_nanoseconds {
        Some(now) => {
            validate_request_header(header, peer, policy, ProtocolId::MountFuseBroker, now)?
        }
        None => {
            let header =
                validate_request_header_static(header, peer, policy, ProtocolId::MountFuseBroker)?;
            if header.deadline_boottime_nanoseconds() == 0 {
                return Err(ProtocolValidationError::DeadlineExpired);
            }
            header
        }
    };
    let fence = validate_fence(
        request
            .fence
            .as_option()
            .ok_or(ProtocolValidationError::MissingField("fence"))?,
    )?;

    if request.attachment_intent_v2.len() > MAXIMUM_INTENT_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let intent = decode_attachment_intent_v2(
        &request.attachment_intent_v2,
        DecodeLimits {
            maximum_bytes: MAXIMUM_INTENT_BYTES,
            ..DecodeLimits::default()
        },
    )
    .map_err(|_| ProtocolValidationError::InvalidField("attachment_intent_v2"))?;
    let consumer = intent.consumer();
    if intent.presentation() != AttachmentPresentation::Fuse
        || consumer.0.as_bytes() != fence.sandbox_id()
        || consumer.1.as_bytes() != fence.incarnation_id()
        || request.namespace_target_generation == 0
        || intent.expected_namespace_generation().get() != request.namespace_target_generation
    {
        return Err(ProtocolValidationError::InvalidField(
            "FUSE desired-state binding",
        ));
    }

    Ok(ValidatedFuseReserveIntentRequestV1 {
        header,
        fence,
        intent,
        desired_record_digest: exact_nonzero::<32>(
            &request.desired_record_digest,
            "desired_record_digest",
        )?,
        namespace_target_generation: request.namespace_target_generation,
        namespace_allocation_digest: exact_nonzero::<32>(
            &request.namespace_allocation_digest,
            "namespace_allocation_digest",
        )?,
        runtime_handle: validate_runtime_handle(&fence, &request.runtime_handle)?,
        payload_scope_handle: exact_nonzero::<32>(
            &request.payload_scope_handle,
            "payload_scope_handle",
        )?,
    })
}

#[cfg(test)]
mod tests {
    use aos_proto::aos::sandbox::local::v1::{AssignmentFence, RequestHeader};
    use aos_sandbox_core::model::{
        AttachmentConsistency, AttachmentLease, MountAttributes, ViewMutation,
    };
    use aos_sandbox_core::{
        AttachmentId, AttachmentSlotId, DesiredGeneration, IncarnationId, LeaseId, MediaType,
        NamespaceGeneration, ObjectDescriptor, ObjectDigest, PortableMediaType, Revision,
        SandboxId, ViewId, encode_attachment_intent_v1, encode_attachment_intent_v2,
    };

    use super::*;

    fn peer() -> PeerCredentials {
        PeerCredentials {
            uid: 100,
            gid: 200,
            pid: Some(300),
        }
    }

    fn policy() -> PeerPolicy {
        PeerPolicy {
            uid: 100,
            gid: Some(200),
            audience: Audience::AUDIENCE_NODE_CONTROLLER,
        }
    }

    fn intent(presentation: AttachmentPresentation) -> AttachmentIntent {
        let view = ObjectDescriptor::new(
            MediaType::new(PortableMediaType::View.as_str().to_owned()).unwrap(),
            ObjectDigest::from_bytes([7; 32]),
            1,
        );
        AttachmentIntent::new_with_presentation(
            AttachmentId::from_bytes([1; 16]),
            DesiredGeneration::new(2),
            SandboxId::from_bytes([3; 16]),
            IncarnationId::from_bytes([4; 16]),
            NamespaceGeneration::new(5),
            ViewId::from_bytes([6; 16]),
            Revision::new(1),
            None,
            view,
            AttachmentSlotId::from_bytes([8; 16]),
            AttachmentConsistency::ImmutableRevision,
            ViewMutation::ReadOnly,
            MountAttributes::new(true, true, true, true, true, false),
            AttachmentLease::new(LeaseId::from_bytes([9; 16]), 10, 20).unwrap(),
            presentation,
        )
        .unwrap()
    }

    fn request() -> ReserveFuseWorkerIntentRequestV1 {
        let fence = AssignmentFence {
            sandbox_id: vec![3; 16],
            incarnation_id: vec![4; 16],
            assignment_epoch: 6,
            desired_generation: 7,
            assignment_digest: vec![10; 32],
            ..Default::default()
        };
        let runtime_handle =
            crate::semantics::host::runtime_handle_v1(&[4; 16], fence.assignment_epoch, &[10; 32]);
        ReserveFuseWorkerIntentRequestV1 {
            header: Some(RequestHeader {
                protocol_major: 3,
                protocol_minor: 0,
                request_id: vec![11; 16],
                audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
                deadline_boottime_nanoseconds: 100,
                maximum_response_bytes: 4096,
                ..Default::default()
            })
            .into(),
            fence: Some(fence).into(),
            attachment_intent_v2: encode_attachment_intent_v2(&intent(
                AttachmentPresentation::Fuse,
            )),
            desired_record_digest: vec![12; 32],
            namespace_target_generation: 5,
            namespace_allocation_digest: vec![13; 32],
            runtime_handle: runtime_handle.to_vec(),
            payload_scope_handle: vec![14; 32],
            ..Default::default()
        }
    }

    #[test]
    fn exact_v2_fuse_cut_is_structural_only() {
        let validated =
            decode_fuse_reserve_intent_request_v1(&request().encode_to_vec(), peer(), policy(), 50)
                .unwrap();

        assert_eq!(validated.header().protocol_version().major(), 3);
        assert_eq!(validated.fence().desired_generation(), 7);
        assert_eq!(validated.intent().desired_generation().get(), 2);
        assert_eq!(
            validated.intent().presentation(),
            AttachmentPresentation::Fuse
        );
        assert_eq!(validated.desired_record_digest(), &[12; 32]);
        assert_eq!(validated.namespace_target_generation(), 5);
        assert_eq!(validated.namespace_allocation_digest(), &[13; 32]);
        assert_eq!(validated.payload_scope_handle(), &[14; 32]);
    }

    #[test]
    fn downgrade_native_stale_and_cross_assignment_claims_fail_closed() {
        let mut cases = Vec::new();

        let mut wrong_version = request();
        wrong_version.header.as_option_mut().unwrap().protocol_major = 2;
        cases.push(wrong_version);

        let mut native_v2 = request();
        native_v2.attachment_intent_v2 =
            encode_attachment_intent_v2(&intent(AttachmentPresentation::Native));
        cases.push(native_v2);

        let mut native_v1 = request();
        native_v1.attachment_intent_v2 =
            encode_attachment_intent_v1(&intent(AttachmentPresentation::Native)).unwrap();
        cases.push(native_v1);

        let mut wrong_consumer = request();
        wrong_consumer.fence.as_option_mut().unwrap().sandbox_id = vec![15; 16];
        cases.push(wrong_consumer);

        let mut wrong_namespace = request();
        wrong_namespace.namespace_target_generation = 6;
        cases.push(wrong_namespace);

        let mut wrong_runtime = request();
        wrong_runtime.runtime_handle = vec![16; 32];
        cases.push(wrong_runtime);

        let mut missing_record = request();
        missing_record.desired_record_digest = vec![0; 32];
        cases.push(missing_record);

        let mut missing_allocation = request();
        missing_allocation.namespace_allocation_digest.clear();
        cases.push(missing_allocation);

        let mut missing_scope = request();
        missing_scope.payload_scope_handle = vec![0; 32];
        cases.push(missing_scope);

        for candidate in cases {
            assert!(
                decode_fuse_reserve_intent_request_v1(
                    &candidate.encode_to_vec(),
                    peer(),
                    policy(),
                    50,
                )
                .is_err()
            );
        }

        let mut wrong_policy = policy();
        wrong_policy.audience = Audience::AUDIENCE_ROOT_MOUNT;
        assert!(
            decode_fuse_reserve_intent_request_v1(
                &request().encode_to_vec(),
                peer(),
                wrong_policy,
                50,
            )
            .is_err()
        );
    }

    #[test]
    fn replay_preserves_original_deadline_without_renewing_it() {
        let bytes = request().encode_to_vec();
        assert!(decode_fuse_reserve_intent_request_v1(&bytes, peer(), policy(), 100).is_err());
        assert!(
            decode_fuse_reserve_intent_request_for_protected_replay_v1(&bytes, peer(), policy())
                .is_ok()
        );

        let mut absent_deadline = request();
        absent_deadline
            .header
            .as_option_mut()
            .unwrap()
            .deadline_boottime_nanoseconds = 0;
        assert!(
            decode_fuse_reserve_intent_request_for_protected_replay_v1(
                &absent_deadline.encode_to_vec(),
                peer(),
                policy(),
            )
            .is_err()
        );

        let mut unknown_field = bytes;
        unknown_field.extend_from_slice(&[0x98, 0x06, 0x01]);
        assert!(
            decode_fuse_reserve_intent_request_for_protected_replay_v1(
                &unknown_field,
                peer(),
                policy(),
            )
            .is_err()
        );
        assert!(
            decode_fuse_reserve_intent_request_v1(
                &vec![0; MAXIMUM_REQUEST_BYTES + 1],
                peer(),
                policy(),
                50,
            )
            .is_err()
        );
    }
}

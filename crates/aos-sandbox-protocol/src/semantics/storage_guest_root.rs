//! Canonical authority semantics for a separate guest-root publication effect.
//!
//! The request names only a fresh effect operation, the current assignment,
//! and the original committed workspace identity. Storage resolves every
//! physical path, dataset GUID, and package input from protected state.
//!
//! ```text
//! AOSSGR01 | sandbox[16] | incarnation[16] | epoch:u64be
//!          | desired_generation:u64be | assignment_digest[32]
//!          | effect_operation[16] | workspace_handle[32]
//!          | creation_operation[16]
//! ```

use aos_proto::aos::sandbox::local::v1::{
    PopulateStorageGuestRootRequestV1, PopulateStorageGuestRootResponseV1,
};
use aos_sandbox_agent::guest_root_publication::GuestRootPublicationProofV1;
use aos_sandbox_core::{
    BrokerArgumentCommitment, BrokerAssignment, BrokerGrantTarget, BrokerVerb, ProtocolId,
    ProtocolVersion,
};
use buffa::Message as _;

use crate::{
    MAXIMUM_REQUEST_BYTES, MAXIMUM_RESPONSE_BYTES, PeerCredentials, PeerPolicy,
    ProtocolValidationError, ValidatedAssignmentFence, ValidatedHeader, exact_nonzero,
    validate_fence, validate_request_header,
};

const MAGIC: &[u8; 8] = b"AOSSGR01";
const STORAGE_VERSION: ProtocolVersion = ProtocolVersion::new(1, 0);
const CANONICAL_BYTES: usize = 8 + 16 + 16 + 8 + 8 + 32 + 16 + 32 + 16;

/// Holds the plan-signing argument compiled from protected controller facts.
///
/// It deliberately has no request header or peer dependency. The Storage
/// decoder uses the same encoder after checking the hostile local request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanonicalStorageGuestRootArgumentsV1 {
    canonical_bytes: [u8; CANONICAL_BYTES],
}

impl CanonicalStorageGuestRootArgumentsV1 {
    /// Constructs the exact argument from a protected assignment and selectors.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolValidationError`] for zero or reused operation and
    /// workspace identities.
    pub fn from_protected_assignment(
        assignment: BrokerAssignment,
        operation_id: [u8; 16],
        workspace_handle: [u8; 32],
        creation_operation_id: [u8; 16],
    ) -> Result<Self, ProtocolValidationError> {
        let fields = GuestRootArgumentFieldsV1 {
            sandbox: *assignment.sandbox().as_bytes(),
            incarnation: *assignment.incarnation().as_bytes(),
            epoch: assignment.epoch().get(),
            desired_generation: assignment.desired_generation().get(),
            assignment_digest: *assignment.digest().as_bytes(),
            operation_id,
            workspace_handle,
            creation_operation_id,
        };
        Self::from_fields(fields)
    }

    fn from_fields(fields: GuestRootArgumentFieldsV1) -> Result<Self, ProtocolValidationError> {
        if fields.sandbox == [0; 16]
            || fields.incarnation == [0; 16]
            || fields.epoch == 0
            || fields.desired_generation == 0
            || fields.assignment_digest == [0; 32]
            || fields.operation_id == [0; 16]
            || fields.workspace_handle == [0; 32]
            || fields.creation_operation_id == [0; 16]
            || fields.operation_id == fields.creation_operation_id
        {
            return Err(ProtocolValidationError::InvalidField(
                "guest root arguments",
            ));
        }
        let mut canonical_bytes = [0_u8; CANONICAL_BYTES];
        canonical_bytes[..8].copy_from_slice(MAGIC);
        canonical_bytes[8..24].copy_from_slice(&fields.sandbox);
        canonical_bytes[24..40].copy_from_slice(&fields.incarnation);
        canonical_bytes[40..48].copy_from_slice(&fields.epoch.to_be_bytes());
        canonical_bytes[48..56].copy_from_slice(&fields.desired_generation.to_be_bytes());
        canonical_bytes[56..88].copy_from_slice(&fields.assignment_digest);
        canonical_bytes[88..104].copy_from_slice(&fields.operation_id);
        canonical_bytes[104..136].copy_from_slice(&fields.workspace_handle);
        canonical_bytes[136..152].copy_from_slice(&fields.creation_operation_id);
        Ok(Self { canonical_bytes })
    }

    /// Returns the exact 152-byte AOSSGR01 argument.
    #[must_use]
    pub const fn canonical_bytes(&self) -> &[u8; CANONICAL_BYTES] {
        &self.canonical_bytes
    }

    /// Returns the same domain-separated commitment used by Storage admission.
    #[must_use]
    pub fn argument_commitment(&self) -> BrokerArgumentCommitment {
        BrokerArgumentCommitment::for_canonical_bytes(&self.canonical_bytes)
    }
}

#[derive(Clone, Copy)]
struct GuestRootArgumentFieldsV1 {
    sandbox: [u8; 16],
    incarnation: [u8; 16],
    epoch: u64,
    desired_generation: u64,
    assignment_digest: [u8; 32],
    operation_id: [u8; 16],
    workspace_handle: [u8; 32],
    creation_operation_id: [u8; 16],
}

/// Carries one nonauthorizing, exact guest-root publication request meaning.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalStorageGuestRootSemanticsV1 {
    header: ValidatedHeader,
    fence: ValidatedAssignmentFence,
    operation_id: [u8; 16],
    workspace_handle: [u8; 32],
    creation_operation_id: [u8; 16],
    canonical_bytes: [u8; CANONICAL_BYTES],
}

impl CanonicalStorageGuestRootSemanticsV1 {
    /// Decodes a peer-bound request and fixes its sole signed-plan meaning.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolValidationError`] for malformed, unbounded, unknown,
    /// mismatched, or zero-valued request fields.
    pub fn decode(
        bytes: &[u8],
        peer: PeerCredentials,
        policy: PeerPolicy,
        now_boottime_nanoseconds: u64,
    ) -> Result<Self, ProtocolValidationError> {
        if bytes.len() > MAXIMUM_REQUEST_BYTES {
            return Err(ProtocolValidationError::RequestTooLarge);
        }
        let request = PopulateStorageGuestRootRequestV1::decode_from_slice(bytes)
            .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
        if !request.__buffa_unknown_fields.is_empty() {
            return Err(ProtocolValidationError::UnknownFields);
        }
        let header = validate_request_header(
            request
                .header
                .as_option()
                .ok_or(ProtocolValidationError::MissingField("header"))?,
            peer,
            policy,
            ProtocolId::StorageBroker,
            now_boottime_nanoseconds,
        )?;
        if header.protocol_version() != STORAGE_VERSION {
            return Err(ProtocolValidationError::MethodMismatch);
        }
        let fence = validate_fence(
            request
                .fence
                .as_option()
                .ok_or(ProtocolValidationError::MissingField("fence"))?,
        )?;
        let operation_id = exact_nonzero::<16>(&request.operation_id, "operation_id")?;
        let workspace_handle = exact_nonzero::<32>(&request.workspace_handle, "workspace_handle")?;
        let creation_operation_id =
            exact_nonzero::<16>(&request.creation_operation_id, "creation_operation_id")?;
        let arguments =
            CanonicalStorageGuestRootArgumentsV1::from_fields(GuestRootArgumentFieldsV1 {
                sandbox: *fence.sandbox_id(),
                incarnation: *fence.incarnation_id(),
                epoch: fence.assignment_epoch(),
                desired_generation: fence.desired_generation(),
                assignment_digest: *fence.assignment_digest(),
                operation_id,
                workspace_handle,
                creation_operation_id,
            })?;

        Ok(Self {
            header,
            fence,
            operation_id,
            workspace_handle,
            creation_operation_id,
            canonical_bytes: *arguments.canonical_bytes(),
        })
    }

    /// Returns the validated common header.
    #[must_use]
    pub const fn header(&self) -> &ValidatedHeader {
        &self.header
    }

    /// Returns the exact assignment fence.
    #[must_use]
    pub const fn fence(&self) -> &ValidatedAssignmentFence {
        &self.fence
    }

    /// Returns the new effect operation identity.
    #[must_use]
    pub const fn operation_id(&self) -> [u8; 16] {
        self.operation_id
    }

    /// Returns the existing workspace handle.
    #[must_use]
    pub const fn workspace_handle(&self) -> [u8; 32] {
        self.workspace_handle
    }

    /// Returns the original workspace creation operation.
    #[must_use]
    pub const fn creation_operation_id(&self) -> [u8; 16] {
        self.creation_operation_id
    }

    /// Returns the exact portable bytes committed by the signed plan.
    #[must_use]
    pub const fn canonical_bytes(&self) -> &[u8; CANONICAL_BYTES] {
        &self.canonical_bytes
    }

    /// Returns the domain-separated argument commitment.
    #[must_use]
    pub fn argument_commitment(&self) -> BrokerArgumentCommitment {
        BrokerArgumentCommitment::for_canonical_bytes(&self.canonical_bytes)
    }

    /// Returns the distinct publication verb.
    #[must_use]
    pub const fn broker_verb(&self) -> BrokerVerb {
        BrokerVerb::StoragePopulateGuestRoot
    }

    /// Returns the assignment grant scope, with the workspace bound by arguments.
    #[must_use]
    pub const fn grant_target(&self) -> BrokerGrantTarget {
        BrokerGrantTarget::Assignment
    }
}

/// Decodes the sole successful physical publication response.
///
/// # Errors
///
/// Returns [`ProtocolValidationError`] for malformed wire, unknown fields,
/// invalid proof bytes, or a response beyond its caller's admitted bound.
pub fn decode_storage_guest_root_response_v1(
    bytes: &[u8],
    maximum_response_bytes: u32,
) -> Result<GuestRootPublicationProofV1, ProtocolValidationError> {
    if maximum_response_bytes > MAXIMUM_RESPONSE_BYTES
        || bytes.len() > maximum_response_bytes as usize
    {
        return Err(ProtocolValidationError::ResponseTooLarge);
    }
    let response = PopulateStorageGuestRootResponseV1::decode_from_slice(bytes)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !response.__buffa_unknown_fields.is_empty() {
        return Err(ProtocolValidationError::UnknownFields);
    }
    GuestRootPublicationProofV1::decode(&response.publication_proof)
        .map_err(|_| ProtocolValidationError::InvalidField("guest root publication proof"))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use aos_proto::aos::sandbox::local::v1::Audience;
    use aos_sandbox_core::{
        AssignmentEpoch, DesiredGeneration, IncarnationId, ObjectDigest, SandboxId,
    };

    use super::*;

    fn request() -> PopulateStorageGuestRootRequestV1 {
        let mut request = PopulateStorageGuestRootRequestV1::default();
        let header = request.header.get_or_insert_default();
        header.protocol_major = 1;
        header.request_id = vec![1; 16];
        header.audience = Audience::AUDIENCE_NODE_CONTROLLER.into();
        header.deadline_boottime_nanoseconds = 200;
        header.maximum_response_bytes = 4096;

        let fence = request.fence.get_or_insert_default();
        fence.sandbox_id = vec![2; 16];
        fence.incarnation_id = vec![3; 16];
        fence.assignment_epoch = 4;
        fence.desired_generation = 5;
        fence.assignment_digest = vec![6; 32];

        request.operation_id = vec![7; 16];
        request.workspace_handle = vec![8; 32];
        request.creation_operation_id = vec![9; 16];
        request
    }

    fn decode(
        request: &PopulateStorageGuestRootRequestV1,
    ) -> Result<CanonicalStorageGuestRootSemanticsV1, ProtocolValidationError> {
        CanonicalStorageGuestRootSemanticsV1::decode(
            &request.encode_to_vec(),
            PeerCredentials {
                uid: 100,
                gid: 200,
                pid: Some(300),
            },
            PeerPolicy {
                uid: 100,
                gid: Some(200),
                audience: Audience::AUDIENCE_NODE_CONTROLLER,
            },
            100,
        )
    }

    #[test]
    fn every_authority_field_changes_the_commitment() {
        let baseline = decode(&request()).unwrap();
        let assignment = BrokerAssignment::new(
            SandboxId::from_bytes([2; 16]),
            IncarnationId::from_bytes([3; 16]),
            AssignmentEpoch::new(4),
            DesiredGeneration::new(5),
            ObjectDigest::from_bytes([6; 32]),
        )
        .unwrap();
        let protected = CanonicalStorageGuestRootArgumentsV1::from_protected_assignment(
            assignment, [7; 16], [8; 32], [9; 16],
        )
        .unwrap();
        assert_eq!(baseline.canonical_bytes().len(), CANONICAL_BYTES);
        assert_eq!(baseline.canonical_bytes(), protected.canonical_bytes());
        assert_eq!(
            baseline.argument_commitment(),
            protected.argument_commitment()
        );
        assert_eq!(baseline.broker_verb(), BrokerVerb::StoragePopulateGuestRoot);
        assert_eq!(baseline.grant_target(), BrokerGrantTarget::Assignment);

        let changes: [fn(&mut PopulateStorageGuestRootRequestV1); 8] = [
            |value| value.fence.get_or_insert_default().sandbox_id = vec![10; 16],
            |value| value.fence.get_or_insert_default().incarnation_id = vec![11; 16],
            |value| value.fence.get_or_insert_default().assignment_epoch = 12,
            |value| value.fence.get_or_insert_default().desired_generation = 13,
            |value| value.fence.get_or_insert_default().assignment_digest = vec![14; 32],
            |value| value.operation_id = vec![15; 16],
            |value| value.workspace_handle = vec![16; 32],
            |value| value.creation_operation_id = vec![17; 16],
        ];
        for change in changes {
            let mut candidate = request();
            change(&mut candidate);
            assert_ne!(
                decode(&candidate).unwrap().argument_commitment(),
                baseline.argument_commitment()
            );
        }
    }

    #[test]
    fn invalid_and_reused_identifiers_fail_closed() {
        let mut duplicate = request();
        duplicate.creation_operation_id = duplicate.operation_id.clone();
        assert!(decode(&duplicate).is_err());

        let mut missing = request();
        missing.workspace_handle.clear();
        assert!(decode(&missing).is_err());

        let mut unsupported = request();
        unsupported.header.get_or_insert_default().protocol_minor = 1;
        assert!(decode(&unsupported).is_err());
    }
}

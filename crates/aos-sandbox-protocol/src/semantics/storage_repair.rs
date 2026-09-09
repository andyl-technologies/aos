//! Canonical portable authority semantics for workspace root-pin repair.
//!
//! Storage 1.4 admits only a fresh operation identity, the current assignment
//! fence, and an existing opaque workspace handle. Physical storage identity,
//! pin observations, attempt ordinals, and worker inputs remain protected
//! broker state and cannot be selected by a caller.
//!
//! The V1 canonical meaning uses ordered TLV fields. Each field is an unsigned
//! `u8` tag, unsigned big-endian `u32` length, and the value:
//!
//! ```text
//! 1 magic = "AOSSRPR1"          2 format version = u16 BE
//! 3 sandbox ID = 16 bytes       4 incarnation ID = 16 bytes
//! 5 assignment epoch = u64 BE   6 desired generation = u64 BE
//! 7 assignment digest = 32 bytes
//! 8 operation ID = 16 bytes     9 storage handle = 32 bytes
//! ```

use aos_proto::aos::sandbox::local::v1::RepairStorageWorkspacePinRequest;
use aos_sandbox_core::{
    BrokerArgumentCommitment, BrokerGrantTarget, BrokerResourceHandle, BrokerVerb, ProtocolId,
};
use buffa::Message as _;

use crate::{
    MAXIMUM_REQUEST_BYTES, PeerCredentials, PeerPolicy, ProtocolValidationError,
    ValidatedAssignmentFence, ValidatedHeader, exact_nonzero, validate_fence,
    validate_request_header,
};

const FORMAT_MAGIC: &[u8; 8] = b"AOSSRPR1";
const FORMAT_VERSION: u16 = 1;
const MINIMUM_PROTOCOL_MINOR: u16 = 4;
const MAXIMUM_CANONICAL_BYTES: usize = 256;

/// Reports a repair request that has no single closed portable meaning.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum StorageRepairSemanticsError {
    /// The common envelope or a fixed-width field is invalid.
    #[error("invalid Storage workspace-pin repair request: {0}")]
    Protocol(#[from] ProtocolValidationError),
    /// The canonical representation exceeded its fixed invariant.
    #[error("canonical Storage workspace-pin repair exceeds the V1 byte ceiling")]
    CanonicalEncodingTooLarge,
}

/// Carries one validated workspace-pin repair meaning for authorization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalStorageRepairSemanticsV1 {
    header: ValidatedHeader,
    fence: ValidatedAssignmentFence,
    operation_id: [u8; 16],
    storage_handle: BrokerResourceHandle,
    bytes: Vec<u8>,
    commitment: BrokerArgumentCommitment,
}

impl CanonicalStorageRepairSemanticsV1 {
    /// Decodes hostile protobuf bytes into their sole portable V1 meaning.
    ///
    /// # Errors
    ///
    /// Returns [`StorageRepairSemanticsError`] for an oversized or malformed
    /// message, unknown fields, peer/header/fence failure, a protocol older
    /// than Storage 1.4, zero or incorrectly sized identities, or overflow.
    pub fn decode(
        bytes: &[u8],
        peer: PeerCredentials,
        policy: PeerPolicy,
        now_boottime_nanoseconds: u64,
    ) -> Result<Self, StorageRepairSemanticsError> {
        if bytes.len() > MAXIMUM_REQUEST_BYTES {
            return Err(ProtocolValidationError::RequestTooLarge.into());
        }
        let request = RepairStorageWorkspacePinRequest::decode_from_slice(bytes)
            .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
        if !request.__buffa_unknown_fields.is_empty() {
            return Err(ProtocolValidationError::UnknownFields.into());
        }

        let header = request
            .header
            .as_option()
            .ok_or(ProtocolValidationError::MissingField("header"))?;
        let header = validate_request_header(
            header,
            peer,
            policy,
            ProtocolId::StorageBroker,
            now_boottime_nanoseconds,
        )?;
        if header.protocol_version().minor() < MINIMUM_PROTOCOL_MINOR {
            return Err(ProtocolValidationError::InvalidField("header.protocol_minor").into());
        }

        let fence = validate_fence(
            request
                .fence
                .as_option()
                .ok_or(ProtocolValidationError::MissingField("fence"))?,
        )?;
        let operation_id = exact_nonzero::<16>(&request.operation_id, "operation_id")?;
        let storage_handle_bytes = exact_nonzero::<32>(&request.storage_handle, "storage_handle")?;
        let storage_handle = BrokerResourceHandle::from_bytes(storage_handle_bytes)
            .map_err(|_| ProtocolValidationError::InvalidField("storage_handle"))?;

        let canonical = encode_canonical(&fence, operation_id, storage_handle_bytes)?;
        let commitment = BrokerArgumentCommitment::for_canonical_bytes(&canonical);

        Ok(Self {
            header,
            fence,
            operation_id,
            storage_handle,
            bytes: canonical,
            commitment,
        })
    }

    /// Returns the validated common request header.
    #[must_use]
    pub const fn header(&self) -> &ValidatedHeader {
        &self.header
    }

    /// Returns the exact assignment fence committed by repair authority.
    #[must_use]
    pub const fn fence(&self) -> &ValidatedAssignmentFence {
        &self.fence
    }

    /// Returns the fresh durable repair operation identity.
    #[must_use]
    pub const fn operation_id(&self) -> [u8; 16] {
        self.operation_id
    }

    /// Returns the existing workspace resource authorized for repair.
    #[must_use]
    pub const fn storage_handle(&self) -> BrokerResourceHandle {
        self.storage_handle
    }

    /// Returns the exact portable bytes committed by the argument digest.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the domain-separated signed-plan argument commitment.
    #[must_use]
    pub const fn argument_commitment(&self) -> BrokerArgumentCommitment {
        self.commitment
    }

    /// Returns the distinct workspace-pin repair verb.
    #[must_use]
    pub const fn broker_verb(&self) -> BrokerVerb {
        BrokerVerb::StorageRepairWorkspacePin
    }

    /// Returns the exact existing workspace as the grant target.
    #[must_use]
    pub const fn grant_target(&self) -> BrokerGrantTarget {
        BrokerGrantTarget::Resource(self.storage_handle)
    }
}

fn encode_canonical(
    fence: &ValidatedAssignmentFence,
    operation_id: [u8; 16],
    storage_handle: [u8; 32],
) -> Result<Vec<u8>, StorageRepairSemanticsError> {
    let mut encoder = Encoder::new();
    encoder.field(1, FORMAT_MAGIC)?;
    encoder.field(2, &FORMAT_VERSION.to_be_bytes())?;
    encoder.field(3, fence.sandbox_id())?;
    encoder.field(4, fence.incarnation_id())?;
    encoder.field(5, &fence.assignment_epoch().to_be_bytes())?;
    encoder.field(6, &fence.desired_generation().to_be_bytes())?;
    encoder.field(7, fence.assignment_digest())?;
    encoder.field(8, &operation_id)?;
    encoder.field(9, &storage_handle)?;
    Ok(encoder.finish())
}

struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    fn new() -> Self {
        Self {
            bytes: Vec::with_capacity(192),
        }
    }

    fn field(&mut self, tag: u8, value: &[u8]) -> Result<(), StorageRepairSemanticsError> {
        let length = u32::try_from(value.len())
            .map_err(|_| StorageRepairSemanticsError::CanonicalEncodingTooLarge)?;
        let next = self
            .bytes
            .len()
            .checked_add(5)
            .and_then(|size| size.checked_add(value.len()))
            .filter(|size| *size <= MAXIMUM_CANONICAL_BYTES)
            .ok_or(StorageRepairSemanticsError::CanonicalEncodingTooLarge)?;
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use aos_proto::aos::sandbox::local::v1::Audience;
    use buffa::{UnknownField, UnknownFieldData};

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

    fn request() -> RepairStorageWorkspacePinRequest {
        let mut request = RepairStorageWorkspacePinRequest::default();
        let header = request.header.get_or_insert_default();
        header.protocol_major = 1;
        header.protocol_minor = MINIMUM_PROTOCOL_MINOR.into();
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
        request.storage_handle = vec![8; 32];
        request
    }

    fn decode(
        request: &RepairStorageWorkspacePinRequest,
    ) -> Result<CanonicalStorageRepairSemanticsV1, StorageRepairSemanticsError> {
        CanonicalStorageRepairSemanticsV1::decode(&request.encode_to_vec(), peer(), policy(), 100)
    }

    #[test]
    fn canonical_repair_has_closed_resource_authority() {
        let semantics = decode(&request()).unwrap();

        #[rustfmt::skip]
        let expected_canonical = [
            1, 0, 0, 0, 8, 65, 79, 83, 83, 82, 80, 82, 49,
            2, 0, 0, 0, 2, 0, 1,
            3, 0, 0, 0, 16, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
            4, 0, 0, 0, 16, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
            5, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 4,
            6, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 5,
            7, 0, 0, 0, 32, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
            6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
            8, 0, 0, 0, 16, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
            9, 0, 0, 0, 32, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
            8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
        ];

        assert_eq!(
            semantics.broker_verb(),
            BrokerVerb::StorageRepairWorkspacePin
        );
        assert_eq!(semantics.operation_id(), [7; 16]);
        assert_eq!(semantics.storage_handle().as_bytes(), &[8; 32]);
        assert_eq!(
            semantics.grant_target(),
            BrokerGrantTarget::Resource(semantics.storage_handle())
        );
        assert_eq!(semantics.canonical_bytes(), expected_canonical);
        assert_eq!(
            semantics.argument_commitment().digest().as_bytes(),
            &[
                188, 150, 28, 14, 59, 116, 52, 71, 137, 26, 137, 151, 238, 111, 205, 87, 53, 158,
                247, 233, 7, 34, 69, 75, 217, 248, 218, 205, 97, 221, 245, 194,
            ]
        );
    }

    #[test]
    fn every_repair_authority_input_changes_the_commitment() {
        let baseline = decode(&request()).unwrap().argument_commitment();
        let mutations: [fn(&mut RepairStorageWorkspacePinRequest); 7] = [
            |request| request.fence.get_or_insert_default().sandbox_id = vec![9; 16],
            |request| request.fence.get_or_insert_default().incarnation_id = vec![10; 16],
            |request| request.fence.get_or_insert_default().assignment_epoch = 11,
            |request| request.fence.get_or_insert_default().desired_generation = 12,
            |request| request.fence.get_or_insert_default().assignment_digest = vec![13; 32],
            |request| request.operation_id = vec![14; 16],
            |request| request.storage_handle = vec![15; 32],
        ];

        for mutate in mutations {
            let mut candidate = request();
            mutate(&mut candidate);
            assert_ne!(decode(&candidate).unwrap().argument_commitment(), baseline);
        }
    }

    #[test]
    fn protocol_version_id_shapes_and_unknown_fields_fail_closed() {
        for minor in 0..=3 {
            let mut old = request();
            old.header.get_or_insert_default().protocol_minor = minor;
            assert!(decode(&old).is_err());
        }
        let mut wrong_major = request();
        wrong_major.header.get_or_insert_default().protocol_major = 2;
        assert!(decode(&wrong_major).is_err());

        for invalid in [Vec::new(), vec![0; 16], vec![1; 15], vec![1; 17]] {
            let mut candidate = request();
            candidate.operation_id = invalid;
            assert!(decode(&candidate).is_err());
        }
        for invalid in [Vec::new(), vec![0; 32], vec![1; 31], vec![1; 33]] {
            let mut candidate = request();
            candidate.storage_handle = invalid;
            assert!(decode(&candidate).is_err());
        }

        let mut unknown = request().encode_to_vec();
        unknown.extend_from_slice(&[0xa0, 0x06, 0x01]);
        assert!(matches!(
            CanonicalStorageRepairSemanticsV1::decode(&unknown, peer(), policy(), 100),
            Err(StorageRepairSemanticsError::Protocol(
                ProtocolValidationError::UnknownFields
            ))
        ));

        for nested in ["header", "fence"] {
            let mut candidate = request();
            let unknown = UnknownField {
                number: 100,
                data: UnknownFieldData::Varint(1),
            };
            match nested {
                "header" => candidate
                    .header
                    .get_or_insert_default()
                    .__buffa_unknown_fields
                    .push(unknown),
                "fence" => candidate
                    .fence
                    .get_or_insert_default()
                    .__buffa_unknown_fields
                    .push(unknown),
                _ => unreachable!(),
            }
            assert!(matches!(
                decode(&candidate),
                Err(StorageRepairSemanticsError::Protocol(
                    ProtocolValidationError::UnknownFields
                ))
            ));
        }
    }
}

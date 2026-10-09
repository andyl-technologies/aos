//! Canonical, nonauthorizing Controller argument-source carrier.
//!
//! This versioned source describes the protected facts a future Controller
//! issuer must sign before Host can mint a one-shot Guest `ARG_MAX` challenge.
//! Parsing proves only structural integrity. In particular, the source digest
//! is not a signature, a Controller journal proof, or permission to contact a
//! Guest. A future issuer must derive it under the exclusive Controller owner;
//! the pinned grant signer and generation belong to the authenticated broker
//! envelope, not caller-selected fields here. The broker transport is
//! registered but production dispatch rejects it before any Guest effect.
//!
//! ```text
//! AOSCAS01 || execution:16 || create-operation:16
//!          || sandbox:16 || incarnation:16 || assignment-epoch:u64be
//!          || assignment-digest:32 || desired-generation:u64be
//!          || namespace-generation:u64be || host-boot-id:16
//!          || payload-boot-id:16
//!          || assignment-manifest-digest:32 || parent-record-digest:32
//!          || accepted-output-record-digest:32 || sandbox-spec-record-digest:32
//!          || environment-manifest-digest:32 || environment-generation:u64be
//!          || environment-source-digest:32 || media-type-length:u8
//!          || media-type:bytes || environment-descriptor-digest:32
//!          || environment-descriptor-size:u64be || guest-policy-record-digest:32
//!          || runtime-profile-commitment:32 || controller-epoch:u64be
//!          || controller-head-sequence:u64be || controller-head-digest:32
//!          || issuer-nonce:32 || deadline-boottime-nanoseconds:u64be
//!          || SHA256("aos.sandbox.controller-argument-source.v1\0" || preceding):32
//! ```

use aos_sandbox_core::{
    ExecutionId, IncarnationId, MediaType, ObjectDescriptor, ObjectDigest, OperationId, SandboxId,
};
use sha2::{Digest as _, Sha256};

mod transport;

pub use transport::{
    HostArgumentSourceContentFieldsV1, ValidatedHostRuntimeArgumentRequestV1,
    decode_host_runtime_argument_request_v1, host_argument_source_content_fields_v1,
};

const MAGIC: &[u8; 8] = b"AOSCAS01";
const DIGEST_DOMAIN: &[u8] = b"aos.sandbox.controller-argument-source.v1\0";
/// Maximum canonical AOSCAS01 content carried by its sealed descriptor.
pub const MAXIMUM_CONTROLLER_EXECUTION_ARGUMENT_SOURCE_BYTES_V1: usize = 1_024;

/// Reports a malformed or noncanonical Controller argument-source carrier.
#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum ControllerExecutionArgumentSourceErrorV1 {
    /// The version, length, field encoding, or digest is invalid.
    #[error("Controller execution argument source is not canonical")]
    InvalidCarrier,
}

/// Retains structurally decoded, untrusted accepted-Create source fields.
///
/// A Host must still verify a future signed Controller grant and its own
/// protected runtime currentness before using these fields. The Controller
/// head is correlation, not proof of exclusive journal ownership.
pub struct DecodedControllerExecutionArgumentSourceV1 {
    execution: ExecutionId,
    create_operation: OperationId,
    sandbox: SandboxId,
    incarnation: IncarnationId,
    assignment_epoch: u64,
    assignment_digest: ObjectDigest,
    desired_generation: u64,
    namespace_generation: u64,
    host_boot_id: [u8; 16],
    payload_boot_id: [u8; 16],
    assignment_manifest_digest: ObjectDigest,
    parent_record_digest: ObjectDigest,
    accepted_output_record_digest: ObjectDigest,
    sandbox_spec_record_digest: ObjectDigest,
    environment_manifest_digest: ObjectDigest,
    environment_generation: u64,
    environment_source_digest: ObjectDigest,
    environment_descriptor: ObjectDescriptor,
    guest_policy_record_digest: ObjectDigest,
    runtime_profile_commitment: ObjectDigest,
    controller_epoch: u64,
    controller_head_sequence: u64,
    controller_head_digest: ObjectDigest,
    issuer_nonce: [u8; 32],
    deadline_boottime_nanoseconds: u64,
    source_digest: ObjectDigest,
}

impl DecodedControllerExecutionArgumentSourceV1 {
    /// Returns the exact accepted execution identifier.
    #[must_use]
    pub const fn execution(&self) -> ExecutionId {
        self.execution
    }

    /// Returns the exact accepted Create operation identifier.
    #[must_use]
    pub const fn create_operation(&self) -> OperationId {
        self.create_operation
    }

    /// Returns the signed assignment's sandbox identifier.
    #[must_use]
    pub const fn sandbox(&self) -> SandboxId {
        self.sandbox
    }

    /// Returns the signed assignment's incarnation identifier.
    #[must_use]
    pub const fn incarnation(&self) -> IncarnationId {
        self.incarnation
    }

    /// Returns the signed assignment epoch.
    #[must_use]
    pub const fn assignment_epoch(&self) -> u64 {
        self.assignment_epoch
    }

    /// Returns the signed assignment commitment.
    #[must_use]
    pub const fn assignment_digest(&self) -> ObjectDigest {
        self.assignment_digest
    }

    /// Returns the desired generation bound by the assignment.
    #[must_use]
    pub const fn desired_generation(&self) -> u64 {
        self.desired_generation
    }

    /// Returns the namespace generation bound by the assignment.
    #[must_use]
    pub const fn namespace_generation(&self) -> u64 {
        self.namespace_generation
    }

    /// Returns the Host kernel boot identifier that a future grant must bind.
    #[must_use]
    pub const fn host_boot_id(&self) -> [u8; 16] {
        self.host_boot_id
    }

    /// Returns the payload boot identifier bound by the Host runtime.
    #[must_use]
    pub const fn payload_boot_id(&self) -> [u8; 16] {
        self.payload_boot_id
    }

    /// Returns the independent assignment-manifest commitment.
    #[must_use]
    pub const fn assignment_manifest_digest(&self) -> ObjectDigest {
        self.assignment_manifest_digest
    }

    /// Returns the protected execution-parent record commitment.
    #[must_use]
    pub const fn parent_record_digest(&self) -> ObjectDigest {
        self.parent_record_digest
    }

    /// Returns the accepted `AOSEOR02` output record commitment.
    #[must_use]
    pub const fn accepted_output_record_digest(&self) -> ObjectDigest {
        self.accepted_output_record_digest
    }

    /// Returns the exact version-two sandbox-spec record commitment.
    #[must_use]
    pub const fn sandbox_spec_record_digest(&self) -> ObjectDigest {
        self.sandbox_spec_record_digest
    }

    /// Returns the immutable environment-manifest commitment.
    #[must_use]
    pub const fn environment_manifest_digest(&self) -> ObjectDigest {
        self.environment_manifest_digest
    }

    /// Returns the selected environment generation.
    #[must_use]
    pub const fn environment_generation(&self) -> u64 {
        self.environment_generation
    }

    /// Returns the protected environment-source commitment.
    #[must_use]
    pub const fn environment_source_digest(&self) -> ObjectDigest {
        self.environment_source_digest
    }

    /// Borrows the complete canonical environment object descriptor.
    #[must_use]
    pub const fn environment_descriptor(&self) -> &ObjectDescriptor {
        &self.environment_descriptor
    }

    /// Returns the protected Guest identity-policy record commitment.
    #[must_use]
    pub const fn guest_policy_record_digest(&self) -> ObjectDigest {
        self.guest_policy_record_digest
    }

    /// Returns the protected runtime-profile commitment.
    #[must_use]
    pub const fn runtime_profile_commitment(&self) -> ObjectDigest {
        self.runtime_profile_commitment
    }

    /// Returns the Controller epoch used only for signed-grant correlation.
    #[must_use]
    pub const fn controller_epoch(&self) -> u64 {
        self.controller_epoch
    }

    /// Returns the Controller journal sequence used only for correlation.
    #[must_use]
    pub const fn controller_head_sequence(&self) -> u64 {
        self.controller_head_sequence
    }

    /// Returns the Controller head commitment used only for correlation.
    #[must_use]
    pub const fn controller_head_digest(&self) -> ObjectDigest {
        self.controller_head_digest
    }

    /// Returns the issuer nonce; this is not a Guest challenge nonce.
    #[must_use]
    pub const fn issuer_nonce(&self) -> [u8; 32] {
        self.issuer_nonce
    }

    /// Returns the proposed monotonic Host deadline for a future grant.
    #[must_use]
    pub const fn deadline_boottime_nanoseconds(&self) -> u64 {
        self.deadline_boottime_nanoseconds
    }

    /// Returns the domain-separated digest of the exact canonical carrier.
    #[must_use]
    pub const fn source_digest(&self) -> ObjectDigest {
        self.source_digest
    }
}

/// Decodes one versioned Controller source without granting Guest contact.
///
/// The future issuer must derive these fields under its protected accepted-
/// Create owner and bind the exact bytes in a Host-audience signed grant. Host
/// must independently validate that grant, assignment, profile, and deadline.
/// This decoder deliberately does not accept Guest request bytes or mint a
/// one-shot challenge.
///
/// # Errors
///
/// Rejects wrong versions, truncation, trailing bytes, zero sentinels, an
/// invalid environment descriptor, or a noncanonical source digest.
pub fn decode_controller_execution_argument_source_v1(
    bytes: &[u8],
) -> Result<DecodedControllerExecutionArgumentSourceV1, ControllerExecutionArgumentSourceErrorV1> {
    if bytes.len() > MAXIMUM_CONTROLLER_EXECUTION_ARGUMENT_SOURCE_BYTES_V1 {
        return Err(ControllerExecutionArgumentSourceErrorV1::InvalidCarrier);
    }
    let mut cursor = 0;
    if &take::<8>(bytes, &mut cursor)? != MAGIC {
        return Err(ControllerExecutionArgumentSourceErrorV1::InvalidCarrier);
    }

    let execution = ExecutionId::from_bytes(nonzero(take(bytes, &mut cursor)?)?);
    let create_operation = OperationId::from_bytes(nonzero(take(bytes, &mut cursor)?)?);
    let sandbox = SandboxId::from_bytes(nonzero(take(bytes, &mut cursor)?)?);
    let incarnation = IncarnationId::from_bytes(nonzero(take(bytes, &mut cursor)?)?);
    let assignment_epoch = positive_u64(bytes, &mut cursor)?;
    let assignment_digest = digest(bytes, &mut cursor)?;
    let desired_generation = positive_u64(bytes, &mut cursor)?;
    let namespace_generation = positive_u64(bytes, &mut cursor)?;
    let host_boot_id = nonzero(take(bytes, &mut cursor)?)?;
    let payload_boot_id = nonzero(take(bytes, &mut cursor)?)?;
    let assignment_manifest_digest = digest(bytes, &mut cursor)?;
    let parent_record_digest = digest(bytes, &mut cursor)?;
    let accepted_output_record_digest = digest(bytes, &mut cursor)?;
    let sandbox_spec_record_digest = digest(bytes, &mut cursor)?;
    let environment_manifest_digest = digest(bytes, &mut cursor)?;
    let environment_generation = positive_u64(bytes, &mut cursor)?;
    let environment_source_digest = digest(bytes, &mut cursor)?;

    let media_type_length = usize::from(take::<1>(bytes, &mut cursor)?[0]);
    let media_type_end = cursor
        .checked_add(media_type_length)
        .ok_or(ControllerExecutionArgumentSourceErrorV1::InvalidCarrier)?;
    let media_type_bytes = bytes
        .get(cursor..media_type_end)
        .ok_or(ControllerExecutionArgumentSourceErrorV1::InvalidCarrier)?;
    let media_type = std::str::from_utf8(media_type_bytes)
        .ok()
        .and_then(|value| MediaType::new(value.to_owned()).ok())
        .ok_or(ControllerExecutionArgumentSourceErrorV1::InvalidCarrier)?;
    cursor = media_type_end;
    let environment_descriptor = ObjectDescriptor::new(
        media_type,
        digest(bytes, &mut cursor)?,
        positive_u64(bytes, &mut cursor)?,
    );

    let guest_policy_record_digest = digest(bytes, &mut cursor)?;
    let runtime_profile_commitment = digest(bytes, &mut cursor)?;
    let controller_epoch = positive_u64(bytes, &mut cursor)?;
    let controller_head_sequence = positive_u64(bytes, &mut cursor)?;
    let controller_head_digest = digest(bytes, &mut cursor)?;
    let issuer_nonce = nonzero(take(bytes, &mut cursor)?)?;
    let deadline_boottime_nanoseconds = positive_u64(bytes, &mut cursor)?;
    let source_digest_start = cursor;
    let source_digest = digest(bytes, &mut cursor)?;
    if cursor != bytes.len() {
        return Err(ControllerExecutionArgumentSourceErrorV1::InvalidCarrier);
    }

    let mut hash = Sha256::new();
    hash.update(DIGEST_DOMAIN);
    hash.update(&bytes[..source_digest_start]);
    if hash.finalize().as_slice() != source_digest.as_bytes() {
        return Err(ControllerExecutionArgumentSourceErrorV1::InvalidCarrier);
    }

    Ok(DecodedControllerExecutionArgumentSourceV1 {
        execution,
        create_operation,
        sandbox,
        incarnation,
        assignment_epoch,
        assignment_digest,
        desired_generation,
        namespace_generation,
        host_boot_id,
        payload_boot_id,
        assignment_manifest_digest,
        parent_record_digest,
        accepted_output_record_digest,
        sandbox_spec_record_digest,
        environment_manifest_digest,
        environment_generation,
        environment_source_digest,
        environment_descriptor,
        guest_policy_record_digest,
        runtime_profile_commitment,
        controller_epoch,
        controller_head_sequence,
        controller_head_digest,
        issuer_nonce,
        deadline_boottime_nanoseconds,
        source_digest,
    })
}

fn take<const N: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], ControllerExecutionArgumentSourceErrorV1> {
    let end = cursor
        .checked_add(N)
        .ok_or(ControllerExecutionArgumentSourceErrorV1::InvalidCarrier)?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(ControllerExecutionArgumentSourceErrorV1::InvalidCarrier)?;
    *cursor = end;
    value
        .try_into()
        .map_err(|_| ControllerExecutionArgumentSourceErrorV1::InvalidCarrier)
}

fn nonzero<const N: usize>(
    bytes: [u8; N],
) -> Result<[u8; N], ControllerExecutionArgumentSourceErrorV1> {
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(ControllerExecutionArgumentSourceErrorV1::InvalidCarrier);
    }
    Ok(bytes)
}

fn positive_u64(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<u64, ControllerExecutionArgumentSourceErrorV1> {
    let value = u64::from_be_bytes(take(bytes, cursor)?);
    if value == 0 {
        return Err(ControllerExecutionArgumentSourceErrorV1::InvalidCarrier);
    }
    Ok(value)
}

fn digest(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<ObjectDigest, ControllerExecutionArgumentSourceErrorV1> {
    Ok(ObjectDigest::from_bytes(nonzero(take(bytes, cursor)?)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PeerCredentials, PeerPolicy};
    use aos_proto::aos::sandbox::local::v1::{
        Audience, ObserveHostRuntimeArgumentRequestV1, RequestHeader,
    };
    use buffa::Message as _;

    fn reseal(bytes: &mut [u8]) {
        let digest_start = bytes.len() - 32;
        let mut hash = Sha256::new();
        hash.update(DIGEST_DOMAIN);
        hash.update(&bytes[..digest_start]);
        bytes[digest_start..].copy_from_slice(&hash.finalize());
    }

    fn source() -> Vec<u8> {
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&[1; 16]);
        bytes.extend_from_slice(&[2; 16]);
        bytes.extend_from_slice(&[3; 16]);
        bytes.extend_from_slice(&[4; 16]);
        bytes.extend_from_slice(&5_u64.to_be_bytes());
        bytes.extend_from_slice(&[6; 32]);
        bytes.extend_from_slice(&7_u64.to_be_bytes());
        bytes.extend_from_slice(&8_u64.to_be_bytes());
        bytes.extend_from_slice(&[26; 16]);
        bytes.extend_from_slice(&[9; 16]);
        for marker in 10..=14 {
            bytes.extend_from_slice(&[marker; 32]);
        }
        bytes.extend_from_slice(&15_u64.to_be_bytes());
        bytes.extend_from_slice(&[16; 32]);
        let media_type = b"application/vnd.aos.environment+cbor";
        bytes.push(u8::try_from(media_type.len()).unwrap());
        bytes.extend_from_slice(media_type);
        bytes.extend_from_slice(&[17; 32]);
        bytes.extend_from_slice(&18_u64.to_be_bytes());
        bytes.extend_from_slice(&[19; 32]);
        bytes.extend_from_slice(&[20; 32]);
        bytes.extend_from_slice(&21_u64.to_be_bytes());
        bytes.extend_from_slice(&22_u64.to_be_bytes());
        bytes.extend_from_slice(&[23; 32]);
        bytes.extend_from_slice(&[24; 32]);
        bytes.extend_from_slice(&25_u64.to_be_bytes());
        bytes.extend_from_slice(&[0; 32]);
        reseal(&mut bytes);
        bytes
    }

    #[test]
    fn exact_source_decodes_without_granting_challenge_authority() {
        let bytes = source();
        let decoded = decode_controller_execution_argument_source_v1(&bytes).unwrap();
        assert_eq!(decoded.execution().as_bytes(), &[1; 16]);
        assert_eq!(decoded.create_operation().as_bytes(), &[2; 16]);
        assert_eq!(decoded.assignment_digest().as_bytes(), &[6; 32]);
        assert_eq!(decoded.host_boot_id(), [26; 16]);
        assert_eq!(
            decoded.accepted_output_record_digest().as_bytes(),
            &[12; 32]
        );
        assert_eq!(decoded.environment_descriptor().encoded_size(), 18);
        assert_eq!(decoded.controller_head_sequence(), 22);
        assert_eq!(decoded.issuer_nonce(), [24; 32]);
        assert_eq!(decoded.deadline_boottime_nanoseconds(), 25);
    }

    #[test]
    fn source_rejects_tampering_truncation_and_trailing_bytes() {
        let bytes = source();
        for length in 0..bytes.len() {
            assert!(decode_controller_execution_argument_source_v1(&bytes[..length]).is_err());
        }
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(decode_controller_execution_argument_source_v1(&extra).is_err());

        for offset in 0..bytes.len() {
            let mut tampered = bytes.clone();
            tampered[offset] ^= 1;
            assert!(
                decode_controller_execution_argument_source_v1(&tampered).is_err(),
                "changed byte {offset} remained canonical"
            );
        }
    }

    #[test]
    fn source_rejects_zero_accepted_create_and_noncanonical_media_type() {
        let mut bytes = source();
        bytes[8..24].fill(0);
        reseal(&mut bytes);
        assert!(decode_controller_execution_argument_source_v1(&bytes).is_err());

        let mut bytes = source();
        bytes[128..144].fill(0);
        reseal(&mut bytes);
        assert!(decode_controller_execution_argument_source_v1(&bytes).is_err());

        let mut bytes = source();
        let deadline_start = bytes.len() - 32 - 8;
        bytes[deadline_start..deadline_start + 8].fill(0);
        reseal(&mut bytes);
        assert!(decode_controller_execution_argument_source_v1(&bytes).is_err());

        let mut bytes = source();
        let media_type_start = bytes
            .windows(b"application/vnd.aos.environment+cbor".len())
            .position(|window| window == b"application/vnd.aos.environment+cbor")
            .unwrap();
        bytes[media_type_start] = b'A';
        reseal(&mut bytes);
        assert!(decode_controller_execution_argument_source_v1(&bytes).is_err());
    }

    #[test]
    fn argument_source_sealed_reference_checks_attempt_bytes_boot_and_both_deadlines() {
        let source = source();
        let fields = host_argument_source_content_fields_v1(
            [31; 16],
            ExecutionId::from_bytes([1; 16]),
            OperationId::from_bytes([2; 16]),
            &source,
        )
        .unwrap();
        let mut request = ObserveHostRuntimeArgumentRequestV1 {
            header: Some(RequestHeader {
                protocol_major: 1,
                request_id: vec![31; 16],
                audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
                deadline_boottime_nanoseconds: 10,
                maximum_response_bytes: 4_096,
                ..Default::default()
            })
            .into(),
            source_transfer_version: 1,
            source_content_bytes: fields.bytes(),
            source_content_digest: fields.digest().to_vec(),
            source_digest: fields.source_digest().as_bytes().to_vec(),
            source_attempt_commitment: fields.attempt_commitment().to_vec(),
            execution_id: vec![1; 16],
            create_operation_id: vec![2; 16],
            ..Default::default()
        };
        let peer = PeerCredentials {
            uid: 100,
            gid: 200,
            pid: Some(300),
        };
        let policy = PeerPolicy {
            uid: 100,
            gid: Some(200),
            audience: Audience::AUDIENCE_NODE_CONTROLLER,
        };
        let decode = |request: &ObserveHostRuntimeArgumentRequestV1| {
            decode_host_runtime_argument_request_v1(&request.encode_to_vec(), peer, policy, 1)
        };

        let decoded = decode(&request).unwrap();
        assert!(decoded.verify_source(&source, [26; 16], 1).is_ok());
        assert!(decoded.verify_source(&source, [27; 16], 1).is_err());
        assert!(decoded.verify_source(&source, [26; 16], 10).is_err());
        assert!(decoded.verify_source(&source, [26; 16], 25).is_err());

        let mut changed = source.clone();
        changed[9] ^= 1;
        assert!(decoded.verify_source(&changed, [26; 16], 1).is_err());
        request.source_attempt_commitment[0] ^= 1;
        assert!(decode(&request).is_err());
    }
}

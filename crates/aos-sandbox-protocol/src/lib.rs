//! Validates hostile node-local sandbox protocol messages.
//!
//! Unix transports obtain peer credentials from the accepted socket and pass
//! them here as values. This crate binds those credentials to a single broker
//! audience, rejects unknown protobuf fields and enums, applies message and
//! response bounds, validates assignment fences, and resolves portable
//! descriptors through the closed role registry before privileged code sees a
//! request.

use aos_proto::aos::sandbox::local::v1::{
    ApplyGuardianRequest, ApplyGuestExecutionRequest, ApplyMountRequest, ApplyNetworkRequest,
    ApplyRuntimeRequest, ApplyStorageRequest, AssignmentFence, Audience, Descriptor, MountAction,
    RequestHeader,
};
use aos_sandbox_core::{
    DescriptorRole, MediaType, ObjectDescriptor, ObjectDigest, ProtocolId, ProtocolVersion,
    RegistryError, negotiate_protocol, validate_descriptor_role,
};
use buffa::Message as _;

/// Default maximum encoded local request accepted before protobuf decoding.
pub const MAXIMUM_REQUEST_BYTES: usize = 1024 * 1024;
/// Default maximum response allocation a request may ask a broker to produce.
pub const MAXIMUM_RESPONSE_BYTES: u32 = 16 * 1024 * 1024;

/// Carries credentials obtained from the accepted Unix socket.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerCredentials {
    /// Effective peer user ID reported by the kernel.
    pub uid: u32,
    /// Effective peer group ID reported by the kernel.
    pub gid: u32,
    /// Peer process ID reported by the kernel, used only for audit correlation.
    pub pid: Option<u32>,
}

/// Defines the single identity and audience accepted by one broker socket.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerPolicy {
    /// Required peer user ID.
    pub uid: u32,
    /// Required peer group ID, when the socket contract binds both values.
    pub gid: Option<u32>,
    /// Sole protocol audience served by this socket.
    pub audience: Audience,
}

/// Carries an accepted request header after peer and bound validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedHeader {
    request_id: [u8; 16],
    deadline_boottime_nanoseconds: u64,
    maximum_response_bytes: u32,
}

impl ValidatedHeader {
    /// Returns the nonzero request identifier.
    #[must_use]
    pub const fn request_id(&self) -> &[u8; 16] {
        &self.request_id
    }

    /// Returns the absolute `CLOCK_BOOTTIME` request deadline.
    #[must_use]
    pub const fn deadline_boottime_nanoseconds(&self) -> u64 {
        self.deadline_boottime_nanoseconds
    }

    /// Returns the admitted response-byte ceiling.
    #[must_use]
    pub const fn maximum_response_bytes(&self) -> u32 {
        self.maximum_response_bytes
    }
}

/// Carries a mount request only after all common and descriptor checks pass.
#[derive(Clone, Debug, PartialEq)]
pub struct ValidatedMountRequest {
    header: ValidatedHeader,
    request: ApplyMountRequest,
    view_revision: Option<ObjectDescriptor>,
}

impl ValidatedMountRequest {
    /// Returns the validated common header.
    #[must_use]
    pub const fn header(&self) -> &ValidatedHeader {
        &self.header
    }

    /// Returns the original request after hostile-input validation.
    #[must_use]
    pub const fn request(&self) -> &ApplyMountRequest {
        &self.request
    }

    /// Returns the validated view descriptor when the action supplies one.
    #[must_use]
    pub const fn view_revision(&self) -> Option<&ObjectDescriptor> {
        self.view_revision.as_ref()
    }
}

/// Reports a malformed or unauthorized local broker request.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProtocolValidationError {
    /// The encoded request exceeds the broker's pre-decode byte ceiling.
    #[error("local request exceeds the maximum encoded byte length")]
    RequestTooLarge,
    /// Protobuf wire decoding failed before semantic validation.
    #[error("malformed local protobuf request: {0}")]
    MalformedWire(String),
    /// A required message field is absent.
    #[error("required local protocol field {0} is absent")]
    MissingField(&'static str),
    /// An ID or digest has another byte length or is the all-zero sentinel.
    #[error("local protocol field {field} is not an exact nonzero {bytes}-byte value")]
    InvalidFixedBytes {
        /// Field whose value failed validation.
        field: &'static str,
        /// Required byte length.
        bytes: usize,
    },
    /// The accepted socket peer does not match the fixed broker policy.
    #[error("Unix peer credentials do not match the broker socket policy")]
    PeerCredentialMismatch,
    /// The request targets another broker audience or an unknown enum value.
    #[error("local request audience is unknown or does not match the broker socket")]
    AudienceMismatch,
    /// The request protocol version cannot be negotiated by this broker.
    #[error("local protocol version is incompatible: {0}")]
    Protocol(#[from] RegistryError),
    /// The request deadline is absent or already expired.
    #[error("local request deadline is absent or expired")]
    DeadlineExpired,
    /// The response ceiling is zero or exceeds the broker bound.
    #[error("local request response-byte ceiling is invalid")]
    InvalidResponseBound,
    /// An authority-bearing local message contains unregistered fields.
    #[error("authority-bearing local message contains unknown protobuf fields")]
    UnknownFields,
    /// A closed action is absent or unknown.
    #[error("local request action is unspecified or unknown")]
    UnknownAction,
    /// A descriptor is malformed or appears in the wrong semantic role.
    #[error("invalid local descriptor: {0}")]
    InvalidDescriptor(String),
}

/// Decodes and validates one mount-broker request from hostile wire bytes.
///
/// # Errors
///
/// Returns [`ProtocolValidationError`] for size/wire failures, unknown fields
/// or enums, peer/audience mismatch, stale deadline, invalid assignment fence,
/// or a view descriptor with an unregistered media type or role.
pub fn decode_mount_request(
    bytes: &[u8],
    peer: PeerCredentials,
    policy: PeerPolicy,
    now_boottime_nanoseconds: u64,
) -> Result<ValidatedMountRequest, ProtocolValidationError> {
    if bytes.len() > MAXIMUM_REQUEST_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let request = ApplyMountRequest::decode_from_slice(bytes)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !request.__buffa_unknown_fields.is_empty() {
        return Err(ProtocolValidationError::UnknownFields);
    }
    let header = request
        .header
        .as_option()
        .ok_or(ProtocolValidationError::MissingField("header"))?;
    let header = validate_request_header(
        header,
        peer,
        policy,
        ProtocolId::MountBroker,
        now_boottime_nanoseconds,
    )?;
    validate_fence(
        request
            .fence
            .as_option()
            .ok_or(ProtocolValidationError::MissingField("fence"))?,
    )?;
    let action = request
        .action
        .as_known()
        .filter(|action| *action != MountAction::MOUNT_ACTION_UNSPECIFIED)
        .ok_or(ProtocolValidationError::UnknownAction)?;
    let view_revision = match request.view_revision.as_option() {
        Some(descriptor) => Some(validate_descriptor(
            descriptor,
            DescriptorRole::FilesystemViewRevision,
        )?),
        None if matches!(
            action,
            MountAction::MOUNT_ACTION_CREATE_DETACHED
                | MountAction::MOUNT_ACTION_INSTALL
                | MountAction::MOUNT_ACTION_REPLACE
        ) =>
        {
            return Err(ProtocolValidationError::MissingField("view_revision"));
        }
        None => None,
    };

    Ok(ValidatedMountRequest {
        header,
        request,
        view_revision,
    })
}

/// Validates one broker header against kernel-supplied peer credentials.
///
/// Broker frontends call this immediately after bounded wire decoding and
/// before dispatching a fixed verb. The selected [`ProtocolId`] keeps local
/// compatibility domains independent.
///
/// # Errors
///
/// Returns [`ProtocolValidationError`] for unknown fields, peer or audience
/// mismatch, incompatible versions, invalid request IDs, expired deadlines,
/// or response allocations outside the fixed bound.
pub fn validate_request_header(
    header: &RequestHeader,
    peer: PeerCredentials,
    policy: PeerPolicy,
    protocol: ProtocolId,
    now_boottime_nanoseconds: u64,
) -> Result<ValidatedHeader, ProtocolValidationError> {
    if !header.__buffa_unknown_fields.is_empty() {
        return Err(ProtocolValidationError::UnknownFields);
    }
    if peer.uid != policy.uid || policy.gid.is_some_and(|gid| peer.gid != gid) {
        return Err(ProtocolValidationError::PeerCredentialMismatch);
    }
    if header.audience.as_known() != Some(policy.audience)
        || policy.audience == Audience::AUDIENCE_UNSPECIFIED
    {
        return Err(ProtocolValidationError::AudienceMismatch);
    }
    negotiate_protocol(
        protocol,
        ProtocolVersion::new(
            u16::try_from(header.protocol_major).map_err(|_| {
                RegistryError::IncompatibleProtocol {
                    protocol,
                    offered_major: u16::MAX,
                    offered_minor: u16::MAX,
                    local_major: 1,
                    local_minor: 0,
                }
            })?,
            u16::try_from(header.protocol_minor).map_err(|_| {
                RegistryError::IncompatibleProtocol {
                    protocol,
                    offered_major: u16::MAX,
                    offered_minor: u16::MAX,
                    local_major: 1,
                    local_minor: 0,
                }
            })?,
        ),
    )?;
    let request_id = exact_nonzero::<16>(&header.request_id, "header.request_id")?;
    if header.deadline_boottime_nanoseconds <= now_boottime_nanoseconds {
        return Err(ProtocolValidationError::DeadlineExpired);
    }
    if header.maximum_response_bytes == 0 || header.maximum_response_bytes > MAXIMUM_RESPONSE_BYTES
    {
        return Err(ProtocolValidationError::InvalidResponseBound);
    }
    Ok(ValidatedHeader {
        request_id,
        deadline_boottime_nanoseconds: header.deadline_boottime_nanoseconds,
        maximum_response_bytes: header.maximum_response_bytes,
    })
}

fn validate_fence(fence: &AssignmentFence) -> Result<(), ProtocolValidationError> {
    if !fence.__buffa_unknown_fields.is_empty() {
        return Err(ProtocolValidationError::UnknownFields);
    }
    exact_nonzero::<16>(&fence.sandbox_id, "fence.sandbox_id")?;
    exact_nonzero::<16>(&fence.incarnation_id, "fence.incarnation_id")?;
    exact_nonzero::<32>(&fence.assignment_digest, "fence.assignment_digest")?;
    Ok(())
}

fn validate_descriptor(
    descriptor: &Descriptor,
    role: DescriptorRole,
) -> Result<ObjectDescriptor, ProtocolValidationError> {
    if !descriptor.__buffa_unknown_fields.is_empty() {
        return Err(ProtocolValidationError::UnknownFields);
    }
    let media_type = MediaType::new(descriptor.media_type.clone())
        .map_err(|error| ProtocolValidationError::InvalidDescriptor(error.to_string()))?;
    let digest = ObjectDigest::from_bytes(exact_nonzero::<32>(
        &descriptor.sha256,
        "descriptor.sha256",
    )?);
    let descriptor = ObjectDescriptor::new(media_type, digest, descriptor.encoded_size);
    validate_descriptor_role(role, &descriptor)
        .map_err(|error| ProtocolValidationError::InvalidDescriptor(error.to_string()))?;
    Ok(descriptor)
}

fn exact_nonzero<const N: usize>(
    bytes: &[u8],
    field: &'static str,
) -> Result<[u8; N], ProtocolValidationError> {
    let exact: [u8; N] = bytes
        .try_into()
        .map_err(|_| ProtocolValidationError::InvalidFixedBytes { field, bytes: N })?;
    if exact.iter().all(|byte| *byte == 0) {
        Err(ProtocolValidationError::InvalidFixedBytes { field, bytes: N })
    } else {
        Ok(exact)
    }
}

/// Exercises every privileged request decoder with arbitrary input bytes.
///
/// This entry point performs no effects and is intended for deterministic test
/// corpora and external coverage-guided fuzz engines. Successful protobuf
/// decoding is deliberately discarded; semantic entry points validate the
/// corresponding message before use.
pub fn exercise_malformed_request_decoders(bytes: &[u8]) {
    if bytes.len() > MAXIMUM_REQUEST_BYTES {
        return;
    }
    let _ = ApplyRuntimeRequest::decode_from_slice(bytes);
    let _ = ApplyStorageRequest::decode_from_slice(bytes);
    let _ = ApplyMountRequest::decode_from_slice(bytes);
    let _ = ApplyNetworkRequest::decode_from_slice(bytes);
    let _ = ApplyGuardianRequest::decode_from_slice(bytes);
    let _ = aos_proto::aos::sandbox::local::v1::GuestHandshakeRequest::decode_from_slice(bytes);
    let _ = ApplyGuestExecutionRequest::decode_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_mount_request() -> Vec<u8> {
        let mut request = ApplyMountRequest::default();
        let header = request.header.get_or_insert_default();
        header.protocol_major = 1;
        header.protocol_minor = 0;
        header.request_id = vec![1; 16];
        header.audience = Audience::AUDIENCE_NODE_CONTROLLER.into();
        header.deadline_boottime_nanoseconds = 101;
        header.maximum_response_bytes = 4096;
        let fence = request.fence.get_or_insert_default();
        fence.sandbox_id = vec![2; 16];
        fence.incarnation_id = vec![3; 16];
        fence.assignment_epoch = 1;
        fence.desired_generation = 1;
        fence.assignment_digest = vec![4; 32];
        request.action = MountAction::MOUNT_ACTION_CREATE_DETACHED.into();
        request.attachment_id = vec![5; 16];
        request.destination_slot_id = vec![6; 16];
        let descriptor = request.view_revision.get_or_insert_default();
        descriptor.media_type = "application/vnd.aos.sandbox.view.v1+cbor".to_owned();
        descriptor.sha256 = vec![7; 32];
        descriptor.encoded_size = 1;
        request.encode_to_vec()
    }

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

    #[test]
    fn mount_validation_binds_peer_audience_fence_and_descriptor_role() {
        let encoded = valid_mount_request();
        let validated = decode_mount_request(&encoded, peer(), policy(), 100)
            .unwrap_or_else(|error| panic!("valid request failed: {error}"));
        assert_eq!(validated.header().request_id(), &[1; 16]);

        let mut wrong_peer = peer();
        wrong_peer.uid = 0;
        assert_eq!(
            decode_mount_request(&encoded, wrong_peer, policy(), 100),
            Err(ProtocolValidationError::PeerCredentialMismatch)
        );
    }

    #[test]
    fn malformed_request_corpus_never_panics_or_allocates_unboundedly() {
        let seed = valid_mount_request();
        for length in 0..seed.len() {
            exercise_malformed_request_decoders(&seed[..length]);
        }

        let mut state = 0x9e37_79b9_u32;
        for length in 0..=512 {
            let mut bytes = vec![0; length];
            for byte in &mut bytes {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                *byte = state as u8;
            }
            exercise_malformed_request_decoders(&bytes);
        }
    }

    #[test]
    fn unknown_fields_and_descriptor_type_confusion_fail_closed() {
        let mut encoded = valid_mount_request();
        encoded.extend_from_slice(&[0xf8, 0x07, 0x01]); // Unknown field 127.
        assert_eq!(
            decode_mount_request(&encoded, peer(), policy(), 100),
            Err(ProtocolValidationError::UnknownFields)
        );

        let mut request = ApplyMountRequest::decode_from_slice(&valid_mount_request())
            .unwrap_or_else(|error| panic!("fixture decode failed: {error}"));
        request.view_revision.get_or_insert_default().media_type =
            "application/vnd.aos.sandbox.tree.v1+cbor".to_owned();
        assert!(matches!(
            decode_mount_request(&request.encode_to_vec(), peer(), policy(), 100),
            Err(ProtocolValidationError::InvalidDescriptor(_))
        ));
    }
}

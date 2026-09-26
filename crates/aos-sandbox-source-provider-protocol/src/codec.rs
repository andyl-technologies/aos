//! Canonical SourceProvider 1.0 wire encoding.
//!
//! Integer fields are big-endian, discriminants use closed numeric registries,
//! and byte strings carry one bounded `u32` length. No implementation-native
//! enum representation crosses this process boundary. Hello bodies and every
//! response status are signed envelopes; an unsigned typed subject is never a
//! complete wire message.
//!
//! ```text
//! AOSSPV01 || major:u16be || minor:u16be || method:u8 || kind:u8 ||
//! flags:u16be=0 || reserved:u32be=0 || body-length:u32be || typed-body
//! ```

use aos_sandbox_core::ObjectDigest;

use crate::crypto::{
    SignedSourceProviderHelloV1, SignedSourceProviderInventoryV1, SignedSourceProviderReceiptV1,
    SignedSourceProviderRequestV1, SignedSourceProviderStatusV1, SignedSourceReleaseReceiptV1,
    decode_signer, encode_signer,
};
use crate::model::{
    AcquireSourceRequestV1, AcquireSourceResponseV1, InventoryLeaseStateV1,
    InventorySourceRequestV1, InventorySourceResponseV1, MAXIMUM_BINDING_BYTES,
    MAXIMUM_INVENTORY_ENTRIES, ReleaseSourceRequestV1, ReleaseSourceResponseV1,
    SourceExportLeaseV1, SourceProviderAuthorityV1, SourceProviderDescriptorRole,
    SourceProviderHelloV1, SourceProviderInventoryEntryV1, SourceProviderInventoryV1,
    SourceProviderMethod, SourceProviderPeerRole, SourceProviderReceiptV1,
    SourceProviderResponseStatusV1, SourceProviderStatus, SourceProviderValidationError,
    SourceReleaseReceiptV1, SourceResourceV1, SourceUseV1,
};
use crate::proof::{
    BestEffortReplicaProofV1, ImmutablePublisherTreeProofV1, LocalLiveExportProofV1,
    RecursiveTopologyProofV1, SourceProviderProofV1, ZfsHeldSnapshotProofV1,
};

const FRAME_MAGIC: &[u8; 8] = b"AOSSPV01";
const PROTOCOL_MAJOR: u16 = 1;
const PROTOCOL_MINOR: u16 = 0;
const FRAME_HEADER_BYTES: usize = 24;
const HELLO_METHOD_MASK: u32 = 0b1111;
const HELLO_FEATURE_MASK: u32 = 0b11;
const HELLO_DESCRIPTOR_MASK: u32 = 0b1;
const INVENTORY_ENTRY_BYTES: usize = 344;

/// Largest complete SourceProvider 1.0 record.
pub const MAXIMUM_FRAME_BYTES: usize = 1024 * 1024;
/// Exact canonical SourceProvider 1.0 hello subject size.
pub const SOURCE_PROVIDER_HELLO_SUBJECT_BYTES: usize = 424;
/// Exact signed SourceProvider 1.0 hello envelope size.
pub const SIGNED_SOURCE_PROVIDER_HELLO_BYTES: usize = 628;
/// Exact outer SourceProvider 1.0 hello frame size.
pub const SOURCE_PROVIDER_HELLO_FRAME_BYTES: usize = 652;

const _: () =
    assert!(SIGNED_SOURCE_PROVIDER_HELLO_BYTES == SOURCE_PROVIDER_HELLO_SUBJECT_BYTES + 204);
const _: () = assert!(
    SOURCE_PROVIDER_HELLO_FRAME_BYTES == SIGNED_SOURCE_PROVIDER_HELLO_BYTES + FRAME_HEADER_BYTES
);

/// Reports malformed, noncanonical, or oversized SourceProvider bytes.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SourceProviderFrameError {
    /// The fixed frame or a message body is truncated or has trailing bytes.
    #[error("invalid SourceProvider frame")]
    InvalidFrame,
    /// The frame uses a protocol version other than exact 1.0.
    #[error("unsupported SourceProvider protocol version {major}.{minor}; local version is 1.0")]
    UnsupportedVersion {
        /// Offered major version.
        major: u16,
        /// Offered minor version.
        minor: u16,
    },
    /// A method, record kind, status, role, feature, or proof kind is unknown.
    #[error("unknown SourceProvider discriminant")]
    UnknownDiscriminant,
    /// Flags or reserved bytes are nonzero.
    #[error("SourceProvider reserved bytes or flags are nonzero")]
    NonzeroReserved,
    /// A length is empty, exceeds its bound, or exceeds remaining input.
    #[error("invalid or oversized SourceProvider length")]
    InvalidLength,
    /// The decoded value violates semantic invariants.
    #[error("invalid SourceProvider value: {0}")]
    InvalidValue(#[from] SourceProviderValidationError),
}

/// Distinguishes request and response records independently of methods.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SourceProviderFrameKind {
    /// Client-to-provider request.
    Request = 1,
    /// Provider-to-client response.
    Response = 2,
}

/// Carries one decoded outer frame and canonical typed-method body.
#[derive(Clone, Debug, Eq, PartialEq)]
struct SourceProviderFrame {
    method: SourceProviderMethod,
    kind: SourceProviderFrameKind,
    body: Vec<u8>,
}

impl SourceProviderFrame {
    /// Constructs one bounded SourceProvider frame.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderFrameError::InvalidLength`] for an empty or
    /// oversized body.
    fn new(
        method: SourceProviderMethod,
        kind: SourceProviderFrameKind,
        body: Vec<u8>,
    ) -> Result<Self, SourceProviderFrameError> {
        if body.is_empty() || body.len() > MAXIMUM_FRAME_BYTES - FRAME_HEADER_BYTES {
            return Err(SourceProviderFrameError::InvalidLength);
        }
        Ok(Self { method, kind, body })
    }
}

/// Carries one fully typed SourceProvider 1.0 wire message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SourceProviderMessageV1 {
    /// Root Mount session introduction.
    HelloRequest(SignedSourceProviderHelloV1),
    /// Provider session introduction.
    HelloResponse(SignedSourceProviderHelloV1),
    /// Signed Root Mount Acquire query.
    AcquireRequest(SignedSourceProviderRequestV1),
    /// Acquire status and optional signed provider receipt.
    AcquireResponse(AcquireSourceResponseV1),
    /// Signed Root Mount Release query.
    ReleaseRequest(SignedSourceProviderRequestV1),
    /// Release status and optional signed provider receipt.
    ReleaseResponse(ReleaseSourceResponseV1),
    /// Signed Root Mount Inventory query.
    InventoryRequest(SignedSourceProviderRequestV1),
    /// Inventory status and optional signed provider snapshot.
    InventoryResponse(InventorySourceResponseV1),
}

/// Validates descriptor roles against the complete typed message phase.
///
/// # Errors
///
/// Returns [`SourceProviderValidationError::DescriptorContract`] unless a
/// completed Acquire response carries exactly one `SourceRoot` and every
/// request, hello, other response, and non-complete status carries none.
pub fn validate_message_descriptor_contract(
    message: &SourceProviderMessageV1,
    roles: &[SourceProviderDescriptorRole],
) -> Result<(), SourceProviderValidationError> {
    let requires_source = matches!(
        message,
        SourceProviderMessageV1::AcquireResponse(response)
            if response.status() == SourceProviderStatus::Complete
    );
    if requires_source && roles == [SourceProviderDescriptorRole::SourceRoot] {
        return Ok(());
    }
    if !requires_source && roles.is_empty() {
        return Ok(());
    }
    Err(SourceProviderValidationError::DescriptorContract)
}

/// Encodes one exact SourceProvider 1.0 outer frame.
#[must_use]
fn encode_frame(frame: &SourceProviderFrame) -> Vec<u8> {
    let mut writer = Writer::with_capacity(FRAME_HEADER_BYTES + frame.body.len());
    writer.bytes(FRAME_MAGIC);
    writer.u16(PROTOCOL_MAJOR);
    writer.u16(PROTOCOL_MINOR);
    writer.u8(frame.method as u8);
    writer.u8(frame.kind as u8);
    writer.u16(0);
    writer.u32(0);
    writer.u32(frame.body.len() as u32);
    writer.bytes(&frame.body);
    writer.finish()
}

/// Decodes one exact SourceProvider 1.0 outer frame.
///
/// # Errors
///
/// Returns [`SourceProviderFrameError`] for truncation, trailing bytes,
/// oversized records, unknown discriminants, nonzero reserved values, or a
/// protocol version other than exact 1.0.
fn decode_frame(bytes: &[u8]) -> Result<SourceProviderFrame, SourceProviderFrameError> {
    if bytes.len() < FRAME_HEADER_BYTES || bytes.len() > MAXIMUM_FRAME_BYTES {
        return Err(SourceProviderFrameError::InvalidLength);
    }
    let mut reader = Reader::new(bytes);
    if reader.array::<8>()? != *FRAME_MAGIC {
        return Err(SourceProviderFrameError::InvalidFrame);
    }
    let major = reader.u16()?;
    let minor = reader.u16()?;
    if major != PROTOCOL_MAJOR || minor != PROTOCOL_MINOR {
        return Err(SourceProviderFrameError::UnsupportedVersion { major, minor });
    }
    let method = decode_method(reader.u8()?)?;
    let kind = match reader.u8()? {
        1 => SourceProviderFrameKind::Request,
        2 => SourceProviderFrameKind::Response,
        _ => return Err(SourceProviderFrameError::UnknownDiscriminant),
    };
    if reader.u16()? != 0 || reader.u32()? != 0 {
        return Err(SourceProviderFrameError::NonzeroReserved);
    }
    let body_length = reader.u32()? as usize;
    if body_length == 0 || body_length > MAXIMUM_FRAME_BYTES - FRAME_HEADER_BYTES {
        return Err(SourceProviderFrameError::InvalidLength);
    }
    let body = reader.take(body_length)?.to_vec();
    reader.finish()?;
    SourceProviderFrame::new(method, kind, body)
}

/// Encodes one fully typed exact SourceProvider 1.0 message.
///
/// # Errors
///
/// Returns [`SourceProviderFrameError`] when a hello uses the wrong role, a
/// signed request method differs from its message variant, or the complete
/// frame exceeds the protocol ceiling.
pub fn encode_message(
    message: &SourceProviderMessageV1,
) -> Result<Vec<u8>, SourceProviderFrameError> {
    let (method, kind, body) = message_parts(message)?;
    let frame = SourceProviderFrame::new(method, kind, body)?;
    Ok(encode_frame(&frame))
}

/// Decodes one fully typed exact SourceProvider 1.0 message.
///
/// # Errors
///
/// Returns [`SourceProviderFrameError`] for any malformed frame, method/kind
/// mismatch, wrong hello role, malformed signed envelope, or typed body error.
pub fn decode_message(bytes: &[u8]) -> Result<SourceProviderMessageV1, SourceProviderFrameError> {
    let frame = decode_frame(bytes)?;
    match (frame.method, frame.kind) {
        (SourceProviderMethod::Hello, SourceProviderFrameKind::Request) => {
            let hello = SignedSourceProviderHelloV1::from_canonical_bytes(&frame.body)
                .map_err(|_| SourceProviderFrameError::InvalidFrame)?;
            if hello.subject().role() != SourceProviderPeerRole::RootMount {
                return Err(SourceProviderFrameError::InvalidFrame);
            }
            Ok(SourceProviderMessageV1::HelloRequest(hello))
        }
        (SourceProviderMethod::Hello, SourceProviderFrameKind::Response) => {
            let hello = SignedSourceProviderHelloV1::from_canonical_bytes(&frame.body)
                .map_err(|_| SourceProviderFrameError::InvalidFrame)?;
            if hello.subject().role() != SourceProviderPeerRole::Provider {
                return Err(SourceProviderFrameError::InvalidFrame);
            }
            Ok(SourceProviderMessageV1::HelloResponse(hello))
        }
        (method @ SourceProviderMethod::Acquire, SourceProviderFrameKind::Request)
        | (method @ SourceProviderMethod::Release, SourceProviderFrameKind::Request)
        | (method @ SourceProviderMethod::Inventory, SourceProviderFrameKind::Request) => {
            let signed = SignedSourceProviderRequestV1::from_canonical_bytes(&frame.body)
                .map_err(|_| SourceProviderFrameError::InvalidFrame)?;
            if signed.method() != method {
                return Err(SourceProviderFrameError::InvalidFrame);
            }
            Ok(match method {
                SourceProviderMethod::Acquire => SourceProviderMessageV1::AcquireRequest(signed),
                SourceProviderMethod::Release => SourceProviderMessageV1::ReleaseRequest(signed),
                SourceProviderMethod::Inventory => {
                    SourceProviderMessageV1::InventoryRequest(signed)
                }
                SourceProviderMethod::Hello => return Err(SourceProviderFrameError::InvalidFrame),
            })
        }
        (SourceProviderMethod::Acquire, SourceProviderFrameKind::Response) => {
            let response = decode_acquire_response(&frame.body)?;
            validate_acquire_response_result(&response)?;
            Ok(SourceProviderMessageV1::AcquireResponse(response))
        }
        (SourceProviderMethod::Release, SourceProviderFrameKind::Response) => {
            let response = decode_release_response(&frame.body)?;
            validate_release_response_result(&response)?;
            Ok(SourceProviderMessageV1::ReleaseResponse(response))
        }
        (SourceProviderMethod::Inventory, SourceProviderFrameKind::Response) => {
            let response = decode_inventory_response(&frame.body)?;
            validate_inventory_response_result(&response)?;
            Ok(SourceProviderMessageV1::InventoryResponse(response))
        }
    }
}

fn message_parts(
    message: &SourceProviderMessageV1,
) -> Result<(SourceProviderMethod, SourceProviderFrameKind, Vec<u8>), SourceProviderFrameError> {
    match message {
        SourceProviderMessageV1::HelloRequest(hello)
            if hello.subject().role() == SourceProviderPeerRole::RootMount =>
        {
            Ok((
                SourceProviderMethod::Hello,
                SourceProviderFrameKind::Request,
                hello.to_canonical_bytes(),
            ))
        }
        SourceProviderMessageV1::HelloResponse(hello)
            if hello.subject().role() == SourceProviderPeerRole::Provider =>
        {
            Ok((
                SourceProviderMethod::Hello,
                SourceProviderFrameKind::Response,
                hello.to_canonical_bytes(),
            ))
        }
        SourceProviderMessageV1::AcquireRequest(signed)
            if signed.method() == SourceProviderMethod::Acquire =>
        {
            Ok((
                SourceProviderMethod::Acquire,
                SourceProviderFrameKind::Request,
                signed.to_canonical_bytes(),
            ))
        }
        SourceProviderMessageV1::ReleaseRequest(signed)
            if signed.method() == SourceProviderMethod::Release =>
        {
            Ok((
                SourceProviderMethod::Release,
                SourceProviderFrameKind::Request,
                signed.to_canonical_bytes(),
            ))
        }
        SourceProviderMessageV1::InventoryRequest(signed)
            if signed.method() == SourceProviderMethod::Inventory =>
        {
            Ok((
                SourceProviderMethod::Inventory,
                SourceProviderFrameKind::Request,
                signed.to_canonical_bytes(),
            ))
        }
        SourceProviderMessageV1::AcquireResponse(response) => {
            validate_acquire_response_result(response)?;
            Ok((
                SourceProviderMethod::Acquire,
                SourceProviderFrameKind::Response,
                encode_acquire_response(response),
            ))
        }
        SourceProviderMessageV1::ReleaseResponse(response) => {
            validate_release_response_result(response)?;
            Ok((
                SourceProviderMethod::Release,
                SourceProviderFrameKind::Response,
                encode_release_response(response),
            ))
        }
        SourceProviderMessageV1::InventoryResponse(response) => {
            validate_inventory_response_result(response)?;
            Ok((
                SourceProviderMethod::Inventory,
                SourceProviderFrameKind::Response,
                encode_inventory_response(response),
            ))
        }
        _ => Err(SourceProviderFrameError::InvalidFrame),
    }
}

fn validate_acquire_response_result(
    response: &AcquireSourceResponseV1,
) -> Result<(), SourceProviderFrameError> {
    if let Some(bytes) = response.signed_receipt() {
        SignedSourceProviderReceiptV1::from_canonical_bytes(bytes)
            .map_err(|_| SourceProviderFrameError::InvalidFrame)?;
    }
    Ok(())
}

fn validate_release_response_result(
    response: &ReleaseSourceResponseV1,
) -> Result<(), SourceProviderFrameError> {
    if let Some(bytes) = response.signed_receipt() {
        SignedSourceReleaseReceiptV1::from_canonical_bytes(bytes)
            .map_err(|_| SourceProviderFrameError::InvalidFrame)?;
    }
    Ok(())
}

fn validate_inventory_response_result(
    response: &InventorySourceResponseV1,
) -> Result<(), SourceProviderFrameError> {
    if let Some(bytes) = response.signed_inventory() {
        SignedSourceProviderInventoryV1::from_canonical_bytes(bytes)
            .map_err(|_| SourceProviderFrameError::InvalidFrame)?;
    }
    Ok(())
}

/// Encodes one exact Hello body including closed method, feature, and role sets.
#[must_use]
pub fn encode_hello(value: &SourceProviderHelloV1) -> Vec<u8> {
    let mut writer = Writer::with_capacity(SOURCE_PROVIDER_HELLO_SUBJECT_BYTES);
    writer.u8(value.role as u8);
    writer.zeros(7);
    writer.bytes(&value.nonce);
    writer.bytes(&value.process_instance);
    writer.bytes(&value.kernel_boot_id);
    let mut signer = Vec::with_capacity(120);
    encode_signer(&mut signer, &value.traffic_signer);
    writer.bytes(&signer);
    signer.clear();
    encode_signer(&mut signer, &value.expected_peer_traffic_signer);
    writer.bytes(&signer);
    writer.bytes(&value.route_id);
    writer.u64(value.route_generation);
    writer.digest(value.route_digest);
    match value.client_hello_digest {
        Some(digest) => {
            writer.u8(1);
            writer.zeros(7);
            writer.digest(digest);
        }
        None => {
            writer.u8(0);
            writer.zeros(7);
            writer.zeros(32);
        }
    }
    writer.u32(HELLO_METHOD_MASK);
    writer.u32(HELLO_FEATURE_MASK);
    writer.u32(HELLO_DESCRIPTOR_MASK);
    writer.u8(value.proof_class_capabilities);
    writer.u8(u8::from(value.supports_recursive) | (u8::from(value.supports_kernel_coupled) << 1));
    writer.u16(0);
    writer.finish()
}

/// Decodes one exact Hello body.
///
/// # Errors
///
/// Returns [`SourceProviderFrameError`] for truncation, trailing data, unknown
/// roles/methods/features/descriptor roles, reserved bytes, or sentinels.
pub fn decode_hello(bytes: &[u8]) -> Result<SourceProviderHelloV1, SourceProviderFrameError> {
    if bytes.len() != SOURCE_PROVIDER_HELLO_SUBJECT_BYTES {
        return Err(SourceProviderFrameError::InvalidLength);
    }
    let mut reader = Reader::new(bytes);
    let role = match reader.u8()? {
        1 => SourceProviderPeerRole::RootMount,
        2 => SourceProviderPeerRole::Provider,
        _ => return Err(SourceProviderFrameError::UnknownDiscriminant),
    };
    reader.require_zeros(7)?;
    let nonce = reader.array::<32>()?;
    let process_instance = reader.array::<16>()?;
    let kernel_boot_id = reader.array::<16>()?;
    let traffic_signer =
        decode_signer(reader.take(120)?).map_err(|_| SourceProviderFrameError::InvalidFrame)?;
    let expected_peer_traffic_signer =
        decode_signer(reader.take(120)?).map_err(|_| SourceProviderFrameError::InvalidFrame)?;
    let route_id = reader.array::<16>()?;
    let route_generation = reader.u64()?;
    let route_digest = reader.digest()?;
    let has_client_digest = reader.u8()?;
    if has_client_digest > 1 {
        return Err(SourceProviderFrameError::UnknownDiscriminant);
    }
    reader.require_zeros(7)?;
    let client_digest_bytes = reader.array::<32>()?;
    let client_hello_digest = if has_client_digest == 1 {
        Some(ObjectDigest::from_bytes(client_digest_bytes))
    } else {
        if client_digest_bytes.iter().any(|byte| *byte != 0) {
            return Err(SourceProviderFrameError::NonzeroReserved);
        }
        None
    };
    if reader.u32()? != HELLO_METHOD_MASK
        || reader.u32()? != HELLO_FEATURE_MASK
        || reader.u32()? != HELLO_DESCRIPTOR_MASK
    {
        return Err(SourceProviderFrameError::NonzeroReserved);
    }
    let proof_class_capabilities = reader.u8()?;
    let capability_flags = reader.u8()?;
    if capability_flags & !0b11 != 0 || reader.u16()? != 0 {
        return Err(SourceProviderFrameError::NonzeroReserved);
    }
    reader.finish()?;
    SourceProviderHelloV1::new(
        role,
        nonce,
        process_instance,
        kernel_boot_id,
        traffic_signer,
        expected_peer_traffic_signer,
        route_id,
        route_generation,
        route_digest,
        client_hello_digest,
        proof_class_capabilities,
        capability_flags & 1 != 0,
        capability_flags & 2 != 0,
    )
    .map_err(Into::into)
}

/// Encodes one exact Acquire request subject.
#[must_use]
pub fn encode_acquire_request(value: &AcquireSourceRequestV1) -> Vec<u8> {
    let mut writer = Writer::new();
    if value.acquisition_version == crate::ACQUIRE_SOURCE_REQUEST_VERSION_V2 {
        writer.u16(crate::ACQUIRE_SOURCE_REQUEST_VERSION_V2);
        writer.zeros(6);
    }
    writer.digest(value.session_binding);
    writer.u64(value.sequence);
    writer.bytes(&value.request_id);
    writer.digest(value.acquisition_id);
    if value.acquisition_version == crate::ACQUIRE_SOURCE_REQUEST_VERSION_V2 {
        writer.u64(value.acquisition_sequence);
    }
    writer.sized_bytes(&value.prospective_apply_template);
    writer.digest(value.prospective_apply_template_digest);
    writer.u8(value.source_use as u8);
    writer.zeros(7);
    writer.bytes(&value.node_id);
    writer.bytes(&value.boot_id);
    writer.bytes(&value.holder_authority_id);
    writer.u64(value.holder_generation);
    writer.digest(value.holder_authority_digest);
    writer.sized_bytes(&value.binding);
    writer.digest(value.binding_digest);
    writer.i64(value.deadline_seconds);
    writer.u64(value.requested_lease_seconds);
    writer.digest(value.revocation_digest);
    writer.u8(u8::from(value.recursive) | (u8::from(value.kernel_coupled) << 1));
    writer.zeros(3);
    writer.u32(value.requested_maximum_submounts);
    writer.finish()
}

/// Decodes one exact Acquire request subject.
///
/// # Errors
///
/// Returns [`SourceProviderFrameError`] for malformed, unknown, reserved,
/// oversized, sentinel, or trailing fields.
pub fn decode_acquire_request(
    bytes: &[u8],
) -> Result<AcquireSourceRequestV1, SourceProviderFrameError> {
    let legacy = decode_acquire_request_v1(bytes).ok();
    let version_2 = decode_acquire_request_v2(bytes).ok();
    match (legacy, version_2) {
        (Some(value), None) | (None, Some(value)) => Ok(value),
        _ => Err(SourceProviderFrameError::InvalidFrame),
    }
}

fn decode_acquire_request_v1(
    bytes: &[u8],
) -> Result<AcquireSourceRequestV1, SourceProviderFrameError> {
    let mut reader = Reader::new(bytes);
    let session_binding = reader.digest()?;
    let sequence = reader.u64()?;
    let request_id = reader.array::<16>()?;
    let acquisition_id = reader.digest()?;
    decode_acquire_request_tail(
        reader,
        session_binding,
        sequence,
        request_id,
        acquisition_id,
        None,
    )
}

fn decode_acquire_request_v2(
    bytes: &[u8],
) -> Result<AcquireSourceRequestV1, SourceProviderFrameError> {
    let mut reader = Reader::new(bytes);
    if reader.u16()? != crate::ACQUIRE_SOURCE_REQUEST_VERSION_V2 {
        return Err(SourceProviderFrameError::InvalidFrame);
    }
    reader.require_zeros(6)?;
    let session_binding = reader.digest()?;
    let sequence = reader.u64()?;
    let request_id = reader.array::<16>()?;
    let acquisition_id = reader.digest()?;
    let acquisition_sequence = reader.u64()?;
    decode_acquire_request_tail(
        reader,
        session_binding,
        sequence,
        request_id,
        acquisition_id,
        Some(acquisition_sequence),
    )
}

fn decode_acquire_request_tail(
    mut reader: Reader<'_>,
    session_binding: ObjectDigest,
    sequence: u64,
    request_id: [u8; 16],
    acquisition_id: ObjectDigest,
    acquisition_sequence: Option<u64>,
) -> Result<AcquireSourceRequestV1, SourceProviderFrameError> {
    let prospective_apply_template = reader.sized_bytes(2 * 1024)?.to_vec();
    let prospective_apply_template_digest = reader.digest()?;
    let source_use = match reader.u8()? {
        1 => SourceUseV1::MountCreate,
        _ => return Err(SourceProviderFrameError::UnknownDiscriminant),
    };
    reader.require_zeros(7)?;
    let node_id = reader.array::<16>()?;
    let boot_id = reader.array::<16>()?;
    let holder_authority_id = reader.array::<16>()?;
    let holder_generation = reader.u64()?;
    let holder_authority_digest = reader.digest()?;
    let binding = reader.sized_bytes(MAXIMUM_BINDING_BYTES)?.to_vec();
    let binding_digest = reader.digest()?;
    let deadline_seconds = reader.i64()?;
    let requested_lease_seconds = reader.u64()?;
    let revocation_digest = reader.digest()?;
    let source_flags = reader.u8()?;
    if source_flags & !0b11 != 0 {
        return Err(SourceProviderFrameError::NonzeroReserved);
    }
    reader.require_zeros(3)?;
    let requested_maximum_submounts = reader.u32()?;
    reader.finish()?;
    let value = match acquisition_sequence {
        Some(acquisition_sequence) => AcquireSourceRequestV1::new_with_acquisition_sequence(
            session_binding,
            sequence,
            request_id,
            acquisition_id,
            acquisition_sequence,
            prospective_apply_template,
            prospective_apply_template_digest,
            source_use,
            node_id,
            boot_id,
            holder_authority_id,
            holder_generation,
            holder_authority_digest,
            binding,
            binding_digest,
            deadline_seconds,
            requested_lease_seconds,
            revocation_digest,
            source_flags & 1 != 0,
            requested_maximum_submounts,
            source_flags & 2 != 0,
        ),
        None => AcquireSourceRequestV1::new(
            session_binding,
            sequence,
            request_id,
            acquisition_id,
            prospective_apply_template,
            prospective_apply_template_digest,
            source_use,
            node_id,
            boot_id,
            holder_authority_id,
            holder_generation,
            holder_authority_digest,
            binding,
            binding_digest,
            deadline_seconds,
            requested_lease_seconds,
            revocation_digest,
            source_flags & 1 != 0,
            requested_maximum_submounts,
            source_flags & 2 != 0,
        ),
    };
    value.map_err(Into::into)
}

/// Encodes one provider-signed response-status subject.
#[must_use]
pub fn encode_response_status(value: &SourceProviderResponseStatusV1) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.u8(value.method as u8);
    writer.u8(value.status as u8);
    writer.zeros(6);
    writer.bytes(&value.request_id);
    writer.digest(value.signed_request_digest);
    writer.bytes(&value.provider_process_instance);
    writer.digest(value.session_binding);
    writer.u64(value.response_sequence);
    writer.digest(value.result_digest);
    writer.digest(value.descriptor_commitment);
    writer.finish()
}

/// Decodes one provider-signed response-status subject.
///
/// # Errors
///
/// Returns [`SourceProviderFrameError`] for malformed, unknown, reserved,
/// sentinel, or trailing fields.
pub fn decode_response_status(
    bytes: &[u8],
) -> Result<SourceProviderResponseStatusV1, SourceProviderFrameError> {
    let mut reader = Reader::new(bytes);
    let method = decode_method(reader.u8()?)?;
    let status = decode_status(reader.u8()?)?;
    reader.require_zeros(6)?;
    let request_id = reader.array::<16>()?;
    let signed_request_digest = reader.digest()?;
    let provider_process_instance = reader.array::<16>()?;
    let session_binding = reader.digest()?;
    let response_sequence = reader.u64()?;
    let result_digest = reader.digest()?;
    let descriptor_commitment = reader.digest()?;
    reader.finish()?;
    SourceProviderResponseStatusV1::new(
        method,
        request_id,
        signed_request_digest,
        status,
        provider_process_instance,
        session_binding,
        response_sequence,
        result_digest,
        descriptor_commitment,
    )
    .map_err(Into::into)
}

/// Encodes one exact Acquire response body.
#[must_use]
pub fn encode_acquire_response(value: &AcquireSourceResponseV1) -> Vec<u8> {
    encode_status_response(&value.signed_status, value.signed_receipt.as_deref())
}

/// Decodes one exact Acquire response body.
///
/// # Errors
///
/// Returns [`SourceProviderFrameError`] for malformed status/receipt shape,
/// truncation, trailing data, or an oversized receipt.
pub fn decode_acquire_response(
    bytes: &[u8],
) -> Result<AcquireSourceResponseV1, SourceProviderFrameError> {
    let (signed_status, signed_receipt) = decode_status_response(bytes, 64 * 1024)?;
    AcquireSourceResponseV1::new(signed_status, signed_receipt).map_err(Into::into)
}

/// Encodes one exact Release response body.
#[must_use]
pub fn encode_release_response(value: &ReleaseSourceResponseV1) -> Vec<u8> {
    encode_status_response(&value.signed_status, value.signed_receipt.as_deref())
}

/// Decodes one exact Release response body.
///
/// # Errors
///
/// Returns [`SourceProviderFrameError`] for malformed status/result shape,
/// truncation, trailing data, or an oversized signed receipt.
pub fn decode_release_response(
    bytes: &[u8],
) -> Result<ReleaseSourceResponseV1, SourceProviderFrameError> {
    let (signed_status, signed_result) = decode_status_response(bytes, 64 * 1024)?;
    ReleaseSourceResponseV1::new(signed_status, signed_result).map_err(Into::into)
}

/// Encodes one exact Inventory response body.
#[must_use]
pub fn encode_inventory_response(value: &InventorySourceResponseV1) -> Vec<u8> {
    encode_status_response(&value.signed_status, value.signed_inventory.as_deref())
}

/// Decodes one exact Inventory response body.
///
/// # Errors
///
/// Returns [`SourceProviderFrameError`] for malformed status/result shape,
/// truncation, trailing data, or an oversized signed inventory.
pub fn decode_inventory_response(
    bytes: &[u8],
) -> Result<InventorySourceResponseV1, SourceProviderFrameError> {
    let (signed_status, signed_result) =
        decode_status_response(bytes, MAXIMUM_FRAME_BYTES - FRAME_HEADER_BYTES)?;
    InventorySourceResponseV1::new(signed_status, signed_result).map_err(Into::into)
}

fn encode_status_response(
    signed_status: &SignedSourceProviderStatusV1,
    signed_result: Option<&[u8]>,
) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.sized_bytes(&signed_status.to_canonical_bytes());
    match signed_result {
        Some(result) => writer.sized_bytes(result),
        None => writer.u32(0),
    }
    writer.finish()
}

fn decode_status_response(
    bytes: &[u8],
    maximum_result: usize,
) -> Result<(SignedSourceProviderStatusV1, Option<Vec<u8>>), SourceProviderFrameError> {
    let mut reader = Reader::new(bytes);
    let status_bytes = reader.sized_bytes(4 * 1024)?;
    let signed_status = SignedSourceProviderStatusV1::from_canonical_bytes(status_bytes)
        .map_err(|_| SourceProviderFrameError::InvalidFrame)?;
    let result_length = reader.u32()? as usize;
    let signed_result = if result_length == 0 {
        None
    } else if result_length <= maximum_result {
        Some(reader.take(result_length)?.to_vec())
    } else {
        return Err(SourceProviderFrameError::InvalidLength);
    };
    reader.finish()?;
    Ok((signed_status, signed_result))
}

/// Encodes one exact provider lease-release request subject.
#[must_use]
pub fn encode_release_request(value: &ReleaseSourceRequestV1) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.digest(value.session_binding);
    writer.u64(value.sequence);
    writer.bytes(&value.request_id);
    writer.digest(value.acquisition_id);
    writer.bytes(&value.holder_authority_id);
    writer.u64(value.holder_generation);
    writer.digest(value.holder_authority_digest);
    writer.bytes(&value.lease_id);
    writer.digest(value.lease_digest);
    writer.i64(value.deadline_seconds);
    writer.finish()
}

/// Decodes one exact provider lease-release request subject.
///
/// # Errors
///
/// Returns [`SourceProviderFrameError`] for malformed, sentinel, or trailing fields.
pub fn decode_release_request(
    bytes: &[u8],
) -> Result<ReleaseSourceRequestV1, SourceProviderFrameError> {
    let mut reader = Reader::new(bytes);
    let value = ReleaseSourceRequestV1::new(
        reader.digest()?,
        reader.u64()?,
        reader.array::<16>()?,
        reader.digest()?,
        reader.array::<16>()?,
        reader.u64()?,
        reader.digest()?,
        reader.array::<16>()?,
        reader.digest()?,
        reader.i64()?,
    )?;
    reader.finish()?;
    Ok(value)
}

/// Encodes one holder-scoped provider inventory request subject.
#[must_use]
pub fn encode_inventory_request(value: &InventorySourceRequestV1) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.digest(value.session_binding);
    writer.u64(value.sequence);
    writer.bytes(&value.request_id);
    writer.bytes(&value.holder_authority_id);
    writer.u64(value.holder_generation);
    writer.digest(value.holder_authority_digest);
    match value.known_inventory_digest {
        Some(digest) => {
            writer.u8(1);
            writer.digest(digest);
        }
        None => {
            writer.u8(0);
            writer.zeros(32);
        }
    }
    writer.zeros(7);
    writer.i64(value.deadline_seconds);
    writer.finish()
}

/// Decodes one holder-scoped provider inventory request subject.
///
/// # Errors
///
/// Returns [`SourceProviderFrameError`] for malformed optional fields,
/// reserved bytes, sentinel values, or trailing data.
pub fn decode_inventory_request(
    bytes: &[u8],
) -> Result<InventorySourceRequestV1, SourceProviderFrameError> {
    let mut reader = Reader::new(bytes);
    let session_binding = reader.digest()?;
    let sequence = reader.u64()?;
    let request_id = reader.array::<16>()?;
    let holder_authority_id = reader.array::<16>()?;
    let holder_generation = reader.u64()?;
    let holder_authority_digest = reader.digest()?;
    let present = reader.u8()?;
    let digest = reader.digest()?;
    let known_inventory_digest = match present {
        0 if digest.as_bytes() == &[0; 32] => None,
        1 if digest.as_bytes() != &[0; 32] => Some(digest),
        0 | 1 => return Err(SourceProviderFrameError::InvalidFrame),
        _ => return Err(SourceProviderFrameError::UnknownDiscriminant),
    };
    reader.require_zeros(7)?;
    let deadline_seconds = reader.i64()?;
    reader.finish()?;
    InventorySourceRequestV1::new(
        session_binding,
        sequence,
        request_id,
        holder_authority_id,
        holder_generation,
        holder_authority_digest,
        known_inventory_digest,
        deadline_seconds,
    )
    .map_err(Into::into)
}

/// Encodes one canonical source export lease subject.
#[must_use]
pub fn encode_export_lease(value: &SourceExportLeaseV1) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.bytes(&value.lease_id);
    writer.bytes(&value.request_id);
    writer.digest(value.request_digest);
    writer.bytes(&value.holder_authority_id);
    writer.u64(value.holder_generation);
    writer.digest(value.holder_authority_digest);
    encode_provider_authority(&mut writer, &value.provider);
    encode_resource(&mut writer, &value.resource);
    encode_proof(&mut writer, &value.proof);
    writer.digest(value.binding_digest);
    writer.i64(value.issued_seconds);
    writer.i64(value.expires_seconds);
    writer.digest(value.revocation_digest);
    writer.finish()
}

/// Decodes one canonical source export lease subject.
///
/// # Errors
///
/// Returns [`SourceProviderFrameError`] for malformed, unknown, sentinel,
/// reserved, or trailing proof/lease fields.
pub fn decode_export_lease(bytes: &[u8]) -> Result<SourceExportLeaseV1, SourceProviderFrameError> {
    let mut reader = Reader::new(bytes);
    let lease_id = reader.array::<16>()?;
    let request_id = reader.array::<16>()?;
    let request_digest = reader.digest()?;
    let holder_authority_id = reader.array::<16>()?;
    let holder_generation = reader.u64()?;
    let holder_authority_digest = reader.digest()?;
    let provider = decode_provider_authority(&mut reader)?;
    let resource = decode_resource(&mut reader)?;
    let proof = decode_proof(&mut reader)?;
    let binding_digest = reader.digest()?;
    let issued_seconds = reader.i64()?;
    let expires_seconds = reader.i64()?;
    let revocation_digest = reader.digest()?;
    reader.finish()?;
    SourceExportLeaseV1::new(
        lease_id,
        request_id,
        request_digest,
        holder_authority_id,
        holder_generation,
        holder_authority_digest,
        provider,
        resource,
        proof,
        binding_digest,
        issued_seconds,
        expires_seconds,
        revocation_digest,
    )
    .map_err(Into::into)
}

/// Encodes one canonical successful provider receipt subject.
#[must_use]
pub fn encode_provider_receipt(value: &SourceProviderReceiptV1) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.bytes(&value.request_id);
    writer.digest(value.request_digest);
    writer.digest(value.acquisition_id);
    writer.bytes(&value.provider_process_instance);
    writer.digest(value.lease_digest);
    writer.sized_bytes(&value.signed_export_lease);
    writer.u8(value.descriptor_role as u8);
    writer.zeros(7);
    writer.bytes(&value.kernel_boot_id);
    writer.u64(value.device);
    writer.u64(value.inode);
    writer.u64(value.unique_mount_id);
    writer.digest(value.observed_proof_digest);
    writer.finish()
}

/// Decodes one canonical successful provider receipt subject.
///
/// # Errors
///
/// Returns [`SourceProviderFrameError`] for malformed, unknown, reserved,
/// sentinel, or trailing receipt fields.
pub fn decode_provider_receipt(
    bytes: &[u8],
) -> Result<SourceProviderReceiptV1, SourceProviderFrameError> {
    let mut reader = Reader::new(bytes);
    let request_id = reader.array::<16>()?;
    let request_digest = reader.digest()?;
    let acquisition_id = reader.digest()?;
    let provider_process_instance = reader.array::<16>()?;
    let lease_digest = reader.digest()?;
    let signed_export_lease = reader.sized_bytes(256 * 1024)?.to_vec();
    let descriptor_role = match reader.u8()? {
        1 => SourceProviderDescriptorRole::SourceRoot,
        _ => return Err(SourceProviderFrameError::UnknownDiscriminant),
    };
    reader.require_zeros(7)?;
    let kernel_boot_id = reader.array::<16>()?;
    let device = reader.u64()?;
    let inode = reader.u64()?;
    let unique_mount_id = reader.u64()?;
    let observed_proof_digest = reader.digest()?;
    reader.finish()?;
    SourceProviderReceiptV1::new(
        request_id,
        request_digest,
        acquisition_id,
        provider_process_instance,
        lease_digest,
        signed_export_lease,
        descriptor_role,
        kernel_boot_id,
        device,
        inode,
        unique_mount_id,
        observed_proof_digest,
    )
    .map_err(Into::into)
}

/// Encodes one exact provider release receipt subject.
#[must_use]
pub fn encode_release_receipt(value: &SourceReleaseReceiptV1) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.bytes(&value.request_id);
    writer.digest(value.request_digest);
    writer.bytes(&value.lease_id);
    writer.digest(value.lease_digest);
    encode_provider_authority(&mut writer, &value.provider);
    writer.bytes(&value.provider_process_instance);
    writer.u64(value.release_generation);
    writer.i64(value.released_seconds);
    writer.finish()
}

/// Decodes one exact provider release receipt subject.
///
/// # Errors
///
/// Returns [`SourceProviderFrameError`] for malformed, sentinel, or trailing fields.
pub fn decode_release_receipt(
    bytes: &[u8],
) -> Result<SourceReleaseReceiptV1, SourceProviderFrameError> {
    let mut reader = Reader::new(bytes);
    let request_id = reader.array::<16>()?;
    let request_digest = reader.digest()?;
    let lease_id = reader.array::<16>()?;
    let lease_digest = reader.digest()?;
    let provider = decode_provider_authority(&mut reader)?;
    let provider_process_instance = reader.array::<16>()?;
    let release_generation = reader.u64()?;
    let released_seconds = reader.i64()?;
    reader.finish()?;
    SourceReleaseReceiptV1::new(
        request_id,
        request_digest,
        lease_id,
        lease_digest,
        provider,
        provider_process_instance,
        release_generation,
        released_seconds,
    )
    .map_err(Into::into)
}

/// Encodes one canonical provider inventory subject.
#[must_use]
pub fn encode_inventory(value: &SourceProviderInventoryV1) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.bytes(&value.request_id);
    writer.digest(value.request_digest);
    writer.bytes(&value.holder_authority_id);
    writer.u64(value.holder_generation);
    writer.digest(value.holder_authority_digest);
    encode_provider_authority(&mut writer, &value.provider);
    writer.bytes(&value.provider_process_instance);
    writer.u64(value.catalog_generation);
    writer.digest(value.catalog_digest);
    writer.u64(value.inventory_generation);
    writer.u32(value.entries.len() as u32);
    for entry in &value.entries {
        writer.bytes(&entry.lease_id);
        writer.digest(entry.lease_digest);
        writer.digest(entry.acquisition_id);
        writer.u8(entry.state as u8);
        writer.zeros(7);
        encode_resource(&mut writer, &entry.resource);
        writer.u8(entry.proof_class);
        writer.zeros(7);
        writer.digest(entry.proof_digest);
        writer.digest(entry.resource_commitment);
    }
    writer.finish()
}

/// Decodes one canonical provider inventory subject.
///
/// # Errors
///
/// Returns [`SourceProviderFrameError`] for malformed, unknown, oversized,
/// unordered, duplicate, sentinel, reserved, or trailing fields.
pub fn decode_inventory(
    bytes: &[u8],
) -> Result<SourceProviderInventoryV1, SourceProviderFrameError> {
    let mut reader = Reader::new(bytes);
    let request_id = reader.array::<16>()?;
    let request_digest = reader.digest()?;
    let holder_authority_id = reader.array::<16>()?;
    let holder_generation = reader.u64()?;
    let holder_authority_digest = reader.digest()?;
    let provider = decode_provider_authority(&mut reader)?;
    let provider_process_instance = reader.array::<16>()?;
    let catalog_generation = reader.u64()?;
    let catalog_digest = reader.digest()?;
    let inventory_generation = reader.u64()?;
    let count = reader.u32()? as usize;
    if count > MAXIMUM_INVENTORY_ENTRIES {
        return Err(SourceProviderFrameError::InvalidLength);
    }
    let required_entry_bytes = count
        .checked_mul(INVENTORY_ENTRY_BYTES)
        .ok_or(SourceProviderFrameError::InvalidLength)?;
    if reader.remaining() < required_entry_bytes {
        return Err(SourceProviderFrameError::InvalidLength);
    }
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let lease_id = reader.array::<16>()?;
        let lease_digest = reader.digest()?;
        let acquisition_id = reader.digest()?;
        let state = match reader.u8()? {
            1 => InventoryLeaseStateV1::Active,
            2 => InventoryLeaseStateV1::Reaping,
            3 => InventoryLeaseStateV1::Released,
            _ => return Err(SourceProviderFrameError::UnknownDiscriminant),
        };
        reader.require_zeros(7)?;
        entries.push(SourceProviderInventoryEntryV1::new(
            lease_id,
            lease_digest,
            acquisition_id,
            state,
            decode_resource(&mut reader)?,
            reader.u8()?,
            {
                reader.require_zeros(7)?;
                reader.digest()?
            },
            reader.digest()?,
        )?);
    }
    reader.finish()?;
    SourceProviderInventoryV1::new(
        request_id,
        request_digest,
        holder_authority_id,
        holder_generation,
        holder_authority_digest,
        provider,
        provider_process_instance,
        catalog_generation,
        catalog_digest,
        inventory_generation,
        entries,
    )
    .map_err(Into::into)
}

fn encode_provider_authority(writer: &mut Writer, value: &SourceProviderAuthorityV1) {
    writer.bytes(&value.authority_id);
    writer.u64(value.authority_generation);
    writer.digest(value.authority_digest);
}

fn decode_provider_authority(
    reader: &mut Reader<'_>,
) -> Result<SourceProviderAuthorityV1, SourceProviderFrameError> {
    SourceProviderAuthorityV1::new(reader.array::<16>()?, reader.u64()?, reader.digest()?)
        .map_err(Into::into)
}

fn encode_resource(writer: &mut Writer, value: &SourceResourceV1) {
    writer.digest(value.resource_namespace_digest);
    writer.bytes(&value.resource_id);
    writer.u64(value.resource_generation);
    writer.digest(value.resource_digest);
    writer.u64(value.catalog_generation);
    writer.digest(value.catalog_digest);
    writer.u64(value.selection_generation);
    writer.digest(value.selection_digest);
}

fn decode_resource(reader: &mut Reader<'_>) -> Result<SourceResourceV1, SourceProviderFrameError> {
    SourceResourceV1::new(
        reader.digest()?,
        reader.array::<32>()?,
        reader.u64()?,
        reader.digest()?,
        reader.u64()?,
        reader.digest()?,
        reader.u64()?,
        reader.digest()?,
    )
    .map_err(Into::into)
}

fn encode_topology(writer: &mut Writer, value: &RecursiveTopologyProofV1) {
    writer.bytes(&value.authority_id);
    writer.u64(value.generation);
    writer.digest(value.topology_digest);
    writer.u64(value.entry_count);
    writer.u64(value.byte_count);
    writer.u32(value.maximum_depth);
    writer.u32(value.observed_submounts);
}

fn decode_topology(
    reader: &mut Reader<'_>,
) -> Result<RecursiveTopologyProofV1, SourceProviderFrameError> {
    let value = RecursiveTopologyProofV1::new(
        reader.array::<16>()?,
        reader.u64()?,
        reader.digest()?,
        reader.u64()?,
        reader.u64()?,
        reader.u32()?,
        reader.u32()?,
    )?;
    Ok(value)
}

fn encode_proof(writer: &mut Writer, value: &SourceProviderProofV1) {
    writer.u8(value.class_code());
    writer.zeros(7);
    match value {
        SourceProviderProofV1::ZfsHeldSnapshot { proof, topology } => {
            writer.bytes(&proof.storage_handle);
            writer.u64(proof.storage_version);
            writer.u64(proof.pool_guid);
            writer.u64(proof.dataset_guid);
            writer.u64(proof.snapshot_guid);
            writer.bytes(&proof.hold_id);
            writer.u64(proof.hold_generation);
            writer.digest(proof.active_hold_digest);
            writer.digest(proof.root_policy_digest);
            writer.digest(proof.read_only_content_digest);
            encode_topology(writer, topology);
        }
        SourceProviderProofV1::LocalLiveExport { proof, topology } => {
            writer.digest(proof.source_assignment_digest);
            writer.bytes(&proof.owner_sandbox);
            writer.bytes(&proof.source_incarnation);
            writer.bytes(&proof.export_id);
            writer.u64(proof.export_generation);
            writer.digest(proof.export_revocation_digest);
            writer.digest(proof.export_lease_digest);
            writer.bytes(&proof.consumer_authority_id);
            writer.u64(proof.consumer_generation);
            writer.digest(proof.kernel_grant_digest);
            writer.bytes(&proof.workspace_id);
            writer.digest(proof.workspace_digest);
            encode_topology(writer, topology);
        }
        SourceProviderProofV1::ImmutablePublisherTree { proof, topology } => {
            writer.digest(proof.tree_digest);
            writer.digest(proof.view_digest);
            writer.u64(proof.publication_generation);
            writer.digest(proof.publication_receipt_digest);
            writer.u64(proof.catalog_generation);
            writer.digest(proof.catalog_digest);
            writer.bytes(&proof.cache_id);
            writer.u64(proof.cache_generation);
            writer.digest(proof.cache_digest);
            writer.digest(proof.disclosure_digest);
            writer.digest(proof.materialization_digest);
            writer.digest(proof.verity_measurement_set_digest);
            writer.digest(proof.writer_closure_digest);
            encode_topology(writer, topology);
        }
        SourceProviderProofV1::BestEffortReplica { proof, topology } => {
            writer.digest(proof.reconstructibility_digest);
            writer.bytes(&proof.replica_id);
            writer.u64(proof.replica_generation);
            writer.digest(proof.replica_digest);
            writer.i64(proof.cutoff_seconds);
            writer.u64(proof.checkpoint_generation);
            writer.digest(proof.checkpoint_digest);
            writer.u64(proof.lag_bound_seconds);
            writer.u64(proof.observed_lag_seconds);
            writer.digest(proof.access_grant_digest);
            writer.u8(u8::from(proof.degraded));
            writer.zeros(7);
            encode_topology(writer, topology);
        }
    }
}

/// Encodes one canonical backend proof and topology claim.
#[must_use]
pub fn encode_provider_proof(value: &SourceProviderProofV1) -> Vec<u8> {
    let mut writer = Writer::new();
    encode_proof(&mut writer, value);
    writer.finish()
}

/// Decodes one canonical backend proof and topology claim.
///
/// # Errors
///
/// Returns [`SourceProviderFrameError`] for truncation, trailing bytes,
/// unknown classes, noncanonical flags, or invalid proof values.
pub fn decode_provider_proof(
    bytes: &[u8],
) -> Result<SourceProviderProofV1, SourceProviderFrameError> {
    let mut reader = Reader::new(bytes);
    let proof = decode_proof(&mut reader)?;
    reader.finish()?;
    Ok(proof)
}

fn decode_proof(
    reader: &mut Reader<'_>,
) -> Result<SourceProviderProofV1, SourceProviderFrameError> {
    let class = reader.u8()?;
    reader.require_zeros(7)?;
    match class {
        1 => Ok(SourceProviderProofV1::ZfsHeldSnapshot {
            proof: ZfsHeldSnapshotProofV1::new(
                reader.array::<32>()?,
                reader.u64()?,
                reader.u64()?,
                reader.u64()?,
                reader.u64()?,
                reader.array::<16>()?,
                reader.u64()?,
                reader.digest()?,
                reader.digest()?,
                reader.digest()?,
            )?,
            topology: decode_topology(reader)?,
        }),
        2 => Ok(SourceProviderProofV1::LocalLiveExport {
            proof: LocalLiveExportProofV1::new(
                reader.digest()?,
                reader.array::<16>()?,
                reader.array::<16>()?,
                reader.array::<16>()?,
                reader.u64()?,
                reader.digest()?,
                reader.digest()?,
                reader.array::<16>()?,
                reader.u64()?,
                reader.digest()?,
                reader.array::<32>()?,
                reader.digest()?,
            )?,
            topology: decode_topology(reader)?,
        }),
        3 => Ok(SourceProviderProofV1::ImmutablePublisherTree {
            proof: ImmutablePublisherTreeProofV1::new(
                reader.digest()?,
                reader.digest()?,
                reader.u64()?,
                reader.digest()?,
                reader.u64()?,
                reader.digest()?,
                reader.array::<32>()?,
                reader.u64()?,
                reader.digest()?,
                reader.digest()?,
                reader.digest()?,
                reader.digest()?,
                reader.digest()?,
            )?,
            topology: decode_topology(reader)?,
        }),
        4 => Ok(SourceProviderProofV1::BestEffortReplica {
            proof: BestEffortReplicaProofV1::new(
                reader.digest()?,
                reader.array::<32>()?,
                reader.u64()?,
                reader.digest()?,
                reader.i64()?,
                reader.u64()?,
                reader.digest()?,
                reader.u64()?,
                reader.u64()?,
                reader.digest()?,
                match reader.u8()? {
                    0 => false,
                    1 => true,
                    _ => return Err(SourceProviderFrameError::UnknownDiscriminant),
                },
            )?,
            topology: {
                reader.require_zeros(7)?;
                decode_topology(reader)?
            },
        }),
        _ => Err(SourceProviderFrameError::UnknownDiscriminant),
    }
}

fn decode_method(value: u8) -> Result<SourceProviderMethod, SourceProviderFrameError> {
    match value {
        1 => Ok(SourceProviderMethod::Hello),
        2 => Ok(SourceProviderMethod::Acquire),
        3 => Ok(SourceProviderMethod::Release),
        4 => Ok(SourceProviderMethod::Inventory),
        _ => Err(SourceProviderFrameError::UnknownDiscriminant),
    }
}

fn decode_status(value: u8) -> Result<SourceProviderStatus, SourceProviderFrameError> {
    match value {
        1 => Ok(SourceProviderStatus::Complete),
        2 => Ok(SourceProviderStatus::Pending),
        3 => Ok(SourceProviderStatus::Rejected),
        4 => Ok(SourceProviderStatus::Unavailable),
        _ => Err(SourceProviderFrameError::UnknownDiscriminant),
    }
}

struct Writer {
    bytes: Vec<u8>,
}

impl Writer {
    fn new() -> Self {
        Self { bytes: Vec::new() }
    }
    fn with_capacity(capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
        }
    }
    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }
    fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }
    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }
    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }
    fn i64(&mut self, value: i64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }
    fn bytes(&mut self, value: &[u8]) {
        self.bytes.extend_from_slice(value);
    }
    fn zeros(&mut self, count: usize) {
        self.bytes.resize(self.bytes.len() + count, 0);
    }
    fn digest(&mut self, value: ObjectDigest) {
        self.bytes(value.as_bytes());
    }
    fn sized_bytes(&mut self, value: &[u8]) {
        self.u32(value.len() as u32);
        self.bytes(value);
    }
    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], SourceProviderFrameError> {
        let end = self
            .cursor
            .checked_add(count)
            .ok_or(SourceProviderFrameError::InvalidLength)?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or(SourceProviderFrameError::InvalidLength)?;
        self.cursor = end;
        Ok(value)
    }

    const fn remaining(&self) -> usize {
        self.bytes.len() - self.cursor
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], SourceProviderFrameError> {
        self.take(N)?
            .try_into()
            .map_err(|_| SourceProviderFrameError::InvalidLength)
    }

    fn u8(&mut self) -> Result<u8, SourceProviderFrameError> {
        Ok(self.array::<1>()?[0])
    }
    fn u16(&mut self) -> Result<u16, SourceProviderFrameError> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    fn u32(&mut self) -> Result<u32, SourceProviderFrameError> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, SourceProviderFrameError> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn i64(&mut self) -> Result<i64, SourceProviderFrameError> {
        Ok(i64::from_be_bytes(self.array()?))
    }
    fn digest(&mut self) -> Result<ObjectDigest, SourceProviderFrameError> {
        Ok(ObjectDigest::from_bytes(self.array()?))
    }

    fn sized_bytes(&mut self, maximum: usize) -> Result<&'a [u8], SourceProviderFrameError> {
        let count = self.u32()? as usize;
        if count == 0 || count > maximum {
            return Err(SourceProviderFrameError::InvalidLength);
        }
        self.take(count)
    }

    fn require_zeros(&mut self, count: usize) -> Result<(), SourceProviderFrameError> {
        if self.take(count)?.iter().any(|byte| *byte != 0) {
            Err(SourceProviderFrameError::NonzeroReserved)
        } else {
            Ok(())
        }
    }

    fn finish(self) -> Result<(), SourceProviderFrameError> {
        if self.cursor == self.bytes.len() {
            Ok(())
        } else {
            Err(SourceProviderFrameError::InvalidFrame)
        }
    }
}

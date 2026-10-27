//! Retains an ordinary Stop's exact prepared SDK request as comparison DATA.
//!
//! ```text
//! AOSLSD01 | public-stop16 | operation-record32 | source-root32 |
//! sdk-request16 | sdk-session32 | sdk-signed-request32 | packet-length4 | packet
//! ```
//!
//! The Source atomic Operation/Dispatch pair supplies provenance. Decoding this
//! payload supplies no current Source, authenticated Session or cleanup grant.

use aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod;
use aos_sandbox_broker_session_protocol::{
    AUTHENTICATED_ORDINARY_REQUEST_MAXIMUM_BYTES, complete_signed_request_digest_v1,
    decode_canonical_request_v1,
};
use aos_sandbox_model::{ObjectDigest, OperationId};

use super::lifecycle_model::LifecycleModelError;
use crate::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1;

const MAGIC: &[u8; 8] = b"AOSLSD01";
const HEADER_BYTES: usize = 172;

/// Retains one complete ordinary Stop dispatch binding without adopting it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleStopDispatchDataV1 {
    operation: OperationId,
    operation_record: ObjectDigest,
    source_root: ObjectDigest,
    request_id: [u8; 16],
    session: [u8; 32],
    signed_request: [u8; 32],
    packet: Vec<u8>,
}

impl LifecycleStopDispatchDataV1 {
    /// Copies the literal prepared request after the ordinary Stop comparison.
    ///
    /// # Errors
    /// Refuses sentinel identities, a non-Stop request or checked allocation.
    pub fn from_prepared_request_data_v1(
        operation: OperationId,
        operation_record: ObjectDigest,
        source_root: ObjectDigest,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<Self, LifecycleModelError> {
        let invalid = LifecycleModelError::InvalidModel;
        if operation.as_bytes() == &[0; 16]
            || operation_record.as_bytes() == &[0; 32]
            || source_root.as_bytes() == &[0; 32]
            || request.method() != BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME
        {
            return Err(invalid);
        }
        require_ordinary_stop_packet_v1(
            request.canonical_packet(), request.request_id(), request.session_binding(),
            request.signed_request_digest(),
        )?;
        let mut packet = Vec::new();
        packet.try_reserve_exact(request.canonical_packet().len())
            .map_err(|_| LifecycleModelError::Allocation)?;
        packet.extend_from_slice(request.canonical_packet());
        Ok(Self { operation, operation_record, source_root,
            request_id: request.request_id(), session: request.session_binding(),
            signed_request: request.signed_request_digest(), packet })
    }

    /// Decodes the bounded payload through the existing canonical SDK codecs.
    ///
    /// # Errors
    /// Refuses malformed framing, noncanonical Stop packets, changed request
    /// triples, missing authorization or checked allocation failure.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, LifecycleModelError> {
        let invalid = || LifecycleModelError::CorruptEncoding;
        if bytes.len() < HEADER_BYTES || bytes.get(..8) != Some(MAGIC.as_slice()) {
            return Err(invalid());
        }
        let length = usize::try_from(u32::from_be_bytes(read(bytes, 168)?))
            .map_err(|_| invalid())?;
        if length == 0 || length > AUTHENTICATED_ORDINARY_REQUEST_MAXIMUM_BYTES
            || HEADER_BYTES.checked_add(length) != Some(bytes.len())
        {
            return Err(invalid());
        }
        let operation = OperationId::from_bytes(read(bytes, 8)?);
        let operation_record = ObjectDigest::from_bytes(read(bytes, 24)?);
        let source_root = ObjectDigest::from_bytes(read(bytes, 56)?);
        let request_id = read(bytes, 88)?;
        let session = read(bytes, 104)?;
        let signed_request = read(bytes, 136)?;
        if operation.as_bytes() == &[0; 16] || operation_record.as_bytes() == &[0; 32]
            || source_root.as_bytes() == &[0; 32]
        {
            return Err(invalid());
        }
        require_ordinary_stop_packet_v1(&bytes[HEADER_BYTES..], request_id, session, signed_request)?;
        let mut packet = Vec::new();
        packet.try_reserve_exact(length).map_err(|_| LifecycleModelError::Allocation)?;
        packet.extend_from_slice(&bytes[HEADER_BYTES..]);
        Ok(Self { operation, operation_record, source_root, request_id, session,
            signed_request, packet })
    }

    /// Encodes the retained literal request without changing its signed fields.
    ///
    /// # Errors
    /// Refuses checked allocation or an unrepresentable packet length.
    pub fn encode(&self) -> Result<Vec<u8>, LifecycleModelError> {
        let length = u32::try_from(self.packet.len()).map_err(|_| LifecycleModelError::InvalidModel)?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(self.encoded_length()).map_err(|_| LifecycleModelError::Allocation)?;
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(self.operation.as_bytes());
        bytes.extend_from_slice(self.operation_record.as_bytes());
        bytes.extend_from_slice(self.source_root.as_bytes());
        bytes.extend_from_slice(&self.request_id);
        bytes.extend_from_slice(&self.session);
        bytes.extend_from_slice(&self.signed_request);
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(&self.packet);
        Ok(bytes)
    }

    /// Returns the complete retained payload length.
    pub fn encoded_length(&self) -> usize { HEADER_BYTES + self.packet.len() }

    /// Returns the public Stop identity, independently of the SDK request ID.
    pub const fn operation(&self) -> OperationId { self.operation }

    /// Returns the exact Source Operation member commitment before dispatch.
    pub const fn operation_record(&self) -> ObjectDigest { self.operation_record }

    /// Returns the captured Source projection root before the binding append.
    pub const fn source_root(&self) -> ObjectDigest { self.source_root }

    /// Returns the signed Host request triple as comparison DATA.
    pub const fn sdk_request_data_v1(&self) -> ([u8; 16], [u8; 32], [u8; 32]) {
        (self.request_id, self.session, self.signed_request)
    }

    /// Borrows the complete original signed packet, including its plan quartet.
    pub fn canonical_packet(&self) -> &[u8] { &self.packet }
}

fn require_ordinary_stop_packet_v1(
    bytes: &[u8], request_id: [u8; 16], session: [u8; 32], signed_request: [u8; 32],
) -> Result<(), LifecycleModelError> {
    let invalid = || LifecycleModelError::CorruptEncoding;
    if request_id == [0; 16] || session == [0; 32] || signed_request == [0; 32]
        || bytes.len() > AUTHENTICATED_ORDINARY_REQUEST_MAXIMUM_BYTES
    {
        return Err(invalid());
    }
    let request = decode_canonical_request_v1(bytes).map_err(|_| invalid())?;
    let subject = request.signed_artifact().subject();
    if request.message().method.as_known() != Some(BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME)
        || request.message().authorization.as_option().is_none()
        || subject.request_id() != request_id || subject.session_binding() != session
        || complete_signed_request_digest_v1(request.signed_artifact()) != signed_request
    {
        return Err(invalid());
    }
    let body = crate::decode_canonical_live_host_stop_envelope_data_v4(&request.message().body)
        .map_err(|_| invalid())?;
    if body.request_id_v1() != &request_id {
        return Err(invalid());
    }
    Ok(())
}

fn read<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], LifecycleModelError> {
    bytes.get(offset..offset + N).and_then(|value| value.try_into().ok())
        .ok_or(LifecycleModelError::CorruptEncoding)
}

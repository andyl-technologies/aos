//! Exact public mutation request envelopes.
//!
//! The controller compiler needs both a closed RPC method and the exact
//! protobuf bytes received on its authenticated HTTP/2 stream. This envelope
//! preserves those bytes without decoding and re-encoding them first:
//!
//! ```text
//! +----------------+----------------+----------------+-------------------+
//! | magic (8 bytes)| method (u16 BE)| length (u32 BE)| protobuf body ... |
//! +----------------+----------------+----------------+-------------------+
//! ```

use aos_proto::aos::sandbox::v1 as wire;
use buffa::Message as _;

use super::{
    DormantClientStatePlanV1, DormantPublicApiAuthorizationV1, DormantSandboxOutputV1,
    DormantSandboxRequestKindV1, DormantSandboxRequestV1, PublicApiAuditMethodV1,
};

const MAGIC: &[u8; 8] = b"AOSPMR01";
const HEADER_BYTES: usize = MAGIC.len() + 2 + 4;
const MAXIMUM_PROTOBUF_BODY_BYTES: usize = 64 * 1024;

/// Carries one mutation RPC method and its exact received protobuf body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicMutationRequestV1 {
    method: PublicApiAuditMethodV1,
    method_code: u16,
    protobuf_body: Vec<u8>,
}

impl PublicMutationRequestV1 {
    /// Constructs an envelope from one supported mutation method and exact body.
    ///
    /// # Errors
    ///
    /// Returns [`PublicMutationRequestError`] when the method is not a mutation
    /// or the protobuf body is empty or exceeds the authorization bound.
    pub fn new(
        method: PublicApiAuditMethodV1,
        protobuf_body: &[u8],
    ) -> Result<Self, PublicMutationRequestError> {
        let method_code = mutation_method_code(method)?;
        if protobuf_body.is_empty() || protobuf_body.len() > MAXIMUM_PROTOBUF_BODY_BYTES {
            return Err(PublicMutationRequestError::InvalidBody);
        }

        Ok(Self {
            method,
            method_code,
            protobuf_body: protobuf_body.to_vec(),
        })
    }

    /// Decodes and exact-validates a canonical mutation envelope.
    ///
    /// # Errors
    ///
    /// Returns [`PublicMutationRequestError`] for an invalid magic, method,
    /// length, body bound, or trailing bytes.
    pub fn decode(encoded: &[u8]) -> Result<Self, PublicMutationRequestError> {
        let header = encoded
            .get(..HEADER_BYTES)
            .ok_or(PublicMutationRequestError::MalformedEnvelope)?;
        if header.get(..MAGIC.len()) != Some(MAGIC.as_slice()) {
            return Err(PublicMutationRequestError::MalformedEnvelope);
        }
        let method_bytes: [u8; 2] = header[MAGIC.len()..MAGIC.len() + 2]
            .try_into()
            .map_err(|_| PublicMutationRequestError::MalformedEnvelope)?;
        let length_bytes: [u8; 4] = header[MAGIC.len() + 2..HEADER_BYTES]
            .try_into()
            .map_err(|_| PublicMutationRequestError::MalformedEnvelope)?;
        let body_length = usize::try_from(u32::from_be_bytes(length_bytes))
            .map_err(|_| PublicMutationRequestError::MalformedEnvelope)?;
        let protobuf_body = encoded
            .get(HEADER_BYTES..)
            .filter(|body| body.len() == body_length)
            .ok_or(PublicMutationRequestError::MalformedEnvelope)?;

        Self::new(
            mutation_method(u16::from_be_bytes(method_bytes))?,
            protobuf_body,
        )
    }

    /// Encodes the canonical envelope without changing the protobuf body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let body_length = self.protobuf_body.len() as u32;
        let mut encoded = Vec::with_capacity(HEADER_BYTES + self.protobuf_body.len());
        encoded.extend_from_slice(MAGIC);
        encoded.extend_from_slice(&self.method_code.to_be_bytes());
        encoded.extend_from_slice(&body_length.to_be_bytes());
        encoded.extend_from_slice(&self.protobuf_body);
        encoded
    }

    /// Returns the closed public RPC method.
    #[must_use]
    pub const fn method(&self) -> PublicApiAuditMethodV1 {
        self.method
    }

    /// Returns the exact protobuf bytes received from the public transport.
    #[must_use]
    pub fn protobuf_body(&self) -> &[u8] {
        &self.protobuf_body
    }

    /// Decodes the exact body into the method-selected request and validates it.
    ///
    /// The ordinary CLI route validator remains the single source of field,
    /// feature, descriptor, and concurrency-fence constraints. The temporary
    /// client context used here is opaque and never becomes controller
    /// authorization evidence.
    ///
    /// # Errors
    ///
    /// Returns [`PublicMutationRequestError`] when the body is malformed,
    /// noncanonical, inconsistent with the selected method, or fails the
    /// established request validator.
    pub(crate) fn decode_validated_kind(
        &self,
    ) -> Result<DormantSandboxRequestKindV1, PublicMutationRequestError> {
        macro_rules! decode {
            ($message:ty, $variant:ident) => {{
                let message = <$message>::decode_from_slice(&self.protobuf_body)
                    .map_err(|_| PublicMutationRequestError::InvalidProtobuf)?;
                if message.encode_to_vec() != self.protobuf_body {
                    return Err(PublicMutationRequestError::InvalidProtobuf);
                }
                DormantSandboxRequestKindV1::$variant(message)
            }};
        }

        use PublicApiAuditMethodV1 as M;
        let kind = match self.method {
            M::CreateSandbox => decode!(wire::CreateSandboxRequest, Create),
            M::UpdatePolicy => decode!(wire::UpdateSandboxPolicyRequest, UpdatePolicy),
            M::StartSandbox => decode!(wire::SandboxLifecycleRequest, Start),
            M::StopSandbox => decode!(wire::SandboxLifecycleRequest, Stop),
            M::SuspendSandbox => decode!(wire::SandboxLifecycleRequest, Suspend),
            M::ResumeSandbox => decode!(wire::SandboxLifecycleRequest, Resume),
            M::DeleteSandbox => decode!(wire::DeleteSandboxRequest, Delete),
            M::CreateExecution => decode!(wire::CreateExecutionRequest, Exec),
            M::ControlExecution => decode!(wire::ExecutionControlRequest, ExecutionControl),
            M::CancelExecution => decode!(wire::CancelExecutionRequest, CancelExec),
            M::CreateView => decode!(wire::CreateViewRequest, ViewCreate),
            M::AttachView => decode!(wire::AttachViewRequest, ViewAttach),
            M::ReplaceAttachment => {
                decode!(wire::ReplaceAttachmentRequest, ViewReplace)
            }
            M::DetachView => decode!(wire::DetachViewRequest, ViewDetach),
            M::ReleaseView => decode!(wire::ReleaseViewRequest, ViewRelease),
            M::CreateSnapshot => decode!(wire::CreateSnapshotRequest, Snapshot),
            M::RestoreSnapshot => decode!(wire::RestoreSnapshotRequest, Restore),
            M::ForkSnapshot => decode!(wire::ForkSnapshotRequest, Fork),
            M::DeleteSnapshot => decode!(wire::DeleteSnapshotRequest, DeleteSnapshot),
            M::AttenuateCapability => {
                decode!(wire::AttenuateCapabilityRequest, CapabilityAttenuate)
            }
            M::RenewCapability => decode!(wire::RenewCapabilityRequest, CapabilityRenew),
            M::RevokeCapability => decode!(wire::RevokeCapabilityRequest, CapabilityRevoke),
            M::CancelOperation => decode!(wire::CancelOperationRequest, CancelOperation),
            M::PinCacheObject => decode!(wire::PinCacheObjectRequest, CachePin),
            M::UnpinCacheObject => decode!(wire::UnpinCacheObjectRequest, CacheUnpin),
            _ => return Err(PublicMutationRequestError::UnsupportedMethod),
        };
        let authorization = DormantPublicApiAuthorizationV1::new(vec![1])
            .map_err(|_| PublicMutationRequestError::InvalidProtobuf)?;
        let client_state = DormantClientStatePlanV1::new(1, 1, None)
            .map_err(|_| PublicMutationRequestError::InvalidProtobuf)?;
        DormantSandboxRequestV1::from_parsed_command_with_authorization(
            kind.clone(),
            DormantSandboxOutputV1::Json,
            client_state,
            authorization,
        )
        .map_err(|_| PublicMutationRequestError::InvalidProtobuf)?;

        Ok(kind)
    }
}

/// Reports an invalid public mutation request envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PublicMutationRequestError {
    /// The selected RPC is not part of the public mutation surface.
    #[error("public RPC method is not a mutation")]
    UnsupportedMethod,
    /// The exact protobuf body is empty or exceeds the authorization bound.
    #[error("public mutation protobuf body is invalid")]
    InvalidBody,
    /// The transport envelope is truncated, inconsistent, or has trailing bytes.
    #[error("public mutation envelope is malformed")]
    MalformedEnvelope,
    /// The method-selected protobuf body is malformed, noncanonical, or invalid.
    #[error("public mutation protobuf body is malformed or invalid")]
    InvalidProtobuf,
}

fn mutation_method_code(method: PublicApiAuditMethodV1) -> Result<u16, PublicMutationRequestError> {
    use PublicApiAuditMethodV1 as M;

    match method {
        M::CreateSandbox => Ok(1),
        M::UpdatePolicy => Ok(2),
        M::StartSandbox => Ok(3),
        M::StopSandbox => Ok(4),
        M::SuspendSandbox => Ok(5),
        M::ResumeSandbox => Ok(6),
        M::DeleteSandbox => Ok(7),
        M::CreateExecution => Ok(8),
        M::ControlExecution => Ok(9),
        M::CancelExecution => Ok(10),
        M::CreateView => Ok(11),
        M::AttachView => Ok(12),
        M::ReplaceAttachment => Ok(13),
        M::DetachView => Ok(14),
        M::ReleaseView => Ok(15),
        M::CreateSnapshot => Ok(16),
        M::RestoreSnapshot => Ok(17),
        M::ForkSnapshot => Ok(18),
        M::DeleteSnapshot => Ok(19),
        M::AttenuateCapability => Ok(20),
        M::RenewCapability => Ok(21),
        M::RevokeCapability => Ok(22),
        M::CancelOperation => Ok(23),
        M::PinCacheObject => Ok(24),
        M::UnpinCacheObject => Ok(25),
        _ => Err(PublicMutationRequestError::UnsupportedMethod),
    }
}

fn mutation_method(code: u16) -> Result<PublicApiAuditMethodV1, PublicMutationRequestError> {
    use PublicApiAuditMethodV1 as M;

    match code {
        1 => Ok(M::CreateSandbox),
        2 => Ok(M::UpdatePolicy),
        3 => Ok(M::StartSandbox),
        4 => Ok(M::StopSandbox),
        5 => Ok(M::SuspendSandbox),
        6 => Ok(M::ResumeSandbox),
        7 => Ok(M::DeleteSandbox),
        8 => Ok(M::CreateExecution),
        9 => Ok(M::ControlExecution),
        10 => Ok(M::CancelExecution),
        11 => Ok(M::CreateView),
        12 => Ok(M::AttachView),
        13 => Ok(M::ReplaceAttachment),
        14 => Ok(M::DetachView),
        15 => Ok(M::ReleaseView),
        16 => Ok(M::CreateSnapshot),
        17 => Ok(M::RestoreSnapshot),
        18 => Ok(M::ForkSnapshot),
        19 => Ok(M::DeleteSnapshot),
        20 => Ok(M::AttenuateCapability),
        21 => Ok(M::RenewCapability),
        22 => Ok(M::RevokeCapability),
        23 => Ok(M::CancelOperation),
        24 => Ok(M::PinCacheObject),
        25 => Ok(M::UnpinCacheObject),
        _ => Err(PublicMutationRequestError::UnsupportedMethod),
    }
}

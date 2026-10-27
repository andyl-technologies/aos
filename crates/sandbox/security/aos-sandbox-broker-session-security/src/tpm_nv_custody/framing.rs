//! Adapts the single shared version-two TPM frame codec to private owner errors.
//!
//! The codec handles comparison DATA only. Security retains actual helper,
//! record-subject, provisioning, recovery and effect admission.

use aos_sandbox_broker::fixed_tpm_helper_wire as shared;
use zeroize::Zeroizing;

use super::{NvCustodyEndpointV1, NvCustodyErrorV1};

pub(crate) use shared::{
    AUTH_BYTES, HELLO_BYTES, HelperObservationV1, HelperOperationV1, LOCK_ACK_BYTES, REQUEST_BYTES,
    RESPONSE_BYTES, salt_handle_v1,
};

pub(crate) fn encode_hello_v2(
    endpoint: NvCustodyEndpointV1,
    nonce: [u8; 32],
    salt_name: [u8; 34],
    locks: [(u64, u64, u32); 2],
) -> Result<Zeroizing<[u8; HELLO_BYTES]>, NvCustodyErrorV1> {
    shared::encode_hello_v2(endpoint, nonce, salt_name, locks).map_err(Into::into)
}

pub(crate) fn require_lock_ack_v2(bytes: &[u8], nonce: [u8; 32]) -> Result<(), NvCustodyErrorV1> {
    shared::require_lock_ack_v2(bytes, nonce).map_err(Into::into)
}

pub(crate) fn encode_auth_v2(
    endpoint: NvCustodyEndpointV1,
    nonce: [u8; 32],
    auth: &[u8; 32],
) -> Result<Zeroizing<[u8; AUTH_BYTES]>, NvCustodyErrorV1> {
    shared::encode_auth_v2(endpoint, nonce, auth).map_err(Into::into)
}

pub(crate) fn encode_request_v2(
    operation: HelperOperationV1,
    nonce: [u8; 32],
    sequence: u64,
    input: [u8; 32],
) -> Result<[u8; REQUEST_BYTES], NvCustodyErrorV1> {
    shared::encode_request_v2(operation, nonce, sequence, input).map_err(Into::into)
}

pub(crate) fn decode_response_v2(
    bytes: &[u8],
    operation: HelperOperationV1,
    nonce: [u8; 32],
    sequence: u64,
) -> Result<HelperObservationV1, NvCustodyErrorV1> {
    shared::decode_response_v2(bytes, operation, nonce, sequence).map_err(Into::into)
}

impl From<shared::TpmHelperFrameErrorV2> for NvCustodyErrorV1 {
    fn from(cause: shared::TpmHelperFrameErrorV2) -> Self {
        match cause {
            shared::TpmHelperFrameErrorV2::Encoding => Self::Encoding,
            shared::TpmHelperFrameErrorV2::Provisioning => Self::Provisioning,
        }
    }
}

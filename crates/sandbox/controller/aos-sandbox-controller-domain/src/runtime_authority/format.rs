//! Encloses sole portable Runtime codecs at the existing private Native boundary.
//!
//! DATA parses move directly into the same private store wrappers. Portable
//! errors project to the old flat Native variants; this creates no public
//! accepted-record/currentness factory or alternate canonical engine.

use super::*;
use aos_sandbox_protocol::domain_ledger::runtime_authority_history as data;

pub(super) fn encode_pending(
    value: &RuntimeAuthorityPendingV1,
) -> Result<Vec<u8>, RuntimeAuthorityError> {
    data::encode_pending(&value.data).map_err(RuntimeAuthorityError::from)
}

pub(super) fn decode_pending(bytes: &[u8]) -> Result<RuntimeAuthorityPendingV1, RuntimeAuthorityError> {
    data::decode_pending(bytes)
        .map(|data| RuntimeAuthorityPendingV1 { data })
        .map_err(RuntimeAuthorityError::from)
}

pub(super) fn encode_binding(
    value: &RuntimeAuthorityBindingV1,
) -> Result<Vec<u8>, RuntimeAuthorityError> {
    data::encode_binding(&value.data).map_err(RuntimeAuthorityError::from)
}

pub(super) fn decode_binding(bytes: &[u8]) -> Result<RuntimeAuthorityBindingV1, RuntimeAuthorityError> {
    data::decode_binding(bytes)
        .map(|data| RuntimeAuthorityBindingV1 { data })
        .map_err(RuntimeAuthorityError::from)
}

pub(super) fn encode_head(head: RuntimeAuthorityHeadV1) -> Vec<u8> {
    data::encode_head(head)
}

pub(super) fn decode_head(bytes: &[u8]) -> Result<RuntimeAuthorityHeadV1, RuntimeAuthorityError> {
    data::decode_head(bytes).map_err(RuntimeAuthorityError::from)
}

pub(super) fn binding_digest(bytes: &[u8]) -> ObjectDigest {
    data::binding_digest(bytes)
}

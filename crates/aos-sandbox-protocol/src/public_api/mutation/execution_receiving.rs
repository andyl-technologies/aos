//! Prices the sole Execution Create protobuf decoder and validation copies.
//!
//! The grammar is CreateExecutionRequest -> Command | MutationContext, with
//! repeated argument bytes, EnvironmentVariable and Feature leaves. Every
//! reached repeated/unknown element consumes an input tag; their actual Rust
//! carrier layouts bound hostile input before the canonical body is decoded.
//! This is receiving DATA only and never authenticates a request or pays it.

use std::mem::size_of;

use aos_proto::aos::sandbox::v1 as wire;

/// Returns the concrete protobuf model/byte peak for an actual bounded body.
///
/// The sole decoder temporarily retains the original kind, its validation
/// clone, and `to_command_proto`'s transport clone. Unknown and repeated fields
/// are bounded before validation rejects them. The two raw body owners and
/// canonical re-encoding coexist at their separate peak. Vec growth allows
/// twice the reached element count; no namespace or per-field fee is added.
/// Holder-proof cryptography and Controller authorization/ledger models are
/// separate source-owned recipes joined by the actual C18 caller.
#[must_use]
pub fn create_execution_model_receiving_bytes_v2(body_bytes: usize) -> Option<usize> {
    if body_bytes == 0 || body_bytes > super::MAXIMUM_PROTOBUF_BODY_BYTES {
        return None;
    }
    let fixed = size_of::<wire::CreateExecutionRequest>()
        .checked_add(size_of::<wire::Command>())?
        .checked_add(size_of::<wire::MutationContext>())?
        .checked_add(size_of::<wire::Duration>().checked_mul(2)?)?
        .checked_add(size_of::<wire::SandboxCommandRequest>())?;
    let repeated = size_of::<Vec<u8>>()
        .checked_add(size_of::<wire::EnvironmentVariable>())?
        .checked_add(size_of::<wire::Feature>())?
        .checked_add(size_of::<buffa::UnknownField>())?;
    let decoded = fixed
        .checked_add(body_bytes.checked_mul(repeated)?.checked_mul(2)?)?
        .checked_add(body_bytes.checked_mul(2)?)?;
    decoded.checked_mul(3)?.checked_add(body_bytes.checked_mul(3)?)
}

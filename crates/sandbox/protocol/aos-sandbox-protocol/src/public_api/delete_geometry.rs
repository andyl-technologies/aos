//! Prices the actual canonical Delete decoder and its concrete retained header.
//!
//! The pure recipe supplies Memory bytes only, never payment or permission. A
//! real private owner binds T to its actual compiled retained request/header
//! before growth. Existing Domain callers retain their Authorized header; a
//! native observer uses its real resolved DATA type and separately prices its
//! plan/error/control owners. No numeric header, paid shape or mirror type is
//! accepted, and a smaller native type is not called equivalent to the old one.

use std::mem::size_of;

/// Prices Delete decode work for the caller's concrete retained header type.
///
/// Returns None if any checked byte computation overflows. The caller retains
/// its original geometry-error projection and funding frontier.
#[must_use]
pub fn delete_decode_bytes_v1<T>(encoded: usize) -> Option<usize> {
    use aos_sandbox_api::aos::sandbox::v1 as wire;
    // Every unknown field consumes at least one input tag byte, and each
    // repeated Feature consumes at least one message tag byte. These are the actual reached
    // collection element layouts, not a largest request model per input byte.
    let nodes = size_of::<buffa::UnknownField>().checked_add(size_of::<wire::Feature>())?;
    let dynamic = encoded.checked_mul(nodes)?.checked_mul(6)?;
    let fixed = size_of::<wire::DeleteSandboxRequest>()
        .checked_add(size_of::<wire::MutationContext>())?
        .checked_add(size_of::<wire::Duration>())?
        .checked_add(size_of::<T>())?
        .checked_mul(4)?;
    // Envelope/body ownership, validated-kind clone, canonical protobuf and
    // JSON authorization envelope/hex scratch coexist under these byte lanes.
    dynamic
        .checked_add(encoded.checked_mul(32)?)?
        .checked_add(fixed)
}


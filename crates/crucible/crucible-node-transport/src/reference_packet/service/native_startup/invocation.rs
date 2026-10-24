//! Retains actual native/report counter scopes beside shared purpose DATA.
//!
//! The immutable purpose and canonical wire implementation are shared with the
//! contained worker. Native admission and private constructor layouts remain
//! here; reading or constructing purpose DATA issues no live capability.

use crate::ProviderError;
use crucible_source_birth_data::profile::reference_packet::service::native_startup::invocation as shared;

pub use shared::PacketNativeInvocationPurposeData;

/// Names fixed purpose, writer, native and report counter windows.
pub const fn original_native_invocation_counter_scratch_data() -> usize {
    shared::purpose_counter_scratch_data()
        + crate::reference_packet::service::report_startup::original_invocation_report_startup_allocation_counter_scratch_data()
        + wire::counter_scratch_data()
        + storage::counter_scratch_data()
        // New native claim/first-baseline views coexist with the complete old
        // counter. None of these headers borrows heap/tree backing as credit.
        + 2 * std::mem::size_of::<super::PacketNativeInvocationPreambleData>()
        + 4 * std::mem::size_of::<PacketNativeInvocationPurposeData>()
        + std::mem::size_of::<Option<PacketNativeInvocationPurposeData>>()
        + std::mem::size_of::<Result<PacketNativeInvocationPurposeData, ProviderError>>()
        + std::mem::size_of::<crate::protocol_snapshot::owned11::OriginalOwned11Fields<'_>>()
        + std::mem::size_of::<[&[u8]; 3]>()
        + std::mem::size_of::<[u8; 128]>() // actual borrowed Fields::span cursor
        + std::mem::size_of::<[bool; 11]>()
        + std::mem::size_of::<[usize; 10]>()
        + 2 * std::mem::size_of::<fn(&[u8], usize) -> Result<(), ProviderError>>()
}
/// Names the complete original Value-reader and native counter windows.
pub const fn original_native_invocation_value_counter_scratch_data() -> usize {
    original_native_invocation_counter_scratch_data()
        + shared::value_reader_additional_counter_scratch_data()
}

#[path = "invocation/wire.rs"]
mod wire;
pub use wire::{
    PacketNativeInvocationLaunchIdentityData, original_native_invocation_launch_identity_data,
    write_original_native_invocation_launch_data, write_original_native_invocation_purpose_data,
};

#[path = "invocation/storage.rs"]
mod storage;
pub use storage::{
    PacketNativeInvocationConstructionStorageData,
    original_native_invocation_construction_storage_data,
};

#[cfg(test)]
fn invalid() -> ProviderError {
    ProviderError::Correlation("native invocation purpose DATA")
}

#[cfg(test)]
#[path = "invocation/test_purpose.rs"]
mod tests;

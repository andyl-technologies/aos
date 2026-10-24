//! Preserves original paths for the shared canonical invocation writer.

pub use crucible_source_birth_data::profile::reference_packet::service::native_startup::invocation::wire::{
    PacketNativeInvocationLaunchIdentityData, original_native_invocation_launch_identity_data,
    write_original_native_invocation_launch_data, write_original_native_invocation_purpose_data,
};
pub(super) use crucible_source_birth_data::profile::reference_packet::service::native_startup::invocation::wire::counter_scratch_data;

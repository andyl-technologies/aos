//! Adapts the same original launch to the shared schema-only Fields schedule.

use super::*;
use crucible_source_birth_data::profile::reference_packet::service::{
    PacketNative5LaunchValidationFields as Fields, native_startup::schema_shapes as shared,
};
pub(super) use shared::InitialSchemaStorage;

pub(super) fn project(
    launch: &PacketNative5SourceLaunch,
    maximum: usize,
) -> Result<InitialSchemaStorage, ProviderError> {
    shared::project(&Fields::from_launch_data(launch), maximum)
}

// These are actual added adapter and lower literal-population windows. The
// original host observer source expansions preserve its old call boundaries.
pub(super) fn counter_scratch_data() -> usize {
    // Only the actual getter input/initializer/return are constructed here;
    // the independent validator's Credit and dispatch are not invoked.
    size_of::<&PacketNative5SourceLaunch>()
        + 2 * size_of::<Fields<'static>>()
        + size_of::<Fields<'static>>()
        + size_of::<&Fields<'static>>()
        + size_of::<&PacketNative5SourceLaunch>()
        + size_of::<Result<InitialSchemaStorage, ProviderError>>()
        + size_of::<&Fields<'static>>() // actual lower Fields input
        + size_of::<usize>() // actual lower maximum input
        + 2 * size_of::<crate::retained_metadata::RetainedProtocolMetadataFacts>() // literal initializer/local
        + size_of::<&crate::retained_metadata::RetainedProtocolMetadataFacts>() // actual backing query loan
        + size_of::<&mut crate::retained_metadata::RetainedProtocolMetadataFacts>() // actual unprofiled record input
        + size_of::<Result<(), ProviderError>>() // sequential literal population results
        + size_of::<usize>() // scoped literal entry/capacity identifiers
        + size_of::<usize>() // returned declared adapter count
}

#[cfg(test)]
#[path = "schemas/original.rs"]
mod original;

#[cfg(test)]
#[path = "schemas/shapes_tests.rs"]
mod shapes_tests;

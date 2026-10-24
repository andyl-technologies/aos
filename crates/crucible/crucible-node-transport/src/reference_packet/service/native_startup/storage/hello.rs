//! Separates the original Hello's retained owners and returning work phases.
//!
//! Arbitrary input retains the unchanged 64 KiB raw parser. Only the actual
//! locally generated result uses a closed projection. The constructor drops
//! typed claims before publication and all Hello locals before policy birth.

use super::*;
use crate::handshake::{HelloRequest, HelloResult, ResumeSession};
use crate::reference_packet::service::server::complete::hello_selection;
use crate::retained_metadata::serialization_storage::OriginalSerializationStorageData;

use crucible_source_birth_data::profile::reference_packet::service::{
    PacketNative5LaunchValidationFields, native_startup::hello_shapes,
};
pub(super) use hello_shapes::HelloStorage;

pub(super) const HEADER_LAYOUT: hello_shapes::HelloHeaderLayoutData =
    hello_shapes::HelloHeaderLayoutData {
        hello_request_bytes: size_of::<HelloRequest>(),
        resume_session_bytes: size_of::<ResumeSession>(),
        extension_offer_bytes: size_of::<crate::handshake::ExtensionOfferV1>(),
        extension_selection_bytes: size_of::<crate::handshake::ExtensionSelectionV1>(),
        connection_authority_bytes: size_of::<crate::handshake::ConnectionAuthority>(),
        hello_result_bytes: size_of::<HelloResult>(),
        metadata_observer_bytes: size_of::<MetadataObserver<'static>>(),
    };

fn generated_result(
    launch: &PacketNative5SourceLaunch,
    maximum: usize,
) -> Result<OriginalSerializationStorageData, ProviderError> {
    let fields = PacketNative5LaunchValidationFields::from_launch_data(launch);
    hello_shapes::generated_result(&fields, maximum)
}

pub(super) fn project(
    input: &PacketNativeBirthStartupInputs<'_>,
    maximum: usize,
) -> Result<HelloStorage, ProviderError> {
    project_with_raw(
        input.launch,
        input.host_registration,
        original_json_value_storage_extent_data(NATIVE_HELLO_BYTES)?,
        maximum,
    )
}

pub(super) fn project_with_raw(
    launch: &PacketNative5SourceLaunch,
    registration_bytes: &[u8],
    raw: crate::retained_metadata::serialization_storage::OriginalJsonValueStorageExtentData,
    maximum: usize,
) -> Result<HelloStorage, ProviderError> {
    let fixed = &HEADER_LAYOUT;
    crucible_source_birth_data::source_birth_native_hello_storage!(
        launch,
        registration_bytes,
        raw,
        maximum,
        fixed,
        binding,
        generated_result(launch, maximum)?,
        metadata_backing(&launch.selection.provider)?,
        metadata_backing(&binding.compatibility.guarantees_ref)?,
        hello_selection::counter_scratch_data(),
        crate::handshake::Handshake::original_native_hello_reuse_counter_scratch_data(),
        hello_shapes::additional_counter_scratch_data()
    )
}

#[cfg(test)]
#[path = "hello/original.rs"]
mod original;
#[cfg(test)]
#[path = "hello/tests.rs"]
mod tests;

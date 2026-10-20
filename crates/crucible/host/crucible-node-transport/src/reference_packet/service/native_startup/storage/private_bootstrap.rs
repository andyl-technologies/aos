//! Projects the new private-bootstrap banks before parsing a private launch.
//!
//! Existing canonical Source/registration children are scanned from their actual
//! retained encodings. Every new Binding14/boot6 field has a closed projection;
//! no future grant object or private key is fabricated to run the counter.

use super::*;
use crate::reference_packet::service::PacketNative5LaunchValidationFields as Fields;
use crate::retained_metadata::serialization_storage::OriginalSerializationStorageData;
use crucible_source_birth_data::profile::reference_packet::service::native_startup::private_shapes as shapes;
pub(super) use crucible_source_birth_data::profile::reference_packet::service::native_startup::private_bootstrap::{
    PrivateBootstrapStorage, canonical_launch_spare_data,
};

pub(super) trait PrivateBootstrapStorageExt {
    fn shared_retained_owner_data(
        &self,
        input: &PacketNativeBirthStartupInputs<'_>,
        maximum: usize,
    ) -> Result<[usize; 3], ProviderError>;
}

impl PrivateBootstrapStorageExt for PrivateBootstrapStorage {
    // These are precisely the three owners also named in retained_copies.
    // The typed native launch and this private launch Value remain distinct.
    fn shared_retained_owner_data(
        &self,
        input: &PacketNativeBirthStartupInputs<'_>,
        maximum: usize,
    ) -> Result<[usize; 3], ProviderError> {
        let launch = sum(
            &[
                input.encoded_launch.len(),
                canonical_launch_spare_data(input.encoded_launch.len(), maximum)?,
            ],
            maximum,
        )?;
        // Same original and same defining Value walk as this row's retained
        // registration term; no arbitrary encoded-byte heap multiplier.
        let registration = decoded::quote(
            input.host_registration,
            size_of::<serde_json::Value>(),
            size_of::<serde_json::Value>(),
            maximum,
        )?
        .value_backing;
        Ok([launch, self.source_value_backing_bytes, registration])
    }
}

fn source_additions(
    input: &PacketNativeBirthStartupInputs<'_>,
    maximum: usize,
) -> Result<OriginalSerializationStorageData, ProviderError> {
    shapes::source_additions(&Fields::from_launch_data(input.launch), maximum)
}

pub(super) fn boot_fields(
    input: &PacketNativeBirthStartupInputs<'_>,
    maximum: usize,
) -> Result<OriginalSerializationStorageData, ProviderError> {
    shapes::boot_fields(
        &Fields::from_launch_data(input.launch),
        input.private_launch,
        maximum,
    )
}

// This is the new borrowed adapter family, not a native construction grant.
pub(super) const fn literal_shape_counter_scratch_data() -> usize {
    2 * size_of::<Fields<'static>>() // actual defining getter return
        + size_of::<&Fields<'static>>() // lower Fields loan
        + size_of::<&PacketNative5SourceLaunch>() // actual getter input loan
        + size_of::<&crucible_node_format::Id>() // actual private Id input loan
        + size_of::<usize>() // new lower maximum input; sequential calls share this window
        + size_of::<Result<OriginalSerializationStorageData, ProviderError>>() // direct return
}

pub(super) fn project(
    input: &PacketNativeBirthStartupInputs<'_>,
    maximum: usize,
) -> Result<PrivateBootstrapStorage, ProviderError> {
    project_with_source(input, maximum, source_binding::project, false)
}

pub(super) fn project_invocation(
    input: &PacketNativeBirthStartupInputs<'_>,
    maximum: usize,
) -> Result<PrivateBootstrapStorage, ProviderError> {
    project_with_source(input, maximum, source_binding::project_invocation, false)
}

pub(super) fn project_preflight(
    input: &PacketNativeBirthStartupInputs<'_>,
    maximum: usize,
) -> Result<PrivateBootstrapStorage, ProviderError> {
    project_with_source(input, maximum, source_binding::project, true)
}

fn project_with_source(
    input: &PacketNativeBirthStartupInputs<'_>,
    maximum: usize,
    source_project: fn(&[u8], usize) -> Result<source_binding::SourceBindingStorage, ProviderError>,
    preflight: bool,
) -> Result<PrivateBootstrapStorage, ProviderError> {
    crucible_source_birth_data::source_birth_private_bootstrap_body!(
        input = input,
        maximum = maximum,
        source_project = source_project,
        preflight = preflight,
        bootstrap_layout = super::super::super::ack_emitter::original_native_private_bootstrap_layout,
        measurement_counter = super::super::super::ack_emitter::original_prepare_executable_measurement_counter_scratch_data,
        invocation_backing = super::super::original_native_private_invocation_backing_data,
        bank_shared_layout = super::super::original_native_private_bank_shared_layout_data,
        private_frame_work = super::private_frame_work_data,
        raw_extent = super::super::pre_dom::raw_extent_data,
        preflight_validation = launch_validation::preflight_work,
        decode = decoded::quote,
        source_additions = source_additions,
        boot_fields = boot_fields,
        sum = sum,
        refused = refused,
        decode_value = decode_value,
        native_element_slot = native_element_slot,
        literal_bank = literal_bank,
        launch_validation_work = launch_validation_work,
        original_json_value_storage_extent_data = original_json_value_storage_extent_data,
        canonical_launch_spare_data = canonical_launch_spare_data,
        size_of = size_of,
        PacketNative5SourceLaunch = PacketNative5SourceLaunch,
        PRIVATE_BOOT_BYTES = PRIVATE_BOOT_BYTES,
        PRIVATE_LAUNCH_BYTES = PRIVATE_LAUNCH_BYTES,
        PrivateBootstrapStorage = PrivateBootstrapStorage,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_launch_bank_covers_actual_capacity_and_refuses_one_short_retained_window()
    -> Result<(), Box<dyn std::error::Error>> {
        for value in [
            serde_json::json!({}),
            serde_json::json!({"launch": "x".repeat(8193)}),
            serde_json::json!({"escaped": "\n\t\"\\", "unicode": "𝄞", "values": [1, 2, 3]}),
        ] {
            let actual = crucible_node_format::canonical::canonical_json(&value)?;
            let spare = canonical_launch_spare_data(actual.len(), usize::MAX)?;
            let complete = sum(&[actual.len(), spare], usize::MAX)?;

            assert!(complete >= actual.capacity());
            assert!(spare > 0);
            assert_eq!(canonical_launch_spare_data(actual.len(), complete)?, spare);
            assert!(canonical_launch_spare_data(actual.len(), complete - 1).is_err());
        }
        assert!(canonical_launch_spare_data(usize::MAX, usize::MAX).is_err());
        Ok(())
    }
}

#[cfg(test)]
#[path = "private_bootstrap/original.rs"]
mod original;
#[cfg(test)]
#[path = "private_bootstrap/shapes_tests.rs"]
mod shapes_tests;

#[cfg(test)]
#[path = "private_bootstrap/fold_original.rs"]
mod fold_original;

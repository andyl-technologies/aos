//! Preserves the original full-input private shape implementation independently.

use super::super::*;
use crate::retained_metadata::serialization_storage::{
    OriginalSerializationStorageData, OriginalSerializationStorageProjection as Projection,
};

fn object(p: &mut Projection, keys: &[&str]) -> Result<(), ProviderError> {
    p.add_object()?;
    for key in keys {
        p.add_field(key)?;
    }
    Ok(())
}

fn row(p: &mut Projection, report: bool) -> Result<(), ProviderError> {
    if report {
        object(
            p,
            &[
                "raw_report_capacity",
                "retained_growth_bytes",
                "maximum_simultaneous_transient_bytes",
                "declared_counter_scratch_bytes",
            ],
        )?;
        p.add_unescaped_ascii_extent(20)?;
    } else {
        object(
            p,
            &[
                "retained_requested_bytes",
                "maximum_simultaneous_transient_bytes",
                "declared_counter_scratch_bytes",
            ],
        )?;
    }
    for _ in 0..3 {
        p.add_unescaped_ascii_extent(20)?;
    }
    Ok(())
}

pub(super) fn source_additions(
    input: &PacketNativeBirthStartupInputs<'_>,
    maximum: usize,
) -> Result<OriginalSerializationStorageData, ProviderError> {
    let launch = input.launch;
    let mut p = Projection::new(maximum)?;
    object(
        &mut p,
        &[
            "schema",
            "native_codec_metadata_extent",
            "protocol_metadata_limits",
            "complete_restore_selection",
            "restore_input_emitter_selection",
            "capture_allocation_selection",
            "fresh_restore_allocation_selection",
            "report_startup_allocation",
            "native_startup_allocation",
        ],
    )?;
    p.add_string(crate::reference_packet::service::native_startup::PACKET_NATIVE_STARTUP_SOURCE_BINDING_SCHEMA)?;
    p.add_value(&launch.native_codec_metadata_extent)?;
    p.add_value(&launch.protocol_metadata_limits)?;
    p.add_value(&launch.complete_restore_selection)?;
    p.add_value(&launch.restore_input_emitter_selection)?;
    p.add_value(&launch.capture_allocation_selection)?;
    p.add_value(&launch.fresh_restore_allocation_selection)?;
    if launch.capture_allocation_selection.is_some()
        || launch.fresh_restore_allocation_selection.is_some()
    {
        object(
            &mut p,
            &["schema", "original_observe12", "fresh_completed_admit13"],
        )?;
        p.add_string(
            crate::reference_packet::service::report_startup::PACKET_NATIVE_REPORT_STARTUP_ALLOCATION_SCHEMA,
        )?;
        for selected in [
            launch.capture_allocation_selection.is_some(),
            launch.fresh_restore_allocation_selection.is_some(),
        ] {
            if selected {
                row(&mut p, true)?;
            } else {
                p.add_value(&())?;
            }
        }
    } else {
        p.add_value(&())?;
    }
    object(
        &mut p,
        &[
            "schema",
            "private_bootstrap",
            "native_birth",
            "restore_prepare",
        ],
    )?;
    p.add_string(
        crate::reference_packet::service::native_startup::PACKET_NATIVE_STARTUP_ALLOCATION_SCHEMA,
    )?;
    row(&mut p, false)?;
    row(&mut p, false)?;
    if launch.complete_restore_selection==Some(crate::reference_packet::service::complete_restore::PacketNative5CompleteRestoreSelection::SourceSignedTransfer12) {
        row(&mut p,false)?;
    } else { p.add_value(&())?; }
    p.finish(maximum)
}

pub(super) fn boot_fields(
    input: &PacketNativeBirthStartupInputs<'_>,
    maximum: usize,
) -> Result<OriginalSerializationStorageData, ProviderError> {
    let mut p = Projection::new(maximum)?;
    object(
        &mut p,
        &[
            "schema",
            "private_key",
            "birth_id",
            "source_birth",
            "expected_host_registration",
            "private_launch",
            "host_executable",
        ],
    )?;
    p.add_string(
        crate::reference_packet::service::native_startup::PACKET_NATIVE_STARTUP_PRIVATE_BOOT_SCHEMA,
    )?;
    p.add_unescaped_ascii_extent(43)?;
    p.add_unescaped_ascii_extent(43)?;
    // The two complete actual canonical children are charged independently
    // below. These placeholders add only the outer embedding value slots.
    p.add_value(&())?;
    p.add_value(&())?;
    p.add_string(input.private_launch.as_str())?;
    // ContentRef has no custom Bytes formatter or allocating Serialize child.
    p.add_value(&input.launch.controller_executable)?;
    p.finish(maximum)
}

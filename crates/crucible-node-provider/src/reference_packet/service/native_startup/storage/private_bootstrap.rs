//! Projects the new private-bootstrap banks before parsing a private launch.
//!
//! Existing canonical Source/registration children are scanned from their actual
//! retained encodings. Every new Binding14/boot6 field has a closed projection;
//! no future grant object or private key is fabricated to run the counter.

use super::*;
use crate::retained_metadata::serialization_storage::{
    OriginalSerializationStorageData, OriginalSerializationStorageProjection as Projection,
};

pub(super) struct PrivateBootstrapStorage {
    pub(super) retained: usize,
    pub(super) transient: usize,
    pub(super) maximum_boot_bytes: usize,
    pub(super) maximum_source_bytes: usize,
    // Complete known base/additions Value plus canonical/parser work, not bytes.
    pub(super) source_requested_bytes: usize,
    pub(super) source_value_backing_bytes: usize,
}

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

fn source_additions(
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
    p.add_string(super::super::PACKET_NATIVE_STARTUP_SOURCE_BINDING_SCHEMA)?;
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
            super::super::super::report_startup::PACKET_NATIVE_REPORT_STARTUP_ALLOCATION_SCHEMA,
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
    p.add_string(super::super::PACKET_NATIVE_STARTUP_ALLOCATION_SCHEMA)?;
    row(&mut p, false)?;
    row(&mut p, false)?;
    if launch.complete_restore_selection==Some(super::super::super::complete_restore::PacketNative5CompleteRestoreSelection::SourceSignedTransfer12) {
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
    p.add_string(super::super::PACKET_NATIVE_STARTUP_PRIVATE_BOOT_SCHEMA)?;
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

pub(super) fn project(
    input: &PacketNativeBirthStartupInputs<'_>,
    maximum: usize,
) -> Result<PrivateBootstrapStorage, ProviderError> {
    let additions = source_additions(input, maximum)?;
    let fields = boot_fields(input, maximum)?;
    let added_encoded = additions
        .canonical_output_requested_bytes
        .checked_sub(256)
        .map(|n| n / 4)
        .ok_or_else(refused)?;
    let fields_encoded = fields
        .canonical_output_requested_bytes
        .checked_sub(256)
        .map(|n| n / 4)
        .ok_or_else(refused)?;
    // Existing Source keys that the additions replace are conservatively
    // retained in this extent. No old object or numeric maximum is erased.
    let base = source_binding::project(input.source_birth, maximum)?;
    let maximum_boot_bytes = sum(
        &[
            base.base_encoded_bytes,
            input.host_registration.len(),
            added_encoded,
            fields_encoded,
        ],
        maximum,
    )?;
    if maximum_boot_bytes > PRIVATE_BOOT_BYTES {
        return Err(refused());
    }
    let source = sum(
        &[base.base_decoded_bytes, additions.requested_total()?],
        maximum,
    )?;
    let source_backing = sum(&[base.base_value_backing_bytes, additions.retained_value_backing_bytes], maximum)?;
    let registration = decode_value(input.host_registration, maximum)?;
    let registration_backing = decoded::quote(input.host_registration, size_of::<serde_json::Value>(), size_of::<serde_json::Value>(), maximum)?.value_backing;
    let launch_backing = decoded::quote(input.encoded_launch, size_of::<PacketNative5SourceLaunch>(), native_element_slot(), maximum)?.value_backing;
    let launch = decode(
        input.encoded_launch,
        size_of::<PacketNative5SourceLaunch>(),
        maximum,
    )?;
    let private_literals = literal_bank(PRIVATE_LAUNCH_BYTES + PRIVATE_BOOT_BYTES + 8, 2)?;
    // FrameReader's generic raw+Value pass is restricted to the authenticated
    // preamble's actual launch length/closed boot extent BEFORE allocating. The
    // original literal reservation remains independent and is counted whole.
    let incoming = original_json_value_storage_extent_data(
        input.encoded_launch.len().max(maximum_boot_bytes),
    )?;
    // The raw frame canonical pass returns before typed launch decoding;
    // BootData and its known Source/host verification follow that launch.
    // All persistent holders below remain charged across every phase.
    let transient = incoming.canonical_pass_requested_bytes()?.max(sum(
        &[
            launch,
            source,
            registration,
            additions.requested_total()?,
            fields.requested_total()?,
            super::super::super::ack_emitter::original_native_private_bootstrap_layout(),
            2 * 32,
        ], maximum)?);
    // Original launch/source/registration/boot DOM children survive successful
    // service birth in the original private bootstrap holder. These independent
    // owners are not released merely because policy retains equivalent values.
    let retained = sum(
        &[
            private_literals,
            super::super::original_native_private_invocation_backing_data()?,
            super::super::original_native_private_bank_shared_layout_data()?,
            input.encoded_launch.len(),
            launch_backing,
            source_backing,
            registration_backing,
            additions.retained_value_backing_bytes,
            fields.retained_value_backing_bytes,
            super::super::super::ack_emitter::original_native_private_bootstrap_layout(),
        ], maximum)?;
    let maximum_source_bytes = sum(&[base.base_encoded_bytes, added_encoded], maximum)?;
    Ok(PrivateBootstrapStorage {
        retained,
        transient,
        maximum_boot_bytes,
        maximum_source_bytes,
        source_requested_bytes: source,
        source_value_backing_bytes: source_backing,
    })
}

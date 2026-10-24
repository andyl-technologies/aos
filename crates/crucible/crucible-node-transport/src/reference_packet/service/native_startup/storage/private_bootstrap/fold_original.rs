//! Preserves the complete original private bootstrap calculation independently.

use super::*;

pub(super) fn project_with_source(
    input: &PacketNativeBirthStartupInputs<'_>,
    maximum: usize,
    source_project: fn(&[u8], usize) -> Result<source_binding::SourceBindingStorage, ProviderError>,
    preflight: bool,
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
    let base = source_project(input.source_birth, maximum)?;
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
    let source_backing = sum(
        &[
            base.base_value_backing_bytes,
            additions.retained_value_backing_bytes,
        ],
        maximum,
    )?;
    let registration = decode_value(input.host_registration, maximum)?;
    let registration_backing = decoded::quote(
        input.host_registration,
        size_of::<serde_json::Value>(),
        size_of::<serde_json::Value>(),
        maximum,
    )?
    .value_backing;
    let launch_data = decoded::quote(
        input.encoded_launch,
        size_of::<PacketNative5SourceLaunch>(),
        native_element_slot(),
        maximum,
    )?;
    let launch_backing = launch_data.value_backing;
    let private_literals = literal_bank(PRIVATE_LAUNCH_BYTES + PRIVATE_BOOT_BYTES + 8, 2)?;
    // FrameReader's generic raw+Value pass is restricted to the authenticated
    // preamble's actual launch length/closed boot extent BEFORE allocating. The
    // original literal reservation remains independent and is counted whole.
    // After the quote/boot preparation, Bootstrap::prepare still invokes the
    // complete launch validator before moving launch into service. Retained
    // private Value banks persist; its temporary policy/coordinator/model work
    // is not the later permanent service coordinator.
    let decode_phase = sum(
        &[
            if preflight {
                // Bootstrap keeps the deserialized launch before reading Boot
                // and entering validate(). Its typed carry below is still live
                // in both phases; no failed/retained Boot owner is reclaimed.
                launch_validation::preflight_work(input, maximum)?
            } else {
                launch_validation_work(input, maximum)?
            },
            source,
            registration,
            additions.requested_total()?,
            fields.requested_total()?,
            super::super::super::super::ack_emitter::original_native_private_bootstrap_layout(),
            2 * 32,
        ],
        maximum,
    )?;
    let transient = if preflight {
        // First-frame Value/canonical banks remain in retained. The second
        // borrowed BootData and its independent canonical child banks are
        // charged alongside the full validator and carried typed launch/body.
        // Actual raw input must independently fit the two-pass gate BEFORE
        // either Value exists, including malformed partial DTO ownership.
        let carry = sum(
            &[launch_data.typed_backing, input.encoded_launch.len()],
            maximum,
        )?;
        let construction = sum(
            &[
                decode_phase,
                source,
                registration,
                additions.requested_total()?,
                fields.requested_total()?,
                carry,
            ],
            maximum,
        )?;
        let first = sum(
            &[
                input.encoded_launch.len(),
                super::super::private_frame_work_data(
                    super::super::super::pre_dom::raw_extent_data(input.encoded_launch)?,
                    0,
                )?,
            ],
            maximum,
        )?;
        construction
            .max(first)
            .max(sum(&[maximum_boot_bytes, carry], maximum)?)
    } else {
        let incoming = original_json_value_storage_extent_data(
            input.encoded_launch.len().max(maximum_boot_bytes),
        )?;
        // The FIRST raw launch frame precedes its typed owner. The SECOND raw
        // boot frame is parsed while self.launch retains that independent typed
        // launch. Its actual maximum_boot_bytes is enforced before reading. Keep
        // the original max(launch,boot) raw extent term unchanged as well.
        let second_raw = original_json_value_storage_extent_data(maximum_boot_bytes)?;
        let second_raw_phase = sum(
            &[
                second_raw.canonical_pass_requested_bytes()?,
                launch_data.typed_backing,
            ],
            maximum,
        )?;
        incoming
            .canonical_pass_requested_bytes()?
            .max(second_raw_phase)
            .max(decode_phase)
    };
    // The selected controller-image check runs after these parser/validator
    // phases return, while every original private bank remains retained. Fund
    // its actual complete read bank and independent returned reference strings
    // before claim_birth_data authenticates this row and enters measurement.
    let measurement = sum(
        &[
            super::super::super::super::ack_emitter::original_prepare_executable_measurement_counter_scratch_data(),
            "blake3-256".len(),
            "cnp.blob.v1".len(),
            64,
            "application/octet-stream".len(),
        ],
        maximum,
    )?;
    let transient = transient.max(measurement);
    // Original launch/source/registration/boot DOM children survive successful
    // service birth in the original private bootstrap holder. These independent
    // owners are not released merely because policy retains equivalent values.
    let retained = sum(
        &[
            private_literals,
            super::super::super::original_native_private_invocation_backing_data()?,
            // The private reader retains both cut allocations before native admission.
            super::super::super::original_native_private_cut_backing_data()?,
            super::super::super::original_native_private_bank_shared_layout_data()?,
            input.encoded_launch.len(),
            // Bootstrap canonical_json writes a growable Vec, not a boxed
            // exact-length slice. Keep the original length term and separately
            // fund its possible spare backing in both14 and15 projections.
            canonical_launch_spare_data(input.encoded_launch.len(), maximum)?,
            launch_backing,
            source_backing,
            registration_backing,
            additions.retained_value_backing_bytes,
            fields.retained_value_backing_bytes,
            super::super::super::super::ack_emitter::original_native_private_bootstrap_layout(),
        ],
        maximum,
    )?;
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

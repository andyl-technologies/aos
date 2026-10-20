//! Projects the new private-bootstrap banks before parsing a private launch.
//!
//! Existing canonical Source/registration children are scanned from their actual
//! retained encodings. Every new Binding14/boot6 field has a closed projection;
//! no future grant object or private key is fabricated to run the counter.

use super::*;
use crate::reference_packet::service::PacketNative5LaunchValidationFields as Fields;
use crate::retained_metadata::serialization_storage::OriginalSerializationStorageData;
use crucible_source_birth_data::profile::reference_packet::service::native_startup::private_shapes as shapes;

pub(super) struct PrivateBootstrapStorage {
    pub(super) retained: usize,
    pub(super) transient: usize,
    pub(super) maximum_boot_bytes: usize,
    pub(super) maximum_source_bytes: usize,
    // Complete known base/additions Value plus canonical/parser work, not bytes.
    pub(super) source_requested_bytes: usize,
    pub(super) source_value_backing_bytes: usize,
}

impl PrivateBootstrapStorage {
    // These are precisely the three owners also named in retained_copies.
    // The typed native launch and this private launch Value remain distinct.
    pub(super) fn shared_retained_owner_data(
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
            super::super::super::ack_emitter::original_native_private_bootstrap_layout(),
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
                super::private_frame_work_data(
                    super::super::pre_dom::raw_extent_data(input.encoded_launch)?,
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
            super::super::super::ack_emitter::original_prepare_executable_measurement_counter_scratch_data(),
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
            super::super::original_native_private_invocation_backing_data()?,
            super::super::original_native_private_bank_shared_layout_data()?,
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
            super::super::super::ack_emitter::original_native_private_bootstrap_layout(),
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

// This is the existing canonical-output growth geometry (4*n+256). The old
// length term remains in retained; this supplies only its missing spare bank.
// It is unrelated to the second independent launch_body clone carried in T.
fn canonical_launch_spare_data(encoded: usize, maximum: usize) -> Result<usize, ProviderError> {
    let complete = encoded
        .checked_mul(4)
        .and_then(|bytes| bytes.checked_add(256))
        .filter(|bytes| *bytes <= maximum)
        .ok_or_else(refused)?;
    complete.checked_sub(encoded).ok_or_else(refused)
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

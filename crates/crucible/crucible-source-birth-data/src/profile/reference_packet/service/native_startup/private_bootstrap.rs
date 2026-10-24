//! Shares the original private bootstrap storage calculation without live owners.
//!
//! The numeric record and canonical output growth are pure DATA. The finite
//! source-body macro preserves the actual upper query and failure schedule;
//! transport authentication, typed owners and native overlap seals stay upper.

use crate::errors::ProviderError;

/// Reports the closed private launch, Source, registration and boot owners.
///
/// These numeric components describe requested storage only. They neither own
/// the underlying banks nor authenticate an invocation or native admission.
pub struct PrivateBootstrapStorage {
    /// Counts retained private banks and their independent literal owners.
    pub retained: usize,
    /// Counts the greatest simultaneous private parsing or validation phase.
    pub transient: usize,
    /// Bounds the original canonical boot encoding before reading that frame.
    pub maximum_boot_bytes: usize,
    /// Bounds the original canonical Source plus its closed additions.
    pub maximum_source_bytes: usize,
    /// Counts the complete base and additions Value/canonical/parser work.
    pub source_requested_bytes: usize,
    /// Counts only the original retained Source Value backing.
    pub source_value_backing_bytes: usize,
}

/// Counts the spare backing of the original growable canonical launch bank.
///
/// The original encoded length is accounted independently. This returns only
/// the remaining capacity under the defining canonical output growth bound.
///
/// # Errors
/// Refuses checked growth overflow or a complete bank exceeding `maximum`.
pub fn canonical_launch_spare_data(encoded: usize, maximum: usize) -> Result<usize, ProviderError> {
    let complete = encoded
        .checked_mul(4)
        .and_then(|bytes| bytes.checked_add(256))
        .filter(|bytes| *bytes <= maximum)
        .ok_or_else(refused)?;
    complete.checked_sub(encoded).ok_or_else(refused)
}

/// Expands the original private bootstrap calculation at its defining query sites.
///
/// Every lexical slot names an existing function, type, constant or input. Slots
/// are not evaluated as function arguments: fallible validation, allocation
/// geometry and private layout queries remain at their original statements.
/// This source body issues no parsing, Source, process or native authority.
#[macro_export]
macro_rules! source_birth_private_bootstrap_body {
    (
        input = $input:ident,
        maximum = $maximum:ident,
        source_project = $source_project:ident,
        preflight = $preflight:ident,
        bootstrap_layout = $bootstrap_layout:path,
        startup_attempt_transient = $startup_attempt_transient:path,
        measurement_counter = $measurement_counter:path,
        invocation_backing = $invocation_backing:path,
        bank_shared_layout = $bank_shared_layout:path,
        private_frame_work = $private_frame_work:path,
        raw_extent = $raw_extent:path,
        preflight_validation = $preflight_validation:path,
        decode = $decode:path,
        source_additions = $source_additions:ident,
        boot_fields = $boot_fields:ident,
        sum = $sum:ident,
        refused = $refused:ident,
        decode_value = $decode_value:ident,
        native_element_slot = $native_element_slot:ident,
        literal_bank = $literal_bank:ident,
        launch_validation_work = $launch_validation_work:ident,
        original_json_value_storage_extent_data = $original_json_value_storage_extent_data:ident,
        canonical_launch_spare_data = $canonical_launch_spare_data:ident,
        size_of = $size_of:ident,
        PacketNative5SourceLaunch = $PacketNative5SourceLaunch:ty,
        PRIVATE_BOOT_BYTES = $PRIVATE_BOOT_BYTES:ident,
        PRIVATE_LAUNCH_BYTES = $PRIVATE_LAUNCH_BYTES:ident,
        PrivateBootstrapStorage = $PrivateBootstrapStorage:ident,
    ) => {{
        let additions = $source_additions($input, $maximum)?;
        let fields = $boot_fields($input, $maximum)?;
        let added_encoded = additions
            .canonical_output_requested_bytes
            .checked_sub(256)
            .map(|n| n / 4)
            .ok_or_else($refused)?;
        let fields_encoded = fields
            .canonical_output_requested_bytes
            .checked_sub(256)
            .map(|n| n / 4)
            .ok_or_else($refused)?;
        // Existing Source keys that the additions replace are conservatively
        // retained in this extent. No old object or numeric maximum is erased.
        let base = $source_project($input.source_birth, $maximum)?;
        let maximum_boot_bytes = $sum(
            &[
                base.base_encoded_bytes,
                $input.host_registration.len(),
                added_encoded,
                fields_encoded,
            ],
            $maximum,
        )?;
        if maximum_boot_bytes > $PRIVATE_BOOT_BYTES {
            return Err($refused());
        }
        let source = $sum(
            &[base.base_decoded_bytes, additions.requested_total()?],
            $maximum,
        )?;
        let source_backing = $sum(
            &[
                base.base_value_backing_bytes,
                additions.retained_value_backing_bytes,
            ],
            $maximum,
        )?;
        let registration = $decode_value($input.host_registration, $maximum)?;
        let registration_backing = $decode(
            $input.host_registration,
            $size_of::<serde_json::Value>(),
            $size_of::<serde_json::Value>(),
            $maximum,
        )?
        .value_backing;
        let launch_data = $decode(
            $input.encoded_launch,
            $size_of::<$PacketNative5SourceLaunch>(),
            $native_element_slot(),
            $maximum,
        )?;
        let launch_backing = launch_data.value_backing;
        let private_literals = $literal_bank($PRIVATE_LAUNCH_BYTES + $PRIVATE_BOOT_BYTES + 8, 2)?;
        // FrameReader's generic raw+Value pass is restricted to the authenticated
        // preamble's actual launch length/closed boot extent BEFORE allocating. The
        // original literal reservation remains independent and is counted whole.
        // After the quote/boot preparation, Bootstrap::prepare still invokes the
        // complete launch validator before moving launch into service. Retained
        // private Value banks persist; its temporary policy/coordinator/model work
        // is not the later permanent service coordinator.
        let decode_phase = $sum(
            &[
                if $preflight {
                    // Bootstrap keeps the deserialized launch before reading Boot
                    // and entering validate(). Its typed carry below is still live
                    // in both phases; no failed/retained Boot owner is reclaimed.
                    $preflight_validation($input, $maximum)?
                } else {
                    $launch_validation_work($input, $maximum)?
                },
                source,
                registration,
                additions.requested_total()?,
                fields.requested_total()?,
                $bootstrap_layout(),
                2 * 32,
            ],
            $maximum,
        )?;
        let transient = if $preflight {
            // First-frame Value/canonical banks remain in retained. The second
            // borrowed BootData and its independent canonical child banks are
            // charged alongside the full validator and carried typed launch/body.
            // Actual raw input must independently fit the two-pass gate BEFORE
            // either Value exists, including malformed partial DTO ownership.
            let carry = $sum(
                &[launch_data.typed_backing, $input.encoded_launch.len()],
                $maximum,
            )?;
            let construction = $sum(
                &[
                    decode_phase,
                    source,
                    registration,
                    additions.requested_total()?,
                    fields.requested_total()?,
                    carry,
                ],
                $maximum,
            )?;
            let first = $sum(
                &[
                    $input.encoded_launch.len(),
                    $private_frame_work($raw_extent($input.encoded_launch)?, 0)?,
                ],
                $maximum,
            )?;
            construction
                .max(first)
                .max($sum(&[maximum_boot_bytes, carry], $maximum)?)
        } else {
            let incoming = $original_json_value_storage_extent_data(
                $input.encoded_launch.len().max(maximum_boot_bytes),
            )?;
            // The FIRST raw launch frame precedes its typed owner. The SECOND raw
            // boot frame is parsed while self.launch retains that independent typed
            // launch. Its actual maximum_boot_bytes is enforced before reading. Keep
            // the original max(launch,boot) raw extent term unchanged as well.
            let second_raw = $original_json_value_storage_extent_data(maximum_boot_bytes)?;
            let second_raw_phase = $sum(
                &[
                    second_raw.canonical_pass_requested_bytes()?,
                    launch_data.typed_backing,
                ],
                $maximum,
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
        let measurement = $sum(
            &[
                $measurement_counter(),
                "blake3-256".len(),
                "cnp.blob.v1".len(),
                64,
                "application/octet-stream".len(),
            ],
            $maximum,
        )?;
        // Retaining the decoded original14 copy has its own fixed initializer
        // and Option assignment beside the resident Bootstrap header.
        let transient = $sum(
            &[transient.max(measurement), $startup_attempt_transient()],
            $maximum,
        )?;
        // Original launch/source/registration/boot DOM children survive successful
        // service birth in the original private bootstrap holder. These independent
        // owners are not released merely because policy retains equivalent values.
        let retained = $sum(
            &[
                private_literals,
                $invocation_backing()?,
                $bank_shared_layout()?,
                $input.encoded_launch.len(),
                // Bootstrap canonical_json writes a growable Vec, not a boxed
                // exact-length slice. Keep the original length term and separately
                // fund its possible spare backing in both14 and15 projections.
                $canonical_launch_spare_data($input.encoded_launch.len(), $maximum)?,
                launch_backing,
                source_backing,
                registration_backing,
                additions.retained_value_backing_bytes,
                fields.retained_value_backing_bytes,
                $bootstrap_layout(),
            ],
            $maximum,
        )?;
        let maximum_source_bytes = $sum(&[base.base_encoded_bytes, added_encoded], $maximum)?;
        Ok($PrivateBootstrapStorage {
            retained,
            transient,
            maximum_boot_bytes,
            maximum_source_bytes,
            source_requested_bytes: source,
            source_value_backing_bytes: source_backing,
        })
    }};
}

fn refused() -> ProviderError {
    ProviderError::ResourceExhausted("native baseline requested storage")
}

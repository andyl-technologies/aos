//! Separates completed launch decoding from later borrowed validation.
//!
//! Only the actual original14 pre-DOM producer uses this arithmetic DATA.
//! Bootstrap stores its typed launch before reading the independent Boot frame
//! and calling validate(). Decode work has returned then; typed carry, original
//! Value/literal banks, Boot/additions and failed partials remain independently
//! charged by the caller. Unknown raw classes preserve the old complete sum.

use super::*;

mod complete;

struct LaunchValidationPhases {
    syntax: usize,
    validation: usize,
}

impl LaunchValidationPhases {
    fn peak(&self, maximum: usize) -> Result<usize, ProviderError> {
        let peak = self.syntax.max(self.validation);
        if peak > maximum {
            return Err(refused());
        }
        Ok(peak)
    }
}

fn phases(
    input: &PacketNativeBirthStartupInputs<'_>,
    maximum: usize,
) -> Result<LaunchValidationPhases, ProviderError> {
    // Keep the complete old syntax/DTO quote. In particular, its returned typed
    // owner is not presumed free: private_bootstrap adds independent typed
    // carry through Boot/validation, beside all its actual retained Value banks.
    let syntax = launch_decode::quote(input.encoded_launch, maximum)?;
    let launch = input.launch;
    let mut configuration = crate::retained_metadata::serialization_storage::OriginalSerializationStorageProjection::new(maximum)?;
    match &launch.program {
        PacketConnectedSourceProgram::Producer { program } => configuration.add_value(program)?,
        PacketConnectedSourceProgram::Reactive { program } => configuration.add_value(program)?,
    }
    let configuration = configuration.finish(maximum)?;
    let definitions = schemas::project(launch, maximum)?;
    // validate() first decodes a coordinator, then materializes configuration
    // and may construct Native5Policy. That policy decodes the coordinator
    // AGAIN while configuration and cloned selection/raw content are live.
    // Keep every old validation term summed: this is not a MAX over those calls.
    let validation = sum(
        &[
            original_native_coordinator_decode_storage_data(
                launch.initial_coordinator.bytes.as_slice(),
                maximum,
            )?,
            coordinator_decode::backing(launch.initial_coordinator.bytes.as_slice(), maximum)?,
            metadata_backing(&launch.selection)?,
            launch.initial_coordinator.bytes.as_slice().len(),
            size_of::<crate::reference_packet::service::Native5Policy>(),
            configuration.requested_total()?,
            definitions.transient,
            definitions.retained_reference_children,
        ],
        maximum,
    )?;
    Ok(LaunchValidationPhases { syntax, validation })
}

/// Projects only the closed actual14 syntax-before-validation call order.
///
/// No decoded label or boolean supplies an owner or parser right. The existing
/// private startup claim/native row still authenticates actual inputs and the
/// unchanged pre-DOM gates, strict decoder and full validator still execute.
///
/// # Errors
/// Refuses overflow, an unsupported component or a complete phase above maximum.
/// Unrecognized raw classes use the original unrefined full validation quote.
pub(super) fn preflight_work(
    input: &PacketNativeBirthStartupInputs<'_>,
    maximum: usize,
) -> Result<usize, ProviderError> {
    if launch_decode::recognized(input.encoded_launch).is_err() {
        return launch_validation_work(input, maximum);
    }
    phases(input, maximum)?.peak(maximum)
}

pub(super) const fn counter_scratch_data() -> usize {
    size_of::<LaunchValidationPhases>()
        + size_of::<Result<LaunchValidationPhases, ProviderError>>()
        + size_of::<Result<crate::retained_metadata::serialization_storage::OriginalSerializationStorageProjection, ProviderError>>()
        + size_of::<&LaunchValidationPhases>()
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<
            crate::retained_metadata::serialization_storage::OriginalSerializationStorageProjection,
        >()
        + size_of::<crate::retained_metadata::serialization_storage::OriginalSerializationStorageData>(
        )
        + size_of::<
            Result<
                crate::retained_metadata::serialization_storage::OriginalSerializationStorageData,
                ProviderError,
            >,
        >()
        + size_of::<schemas::InitialSchemaStorage>()
        + size_of::<Result<schemas::InitialSchemaStorage, ProviderError>>()
        + size_of::<[usize; 8]>()
        + size_of::<&[usize]>()
        + size_of::<std::slice::Iter<'static, usize>>()
        + size_of::<&PacketNativeBirthStartupInputs<'static>>()
        + size_of::<&PacketNative5SourceLaunch>()
        + 3 * size_of::<usize>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_node_contract::{Bytes, Id, canonical};
    use serde_json::{Value, json};
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn launch_value() -> Value {
        let (_, _, selection, coordinator) =
            crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
        json!({"schema_version":5,"selection":selection,"program":{"kind":"producer","program":{
            "schema":"source-owned.packet-program.v1","events":[]}},
            "controller_pid":"1","controller_uid":"0","controller_executable":coordinator.reference,
            "admission_token":Bytes::new(vec![7;32]),"initial_coordinator":coordinator,
            "limits":{"frame_bytes":"65536","nesting":"64","requests":"64","journal_entries":"256","blob_chunk_bytes":"1024"},
            "storage":{"snapshot_bytes":"16384","control_snapshot_bytes":"8192","protocol_snapshot_bytes":"65536","frame_bank_bytes":"65536","frames_per_direction":"256","hello_bytes":"131080","settlement_bytes":"65536"},
            "effects":"/not-opened-by-data-control"})
    }

    #[test]
    fn actual_launch_decode_and_validation_keep_typed_carry_and_complete_old_terms() -> TestResult {
        // A real DTO decode and capacity walk, never accepted native authority:
        // the inert fixture deliberately has no valid model event population.
        let value = launch_value();
        let raw = canonical::canonical_json(&value)?;
        let launch: PacketNative5SourceLaunch = serde_json::from_value(value)?;
        let private = Id::new("phase-data-only")?;
        let input = PacketNativeBirthStartupInputs {
            launch: &launch,
            private_launch: &private,
            encoded_launch: &raw,
            source_birth: b"{}",
            host_registration: b"{}",
        };
        let phases = phases(&input, usize::MAX)?;
        let old = launch_validation_work(&input, usize::MAX)?;
        let refined = preflight_work(&input, usize::MAX)?;
        let actual = crate::retained_metadata::observe_retained_native_launch(&launch)?;
        let typed = requested_metadata_backing_storage_data(&actual)?;
        let carry = decoded::quote(
            &raw,
            size_of::<PacketNative5SourceLaunch>(),
            native_element_slot(),
            usize::MAX,
        )?
        .typed_backing;

        assert_eq!(sum(&[phases.syntax, phases.validation], usize::MAX)?, old);
        assert_eq!(refined, phases.syntax.max(phases.validation));
        assert!(refined < old);
        assert!(carry >= typed + size_of::<PacketNative5SourceLaunch>());
        assert!(sum(&[carry, refined], usize::MAX)? >= carry + phases.validation);
        assert_eq!(preflight_work(&input, refined)?, refined);
        assert!(preflight_work(&input, refined - 1).is_err());
        Ok(())
    }

    #[test]
    fn unknown_launch_shape_keeps_full_sum_and_zero_window_refuses() -> TestResult {
        let mut value = launch_value();
        let launch: PacketNative5SourceLaunch = serde_json::from_value(value.clone())?;
        value["future_owner"] = json!({"retained":[{},{}]});
        let raw = canonical::canonical_json(&value)?;
        let private = Id::new("unknown-phase-data")?;
        let input = PacketNativeBirthStartupInputs {
            launch: &launch,
            private_launch: &private,
            encoded_launch: &raw,
            source_birth: b"{}",
            host_registration: b"{}",
        };

        assert!(launch_decode::recognized(&raw).is_err());
        assert_eq!(
            preflight_work(&input, usize::MAX)?,
            launch_validation_work(&input, usize::MAX)?
        );
        assert!(preflight_work(&input, 0).is_err());
        assert!(PacketNative5SourceLaunch::decode(&raw, raw.len()).is_err());
        Ok(())
    }
}

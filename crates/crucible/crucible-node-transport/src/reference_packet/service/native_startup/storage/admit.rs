//! Counts the five retained once-Admit normalization trees and fixed MAC owners.
//!
//! Source/registration canonical extents come from the SAME original input and
//! closed Binding14 additions. The producer does not build a future context,
//! key, executable reference, assigned Envelope or native permission object.

use super::*;
use crate::retained_metadata::serialization_storage::{
    OriginalSerializationStorageData, OriginalSerializationStorageProjection as Projection,
};

use crate::reference_packet::service::PacketNative5LaunchValidationFields as Fields;
use crucible_source_birth_data::profile::reference_packet::service::native_startup::admit_normalization::AdmitNormalization;
pub(super) use crucible_source_birth_data::profile::reference_packet::service::native_startup::admit_normalization::AdmitStorage;

pub(super) fn project(
    input: &PacketNativeBirthStartupInputs<'_>,
    private: &private_bootstrap::PrivateBootstrapStorage,
    maximum: usize,
) -> Result<AdmitStorage, ProviderError> {
    let phase = AdmitNormalization::new(
        &Fields::from_launch_data(input.launch),
        input.private_launch,
        input.host_registration,
        private.source_requested_bytes,
        private.source_value_backing_bytes,
        private.maximum_source_bytes,
        maximum,
    )?;
    // verify_admit decodes a SECOND launch from owner.launch_body at its
    // entry. That independent typed owner survives through owner.original,
    // expected_body and all five normalizations; it is not the service's moved
    // launch already counted by the parent permanent row. The decode returns
    // before normalization, but its resulting backing stays live throughout.
    let launch_local = decoded::quote(
        input.encoded_launch,
        size_of::<PacketNative5SourceLaunch>(),
        native_element_slot(),
        maximum,
    )?;
    let launch_work = launch_validation_work(input, maximum)?;
    let phase = phase.with_launch(launch_local.typed_backing, launch_work, maximum)?;
    let scratch = sum(
        &[
            size_of::<AdmitStorage>(),
            size_of::<decoded::DecodedStorage>(),
            size_of::<[usize; 3]>(),
            decoded::counter_scratch_data(),
            launch_validation_counter_scratch_data(),
            size_of::<[usize; 5]>(),
            size_of::<[usize; 3]>(),
            // The three outer projections coexist before finishing; their
            // returned data can coexist with the native-ID projection/result.
            3 * size_of::<Projection>(),
            4 * size_of::<OriginalSerializationStorageData>(),
            size_of::<blake3::Hasher>(),
            size_of::<[u8; 32]>(),
        ],
        maximum,
    )?;
    Ok(phase.finish(scratch))
}

// Additional actual adapter owners, separately from all old normalization terms.
pub(super) const fn adapter_counter_scratch_data() -> usize {
    2 * size_of::<Fields<'static>>() // defining getter return
        + size_of::<&Fields<'static>>() // lower input loan
        + size_of::<&PacketNative5SourceLaunch>() // defining getter input
        + size_of::<&crucible_node_format::Id>()
        + size_of::<&[u8]>() // actual registration input loan
        + 4 * size_of::<usize>() // source/backing/source extent/maximum inputs
        + 2 * size_of::<AdmitNormalization>() // new constructor initializer and owned Ok input
        + 2 * size_of::<AdmitNormalization>() // first and post-launch caller bindings
        + 2 * size_of::<Result<AdmitNormalization, ProviderError>>() // staged returns
        + 2 * size_of::<AdmitNormalization>() // with_launch and finish owned self
        + 4 * size_of::<usize>() // with_launch inputs and finish scratch input
        + size_of::<AdmitStorage>() // new direct finish return
}

#[cfg(test)]
#[path = "admit/original.rs"]
mod original;
#[cfg(test)]
#[path = "admit/tests.rs"]
mod tests;

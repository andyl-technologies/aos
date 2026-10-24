//! Composes the closed original initial SDK admission constructor as DATA.
//!
//! This row includes the SDK's repeated offer decode, empty installed selection,
//! bounded writers, validators, complete original-body comparisons, owning leaf
//! clones, tree insertion and the concrete native verifier callbacks. The caller
//! retains and authenticates the original request/result/envelopes and actual
//! empty registry before construction. This quote supplies no Source grant,
//! admission, lease, ACK, policy, opaque Initial or Recipe.

use super::super::{hello_request, hello_response, hello_verifier};
use super::clone_controls::CloneControls;
use super::{
    Attempt, clone_controls, initial_admission_backing, initial_admission_controls,
    initial_admission_validation,
};
use crate::ProviderError;
use crate::handshake::{
    ExtensionOfferV1, ExtensionSelectionV1,
    original_initial_negotiation_writer_layer_counter_scratch_data,
};
use crate::reference_packet::continuation_models::serde_partials::{
    self, DecoderPartial, decoder_struct,
};
use crate::reference_packet::service::PacketNative5SourceLaunch;
use crucible_node_format::{Bytes, ContractError, ExtensionSelection, Id};
use std::mem::size_of;

decoder_struct!(ExtensionSelectionV1 { format, selected });

type TransientFields = [usize; 11];
type ScratchFields = [usize; 10];
type NegotiationFields = [usize; 23];

/// Quotes every internal phase of initial SDK admission under original custody.
///
/// The same immutable offer has already passed the original typed decoder and
/// validation; the SDK deserializes that same Value again. The response contains
/// the actual serializer's format1/empty Selection1. Neither decode can produce
/// an input-dependent diagnostic on this closed path. Writer refusals map to a
/// fixed resource error before typed decoding. Arbitrary callbacks, changed
/// trees, a nonempty installed registry and resumption require different rows.
///
/// Success backing remains retained beside all original owners. The second
/// decoded offer is local to the SDK and persists through later phases, so its
/// entire decoder row's retained axis joins transient demand. Sequential inner
/// windows are conservatively summed; the caller's terminal whole-root guards
/// and census remain separate construction terms.
///
/// # Errors
/// Refuses an invalid declaration, zero/overflowing framing, unsupported pinned
/// layouts or a complete row above the independent original restriction.
pub(in crate::reference_packet::service) fn construction_data(
    launch: &PacketNative5SourceLaunch,
    maximum: usize,
) -> Result<[usize; 3], ProviderError> {
    let frame = usize::try_from(launch.limits.frame_bytes.get()).map_err(|_| refused())?;
    if frame == 0 || maximum == 0 {
        return Err(refused());
    }

    let retained = initial_admission_backing::retained_backing_data(launch, maximum)?;
    let offer = hello_request::sdk_offer_reconstruction_data(frame, maximum)?;
    let validation = initial_admission_validation::construction_data(frame, maximum)?;
    let entry = initial_admission_controls::data()?;
    let string_clone = String::fresh_controls_data()?;
    let id_clone = Id::fresh_controls_data()?;
    let features_clone = Vec::<Id>::fresh_controls_data()?;
    let verifier = hello_verifier::construction_data()?;
    let writer = negotiation_counter_scratch_data()?;

    let transient_fields: TransientFields = [
        offer[0],
        offer[1],
        validation[1],
        entry[0],
        string_clone[0],
        id_clone[0],
        features_clone[0],
        verifier[0],
        verifier[1],
        // matches_object serializes either original 32-byte Bytes leaf into
        // one base64url String. The original vectors are already retained.
        43,
        serde_partials::diagnostic_error_impl_allocation_upper_bytes_data(),
    ];
    let scratch_fields: ScratchFields = [
        offer[2],
        validation[2],
        entry[1],
        string_clone[1],
        id_clone[1],
        features_clone[1],
        verifier[2],
        writer,
        Attempt::initial_admission_wrapper_counter_scratch_data(),
        counter_scratch_data(),
    ];
    let row = [
        retained.max(validation[0]),
        total(&transient_fields)?,
        total(&scratch_fields)?,
    ];
    if total(&row)? > maximum {
        return Err(refused());
    }
    Ok(row)
}

fn negotiation_counter_scratch_data() -> Result<usize, ProviderError> {
    // The original Value has the same closed string/object/array/null field
    // path as Offer1. The empty installed projection and Selection1 are shorter.
    let writer = original_initial_negotiation_writer_layer_counter_scratch_data()
        .checked_mul(hello_response::initial_negotiation_writer_depth_data())
        .ok_or_else(refused)?;
    let fields: NegotiationFields = [
        writer,
        ExtensionSelectionV1::partial_counter_data(),
        Bytes::serialization_counter_scratch_data(),
        size_of::<[u8; 20]>(), // allocation-free quoted U64 formatter
        size_of::<Result<&str, std::str::Utf8Error>>(),
        size_of::<u64>() * 2,
        size_of::<usize>() * 4,
        size_of::<&ExtensionOfferV1>() * 3,
        size_of::<&ExtensionSelectionV1>() * 3,
        size_of::<&[ExtensionSelection]>() * 6,
        size_of::<std::slice::Iter<'static, ExtensionSelection>>() * 4,
        size_of::<
            std::iter::Chain<
                std::slice::Iter<'static, ExtensionSelection>,
                std::slice::Iter<'static, ExtensionSelection>,
            >,
        >() * 2,
        // The count filter and its predicate each borrow the same installed
        // verifier; no closure owns an extension or has an allocating capture.
        size_of::<&dyn crate::handshake::InstalledExtensionNegotiationVerifier>() * 4,
        size_of::<Option<&ExtensionSelection>>() * 4,
        size_of::<&Id>() * 4,
        size_of::<&str>() * 6,
        size_of::<&[u8]>() * 4,
        size_of::<[&str; 3]>(), // preflight_roster_entries' actual field array
        size_of::<std::array::IntoIter<&str, 3>>(),
        size_of::<Option<&serde_json::Value>>() * 4,
        size_of::<Result<(), ContractError>>() * 4,
        size_of::<Result<(), ProviderError>>() * 6,
        size_of::<std::collections::TryReserveError>(),
    ];
    total(&fields)
}

/// Names complete quote helpers and this composition's actual array controls.
pub(in crate::reference_packet::service) fn counter_scratch_data() -> usize {
    initial_admission_backing::counter_scratch_data()
        + initial_admission_controls::counter_scratch_data()
        + initial_admission_validation::counter_scratch_data()
        + hello_request::sdk_offer_reconstruction_counter_scratch_data()
        + hello_verifier::counter_scratch_data()
        + clone_controls::quote_counter_scratch_data()
        + String::quote_counter_scratch_data()
        + Id::quote_counter_scratch_data()
        + Vec::<Id>::quote_counter_scratch_data()
        + size_of::<TransientFields>()
        + size_of::<ScratchFields>()
        + size_of::<NegotiationFields>()
        + size_of::<[usize; 3]>() * 5
        + size_of::<[usize; 2]>() * 4
        + size_of::<std::slice::Iter<'static, usize>>()
        + size_of::<&PacketNative5SourceLaunch>()
        + size_of::<[usize; 8]>()
        + size_of::<Option<usize>>() * 3
        + size_of::<Result<usize, ProviderError>>() * 6
        + size_of::<Result<[usize; 3], ProviderError>>() * 4
        + size_of::<Result<[usize; 2], ProviderError>>() * 4
}

fn total(fields: &[usize]) -> Result<usize, ProviderError> {
    fields.iter().try_fold(0usize, |sum, field| {
        sum.checked_add(*field).ok_or_else(refused)
    })
}

fn refused() -> ProviderError {
    ProviderError::ResourceExhausted("original import18 initial SDK constructor")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_node_format::U64;

    #[test]
    fn complete_sdk_quote_refuses_short_credit_and_unbounded_framing() {
        for reactive in [false, true] {
            let (mut launch, _, _) = super::super::tests::configuration_data(reactive);
            let row = construction_data(&launch, 268_435_456).unwrap();
            let peak = row.into_iter().sum::<usize>();

            assert!(row.into_iter().all(|axis| axis > 0));
            assert!(construction_data(&launch, peak - 1).is_err());
            assert!(construction_data(&launch, 0).is_err());

            launch.limits.frame_bytes = U64::new(0);
            assert!(construction_data(&launch, usize::MAX).is_err());

            launch.limits.frame_bytes = U64::new(u64::MAX);
            assert!(construction_data(&launch, usize::MAX).is_err());
        }
    }
}

//! Composes concrete SDK headers, tree controls and original comparison paths.
//!
//! These are partial constructor terms, not complete admission or numeric
//! authority. Decoder/writer and validator work, key clones and backing,
//! trusted callback measurement/equality, terminal guards and census must join
//! them before the genuine original producer can invoke SDK admission.

use super::super::{hello_response, hello_verifier::Verifier};
use super::clone_controls;
use crate::ProviderError;
use crate::handshake::{ExtensionHandshake, HelloRequest, HelloResult};
use crate::reference_packet::service::native_startup::data_equality;
use crucible_node_format::Id;
use std::mem::size_of;

type ComponentRows = [[usize; 2]; 5];

/// Combines initialized entry headers and the three actual insertion key types.
///
/// Only one insertion is active at a time: borrowed protocol-version keys,
/// owned selected envelope names, or the original request journal's owned Id.
/// Complete borrowed-set destruction and request/result comparison run in
/// separate windows. Their headers coexist with the enclosing SDK call.
///
/// # Errors
/// Refuses unsupported pinned container layouts or checked arithmetic overflow.
pub(super) fn data() -> Result<[usize; 2], ProviderError> {
    let components: ComponentRows = [
        clone_controls::set_insertion_data::<&'static String>()?,
        clone_controls::set_insertion_data::<String>()?,
        clone_controls::set_insertion_data::<Id>()?,
        clone_controls::borrowed_set_drop_data()?,
        [0, comparison_counter_scratch_data()?],
    ];
    let mut window = [0usize; 2];
    for component in components {
        window[0] = window[0].max(component[0]);
        window[1] = window[1].max(component[1]);
    }

    let entry = ExtensionHandshake::original_initial_admission_controls_data::<Verifier<'static>>();
    Ok([
        entry[0].checked_add(window[0]).ok_or_else(refused)?,
        entry[1].checked_add(window[1]).ok_or_else(refused)?,
    ])
}

fn comparison_counter_scratch_data() -> Result<usize, ProviderError> {
    let request = hello_response::initial_request_comparison_depth_data();
    // OriginalCompletedHello adds its actual outer borrowed result wrapper.
    let completed = hello_response::initial_result_comparison_depth_data()
        .checked_add(1)
        .ok_or_else(refused)?;
    let layer = data_equality::serialization_layer_counter_scratch_data::<HelloRequest>().max(
        data_equality::serialization_layer_counter_scratch_data::<HelloResult>(),
    );
    layer
        .checked_mul(request.max(completed))
        .ok_or_else(refused)
}

/// Names this supplier's actual arrays, helper quotes and checked accumulation.
pub(super) fn counter_scratch_data() -> usize {
    clone_controls::set_insertion_quote_counter_scratch_data()
        + clone_controls::set_drop_quote_counter_scratch_data()
        + size_of::<ComponentRows>()
        + size_of::<std::array::IntoIter<[usize; 2], 5>>()
        + size_of::<[usize; 2]>() * 4
        + size_of::<usize>() * 5
        + size_of::<Result<usize, ProviderError>>() * 3
        + size_of::<Result<[usize; 2], ProviderError>>() * 5
}

fn refused() -> ProviderError {
    ProviderError::ResourceExhausted("original import18 initial SDK control windows")
}

//! Quotes actual SDK response reservation and moved confirmed bootstrap records.
//!
//! The containing Reply Attempt already owns the
//! publication header; this module prices the additional backing and work only.

use super::*;
use crate::retained_metadata::requested_storage::tree_storage_data;
use crucible_node_format::{Id, values::MAX_ID_BYTES};
use serde_json::Value;
use std::mem::{align_of, size_of};

/// Quotes complete SDK reservation, confirmation backing and physical controls.
///
/// # Errors
/// Refuses unsupported metadata layouts or checked accumulation overflow.
pub(in super::super) fn backing_construction_data() -> Result<[usize; 3], ProviderError> {
    let response_text = super::super::storage::envelope_backing_text_data()?;
    let original_text = super::super::super::bootstrap_codec::envelope_text_data()?;
    // Original correlation's independent baseline already covers its actual
    // received request and cloned SDK parameters. Writing adds the response's
    // six maps/18 fields and one actual (Id, Envelope) map entry. The maximum
    // SDK entry layout also applies to every nested map in its ordinary census.
    let writing_trees = tree_storage_data(
        7,
        19,
        size_of::<Id>() + size_of::<Envelope>(),
        align_of::<Id>().max(align_of::<Envelope>()),
    )?;
    let writing = sum(&[writing_trees, response_text, MAX_ID_BYTES])?;
    // Confirmation moves both actual SDK Envelope values into retained slots.
    // No new request or response is reconstructed. The slots' ordinary census
    // combines their ten body/extension maps and 29 actual object members.
    let confirmed_trees = tree_storage_data(
        10,
        29,
        size_of::<String>() + size_of::<Value>(),
        align_of::<String>().max(align_of::<Value>()),
    )?;
    let confirmed = sum(&[confirmed_trees, original_text, response_text])?;
    let retained = writing.max(confirmed);
    // The response clone can fail before insertion. Its complete owned prefix,
    // copied map key and returned headers have independent transient credit.
    let transient = sum(&[
        writing,
        size_of::<Envelope>(),
        size_of::<Option<Envelope>>(),
        size_of::<Result<Envelope, ProviderError>>(),
        size_of::<Id>(),
        size_of::<Option<Id>>(),
        size_of::<ProviderError>(),
    ])?;
    Ok([retained, transient, counter_scratch_data()?])
}

/// Counts actual moved SDK records and known native I/O failure backing.
///
/// # Errors
/// Refuses unsupported dynamic error ownership, metadata limits or overflow.
pub(in super::super) fn retained_backing_data(
    attempt: &Publication,
) -> Result<usize, ProviderError> {
    let mut observer = crate::retained_metadata::MetadataObserver::new();
    if let Some(original) = &attempt.confirmed_request {
        super::super::super::bootstrap_codec::observe_envelope_data(original, &mut observer)?;
    }
    if let Some(response) = &attempt.confirmed_response {
        super::super::super::bootstrap_codec::observe_envelope_data(response, &mut observer)?;
    }
    match attempt.failure.as_ref() {
        None
        | Some(ProviderError::Frame(_))
        | Some(ProviderError::Correlation(_))
        | Some(ProviderError::ResourceExhausted(_))
        | Some(ProviderError::Conflict(_)) => {}
        Some(ProviderError::Io(error)) if error.get_ref().is_none() => {}
        // Native stream refusals are OS codes or static kinds. An arbitrary
        // custom error stays retained, but has no source-pinned dynamic layout.
        Some(_) => return Err(refused()),
    }
    crate::retained_metadata::requested_metadata_backing_storage_data(&observer.finish())
}

fn sum(terms: &[usize]) -> Result<usize, ProviderError> {
    terms.iter().try_fold(0usize, |sum, term| {
        sum.checked_add(*term).ok_or_else(exhausted)
    })
}

/// Names concrete publication, SDK, physical write and full-loan controls.
fn counter_scratch_data() -> Result<usize, ProviderError> {
    use crate::client::OriginalNativePublicBirthChannel;
    use crate::retained_metadata::{MetadataObserver, RetainedProtocolMetadataFacts};
    use std::mem::size_of_val;

    let terms = [
        super::super::literal::publication_counter_scratch_data(),
        OriginalNativePublicBirthChannel::write_counter_scratch_data(),
        super::super::super::hello_exchange::Holder::counter_scratch_data(),
        super::super::super::hello_publication::Attempt::completed_stream_counter_scratch_data::<
            OriginalNativePublicBirthChannel,
            (),
        >()?,
        super::super::super::bootstrap_correlation::Attempt::received_loan_counter_scratch_data::<()>(
        )?,
        super::super::super::bootstrap_correlation::counter_scratch_data()?,
        size_of::<correlation::Predecessors<'static>>() * 2,
        size_of::<Admissions<'static>>() * 2,
        size_of::<Publication>(),
        size_of::<Inputs<'static>>() * 8,
        size_of::<&dyn proof::Admission>(),
        size_of::<&dyn super::super::Admission>(),
        size_of::<&mut Proof>(),
        size_of::<proof::Inputs<'static>>() * 3,
        size_of::<Current<'static>>() * 6,
        size_of::<&dyn Admission>(),
        size_of::<&mut super::super::Attempt>(),
        size_of::<&mut CorrelationGuard>(),
        size_of::<&CorrelationGuard>() * 4,
        size_of::<&OriginalImport18RawBootstrap>() * 4,
        size_of::<&Envelope>() * 12,
        size_of::<Option<&Envelope>>() * 8,
        size_of::<&Id>() * 6,
        size_of::<&mut Option<Envelope>>() * 2,
        size_of::<Option<Envelope>>() * 2,
        size_of::<&BootstrapAckOperands<'static>>() * 4,
        size_of::<&Context>(),
        size_of::<&[u8; 32]>(),
        size_of::<Result<(&Context, &[u8; 32]), ProviderError>>(),
        size_of::<[Step; 3]>(),
        size_of::<std::array::IntoIter<Step, 3>>(),
        size_of::<Step>() * 5,
        size_of::<Phase>() * 3,
        size_of::<[usize; 3]>() * 5,
        size_of::<Weak<PacketNativeImport18SelectedLaunchWireData>>() * 2,
        size_of::<MetadataObserver<'static>>() * 2,
        size_of::<RetainedProtocolMetadataFacts>() * 2,
        size_of::<&ProviderError>(),
        size_of::<&std::io::Error>(),
        size_of::<std::collections::btree_map::Iter<'static, Id, Envelope>>() * 4,
        // Both moved Envelope owners use the ordinary closed object walker.
        10 * (size_of::<&Value>()
            + size_of::<&String>()
            + size_of::<serde_json::map::Iter<'static>>()
            + size_of::<std::collections::btree_map::Iter<'static, String, Value>>()
            + size_of::<&mut MetadataObserver<'static>>()
            + size_of::<Result<(), ProviderError>>()),
        size_of::<usize>() * 20,
        size_of::<Option<usize>>() * 5,
        size_of::<Result<usize, ProviderError>>() * 7,
        size_of::<Result<(), ProviderError>>() * 18,
        size_of::<Result<[usize; 3], ProviderError>>(),
        size_of::<std::slice::Iter<'static, usize>>() * 3,
        size_of::<&[usize]>() * 3,
    ];
    let controls = size_of_val(&terms) + size_of_val(&terms.into_iter());
    terms.into_iter().try_fold(controls, |sum, term| {
        sum.checked_add(term).ok_or_else(exhausted)
    })
}

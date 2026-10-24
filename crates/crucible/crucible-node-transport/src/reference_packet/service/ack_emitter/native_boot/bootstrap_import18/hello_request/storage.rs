//! Prices the real borrowed-Value offer decoder and its retained typed output.
//!
//! The offer has no Value, RawValue, Bytes or buffered tagged-enum field. Its
//! bounded two root vectors and concrete String leaves are priced directly.
//! Existing original Value/body/journal allocations remain separate owners.

use crate::ProviderError;
use crate::handshake::{ExtensionOfferV1, MAXIMUM_NEGOTIATED_EXTENSIONS};
use crate::reference_packet::continuation_models::serde_partials::{
    self, DecoderPartial, decoder_struct,
};
use crucible_node_format::{ContentRef, ExtensionSelection, HashRef, Id, SemanticVersion, U64};
use serde_json::Value;
use std::mem::size_of;

decoder_struct!(ExtensionOfferV1 {
    format,
    required,
    optional,
});

trait StringSlots {
    const COUNT: usize;
}

impl StringSlots for String {
    const COUNT: usize = 1;
}

impl StringSlots for Id {
    const COUNT: usize = 1;
}

impl StringSlots for U64 {
    const COUNT: usize = 0;
}

impl<T: StringSlots> StringSlots for Option<T> {
    const COUNT: usize = T::COUNT;
}

const fn string_slots<S, T: StringSlots>(_: fn(&S) -> &T) -> usize {
    T::COUNT
}

macro_rules! string_fields {
    ($type:ident { $($field:ident),+ $(,)? }) => {
        impl StringSlots for $type {
            const COUNT: usize = 0 $(+ string_slots(|value: &Self| &value.$field))+;
        }

        const _: fn(&$type) = |value| {
            let $type { $($field: _,)+ } = value;
        };
    };
}

string_fields!(HashRef {
    algorithm,
    domain,
    digest
});
string_fields!(ContentRef {
    hash,
    length,
    media_type
});
string_fields!(SemanticVersion {
    major,
    minor,
    patch,
    prerelease,
    build
});
string_fields!(ExtensionSelection {
    declaration,
    identifier,
    semantic_version,
    schema_digest
});

// These are the actual validation literals reached by Offer1's closed DAG.
// Decoder formatting text and input-derived unknown field/type text are priced
// separately. Controls compare every reached validation family with this row.
const VALIDATION_REASONS: [&str; 12] = [
    "expected 1–128 bounded ASCII identifier bytes",
    "unsupported hash algorithm",
    "expected 1–128 ASCII bytes",
    "expected 64 lowercase hexadecimal characters",
    "content must use cnp.blob.v1",
    "expected 1–128 printable ASCII bytes",
    "expected bounded exact SemVer identifiers",
    "expected exact schema content identity",
    "expected owner-controlled namespaced identifier",
    "unsupported negotiation edition",
    "require a bounded roster with unique sorted identifiers",
    "offer repeats an identifier or exceeds its aggregate bound",
];

/// Quotes a bounded actual offer decode without constructing or parsing it.
///
/// `frame_bytes` bounds the same original strict body and every borrowed String
/// supplied to the decoder. The caller first checks the actual root vector
/// populations against the unchanged aggregate negotiation limit. A failed
/// typed decode retains fixed error coordinates; a validation failure retains
/// its actual reason String alongside the typed offer.
///
/// # Errors
/// Refuses zero framing, overflow or a row above the independent restriction.
pub(super) fn construction_data(
    frame_bytes: usize,
    maximum: usize,
) -> Result<[usize; 3], ProviderError> {
    if frame_bytes == 0 {
        return Err(refused());
    }
    // serde 1.0.228's de/impls.rs and private/size_hint.rs cap the initial
    // allocation at the original borrowed array's length.
    // Rust 1.98.1 Vec growth doubles capacity, with at most four initial slots
    // for this nonzero element type. Across all old/new allocation requests,
    // four times the bounded length plus four slots covers either root vector.
    // Keep their independent allowances despite the earlier aggregate check.
    let vector_slots = MAXIMUM_NEGOTIATED_EXTENSIONS
        .checked_mul(4)
        .and_then(|n| n.checked_add(4))
        .ok_or_else(refused)?;
    let vector_bytes = 2usize
        .checked_mul(vector_slots)
        .and_then(|n| n.checked_mul(size_of::<ExtensionSelection>()))
        .ok_or_else(refused)?;
    let string_count = MAXIMUM_NEGOTIATED_EXTENSIONS
        .checked_mul(ExtensionSelection::COUNT)
        .ok_or_else(refused)?;
    let strings = frame_bytes
        .checked_mul(8)
        .and_then(|n| {
            string_count
                .checked_mul(32)
                .and_then(|fixed| n.checked_add(fixed))
        })
        .ok_or_else(refused)?;
    let validation = VALIDATION_REASONS
        .iter()
        .map(|reason| reason.len())
        .max()
        .ok_or_else(refused)?;
    let diagnostic_text = frame_bytes
        .checked_mul(6)
        .and_then(|n| n.checked_add(ExtensionOfferV1::DIAGNOSTIC_NAMES_BYTES))
        .and_then(|n| n.checked_add(serde_partials::diagnostic_format_text_bytes_data()))
        .and_then(|n| n.checked_add(validation))
        .and_then(|n| n.checked_add(size_of::<[u8; 20]>()))
        .ok_or_else(refused)?;
    let diagnostic = diagnostic_text
        .checked_mul(8)
        .and_then(|n| n.checked_add(8))
        .ok_or_else(refused)?;
    let retained = vector_bytes
        .checked_add(strings)
        .and_then(|n| n.checked_add(diagnostic))
        .ok_or_else(refused)?;
    let transient = strings
        .checked_add(diagnostic)
        .and_then(|n| {
            n.checked_add(serde_partials::diagnostic_error_impl_allocation_upper_bytes_data())
        })
        .and_then(|n| n.checked_add(size_of::<ExtensionOfferV1>() * 2))
        .and_then(|n| n.checked_add(size_of::<Result<ExtensionOfferV1, serde_json::Error>>()))
        .ok_or_else(refused)?;
    let row = [retained, transient, counter_scratch_data()];
    let peak = row.into_iter().try_fold(0usize, |sum, axis| {
        sum.checked_add(axis).ok_or_else(refused)
    })?;
    if peak > maximum {
        return Err(refused());
    }
    Ok(row)
}

/// Checks original vector populations before the real typed Vec constructors.
///
/// # Errors
/// Refuses another offer object or a missing/oversized aggregate roster.
pub(super) fn admit_populations_data(value: &Value) -> Result<(), ProviderError> {
    let object = value.as_object().ok_or_else(refused)?;
    if object.len() != 3 || !object.contains_key("format") {
        return Err(refused());
    }
    let required = object
        .get("required")
        .and_then(Value::as_array)
        .ok_or_else(refused)?;
    let optional = object
        .get("optional")
        .and_then(Value::as_array)
        .ok_or_else(refused)?;
    if required
        .len()
        .checked_add(optional.len())
        .is_none_or(|n| n > MAXIMUM_NEGOTIATED_EXTENSIONS)
    {
        return Err(refused());
    }
    Ok(())
}

/// Names actual borrowed-Value adapters, real derive partials and quote controls.
pub(super) fn counter_scratch_data() -> usize {
    ExtensionOfferV1::partial_counter_data()
        + size_of::<&Value>() * 4
        + size_of::<serde_json::map::Iter<'static>>() * 6
        + size_of::<std::slice::Iter<'static, Value>>() * 6
        + size_of::<serde::de::Unexpected<'static>>() * 2
        + size_of::<Result<(), serde_json::Error>>() * 6
        + size_of::<Option<&str>>() * 4
        + size_of::<&str>() * 6
        + size_of::<ExtensionOfferV1>()
        + size_of::<Result<ExtensionOfferV1, serde_json::Error>>()
        + size_of::<[usize; 3]>() * 2
        + size_of::<std::array::IntoIter<usize, 3>>()
        + size_of::<std::slice::Iter<'static, &'static str>>()
        + size_of::<usize>() * 15
        + size_of::<Result<usize, ProviderError>>() * 3
        + size_of::<Result<(), ProviderError>>() * 2
}

fn refused() -> ProviderError {
    ProviderError::ResourceExhausted("original import18 typed Hello offer")
}

#[cfg(test)]
pub(super) fn validation_reason_fixture_data(reason: &str) -> bool {
    VALIDATION_REASONS.contains(&reason)
}

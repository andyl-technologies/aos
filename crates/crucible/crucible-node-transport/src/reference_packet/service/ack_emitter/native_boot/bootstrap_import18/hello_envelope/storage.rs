//! Prices the real SDK envelope decoder for the checked initial-only grammar.
//!
//! The body has three string arrays and fixed Limits. Its sole envelope
//! extension has two arrays containing at most the already checked aggregate
//! extension-selection population. Every selection has exactly five objects:
//! selection, semantic version, declaration, declaration hash and schema digest. No arbitrary
//! extension Value or resumed body reaches this constructor.

use crate::ProviderError;
use crate::envelope::{Envelope, MessageKind, Method};
use crate::handshake::{ExtensionOfferV1, HelloRequest, Limits, MAXIMUM_NEGOTIATED_EXTENSIONS};
use crate::reference_packet::continuation_models::serde_partials::{
    self, DecoderPartial, decoder_struct,
};
use crate::retained_metadata::requested_storage::tree_storage_data;
use crucible_node_format::{
    ContentRef, ExtensionSelection, HashRef, MAX_ARRAY_ELEMENTS, SemanticVersion, canonical,
};
use serde_json::Value;
use std::mem::{align_of, needs_drop, size_of};

macro_rules! fields {
    ($count:ident, $type:ident { $($field:ident),+ $(,)? }) => {
        const $count: (usize, usize) = (
            0 $(+ { let _ = stringify!($field); 1 })+,
            0 $(+ stringify!($field).len())+,
        );

        const _: fn(&$type) = |value| {
            let $type { $($field: _,)+ } = value;
        };
    };
}

fields!(
    BODY_FIELDS,
    HelloRequest {
        versions,
        session_id,
        controller_nonce,
        required_features,
        optional_features,
        limits,
        admission_token,
        resume_session,
        extensions,
    }
);
fields!(
    LIMIT_FIELDS,
    Limits {
        frame_bytes,
        nesting,
        requests,
        journal_entries,
        blob_chunk_bytes,
    }
);
fields!(
    OFFER_FIELDS,
    ExtensionOfferV1 {
        format,
        required,
        optional
    }
);
fields!(
    SELECTION_FIELDS,
    ExtensionSelection {
        declaration,
        identifier,
        semantic_version,
        schema_digest,
    }
);
fields!(
    VERSION_FIELDS,
    SemanticVersion {
        major,
        minor,
        patch,
        prerelease,
        build
    }
);
fields!(
    REFERENCE_FIELDS,
    ContentRef {
        hash,
        length,
        media_type
    }
);
fields!(
    HASH_FIELDS,
    HashRef {
        algorithm,
        domain,
        digest
    }
);

const _: fn(&ExtensionSelection) = |value| {
    let _: &ContentRef = &value.declaration;
    let _: &HashRef = &value.schema_digest;
    let _: &SemanticVersion = &value.semantic_version;
};
const _: fn(&ContentRef) = |value| {
    let _: &HashRef = &value.hash;
};

macro_rules! unit_enum {
    ($type:ident { $($variant:ident),+ $(,)? }) => {
        impl DecoderPartial for $type {
            const DIAGNOSTIC_NAMES_BYTES: usize = stringify!($type).len()
                $(+ 2 * stringify!($variant).len() + 4)+;

            fn partial_counter_data() -> usize {
                size_of::<Self>() + size_of::<Result<Self, serde_json::Error>>()
            }
        }

        const _: fn($type) = |value| match value {
            $($type::$variant => (),)+
        };
    };
}

unit_enum!(MessageKind {
    Request,
    Response,
    Event
});
unit_enum!(Method {
    Hello,
    Discover,
    Realize,
    Admit,
    NativeImport18Bootstrap,
    Activate,
    Input,
    Observe,
    Begin,
    Poll,
    Cancel,
    QuantumClose,
    WorldActivate,
    Abort,
    Retire,
    BlobBegin,
    BlobChunk,
    BlobFinish,
    Release,
    OperationUpdate,
    ObservationReady,
    ProviderFault,
});

decoder_struct!(Envelope {
    protocol,
    message,
    session_id,
    incarnation_id,
    node_id,
    execution_owner_id,
    capture_owner_id,
    request_id,
    operation_id,
    sequence,
    method,
    body,
    extensions,
});

type RetainedFields = [usize; 3];
type TransientFields = [usize; 6];

/// Quotes actual borrowed-Value envelope decoding under the closed initial body.
///
/// The pinned Value visitor starts each array empty and pushes its elements;
/// it ignores the borrowed sequence's size hint. Its first nonempty allocation
/// holds four Value slots, then doubling bounds retained capacity by twice the
/// length plus four and cumulative requests by four times the length plus four.
/// All five original arrays retain separate minimum-allocation allowances.
/// Borrowed String and Value-string decoders request actual decoded lengths.
/// All copied key/value text, protocol and request ID fit the original literal.
///
/// # Errors
/// Refuses zero framing, unsupported map/Number geometry, checked overflow or
/// a complete row above the independently selected original restriction.
pub(super) fn construction_data(
    frame_bytes: usize,
    maximum: usize,
) -> Result<[usize; 3], ProviderError> {
    if frame_bytes == 0
        || canonical::STRICT_JSON_KEY_LOOKUP_STORAGE_DATA.is_none()
        || needs_drop::<serde_json::Number>()
    {
        return Err(refused());
    }
    // Every nonempty ASCII string needs two quotes and at least one byte;
    // comma separation contributes another byte apart from each array's last
    // element. Three body arrays therefore contain at most (frame + 3) / 4.
    let body_elements = (add(frame_bytes, 3)? / 4).min(mul(MAX_ARRAY_ELEMENTS, 3)?);
    let members_per_selection = add(
        add(
            add(SELECTION_FIELDS.0, REFERENCE_FIELDS.0)?,
            VERSION_FIELDS.0,
        )?,
        mul(HASH_FIELDS.0, 2)?,
    )?;
    // All five objects are nonempty. Each field needs its literal name,
    // quotes/colon, and a separating comma except the last in each object.
    // Four values are nested objects; the remaining validated leaves need at
    // least three encoded bytes each. Both actual digests require 64 characters,
    // adding 63 bytes over that one-character String minimum. Escaped keys or
    // values only increase this independently proven minimum literal extent.
    let key_bytes = total(&[
        SELECTION_FIELDS.1,
        REFERENCE_FIELDS.1,
        VERSION_FIELDS.1,
        mul(HASH_FIELDS.1, 2)?,
    ])?;
    let minimum_selection_bytes = total(&[
        key_bytes,
        mul(members_per_selection, 3)?,
        5 * 2,
        members_per_selection - 5,
        mul(members_per_selection - 4, 3)?,
        2 * (64 - 1),
    ])?;
    let selections = (frame_bytes / minimum_selection_bytes).min(MAXIMUM_NEGOTIATED_EXTENSIONS);
    let elements = add(body_elements, selections)?;
    // Initial Hello omits resume_session. Empty body extensions remain an
    // actual census root. The other roots are body/limits and offer/outer map.
    let members = add(
        mul(selections, members_per_selection)?,
        add(
            add(BODY_FIELDS.0 - 1, LIMIT_FIELDS.0)?,
            add(OFFER_FIELDS.0, 1)?,
        )?,
    )?;
    let containers = add(mul(selections, 5)?, 5)?;
    let trees = tree_storage_data(
        containers,
        members,
        add(size_of::<String>(), size_of::<Value>())?,
        align_of::<String>().max(align_of::<Value>()),
    )?;
    let array_slots = mul(elements, size_of::<Value>())?;
    let minimum_array_slots = mul(5, mul(4, size_of::<Value>())?)?;
    let retained_fields: RetainedFields = [
        frame_bytes,
        add(mul(array_slots, 2)?, minimum_array_slots)?,
        trees,
    ];
    let retained = total(&retained_fields)?;
    let diagnostic_text = total(&[
        mul(frame_bytes, 6)?,
        Envelope::DIAGNOSTIC_NAMES_BYTES,
        serde_partials::diagnostic_format_text_bytes_data(),
        size_of::<[u8; 20]>(),
    ])?;
    let diagnostic = add(mul(diagnostic_text, 8)?, 8)?;
    let transient_fields: TransientFields = [
        retained,
        add(mul(array_slots, 4)?, minimum_array_slots)?,
        diagnostic,
        serde_partials::diagnostic_error_impl_allocation_upper_bytes_data(),
        size_of::<Envelope>() * 2 + size_of::<Result<Envelope, serde_json::Error>>(),
        Envelope::partial_counter_data(),
    ];
    let row = [retained, total(&transient_fields)?, counter_scratch_data()];
    if maximum == 0 || total(&row)? > maximum {
        return Err(refused());
    }
    Ok(row)
}

/// Names actual derive partials, bounded geometry and fixed quote controls.
pub(super) fn counter_scratch_data() -> usize {
    Envelope::partial_counter_data()
        + size_of::<RetainedFields>()
        + size_of::<TransientFields>()
        + size_of::<[usize; 4]>()
        + size_of::<[usize; 6]>()
        + size_of::<std::slice::Iter<'static, usize>>()
        + size_of::<[usize; 3]>() * 2
        + size_of::<Result<[usize; 3], ProviderError>>()
        + size_of::<Result<usize, ProviderError>>() * 4
        + size_of::<Option<usize>>() * 3
        + size_of::<usize>() * 16
}

fn add(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_add(right).ok_or_else(refused)
}

fn mul(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_mul(right).ok_or_else(refused)
}

fn total(fields: &[usize]) -> Result<usize, ProviderError> {
    fields
        .iter()
        .try_fold(0usize, |sum, field| add(sum, *field))
}

fn refused() -> ProviderError {
    ProviderError::ResourceExhausted("original import18 SDK Hello envelope construction")
}

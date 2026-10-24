//! Declares error-construction facts of the existing Control validation path.
//!
//! The source-pinned callgraph covers the actual Control/model validators,
//! reached Begin argument/response branches, complete coordinator and their
//! nested portable schema validators. Deserialize diagnostics, dynamic input
//! text, formatting growth, parser errors and enclosing owners are separate.
//! None of these DATA facts grants decoding, native allocation or currentness.

use super::PacketDecodedCaptureFutureControlData;
use crate::ProviderError;
use crucible_node_format::ContractError;
use std::error::Error;
use std::io;
use std::mem::{align_of, size_of};
use std::ptr::NonNull;

// These are reached constructor arguments, not a census of unrelated source
// literals. callgraph.json pins each defining function and its direct pairs.

// Fields passed to the reached invalid/sorted/count helpers.
const FIELDS: &[&str] = &[
    "algorithm",
    "arguments",
    "array",
    "artifacts",
    "binding_hash",
    "bindings",
    "body",
    "connections",
    "content.hash",
    "content.length",
    "descriptor_hash",
    "descriptors",
    "destination_owner_ids",
    "digest",
    "domain",
    "extensions_supported",
    "facets",
    "features",
    "formats",
    "grant",
    "grid",
    "hash.domain",
    "id",
    "json_depth",
    "lanes",
    "limit",
    "limits",
    "media_type",
    "message",
    "model_definitions",
    "node_bindings",
    "node_id",
    "number",
    "operation_facets",
    "operation_state",
    "ordering_profile",
    "owner_bindings",
    "owner_generation",
    "owner_roles",
    "owners",
    "participant_ids",
    "ports",
    "protocol_versions",
    "qualification_refs",
    "requested_node_ids",
    "resolution_ps",
    "roles",
    "schema_version",
    "state_domain_ids",
    "state_formats",
    "supported_profiles",
    "version",
];

// Static reasons copied into ContractError::Invalid.reason.
const REASONS: &[&str] = &[
    "accepted response requires running custody",
    "an exact physical ceiling excludes every position at its tick",
    "array exceeds 65536 elements",
    "binding roster must equal owner participants",
    "body exceeds hard frame ceiling",
    "boundary settlement must stay within one physical tick",
    "completed response requires completed custody",
    "content must use cnp.blob.v1",
    "error message exceeds 4096 UTF-8 bytes",
    "exact grant requires exact mode and start <= limit",
    "exceeds 65536 elements",
    "expected 1–128 ASCII bytes",
    "expected 1–128 bounded ASCII identifier bytes",
    "expected 1–128 printable ASCII bytes",
    "expected 64 lowercase hexadecimal characters",
    "expected baseline version 1",
    "expected execution, capture, or both",
    "generation must be positive",
    "grant disagrees with enclosing live authority",
    "incorrect typed identity domain",
    "live owner generation must be positive",
    "nesting exceeds 64 containers",
    "node missing from execution or capture owner roster",
    "not a finite JCS number",
    "quantum requires quantized mode and from < until",
    "require positive quantum and phase < quantum",
    "require positive receiving ceilings within baseline hard caps",
    "resolution and phase must both be present or both null",
    "set must be strictly sorted with no duplicates",
    "set must be strictly sorted without duplicates",
    "stored byte length disagrees with reference",
    "stored bytes disagree with digest",
    "unsupported hash algorithm",
    "unsupported ordering profile",
    "wrong descriptor identity domain",
    "wrong node-binding identity domain",
    "zero schema/facet edition is forbidden",
];

// Reached borrowed ProviderError labels; these are not owned Strings.
const PROVIDER_LABELS: &[&str] = &[
    "captured complete restore birth absent",
    "captured complete restore coordinator absent",
    "captured complete restore schema differs",
    "captured native allocation definition differs",
    "captured native allocation family lacks original tuple",
    "captured native restore input writer tuple differs",
    "captured native restore transfer schema differs",
    "native metadata bank layout",
    "native metadata born backing differs",
    "native metadata born selection differs",
    "native metadata selected row bounds",
    "native5 captured ACK emitter lacks original tuple",
    "native5 captured confirmation lacks original birth tuple",
    "native5 captured coordinator mixture",
    "native5 captured metadata birth facts absent",
    "native5 captured metadata facts lack selection",
    "native5 captured profile lacks original birth storage",
    "native5 captured protocol metadata lacks original birth",
    "native5 captured protocol metadata profile differs",
    "native5 captured storage/coordinator mixture",
    "native5 compact protocol bounds",
    "native5 selected prefix count",
    "native5 selected prefix descriptor credit",
    "native5 selected storage bounds",
    "packet captured content bytes",
    "packet captured content credit changed",
    "packet captured control inventory",
    "packet complete Control edition/selection differs",
    "packet complete Control object absent",
    "packet complete control roundtrip changed",
    "packet complete control snapshot scope",
    "packet control snapshot bytes",
    "packet control snapshot canonical bytes",
    "packet control snapshot content role",
    "packet model snapshot bytes",
    "packet model snapshot canonical bytes",
    "packet model snapshot content role",
    "packet model snapshot edition",
    "packet original common coordinator scope differs",
    "packet original control/model association",
    "prepared whole frame bytes",
];

const WRITER_MESSAGE: &str = "prepared frame exceeds complete byte credit";

const fn largest(left: usize, right: usize) -> usize {
    if left > right { left } else { right }
}

const fn longest(values: &[&str]) -> usize {
    let mut maximum = 0;
    let mut index = 0;
    while index < values.len() {
        maximum = largest(maximum, values[index].len());
        index += 1;
    }
    maximum
}

const OWNED_REASON: usize = longest(REASONS);
const CONTRACT_STATIC: usize = largest(
    "invalid ".len() + longest(FIELDS) + ": ".len(),
    largest(
        "contract arithmetic overflow".len(),
        "invalid contract JSON: ".len(),
    ),
);
const PROVIDER_DIRECT_PREFIX: usize = largest(
    "invalid provider frame: ".len(),
    largest(
        "provider correlation failure: ".len(),
        largest(
            "provider resource exhausted: ".len(),
            "provider request conflict: ".len(),
        ),
    ),
);
const STATIC_DISPLAY: usize = largest(
    "invalid provider data: ".len() + CONTRACT_STATIC,
    largest(
        PROVIDER_DIRECT_PREFIX + longest(PROVIDER_LABELS),
        "provider stream I/O failed: ".len(),
    ),
);

impl PacketDecodedCaptureFutureControlData {
    /// Bounds one owned static validation reason in the reached Control path.
    ///
    /// The actual `invalid` helpers copy a static reason into a fresh String.
    /// This is its byte-bank request; its inline header and later Display/String
    /// growth are separate. Provider static labels allocate no reason bank.
    pub const fn validation_error_owned_reason_bytes_data() -> usize {
        OWNED_REASON
    }

    /// Bounds the static contribution of one reached outer error Display.
    ///
    /// Includes the actual ContractError field/punctuation or borrowed Provider
    /// label plus its prefix. Excludes the owned reason, nested serde/I/O text,
    /// numeric/location text and the destination String's growth. A caller adds
    /// those independent terms for its actual formatting/wrapping occurrence.
    pub const fn validation_error_static_text_bytes_data() -> usize {
        STATIC_DISPLAY
    }

    /// Names actual String, ContractError and ProviderError inline layouts.
    ///
    /// These three headers are not backing, an ErrorImpl allocation or credit.
    pub const fn validation_error_layout_data() -> (usize, usize, usize) {
        (
            size_of::<String>(),
            size_of::<ContractError>(),
            size_of::<ProviderError>(),
        )
    }

    /// Names the direct reached validation-error construction controls.
    ///
    /// Includes the writer-failure getter's own controls before its returned
    /// row is available. Validation traversal and later formatting controls remain
    /// separately admitted. No serializer is executed to discover these facts.
    pub fn validation_error_counter_scratch_data() -> usize {
        size_of::<&'static str>() // invalid field
            + size_of::<&str>() // reason before Into<String>/to_owned
            + size_of::<String>()
            + size_of::<Vec<u8>>() // the reached str-to-owned byte vector
            + size_of::<&[u8]>()
            + size_of::<ContractError>()
            + size_of::<ProviderError>()
            + size_of::<Result<(), ContractError>>()
            + size_of::<Result<(), ProviderError>>()
            + size_of::<(usize, usize, usize)>()
            + writer_failure_counter_scratch_data()
    }

    /// Bounds the reached counting-writer failure's separate transient owners.
    ///
    /// Returns `(0, transient_requested_bytes, counter_scratch_bytes)`. The
    /// pinned Rust1.98 `Error::other(&str)` copies the message, boxes a one-field
    /// StringError and boxes its four-field Custom. serde_json then boxes an
    /// ErrorImpl containing that I/O error before `serialized_credit` maps it to
    /// a borrowed ResourceExhausted label. Every allocation is charged here;
    /// none is paid by the Deserialize error pool or final static label.
    ///
    /// The bound includes requested allocator payloads, not allocator metadata,
    /// compiler frames or a physical-stack guarantee. The actual caller admits
    /// it before the borrowed counting serializer can reach this failure.
    pub fn validation_writer_failure_storage_data() -> (usize, usize, usize) {
        let custom = io_custom_allocation_upper_bytes_data();
        let error_impl = Self::decoder_error_impl_allocation_upper_bytes_data();
        let transient = WRITER_MESSAGE.len() + size_of::<String>() + custom + error_impl;
        (0, transient, writer_failure_counter_scratch_data())
    }
}

type DynamicError = dyn Error + Send + Sync;
type ErrorDrop = fn(*mut DynamicError);
type OuterDrop = fn(*mut ());

fn io_custom_allocation_upper_bytes_data() -> usize {
    // Rust1.98 core::io::Custom: ErrorKind, NonNull<dyn Error+Send+Sync>,
    // error_drop, outer_drop; repr(align(4)). Function pointer safety qualifiers
    // do not change their layout; no private std type or unsafe code is used.
    // Four (alignment-1) allowances cover the three possible internal gaps and
    // final rounding for any ordering of these four actual fields.
    let alignment = align_of::<io::ErrorKind>()
        .max(align_of::<NonNull<DynamicError>>())
        .max(align_of::<ErrorDrop>())
        .max(align_of::<OuterDrop>())
        .max(4);
    size_of::<io::ErrorKind>()
        + size_of::<NonNull<DynamicError>>()
        + size_of::<ErrorDrop>()
        + size_of::<OuterDrop>()
        + 4 * (alignment - 1)
}

fn writer_failure_counter_scratch_data() -> usize {
    // Each private owner uses its actual component layout, including Custom's
    // temporary value. CustomOwner is repr(transparent) NonNull<Custom> and
    // StringError is a single String. The boxed ErrorImpl is independently
    // charged on the heap above; serde_json::Error is its pointer header here.
    size_of::<&str>()
        + size_of::<String>()
        + size_of::<Vec<u8>>() // String::from<&str> delegates through ToOwned bytes
        + size_of::<&[u8]>()
        + size_of::<Box<String>>()
        + size_of::<Box<DynamicError>>()
        + size_of::<NonNull<DynamicError>>()
        + size_of::<io::ErrorKind>()
        + size_of::<ErrorDrop>()
        + size_of::<OuterDrop>()
        + io_custom_allocation_upper_bytes_data()
        + size_of::<NonNull<()>>() // actual CustomOwner / Box<Custom> thin header
        + size_of::<NonNull<()>>() // returned separately constructed CustomOwner
        + size_of::<io::Error>()
        + size_of::<Result<usize, io::Error>>()
        + size_of::<Result<(), io::Error>>() // actual Write::write_all return
        + size_of::<&[u8]>() // writer input, distinct from String copy source
        + size_of::<Option<usize>>()
        + size_of::<usize>() * 3 // maximum, checked next, actual slice length
        // ErrorImpl is also constructed as a value before its Box owns it.
        + PacketDecodedCaptureFutureControlData::decoder_error_impl_allocation_upper_bytes_data()
        + size_of::<serde_json::Error>()
        + size_of::<Result<(), serde_json::Error>>()
        + size_of::<ProviderError>()
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<usize>() * 4 // row custom, ErrorImpl, transient, layout alignment
        + size_of::<(usize, usize, usize)>()
}

// Exhaustive variant/field guards pin construction and wrapping semantics.
const _: fn(&ContractError) = |error| match error {
    ContractError::Invalid {
        field: _,
        reason: _,
    } => {}
    ContractError::Overflow => {}
    ContractError::Json(_) => {}
};

const _: fn(&ProviderError) = |error| match error {
    ProviderError::Io(_) => {}
    ProviderError::Contract(_) => {}
    ProviderError::Frame(_) => {}
    ProviderError::Correlation(_) => {}
    ProviderError::ResourceExhausted(_) => {}
    ProviderError::Conflict(_) => {}
};

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_node_format::{Id, SchemaRef, Validate, canonical};
    use std::collections::BTreeMap;
    use std::mem::size_of_val;

    fn check_invalid(error: ContractError) {
        let display = error.to_string();
        let ContractError::Invalid { field, reason } = &error else {
            panic!("actual validation must return its owned Invalid reason");
        };

        assert!(FIELDS.contains(field));
        assert!(REASONS.contains(&reason.as_str()));
        assert!(
            reason.len()
                <= PacketDecodedCaptureFutureControlData::validation_error_owned_reason_bytes_data(
                )
        );
        assert!(display.len() <= STATIC_DISPLAY + reason.len());
        assert!(ProviderError::Contract(error).to_string().len() <= STATIC_DISPLAY + OWNED_REASON);
    }

    #[test]
    fn actual_id_schema_and_fullref_validation_errors_fit_distinct_facts() {
        check_invalid(Id::new("").unwrap_err());

        let reference = canonical::content_ref(b"actual", "application/json").unwrap();
        let schema = SchemaRef {
            id: Id::new("schema").unwrap(),
            version: 0,
            definition: reference.clone(),
            extensions: BTreeMap::new(),
        };
        check_invalid(schema.validate().unwrap_err());
        check_invalid(reference.verify(b"changed").unwrap_err());

        let mut wrong_media = reference;
        wrong_media.media_type.clear();
        check_invalid(wrong_media.validate().unwrap_err());
    }

    #[test]
    fn actual_credit_writer_maps_intermediate_io_failure_to_borrowed_label() {
        let error = crate::connection::serialized_credit(&"actual borrowed input", 0).unwrap_err();
        assert!(matches!(
            error,
            ProviderError::ResourceExhausted("prepared whole frame bytes")
        ));
        assert!(error.to_string().len() <= STATIC_DISPLAY);

        let (retained, transient, scratch) =
            PacketDecodedCaptureFutureControlData::validation_writer_failure_storage_data();
        assert_eq!(retained, 0);
        let io = io::Error::other(WRITER_MESSAGE);
        let inner = io.get_ref().unwrap();
        assert_eq!(size_of_val(inner), size_of::<String>());
        assert_eq!(inner.to_string(), WRITER_MESSAGE);
        assert!(transient >= WRITER_MESSAGE.len() + size_of_val(inner)
            + io_custom_allocation_upper_bytes_data()
            + PacketDecodedCaptureFutureControlData::decoder_error_impl_allocation_upper_bytes_data());
        assert!(scratch >= size_of_val(&io) + size_of_val(&error));
    }

    #[test]
    fn error_header_facts_name_actual_public_types_without_heap_credit() {
        assert_eq!(
            PacketDecodedCaptureFutureControlData::validation_error_layout_data(),
            (
                size_of::<String>(),
                size_of::<ContractError>(),
                size_of::<ProviderError>()
            )
        );
    }
}

//! Counts the actual original Hello's raw, typed and registration owners.
//!
//! The native service always reserves its existing65,536-byte Hello parser.
//! This census keeps that raw ceiling even when later control frames are lower.
//! Only the selected first-Hello guard may narrow successful typed construction;
//! malformed/raw parsing and contract-error custody remain independently priced.

use super::*;
use crate::handshake::{HelloRequest, HelloResult, ResumeSession};
use crucible_node_contract::{ContentRef, ExtensionSelection, Id, SchemaRef};

pub(super) struct HelloStorage {
    pub(super) retained: usize,
    pub(super) transient: usize,
    pub(super) scratch: usize,
}

pub(super) fn project(
    input: &PacketNativeBirthStartupInputs<'_>,
    maximum: usize,
) -> Result<HelloStorage, ProviderError> {
    let raw = original_json_value_storage_extent_data(NATIVE_HELLO_BYTES)?;
    // All dynamic Hello children are JSON string/array/object occurrences. A
    // typed child can own its actual fixed schema/extension/resumption slot;
    // independently growable Vec payloads use the pinned geometric factor2.
    // Arbitrary Value extension children remain covered by the raw DOM row.
    let typed_node = [
        size_of::<HelloRequest>(),
        size_of::<HelloResult>(),
        size_of::<ResumeSession>(),
        size_of::<SchemaRef>(),
        size_of::<ExtensionSelection>(),
        size_of::<Id>(),
        size_of::<ContentRef>(),
    ]
    .into_iter()
    .max()
    .ok_or_else(refused)?;
    let typed_children = raw
        .maximum_value_nodes
        .checked_mul(typed_node)
        .and_then(|bytes| bytes.checked_mul(2))
        .ok_or_else(refused)?;
    let typed_strings = raw
        .maximum_decoded_string_bytes
        .checked_mul(8)
        .ok_or_else(refused)?;
    let one_typed = sum(&[typed_children, typed_strings], maximum)?;
    let one_raw = raw.canonical_pass_requested_bytes()?;
    let registration = decode(
        input.host_registration,
        size_of::<crate::handshake::ConnectionAuthority>(),
        maximum,
    )?;

    // These are distinct concrete constructor associations, conservatively
    // retained together: Connection, Endpoint, ACK-token, its identity, and the
    // short-lived Control-Admit handoff's independent authority data clones.
    // Each complete actual registration DOM/typed row dominates that clone's
    // IDs, Id Vec and String BTreeSet, retaining all original key/feature bytes.
    let authority_copies = sum(
        &[
            registration,
            registration,
            registration,
            registration,
            registration,
        ],
        maximum,
    )?;
    // Handshake owns supported/required/selected rosters; constructor selected
    // and HelloResult selected are independent Vecs; CorrelationGuard owns the
    // negotiated envelope set. Count a full registration row for each named
    // roster, including transient locals, without an equal-value alias refund.
    let roster_copies = sum(
        &[
            registration,
            registration,
            registration,
            registration,
            registration,
            registration,
        ],
        maximum,
    )?;
    let provider = metadata_backing(&input.launch.selection.provider)?;
    let [binding] = input.launch.selection.realization.bindings.as_slice() else {
        return Err(refused());
    };
    let guarantee = metadata_backing(&binding.compatibility.guarantees_ref)?;
    let retained = sum(
        &[
            authority_copies,
            roster_copies,
            provider,
            guarantee,
            // OriginalNativeAckConnectionIdentity owns an independent admit Id.
            128,
        ],
        maximum,
    )?;

    // The outer value, Envelope-owned body, response clone and completed-result
    // body can coexist. Handshake re-decodes a request, clones its typed input
    // and decodes the typed result while the constructor's own pair survives.
    // Summing all four raw/canonical and four typed phases conservatively covers
    // these finite concrete calls, even where their canonical banks drop sooner.
    let transient = sum(
        &[
            one_raw,
            one_raw,
            one_raw,
            one_raw,
            one_typed,
            one_typed,
            one_typed,
            one_typed,
            // Nonce/launch token vectors and bounded contract-error strings are
            // independent of the parsed JSON tree and actual retained literal bank.
            2 * 32,
            raw.maximum_canonical_encoded_bytes,
            size_of::<crate::ProviderError>(),
            size_of::<std::io::Error>(),
        ],
        maximum,
    )?;
    let scratch = sum(
        &[
            size_of::<HelloStorage>(),
            size_of::<
                crate::retained_metadata::serialization_storage::OriginalJsonValueStorageExtentData,
            >(),
            size_of::<[usize; 7]>(),
            size_of::<[usize; 6]>(),
            size_of::<HelloRequest>(),
            size_of::<HelloResult>(),
        ],
        maximum,
    )?;
    Ok(HelloStorage {
        retained,
        transient,
        scratch,
    })
}

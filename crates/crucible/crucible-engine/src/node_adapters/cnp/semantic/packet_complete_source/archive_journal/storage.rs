//! Counts the actual settled Journal backing and its existing decode footprint.
//!
//! These pure accounting helpers neither decode bytes nor authenticate an
//! archive. A caller admits the prospective constructor extent before decoding
//! and independently retains/counts the output holder and every partial owner.

use super::*;
use crate::node_contract::RuntimeError;
use crucible_node_format::HashRef;
use crucible_node_transport::reference_packet::service::confirmation::PacketNativeAfterConfirmationRequest;
use std::mem::size_of;

// The exhaustive field loans coexist with the loop cursors below. These
// borrowed layout rosters own no fields and create no Journal or receipt.
type JournalFieldLoans<'a> = (
    &'a String,
    &'a Id,
    &'a IdSet,
    &'a ContentRef,
    &'a ContentRef,
    &'a ContentRef,
    &'a ContentRef,
    &'a ContentRef,
    &'a ContentRef,
    &'a ContentRef,
    &'a ContentRef,
    &'a ContentRef,
    &'a Option<ContentRef>,
    &'a Id,
    &'a PacketNativeAfterConfirmationReceipt,
);

type ReceiptFieldLoans<'a> = (
    &'a String,
    &'a PacketNativeAfterConfirmationRequest,
    &'a ContentRef,
);

type ConfirmationFieldLoans<'a> = (
    &'a String,
    &'a Id,
    &'a HashRef,
    &'a Id,
    &'a HashRef,
    &'a ContentRef,
    &'a ContentRef,
    &'a ContentRef,
);

type ParticipantCursor<'a> =
    std::iter::Chain<std::slice::Iter<'a, Id>, std::array::IntoIter<&'a Id, 4>>;

type ReferenceCursor<'a> =
    std::iter::Chain<std::array::IntoIter<&'a ContentRef, 13>, std::option::Iter<'a, ContentRef>>;

impl PacketCompleteSettledJournal {
    /// Counts the requested backing of every initialized Journal field.
    ///
    /// The containing Journal or Option root is separate. Each independently
    /// owned reference/hash occurrence is counted, including equal fullrefs.
    /// This walk does not require validation or discount refused/partial state.
    ///
    /// # Errors
    /// Refuses arithmetic overflow or backing above `maximum`.
    pub fn retained_requested_storage_data(&self, maximum: usize) -> Result<usize, RuntimeError> {
        use crucible_node_transport::reference_packet::service::confirmation::{
            PacketNativeAfterConfirmationReceipt, PacketNativeAfterConfirmationRequest,
        };
        let PacketCompleteSettledJournal {
            schema,
            owner,
            participants,
            cut: _,
            ordinal: _,
            runtime,
            backend_implementation,
            semantic,
            ancestry,
            native_snapshot,
            native_control,
            native_anchor,
            native_after_protocol,
            host_protocol,
            host_extension_registry,
            confirmation_request,
            confirmation,
        } = self;
        let PacketNativeAfterConfirmationReceipt {
            schema: receipt_schema,
            capture,
            native_after_ref,
            native_after_capacity: _,
        } = confirmation;
        let PacketNativeAfterConfirmationRequest {
            schema: request_schema,
            capture_request_id,
            capture_request_hash,
            capture_operation_id,
            capture_terminal_hash,
            capture_terminal_sequence: _,
            native_snapshot_ref,
            native_control_ref,
            native_anchor_ref,
        } = capture;
        let mut total = 0usize;
        for text in [schema, receipt_schema, request_schema] {
            add(&mut total, text.capacity(), maximum)?;
        }
        add(
            &mut total,
            participants
                .capacity()
                .checked_mul(size_of::<Id>())
                .ok_or(RuntimeError::ResourceLimit)?,
            maximum,
        )?;
        for id in participants.iter().chain([
            owner,
            confirmation_request,
            capture_request_id,
            capture_operation_id,
        ]) {
            add(&mut total, id.allocated_capacity(), maximum)?;
        }
        for reference in [
            runtime,
            backend_implementation,
            semantic,
            ancestry,
            native_snapshot,
            native_control,
            native_anchor,
            native_after_protocol,
            host_protocol,
            native_after_ref,
            native_snapshot_ref,
            native_control_ref,
            native_anchor_ref,
        ]
        .into_iter()
        .chain(host_extension_registry.iter())
        {
            add(
                &mut total,
                NodeRuntime::capture_reference_storage(reference)?,
                maximum,
            )?;
        }
        for hash in [capture_request_hash, capture_terminal_hash] {
            add(
                &mut total,
                NodeRuntime::capture_hash_storage(hash)?,
                maximum,
            )?;
        }
        Ok(total)
    }

    /// Names the concrete borrowed controls of the Journal backing walk.
    ///
    /// Reference and hash walks read their actual String capacities, with no
    /// serializer, JSON parser, formatter or owning temporary.
    pub fn retained_counter_scratch_data() -> usize {
        size_of::<&Self>()
            + size_of::<JournalFieldLoans<'static>>()
            + size_of::<ReceiptFieldLoans<'static>>()
            + size_of::<ConfirmationFieldLoans<'static>>()
            + size_of::<[&String; 3]>()
            + size_of::<std::array::IntoIter<&'static String, 3>>()
            + size_of::<[&Id; 4]>()
            + size_of::<std::slice::Iter<'static, Id>>()
            + size_of::<std::array::IntoIter<&'static Id, 4>>()
            + size_of::<ParticipantCursor<'static>>()
            + size_of::<[&ContentRef; 13]>()
            + size_of::<std::array::IntoIter<&'static ContentRef, 13>>()
            + size_of::<std::option::Iter<'static, ContentRef>>()
            + size_of::<ReferenceCursor<'static>>()
            + size_of::<[&HashRef; 2]>()
            + size_of::<std::array::IntoIter<&'static HashRef, 2>>()
            + size_of::<&Id>()
            + size_of::<&ContentRef>()
            + size_of::<&HashRef>()
            + size_of::<&String>()
            // The direct ContentRef/HashRef OwnedStorage implementations fold
            // the actual string capacities through checked scalar adders.
            + size_of::<(&mut usize, usize, usize)>()
            + size_of::<usize>() * 3
            + size_of::<Option<usize>>()
            + size_of::<Result<usize, RuntimeError>>()
            + size_of::<Result<(), RuntimeError>>()
    }

    /// Returns the existing raw Journal decode construction allowance.
    ///
    /// This is the defining combined simultaneous parser/tree/string/vector
    /// extent used by the archived-owner decoder. It is not measured retained
    /// backing or a partition into retained and transient bytes. A conservative
    /// new caller can independently charge this bound on both axes; it must
    /// separately charge its actual output holder/root and fixed scratch.
    /// No byte is parsed, decoded, hashed or allocated by this quote.
    ///
    /// # Errors
    /// Refuses overflow in the pinned per-character layout or raw extent.
    pub fn decode_construction_storage_data(raw: &[u8]) -> Result<usize, OperationFailure> {
        let per_character = size_of::<serde_json::Value>()
            .checked_mul(2)
            .and_then(|n| n.checked_add(size_of::<String>() * 2))
            .and_then(|n| {
                n.checked_add(NodeRuntime::capture_map_node_storage::<
                    String,
                    serde_json::Value,
                >())
            })
            .ok_or_else(|| refused("cold journal parser layout overflow"))?;
        raw.len()
            .checked_mul(per_character)
            .ok_or_else(|| refused("cold journal parser extent overflow"))
    }

    /// Names only the pure prospective-layout quote's fixed controls.
    ///
    /// The actual decoder/parser/validator stack is a separate defining caller
    /// obligation; this getter grants no allowance for running those methods.
    pub fn decode_construction_counter_scratch_data() -> usize {
        size_of::<&[u8]>()
            + size_of::<usize>() * 3
            + size_of::<Option<usize>>()
            + size_of::<Result<usize, OperationFailure>>()
    }
}

fn add(total: &mut usize, bytes: usize, maximum: usize) -> Result<(), RuntimeError> {
    *total = total
        .checked_add(bytes)
        .filter(|n| *n <= maximum)
        .ok_or(RuntimeError::ResourceLimit)?;
    Ok(())
}

// These are the generated serde struct visitors' independent field slots. The
// existing exhaustive retained-field matches above keep the defining rosters
// compile-checked. The nine ContentRef slots name runtime/backend/semantic/
// ancestry/snapshot/control/anchor/after/host, not a generic largest-root pool.
type JournalDecodeSlots = (
    Option<String>,
    Option<Id>,
    Option<IdSet>,
    Option<crucible_node_format::Position>,
    Option<crucible_node_format::U64>,
    [Option<ContentRef>; 9],
    Option<Option<ContentRef>>,
    Option<Id>,
    Option<PacketNativeAfterConfirmationReceipt>,
);

type ReceiptDecodeSlots = (
    Option<String>,
    Option<PacketNativeAfterConfirmationRequest>,
    Option<ContentRef>,
    Option<crucible_node_format::U64>,
);

type ConfirmationDecodeSlots = (
    Option<String>,
    Option<Id>,
    Option<HashRef>,
    Option<Id>,
    Option<HashRef>,
    Option<crucible_node_format::U64>,
    [Option<ContentRef>; 3],
);

type ContentReferenceDecodeSlots = (
    Option<HashRef>,
    Option<crucible_node_format::U64>,
    Option<String>,
);

type HashReferenceDecodeSlots = (Option<String>, Option<String>, Option<String>);

type PositionDecodeSlots = (
    Option<crucible_node_format::U64>,
    Option<crucible_node_format::U64>,
    Option<crucible_node_format::Phase>,
);

type DependencyValidationCursor<'a> =
    std::iter::Chain<std::array::IntoIter<&'a ContentRef, 9>, std::option::Iter<'a, ContentRef>>;

impl PacketCompleteSettledJournal {
    /// Names the actual Journal parser, typed decoder and local validator controls.
    ///
    /// The caller admits this fixed workspace before `decode_data`. Parsed trees,
    /// typed backing, participant-key String copies and error diagnostics remain
    /// separate retained/transient constructor terms. This getter performs no
    /// parser, validator, serialization, allocation or authority operation.
    ///
    /// The private serde_json 1.0.150 owned map accessor consists of its public
    /// map IntoIter plus a pending Option<Value>; its sequence accessor contains
    /// the public Vec IntoIter. These exact field rosters below independently
    /// cover both accepted struct representations. The maximum nested path is
    /// Journal -> receipt -> confirmation request -> ContentRef -> HashRef.
    /// Generated field selectors carry no data and have at most seventeen cases;
    /// the separately named u32/Result<u32> slots conservatively bound those tags.
    pub fn decode_validation_counter_scratch_data() -> usize {
        use crucible_node_format::{ContractError, Phase, Position, U64};
        use crucible_node_transport::ProviderError;
        use std::borrow::Cow;
        use std::mem::align_of;

        // Named private accessor fields plus one explicit alignment allowance
        // avoid substituting the layout of an unrelated public deserializer.
        let map_access = size_of::<serde_json::map::IntoIter>()
            + size_of::<Option<serde_json::Value>>()
            + align_of::<serde_json::map::IntoIter>().max(align_of::<Option<serde_json::Value>>())
            - 1;
        let sequence_access = size_of::<std::vec::IntoIter<serde_json::Value>>();
        let field_access = size_of::<Cow<'static, str>>()
            + size_of::<(String, serde_json::Value)>()
            + size_of::<Option<(String, serde_json::Value)>>()
            + size_of::<u32>()
            + size_of::<Result<u32, serde_json::Error>>();
        let value_access = size_of::<serde_json::Value>()
            + size_of::<Result<serde_json::Value, serde_json::Error>>();

        crucible_node_format::canonical::json_parse_counter_scratch_bytes_data()
            + crucible_node_format::canonical::canonical_number_counter_scratch_bytes_data()
            + 5 * (map_access + sequence_access + field_access + value_access)
            + size_of::<JournalDecodeSlots>()
            + size_of::<ReceiptDecodeSlots>()
            + size_of::<ConfirmationDecodeSlots>()
            + size_of::<ContentReferenceDecodeSlots>()
            + size_of::<HashReferenceDecodeSlots>()
            + size_of::<PositionDecodeSlots>()
            + size_of::<Self>()
            + size_of::<Result<Self, OperationFailure>>()
            + size_of::<Result<Self, serde_json::Error>>()
            + size_of::<PacketNativeAfterConfirmationReceipt>()
            + size_of::<Result<PacketNativeAfterConfirmationReceipt, serde_json::Error>>()
            + size_of::<PacketNativeAfterConfirmationRequest>()
            + size_of::<Result<PacketNativeAfterConfirmationRequest, serde_json::Error>>()
            + size_of::<ContentRef>()
            + size_of::<Result<ContentRef, serde_json::Error>>()
            + size_of::<HashRef>()
            + size_of::<Result<HashRef, serde_json::Error>>()
            + size_of::<Position>()
            + size_of::<Result<Position, serde_json::Error>>()
            + size_of::<Phase>()
            + size_of::<Result<Phase, serde_json::Error>>()
            + size_of::<U64>()
            + size_of::<Result<U64, serde_json::Error>>()
            + size_of::<Result<U64, ContractError>>()
            + size_of::<Result<u64, std::num::ParseIntError>>()
            + size_of::<serde_json::Number>()
            + size_of::<Result<serde_json::Number, serde_json::Error>>()
            + size_of::<Result<u16, serde_json::Error>>()
            + size_of::<Result<u16, std::num::TryFromIntError>>()
            + size_of::<String>()
            + size_of::<Result<String, serde_json::Error>>()
            + size_of::<Id>()
            + size_of::<Result<Id, serde_json::Error>>()
            + size_of::<Result<Id, ContractError>>()
            + size_of::<Result<Id, crucible_node_format::IdFromOwnedError>>()
            + crucible_node_format::IdFromOwnedError::construction_transient_bytes_data()
            + crucible_node_format::IdFromOwnedError::construction_counter_scratch_bytes_data()
            + size_of::<IdSet>()
            + size_of::<Result<IdSet, serde_json::Error>>()
            + size_of::<&Self>()
            + size_of::<&PacketNativeAfterConfirmationReceipt>()
            + size_of::<&PacketNativeAfterConfirmationRequest>()
            + size_of::<&ContentRef>()
            + size_of::<&HashRef>()
            + size_of::<&Id>()
            + size_of::<Option<&str>>()
            + size_of::<Option<&serde_json::Value>>()
            + size_of::<&[u8]>()
            + size_of::<&str>()
            + size_of::<[&ContentRef; 9]>()
            + size_of::<DependencyValidationCursor<'static>>()
            + size_of::<std::array::IntoIter<&'static ContentRef, 9>>()
            + size_of::<std::option::Iter<'static, ContentRef>>()
            + size_of::<std::slice::Windows<'static, Id>>()
            + size_of::<&[Id]>()
            + size_of::<[String; 2]>()
            + size_of::<std::str::Bytes<'static>>()
            + size_of::<std::ops::RangeInclusive<u8>>()
            + size_of::<Option<u8>>()
            + size_of::<bool>()
            + size_of::<Result<(), ProviderError>>()
            + size_of::<Result<(), ContractError>>()
            + size_of::<Result<(), OperationFailure>>()
            + size_of::<OperationFailure>()
            + size_of::<ContractError>()
            + size_of::<serde_json::Error>()
            + size_of::<[usize; 4]>()
    }
}

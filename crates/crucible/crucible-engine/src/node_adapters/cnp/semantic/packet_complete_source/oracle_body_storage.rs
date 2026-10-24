//! Quotes raw/typed Oracle body copies from the same retained Controller DATA.
//!
//! No receipt is decoded, hash verified, native process queried or Source
//! callback invoked. This covers body ownership and parser construction only;
//! schema factories and semantic/currentness validators need independent rows.

use super::*;
use crucible_node_transport::retained_metadata::{
    OriginalNativeOracleTypedLayoutsData, original_native_oracle_body_decode_storage_data,
    original_native_oracle_expanded_decode_storage_data,
    original_native_oracle_geometry_counter_scratch_data,
    original_native_oracle_initial_inputs_data, original_native_oracle_raw_reference_matches_data,
    original_native_oracle_typed_layouts_data, original_native_oracle_underlying_reference_data,
    original_native_oracle_value_reference_matches_data,
};
use std::mem::size_of;

impl PacketCompleteSemanticSource {
    /// Quotes new Oracle body copies and the separate witness parser window.
    ///
    /// Actual closed-response full references select retained receipt candidates;
    /// their raw native_record full references select underlying bodies. Receipt and
    /// underlying-record copies are counted independently. This quote creates
    /// no source/currentness/receipt authority. Reactive input journals refuse
    /// in this initial-only quote. The actual caller must join its
    /// same Controller and fund semantic/schema validators separately.
    ///
    /// The returned tuple is (new backing R, parser/constructor T, fixed S).
    /// Existing Source/Controller backing and the Oracle Seal slot bank remain
    /// retained outer-owner charges, rather than new requests in this row.
    ///
    /// # Errors
    /// Refuses another creator, malformed candidate framing, unsupported nested
    /// layout, checked overflow or a complete body row beyond maximum.
    pub fn original_native_oracle_observation_construction_storage_data(
        &self,
        controller: &CnpController,
        maximum: usize,
    ) -> Result<(usize, usize, usize), RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        let layouts =
            original_native_oracle_typed_layouts_data().map_err(|_| RuntimeError::ResourceLimit)?;
        let mut retained = 0usize;
        let mut transient = 0usize;
        let mut matched_receipt = false;
        let mut scratch = Self::original_native_oracle_observation_counter_scratch_data();
        for (reference, receipt) in controller.original_completed_content_data() {
            if !is_response_root(controller, reference) {
                continue;
            }
            matched_receipt = true;
            include_body(
                reference,
                receipt,
                layouts,
                &mut retained,
                &mut transient,
                &mut scratch,
                maximum,
            )?;
            let native_reference = original_native_oracle_underlying_reference_data(receipt)
                .map_err(|_| RuntimeError::InvalidReceipt)?;
            let mut found = false;
            for (reference, native) in controller.original_completed_content_data() {
                if !original_native_oracle_raw_reference_matches_data(native_reference, reference)
                    .map_err(|_| RuntimeError::InvalidReceipt)?
                {
                    continue;
                }
                if found {
                    return Err(RuntimeError::ForeignAuthority);
                }
                found = true;
                original_native_oracle_initial_inputs_data(native)
                    .map_err(|_| RuntimeError::UnsupportedFacet)?;
                include_body(
                    reference,
                    native,
                    layouts,
                    &mut retained,
                    &mut transient,
                    &mut scratch,
                    maximum,
                )?;
            }
            if !found {
                return Err(RuntimeError::OwnerUnavailable);
            }
        }
        if !matched_receipt {
            return Err(RuntimeError::OwnerUnavailable);
        }
        let mut originals = 0usize;
        for original in controller.originals() {
            originals = add(originals, 1, maximum)?;
            include_body_map_reparse(
                &original.request.body,
                &mut transient,
                &mut scratch,
                maximum,
            )?;
            transient = add(
                transient,
                original_native_oracle_body_decode_storage_data(&original.request.body, maximum)
                    .map_err(|_| RuntimeError::ResourceLimit)?,
                maximum,
            )?;
            if let Some(response) = &original.response {
                include_body_map_reparse(&response.body, &mut transient, &mut scratch, maximum)?;
                transient = add(
                    transient,
                    original_native_oracle_body_decode_storage_data(&response.body, maximum)
                        .map_err(|_| RuntimeError::ResourceLimit)?,
                    maximum,
                )?;
            }
        }
        // Producer latest_root retains one independently decoded full reference
        // per original before selecting by sequence. Name its actual Vec slots.
        let roots = originals
            .checked_mul(4)
            .and_then(|n| n.checked_add(4))
            .and_then(|n| n.checked_mul(size_of::<(U64, ContentRef)>()))
            .ok_or(RuntimeError::ResourceLimit)?;
        transient = add(transient, roots, maximum)?;
        // verify_original_record_data constructs one of these real Box payloads.
        // Sum both alternatives conservatively; their by-value enum/witness
        // headers belong to the independently admitted fixed scratch below.
        transient = add(transient,
            size_of::<crucible_node_transport::reference_packet::control::PacketNativeRecord>()
                + size_of::<crucible_node_transport::reference_packet::connected::PacketConnectedNativeRecord>(),
            maximum)?;
        let row = finish_row(retained, transient, scratch, maximum)?;
        self.storage_origin_with_error::<RuntimeError>()?;
        Ok(row)
    }

    /// Names actual borrowed walkers and by-value witness/parser control views.
    ///
    /// Actual native validation/schema/currentness call frames remain separate.
    pub fn original_native_oracle_observation_counter_scratch_data() -> usize {
        CnpController::original_completed_content_counter_scratch_data()
            + CnpController::original_completed_content_counter_scratch_data()
            + original_native_oracle_geometry_counter_scratch_data()
            + NodeRuntime::capture_selected_json_decode_counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<&CnpController>()
            + size_of::<PacketCompleteNativeWitness<'static>>()
            + size_of::<super::super::packet_source::PacketNativeWitness<'static>>()
            + size_of::<super::super::packet_connected_source::PacketConnectedNativeWitness<'static>>(
            )
            + size_of::<
                crucible_node_transport::reference_packet::control::PacketNative5UnderlyingRecord,
            >()
            + size_of::<crucible_node_transport::reference_packet::control::PacketNative5Record>()
            + size_of::<crucible_node_transport::bodies::RequestBody>()
            + size_of::<crucible_node_transport::bodies::ResponseBody>()
            + size_of::<CnpSemanticRealizationScope<'static>>()
            + size_of::<&CnpSemanticRealizationScope<'static>>()
            + size_of::<OriginalNativeOracleTypedLayoutsData>()
            + size_of::<
                Result<
                    OriginalNativeOracleTypedLayoutsData,
                    crucible_node_transport::ProviderError,
                >,
            >()
            + size_of::<
                std::collections::btree_map::Values<
                    'static,
                    Id,
                    crucible_node_transport::client::ClientOriginal,
                >,
            >()
            + size_of::<
                std::iter::Chain<
                    std::collections::btree_map::Values<
                        'static,
                        Id,
                        crucible_node_transport::client::ClientOriginal,
                    >,
                    std::collections::btree_map::Values<
                        'static,
                        Id,
                        crucible_node_transport::client::ClientOriginal,
                    >,
                >,
            >()
            + size_of::<&crucible_node_transport::client::ClientOriginal>()
            + size_of::<&serde_json::Map<String, serde_json::Value>>()
            + size_of::<Option<&serde_json::Map<String, serde_json::Value>>>()
            + size_of::<Option<&serde_json::Value>>()
            + size_of::<Option<&Vec<serde_json::Value>>>()
            + size_of::<Option<&str>>()
            + size_of::<Option<&crucible_node_transport::envelope::Envelope>>()
            + size_of::<[usize; 5]>()
            + size_of::<std::array::IntoIter<usize, 5>>()
            + size_of::<std::slice::Iter<'static, serde_json::Value>>()
            + size_of::<[usize; 6]>()
            + size_of::<std::array::IntoIter<usize, 6>>()
            + size_of::<[&str; 4]>()
            + size_of::<std::array::IntoIter<&str, 4>>()
            + size_of::<(usize, usize, usize)>()
            + size_of::<Result<(usize, usize, usize), RuntimeError>>()
            + size_of::<Result<usize, RuntimeError>>()
            + 7 * size_of::<usize>()
            + size_of::<std::ops::Range<usize>>()
            + size_of::<std::thread::Thread>()
            + size_of::<std::thread::ThreadId>()
            + size_of::<u32>()
    }
}

fn reference_clone_backing(reference: &ContentRef, maximum: usize) -> Result<usize, RuntimeError> {
    [
        reference.hash.algorithm.as_str(),
        reference.hash.domain.as_str(),
        reference.hash.digest.as_str(),
        reference.media_type.as_str(),
    ]
    .into_iter()
    .try_fold(0usize, |sum, text| add(sum, text.len(), maximum))
}

fn add(left: usize, right: usize, maximum: usize) -> Result<usize, RuntimeError> {
    left.checked_add(right)
        .filter(|sum| *sum <= maximum)
        .ok_or(RuntimeError::ResourceLimit)
}

fn include_body(
    reference: &ContentRef,
    bytes: &[u8],
    layouts: OriginalNativeOracleTypedLayoutsData,
    retained: &mut usize,
    transient: &mut usize,
    scratch: &mut usize,
    maximum: usize,
) -> Result<(), RuntimeError> {
    let extra = crucible_node_transport::protocol_snapshot::raw_value_reparse::quote_raw_json_data(
        bytes, maximum,
    )
    .map_err(|_| RuntimeError::ResourceLimit)?;
    let (extra_retained, extra_transient, extra_scratch) =
        original_native_oracle_expanded_decode_storage_data(&extra, maximum)
            .map_err(|_| RuntimeError::ResourceLimit)?;
    *retained = add(*retained, extra_retained, maximum)?;
    for _ in 0..3 {
        *transient = add(*transient, extra_retained, maximum)?;
        *scratch = add(*scratch, extra_scratch, maximum)?;
    }
    for _ in 0..2 {
        *transient = add(*transient, extra_transient, maximum)?;
    }
    let (typed, parser, canonical) = NodeRuntime::capture_selected_json_decode_axes_data(
        bytes,
        layouts.maximum_array_element_bytes,
        layouts.maximum_tree_node_bytes,
        maximum,
    )?;
    // One future NativeBody clone plus separate receipt/native raw roles. The
    // same dictionary object can be reused across those roles and older roots.
    for term in [
        typed,
        bytes.len(),
        bytes.len(),
        reference_clone_backing(reference, maximum)?,
        reference_clone_backing(reference, maximum)?,
    ] {
        *retained = add(*retained, term, maximum)?;
    }
    // Underlying witness, the initial source receipt decode, then the outer
    // complete receipt reparse are independent typed populations. Two raw Value
    // parser phases and canonical validation output are retained separately.
    for term in [typed, typed, typed, parser, parser, canonical] {
        *transient = add(*transient, term, maximum)?;
    }
    Ok(())
}

fn is_response_root(controller: &CnpController, expected: &ContentRef) -> bool {
    use crucible_node_transport::envelope::Method;
    for original in controller.originals() {
        let Some(result) = original
            .response
            .as_ref()
            .and_then(|response| response.body.get("result"))
            .and_then(serde_json::Value::as_object)
        else {
            continue;
        };
        let candidate = match original.request.method {
            Method::Realize => result.get("closed_gate_receipt"),
            Method::Activate | Method::WorldActivate => result.get("activation_receipt"),
            Method::Begin
                if matches!(
                    original
                        .request
                        .body
                        .get("kind")
                        .and_then(serde_json::Value::as_str),
                    Some("exact_run" | "boundary_settle")
                ) =>
            {
                result.get("stop_receipt")
            }
            Method::Poll => result
                .get("outcome")
                .and_then(|outcome| outcome.get("result"))
                .and_then(|result| result.get("stop_receipt")),
            Method::Observe => {
                if result
                    .get("observations")
                    .and_then(serde_json::Value::as_array)
                    .is_some_and(|observations| {
                        observations.iter().any(|row| {
                            row.get("measurement_ref").is_some_and(|reference| {
                                original_native_oracle_value_reference_matches_data(
                                    reference, expected,
                                )
                            })
                        })
                    })
                {
                    return true;
                }
                None
            }
            _ => None,
        };
        if candidate.is_some_and(|reference| {
            original_native_oracle_value_reference_matches_data(reference, expected)
        }) {
            return true;
        }
    }
    false
}

fn include_body_map_reparse(
    body: &serde_json::Map<String, serde_json::Value>,
    transient: &mut usize,
    scratch: &mut usize,
    maximum: usize,
) -> Result<(), RuntimeError> {
    // The successful baseline Value-only visitor bounds actual supplied depth
    // to64 before entering the companion's independently documented Map128
    // scanner. No raw-parser depth claim is transferred across RawValue resets.
    original_native_oracle_body_decode_storage_data(body, maximum)
        .map_err(|_| RuntimeError::ResourceLimit)?;
    let extra = crucible_node_transport::protocol_snapshot::raw_value_reparse::quote_map_data(
        body, maximum,
    )
    .map_err(|_| RuntimeError::ResourceLimit)?;
    let (retained, temporary, fixed) =
        original_native_oracle_expanded_decode_storage_data(&extra, maximum)
            .map_err(|_| RuntimeError::ResourceLimit)?;
    // latest_root and original record/request correlation independently decode
    // these cached maps; no resulting typed/Value owner persists in the Oracle.
    for _ in 0..3 {
        *transient = add(add(*transient, retained, maximum)?, temporary, maximum)?;
        *scratch = add(*scratch, fixed, maximum)?;
    }
    Ok(())
}

fn finish_row(
    retained: usize,
    transient: usize,
    scratch: usize,
    maximum: usize,
) -> Result<(usize, usize, usize), RuntimeError> {
    add(add(retained, transient, maximum)?, scratch, maximum)?;
    Ok((retained, transient, scratch))
}

#[cfg(test)]
mod body_copy_controls {
    use super::*;
    use crate::node_adapters::cnp::semantic::retained_storage::preparation::PreparationCounter;
    use crucible_node_transport::envelope::{Envelope, MessageKind, Method, Nullable};
    use crucible_node_transport::reference_packet::connected::{
        PacketConnectedInventory, PacketConnectedNativeRecord,
    };
    use crucible_node_transport::reference_packet::control::PacketNativeRecord;
    use crucible_node_transport::reference_packet::{PacketEvent, PacketInventory};
    use crucible_node_transport::retained_metadata::RetainedPacketNativeRecord;

    fn original() -> Envelope {
        Envelope {
            protocol: "CNP/1".into(),
            message: MessageKind::Request,
            session_id: Nullable(Some(Id::new("actual-session").unwrap())),
            incarnation_id: Nullable(Some(Id::new("actual-incarnation").unwrap())),
            node_id: Nullable(Some(Id::new("producer").unwrap())),
            execution_owner_id: Nullable(Some(Id::new("actual-owner").unwrap())),
            capture_owner_id: Nullable(Some(Id::new("actual-owner").unwrap())),
            request_id: Nullable(Some(Id::new("world-activate").unwrap())),
            operation_id: Nullable(None),
            sequence: U64::new(5),
            method: Method::WorldActivate,
            body: serde_json::Map::new(),
            extensions: Extensions::new(),
        }
    }

    #[test]
    fn real_native_body_clone_and_raw_roles_fit_the_prospective_row()
    -> Result<(), Box<dyn std::error::Error>> {
        let start = Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl);
        let producer = PacketNativeRecord {
            schema: "source-owned.packet-native/2".into(),
            native_pid: U64::new(37),
            original: original(),
            inventory: PacketInventory {
                reached: start,
                gate_closed: false,
                pending: vec![PacketEvent {
                    id: Id::new("pending").unwrap(),
                    evaluation: start,
                    completion: start,
                    payload: Some(Bytes::new(vec![73; 32])),
                }],
                retained_outputs: Vec::new(),
                private_mutations: U64::new(0),
                packet_effects: U64::new(0),
            },
            grant: None,
        };
        let reactive = PacketConnectedNativeRecord {
            schema: "source-owned.packet-native/4".into(),
            native_pid: U64::new(38),
            original: original(),
            inventory: PacketConnectedInventory {
                reached: start,
                gate_closed: false,
                reactions: Vec::new(),
                delivered_inputs: Vec::new(),
                publications: Vec::new(),
                retained_outputs: Vec::new(),
                reactions_completed: U64::new(0),
                packet_effects: U64::new(0),
                stages: Vec::new(),
                commits: Vec::new(),
            },
            grant: None,
        };
        let copied_producer = producer.clone();
        let copied_reactive = reactive.clone();
        let mut marked = producer.clone();
        marked.original.body.insert(
            "actual-dynamic".into(),
            serde_json::json!({
                "$serde_json::private::RawValue": "{\"expanded\":[1,2,{\"text\":\"original\"}]}"
            }),
        );
        let marked_value = serde_json::to_value(&marked)?;
        let marked_raw = canonical::canonical_json(&marked_value)?;
        let marked_decoded: PacketNativeRecord =
            serde_json::from_value(canonical::parse_json(&marked_raw, marked_raw.len())?)?;
        let marked_copy = marked_decoded.clone();
        for (value, fields) in [
            (
                serde_json::to_value(&producer)?,
                RetainedPacketNativeRecord::Producer(&copied_producer)
                    .observe_retained_metadata()?,
            ),
            (
                serde_json::to_value(&reactive)?,
                RetainedPacketNativeRecord::Reactive(&copied_reactive)
                    .observe_retained_metadata()?,
            ),
            (
                marked_value,
                RetainedPacketNativeRecord::Producer(&marked_copy).observe_retained_metadata()?,
            ),
        ] {
            let raw = canonical::canonical_json(&value)?;
            let reference = canonical::content_ref(&raw, "application/json")?;
            let raw_copy = raw.clone();
            let native_copy = raw.clone();
            let first_reference = reference.clone();
            let second_reference = reference.clone();
            let layouts = original_native_oracle_typed_layouts_data()?;
            let quote = |maximum| {
                let (mut retained, mut transient, mut scratch) = (0, 0, 0);
                include_body(
                    &reference,
                    &raw,
                    layouts,
                    &mut retained,
                    &mut transient,
                    &mut scratch,
                    maximum,
                )?;
                finish_row(retained, transient, scratch, maximum)
            };
            let row = quote(usize::MAX)?;
            let mut observed = PreparationCounter::new(usize::MAX);
            observed.metadata(&fields)?;
            let actual = observed.finish().known_requested_bytes()
                + raw_copy.capacity()
                + native_copy.capacity()
                + reference_clone_backing(&first_reference, usize::MAX)?
                + reference_clone_backing(&second_reference, usize::MAX)?;
            assert!(row.0 >= actual);
            let total = row.0 + row.1 + row.2;
            assert_eq!(quote(total)?, row);
            assert!(quote(total - 1).is_err());
        }
        assert_eq!(
            copied_producer.inventory.pending,
            producer.inventory.pending
        );
        assert!(!copied_reactive.inventory.gate_closed);
        Ok(())
    }
}

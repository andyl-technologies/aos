//! Quotes native-private historical authentication without replaying its checks.
//!
//! The completed native graph and Controller supply borrowed construction
//! shapes. No verifier, MAC callback, DTO parser or custom Bytes formatter runs
//! during this counter. Its row is separate from the Source literal walk: that
//! walk funds supplied Source DTOs, their formatter strings, proof byte banks,
//! independent underlying-record decode and comparisons of supplied launch DATA.
//! This module funds native-private expected projections, actual cached body
//! decoding, dynamic selection validation and the defining schema factories.

use super::*;
use crate::envelope::Envelope;
use crate::reference_packet::service::{
    ack_emitter::{
        MAXIMUM_CANONICAL_ACK_ADMISSION_CONTEXT_BYTES, MAXIMUM_CANONICAL_ACK_ADMISSION_PROOF_BYTES,
    },
    complete_restore::{
        activation::MAXIMUM_RESTORATION_ACTIVATION_ARTIFACT_BYTES,
        maximum_complete_restore_held_evidence_bytes,
        restoration_observe::MAXIMUM_RESTORATION_OBSERVE_ARTIFACT_BYTES,
        transfer::{
            MAXIMUM_COMPLETE_RESTORE_TRANSFER_CONTEXT_BYTES,
            MAXIMUM_COMPLETE_RESTORE_TRANSFER_PROOF_BYTES,
            MAXIMUM_COMPLETE_RESTORE_TRANSFER_RECEIPT_BYTES,
            MAXIMUM_COMPLETE_RESTORE_TRANSFER_REQUEST_BYTES,
        },
    },
    restored_settled_capture::MAXIMUM_RESTORED_SETTLED_CAPTURE_ARTIFACT_BYTES,
};
use crate::retained_metadata::RetainedProtocolMetadataFacts;
use crate::retained_metadata::serialization_storage::{
    OriginalSerializationStorageData, OriginalSerializationStorageProjection,
    actual_serialization_storage_data, original_json_value_storage_extent_counter_scratch_data,
    original_json_value_storage_extent_data, original_serialization_counter_scratch_data,
};
use std::alloc::Layout;
use std::mem::size_of;

#[path = "construction/layouts.rs"]
mod layouts;
#[path = "construction/manifest.rs"]
mod manifest;
#[path = "construction/normalization.rs"]
mod normalization;
#[path = "construction/schema_work.rs"]
mod schema_work;

pub(crate) use manifest::world_manifest_window_data;
pub(crate) use normalization::normalized_ack_window_data;

/// Names fixed work admitted before the nonallocating native history quote.
///
/// No parsed Source owner, serialization, native validation or allocation is
/// created by this getter. The construction row separately reports its T peak.
pub fn source_history17_authentication_counter_scratch_data() -> usize {
    counter_scratch_data() + schema_work::counter_scratch_data()
}

/// Describes independently admitted native-private Source authentication work.
///
/// This immutable row creates no native receipt, Source ancestry, admission or
/// fresh process association. Source-owned parser/DTO/backing and malformed
/// custom Bytes formatter work are independently priced from the actual selected
/// Source spans. In particular, a later serialized-credit refusal is not a
/// preallocation guard for a custom formatter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RestoredSettledSourceHistory17AuthGeometryData {
    transient: usize,
    scratch: usize,
    maximum_array_element: Layout,
    maximum_tree_node: Layout,
}

impl RestoredSettledSourceHistory17AuthGeometryData {
    /// Returns the native-private construction high-water bound, excluding S.
    pub const fn maximum_simultaneous_transient_bytes_data(&self) -> usize {
        self.transient
    }

    /// Returns explicit counter, typed-root and borrowed-view scratch demand.
    pub const fn declared_counter_scratch_bytes_data(&self) -> usize {
        self.scratch
    }

    /// Returns the largest concrete nested array-element layout in this family.
    ///
    /// Nested String, Vec and BTree backing remains a separate occurrence term;
    /// an opaque root's inline size is never substituted for this roster.
    pub const fn maximum_typed_element_layout_data(&self) -> Layout {
        self.maximum_array_element
    }

    /// Returns the largest actual pinned tree-node layout in this family.
    pub const fn maximum_typed_tree_node_layout_data(&self) -> Layout {
        self.maximum_tree_node
    }
}

/// Accumulates actual already-retained body and envelope JSON shapes.
///
/// Every `Value` subtree is borrowed from a completed opaque native/Controller
/// owner. These visits allocate neither a DOM nor custom scalar formatting.
#[derive(Default)]
pub(crate) struct HistoricalAuth17Shapes {
    maximum_body_encoded: usize,
    maximum_body_nodes: usize,
    maximum_body_sequence_elements: usize,
    maximum_body_sequence_containers: usize,
    maximum_body_canonical_pass: usize,
    maximum_body_dom: usize,
    maximum_bindings: usize,
    maximum_envelope_encoded: usize,
    maximum_envelope_pass: usize,
}

impl HistoricalAuth17Shapes {
    /// Visits only the actual completed restoration tuples in a Controller.
    ///
    /// # Errors
    /// Refuses absent tuples, unfinished shapes or independent counter limits.
    pub(crate) fn include_controller_data(
        &mut self,
        controller: &crate::protocol_snapshot::current_controller17::ValidatedControllerSettledHistory17,
        maximum: usize,
    ) -> Result<(), ProviderError> {
        let parts = controller.parts_data()?.as_object().ok_or_else(exhausted)?;
        for (name, width) in [
            ("ack_admit", 8),
            ("restore_prepare", 11),
            ("restore_commit", 11),
        ] {
            let row = parts
                .get(name)
                .and_then(Value::as_array)
                .ok_or_else(exhausted)?;
            if row.len() != width {
                return Err(exhausted());
            }
            // These are the defining once tuple's actual original and terminal,
            // not the raw byte-bank arrays or another request found by hash.
            for index in [1, 6] {
                let envelope = row.get(index).ok_or_else(exhausted)?;
                let body = envelope.get("body").ok_or_else(exhausted)?;
                self.include_body_data(body, maximum)?;
                self.maximum_bindings = self.maximum_bindings.max(
                    body.get("bindings")
                        .and_then(Value::as_array)
                        .map_or(0, Vec::len),
                );
                let extensions = envelope
                    .get("extensions")
                    .and_then(Value::as_object)
                    .ok_or_else(exhausted)?;
                for extension in extensions.values() {
                    self.include_body_data(extension, maximum)?;
                }
                let row = value_geometry(envelope, maximum)?;
                self.include_envelope_row_data(&row)?;
            }
        }
        Ok(())
    }

    /// Projects a real retained envelope without custom scalar allocation.
    ///
    /// # Errors
    /// Refuses checked event or independent requested-storage exhaustion.
    pub(crate) fn include_envelope_data(
        &mut self,
        envelope: &Envelope,
        maximum: usize,
    ) -> Result<(), ProviderError> {
        self.include_body_data(&envelope.body, maximum)?;
        self.maximum_bindings = self.maximum_bindings.max(
            envelope
                .body
                .get("bindings")
                .and_then(Value::as_array)
                .map_or(0, Vec::len),
        );
        for extension in envelope.extensions.values() {
            self.include_body_data(extension, maximum)?;
        }
        let mut row = OriginalSerializationStorageProjection::new(maximum)?;
        row.add_object()?;
        // Exhaustive binding makes a new envelope field require quote review.
        let Envelope {
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
        } = envelope;
        macro_rules! field {
            ($name:literal, $value:expr) => {{
                row.add_field($name)?;
                row.add_value($value)?;
            }};
        }
        field!("protocol", protocol);
        field!("message", message);
        field!("session_id", session_id);
        field!("incarnation_id", incarnation_id);
        field!("node_id", node_id);
        field!("execution_owner_id", execution_owner_id);
        field!("capture_owner_id", capture_owner_id);
        field!("request_id", request_id);
        field!("operation_id", operation_id);
        row.add_field("sequence")?;
        let digits = sequence
            .get()
            .checked_ilog10()
            .map_or(1, |digits| digits as usize + 1);
        row.add_unescaped_ascii_extent(digits)?;
        field!("method", method);
        field!("body", body);
        field!("extensions", extensions);
        self.include_envelope_row_data(&row.finish(maximum)?)
    }

    fn include_body_data(
        &mut self,
        body: &impl serde::Serialize,
        maximum: usize,
    ) -> Result<(), ProviderError> {
        let row = value_geometry(body, maximum)?;
        self.maximum_body_encoded = self.maximum_body_encoded.max(row.maximum_encoded_bytes);
        self.maximum_body_nodes = self.maximum_body_nodes.max(row.serialized_value_nodes);
        self.maximum_body_sequence_elements = self
            .maximum_body_sequence_elements
            .max(row.sequence_elements);
        self.maximum_body_sequence_containers = self
            .maximum_body_sequence_containers
            .max(row.sequence_containers);
        self.maximum_body_canonical_pass = self
            .maximum_body_canonical_pass
            .max(serialization_transient(&row)?);
        self.maximum_body_dom = self
            .maximum_body_dom
            .max(row.projected_parser_requested_bytes);
        Ok(())
    }

    fn include_envelope_row_data(
        &mut self,
        row: &OriginalSerializationStorageData,
    ) -> Result<(), ProviderError> {
        self.maximum_envelope_encoded =
            self.maximum_envelope_encoded.max(row.maximum_encoded_bytes);
        self.maximum_envelope_pass = self
            .maximum_envelope_pass
            .max(serialization_transient(row)?);
        Ok(())
    }
}

/// Conjoins independently named cached-body, private proof and model windows.
///
/// # Errors
/// Refuses incomplete construction shapes, layout/arithmetical overflow or a
/// result greater than the separately admitted requested-storage ceiling.
pub(crate) fn source_history17_geometry_data(
    shapes: HistoricalAuth17Shapes,
    normalization: normalization::HistoricalAckNormalizationWindow17,
    manifest: manifest::HistoricalWorldManifestWindow17,
    model_encoded_extent: usize,
    native_selector_encoded_extent: usize,
    maximum: usize,
) -> Result<RestoredSettledSourceHistory17AuthGeometryData, ProviderError> {
    if shapes.maximum_body_encoded == 0
        || shapes.maximum_envelope_encoded == 0
        || model_encoded_extent == 0
        || native_selector_encoded_extent == 0
        || maximum == 0
    {
        return Err(exhausted());
    }
    let typed = layouts::typed_layouts_data()?;
    let arrays = Layout::from_size_align(
        typed.maximum_array_element_bytes,
        typed.maximum_array_element_alignment,
    )
    .map_err(|_| exhausted())?;
    let trees = Layout::from_size_align(
        typed.maximum_tree_node_bytes,
        typed.maximum_tree_node_alignment,
    )
    .map_err(|_| exhausted())?;

    // completed_pair keeps RequestBody while constructing ResponseShape, then
    // keeps the latter's raw result while independently decoding MethodResult.
    // Each concrete decode includes its own serde buffer and partial output.
    // Adding all three windows bounds that overlap without pretending that an
    // inline ResponseBody header pays for its recursive fields.
    let request = typed_decode_window(&shapes, typed)?;
    let response_shape = typed_decode_window(&shapes, typed)?;
    let method_result = typed_decode_window(&shapes, typed)?;
    // Admit response validation also builds/sorts independent expected binding
    // identities while request and response remain live. Bindings serialize a
    // subtree of the actual request, so one complete cached-body projection
    // bounds the single identity hash in progress, independently of its Vec.
    let expected_bindings = if shapes.maximum_bindings == 0 {
        0
    } else {
        let slots = add(mul(4, shapes.maximum_bindings)?, 4)?;
        let expected = mul(slots, size_of::<crucible_node_contract::HashRef>())?;
        let sort = mul(
            shapes.maximum_bindings,
            size_of::<crucible_node_contract::HashRef>(),
        )?;
        let hash_strings = sum(&["blake3-256".len(), "cnp.node-binding.v1".len(), 64])?;
        let returned = mul(shapes.maximum_bindings, add(mul(4, hash_strings)?, 3 * 8)?)?;
        sum(&[
            expected,
            sort,
            returned,
            shapes.maximum_body_canonical_pass,
            4096,
        ])?
    };
    let completed_pair = sum(&[request, response_shape, method_result, expected_bindings])?;
    // Commit also retains independently deserialized Prepare and Commit receipt
    // DTOs from the actual terminal extension Values. Their partial decoders
    // use the same observed-node/array roster, independently of the body DTOs.
    let prepare_receipt_decode = typed_decode_window(&shapes, typed)?;
    let commit_receipt_decode = typed_decode_window(&shapes, typed)?;
    let retained_receipts = sum(&[prepare_receipt_decode, commit_receipt_decode])?;

    // Assigned-envelope helpers own their normalized projection while json_hash
    // constructs another Value and canonical bank. The framing hash streams;
    // there is no additional payload-sized framed Vec to charge.
    let assigned = mul(2, shapes.maximum_envelope_pass)?;
    let returned_hash_strings = sum(&["blake3-256".len(), 128, 64])?;

    // These are the defining private crypto families, not inferred frame caps.
    // A request/context can coexist with its returned canonical bank and the
    // expected proof/receipt comparison. Receipt verification keeps the actual
    // bank while the expected bank is constructed.
    let transfer_request = mul(
        2,
        canonical_window(MAXIMUM_COMPLETE_RESTORE_TRANSFER_REQUEST_BYTES)?,
    )?;
    let transfer_context = canonical_window(MAXIMUM_COMPLETE_RESTORE_TRANSFER_CONTEXT_BYTES)?;
    let transfer_receipt = mul(
        2,
        canonical_window(MAXIMUM_COMPLETE_RESTORE_TRANSFER_RECEIPT_BYTES)?,
    )?;
    let transfer_proof = mul(
        2,
        canonical_window(MAXIMUM_COMPLETE_RESTORE_TRANSFER_PROOF_BYTES)?,
    )?;
    // Each of the two actual receipts is retained alongside the new expected
    // receipt. The defining structs have 8, 11 and 11 String/Bytes banks; their
    // canonical byte cap bounds aggregate decoded string/byte lengths. Include
    // geometric String requests and each nonempty minimum bank separately.
    let expected_receipt_backing = sum(&[
        mul(8, MAXIMUM_COMPLETE_RESTORE_TRANSFER_RECEIPT_BYTES)?,
        mul(8, 11)?,
        32, // the old zero-MAC buffer coexists while its replacement is built
    ])?;
    // Proof constructors return two Strings and two 32-byte Bytes banks while
    // the context bank is still live. This is independent returned DTO backing,
    // rather than parser/canonical or custom formatter scratch.
    let expected_proof_backing = sum(&[
        mul(8, MAXIMUM_COMPLETE_RESTORE_TRANSFER_PROOF_BYTES)?,
        mul(8, 4)?,
    ])?;
    let transfer = sum(&[
        transfer_request,
        transfer_context,
        transfer_receipt,
        transfer_proof,
        assigned,
        returned_hash_strings,
        retained_receipts,
        expected_receipt_backing,
        expected_proof_backing,
        canonical_window(maximum_complete_restore_held_evidence_bytes()?)?,
    ])?;
    // The native selector is independently retained and may disagree with a
    // smaller birth.selector before authentication refuses. Price both complete
    // projections; equality is not a construction-size assumption.
    let selector = normalization
        .selection_encoded_bytes
        .max(native_selector_encoded_extent);
    let ack = sum(&[
        normalization.requested_storage_bytes,
        mul(2, canonical_window(selector)?)?,
        canonical_window(MAXIMUM_CANONICAL_ACK_ADMISSION_CONTEXT_BYTES)?,
        canonical_window(MAXIMUM_CANONICAL_ACK_ADMISSION_PROOF_BYTES)?,
        expected_proof_backing,
        assigned,
    ])?;
    let activation_or_observation = sum(&[
        canonical_window(MAXIMUM_RESTORATION_ACTIVATION_ARTIFACT_BYTES)?,
        canonical_window(MAXIMUM_RESTORATION_OBSERVE_ARTIFACT_BYTES)?,
        assigned,
        returned_hash_strings,
        manifest.requested_storage_bytes,
    ])?;

    // Selection validation borrows the actual native selector. Its sorting and
    // participant checks clone Id/String banks; owner.identity additionally
    // builds its canonical projection. This full selector is retained inside
    // the real normalized birth input, independently of a supplied proof's cap.
    let selection = sum(&[canonical_window(selector)?, id_validation_clones(selector)?])?;
    let schemas = schema_work::native5_record_schema_factory_peak_data(maximum)?;

    // The selected native Control codec maps every modeled field from this
    // actual ProgramHistory view, including nested payload banks. Its extent is
    // used only to bound lexical occurrences in the defining JSON geometry;
    // no native retained-byte census is relabeled as transient credit.
    let model = canonical_window(model_encoded_extent)?;
    let capture = sum(&[
        model,
        canonical_window(MAXIMUM_RESTORED_SETTLED_CAPTURE_ARTIFACT_BYTES)?,
        assigned,
        returned_hash_strings,
    ])?;
    let private_peak = [
        ack,
        transfer,
        activation_or_observation,
        selection,
        schemas,
        capture,
    ]
    .into_iter()
    .max()
    .ok_or_else(exhausted)?;
    let transient = add(completed_pair, private_peak)?;
    let scratch = sum(&[
        counter_scratch_data(),
        normalization.declared_counter_scratch_bytes,
        manifest.declared_counter_scratch_bytes,
        schema_work::counter_scratch_data(),
    ])?;
    if add(transient, scratch)? > maximum {
        return Err(exhausted());
    }
    Ok(RestoredSettledSourceHistory17AuthGeometryData {
        transient,
        scratch,
        maximum_array_element: arrays,
        maximum_tree_node: trees,
    })
}

fn typed_decode_window(
    shapes: &HistoricalAuth17Shapes,
    typed: layouts::HistoricalAuth17TypedLayouts,
) -> Result<usize, ProviderError> {
    // Counts come from the actual immutable JSON bodies, not encoded bytes
    // multiplied by the largest DTO header. An actual array's children map to
    // the closed typed Vec roster. Serde's tagged-content map Vec additionally
    // has at most one key/value pair per actual logical node.
    let strings = sum(&[
        mul(8, shapes.maximum_body_encoded)?,
        mul(32, shapes.maximum_body_nodes)?,
    ])?;
    let array_slots = add(
        mul(4, shapes.maximum_body_sequence_elements)?,
        mul(8, shapes.maximum_body_sequence_containers)?,
    )?;
    let arrays = mul(array_slots, typed.maximum_array_element_bytes)?;
    let trees = mul(
        mul(2, shapes.maximum_body_nodes)?,
        typed.maximum_tree_node_bytes,
    )?;
    let typed_backing = sum(&[strings, arrays, trees])?;
    let serde_slots = mul(
        mul(8, shapes.maximum_body_nodes)?,
        typed.maximum_array_element_bytes,
    )?;
    let serde_boxes = mul(
        shapes.maximum_body_nodes,
        size_of::<serde::__private228::de::Content<'static>>(),
    )?;
    let serde_buffer = sum(&[strings, serde_slots, serde_boxes])?;
    sum(&[
        shapes.maximum_body_canonical_pass,
        shapes.maximum_body_dom,
        typed_backing,
        serde_buffer,
    ])
}

fn canonical_window(encoded: usize) -> Result<usize, ProviderError> {
    let row = original_json_value_storage_extent_data(encoded)?;
    // Actual native private bounded Bytes can format before serialized_credit
    // visits their strings. Fourfold requested String growth plus8 covers one
    // such formatter; supplied Source formatters remain its separate span row.
    sum(&[
        row.value_dom_requested_bytes,
        row.canonical_work_requested_bytes,
        row.canonical_output_requested_bytes,
        mul(4, encoded)?,
        8,
    ])
}

fn id_validation_clones(encoded: usize) -> Result<usize, ProviderError> {
    let row = original_json_value_storage_extent_data(encoded)?;
    sum(&[
        mul(8, row.maximum_decoded_string_bytes)?,
        mul(32, row.maximum_value_nodes)?,
        mul(
            mul(8, row.maximum_value_nodes)?,
            size_of::<crucible_node_contract::Id>(),
        )?,
    ])
}

fn value_geometry(
    value: &impl serde::Serialize,
    maximum: usize,
) -> Result<OriginalSerializationStorageData, ProviderError> {
    // Only already-owned JSON Values/maps enter this helper. Envelope's U64 is
    // handled by the closed projection above; no Bytes formatter is invoked.
    actual_serialization_storage_data(value, RetainedProtocolMetadataFacts::default(), maximum)
}

fn serialization_transient(row: &OriginalSerializationStorageData) -> Result<usize, ProviderError> {
    sum(&[
        row.dom_and_canonical_scratch_bytes,
        row.projected_parser_requested_bytes,
        row.canonical_output_requested_bytes,
        row.serializer_temporary_requested_bytes,
    ])
}

/// Names this counter's actual fixed visitor, root and layout work views.
pub(crate) fn counter_scratch_data() -> usize {
    size_of::<RestoredSettledSourceHistory17AuthGeometryData>()
        + size_of::<HistoricalAuth17Shapes>()
        + size_of::<crate::protocol_snapshot::native_wholegraph17::NativeCurrentGraph17RootSpans<'static>>()
        + size_of::<[crate::protocol_snapshot::owned11::typed::Fields<'static>; 3]>()
        + size_of::<Result<&'static [u8], ProviderError>>()
        + size_of::<[usize; 6]>()
        + size_of::<[Option<&Envelope>; 6]>()
        + size_of::<std::array::IntoIter<Option<&Envelope>, 6>>()
        + size_of::<[(&str, usize); 3]>()
        + size_of::<[usize; 7]>()
        + size_of::<std::array::IntoIter<usize, 6>>()
        + size_of::<Layout>() * 2
        + size_of::<Result<RestoredSettledSourceHistory17AuthGeometryData, ProviderError>>()
        + size_of::<crate::reference_packet::service::ack_emitter::PacketCanonicalAckAdmissionProof>()
        + size_of::<crate::bodies::BeginArguments>()
        + size_of::<crate::bodies::MethodResult>()
        + size_of::<crate::reference_packet::service::complete_restore::transfer::PacketCompleteRestoreCommitReceipt>()
        + size_of::<crate::reference_packet::service::complete_restore::transfer::PacketCompleteRestorePrepareReceipt>()
        + size_of::<crate::reference_packet::service::complete_restore::transfer::PacketCompleteRestoreTransferProof>()
        + super::historical_auth17_counter_scratch_data()
        + original_serialization_counter_scratch_data()
        + crate::reference_packet::service::complete_restore::maximum_complete_restore_held_evidence_counter_scratch_data()
        + original_json_value_storage_extent_counter_scratch_data()
        + layouts::counter_scratch_data()
        + normalization::counter_scratch_data()
        + manifest::counter_scratch_data()
}

fn sum(terms: &[usize]) -> Result<usize, ProviderError> {
    terms.iter().try_fold(0, |total, next| add(total, *next))
}

fn add(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_add(right).ok_or_else(exhausted)
}

fn mul(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_mul(right).ok_or_else(exhausted)
}

fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("native17 historical authentication construction")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{MessageKind, Method, Nullable};
    use crate::retained_metadata::{MetadataObserver, requested_metadata_backing_storage_data};
    use crucible_node_contract::{Id, U64, canonical};
    use serde_json::json;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn original() -> Result<Envelope, Box<dyn std::error::Error>> {
        Ok(Envelope {
            protocol: "CNP/1".to_owned(),
            message: MessageKind::Request,
            session_id: Nullable(Some(Id::new("session")?)),
            incarnation_id: Nullable(Some(Id::new("incarnation")?)),
            node_id: Nullable(Some(Id::new("node")?)),
            execution_owner_id: Nullable(Some(Id::new("owner")?)),
            capture_owner_id: Nullable(None),
            request_id: Nullable(Some(Id::new("observe")?)),
            operation_id: Nullable(None),
            sequence: U64::new(u64::MAX),
            method: Method::Observe,
            body: serde_json::from_value(json!({
                "binding_hash": canonical::hash("cnp.owner-binding.v1", b"owner")?,
                "owner_generation":"1", "after_observation_sequence":"0",
                "maximum_items":"1", "extensions":{},
            }))?,
            extensions: Default::default(),
        })
    }

    #[test]
    fn closed_envelope_projection_covers_actual_maximum_decimal_and_escaped_fields() -> TestResult {
        let mut envelope = original()?;
        envelope
            .extensions
            .insert("escaped".to_owned(), json!(["\"\n", "𝄞", "plain"]));
        let actual = canonical::canonical_json(&serde_json::to_value(&envelope)?)?;
        let mut shapes = HistoricalAuth17Shapes::default();
        shapes.include_envelope_data(&envelope, usize::MAX)?;

        assert!(actual.len() <= shapes.maximum_envelope_encoded);
        assert!(actual.len() <= shapes.maximum_envelope_pass);
        assert!(shapes.maximum_body_sequence_elements >= 3);
        Ok(())
    }

    #[test]
    fn actual_private_body_decode_fits_its_independent_concrete_backing_bound() -> TestResult {
        let mut envelope = original()?;
        envelope
            .body
            .get_mut("extensions")
            .and_then(Value::as_object_mut)
            .ok_or("missing extensions")?
            .insert(
                "actual-array".to_owned(),
                json!([{"first":"long\\escaped\"value"}, {"second":"𝄞"}]),
            );
        let mut shapes = HistoricalAuth17Shapes::default();
        shapes.include_envelope_data(&envelope, usize::MAX)?;
        let quote = typed_decode_window(&shapes, layouts::typed_layouts_data()?)?;
        let request = crate::bodies::decode_request(Method::Observe, &envelope.body)?;
        let crate::bodies::RequestBody::Observe(body) = request else {
            return Err("wrong actual decoder variant".into());
        };
        let mut observer = MetadataObserver::new();
        <crate::bodies::ObserveRequest as
            crate::protocol_snapshot::restored_settled17::current_contracts::CurrentContract17>
            ::observe_current(&body, &mut observer)?;
        let actual = requested_metadata_backing_storage_data(&observer.finish())?;

        assert!(actual > 0);
        assert!(quote >= actual);
        assert!(shapes.maximum_body_sequence_elements >= 2);
        Ok(())
    }

    #[test]
    fn complete_private_row_refuses_one_short_without_renewing_its_ceiling() -> TestResult {
        let envelope = original()?;
        let make_shapes = || -> Result<HistoricalAuth17Shapes, ProviderError> {
            let mut shapes = HistoricalAuth17Shapes::default();
            shapes.include_envelope_data(&envelope, usize::MAX)?;
            Ok(shapes)
        };
        let normalized = normalization::HistoricalAckNormalizationWindow17 {
            requested_storage_bytes: 4096,
            declared_counter_scratch_bytes: normalization::counter_scratch_data(),
            selection_encoded_bytes: 256,
        };
        let manifest = manifest::HistoricalWorldManifestWindow17 {
            requested_storage_bytes: 4096,
            declared_counter_scratch_bytes: manifest::counter_scratch_data(),
        };
        let row = source_history17_geometry_data(
            make_shapes()?,
            normalized,
            manifest,
            512,
            256,
            usize::MAX,
        )?;
        let total = row
            .maximum_simultaneous_transient_bytes_data()
            .checked_add(row.declared_counter_scratch_bytes_data())
            .ok_or("overflow")?;

        assert_eq!(
            row,
            source_history17_geometry_data(make_shapes()?, normalized, manifest, 512, 256, total)?
        );
        assert!(
            source_history17_geometry_data(
                make_shapes()?,
                normalized,
                manifest,
                512,
                256,
                total - 1
            )
            .is_err()
        );
        assert!(
            source_history17_geometry_data(
                make_shapes()?,
                normalized,
                manifest,
                usize::MAX,
                256,
                usize::MAX
            )
            .is_err()
        );
        assert!(
            source_history17_geometry_data(
                HistoricalAuth17Shapes::default(),
                normalized,
                manifest,
                512,
                256,
                total
            )
            .is_err()
        );
        assert!(
            row.maximum_typed_element_layout_data()
                .align()
                .is_power_of_two()
        );
        assert!(
            row.maximum_typed_tree_node_layout_data()
                .align()
                .is_power_of_two()
        );
        Ok(())
    }
}

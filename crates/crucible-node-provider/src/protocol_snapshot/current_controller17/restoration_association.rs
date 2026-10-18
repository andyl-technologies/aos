//! Joins the three actual completed restoration SDK originals to their journals.
//!
//! Typed pairs are temporary historical validation DATA. The native checker
//! borrows these exact terminals and compares its own original wire banks; it
//! does not reconstruct a live Controller, SDK attempt, deadline or authority.

use super::*;
use crate::envelope::Method;
use crate::reference_packet::service::complete_restore::transfer::PacketCompleteRestoreTransferPhase;
use crate::retained_metadata::serialization_storage::{
    OriginalSerializationStorageData, actual_serialization_storage_data,
    original_serialization_counter_scratch_data,
};

struct Pair17 {
    original: Envelope,
    terminal: Envelope,
}

/// Retains the actual completed ACK, Prepare and Commit SDK pair correspondence.
///
/// The enclosing caller admits all three typed pairs before construction and
/// retains the original Controller raw/DOM root on refusal. This result has no
/// live conversion and does not authenticate the native MAC chain on its own.
pub struct ValidatedHistoricalRestorationAssociation17 {
    ack: Pair17,
    prepare: Pair17,
    commit: Pair17,
}

impl ValidatedHistoricalRestorationAssociation17 {
    /// Checks completed once tuples, canonical banks and exact journal pairs.
    ///
    /// # Errors
    /// Refuses another schema/method, incomplete state, absent original literal
    /// slot, a changed canonical bank or journal, or a noncompleted response.
    pub fn validate_data(
        controller: &ValidatedControllerSettledHistory17,
    ) -> Result<Self, ProviderError> {
        let root = controller.parts_data()?.as_object().ok_or_else(invalid)?;
        let ack = pair_data(field(root, "ack_admit")?, None, controller)?;
        let prepare = pair_data(
            field(root, "restore_prepare")?,
            Some(PacketCompleteRestoreTransferPhase::Prepare),
            controller,
        )?;
        let commit = pair_data(
            field(root, "restore_commit")?,
            Some(PacketCompleteRestoreTransferPhase::Commit),
            controller,
        )?;
        if ack.original.sequence >= prepare.original.sequence
            || prepare.original.sequence >= commit.original.sequence
        {
            return Err(invalid());
        }
        Ok(Self {
            ack,
            prepare,
            commit,
        })
    }

    /// Borrows the real acknowledged Admit original and completed terminal.
    pub fn ack_pair_data(&self) -> (&Envelope, &Envelope) {
        (&self.ack.original, &self.ack.terminal)
    }

    /// Borrows the real Prepare original and completed terminal.
    pub fn prepare_pair_data(&self) -> (&Envelope, &Envelope) {
        (&self.prepare.original, &self.prepare.terminal)
    }

    /// Borrows the real Commit original and completed terminal.
    pub fn commit_pair_data(&self) -> (&Envelope, &Envelope) {
        (&self.commit.original, &self.commit.terminal)
    }

    /// Observes the actual six typed envelopes if a caller retains this cache.
    ///
    /// # Errors
    /// Refuses exhaustive metadata traversal or checked counter overflow.
    pub fn retained_metadata_data(
        &self,
    ) -> Result<crate::retained_metadata::RetainedProtocolMetadataFacts, ProviderError> {
        let mut observer = crate::retained_metadata::MetadataObserver::new();
        for pair in [&self.ack, &self.prepare, &self.commit] {
            observer.observe(&pair.original)?;
            observer.observe(&pair.terminal)?;
        }
        Ok(observer.finish())
    }
}

fn pair_data(
    value: &Value,
    phase: Option<PacketCompleteRestoreTransferPhase>,
    controller: &ValidatedControllerSettledHistory17,
) -> Result<Pair17, ProviderError> {
    let restored = phase.is_some();
    let method = if restored {
        Method::Begin
    } else {
        Method::Admit
    };
    let row = tuple(value, if restored { 11 } else { 8 })?;
    text(
        &row[0],
        if restored {
            "source-private.sdk-assigned-restore-current/17"
        } else {
            "source-private.sdk-assigned-admit-current/17"
        },
    )?;
    text(&row[5], "complete")?;
    text(&row[7], "historical-nonrenewable-operational-cut")?;
    number(&row[4])?;
    let original: Envelope = read(&row[1])?;
    let terminal: Envelope = read(&row[6])?;
    original.validate()?;
    terminal.validate()?;
    if original.method != method {
        return Err(invalid());
    }
    controller.authenticate_historical_controller_pair17_data(&original, &terminal)?;
    let request = crate::bodies::decode_request(method, &original.body)?;
    if let Some(phase) = phase {
        // Both real transfer phases use Begin(PrepareRestore); their selected
        // request/proof/receipt extensions distinguish the exact phase.
        if !matches!(&request, RequestBody::Begin(body) if body.kind == BeginKind::PrepareRestore)
            || !original.extensions.contains_key(phase.request_extension())
            || !original.extensions.contains_key(phase.proof_extension())
            || !terminal.extensions.contains_key(phase.receipt_extension())
        {
            return Err(invalid());
        }
    }
    let response = crate::bodies::decode_response(&request, &terminal.body)?;
    if !matches!(
        &response.shape,
        ResponseShape::Completed {
            operation_state: OperationState::Completed,
            ..
        }
    ) {
        return Err(invalid());
    }
    let encoded =
        serde_json::to_vec(&row[2]).map_err(crucible_node_contract::ContractError::from)?;
    let bank = super::super::compact_bytes::ValidatedCompactBytes::validate(
        &encoded,
        encoded.len(),
        usize::MAX,
    )?;
    if u64::try_from(bank.decoded_length()).map_err(|_| invalid())? > number(&row[3])? {
        return Err(invalid());
    }
    let mut actual = Vec::new();
    actual
        .try_reserve_exact(bank.decoded_length())
        .map_err(|_| invalid())?;
    bank.fill_preowned(&mut actual)?;
    if actual
        != crucible_node_contract::canonical::canonical_json(
            &serde_json::to_value(&original)
                .map_err(crucible_node_contract::ContractError::from)?,
        )?
    {
        return Err(invalid());
    }
    Ok(Pair17 { original, terminal })
}

/// Quotes all three pair validators independently of parent raw/DOM retention.
///
/// # Errors
/// Refuses zero geometry or checked arithmetic beyond representable storage.
pub fn historical_restoration_association17_validation_transient_bytes_data(
    maximum_encoded: usize,
) -> Result<usize, ProviderError> {
    super::historical_restored_suffix_pair_validation_transient_bytes_data(maximum_encoded)?
        .checked_mul(3)
        .and_then(|bytes| {
            bytes.checked_add(historical_restoration_association17_counter_scratch_data())
        })
        .ok_or_else(invalid)
}

/// Names the defining typed pair, borrowed loan and compact bank views.
pub fn historical_restoration_association17_counter_scratch_data() -> usize {
    size_of::<ValidatedHistoricalRestorationAssociation17>()
        + size_of::<Option<PacketCompleteRestoreTransferPhase>>()
        + size_of::<PacketCompleteRestoreTransferPhase>()
        + size_of::<Method>()
        + size_of::<RequestBody>()
        + size_of::<Pair17>()
        + size_of::<&Pair17>()
        + size_of::<(&Envelope, &Envelope)>()
        + size_of::<[&Pair17; 3]>()
        + size_of::<std::array::IntoIter<&Pair17, 3>>()
        + size_of::<Result<ValidatedHistoricalRestorationAssociation17, ProviderError>>()
        + size_of::<Result<Pair17, ProviderError>>()
        + size_of::<super::super::compact_bytes::ValidatedCompactBytes<'static>>()
        + size_of::<
            Result<super::super::compact_bytes::ValidatedCompactBytes<'static>, ProviderError>,
        >()
        + super::historical_restored_suffix_pair_counter_scratch_data()
}

/// Quotes the actual three selected SDK tuples without constructing their pairs.
///
/// Only the completed ACK, Prepare and Commit originals, terminals, compact
/// original banks and corresponding journal identities contribute. Unrelated
/// Controller uploads, immutable ancestry and other SDK history stay outside
/// this independent validation row. The caller retains and funds those owners.
///
/// Serialization walks borrowed JSON values only; it does not run a typed SDK
/// decoder, serialize a typed U64/Bytes value or grant validation admission.
///
/// # Errors
/// Refuses unavailable Controller DATA, incomplete selected tuples, missing
/// selected request/response fields, arithmetic overflow or the supplied bound.
pub fn historical_restoration_association17_validation_transient_for_controller_data(
    controller: &ValidatedControllerSettledHistory17,
    maximum_requested_bytes: usize,
) -> Result<usize, ProviderError> {
    selected_association_geometry_data(
        controller.parts_data()?.as_object().ok_or_else(invalid)?,
        maximum_requested_bytes,
    )
}

// Serde 1.0.228's internally tagged ResponseShape decoder buffers this
// private enum and map-entry pair. The versioned path intentionally fails to
// compile when that pinned implementation changes instead of quoting Value.
type TaggedContent17 = serde::__private228::de::Content<'static>;
type TaggedEntry17 = (TaggedContent17, TaggedContent17);

/// Names fixed selected-association controls before its borrowed event walk.
///
/// Source pre-admits this nonallocating quote before invoking the selected
/// geometry helper. Its returned validation demand includes the same term;
/// independent conservative duplication by the enclosing owner is permitted.
pub fn historical_restoration_association17_selected_counter_scratch_data() -> usize {
    historical_restoration_association17_counter_scratch_data()
        + size_of::<AssociationGeometry17>()
        + size_of::<RequestHashProjection17<'static>>()
        + original_serialization_counter_scratch_data()
        + size_of::<TaggedContent17>()
        + size_of::<TaggedEntry17>()
        + size_of::<Vec<TaggedContent17>>()
        + size_of::<Vec<TaggedEntry17>>()
        + size_of::<std::vec::IntoIter<TaggedContent17>>()
        + size_of::<std::vec::IntoIter<TaggedEntry17>>()
        + size_of::<serde::__private228::de::ContentVisitor<'static>>()
        + size_of::<serde::__private228::de::ContentDeserializer<'static, serde_json::Error>>()
}

struct AssociationGeometry17 {
    requested: usize,
    maximum: usize,
}

impl AssociationGeometry17 {
    fn add(&mut self, bytes: usize) -> Result<(), ProviderError> {
        self.requested = self
            .requested
            .checked_add(bytes)
            .filter(|bytes| *bytes <= self.maximum)
            .ok_or_else(geometry_exhausted)?;
        Ok(())
    }

    fn serialization(
        &self,
        value: &impl serde::Serialize,
    ) -> Result<OriginalSerializationStorageData, ProviderError> {
        actual_serialization_storage_data(
            value,
            crate::retained_metadata::RetainedProtocolMetadataFacts::default(),
            self.maximum,
        )
    }

    fn construction(&mut self, value: &impl serde::Serialize) -> Result<(), ProviderError> {
        self.add(self.serialization(value)?.requested_total()?)
    }

    fn envelope_backing(&mut self, value: &Value) -> Result<(), ProviderError> {
        // Envelope's variable children are String/Id and Map<String, Value>.
        // The event visitor prices those exact string/array/object occurrences;
        // no Envelope-sized slot is multiplied by the entire JSON node count.
        self.add(self.serialization(value)?.retained_value_backing_bytes)
    }

    fn vector<T>(&mut self, value: &Value) -> Result<(), ProviderError> {
        let count = value.as_array().ok_or_else(invalid)?.len();
        if count == 0 {
            return Ok(());
        }
        // Deserialize/collect may grow a Vec rather than reserve its final len.
        // Four final-length slots plus the minimum bank dominate cumulative
        // doubling requests for this concrete element layout.
        let bytes = count
            .checked_mul(4)
            .and_then(|slots| slots.checked_add(4))
            .and_then(|slots| slots.checked_mul(size_of::<T>()))
            .ok_or_else(geometry_exhausted)?;
        self.add(bytes)
    }

    fn hash_output(&mut self, domain: &str) -> Result<(), ProviderError> {
        // canonical::hash owns these three strings, independently of its input
        // DOM and output bank. Blake3-256 uses exactly 64 lowercase hex bytes.
        self.add("blake3-256".len() + domain.len() + 64)
    }
}

fn geometry_exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("selected restoration association validation")
}

fn selected_association_geometry_data(
    root: &Map<String, Value>,
    maximum: usize,
) -> Result<usize, ProviderError> {
    let mut geometry = AssociationGeometry17 {
        requested: 0,
        maximum,
    };
    geometry.add(historical_restoration_association17_selected_counter_scratch_data())?;
    for (name, restored) in [
        ("ack_admit", false),
        ("restore_prepare", true),
        ("restore_commit", true),
    ] {
        selected_pair_geometry_data(field(root, name)?, root, restored, &mut geometry)?;
    }
    Ok(geometry.requested)
}

fn selected_pair_geometry_data(
    value: &Value,
    root: &Map<String, Value>,
    restored: bool,
    geometry: &mut AssociationGeometry17,
) -> Result<(), ProviderError> {
    let row = tuple(value, if restored { 11 } else { 8 })?;
    text(
        &row[0],
        if restored {
            "source-private.sdk-assigned-restore-current/17"
        } else {
            "source-private.sdk-assigned-admit-current/17"
        },
    )?;
    text(&row[5], "complete")?;
    text(&row[7], "historical-nonrenewable-operational-cut")?;
    let original = row[1].as_object().ok_or_else(invalid)?;
    let terminal = row[6].as_object().ok_or_else(invalid)?;
    text(
        field(original, "method")?,
        if restored { "begin" } else { "admit" },
    )?;
    let body = field(original, "body")?.as_object().ok_or_else(invalid)?;
    let response = field(terminal, "body")?.as_object().ok_or_else(invalid)?;
    text(field(response, "status")?, "completed")?;
    let result = field(response, "result")?.as_object().ok_or_else(invalid)?;

    // All six final envelopes can coexist. Account their backing cumulatively,
    // then the distinct journal-comparison Values and request-hash projection.
    geometry.envelope_backing(&row[1])?;
    geometry.envelope_backing(&row[6])?;
    geometry.construction(&row[1])?;
    geometry.construction(&row[6])?;
    geometry.construction(&RequestHashProjection17(original))?;
    geometry.hash_output("cnp.request.v1")?;
    let custody = tuple(field(root, "custody")?, 6)?;
    let journal = custody[3].as_object().ok_or_else(invalid)?;
    let request_id = field(original, "request_id")?
        .as_str()
        .ok_or_else(invalid)?;
    let entry = journal
        .get(request_id)
        .and_then(Value::as_object)
        .ok_or_else(invalid)?;
    geometry.envelope_backing(field(entry, "identity")?)?;

    // bodies::object retains canonical bytes while its independent cloned
    // Value is consumed into the typed request or response. These separate
    // event quotes include both banks and the response's retained raw result.
    geometry.construction(&field(original, "body")?)?;
    geometry.construction(&field(terminal, "body")?)?;
    tagged_response_content_geometry_data(field(terminal, "body")?, geometry)?;
    geometry.construction(&field(response, "result")?)?;
    if restored {
        text(field(body, "kind")?, "prepare_restore")?;
        let arguments = field(body, "arguments")?.as_object().ok_or_else(invalid)?;
        geometry.construction(&field(body, "arguments")?)?;
        geometry.vector::<Id>(field(arguments, "destination_owner_ids")?)?;
        geometry.vector::<Id>(field(result, "staged_owner_ids")?)?;
        // The later response-identity check decodes the same actual arguments
        // again while the typed request and completed response remain live.
        geometry.construction(&field(body, "arguments")?)?;
        geometry.vector::<Id>(field(arguments, "destination_owner_ids")?)?;
        geometry.add(size_of::<PrepareRestoreArguments>())?;
        geometry.add(size_of::<PrepareRestoreResult>())?;
    } else {
        admit_geometry_data(body, result, geometry)?;
    }

    // pair_data separately serializes compact JSON, fills a new raw byte bank,
    // and builds the original's canonical Value/output for complete equality.
    let compact = tuple(&row[2], 3)?;
    text(&compact[0], "source-private.compact-bytes/7")?;
    let decoded = usize::try_from(number(&compact[1])?).map_err(|_| geometry_exhausted())?;
    if u64::try_from(decoded).map_err(|_| geometry_exhausted())? > number(&row[3])? {
        return Err(invalid());
    }
    geometry.construction(&row[2])?;
    geometry.add(decoded)?;
    geometry.construction(&row[1])
}

/// Quotes the separate serde buffer used by internally tagged ResponseShape.
fn tagged_response_content_geometry_data(
    response: &Value,
    geometry: &mut AssociationGeometry17,
) -> Result<(), ProviderError> {
    let events = geometry.serialization(response)?;
    let sequence_slots = events
        .sequence_elements
        .checked_mul(4)
        .and_then(|slots| {
            events
                .sequence_containers
                .checked_mul(4)
                .and_then(|minimums| slots.checked_add(minimums))
        })
        .and_then(|slots| slots.checked_mul(size_of::<TaggedContent17>()))
        .ok_or_else(geometry_exhausted)?;
    // Every map entry contributes JSON key/value nodes; every object is one
    // backing record. These event bounds include the top tagged map, whose
    // cautious size hint may reserve the status entry before omitting its tag.
    let map_slots = events
        .serialized_value_nodes
        .checked_mul(4)
        .and_then(|slots| {
            events
                .serialized_capacity_records
                .checked_mul(4)
                .and_then(|minimums| slots.checked_add(minimums))
        })
        .and_then(|slots| slots.checked_mul(size_of::<TaggedEntry17>()))
        .ok_or_else(geometry_exhausted)?;
    geometry.add(sequence_slots)?;
    geometry.add(map_slots)?;
    tagged_string_backing_data(response, geometry)
}

fn tagged_string_backing_data(
    value: &Value,
    geometry: &mut AssociationGeometry17,
) -> Result<(), ProviderError> {
    fn string(bytes: usize, geometry: &mut AssociationGeometry17) -> Result<(), ProviderError> {
        geometry.add(
            bytes
                .checked_mul(4)
                .and_then(|n| n.checked_add(32))
                .ok_or_else(geometry_exhausted)?,
        )
    }

    match value {
        Value::String(value) => string(value.len(), geometry),
        Value::Array(values) => {
            for value in values {
                tagged_string_backing_data(value, geometry)?;
            }
            Ok(())
        }
        Value::Object(values) => {
            for (key, value) in values {
                string(key.len(), geometry)?;
                tagged_string_backing_data(value, geometry)?;
            }
            Ok(())
        }
        // serde_json::Value's deserialize_any produces JSON strings/sequences,
        // never Content::ByteBuf/Some/Newtype. Numeric byte arrays use the
        // independent Content sequence bank above, not an unpriced Bytes bank.
        Value::Null | Value::Bool(_) | Value::Number(_) => Ok(()),
    }
}

struct RequestHashProjection17<'a>(&'a Map<String, Value>);

impl serde::Serialize for RequestHashProjection17<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(None)?;
        for (name, value) in self.0 {
            if name != "message" && name != "sequence" {
                map.serialize_entry(name, value)?;
            }
        }
        map.serialize_entry("request_origin", "controller")?;
        map.end()
    }
}

fn admit_geometry_data(
    request: &Map<String, Value>,
    result: &Map<String, Value>,
    geometry: &mut AssociationGeometry17,
) -> Result<(), ProviderError> {
    use crucible_node_contract::{ArtifactIdentity, FacetSelection, NodeBinding, SchemaRef};
    let bindings = field(request, "bindings")?;
    geometry.vector::<NodeBinding>(bindings)?;
    geometry.vector::<HashRef>(field(result, "accepted_binding_hashes")?)?;
    // validate_result_identity constructs and sorts an independent expected
    // identity vector. Its backing and stable-sort staging coexist with result.
    geometry.vector::<HashRef>(bindings)?;
    geometry.add(
        bindings
            .as_array()
            .ok_or_else(invalid)?
            .len()
            .checked_mul(size_of::<HashRef>())
            .ok_or_else(geometry_exhausted)?,
    )?;
    for binding in bindings.as_array().ok_or_else(invalid)? {
        let binding_fields = binding.as_object().ok_or_else(invalid)?;
        let compatibility = field(binding_fields, "compatibility")?
            .as_object()
            .ok_or_else(invalid)?;
        let implementation = field(compatibility, "implementation")?
            .as_object()
            .ok_or_else(invalid)?;
        geometry.vector::<ArtifactIdentity>(field(implementation, "artifacts")?)?;
        geometry.vector::<ContentRef>(field(implementation, "model_definitions")?)?;
        geometry.vector::<SchemaRef>(field(implementation, "formats")?)?;
        geometry.vector::<ContentRef>(field(compatibility, "qualification_refs")?)?;
        let operating = field(compatibility, "operating_contract")?
            .as_object()
            .ok_or_else(invalid)?;
        geometry.vector::<FacetSelection>(field(operating, "facets")?)?;
        for name in ["execution_owner", "capture_owner"] {
            let owner = field(compatibility, name)?
                .as_object()
                .ok_or_else(invalid)?;
            geometry.vector::<Id>(field(owner, "participant_ids")?)?;
            geometry.vector::<Id>(field(owner, "state_domain_ids")?)?;
        }
        // NodeBinding::identity serializes compatibility; the complete binding
        // events conservatively include that exact subtree. Its
        // validation and HashRef result do not borrow the request's DOM bank.
        geometry.construction(binding)?;
        geometry.hash_output("cnp.node-binding.v1")?;
    }
    Ok(())
}

#[cfg(test)]
mod selected_geometry_tests {
    use super::*;
    use crate::envelope::{MessageKind, RequestOrigin};
    use crucible_node_contract::canonical;
    use serde::de::DeserializeSeed;
    use serde_json::json;

    fn fixture(selected_text: usize) -> (Map<String, Value>, usize) {
        let reference = canonical::content_ref(b"restore fixture", "application/json").unwrap();
        let world = canonical::hash("cnp.world-binding.v1", b"world").unwrap();
        let owner = canonical::hash("cnp.owner-binding.v1", b"owner").unwrap();
        let mut root = Map::new();
        let mut journal = Map::new();
        let mut retained = 0usize;
        for (index, name) in ["ack_admit", "restore_prepare", "restore_commit"]
            .into_iter()
            .enumerate()
        {
            let restored = index != 0;
            let mut original = crate::envelope::tests::request();
            original.method = if restored {
                Method::Begin
            } else {
                Method::Admit
            };
            original.request_id.0 = Some(Id::new(name).unwrap());
            original.sequence = U64::new(index as u64 * 2 + 1);
            original
                .extensions
                .insert("fixture".into(), Value::String("s".repeat(selected_text)));
            let result;
            if restored {
                let arguments = PrepareRestoreArguments {
                    transaction_id: Id::new("transaction").unwrap(),
                    capture_manifest: reference.clone(),
                    expected_world_binding_hash: world.clone(),
                    expected_owner_binding_hash: owner.clone(),
                    destination_owner_ids: vec![Id::new("owner").unwrap()],
                };
                let body = BeginRequest {
                    kind: BeginKind::PrepareRestore,
                    binding_hash: owner.clone(),
                    owner_generation: U64::new(1),
                    activation_id: crate::envelope::Nullable(None),
                    world_generation: U64::new(1),
                    arguments: serde_json::to_value(arguments)
                        .unwrap()
                        .as_object()
                        .unwrap()
                        .clone(),
                    extensions: Default::default(),
                };
                original.body = serde_json::to_value(body)
                    .unwrap()
                    .as_object()
                    .unwrap()
                    .clone();
                result = serde_json::to_value(PrepareRestoreResult {
                    transaction_id: Id::new("transaction").unwrap(),
                    prepared_token: Id::new("prepared").unwrap(),
                    world_binding_hash: world.clone(),
                    owner_binding_hash: owner.clone(),
                    staged_owner_ids: vec![Id::new("owner").unwrap()],
                    closed_gate_receipt: reference.clone(),
                    validated_manifest: reference.clone(),
                })
                .unwrap();
            } else {
                original.body = serde_json::to_value(AdmitRequest {
                    bindings: Vec::new(),
                    world_binding_hash: world.clone(),
                    admission_receipt: reference.clone(),
                    extensions: Default::default(),
                })
                .unwrap()
                .as_object()
                .unwrap()
                .clone();
                result = serde_json::to_value(AdmitResult {
                    accepted_binding_hashes: Vec::new(),
                    admission_id: Id::new("admission").unwrap(),
                })
                .unwrap();
            }
            let mut terminal = original.clone();
            terminal.message = MessageKind::Response;
            terminal.sequence = U64::new(index as u64 * 2 + 2);
            terminal.body = json!({
                "status":"completed", "operation_state":"completed",
                "result":result, "extensions":{},
            })
            .as_object()
            .unwrap()
            .clone();
            let request = crate::bodies::decode_request(original.method, &original.body).unwrap();
            let response = crate::bodies::decode_response(&request, &terminal.body).unwrap();
            assert!(matches!(response.shape, ResponseShape::Completed { .. }));
            let original_value = serde_json::to_value(&original).unwrap();
            let terminal_value = serde_json::to_value(&terminal).unwrap();
            let literal = canonical::canonical_json(&original_value).unwrap();
            let compact = serde_json::to_value(
                super::super::super::compact_bytes::BorrowedCompactBytes::new(&literal),
            )
            .unwrap();
            journal.insert(
                name.into(),
                json!({
                    "request":original_value, "response":terminal_value,
                    "identity":original.request_hash(RequestOrigin::Controller).unwrap(),
                }),
            );
            let mut row = vec![
                json!(if restored {
                    "source-private.sdk-assigned-restore-current/17"
                } else {
                    "source-private.sdk-assigned-admit-current/17"
                }),
                original_value,
                compact,
                json!(literal.len()),
                json!(index * 2 + 2),
                json!("complete"),
                terminal_value,
                json!("historical-nonrenewable-operational-cut"),
            ];
            if restored {
                row.extend([Value::Null, Value::Null, Value::Null]);
            }
            root.insert(name.into(), Value::Array(row));
            let mut observer = crate::retained_metadata::MetadataObserver::new();
            observer.observe(&original).unwrap();
            observer.observe(&terminal).unwrap();
            retained += crate::retained_metadata::requested_metadata_backing_storage_data(
                &observer.finish(),
            )
            .unwrap();
            retained += literal.len();
        }
        root.insert(
            "custody".into(),
            json!([null, null, null, journal, null, null]),
        );
        (root, retained)
    }

    #[test]
    fn selected_typed_pairs_fit_their_own_quote_and_reject_one_short() {
        let (root, observed_backing) = fixture(31);
        let requested = selected_association_geometry_data(&root, 256 * 1024 * 1024).unwrap();
        assert!(requested >= observed_backing);
        assert_eq!(
            selected_association_geometry_data(&root, requested).unwrap(),
            requested
        );
        assert!(selected_association_geometry_data(&root, requested - 1).is_err());
    }

    #[test]
    fn unrelated_controller_history_does_not_price_selected_association_work() {
        let (mut root, _) = fixture(0);
        let initial = selected_association_geometry_data(&root, 256 * 1024 * 1024).unwrap();
        root.insert("uploads".into(), json!(["unrelated".repeat(131072)]));
        assert_eq!(
            selected_association_geometry_data(&root, initial).unwrap(),
            initial
        );
        let (larger, _) = fixture(4096);
        assert!(selected_association_geometry_data(&larger, 256 * 1024 * 1024).unwrap() > initial);
    }

    #[test]
    fn tagged_response_content_uses_actual_serde_pair_layout_and_backing() {
        assert!(size_of::<TaggedEntry17>() > size_of::<Value>());
        let response = json!({
            "status":"completed", "operation_state":"completed", "extensions":{},
            "result":{"nested":[{"receipt":"selected response"}, [1,2,3]]},
        });
        let mut geometry = AssociationGeometry17 {
            requested: 0,
            maximum: 1024 * 1024,
        };
        tagged_response_content_geometry_data(&response, &mut geometry).unwrap();

        let content = serde::__private228::de::ContentVisitor::new()
            .deserialize(response.clone())
            .unwrap();
        fn backing(value: &serde::__private228::de::Content<'_>) -> usize {
            use serde::__private228::de::Content;
            match value {
                Content::String(value) => value.capacity(),
                Content::ByteBuf(value) => value.capacity(),
                Content::Seq(values) => {
                    values.capacity() * size_of::<TaggedContent17>()
                        + values.iter().map(backing).sum::<usize>()
                }
                Content::Map(values) => {
                    values.capacity() * size_of::<TaggedEntry17>()
                        + values
                            .iter()
                            .map(|(key, value)| backing(key) + backing(value))
                            .sum::<usize>()
                }
                Content::Some(value) | Content::Newtype(value) => {
                    size_of::<TaggedContent17>() + backing(value)
                }
                _ => 0,
            }
        }

        assert!(geometry.requested >= backing(&content));
        assert!(geometry.requested >= size_of::<TaggedEntry17>() * 4);
        let mut short = AssociationGeometry17 {
            requested: 0,
            maximum: geometry.requested - 1,
        };
        assert!(tagged_response_content_geometry_data(&response, &mut short).is_err());
    }
}

//! Reconciles the exact signed Observe17 model/restored two-object prefix.
//!
//! This class supplies transport correspondence only. Source MAC verification,
//! current proof, native once/debit and complete publication belong to the
//! defining retained action, never an array length or successful quote.

use super::*;
use crate::reference_packet::service::restored_input_reactive17::{
    RESTORED_INPUT_REACTIVE17_FEATURE, authenticate_restored_input_reactive17_selection_data,
    verify_selected_wire_header_data,
};

pub(super) fn authenticate_original_data<S: ProviderStream>(
    connection: &Connection<S>,
    original: &Envelope,
) -> Result<(), ProviderError> {
    connection.protocol_owner.ensure_current()?;
    connection.authenticate_native5_source_codec()?;
    let installed = connection.original_native_owned11_admission()?;
    let selection = installed
        .policy
        .original_restoration_activation_selection_data();
    authenticate_restored_input_reactive17_selection_data(selection, &connection.authority)?;
    if original.method != Method::Observe
        || !verify_selected_wire_header_data(selection, &connection.authority, original)?
    {
        return Err(refused());
    }
    installed.authenticate_current(connection)
}

pub(super) fn authenticate_actual_inputs_data<S: ProviderStream>(
    connection: &Connection<S>,
    original: &Envelope,
    body: &Map<String, Value>,
    evidence: &[(ContentRef, Vec<u8>)],
) -> Result<(), ProviderError> {
    authenticate_original_data(connection, original)?;
    authenticate_two_roles_data(original, body, evidence)?;
    authenticate_original_data(connection, original)
}

fn authenticate_two_roles_data(
    original: &Envelope,
    body: &Map<String, Value>,
    evidence: &[(ContentRef, Vec<u8>)],
) -> Result<(), ProviderError> {
    let [model, restored] = evidence else {
        return Err(refused());
    };
    if model.0 == restored.0 {
        return Err(refused());
    }
    for (reference, bytes) in evidence {
        if bytes.is_empty() || bytes.len() > 65_536 || reference.media_type != "application/json" {
            return Err(credit());
        }
        reference.verify(bytes)?;
    }
    authenticate_output_pair_data(original, &model.0, &model.1, &restored.1)?;
    closed(body, &["status", "operation_state", "result", "extensions"])?;
    if text(body, "status")? != "completed"
        || text(body, "operation_state")? != "completed"
        || !object(body, "extensions")?.is_empty()
    {
        return Err(refused());
    }
    let artifact = original
        .extensions
        .get(RESTORED_INPUT_REACTIVE17_FEATURE)
        .and_then(Value::as_object)
        .ok_or_else(refused)?;
    let request = object(artifact, "request")?;
    let command = object(request, "command")?;
    closed(command, &["action"])?;
    if text(command, "action")? != "observe" {
        return Err(refused());
    }
    let scope = object(request, "scope")?;
    let target = object(scope, "target")?;
    let result = object(body, "result")?;
    closed(
        result,
        &[
            "observations",
            "next_sequence",
            "complete",
            "inventory_hash",
        ],
    )?;
    if field(result, "complete")?.as_bool() != Some(true)
        || field(result, "next_sequence")?.as_str() != Some("1")
    {
        return Err(refused());
    }
    let Some([batch]) = field(result, "observations")?.as_array().map(Vec::as_slice) else {
        return Err(refused());
    };
    let batch = batch.as_object().ok_or_else(refused)?;
    closed(
        batch,
        &[
            "schema_version",
            "execution_owner_id",
            "owner_binding_hash",
            "world_binding_hash",
            "activation_id",
            "world_generation",
            "owner_generation",
            "operation_id",
            "grant_id",
            "first_sequence",
            "last_sequence",
            "events",
            "visibility",
            "measurement_ref",
            "extensions",
        ],
    )?;
    for (batch_name, target_name) in [
        ("execution_owner_id", "owner"),
        ("owner_binding_hash", "binding_hash"),
        ("world_binding_hash", "world"),
        ("activation_id", "activation"),
        ("world_generation", "generation"),
        ("owner_generation", "owner_generation"),
    ] {
        if field(batch, batch_name)? != field(target, target_name)? {
            return Err(refused());
        }
    }
    if field(batch, "schema_version")?.as_u64() != Some(1)
        || field(batch, "operation_id")?.as_str()
            != original.request_id.0.as_ref().map(|id| id.as_str())
        || !field(batch, "grant_id")?.is_null()
        || field(batch, "first_sequence")?.as_str() != Some("0")
        || field(batch, "last_sequence")?.as_str() != Some("0")
        || field(batch, "events")?
            .as_array()
            .is_none_or(|events| !events.is_empty())
        || text(batch, "visibility")? != "staged"
        || !object(batch, "extensions")?.is_empty()
    {
        return Err(refused());
    }
    reference_matches(field(batch, "measurement_ref")?, &restored.0)?;
    let hash = object(result, "inventory_hash")?;
    closed(hash, &["algorithm", "domain", "digest"])?;
    if text(hash, "algorithm")? != "blake3-256"
        || text(hash, "domain")? != "source-owned.packet-connected-inventory/4"
        || text(hash, "digest")?.len() != 64
        || !text(hash, "digest")?
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(refused());
    }
    Ok(())
}

// Both new proof records contain this newly signed original. Their modeled
// inventory is unchanged by Observe, but their model hash legitimately differs
// from request.current_model, which names the prior authenticated checkpoint.
// The raw field visitor below creates no DOM, DTO, String or canonical bank.
use crate::protocol_snapshot::owned11::json_value::{
    borrowed_json_string_comparison_counter_scratch_data, borrowed_json_string_matches_data,
};
use crate::protocol_snapshot::owned11::typed::{Fields, plain_string, unsigned};

const MAXIMUM_PROOF_DEPTH: usize = 128;

fn raw_field_data<'a>(
    input: &'a [u8],
    field: &str,
    maximum_fields: usize,
) -> Result<&'a [u8], ProviderError> {
    let mut fields = Fields::object(input)?;
    let mut previous: Option<&str> = None;
    let mut found = None;
    let mut count = 0usize;
    while let Some((key, value)) = fields.pair()? {
        let key = plain_string(key)?;
        count = count.checked_add(1).ok_or_else(credit)?;
        if count > maximum_fields || previous.is_some_and(|previous| previous >= key) {
            return Err(refused());
        }
        previous = Some(key);
        if key == field {
            found = Some(value);
        }
    }
    found.ok_or_else(refused)
}

fn raw_reference_matches_data(input: &[u8], reference: &ContentRef) -> Result<(), ProviderError> {
    let mut fields = Fields::object(input)?;
    let hash = fields.named("hash")?;
    let length = fields.named("length")?;
    let media = fields.named("media_type")?;
    fields.finish()?;
    let mut hash = Fields::object(hash)?;
    let algorithm = hash.named("algorithm")?;
    let digest = hash.named("digest")?;
    let domain = hash.named("domain")?;
    hash.finish()?;
    if !borrowed_json_string_matches_data(algorithm, &reference.hash.algorithm)?
        || !borrowed_json_string_matches_data(digest, &reference.hash.digest)?
        || !borrowed_json_string_matches_data(domain, &reference.hash.domain)?
        || unsigned(plain_string(length)?.as_bytes())? != reference.length.get()
        || !borrowed_json_string_matches_data(media, &reference.media_type)?
    {
        return Err(refused());
    }
    Ok(())
}

fn raw_value_matches_data(input: &[u8], actual: &Value, depth: usize) -> Result<(), ProviderError> {
    if depth >= MAXIMUM_PROOF_DEPTH {
        return Err(credit());
    }
    match actual {
        Value::Null if input == b"null" => Ok(()),
        Value::Bool(true) if input == b"true" => Ok(()),
        Value::Bool(false) if input == b"false" => Ok(()),
        Value::String(actual) if borrowed_json_string_matches_data(input, actual)? => Ok(()),
        Value::Number(actual) if actual.as_u64() == Some(unsigned(input)?) => Ok(()),
        Value::Object(actual) => raw_map_matches_data(input, actual, depth + 1),
        Value::Array(actual) => {
            let mut fields = Fields::array(input)?;
            for value in actual {
                raw_value_matches_data(fields.next()?.ok_or_else(refused)?, value, depth + 1)?;
            }
            fields.finish()
        }
        _ => Err(refused()),
    }
}

fn raw_map_matches_data(
    input: &[u8],
    actual: &Map<String, Value>,
    depth: usize,
) -> Result<(), ProviderError> {
    if depth >= MAXIMUM_PROOF_DEPTH {
        return Err(credit());
    }
    let mut fields = Fields::object(input)?;
    // Compare wire keys with the actual map by lookup. Canonical ordering is
    // independent of serde_json's BTreeMap/preserve_order feature selection.
    let mut previous: Option<&str> = None;
    let mut count = 0usize;
    while let Some((key, value)) = fields.pair()? {
        let key = plain_string(key)?;
        count = count.checked_add(1).ok_or_else(credit)?;
        if count > actual.len() || previous.is_some_and(|previous| previous >= key) {
            return Err(refused());
        }
        previous = Some(key);
        raw_value_matches_data(value, actual.get(key).ok_or_else(refused)?, depth + 1)?;
    }
    if count != actual.len() {
        return Err(refused());
    }
    fields.finish()
}

fn raw_original_matches_data(input: &[u8], actual: &Envelope) -> Result<(), ProviderError> {
    if actual.method != Method::Observe || actual.message != MessageKind::Request {
        return Err(refused());
    }
    let mut fields = Fields::object(input)?;
    raw_map_matches_data(fields.named("body")?, &actual.body, 0)?;
    for (name, value) in [
        ("capture_owner_id", &actual.capture_owner_id.0),
        ("execution_owner_id", &actual.execution_owner_id.0),
    ] {
        raw_id_matches_data(fields.named(name)?, value.as_ref())?;
    }
    let mut extensions = Fields::object(fields.named("extensions")?)?;
    for (name, value) in &actual.extensions {
        raw_value_matches_data(extensions.named(name)?, value, 0)?;
    }
    extensions.finish()?;
    raw_id_matches_data(
        fields.named("incarnation_id")?,
        actual.incarnation_id.0.as_ref(),
    )?;
    if plain_string(fields.named("message")?)? != "request"
        || plain_string(fields.named("method")?)? != "observe"
    {
        return Err(refused());
    }
    raw_id_matches_data(fields.named("node_id")?, actual.node_id.0.as_ref())?;
    raw_id_matches_data(
        fields.named("operation_id")?,
        actual.operation_id.0.as_ref(),
    )?;
    if plain_string(fields.named("protocol")?)? != actual.protocol {
        return Err(refused());
    }
    raw_id_matches_data(fields.named("request_id")?, actual.request_id.0.as_ref())?;
    if unsigned(plain_string(fields.named("sequence")?)?.as_bytes())? != actual.sequence.get() {
        return Err(refused());
    }
    raw_id_matches_data(fields.named("session_id")?, actual.session_id.0.as_ref())?;
    fields.finish()
}

fn raw_id_matches_data(input: &[u8], actual: Option<&Id>) -> Result<(), ProviderError> {
    match actual {
        Some(actual) if borrowed_json_string_matches_data(input, actual.as_str())? => Ok(()),
        None if input == b"null" => Ok(()),
        _ => Err(refused()),
    }
}

fn authenticate_output_pair_data(
    original: &Envelope,
    model: &ContentRef,
    model_bytes: &[u8],
    restored_bytes: &[u8],
) -> Result<(), ProviderError> {
    // Each enclosing bank is already hash-verified and capped at 65,536 bytes.
    // The known native4 model has five fields; native12 has nine and its
    // receipt has thirteen required plus seven optional native5 fields.
    let receipt = raw_field_data(restored_bytes, "native_receipt", 9)?;
    raw_reference_matches_data(raw_field_data(receipt, "native_record", 20)?, model)?;
    raw_original_matches_data(raw_field_data(receipt, "original", 20)?, original)?;
    raw_original_matches_data(raw_field_data(model_bytes, "original", 5)?, original)
}

fn closed(value: &Map<String, Value>, fields: &[&str]) -> Result<(), ProviderError> {
    if value.len() != fields.len() || fields.iter().any(|name| !value.contains_key(*name)) {
        return Err(refused());
    }
    Ok(())
}

fn field<'a>(value: &'a Map<String, Value>, name: &str) -> Result<&'a Value, ProviderError> {
    value.get(name).ok_or_else(refused)
}

fn object<'a>(
    value: &'a Map<String, Value>,
    name: &str,
) -> Result<&'a Map<String, Value>, ProviderError> {
    field(value, name)?.as_object().ok_or_else(refused)
}

fn text<'a>(value: &'a Map<String, Value>, name: &str) -> Result<&'a str, ProviderError> {
    field(value, name)?.as_str().ok_or_else(refused)
}

fn reference_matches(value: &Value, reference: &ContentRef) -> Result<(), ProviderError> {
    let value = value.as_object().ok_or_else(refused)?;
    closed(value, &["hash", "length", "media_type"])?;
    let hash = object(value, "hash")?;
    closed(hash, &["algorithm", "domain", "digest"])?;
    if text(hash, "algorithm")? != reference.hash.algorithm
        || text(hash, "domain")? != reference.hash.domain
        || text(hash, "digest")? != reference.hash.digest
        || crate::connection::complete_restore_projection::integer(field(value, "length")?)?
            != reference.length.get()
        || text(value, "media_type")? != reference.media_type
    {
        return Err(refused());
    }
    Ok(())
}

pub(super) const fn validation_transient_storage_data() -> usize {
    "blake3-256".len() + "cnp.blob.v1".len() + 2 * blake3::OUT_LEN
}

pub(super) fn counter_scratch_data() -> usize {
    // Fields::span owns one 128-byte delimiter stack per nested borrowed
    // comparison. The depth cap is enforced before every recursive descent.
    MAXIMUM_PROOF_DEPTH
        * (size_of::<Fields<'static>>()
            + size_of::<[u8; 128]>()
            + size_of::<&Value>()
            + size_of::<&[u8]>()
            + size_of::<usize>())
        + size_of::<&Envelope>()
        + size_of::<&Map<String, Value>>() * 8
        + size_of::<&[(ContentRef, Vec<u8>)]>()
        + size_of::<std::slice::Iter<'static, (ContentRef, Vec<u8>)>>()
        + size_of::<Option<&Value>>()
        + size_of::<Option<&[Value]>>()
        + size_of::<[(&'static str, &'static str); 6]>()
        + size_of::<std::array::IntoIter<(&'static str, &'static str), 6>>()
        + size_of::<blake3::Hasher>()
        + size_of::<blake3::Hash>()
        + super::restored_input17::counter_scratch_data()
        + borrowed_json_string_comparison_counter_scratch_data()
}

impl<S: ProviderStream> Connection<S> {
    /// Quotes the exact retained Observe17 reply after its closed class check.
    ///
    /// # Errors
    /// Refuses another selected header or output roster, revoked actual owner,
    /// original correlation, literal geometry, arithmetic or independent bound.
    pub(crate) fn quote_original_restored_observation17_prefix_storage_data(
        &self,
        first: u64,
        original: &Envelope,
        body: &Map<String, Value>,
        evidence: &[(ContentRef, Vec<u8>)],
        maximum: usize,
    ) -> Result<OriginalPacketPrefixStorageData, ProviderError> {
        authenticate_actual_inputs_data(self, original, body, evidence)?;
        // This is the common allocation-free accounting tail, after THIS
        // distinct class validator. No legacy action or permit is entered.
        let mut data = self.quote_original_packet_prefix_accounting_data(
            first, original, body, evidence, maximum, false,
        )?;
        data.construction_transient_requested_bytes = add(
            data.construction_transient_requested_bytes,
            validation_transient_storage_data(),
        )?;
        data.declared_quote_scratch_bytes =
            add(data.declared_quote_scratch_bytes, counter_scratch_data())?;
        if data.requested_bytes()? > maximum {
            return Err(credit());
        }
        authenticate_original_data(self, original)?;
        Ok(data)
    }

    /// Rechecks every actual component of the same selected Observe17 quote.
    ///
    /// # Errors
    /// Refuses changed actual owners, class, proof banks or any storage term.
    pub(crate) fn authenticate_requoted_original_restored_observation17_prefix_storage_data(
        &self,
        first: u64,
        original: &Envelope,
        body: &Map<String, Value>,
        evidence: &[(ContentRef, Vec<u8>)],
        expected: &OriginalPacketPrefixStorageData,
    ) -> Result<(), ProviderError> {
        let actual = self.quote_original_restored_observation17_prefix_storage_data(
            first,
            original,
            body,
            evidence,
            expected.requested_bytes()?,
        )?;
        if actual != *expected {
            return Err(refused());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // These immutable transport DATA banks issue no Source/native permission.
    // The live constructor independently requires the actual installed owner.
    pub(super) fn data() -> (Envelope, Map<String, Value>, Vec<(ContentRef, Vec<u8>)>) {
        let (mut request, mut original) =
            crate::reference_packet::service::restored_input_reactive17::tests::fixture().unwrap();
        request.command = crate::reference_packet::service::restored_input_reactive17::PacketRestoredInputReactive17Command::Observe;
        original.method = Method::Observe;
        let target = &request.scope.target;
        original.extensions.clear();
        original.extensions.insert(
            RESTORED_INPUT_REACTIVE17_FEATURE.into(),
            json!({"request":request}),
        );
        let model_bytes = canonical::canonical_json(&json!({
            "schema":"source-owned.packet-native/4", "native_pid":"1",
            "original":original, "inventory":{"transport_test_role":"model"}, "grant":null,
        }))
        .unwrap();
        let model_ref = canonical::content_ref(&model_bytes, "application/json").unwrap();
        let restored_bytes = canonical::canonical_json(&json!({
            "schema":"source-owned.packet-restored-native/12",
            "native_receipt":{"native_record":model_ref,"original":original},
            "captured_owner_state":request.scope.restoration.captured_owner_state,
            "captured_journal":request.scope.restoration.captured_journal,
            "mapping":request.scope.restoration.mapping,
            "restore_commit":request.scope.restoration.commit_request,
            "restore_response":request.scope.restoration.commit_response,
            "context_digest":request.scope.restoration.context_digest,"physical_gate_held":false,
        }))
        .unwrap();
        let restored_ref = canonical::content_ref(&restored_bytes, "application/json").unwrap();
        let evidence = vec![(model_ref, model_bytes), (restored_ref, restored_bytes)];
        let body = json!({
            "status":"completed","operation_state":"completed",
            "result":{
                "observations":[{
                    "schema_version":1,"execution_owner_id":target.owner,
                    "owner_binding_hash":target.binding_hash,"world_binding_hash":target.world,
                    "activation_id":target.activation,"world_generation":target.generation,
                    "owner_generation":target.owner_generation,"operation_id":original.request_id.0,
                    "grant_id":null,"first_sequence":"0","last_sequence":"0","events":[],
                    "visibility":"staged","measurement_ref":evidence[1].0,"extensions":{},
                }],
                "next_sequence":"1","complete":true,
                "inventory_hash":{"algorithm":"blake3-256","domain":"source-owned.packet-connected-inventory/4",
                    "digest":"0000000000000000000000000000000000000000000000000000000000000000"},
            },"extensions":{},
        }).as_object().unwrap().clone();
        (original, body, evidence)
    }

    #[test]
    fn exact_two_role_data_rejects_changed_missing_aliased_and_extra_banks() {
        let (original, body, evidence) = data();
        authenticate_two_roles_data(&original, &body, &evidence).unwrap();
        assert!(authenticate_two_roles_data(&original, &body, &evidence[..1]).is_err());
        let mut changed = evidence.clone();
        changed.swap(0, 1);
        assert!(authenticate_two_roles_data(&original, &body, &changed).is_err());
        changed = evidence.clone();
        changed[0] = changed[1].clone();
        assert!(authenticate_two_roles_data(&original, &body, &changed).is_err());
        changed = evidence.clone();
        changed[0].1.push(b' ');
        assert!(authenticate_two_roles_data(&original, &body, &changed).is_err());
        changed = evidence.clone();
        changed.push(evidence[0].clone());
        assert!(authenticate_two_roles_data(&original, &body, &changed).is_err());
    }

    #[test]
    fn observe_data_rejects_foreign_target_grant_extension_and_measurement() {
        let (original, body, evidence) = data();
        for change in 0..6 {
            let mut changed = Value::Object(body.clone());
            match change {
                0 => changed["result"]["observations"][0]["world_generation"] = json!("999999999"),
                1 => changed["result"]["observations"][0]["grant_id"] = json!("foreign/grant"),
                2 => changed["extensions"] = json!({"unselected":null}),
                3 => changed["result"]["observations"][0]["measurement_ref"] = json!(evidence[0].0),
                4 => changed["result"]["inventory_hash"]["domain"] = json!("foreign/inventory"),
                5 => {
                    changed["result"]["observations"][0]["operation_id"] = json!("foreign/request")
                }
                _ => unreachable!(),
            }
            assert!(
                authenticate_two_roles_data(&original, changed.as_object().unwrap(), &evidence)
                    .is_err()
            );
        }
        let mut original = original;
        original
            .extensions
            .get_mut(RESTORED_INPUT_REACTIVE17_FEATURE)
            .unwrap()["request"]["command"] = json!({"action":"input"});
        assert!(authenticate_two_roles_data(&original, &body, &evidence).is_err());
    }
}

#[cfg(test)]
mod proof_pair_tests {
    use super::*;

    #[test]
    fn hash_valid_output_model_and_both_embedded_originals_must_match() {
        let (original, _, evidence) = super::tests::data();
        authenticate_output_pair_data(&original, &evidence[0].0, &evidence[0].1, &evidence[1].1)
            .unwrap();
        let (_, body, mut changed_evidence) = super::tests::data();
        let foreign_bytes = canonical::canonical_json(&serde_json::json!({
            "schema":"source-owned.packet-native/4", "native_pid":"1",
            "original":original, "inventory":{"transport_test_role":"different-model"}, "grant":null,
        })).unwrap();
        let foreign = canonical::content_ref(&foreign_bytes, "application/json").unwrap();
        foreign.verify(&foreign_bytes).unwrap();
        changed_evidence[0] = (foreign, foreign_bytes);
        // Both complete banks still match their hashes and the terminal names
        // the same restored bank. Only its exact native_record→model join fails.
        assert!(authenticate_two_roles_data(&original, &body, &changed_evidence).is_err());
        let mut changed = original.clone();
        changed.sequence = U64::new(original.sequence.get() + 1);
        assert!(
            authenticate_output_pair_data(&changed, &evidence[0].0, &evidence[0].1, &evidence[1].1)
                .is_err()
        );
    }
}

#[cfg(test)]
mod borrowed_field_tests {
    use super::*;

    #[test]
    fn borrowed_proof_fields_reject_duplicates_extra_fields_and_excess_depth() {
        assert!(raw_field_data(br#"{"original":{},"original":{}}"#, "original", 5).is_err());
        assert!(raw_field_data(br#"{"a":0,"b":0,"original":{}}"#, "original", 2).is_err());
        let actual = serde_json::json!({"scope":{"sequence":"1"}});
        assert!(raw_value_matches_data(br#"{"scope":{"sequence":"1"}}"#, &actual, 0).is_ok());
        assert!(
            raw_value_matches_data(br#"{"scope":{"sequence":"1","sequence":"1"}}"#, &actual, 0)
                .is_err()
        );
        assert!(raw_value_matches_data(br#"{"scope":{"sequence":"2"}}"#, &actual, 0).is_err());
        assert!(
            raw_value_matches_data(
                br#"{"scope":{"sequence":"1"}}"#,
                &actual,
                MAXIMUM_PROOF_DEPTH
            )
            .is_err()
        );
    }
}

#[cfg(test)]
mod escaped_output_original_tests {
    use super::*;

    #[test]
    fn borrowed_actual_map_lookup_accepts_escaped_leaves_in_reverse_insertion_order() {
        let mut actual = Map::new();
        actual.insert("z".into(), Value::String("quote\"slash\\".into()));
        actual.insert("a".into(), Value::String("domain\n\0".into()));
        let encoded = canonical::canonical_json(&Value::Object(actual.clone())).unwrap();
        raw_map_matches_data(&encoded, &actual, 0).unwrap();
    }
}

#[cfg(test)]
mod escaped_envelope_id_tests {
    use super::*;
    use crate::envelope::Nullable;

    #[test]
    fn complete_original_compares_borrowed_id_strings_and_refuses_changed_identity() {
        let (mut original, _, _) = super::tests::data();
        original.request_id = Nullable(Some(Id::new("request/base").unwrap()));
        original.session_id = Nullable(Some(Id::new("session/base").unwrap()));
        let encoded = canonical::canonical_json(&serde_json::to_value(&original).unwrap()).unwrap();
        raw_original_matches_data(&encoded, &original).unwrap();
        let escaped = std::str::from_utf8(&encoded)
            .unwrap()
            .replace("session/base", r"session\u002fbase");
        raw_original_matches_data(escaped.as_bytes(), &original).unwrap();
        let mut changed = original.clone();
        changed.session_id = Nullable(Some(Id::new("session/changed").unwrap()));
        assert!(raw_original_matches_data(escaped.as_bytes(), &changed).is_err());
        // These bytes are outside the actual defining identifier profile.
        assert!(Id::new("session\"quote").is_err());
        assert!(Id::new("session\ncontrol").is_err());
    }
}

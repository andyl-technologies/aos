//! Reconciles the distinct completed Input17 five-object proof prefix.
//!
//! This module authenticates transport correspondence only. It never creates a
//! Source claim, authenticates an action MAC, debits a native row or advances a
//! Scheduler. The defining action owner must supply those before construction.

use super::*;
use crate::reference_packet::control::PacketControlSelection;
use crate::reference_packet::service::{
    PacketConnectedSourceProgram, PacketNative5SourceLaunch,
    restored_input_reactive17::{
        RESTORED_INPUT_REACTIVE17_FEATURE, authenticate_restored_input_reactive17_schema_data,
        authenticate_restored_input_reactive17_selection_data, verify_selected_wire_header_data,
    },
};
use crucible_node_format::{HashRef, SchemaRef};

pub(super) fn authenticate_launch_data(
    launch: &PacketNative5SourceLaunch,
) -> Result<(), ProviderError> {
    if !matches!(
        launch.program,
        PacketConnectedSourceProgram::Reactive { .. }
    ) {
        return Err(refused());
    }
    authenticate_formats_data(&launch.selection)
}

fn authenticate_formats_data(selection: &PacketControlSelection) -> Result<(), ProviderError> {
    fn formats(formats: &[SchemaRef]) -> Result<(), ProviderError> {
        let mut selected = formats
            .iter()
            .filter(|schema| schema.id.as_str() == RESTORED_INPUT_REACTIVE17_FEATURE);
        authenticate_restored_input_reactive17_schema_data(selected.next().ok_or_else(refused)?)?;
        if selected.next().is_some() {
            return Err(refused());
        }
        Ok(())
    }

    formats(&selection.provider.implementation.formats)?;
    if selection.realization.bindings.is_empty()
        || selection
            .provider
            .extensions_supported
            .iter()
            .filter(|feature| feature.as_str() == RESTORED_INPUT_REACTIVE17_FEATURE)
            .count()
            != 1
    {
        return Err(refused());
    }
    for binding in &selection.realization.bindings {
        formats(&binding.compatibility.implementation.formats)?;
    }
    Ok(())
}

/// Authenticates only the actual current transport header and full selection.
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
    authenticate_formats_data(selection)?;
    authenticate_restored_input_reactive17_selection_data(selection, &connection.authority)?;
    if original.method != Method::Input
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
    authenticate_five_roles_data(original, body, evidence)?;
    authenticate_original_data(connection, original)
}

// No decoder, cloned Value, invented original or unretained typed proof is
// needed: each full immutable content reference binds its actual retained bank.
fn authenticate_five_roles_data(
    original: &Envelope,
    body: &Map<String, Value>,
    evidence: &[(ContentRef, Vec<u8>)],
) -> Result<(), ProviderError> {
    let [native, _custody, receipt, model, restored] = evidence else {
        return Err(refused());
    };
    for (index, (reference, bytes)) in evidence.iter().enumerate() {
        if bytes.is_empty()
            || bytes.len() > 65_536
            || reference.media_type != "application/json"
            || evidence[..index]
                .iter()
                .any(|(other, _)| other == reference)
        {
            return Err(credit());
        }
        reference.verify(bytes)?;
    }
    closed(body, &["status", "operation_state", "result", "extensions"])?;
    if text(body, "status")? != "completed" || text(body, "operation_state")? != "completed" {
        return Err(refused());
    }
    let result = object(body, "result")?;
    closed(
        result,
        &[
            "accepted_event_ids",
            "input_watermark",
            "custody_receipt",
            "inventory_hash",
        ],
    )?;
    reference_matches(field(result, "custody_receipt")?, &receipt.0)?;
    hash_matches(field(result, "inventory_hash")?, &native.0.hash)?;
    let accepted = field(result, "accepted_event_ids")?
        .as_array()
        .ok_or_else(refused)?;
    let events = field(&original.body, "events")?
        .as_array()
        .ok_or_else(refused)?;
    if events.len() > 4 || accepted.len() != events.len() {
        return Err(refused());
    }
    let mut previous = None;
    for id in accepted {
        let id = id.as_str().ok_or_else(refused)?;
        if previous.is_some_and(|previous| previous >= id)
            || events
                .iter()
                .filter(|event| event.get("id").and_then(Value::as_str) == Some(id))
                .count()
                != 1
        {
            return Err(refused());
        }
        previous = Some(id);
    }
    let artifact = original
        .extensions
        .get(RESTORED_INPUT_REACTIVE17_FEATURE)
        .and_then(Value::as_object)
        .ok_or_else(refused)?;
    let request = object(artifact, "request")?;
    let command = object(request, "command")?;
    if text(command, "action")? != "input" {
        return Err(refused());
    }
    let context = object(command, "context")?;
    let cut = object(context, "cut")?;
    if field(result, "input_watermark")? != field(cut, "batch_sequence")? {
        return Err(refused());
    }
    let extensions = object(body, "extensions")?;
    closed(extensions, &[RESTORED_INPUT_REACTIVE17_FEATURE])?;
    let checkpoint = object(extensions, RESTORED_INPUT_REACTIVE17_FEATURE)?;
    closed(checkpoint, &["schema", "current_record", "current_model"])?;
    if text(checkpoint, "schema")?
        != "source-owned.packet-restored-input-reactive-post-checkpoint/17"
    {
        return Err(refused());
    }
    reference_matches(field(checkpoint, "current_record")?, &restored.0)?;
    reference_matches(field(checkpoint, "current_model")?, &model.0)
}

fn closed(value: &Map<String, Value>, fields: &[&str]) -> Result<(), ProviderError> {
    if value.len() != fields.len() || fields.iter().any(|field| !value.contains_key(*field)) {
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
    hash_matches(field(value, "hash")?, &reference.hash)?;
    if crate::connection::complete_restore_projection::integer(field(value, "length")?)?
        != reference.length.get()
        || text(value, "media_type")? != reference.media_type
    {
        return Err(refused());
    }
    Ok(())
}

fn hash_matches(value: &Value, reference: &HashRef) -> Result<(), ProviderError> {
    let value = value.as_object().ok_or_else(refused)?;
    closed(value, &["algorithm", "domain", "digest"])?;
    if text(value, "algorithm")? != reference.algorithm
        || text(value, "domain")? != reference.domain
        || text(value, "digest")? != reference.digest
    {
        return Err(refused());
    }
    Ok(())
}

// ContentRef::verify creates one fresh unkeyed identity. Each verification
// completes before the next role, so these named String requests coexist once.
pub(super) const fn validation_transient_storage_data() -> usize {
    "blake3-256".len() + "cnp.blob.v1".len() + 2 * blake3::OUT_LEN
}

pub(super) fn counter_scratch_data() -> usize {
    use std::mem::size_of;
    fn returned_layout_bytes<T>(_: impl FnOnce() -> T) -> usize {
        size_of::<T>()
    }
    size_of::<&PacketNative5SourceLaunch>()
        + size_of::<&PacketControlSelection>()
        + size_of::<&Envelope>()
        + size_of::<&Map<String,Value>>()
        + size_of::<&[(ContentRef,Vec<u8>)]>()
        + size_of::<std::slice::Iter<'static,(ContentRef,Vec<u8>)>>()
        + size_of::<std::slice::Iter<'static,Value>>()
        + size_of::<std::slice::Iter<'static,SchemaRef>>()
        + size_of::<std::slice::Iter<'static,crucible_node_format::NodeBinding>>()
        + size_of::<std::slice::Iter<'static,Id>>()
        + size_of::<Option<&str>>()
        + size_of::<Result<&str,ProviderError>>()
        + size_of::<Result<&Value,ProviderError>>()
        + size_of::<Result<&Map<String,Value>,ProviderError>>()
        + size_of::<Result<HashRef,crucible_node_format::ContractError>>()
        + size_of::<Result<HashRef,ProviderError>>()
        + size_of::<Result<(),ProviderError>>()
        + size_of::<Result<u64,std::num::ParseIntError>>()
        + size_of::<blake3::Hasher>()
        + size_of::<blake3::Hash>()
        + returned_layout_bytes(|| blake3::Hash::from_bytes([0;32]).to_hex())
        + size_of::<[u8;4]>() + size_of::<[u8;8]>()
        + 2 * size_of::<usize>()
        + crate::reference_packet::service::restored_input_reactive17::
            restored_input_reactive17_contract_counter_scratch_data()
}

impl<S: ProviderStream> Connection<S> {
    /// Requotes the exact five retained reply banks under the current connection.
    ///
    /// # Errors
    /// Refuses any changed full selection, original, reply role or finite owner,
    /// correlation, wire, literal-bank, arithmetic or total-storage ceiling.
    pub(crate) fn quote_original_restored_input17_prefix_storage_data(
        &self,
        first: u64,
        original: &Envelope,
        body: &Map<String, Value>,
        evidence: &[(ContentRef, Vec<u8>)],
        maximum: usize,
    ) -> Result<OriginalPacketPrefixStorageData, ProviderError> {
        self.quote_original_packet_prefix_storage_inner_data(
            first, original, body, evidence, maximum, true,
        )
    }

    /// Rechecks every actual component of the same previously computed quote.
    ///
    /// # Errors
    /// Refuses changed actual owners or any independent storage component.
    pub(crate) fn authenticate_requoted_original_restored_input17_prefix_storage_data(
        &self,
        first: u64,
        original: &Envelope,
        body: &Map<String, Value>,
        evidence: &[(ContentRef, Vec<u8>)],
        expected: &OriginalPacketPrefixStorageData,
    ) -> Result<(), ProviderError> {
        let actual = self.quote_original_restored_input17_prefix_storage_data(
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
    use crucible_node_format::{Id, canonical};
    use serde_json::json;

    #[test]
    fn every_binding_requires_the_complete_distinct_input17_definition() {
        let (_, _, mut selection, _) =
            crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
        let schema = crate::reference_packet::service::restored_input_reactive17::
            restored_input_reactive17_schema_data().unwrap();
        selection
            .provider
            .implementation
            .formats
            .push(schema.clone());
        selection
            .provider
            .extensions_supported
            .push(Id::new(RESTORED_INPUT_REACTIVE17_FEATURE).unwrap());
        for binding in &mut selection.realization.bindings {
            binding
                .compatibility
                .implementation
                .formats
                .push(schema.clone());
        }
        authenticate_formats_data(&selection).unwrap();

        selection.realization.bindings[0]
            .compatibility
            .implementation
            .formats
            .iter_mut()
            .find(|format| format.id == schema.id)
            .unwrap()
            .definition
            .length = U64::new(schema.definition.length.get() + 1);
        assert!(authenticate_formats_data(&selection).is_err());
        selection.realization.bindings[0]
            .compatibility
            .implementation
            .formats
            .iter_mut()
            .find(|format| format.id == schema.id)
            .unwrap()
            .definition = schema.definition.clone();
        selection.provider.implementation.formats.push(schema);
        assert!(authenticate_formats_data(&selection).is_err());
    }

    #[test]
    fn five_role_transport_data_rejects_reordered_missing_alias_and_changed_banks() {
        let mut original = crate::envelope::tests::request();
        original.method = Method::Input;
        original.body = json!({"events":[]}).as_object().unwrap().clone();
        original.extensions.clear();
        original.extensions.insert(
            RESTORED_INPUT_REACTIVE17_FEATURE.into(),
            json!({
                "request":{"command":{"action":"input","context":{"cut":{"batch_sequence":"7"}}}}
            }),
        );
        // These are transport DATA banks, not native proof DTOs or a Source
        // action scope. The defining native owner supplies that separate join.
        let evidence = (0..5)
            .map(|role| {
                let bytes =
                    canonical::canonical_json(&json!({"transport_test_role":role})).unwrap();
                (
                    canonical::content_ref(&bytes, "application/json").unwrap(),
                    bytes,
                )
            })
            .collect::<Vec<_>>();
        let body = json!({
            "status":"completed","operation_state":"completed",
            "result":{"accepted_event_ids":[],"input_watermark":"7",
                "custody_receipt":evidence[2].0,"inventory_hash":evidence[0].0.hash},
            "extensions":{RESTORED_INPUT_REACTIVE17_FEATURE:{
                "schema":"source-owned.packet-restored-input-reactive-post-checkpoint/17",
                "current_record":evidence[4].0,"current_model":evidence[3].0}}
        })
        .as_object()
        .unwrap()
        .clone();
        authenticate_five_roles_data(&original, &body, &evidence).unwrap();

        let mut changed = evidence.clone();
        changed.swap(3, 4);
        assert!(authenticate_five_roles_data(&original, &body, &changed).is_err());
        assert!(authenticate_five_roles_data(&original, &body, &evidence[..4]).is_err());
        changed = evidence.clone();
        changed[1] = changed[0].clone();
        assert!(authenticate_five_roles_data(&original, &body, &changed).is_err());
        changed = evidence.clone();
        changed[0].1.push(b' ');
        assert!(authenticate_five_roles_data(&original, &body, &changed).is_err());
    }
}

//! Quotes archived Runtime and CNP comparison constructors before their effects.
//!
//! All inputs remain borrowed historical DATA. Actual content spans and typed
//! serializer events determine independent temporary windows; no observer peak,
//! decoder hint, native permission or live Source supplies future allocation.

use super::super::archive_owner::ArchivedContentData;
use super::{PacketCompleteArchivedSemantics, data::*, refused, unknown};
use crate::node_contract::{NodeRuntime, OperationFailure};
use crucible_node_contract::{ActivationManifest, ContentRef, Event, HashRef, Id, PreparedOwner, U64};
use crucible_node_provider::{
    bodies::BeginArguments, envelope::Method,
    protocol_snapshot::owned11::outer::HistoricalControllerState,
};
use serde::Serialize;
use serde_json::Value;
use std::mem::size_of;

// ContentRef::verify and ClientContent::get return one independently owned hash.
const HASH_BACKING: usize = "blake3-256".len() + "cnp.blob.v1".len() + 64;

impl PacketCompleteArchivedSemantics {
    /// Names the actual formatter and content-lookup allocations in this quote.
    ///
    /// The caller admits these temporary bytes plus the fixed counter before
    /// invoking either prospective walk. U64 formatting needs twenty bytes;
    /// the protocol walk additionally verifies one borrowed content body.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) const fn runtime_protocol_terminal_quote_transient_data()
    -> usize {
        20 + HASH_BACKING
    }

    /// Names actual archived predicate, scanner and prospective view controls.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn runtime_protocol_terminal_counter_scratch_data()
    -> usize {
        use crate::node_scheduling::InputPayload;
        use crucible_node_provider::client::ClientOriginal;
        use std::collections::btree_map::{Iter, Values};
        use std::slice;

        type ContentObject = (ContentRef, std::rc::Rc<Vec<u8>>);

        super::validate::counter_scratch_data()
            + super::protocol::counter_scratch_data()
            + NodeRuntime::capture_serialization_counter_scratch_data()
            + NodeRuntime::capture_selected_json_decode_counter_scratch_data()
            + size_of::<Self>()
            + size_of::<Window>()
            + size_of::<[usize; 6]>()
            + size_of::<Result<(usize, usize), OperationFailure>>()
            + size_of::<Result<usize, OperationFailure>>()
            + size_of::<Result<(usize, usize), crate::node_contract::RuntimeError>>()
            + size_of::<Option<&ContentRef>>()
            + size_of::<HashRef>()
            + size_of::<Id>()
            + size_of::<String>()
            + size_of::<Result<&[u8], crucible_node_provider::ProviderError>>()
            + size_of::<Option<&Value>>()
            + size_of::<Option<&serde_json::Map<String, Value>>>()
            + size_of::<Iter<'_, Id, ClientOriginal>>()
            + size_of::<Values<'_, String, ContentObject>>()
            + size_of::<blake3::Hasher>()
            + size_of::<Iter<'_, Id, ArchivedInput>>()
            + size_of::<Iter<'_, Id, ArchivedOperation>>()
            + size_of::<slice::Iter<'_, ArchivedLineage<ContentRef>>>()
            + size_of::<slice::Iter<'_, ArchivedPublication<ContentRef>>>()
            + size_of::<slice::Iter<'_, ArchivedLineage<InputPayload>>>()
            + size_of::<slice::Iter<'_, ArchivedPublication<InputPayload>>>()
            + size_of::<slice::Iter<'_, Event>>()
            + size_of::<slice::Iter<'_, HashRef>>()
    }

    /// Quotes the independent Runtime and protocol validation temporary windows.
    ///
    /// The caller retains the actual archived semantics, controller, Runtime
    /// and content separately and admits the returned rows before calling the
    /// operational validators. Successful quotation does not authenticate any
    /// semantic correlation or replace either original predicate.
    ///
    /// # Errors
    /// Refuses missing actual activation content, inconsistent full references,
    /// raw preflight failure, unsupported DTO layout or checked storage excess.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn runtime_protocol_terminal_transient_data(
        &self,
        host: &HistoricalControllerState,
        content: ArchivedContentData<'_>,
        maximum: usize,
    ) -> Result<(usize, usize), OperationFailure> {
        Ok((
            self.runtime_window(content, maximum)?,
            self.protocol_window(host, maximum)?,
        ))
    }

    fn runtime_window(
        &self,
        content: ArchivedContentData<'_>,
        maximum: usize,
    ) -> Result<usize, OperationFailure> {
        let mut work = Window::new(maximum);
        work.include(HASH_BACKING)?;
        if let Some(prepared) = &self.semantic.prepared_owner {
            let clone = prepared
                .binding_hashes
                .iter()
                .map(|hash| add(hash.domain.len(), hash.digest.len()))
                .try_fold(0usize, |largest, value| {
                    Ok::<_, OperationFailure>(largest.max(value?))
                })?;
            work.include(multiply(clone, 2)?)?;
        }
        for input in self.semantic.inputs.values() {
            let keys = multiply(
                input.request.events.len(),
                NodeRuntime::capture_map_node_storage::<(&Id, U64), ()>(),
            )?;
            let mut event_keys = 0;
            for event in &input.request.events {
                event_keys = event_keys.max(sorted_ids(&event.causal_parent_ids)?);
            }
            work.include(add(keys, event_keys)?)?;
            for response in [
                input.response.as_ref(),
                input
                    .commitment
                    .as_ref()
                    .and_then(|one| one.response.as_ref()),
            ]
            .into_iter()
            .flatten()
            {
                work.include(sorted_ids(&response.accepted_event_ids)?)?;
            }
        }
        for operation in self.semantic.operations.values() {
            if size_of::<BeginArguments>() > NodeRuntime::capture_closed_inline_storage() {
                return Err(refused(
                    "archived prospective Begin layout exceeds selected decoder",
                ));
            }
            let arguments = &operation.begin.arguments;
            let first = serialization(arguments, maximum)?;
            let encoded =
                NodeRuntime::capture_encoded_output_storage(arguments, maximum).map_err(unknown)?;
            let typed =
                NodeRuntime::capture_future_decode_storage(arguments, maximum).map_err(unknown)?;
            work.include(add(add(first, encoded)?, typed)?)?;
        }
        match &self.ancestry {
            ArchivedAncestry::Inline(record) => ancestry_window(record, content, &mut work)?,
            ArchivedAncestry::References(record) => ancestry_window(record, content, &mut work)?,
        }
        work.finish()
    }

    fn protocol_window(
        &self,
        host: &HistoricalControllerState,
        maximum: usize,
    ) -> Result<usize, OperationFailure> {
        let mut work = Window::new(maximum);
        let state = &self.semantic;
        if let Some(activation) = &state.active {
            for value in [
                serialization(&activation.activation_id, maximum)?,
                serialization(&activation.generation, maximum)?,
                serialization(&activation.world_binding_hash, maximum)?,
            ] {
                work.include(value)?;
            }
            for prefix in ["activate", "world-activate"] {
                work.include(request_id_window(prefix, &activation.activation_id)?)?;
            }
            work.include(observe_id_window(
                &activation.activation_id,
                state.observe_sequence.get(),
            )?)?;
            let original = host
                .custody
                .controller
                .iter()
                .find(|(id, _)| {
                    id.as_str().strip_prefix("cnp-world-activate-")
                        == Some(activation.activation_id.as_str())
                })
                .map(|(_, original)| original)
                .ok_or_else(|| refused("prospective archived WorldActivate original absent"))?;
            if original.request.method != Method::WorldActivate {
                return Err(refused("prospective archived activation method differs"));
            }
            let manifest_value = original
                .request
                .body
                .get("activation_manifest")
                .ok_or_else(|| refused("prospective archived activation reference absent"))?;
            let reference = host
                .custody
                .content
                .references()
                .find(|reference| reference_value_matches(reference, manifest_value))
                .ok_or_else(|| refused("prospective archived activation full reference absent"))?;
            // This actual public content read verifies bytes and allocates one
            // HashRef. The caller funded that independent quote window first.
            let bytes = host.custody.content.get(reference).map_err(unknown)?;
            let reference_dto = add(
                size_of::<ContentRef>(),
                serialization(manifest_value, maximum)?,
            )?;
            let raw = raw_decode(
                bytes,
                size_of::<ActivationManifest>().max(size_of::<PreparedOwner>()),
                maximum,
            )?;
            work.include(add(reference_dto, add(raw, HASH_BACKING)?)?)?;
        }
        if let Some(prepared) = &state.prepared_owner {
            work.include(serialization(&prepared.prepared_token, maximum)?)?;
        }
        if let Some(ready) = &state.ready {
            work.include(serialization(&ready.ready_receipt, maximum)?)?;
        }
        if let Some(response) = &state.activate_response {
            work.include(serialization(response, maximum)?)?;
        }
        for (stage, input) in &state.inputs {
            work.include(request_id_window("input", stage)?)?;
            work.include(serialization(&input.request, maximum)?)?;
            if let Some(response) = &input.response {
                work.include(serialization(response, maximum)?)?;
            }
            if let Some(commitment) = &input.commitment {
                work.include(request_id_window("input-consumed", stage)?)?;
                if let Some(response) = &commitment.response {
                    work.include(serialization(response, maximum)?)?;
                }
            }
        }
        for (id, operation) in &state.operations {
            for prefix in ["begin", "cancel", "retire"] {
                work.include(request_id_window(prefix, id)?)?;
            }
            work.include(serialization(&operation.begin, maximum)?)?;
            work.include(serialization(&true, maximum)?)?;
            if let Some(retirement) = &operation.retirement {
                work.include(serialization(&retirement.reference, maximum)?)?;
            }
        }
        if let Some((_, observation)) = &state.observation {
            let activation = state
                .active
                .as_ref()
                .ok_or_else(|| refused("prospective archived observation activation absent"))?;
            work.include(observe_comparison_window(
                &activation.activation_id,
                state.observe_sequence.get(),
                &observation.proof_ref,
                maximum,
            )?)?;
        }
        work.finish()
    }
}

struct Window {
    peak: usize,
    maximum: usize,
}

impl Window {
    fn new(maximum: usize) -> Self {
        Self { peak: 20, maximum }
    }

    fn include(&mut self, bytes: usize) -> Result<(), OperationFailure> {
        if bytes > self.maximum {
            return Err(refused("archived prospective validation window exhausted"));
        }
        self.peak = self.peak.max(bytes);
        Ok(())
    }

    fn finish(self) -> Result<usize, OperationFailure> {
        if self.peak > self.maximum {
            return Err(refused("archived prospective validation floor exhausted"));
        }
        Ok(self.peak)
    }
}

fn ancestry_window<Object>(
    record: &ArchivedAncestryRecord<Object>,
    content: ArchivedContentData<'_>,
    work: &mut Window,
) -> Result<(), OperationFailure> {
    for lineage in &record.lineages {
        for publication in &lineage.publications {
            let bytes = content
                .get(&publication.published)
                .ok_or_else(|| refused("prospective archived publication body absent"))?;
            work.include(add(
                raw_decode(bytes, size_of::<Event>(), work.maximum)?,
                HASH_BACKING,
            )?)?;
        }
    }
    Ok(())
}

fn raw_decode(bytes: &[u8], slot: usize, maximum: usize) -> Result<usize, OperationFailure> {
    let (decode, strings) =
        NodeRuntime::capture_selected_json_decode_and_string_clone_storage_data(
            bytes,
            slot.max(size_of::<Value>())
                .max(size_of::<ContentRef>())
                .max(size_of::<HashRef>()),
            NodeRuntime::capture_map_node_storage::<String, Value>(),
            maximum,
        )
        .map_err(unknown)?;
    // The real raw DTO remains alive through adjacent-key validation and the
    // transaction/gate comparisons. Raw string occurrences, including changed
    // fields that the final equality check refuses, fund those independent clones.
    add(decode, strings)
}

fn serialization(value: &impl Serialize, maximum: usize) -> Result<usize, OperationFailure> {
    NodeRuntime::capture_serialization_storage(value, maximum).map_err(unknown)
}

fn sorted_ids(ids: &[Id]) -> Result<usize, OperationFailure> {
    multiply(ids.iter().map(|id| id.as_str().len()).max().unwrap_or(0), 2)
}

fn request_id_window(prefix: &str, id: &Id) -> Result<usize, OperationFailure> {
    // The actual cnp-{prefix}-{id} format uses geometric String growth. The
    // returned Id moves that buffer; validation adds no independent clone.
    multiply(add(add(5, prefix.len())?, id.as_str().len())?, 4).and_then(|bytes| add(bytes, 8))
}

fn observe_id_window(id: &Id, sequence: u64) -> Result<usize, OperationFailure> {
    let decimal = if sequence == 0 {
        1
    } else {
        sequence.ilog10() as usize + 1
    };
    multiply(
        add(add("cnp-observe--".len(), id.as_str().len())?, decimal)?,
        4,
    )
    .and_then(|bytes| add(bytes, 8))
}

fn observe_comparison_window(
    activation: &Id,
    sequence: u64,
    proof: &ContentRef,
    maximum: usize,
) -> Result<usize, OperationFailure> {
    // Unlike original(), this operational branch retains its generated Id
    // while constructing the independent measurement-reference comparison DOM.
    add(
        observe_id_window(activation, sequence)?,
        serialization(proof, maximum)?,
    )
}

fn reference_value_matches(reference: &ContentRef, value: &Value) -> bool {
    let Some(object) = value.as_object().filter(|object| object.len() == 3) else {
        return false;
    };
    let Some(hash) = object
        .get("hash")
        .and_then(Value::as_object)
        .filter(|hash| hash.len() == 3)
    else {
        return false;
    };
    hash.get("algorithm").and_then(Value::as_str) == Some(reference.hash.algorithm.as_str())
        && hash.get("domain").and_then(Value::as_str) == Some(reference.hash.domain.as_str())
        && hash.get("digest").and_then(Value::as_str) == Some(reference.hash.digest.as_str())
        && object.get("media_type").and_then(Value::as_str) == Some(reference.media_type.as_str())
        && object
            .get("length")
            .and_then(Value::as_str)
            .is_some_and(|length| {
                !length.is_empty()
                    && (length == "0" || !length.starts_with('0'))
                    && length.bytes().all(|byte| byte.is_ascii_digit())
                    && length.parse::<u64>().ok() == Some(reference.length.get())
            })
}

fn add(left: usize, right: usize) -> Result<usize, OperationFailure> {
    left.checked_add(right)
        .ok_or_else(|| refused("archived prospective validation sum overflow"))
}

fn multiply(left: usize, right: usize) -> Result<usize, OperationFailure> {
    left.checked_mul(right)
        .ok_or_else(|| refused("archived prospective validation layout overflow"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_node_contract::canonical;
    use serde_json::json;

    #[test]
    fn borrowed_lookup_binds_every_full_reference_field_without_a_dto() {
        let reference = canonical::content_ref(b"historical DATA", "application/json").unwrap();
        let original = serde_json::to_value(&reference).unwrap();
        assert!(reference_value_matches(&reference, &original));

        let changes = [
            ("hash", "algorithm", json!("sha256")),
            ("hash", "domain", json!("changed.domain.v1")),
            ("hash", "digest", json!("f".repeat(64))),
        ];
        for (field, nested, changed) in changes {
            let mut value = original.clone();
            value[field][nested] = changed;
            assert!(!reference_value_matches(&reference, &value));
        }
        for (field, changed) in [
            ("length", json!("0")),
            ("length", json!(reference.length.get())),
            ("length", json!(format!("0{}", reference.length))),
            ("media_type", json!("application/octet-stream")),
        ] {
            let mut value = original.clone();
            value[field] = changed;
            assert!(!reference_value_matches(&reference, &value));
        }
        let mut extra = original.clone();
        extra["discarded"] = json!(true);
        assert!(!reference_value_matches(&reference, &extra));
        let mut missing = original;
        missing.as_object_mut().unwrap().remove("length");
        assert!(!reference_value_matches(&reference, &missing));
    }

    #[test]
    fn latest_observation_prices_the_live_request_id_beside_comparison() {
        let activation = Id::new("activation/data").unwrap();
        let proof = canonical::content_ref(b"DATA observation", "application/json").unwrap();
        let sequence = 123;
        let request_id = Id::new(format!("cnp-observe-{activation}-{sequence}")).unwrap();
        let comparison = serialization(&proof, usize::MAX).unwrap();
        let prospective =
            observe_comparison_window(&activation, sequence, &proof, usize::MAX).unwrap();

        assert!(prospective > comparison);
        assert!(prospective >= request_id.allocated_capacity() + comparison);
        let mut window = Window::new(comparison);
        assert!(window.include(prospective).is_err());
    }

    #[test]
    fn raw_changed_string_occurrences_receive_independent_clone_credit() {
        // These are pure raw grammar fragments, not qualified Manifest objects.
        let short = br#"{"transaction_id":"a","gate_id":"b"}"#;
        let long = br#"{"transaction_id":"a much longer changed identity","gate_id":"b"}"#;
        let slot = size_of::<ActivationManifest>().max(size_of::<PreparedOwner>());
        let map = NodeRuntime::capture_map_node_storage::<String, Value>();
        let (decode, clones) =
            NodeRuntime::capture_selected_json_decode_and_string_clone_storage_data(
                short,
                slot,
                map,
                usize::MAX,
            )
            .unwrap();
        let (larger_decode, larger_clones) =
            NodeRuntime::capture_selected_json_decode_and_string_clone_storage_data(
                long,
                slot,
                map,
                usize::MAX,
            )
            .unwrap();
        assert!(clones > 0);
        assert!(larger_decode > decode);
        assert!(larger_clones > clones);
        let total = raw_decode(long, slot, usize::MAX).unwrap();
        assert_eq!(total, larger_decode + larger_clones);
        let mut window = Window::new(total - 1);
        assert!(window.include(total).is_err());
    }
}

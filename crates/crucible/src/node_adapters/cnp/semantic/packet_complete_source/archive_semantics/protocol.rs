//! Joins complete common fields to the original historical CNP RPC population.

use super::{PacketCompleteArchivedSemantics, refused, unknown};
use crate::node_contract::{NodeRuntime, OperationFailure};
use crucible_node_contract::Id;
use crucible_node_provider::{
    client::ClientOriginal,
    envelope::{MessageKind, Method},
    protocol_snapshot::owned11::outer::HistoricalControllerState,
};
use serde::Serialize;
use serde_json::Value;

struct ComparisonBudget {
    retained: usize,
    maximum: usize,
}

impl ComparisonBudget {
    fn compare(&self, expected: &impl Serialize, actual: &Value) -> Result<(), OperationFailure> {
        let scratch =
            NodeRuntime::capture_serialization_storage(expected, self.maximum).map_err(unknown)?;
        self.retained
            .checked_add(scratch)
            .filter(|n| *n <= self.maximum)
            .ok_or_else(|| refused("archived common comparison storage exhausted"))?;
        if serde_json::to_value(expected).map_err(unknown)? != *actual {
            return Err(refused(
                "archived common field differs from original CNP body",
            ));
        }
        Ok(())
    }

    fn compare_body(
        &self,
        expected: &impl Serialize,
        original: &ClientOriginal,
    ) -> Result<(), OperationFailure> {
        let scratch =
            NodeRuntime::capture_serialization_storage(expected, self.maximum).map_err(unknown)?;
        self.retained
            .checked_add(scratch)
            .filter(|n| *n <= self.maximum)
            .ok_or_else(|| refused("archived common request comparison storage exhausted"))?;
        let expected = serde_json::to_value(expected).map_err(unknown)?;
        if expected.as_object() != Some(&original.request.body) {
            return Err(refused(
                "archived common request differs from original CNP body",
            ));
        }
        Ok(())
    }
}

impl PacketCompleteArchivedSemantics {
    /// Correlates lifecycle, inputs, operations and counters with original RPC owners.
    ///
    /// Full model projection and the native before/after transition remain
    /// separate source-specific checks. The host owner has already passed the
    /// complete-class parser and literal-journal validation before this call.
    ///
    /// # Errors
    /// Refuses another node, absent/foreign original requests or replies, changed
    /// results, incomplete poll populations, unclosed cancellation or finite excess.
    pub fn authenticate_protocol_data(
        &self,
        host: &HistoricalControllerState,
        additional_retained_bytes: usize,
        maximum_total_bytes: usize,
    ) -> Result<(), OperationFailure> {
        // Counts invoked by comparisons can format U64 values; request_id also
        // owns one finite ASCII identifier. Reserve both before either helper.
        let retained = additional_retained_bytes
            .checked_add(self.reserved_decoder_bytes)
            .and_then(|n| n.checked_add(20 + 256))
            .filter(|n| *n <= maximum_total_bytes)
            .ok_or_else(|| refused("archived common protocol comparison credit exhausted"))?;
        let budget = ComparisonBudget {
            retained,
            maximum: maximum_total_bytes,
        };
        host.require_complete_reader_state().map_err(unknown)?;
        let state = &self.semantic;
        if state
            .inputs
            .values()
            .any(|input| input.original.node != host.node)
            || state
                .operations
                .values()
                .any(|operation| operation.route.node != host.node)
        {
            return Err(refused("archived common CNP node differs"));
        }
        let activation = state
            .active
            .as_ref()
            .ok_or_else(|| refused("archived common activation absent"))?;
        let arm = original(
            host,
            "activate",
            &activation.activation_id,
            Method::Activate,
        )?;
        budget.compare(
            &activation.activation_id,
            arm.request
                .body
                .get("activation_id")
                .ok_or_else(|| refused("original Activate identity absent"))?,
        )?;
        budget.compare(
            &activation.generation,
            arm.request
                .body
                .get("world_generation")
                .ok_or_else(|| refused("original Activate generation absent"))?,
        )?;
        let ready = state
            .ready
            .as_ref()
            .ok_or_else(|| refused("archived common Ready absent"))?;
        let prepared = state
            .prepared_owner
            .as_ref()
            .ok_or_else(|| refused("archived common prepared owner absent"))?;
        budget.compare(&prepared.prepared_token, field(arm, "prepared_token")?)?;
        budget.compare(
            &activation.world_binding_hash,
            field(arm, "world_binding_hash")?,
        )?;
        budget.compare(
            &ready.ready_receipt,
            result(arm)?
                .get("activation_receipt")
                .ok_or_else(|| refused("original Activate receipt absent"))?,
        )?;
        if ready.ready_receipt != ready.state_inventory || ready.boundary != activation.boundary {
            return Err(refused(
                "archived common Ready inventory or boundary differs",
            ));
        }
        let activate = original(
            host,
            "world-activate",
            &activation.activation_id,
            Method::WorldActivate,
        )?;
        budget.compare(&prepared.prepared_token, field(activate, "prepared_token")?)?;
        budget.compare(&activation.activation_id, field(activate, "activation_id")?)?;
        budget.compare(&activation.generation, field(activate, "world_generation")?)?;
        budget.compare(
            &activation.world_binding_hash,
            field(activate, "world_binding_hash")?,
        )?;
        authenticate_activation_manifest(host, activate, activation, prepared, &budget)?;
        budget.compare(
            state
                .activate_response
                .as_ref()
                .ok_or_else(|| refused("archived activation response absent"))?,
            result(activate)?,
        )?;

        for (stage, input) in &state.inputs {
            let staged = original(host, "input", stage, Method::Input)?;
            budget.compare_body(&input.request, staged)?;
            if let Some(response) = &input.response {
                budget.compare(response, result(staged)?)?;
            }
            if let Some(commitment) = &input.commitment {
                let committed = original(host, "input-consumed", stage, Method::Input)?;
                if committed.request.request_id.0.as_ref() != Some(&commitment.request_id)
                    || committed.request.extensions != commitment.extensions
                {
                    return Err(refused("archived common input commitment envelope differs"));
                }
                budget.compare_body(&input.request, committed)?;
                if let Some(response) = &commitment.response {
                    budget.compare(response, result(committed)?)?;
                }
            }
        }
        let watermark = state
            .inputs
            .values()
            .filter(|input| input.acknowledgement.is_some())
            .map(|input| input.watermark)
            .max()
            .unwrap_or(crucible_node_contract::U64::new(0));
        if state.watermark != watermark {
            return Err(refused("archived common input watermark differs"));
        }

        for (operation_id, operation) in &state.operations {
            let begin = original(host, "begin", operation_id, Method::Begin)?;
            if begin.request.operation_id.0.as_ref() != Some(operation_id) {
                return Err(refused("archived Begin operation scope differs"));
            }
            budget.compare_body(&operation.begin, begin)?;
            if operation.begin_acknowledged {
                result(begin)?;
            }
            counter_population(
                host,
                "cnp-poll-",
                operation_id,
                operation.polls.get(),
                Method::Poll,
                Some(operation_id),
            )?;
            match (operation.cancellation.0.as_str(), &operation.cancellation.1) {
                ("not-attempted", None) => {
                    let cancel_id =
                        super::super::super::preparation::request_id("cancel", operation_id)?;
                    if host.custody.controller.contains_key(&cancel_id) {
                        return Err(refused("archived common cancellation attempt omitted"));
                    }
                }
                ("pending", None) | ("failed", Some(_)) => {
                    return Err(refused(
                        "archived cancellation has no supported closed correlation",
                    ));
                }
                ("requested", None) | ("unsupported", None) => {
                    let cancelled = original(host, "cancel", operation_id, Method::Cancel)?;
                    let requested = operation.cancellation.0 == "requested";
                    budget.compare(
                        &requested,
                        result(cancelled)?
                            .get("cancel_requested")
                            .ok_or_else(|| refused("original cancellation result absent"))?,
                    )?;
                }
                _ => return Err(refused("archived common cancellation state differs")),
            }
            if let Some(retirement) = &operation.retirement {
                let retired = original(host, "retire", operation_id, Method::Retire)?;
                budget.compare(
                    &retirement.reference,
                    retired
                        .request
                        .body
                        .get("custody_receipt")
                        .ok_or_else(|| refused("original retirement receipt absent"))?,
                )?;
                if operation.acknowledged {
                    result(retired)?;
                }
            } else if operation.acknowledged {
                return Err(refused("archived acknowledged operation omits retirement"));
            }
        }
        counter_population(
            host,
            "cnp-observe-",
            &activation.activation_id,
            state.observe_sequence.get(),
            Method::Observe,
            None,
        )?;
        if let Some((source, observation)) = &state.observation {
            if source != activation
                || observation.node != host.node
                || state.observe_sequence.get() == 0
            {
                return Err(refused("archived common observation source differs"));
            }
            let request_id = Id::new(format!(
                "cnp-observe-{}-{}",
                activation.activation_id, state.observe_sequence
            ))
            .map_err(unknown)?;
            let original = host
                .custody
                .controller
                .get(&request_id)
                .ok_or_else(|| refused("archived latest Observe request absent"))?;
            let response = result(original)?;
            let observations = response
                .get("observations")
                .and_then(Value::as_array)
                .filter(|observations| observations.len() == 1)
                .ok_or_else(|| refused("archived latest Observe population differs"))?;
            if response.get("complete").and_then(Value::as_bool) != Some(true) {
                return Err(refused("archived latest Observe result is incomplete"));
            }
            budget.compare(
                &observation.proof_ref,
                observations[0]
                    .get("measurement_ref")
                    .ok_or_else(|| refused("archived latest Observe native measurement absent"))?,
            )?;
        }
        Ok(())
    }
}

fn field<'a>(original: &'a ClientOriginal, name: &str) -> Result<&'a Value, OperationFailure> {
    original
        .request
        .body
        .get(name)
        .ok_or_else(|| refused("archived original request field absent"))
}

fn authenticate_activation_manifest(
    host: &HistoricalControllerState,
    activate: &ClientOriginal,
    activation: &crate::node_contract::SavedRuntimeActivation,
    prepared: &crucible_node_contract::PreparedOwner,
    budget: &ComparisonBudget,
) -> Result<(), OperationFailure> {
    use crucible_node_contract::{ActivationManifest, ContentRef, canonical};
    use serde::Deserialize;

    let manifest_value = field(activate, "activation_manifest")?;
    let reference_storage =
        NodeRuntime::capture_serialization_storage(manifest_value, budget.maximum)
            .map_err(unknown)?;
    budget
        .retained
        .checked_add(reference_storage)
        .and_then(|n| n.checked_add(std::mem::size_of::<ContentRef>()))
        .filter(|n| *n <= budget.maximum)
        .ok_or_else(|| refused("archived activation reference storage exhausted"))?;
    let reference = ContentRef::deserialize(manifest_value).map_err(unknown)?;
    let bytes = host.custody.content.get(&reference).map_err(unknown)?;
    let decoded = super::decode_storage(bytes, budget.maximum).map_err(unknown)?;
    budget
        .retained
        .checked_add(reference_storage)
        .and_then(|n| n.checked_add(decoded))
        .filter(|n| *n <= budget.maximum)
        .ok_or_else(|| refused("archived activation manifest storage exhausted"))?;
    reference.verify(bytes).map_err(unknown)?;
    let manifest: ActivationManifest = canonical::decode(bytes, bytes.len()).map_err(unknown)?;
    if manifest.activation_id != activation.activation_id
        || manifest.world_generation != activation.generation
        || manifest.world_binding_hash != activation.world_binding_hash
        || manifest.owners.len() != activation.owners.len()
        || !manifest.owners.contains(prepared)
        || manifest.owners.iter().any(|one| {
            !activation.owners.iter().any(|owner| {
                one.owner_id == owner.owner
                    && one.incarnation_id == owner.incarnation
                    && one.owner_generation == owner.generation
            })
        })
    {
        return Err(refused("archived complete activation manifest differs"));
    }
    let manifest_budget = ComparisonBudget {
        retained: budget
            .retained
            .checked_add(reference_storage)
            .and_then(|n| n.checked_add(decoded))
            .ok_or_else(|| refused("archived activation comparison extent overflow"))?,
        maximum: budget.maximum,
    };
    manifest_budget.compare(&manifest.transaction_id, field(activate, "transaction_id")?)?;
    manifest_budget.compare(&manifest.gate_id, field(activate, "gate_id")?)?;
    Ok(())
}

fn original<'a>(
    host: &'a HistoricalControllerState,
    prefix: &str,
    identity: &Id,
    method: Method,
) -> Result<&'a ClientOriginal, OperationFailure> {
    let request_id = super::super::super::preparation::request_id(prefix, identity)?;
    let original = host
        .custody
        .controller
        .get(&request_id)
        .ok_or_else(|| refused("archived common original request absent"))?;
    if original.request.message != MessageKind::Request
        || original.request.method != method
        || original.request.request_id.0.as_ref() != Some(&request_id)
    {
        return Err(refused("archived common original request identity differs"));
    }
    Ok(original)
}

fn result(original: &ClientOriginal) -> Result<&Value, OperationFailure> {
    let response = original
        .response
        .as_ref()
        .ok_or_else(|| refused("archived original CNP response absent"))?;
    if response.message != MessageKind::Response
        || response.method != original.request.method
        || response.request_id != original.request.request_id
        || response.operation_id != original.request.operation_id
        || !matches!(
            response.body.get("status").and_then(Value::as_str),
            Some("accepted" | "completed")
        )
    {
        return Err(refused(
            "archived original CNP response correlation differs",
        ));
    }
    response
        .body
        .get("result")
        .ok_or_else(|| refused("archived original CNP result absent"))
}

fn counter_population(
    host: &HistoricalControllerState,
    prefix: &str,
    identity: &Id,
    count: u64,
    method: Method,
    operation: Option<&Id>,
) -> Result<(), OperationFailure> {
    if count > host.custody.controller.len() as u64 {
        return Err(refused(
            "archived common counter exceeds original request population",
        ));
    }
    let mut observed = 0_u64;
    for (request_id, original) in &host.custody.controller {
        // Operation IDs can prefix one another. Correlate the actual envelope
        // before interpreting the source-generated decimal request suffix.
        if original.request.method != method
            || original.request.operation_id.0.as_ref() != operation
        {
            continue;
        }
        let Some((scope, suffix)) = request_id
            .as_str()
            .strip_prefix(prefix)
            .and_then(|tail| tail.rsplit_once('-'))
        else {
            continue;
        };
        if scope != identity.as_str() {
            continue;
        }
        if suffix.is_empty()
            || !suffix.bytes().all(|byte| byte.is_ascii_digit())
            || suffix.len() > 1 && suffix.starts_with('0')
        {
            return Err(refused("archived common counter has noncanonical identity"));
        }
        let sequence = suffix.parse::<u64>().map_err(unknown)?;
        if sequence == 0
            || sequence > count
            || original.request.message != MessageKind::Request
            || original.request.request_id.0.as_ref() != Some(request_id)
            || original.request.operation_id.0.as_ref() != operation
        {
            return Err(refused("archived common counter request differs"));
        }
        observed = observed
            .checked_add(1)
            .ok_or_else(|| refused("archived common counter overflow"))?;
    }
    if observed != count {
        return Err(refused("archived common counter population incomplete"));
    }
    Ok(())
}

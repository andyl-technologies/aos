//! Lends a signed Observe17 only after its actual terminal and proof drain.
//!
//! The same Source-owned SDK attempt retains assignment, every partial reply,
//! proof transfer and the saved completion frontier. This borrower authenticates
//! transport and full output correspondence. The Source independently checks its
//! private MAC, current native read and genuine Window17 completion fence.

use super::*;
use crate::reference_packet::service::restored_input_reactive17::PacketRestoredInputReactive17Command;

/// Borrows the actual signed original, complete terminal and transferred proof.
///
/// No constructor, decoder, clone or conversion can manufacture this loan.
/// Historical archive data cannot become this current SDK borrower.
pub struct OriginalCompletedRestoredObservation17Data<'a> {
    controller: &'a CnpController,
    original: &'a Envelope,
    terminal: &'a Envelope,
    typed: &'a ResponseBody,
    request: &'a PacketRestoredInputReactive17Request,
    measurement: &'a ContentRef,
    frontier: U64,
}

impl CnpController {
    /// Borrows one Source-retained signed Observe at its saved current frontier.
    ///
    /// This method neither sends a request nor renews an operational cut. The
    /// artifact is the Source's independently retained complete signed owner;
    /// exact comparison with the SDK original precedes every output loan.
    ///
    /// # Errors
    /// Refuses another Controller/emitter, partial or stale custody, changed
    /// negotiation, a legacy/other command, changed signed original, malformed
    /// terminal or absent hash-verified transferred measurement.
    pub fn original_completed_restored_observation17_data<'a>(
        &'a self,
        emitter: &OriginalCanonicalBlobAckEmitter,
        attempt: &'a OriginalRestoredSuffixHostAttempt,
        artifact: &'a PacketRestoredInputReactive17Artifact,
    ) -> Result<OriginalCompletedRestoredObservation17Data<'a>, ProviderError> {
        let selection = self.session.fresh_restore_query_selection()?;
        authenticate_restored_input_reactive17_selection_data(selection, self.authority())?;
        let (original, terminal, typed) = attempt.authenticate_current_pair_data(self, emitter)?;
        artifact.validate_data()?;
        artifact.request.authenticate_assigned_data(original)?;
        if artifact.request.command != PacketRestoredInputReactive17Command::Observe
            || original.method != Method::Observe
            || original.operation_id.0.is_some()
            || original.extensions.len() != 1
            || original.extensions.get(RESTORED_INPUT_REACTIVE17_FEATURE)
                != Some(
                    &serde_json::to_value(artifact)
                        .map_err(crucible_node_format::ContractError::from)?,
                )
            || !terminal.extensions.is_empty()
        {
            return Err(refused());
        }
        let request: ObserveRequest = serde::Deserialize::deserialize(&original.body)
            .map_err(crucible_node_format::ContractError::from)?;
        if request.after_observation_sequence != U64::new(0)
            || request.maximum_items != U64::new(1)
            || request.binding_hash != artifact.request.scope.target.binding_hash
            || request.owner_generation != artifact.request.scope.target.owner_generation
            || !request.extensions.is_empty()
        {
            return Err(refused());
        }
        let measurement = authenticate_terminal_data(original, typed, &artifact.request)?;
        if attempt.roots.as_slice() != std::slice::from_ref(measurement) {
            return Err(refused());
        }
        let raw = self.custody.content().get(measurement)?;
        measurement.verify(raw)?;
        let frontier = attempt.completed_frontier.ok_or_else(refused)?;
        if frontier <= original.sequence
            || frontier != self.session.fresh_restore_query_sequence()?
        {
            return Err(refused());
        }
        Ok(OriginalCompletedRestoredObservation17Data {
            controller: self,
            original,
            terminal,
            typed,
            request: &artifact.request,
            measurement,
            frontier,
        })
    }
}

impl OriginalCompletedRestoredObservation17Data<'_> {
    /// Borrows the exact original, raw terminal and separately decoded result.
    pub fn pair_data(&self) -> (&Envelope, &Envelope, &ResponseBody) {
        (self.original, self.terminal, self.typed)
    }

    /// Borrows the complete signed request selected by this actual original.
    pub fn request_data(&self) -> &PacketRestoredInputReactive17Request {
        self.request
    }

    /// Borrows the full measurement identity in the actual terminal batch.
    pub fn measurement_data(&self) -> &ContentRef {
        self.measurement
    }

    /// Returns the actual saved frontier after all proof/ACK traffic completed.
    pub fn frontier_data(&self) -> U64 {
        self.frontier
    }

    /// Borrows the complete inventory hash in this actual typed terminal.
    ///
    /// # Errors
    /// Refuses changed private typed-result custody. The Source compares this
    /// value with its independently verified complete expected native inventory.
    pub fn inventory_hash_data(&self) -> Result<&crucible_node_format::HashRef, ProviderError> {
        let Some(MethodResult::Observe(result)) = &self.typed.result else {
            return Err(refused());
        };
        Ok(&result.inventory_hash)
    }

    /// Borrows only this terminal's hash-verified complete restored proof bytes.
    ///
    /// # Errors
    /// Refuses missing or changed actual transferred content without performing
    /// IO, reconstructing an owner or advancing the saved frontier.
    pub fn restored_record_bytes_data(&self) -> Result<&[u8], ProviderError> {
        let bytes = self.controller.custody.content().get(self.measurement)?;
        self.measurement.verify(bytes)?;
        Ok(bytes)
    }
}

fn authenticate_terminal_data<'a>(
    original: &Envelope,
    typed: &'a ResponseBody,
    request: &PacketRestoredInputReactive17Request,
) -> Result<&'a ContentRef, ProviderError> {
    if !matches!(&typed.shape, ResponseShape::Completed {
        operation_state: OperationState::Completed, extensions, ..
    } if extensions.is_empty())
    {
        return Err(refused());
    }
    let Some(MethodResult::Observe(result)) = &typed.result else {
        return Err(refused());
    };
    let [batch] = result.observations.as_slice() else {
        return Err(refused());
    };
    let target = &request.scope.target;
    if !result.complete
        || result.next_sequence != U64::new(1)
        || batch.schema_version != 1
        || batch.execution_owner_id != target.owner
        || batch.owner_binding_hash != target.binding_hash
        || batch.world_binding_hash != target.world
        || batch.activation_id != target.activation
        || batch.world_generation != target.generation
        || batch.owner_generation != target.owner_generation
        || Some(&batch.operation_id) != original.request_id.0.as_ref()
        || batch.grant_id.is_some()
        || batch.first_sequence != U64::new(0)
        || batch.last_sequence != U64::new(0)
        || !batch.events.is_empty()
        || batch.visibility != crucible_node_format::Visibility::Staged
        || !batch.extensions.is_empty()
    {
        return Err(refused());
    }
    batch.measurement_ref.validate()?;
    if batch.measurement_ref.media_type != "application/json"
        || batch.measurement_ref.length.get() == 0
        || batch.measurement_ref.length.get() > 65_536
    {
        return Err(refused());
    }
    Ok(&batch.measurement_ref)
}

impl OriginalCompletedRestoredObservation17Data<'_> {
    /// Names the actual completed borrower and its defining fixed validation views.
    pub fn counter_scratch_data() -> usize {
        size_of::<OriginalCompletedRestoredObservation17Data<'static>>()
            + size_of::<Result<OriginalCompletedRestoredObservation17Data<'static>, ProviderError>>(
            )
            + size_of::<&OriginalRestoredSuffixHostAttempt>()
            + size_of::<&PacketRestoredInputReactive17Artifact>()
            + size_of::<&PacketRestoredInputReactive17Request>()
            + size_of::<(&Envelope, &Envelope, &ResponseBody)>()
            + size_of::<Result<(&Envelope, &Envelope, &ResponseBody), ProviderError>>()
            + size_of::<ObserveRequest>()
            + size_of::<Result<ObserveRequest, serde_json::Error>>()
            + size_of::<Value>()
            + size_of::<Result<Value, serde_json::Error>>()
            + size_of::<&ObserveResult>()
            + size_of::<&crucible_node_format::ObservationBatch>()
            + size_of::<&ContentRef>()
            + size_of::<Result<&ContentRef, ProviderError>>()
            + size_of::<Result<&[u8], ProviderError>>()
            + size_of::<Option<U64>>()
            + size_of::<U64>()
            + size_of::<Result<(), ProviderError>>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_node_format::{ObservationBatch, Visibility};

    // These are terminal-correspondence DATA fixtures, never live SDK loans or
    // signed/native/Window permissions. Real completion requires the constructor.
    fn terminal_data() -> (Envelope, PacketRestoredInputReactive17Request, ResponseBody) {
        let (mut request, mut original) =
            crate::reference_packet::service::restored_input_reactive17::tests::fixture().unwrap();
        request.command = PacketRestoredInputReactive17Command::Observe;
        original.method = Method::Observe;
        let target = &request.scope.target;
        let reference = canonical::content_ref(b"{}", "application/json").unwrap();
        let result = ObserveResult {
            observations: vec![ObservationBatch {
                schema_version: 1,
                execution_owner_id: target.owner.clone(),
                owner_binding_hash: target.binding_hash.clone(),
                world_binding_hash: target.world.clone(),
                activation_id: target.activation.clone(),
                world_generation: target.generation,
                owner_generation: target.owner_generation,
                operation_id: original.request_id.0.as_ref().unwrap().clone(),
                grant_id: None,
                first_sequence: U64::new(0),
                last_sequence: U64::new(0),
                events: vec![],
                visibility: Visibility::Staged,
                measurement_ref: reference.clone(),
                extensions: Extensions::new(),
            }],
            next_sequence: U64::new(1),
            complete: true,
            inventory_hash: reference.hash,
        };
        let result_value = serde_json::to_value(&result)
            .unwrap()
            .as_object()
            .unwrap()
            .clone();
        let typed = ResponseBody {
            shape: ResponseShape::Completed {
                operation_state: OperationState::Completed,
                result: result_value,
                extensions: Extensions::new(),
            },
            result: Some(MethodResult::Observe(result)),
        };
        (original, request, typed)
    }

    #[test]
    fn terminal_data_requires_exact_target_and_grant_free_single_batch() {
        let (original, request, typed) = terminal_data();
        assert!(authenticate_terminal_data(&original, &typed, &request).is_ok());

        for change in 0..6 {
            let (_, _, mut changed) = terminal_data();
            let Some(MethodResult::Observe(result)) = &mut changed.result else {
                unreachable!();
            };
            match change {
                0 => result.complete = false,
                1 => result.next_sequence = U64::new(2),
                2 => result.observations[0].grant_id = Some(Id::new("foreign/grant").unwrap()),
                3 => result.observations[0].world_generation = U64::new(u64::MAX),
                4 => result.observations[0].operation_id = Id::new("foreign/original").unwrap(),
                5 => result.observations.push(result.observations[0].clone()),
                _ => unreachable!(),
            }
            assert!(authenticate_terminal_data(&original, &changed, &request).is_err());
        }
    }

    #[test]
    fn terminal_data_rejects_error_shape_extensions_and_nonjson_measurement() {
        let (original, request, mut typed) = terminal_data();
        if let ResponseShape::Completed { extensions, .. } = &mut typed.shape {
            extensions.insert("unselected".into(), Value::Null);
        }
        assert!(authenticate_terminal_data(&original, &typed, &request).is_err());

        let (original, request, mut typed) = terminal_data();
        let Some(MethodResult::Observe(result)) = &mut typed.result else {
            unreachable!();
        };
        result.observations[0].measurement_ref =
            canonical::content_ref(b"{}", "application/octet-stream").unwrap();
        assert!(authenticate_terminal_data(&original, &typed, &request).is_err());
    }
}

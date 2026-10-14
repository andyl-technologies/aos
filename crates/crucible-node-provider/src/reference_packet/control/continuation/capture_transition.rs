//! Checks the exact pending-Control to completed-Capture historical transition.
//!
//! Source journal validation calls this before issuing any archive/fresh ticket.
//! It checks data only and never reconstructs a native owner or a permission.

use super::*;
use crate::envelope::MessageKind;

/// Borrows every genuine data input for the single native Capture transition.
pub struct PacketOriginalCaptureTransitionData<'a> {
    /// Borrows the original registered Capture request, including actual sequence.
    pub capture_request: &'a Envelope,
    /// Borrows the actual final post-prefix terminal response.
    pub terminal: &'a Envelope,
    /// Names the complete native snapshot transferred by the first proof object.
    pub manifest_ref: &'a ContentRef,
    /// Names this decoder's complete original pending Control body.
    pub control_ref: &'a ContentRef,
    /// Names the independently transferred unchanged-cut anchor.
    pub anchor_ref: &'a ContentRef,
    /// Borrows all exact canonical anchor bytes.
    pub anchor_bytes: &'a [u8],
    /// Bounds independently admitted typed model projection scratch.
    pub maximum_model_bytes: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OriginalAnchorData {
    schema: String,
    native_pid: U64,
    request: Envelope,
    request_hash: HashRef,
    capture: CaptureArguments,
    world: HashRef,
    binding: HashRef,
    local_cursor: Position,
    control_snapshot: ContentRef,
    inventory_hash: HashRef,
}

impl PacketDecodedControlSnapshot {
    /// Authenticates the exact single Capture settlement over retained data.
    ///
    /// The source separately joins original SDK before/after states, complete
    /// literal proof/ACK/Poll suffix, semantic ancestry, Core ticket and fresh
    /// owner. Success here never grants an installation or archive permission.
    ///
    /// # Errors
    /// Refuses another full body, pending record, request/cut/scope, model
    /// inventory, original terminal or any changed promised reference.
    pub fn authenticate_original_capture_transition_data(
        &self,
        data: PacketOriginalCaptureTransitionData<'_>,
    ) -> Result<(), ProviderError> {
        let request = data.capture_request;
        request.validate()?;
        data.terminal.validate()?;
        request.matches_response(data.terminal)?;
        let decoded = decode_request(request.method, &request.body)?;
        let RequestBody::Begin(begin) = &decoded else {
            return Err(refused());
        };
        let BeginArguments::Capture(arguments) = begin.decoded_arguments()? else {
            return Err(refused());
        };
        if request.message != MessageKind::Request
            || request.method != Method::Begin
            || !request.extensions.is_empty()
            || !data.terminal.extensions.is_empty()
            || data.terminal.message != MessageKind::Response
        {
            return Err(refused());
        }
        let request_id = request.request_id.0.as_ref().ok_or_else(refused)?;
        let operation = request.operation_id.0.as_ref().ok_or_else(refused)?;
        let control = &self.record.control;
        let binding = control
            .selection
            .realization
            .bindings
            .first()
            .ok_or_else(refused)?;
        let owner = control
            .selection
            .realization
            .owner_bindings
            .first()
            .ok_or_else(refused)?;
        let original = control
            .originals
            .iter()
            .find(|row| &row.request == request_id)
            .ok_or_else(refused)?;
        let unknown = object(ResponseShape::Error {
            operation_state: OperationState::Unknown,
            error: ErrorRecord {
                code: "OUTCOME_UNKNOWN".into(),
                message: "original native Capture remains unresolved".into(),
                effect: EffectCertainty::Unknown,
                retryable: false,
                details: Map::new(),
            },
            extensions: Extensions::new(),
        })?;
        if original.identity != request.request_hash(RequestOrigin::Controller)?
            || !original.evidence.is_empty()
            || original.response_body != unknown
            || control
                .originals
                .iter()
                .filter(|row| &row.request == request_id)
                .count()
                != 1
            || control.current_operation.as_ref() != Some(operation)
            || control.begins.get(operation) != Some(begin)
            || control.begin_requests.get(operation) != Some(request_id)
            || control.terminals.contains_key(operation)
            || control.fenced
            || !control.immediate
            || request.session_id.0.as_ref() != Some(&binding.authority.session_id)
            || request.incarnation_id.0.as_ref() != Some(&binding.authority.incarnation_id)
            || request.node_id.0.as_ref() != Some(&binding.compatibility.node_id)
            || request.capture_owner_id.0.as_ref() != Some(&binding.compatibility.capture_owner.id)
            || request.execution_owner_id.0.is_some()
            || begin.binding_hash != owner.identity()?
            || begin.owner_generation != binding.authority.owner_generation
            || arguments.participant_ids != owner.owner.participant_ids
            || arguments.cut != self.record.administrative_cut
            || arguments.preservation_contract.as_str()
                != "source-owned.packet-complete-original-lineage/5"
            || control.active.as_ref().is_none_or(|active| {
                begin.activation_id.0.as_ref() != Some(&active.activation_id)
                    || begin.world_generation != active.world_generation
                    || active.world_binding_hash != control.selection.world
            })
        {
            return Err(refused());
        }

        let maximum = usize::try_from(data.control_ref.length.get()).map_err(|_| refused())?;
        if maximum == 0 || maximum > MAXIMUM_BYTES {
            return Err(refused());
        }
        crate::connection::serialized_credit(&self.record, maximum)?;
        let value = serde_json::to_value(&self.record).map_err(ContractError::from)?;
        let bytes = canonical::canonical_json(&value)?;
        data.control_ref.verify(&bytes)?;
        if canonical::content_ref(&bytes, "application/json")? != *data.control_ref
            || data.manifest_ref == data.control_ref
            || data.manifest_ref == data.anchor_ref
            || data.control_ref == data.anchor_ref
        {
            return Err(refused());
        }

        if data.anchor_bytes.len() > 8192 {
            return Err(refused());
        }
        data.anchor_ref.verify(data.anchor_bytes)?;
        if data.anchor_bytes.len() > 8192
            || canonical::content_ref(data.anchor_bytes, "application/json")? != *data.anchor_ref
        {
            return Err(refused());
        }
        let anchor_value = canonical::parse_json(data.anchor_bytes, 8192)?;
        if canonical::canonical_json(&anchor_value)? != data.anchor_bytes {
            return Err(refused());
        }
        let anchor = OriginalAnchorData::deserialize(anchor_value).map_err(ContractError::from)?;
        let model = self.model.capture_boundary_data(data.maximum_model_bytes)?;
        if anchor.schema != "source-owned.packet-native-unchanged-cut/5"
            || anchor.native_pid != self.record.captured_process
            || anchor.request != *request
            || anchor.capture != arguments
            || anchor.request_hash != original.identity
            || anchor.world != control.selection.world
            || anchor.binding != owner.identity()?
            || anchor.local_cursor != self.record.local_cursor
            || anchor.control_snapshot != *data.control_ref
            || anchor.inventory_hash != model.inventory_hash
            || model.local_cursor != self.record.local_cursor
            || model.gate_closed
            || model.retained_outputs != 0
            || model.local_cursor > arguments.cut
            || model
                .earliest_pending_completion
                .is_some_and(|completion| completion < arguments.cut)
        {
            return Err(refused());
        }

        let response = decode_response(&decoded, &data.terminal.body)?;
        let Some(MethodResult::Capture(result)) = response.result else {
            return Err(refused());
        };
        if !matches!(
            response.shape,
            ResponseShape::Completed {
                operation_state: OperationState::Completed,
                ..
            }
        ) || result.capture_manifest != *data.manifest_ref
            || result.owner_state_refs.as_slice() != [data.control_ref.clone()]
            || result.unchanged_cut_receipt != *data.anchor_ref
        {
            return Err(refused());
        }
        Ok(())
    }
}

fn refused() -> ProviderError {
    ProviderError::Correlation("native original Capture transition data differs")
}

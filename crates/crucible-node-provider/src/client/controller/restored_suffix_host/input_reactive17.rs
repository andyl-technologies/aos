//! Seals a distinct Source-signed17 action on the actual SDK-assigned original.
//!
//! Assignment and publication use the same finite journal, immutable original,
//! retained partial, and original operational cut as ordinary suffix transport.
//! The old public assignment guards are unchanged. This marker adds only its
//! separately selected artifact and never creates a Core or native action claim.

use super::*;
use crate::reference_packet::service::restored_input_reactive17::{
    PacketRestoredInputReactive17Artifact, PacketRestoredInputReactive17Context,
    PacketRestoredInputReactive17Request, RESTORED_INPUT_REACTIVE17_FEATURE,
    authenticate_restored_input_reactive17_selection_data,
    restored_input_reactive17_assigned_request_digest_data,
    restored_input_reactive17_context_schema_data,
};

/// Keeps the actual assigned action and its retained Source destination borrowed.
///
/// Its constructor is the genuine Controller assignment below. Dropping or
/// failing this marker leaves the same initialized attempt and original cut.
#[must_use = "retain the same assigned SDK attempt through signing and publication"]
pub struct PreparedOriginalRestoredInputReactive17HostAttempt<'a> {
    inner: PreparedOriginalRestoredSuffixHostAttempt<'a>,
    seal_started: bool,
    sealed: bool,
}

impl CnpController {
    /// Assigns one independently admitted action for its actual Source signature.
    ///
    /// The caller must already retain and fund the exact request, DTO/DOM/codec
    /// banks and SDK attempt. This method owns transport assignment only.
    ///
    /// # Errors
    /// Refuses missing exact negotiation, another command, stale actual SDK
    /// sequence, a reused slot, invalid body or an expired original deadline.
    pub fn prepare_original_restored_input_reactive17_into<'a>(
        &'a mut self,
        emitter: &OriginalCanonicalBlobAckEmitter,
        request_id: Id,
        operation_id: Option<Id>,
        body: OriginalRestoredSuffixBody<'_>,
        request: &PacketRestoredInputReactive17Request,
        completed: &'a mut Option<OriginalRestoredSuffixHostAttempt>,
    ) -> Result<PreparedOriginalRestoredInputReactive17HostAttempt<'a>, ProviderError> {
        let selection = self.session.fresh_restore_query_selection()?;
        authenticate_restored_input_reactive17_selection_data(selection, self.authority())?;
        request.validate_data()?;
        if request.command.method_data() != body.method_data()?
            || request.history_next_sequence != self.session.fresh_restore_query_sequence()?
        {
            return Err(refused());
        }

        // Assignment creates the actual Envelope once. The empty extension is
        // never published: only this distinct marker can install and seal17.
        // The ordinary public SDK constructor keeps all its exact old guards.
        let mut inner = self.prepare_original_restored_suffix_into(
            emitter,
            request_id,
            operation_id,
            body,
            Extensions::new(),
            completed,
        )?;
        let original = inner.attempt.original.as_mut().ok_or_else(refused)?;
        original.extensions.insert(
            RESTORED_INPUT_REACTIVE17_FEATURE.into(),
            serde_json::json!({"request":request}),
        );
        request.authenticate_assigned_data(original)?;
        crate::connection::serialized_credit(original, inner.controller.maximum_frame()?)?;
        inner.original_data()?;
        Ok(PreparedOriginalRestoredInputReactive17HostAttempt {
            inner,
            seal_started: false,
            sealed: false,
        })
    }
}

impl PreparedOriginalRestoredInputReactive17HostAttempt<'_> {
    /// Borrows the actual complete assigned original for its Source-owned signer.
    ///
    /// # Errors
    /// Refuses changed assignment/cut or an action already entering publication.
    pub fn original_data(&self) -> Result<&Envelope, ProviderError> {
        self.inner.original_data()
    }

    /// Installs one complete Source artifact in that same actual assigned owner.
    ///
    /// This checks syntactic and assigned-digest correspondence, not the private
    /// Source MAC. The genuine native consumer verifies the actual Source key
    /// and independently spends its own current action row before dispatch.
    ///
    /// # Errors
    /// Refuses another seal attempt, changed request, wrong context digest,
    /// malformed proof or a complete sealed frame exceeding the negotiated cap.
    pub fn seal_data(
        &mut self,
        artifact: PacketRestoredInputReactive17Artifact,
    ) -> Result<(), ProviderError> {
        if self.seal_started {
            return Err(refused());
        }
        self.seal_started = true;
        self.inner.original_data()?;
        artifact.validate_data()?;
        let original = self.inner.attempt.original.as_ref().ok_or_else(refused)?;
        let request: PacketRestoredInputReactive17Request = serde::Deserialize::deserialize(
            original
                .extensions
                .get(RESTORED_INPUT_REACTIVE17_FEATURE)
                .and_then(Value::as_object)
                .and_then(|value| value.get("request"))
                .ok_or_else(refused)?,
        )
        .map_err(crucible_node_contract::ContractError::from)?;
        if artifact.request != request {
            return Err(refused());
        }
        let maximum = self.inner.controller.maximum_frame()?;
        let assigned = restored_input_reactive17_assigned_request_digest_data(original, maximum)?;
        let context = PacketRestoredInputReactive17Context {
            schema: restored_input_reactive17_context_schema_data().into(),
            request,
            assigned_request: crucible_node_contract::Bytes::new(assigned.to_vec()),
        };
        let value =
            serde_json::to_value(&context).map_err(crucible_node_contract::ContractError::from)?;
        let bytes = canonical::canonical_json(&value)?;
        if blake3::hash(&bytes) != *artifact.proof.context_digest.as_slice() {
            return Err(refused());
        }
        let value =
            serde_json::to_value(artifact).map_err(crucible_node_contract::ContractError::from)?;
        let original = self.inner.attempt.original.as_mut().ok_or_else(refused)?;
        original
            .extensions
            .insert(RESTORED_INPUT_REACTIVE17_FEATURE.into(), value);
        crate::connection::serialized_credit(original, maximum)?;
        if restored_input_reactive17_assigned_request_digest_data(original, maximum)? != assigned {
            return Err(refused());
        }
        self.inner.original_data()?;
        self.sealed = true;
        Ok(())
    }

    /// Publishes the same sealed original once under its unchanged assigned cut.
    ///
    /// # Errors
    /// Refuses an unsealed or failed seal, changed negotiation or uncertain IO.
    /// All actual raw/typed terminal and journal partials remain in the old slot.
    pub fn publish_data(
        &mut self,
        emitter: &OriginalCanonicalBlobAckEmitter,
    ) -> Result<(), ProviderError> {
        if !self.sealed {
            return Err(refused());
        }
        self.sealed = false;
        let selection = self
            .inner
            .controller
            .session
            .fresh_restore_query_selection()?;
        authenticate_restored_input_reactive17_selection_data(
            selection,
            self.inner.controller.authority(),
        )?;
        self.inner.publish_data(emitter)
    }

    /// Counts this actual marker and direct sealing/assignment borrowed views.
    pub fn counter_scratch_data() -> usize {
        size_of::<Self>()
            + size_of::<Result<Self, ProviderError>>()
            + size_of::<&mut Self>()
            + size_of::<PacketRestoredInputReactive17Artifact>()
            + size_of::<PacketRestoredInputReactive17Request>()
            + size_of::<PacketRestoredInputReactive17Context>()
            + size_of::<Result<PacketRestoredInputReactive17Request, serde_json::Error>>()
            + size_of::<Result<Value, serde_json::Error>>()
            + size_of::<Result<Vec<u8>, crucible_node_contract::ContractError>>()
            + size_of::<Result<[u8; 32], ProviderError>>()
            + size_of::<[u8; 32]>()
            + size_of::<blake3::Hash>()
            + size_of::<Value>()
            + size_of::<Vec<u8>>()
            + size_of::<Result<(), ProviderError>>()
            + size_of::<Option<&Value>>()
            + size_of::<Option<&serde_json::Map<String, Value>>>()
            + size_of::<Option<&Envelope>>()
            + size_of::<Option<&mut Envelope>>()
            + OriginalRestoredSuffixHostAttempt::counter_scratch_data()
    }
}

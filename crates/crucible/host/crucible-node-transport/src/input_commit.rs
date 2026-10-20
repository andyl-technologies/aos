//! Negotiated portable commitment to original staged native input.
//!
//! The CNP/1 Input body remains unchanged. A selected envelope extension carries
//! the later coordinator cut; the provider journals it separately from staging.
//! Receipt records are evidence of source-owned effects, not public authority.
//!
//! ```text
//! extensions = { "reference-device/input-commit/1": InputCommitIntentV1 }
//! ```

use crucible_node_format::*;
use serde::{Deserialize, Serialize};

use crate::envelope::Nullable;

/// Names the explicitly negotiated original-input commitment extension.
pub const INPUT_COMMIT_FEATURE: &str = "reference-device/input-commit/1";

/// Binds a later coordinator commitment to one actual original native input.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputCommitIntentV1 {
    /// Selects the closed wire edition.
    pub schema_version: u32,
    /// Names the original authenticated world session.
    pub session_id: Id,
    /// Names the actual surviving provider incarnation.
    pub incarnation_id: Id,
    /// Names the admitted logical target.
    pub node_id: Id,
    /// Names the complete native owner.
    pub execution_owner_id: Id,
    /// Fences earlier realizations of that owner.
    pub owner_generation: U64,
    /// Names the activated complete world.
    pub activation_id: Id,
    /// Fences prior world activations.
    pub world_generation: U64,
    /// Commits to the privately installed complete world.
    pub world_binding_hash: HashRef,
    /// Names the immutable coordinator staging operation.
    pub stage_operation_id: Id,
    /// Names the original accepted Input request.
    pub input_request_id: Id,
    /// Names the immutable public batch.
    pub batch_id: Id,
    /// Commits to the complete public batch actually held by the provider.
    pub batch_hash: HashRef,
    /// Retains the original provider-issued staging receipt.
    pub staging_receipt: ContentRef,
    /// Retains exact canonical coordinator delivery-inventory bytes.
    pub delivery_inventory: ContentRef,
    /// Locates the exclusive original input cut.
    pub cutoff: Position,
}

impl Validate for InputCommitIntentV1 {
    fn validate(&self) -> Result<(), ContractError> {
        self.world_binding_hash.validate()?;
        self.batch_hash.validate()?;
        self.staging_receipt.validate()?;
        self.delivery_inventory.validate()?;
        self.cutoff.validate()?;
        if self.schema_version != 1
            || self.owner_generation.get() == 0
            || self.world_generation.get() == 0
            || self.world_binding_hash.domain != "cnp.world-binding.v1"
            || self.batch_hash.domain != "cnp.input-batch.v1"
            || self.delivery_inventory.media_type != "application/vnd.crucible.input-inventory+json"
            || self.cutoff.phase != Phase::BoundaryControl
            || self.cutoff.microstep.get() != 0
        {
            return Err(crate::bodies::invalid(
                "input_commit",
                "foreign original input cut",
            ));
        }
        Ok(())
    }
}

/// Retains the source-issued commitment record and exact original staged bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputCommitRecordV1 {
    /// Selects the closed source receipt edition.
    pub schema_version: u32,
    /// Retains the complete authenticated later commitment.
    pub intent: InputCommitIntentV1,
    /// Names the source-owned original commitment request.
    pub request_id: Id,
    /// Commits to its complete immutable envelope, including the extension.
    pub request_hash: HashRef,
    /// Commits to the actual concatenated bytes held before any native execution.
    pub staged_bytes: ContentRef,
}

impl Validate for InputCommitRecordV1 {
    fn validate(&self) -> Result<(), ContractError> {
        self.intent.validate()?;
        self.request_hash.validate()?;
        self.staged_bytes.validate()?;
        if self.schema_version != 1 || self.request_hash.domain != "cnp.request.v1" {
            return Err(crate::bodies::invalid(
                "input_commit",
                "foreign source commitment receipt",
            ));
        }
        Ok(())
    }
}

/// Describes one public coordinator delivery without private process objects.
///
/// Nullable fields remain required in the closed canonical inventory grammar.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommittedDeliveryV1 {
    /// Names the original connection when present.
    pub connection_id: Nullable<Id>,
    /// Retains the admitted connection policy when present.
    pub connection_policy_ref: Nullable<ContentRef>,
    /// Retains the declared external root when present.
    pub external_root: Nullable<Endpoint>,
    /// Retains actual original native provenance.
    pub provenance_ref: ContentRef,
    /// Names the original public event.
    pub publication_id: Id,
    /// Names the original producer.
    pub producer: Id,
    /// Names the original consumer.
    pub consumer: Id,
    /// Retains the original public source endpoint.
    pub producer_endpoint: Endpoint,
    /// Retains the original public destination endpoint.
    pub consumer_endpoint: Endpoint,
    /// Retains the coordinator's delivery sequence.
    pub source_sequence: U64,
    /// Retains the independently allocated native sequence.
    pub native_sequence: U64,
    /// Retains the evaluation coordinate when applicable.
    pub evaluation: Nullable<Position>,
    /// Retains original causal membership.
    pub causal_parents: Vec<Position>,
    /// Locates original publication.
    pub publication: Position,
    /// Locates recipient delivery.
    pub delivery: Position,
    /// Commits to the original payload bytes.
    pub payload: ContentRef,
}

impl CommittedDeliveryV1 {
    /// Checks that the complete coordinator row maps to an actual retained event.
    ///
    /// # Errors
    /// Refuses changed endpoints, native sequence, lineage, payload or input cut.
    pub fn verify_event(
        &self,
        event: &Event,
        node: &Id,
        cutoff: Position,
    ) -> Result<(), ContractError> {
        if &self.consumer != node
            || self.producer != self.producer_endpoint.node_id
            || self.consumer != self.consumer_endpoint.node_id
            || self.publication_id != event.id
            || self.producer_endpoint != event.source
            || self.consumer_endpoint != event.destination
            || self.native_sequence != event.source_sequence
            || self.publication != event.publication_position
            || Some(self.delivery) != event.delivery_position
            || self.delivery != event.position
            || self.delivery >= cutoff
            || self.provenance_ref != event.provenance_ref
            || self.payload != event.payload
            || !self.causal_parents.is_empty()
            || !event.causal_parent_ids.is_empty()
            || !event.extensions.is_empty()
            || event.stage != EventStage::Delivery
        {
            return Err(crate::bodies::invalid(
                "delivery",
                "coordinator inventory changed original native input",
            ));
        }
        self.payload.validate()?;
        self.provenance_ref.validate()?;
        self.publication.validate()?;
        self.delivery.validate()?;
        if let Some(policy) = &self.connection_policy_ref.0 {
            policy.validate()?;
        }
        if let Some(root) = &self.external_root.0 {
            root.validate()?;
        }
        if let Some(evaluation) = &self.evaluation.0 {
            evaluation.validate()?;
        }
        Ok(())
    }
}

/// Validates the single selected commitment extension against the actual connection.
///
/// # Errors
/// Refuses foreign keys, unnegotiated features, non-Input requests or malformed cuts.
pub fn verify_envelope(
    authority: &crate::handshake::ConnectionAuthority,
    envelope: &crate::envelope::Envelope,
    body: &crate::connection::ReceivedBody,
) -> Result<(), crate::ProviderError> {
    if envelope.extensions.is_empty() {
        return Ok(());
    }
    if envelope.extensions.len() != 1
        || !authority
            .selected_features()
            .iter()
            .any(|feature| feature.as_str() == INPUT_COMMIT_FEATURE)
        || !matches!(body, crate::connection::ReceivedBody::Request(request) if matches!(request.as_ref(), crate::bodies::RequestBody::Input(_)))
    {
        return Err(crate::ProviderError::Frame(
            "unnegotiated original input commitment extension",
        ));
    }
    let value =
        envelope
            .extensions
            .get(INPUT_COMMIT_FEATURE)
            .ok_or(crate::ProviderError::Frame(
                "foreign input commitment extension",
            ))?;
    let intent: InputCommitIntentV1 =
        serde_json::from_value(value.clone()).map_err(ContractError::from)?;
    intent.validate()?;
    Ok(())
}

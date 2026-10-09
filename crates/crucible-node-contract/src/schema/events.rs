//! Portable events schemas and local integrity checks.
//!
//! ```json
//! { "schema_version": 1, "extensions": {} }
//! ```
//!
//! Complete objects require every field defined by RFC-0025; reference content
//! and live custody are verified separately by host admission.

use super::*;

fn validate_producer_sequences(events: &[Event]) -> Result<(), ContractError> {
    let mut sequences = std::collections::BTreeSet::new();
    for event in events {
        if !sequences.insert((&event.source.node_id, event.source_sequence)) {
            return Err(invalid(
                "source_sequence",
                "producer sequence repeats within the batch",
            ));
        }
    }
    Ok(())
}

/// Identifies an event publication or delivery stage.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventStage {
    /// Publishes produced output.
    Publication,
    /// Delivers admitted input.
    Delivery,
}

/// Distinguishes exclusive from inclusive prefix closure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClosureKind {
    /// Excludes the named position from closure.
    Before,
    /// Includes the named position in closure.
    Through,
}

/// Distinguishes provisional from committed publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Visibility {
    /// Retains output without authorizing peer delivery.
    Staged,
    /// Publishes under admitted host authority.
    Committed,
}

/// Classifies preserved pending custody.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PendingKind {
    /// Retains accepted input.
    Input,
    /// Retains provisional output.
    Output,
    /// Retains a modeled timer.
    Timer,
    /// Retains an outstanding I/O operation.
    Io,
    /// Retains an implementation-native operation.
    NativeOperation,
}

/// Preserves publication and delivery coordinates with causal lineage.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    /// Selects baseline event schema 1.
    #[serde(deserialize_with = "crate::deserialize_version")]
    pub schema_version: Version,
    /// Identifies the event within its logical producer.
    pub id: Id,
    /// Identifies the original logical producer lane.
    pub source: Endpoint,
    /// Identifies the admitted consumer lane.
    pub destination: Endpoint,
    /// Locates the current publication or delivery stage.
    pub position: Position,
    /// Selects publication or delivery semantics.
    pub stage: EventStage,
    /// Retains the original publication coordinate.
    pub publication_position: Position,
    /// Locates admitted delivery, or explicit null before conversion.
    #[serde(deserialize_with = "required_nullable")]
    pub delivery_position: Option<Position>,
    /// Identifies the unique captured producer sequence across all ports.
    pub source_sequence: U64,
    /// Lists same-time causal lineage; roots use an empty set.
    pub causal_parent_ids: IdSet,
    /// Binds exact payload bytes under the selected connection schema.
    pub payload: ContentRef,
    /// Binds original native receipt and input provenance.
    pub provenance_ref: ContentRef,
    /// Carries event extensions.
    pub extensions: Extensions,
}

/// Commits to an ordered batch without changing consumer timestamps.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputBatch {
    /// Selects baseline input-batch schema 1.
    #[serde(deserialize_with = "crate::deserialize_version")]
    pub schema_version: Version,
    /// Identifies the receiving execution owner.
    pub execution_owner_id: Id,
    /// Identifies the admitted input custody epoch.
    pub input_epoch: Id,
    /// Identifies this input batch.
    pub batch_id: Id,
    /// Orders batches within the admitted input stream.
    pub batch_sequence: U64,
    /// Preserves admitted event order.
    pub events: Vec<Event>,
    /// Carries input-batch extensions.
    pub extensions: Extensions,
}

/// Binds evidence justifying a closed input prefix.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputAuthorization {
    /// Selects baseline input-authorization schema 1.
    #[serde(deserialize_with = "crate::deserialize_version")]
    pub schema_version: Version,
    /// Identifies the execution owner.
    pub execution_owner_id: Id,
    /// Identifies the live owner generation.
    pub owner_generation: U64,
    /// Identifies the authenticated input epoch.
    pub input_epoch: Id,
    /// Records input custody progress without proving absence by itself.
    pub input_watermark: U64,
    /// Locates the justified closed input prefix.
    pub closed_input_prefix: Position,
    /// Selects exclusive or inclusive prefix semantics.
    pub closure_kind: ClosureKind,
    /// Binds the complete arbitration policy.
    pub arbitration_ref: ContentRef,
    /// Binds complete due-input and upstream closure evidence.
    pub bound_evidence_refs: Vec<ContentRef>,
    /// Carries authorization extensions.
    pub extensions: Extensions,
}

/// Binds ordered observations to complete owner and activation custody.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationBatch {
    /// Selects baseline observation-batch schema 1.
    #[serde(deserialize_with = "crate::deserialize_version")]
    pub schema_version: Version,
    /// Identifies the producing execution owner.
    pub execution_owner_id: Id,
    /// Commits to complete owner compatibility.
    pub owner_binding_hash: HashRef,
    /// Commits to world compatibility.
    pub world_binding_hash: HashRef,
    /// Identifies the admitted activation.
    pub activation_id: Id,
    /// Identifies the committed world generation.
    pub world_generation: U64,
    /// Identifies the live owner generation.
    pub owner_generation: U64,
    /// Identifies the originating operation.
    pub operation_id: Id,
    /// Identifies the originating grant, or explicit null for a nongrant operation.
    #[serde(deserialize_with = "required_nullable")]
    pub grant_id: Option<Id>,
    /// Starts the contiguous observation range, or zero for an empty batch.
    pub first_sequence: U64,
    /// Ends the contiguous observation range, or zero for an empty batch.
    pub last_sequence: U64,
    /// Preserves every observation in admitted order.
    pub events: Vec<Event>,
    /// States whether publication remains staged or is committed.
    pub visibility: Visibility,
    /// Binds physical measurements separately from modeled coordinates.
    pub measurement_ref: ContentRef,
    /// Carries observation-batch extensions.
    pub extensions: Extensions,
}

/// Binds complete pending custody to an owner generation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingInventory {
    /// Selects baseline pending-inventory schema 1.
    #[serde(deserialize_with = "crate::deserialize_version")]
    pub schema_version: Version,
    /// Identifies the execution owner.
    pub execution_owner_id: Id,
    /// Commits to complete owner compatibility.
    pub owner_binding_hash: HashRef,
    /// Commits to world compatibility.
    pub world_binding_hash: HashRef,
    /// Identifies activation, or explicit null before activation.
    #[serde(deserialize_with = "required_nullable")]
    pub activation_id: Option<Id>,
    /// Identifies the selected world generation.
    pub world_generation: U64,
    /// Identifies scope, or explicit null only for unscoped stopped inventory.
    #[serde(deserialize_with = "required_nullable")]
    pub operation_id: Option<Id>,
    /// Retains grant identity when grant-originated.
    #[serde(deserialize_with = "required_nullable")]
    pub grant_id: Option<Id>,
    /// Identifies the live owner generation.
    pub owner_generation: U64,
    /// Orders inventory revisions.
    pub revision: U64,
    /// Claims complete inventory; false cannot justify absence.
    pub complete: bool,
    /// Records accepted input custody progress.
    pub input_watermark: U64,
    /// Identifies the input custody epoch.
    pub input_epoch: Id,
    /// Lists all pending entries by ID.
    pub entries: Vec<PendingEntry>,
    /// Carries inventory extensions.
    pub extensions: Extensions,
}

/// Identifies one pending input, output, timer, I/O, or native operation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingEntry {
    /// Identifies the inventory entry.
    pub id: Id,
    /// Selects the pending state category.
    pub kind: PendingKind,
    /// Identifies actual custody ownership.
    pub owner_id: Id,
    /// Binds qualified deadline evidence or explicit unknown lookahead.
    pub deadline: Bound,
    /// Binds complete pending state using the selected facet schema.
    pub state_ref: ContentRef,
    /// Carries pending-entry extensions.
    pub extensions: Extensions,
}

impl Validate for Event {
    fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != 1 {
            return Err(invalid("schema_version", "expected baseline version 1"));
        }
        self.source.validate()?;
        self.destination.validate()?;
        self.position.validate()?;
        self.publication_position.validate()?;
        if let Some(value) = &self.delivery_position {
            value.validate()?;
        }
        validate_ids(&self.causal_parent_ids, "causal_parent_ids")?;
        self.payload.validate()?;
        self.provenance_ref.validate()?;
        if self.publication_position.phase != Phase::Publication {
            return Err(invalid(
                "publication_position",
                "publication requires publication phase",
            ));
        }
        match self.stage {
            EventStage::Publication
                if self.position == self.publication_position
                    && self.position.phase == Phase::Publication => {}
            EventStage::Delivery
                if self.delivery_position == Some(self.position)
                    && self.position.phase == Phase::Delivery => {}
            _ => {
                return Err(invalid(
                    "event.stage",
                    "stage disagrees with event coordinates",
                ));
            }
        }
        if let Some(delivery) = self.delivery_position
            && (delivery.phase != Phase::Delivery || delivery <= self.publication_position)
        {
            return Err(invalid(
                "delivery_position",
                "delivery must follow publication",
            ));
        }
        Ok(())
    }
}

impl Validate for InputBatch {
    fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != 1 {
            return Err(invalid("schema_version", "expected baseline version 1"));
        }
        if self.events.len() > crate::MAX_ARRAY_ELEMENTS {
            return Err(invalid("events", "array exceeds 65536 elements"));
        }
        for value in &self.events {
            value.validate()?;
            if value.stage != EventStage::Delivery {
                return Err(invalid(
                    "events",
                    "provisional publication is not delivered input",
                ));
            }
        }
        validate_producer_sequences(&self.events)?;
        Ok(())
    }
}

impl Validate for InputAuthorization {
    fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != 1 {
            return Err(invalid("schema_version", "expected baseline version 1"));
        }
        self.closed_input_prefix.validate()?;
        self.arbitration_ref.validate()?;
        validate_sorted(
            &self.bound_evidence_refs,
            |value| (value.hash.domain.clone(), value.hash.digest.clone()),
            "bound_evidence_refs",
        )?;
        for value in &self.bound_evidence_refs {
            value.validate()?;
        }
        Ok(())
    }
}

impl Validate for ObservationBatch {
    fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != 1 {
            return Err(invalid("schema_version", "expected baseline version 1"));
        }
        self.owner_binding_hash.validate()?;
        if self.owner_binding_hash.domain != "cnp.owner-binding.v1" {
            return Err(invalid("owner_binding_hash", "wrong owner identity domain"));
        }
        self.world_binding_hash.validate()?;
        if self.world_binding_hash.domain != "cnp.world-binding.v1" {
            return Err(invalid("world_binding_hash", "wrong world identity domain"));
        }
        if self.events.len() > crate::MAX_ARRAY_ELEMENTS {
            return Err(invalid("events", "array exceeds 65536 elements"));
        }
        for value in &self.events {
            value.validate()?;
        }
        validate_producer_sequences(&self.events)?;
        self.measurement_ref.validate()?;
        if self.events.is_empty() {
            if self.first_sequence.get() != 0 || self.last_sequence.get() != 0 {
                return Err(invalid(
                    "sequence",
                    "empty observation batch requires zero sequence bounds",
                ));
            }
        } else if self.last_sequence < self.first_sequence {
            return Err(invalid("sequence", "observation range is reversed"));
        }
        Ok(())
    }
}

impl Validate for PendingInventory {
    fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != 1 {
            return Err(invalid("schema_version", "expected baseline version 1"));
        }
        self.owner_binding_hash.validate()?;
        if self.owner_binding_hash.domain != "cnp.owner-binding.v1" {
            return Err(invalid("owner_binding_hash", "wrong owner identity domain"));
        }
        self.world_binding_hash.validate()?;
        if self.world_binding_hash.domain != "cnp.world-binding.v1" {
            return Err(invalid("world_binding_hash", "wrong world identity domain"));
        }
        validate_sorted(&self.entries, |value| value.id.clone(), "entries")?;
        for value in &self.entries {
            value.validate()?;
        }
        if self.operation_id.is_none() && self.grant_id.is_some() {
            return Err(invalid(
                "grant_id",
                "unscoped inventory cannot retain a grant",
            ));
        }
        Ok(())
    }
}

impl Validate for PendingEntry {
    fn validate(&self) -> Result<(), ContractError> {
        self.deadline.validate()?;
        self.state_ref.validate()?;
        Ok(())
    }
}

impl InputBatch {
    /// Validates and computes the complete ordered batch identity.
    ///
    /// # Errors
    /// Rejects local schema violations and canonical serialization failures.
    pub fn identity(&self) -> Result<HashRef, ContractError> {
        self.validate()?;
        canonical::json_hash("cnp.input-batch.v1", self)
    }
}

impl ObservationBatch {
    /// Validates and computes the complete ordered batch identity.
    ///
    /// # Errors
    /// Rejects local schema violations and canonical serialization failures.
    pub fn identity(&self) -> Result<HashRef, ContractError> {
        self.validate()?;
        canonical::json_hash("cnp.observation-batch.v1", self)
    }
}

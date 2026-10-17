//! Checks the distinct original-input lineage manifest without issuing authority.
//!
//! The selected manifest names original delivered/publication bodies and direct
//! codec rows. An installed runtime adopter must authenticate those rows against
//! owning producers before uploading them. Successful decoding proves geometry
//! and body agreement only. Missing rows are never inferred to be leaves.
//!
//! ```json
//! {"schema_version":1,"execution_owner_id":"owner/consumer",
//!  "owner_generation":"1","input_epoch":"input/1","batch_id":"batch/1",
//!  "batch_sequence":"1","entries":[],"dependencies":[]}
//! ```
//! Entries retain full producer scope, separately from producer-local event IDs.
//! No manifest edge points to its enclosing extension-bearing input batch.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crucible_node_contract::*;
use serde::{Deserialize, Serialize};

use crate::ProviderError;

/// Names the independently selected source interpretation of an input inventory.
pub const INPUT_LINEAGE_IDENTIFIER: &str = "org.andyl.reference.original-input-lineage";
/// Identifies the closed manifest body independently of the method application.
pub const INPUT_LINEAGE_MEDIA_TYPE: &str =
    "application/vnd.crucible.reference-original-input-lineage+json";

/// Retains inert original producer control scope without authenticating it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputLineageProducer {
    /// Binds the original indivisible producer owner and its full compatibility.
    pub owner_binding_hash: HashRef,
    /// Names the actual original native owner, independently of the event ID.
    pub execution_owner_id: Id,
    /// Retains the source control session bound to its original Ready/Initialize.
    pub session_id: Id,
    /// Commits to the complete original source world.
    pub world_binding_hash: HashRef,
    /// Retains the actual original source activation.
    pub activation_id: Id,
    /// Retains its original positive committed world generation.
    pub world_generation: U64,
    /// Retains the original native incarnation; a fresh socket does not replace it.
    pub incarnation_id: Id,
    /// Retains the original positive owner generation.
    pub owner_generation: U64,
    /// Names the actual original completed source operation.
    pub operation_id: Id,
    /// Names the actual original admitted native window.
    pub grant_id: Id,
    /// Retains the complete original observation containing the publication.
    pub observation_batch: ContentRef,
    /// Retains the corresponding original source stop and custody scope.
    pub stop_receipt: ContentRef,
    /// Retains the selected measurement root and its explicit dependency closure.
    pub measurement: ContentRef,
}

/// Pairs exact original source publication and recipient delivery body roles.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputLineageEntry {
    /// Retains the exact canonical delivered Event in the enclosing ordered batch.
    pub delivered: ContentRef,
    /// Retains the original source Event inside the original ObservationBatch.
    pub published: ContentRef,
    /// Retains its original producer scope; equal local IDs need not share owners.
    pub producer: InputLineageProducer,
}

/// Declares one explicit direct codec row, including authenticated empty leaves.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputLineageRow {
    /// Preserves the complete original typed role, not only its physical digest.
    pub object: ContentRef,
    /// Lists direct dependencies in strict full-reference order.
    pub dependencies: Vec<ContentRef>,
}

/// Describes an extension-bearing input cut without a circular enclosing-batch edge.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputLineageInventory {
    /// Selects only closed manifest edition one.
    pub schema_version: u16,
    /// Names the actual recipient owner from the original input authorization.
    pub execution_owner_id: Id,
    /// Retains the original recipient owner generation.
    pub owner_generation: U64,
    /// Retains the exact original accepted input epoch.
    pub input_epoch: Id,
    /// Retains the exact original semantic batch identity.
    pub batch_id: Id,
    /// Retains the original positive accepted input FIFO.
    pub batch_sequence: U64,
    /// Preserves ordered delivery occurrences, including identical and zero-byte inputs.
    pub entries: Vec<InputLineageEntry>,
    /// Preserves one explicit direct row for each reachable original typed object.
    pub dependencies: Vec<InputLineageRow>,
}

impl Validate for InputLineageInventory {
    fn validate(&self) -> Result<(), ContractError> {
        self.validate_geometry().map_err(|_| {
            crate::bodies::invalid(
                "original_input_lineage",
                "invalid bounded explicit lineage inventory geometry",
            )
        })
    }
}

impl InputLineageInventory {
    /// Verifies bounded geometry and original body agreement before source effects.
    ///
    /// The resolver must borrow independently retained original bytes. This
    /// function neither uploads them nor authenticates source installation. Every
    /// body is verified under its full original typed reference. Same-time event
    /// parent claims remain unsupported. The native reader must independently
    /// verify strictly earlier-time consumption; data labels cannot establish it.
    /// Cumulative checksum ancestry stays in explicit rows.
    ///
    /// # Errors
    /// Refuses changed input scope/order, invalid original publication/stop,
    /// unsupported same-time parents, missing or extra rows, cycles, altered
    /// bodies/media roles, unknown editions or finite-credit exhaustion.
    pub fn validate_bodies<'a>(
        &self,
        batch: &InputBatch,
        owner_generation: U64,
        resolve: impl Fn(&ContentRef) -> Result<&'a [u8], ProviderError>,
    ) -> Result<(), ProviderError> {
        self.preflight(batch, owner_generation)?;
        let mut roots = BTreeSet::new();
        for entry in &self.entries {
            roots.extend([
                entry.delivered.clone(),
                entry.published.clone(),
                entry.producer.observation_batch.clone(),
                entry.producer.stop_receipt.clone(),
                entry.producer.measurement.clone(),
            ]);
        }
        validate_graph(&roots, &self.dependencies)?;
        for row in &self.dependencies {
            row.object.verify(resolve(&row.object)?)?;
        }
        for (entry, delivered) in self.entries.iter().zip(&batch.events) {
            self.validate_entry(entry, delivered, &resolve)?;
        }
        Ok(())
    }

    fn preflight(&self, batch: &InputBatch, generation: U64) -> Result<(), ProviderError> {
        batch.validate()?;
        if self.schema_version != 1
            || self.owner_generation.get() == 0
            || self.owner_generation != generation
            || self.execution_owner_id != batch.execution_owner_id
            || self.input_epoch != batch.input_epoch
            || self.batch_id != batch.batch_id
            || self.batch_sequence != batch.batch_sequence
            || self.entries.len() != batch.events.len()
            || self.entries.len() > 64
            || self.dependencies.len() > 4096
            || self
                .dependencies
                .windows(2)
                .any(|pair| pair[0].object >= pair[1].object)
        {
            return Err(invalid());
        }
        self.validate_geometry()
    }

    fn validate_geometry(&self) -> Result<(), ProviderError> {
        if self.schema_version != 1
            || self.owner_generation.get() == 0
            || self.batch_sequence.get() == 0
            || self.entries.len() > 64
            || self.dependencies.len() > 4096
            || self
                .dependencies
                .windows(2)
                .any(|pair| pair[0].object >= pair[1].object)
        {
            return Err(invalid());
        }
        let mut bytes = 0u64;
        let mut edges = 0usize;
        let mut extents = BTreeMap::new();
        for row in &self.dependencies {
            row.object.validate()?;
            bytes = bytes
                .checked_add(row.object.length.get())
                .ok_or_else(credit)?;
            edges = edges
                .checked_add(row.dependencies.len())
                .ok_or_else(credit)?;
            if bytes > 64 * 1024 * 1024 || edges > 65_536 {
                return Err(credit());
            }
            if row.dependencies.windows(2).any(|pair| pair[0] >= pair[1])
                || row.dependencies.contains(&row.object)
                || extents
                    .insert(&row.object.hash, row.object.length)
                    .is_some_and(|previous| previous != row.object.length)
            {
                return Err(invalid());
            }
            for dependency in &row.dependencies {
                locate(&self.dependencies, dependency)?;
            }
        }
        Ok(())
    }

    fn validate_entry<'a>(
        &self,
        entry: &InputLineageEntry,
        delivered: &Event,
        resolve: &impl Fn(&ContentRef) -> Result<&'a [u8], ProviderError>,
    ) -> Result<(), ProviderError> {
        for reference in [
            &entry.delivered,
            &entry.published,
            &entry.producer.observation_batch,
            &entry.producer.stop_receipt,
            &entry.producer.measurement,
        ] {
            locate(&self.dependencies, reference)?;
        }
        let original: Event = json_body(&entry.published, resolve)?;
        let supplied: Event = json_body(&entry.delivered, resolve)?;
        let observation: ObservationBatch = json_body(&entry.producer.observation_batch, resolve)?;
        let stop: StopReceipt = json_body(&entry.producer.stop_receipt, resolve)?;
        original.validate()?;
        observation.validate()?;
        stop.validate()?;
        let producer = &entry.producer;
        if supplied != *delivered
            || delivered.stage != EventStage::Delivery
            || original.stage != EventStage::Publication
            || original.source != delivered.source
            || original.id != delivered.id
            || original.source_sequence != delivered.source_sequence
            || original.payload != delivered.payload
            || original.provenance_ref != delivered.provenance_ref
            || original.publication_position != delivered.publication_position
            || !original.causal_parent_ids.is_empty()
            || !delivered.causal_parent_ids.is_empty()
            || !original.extensions.is_empty()
            || !delivered.extensions.is_empty()
            || observation
                .events
                .iter()
                .filter(|event| **event == original)
                .count()
                != 1
            || producer.owner_generation.get() == 0
            || producer.world_generation.get() == 0
            || observation.world_binding_hash != producer.world_binding_hash
            || observation.activation_id != producer.activation_id
            || observation.world_generation != producer.world_generation
            || !observation.extensions.is_empty()
            || observation.visibility != Visibility::Staged
            || observation.execution_owner_id != producer.execution_owner_id
            || observation.owner_generation != producer.owner_generation
            || observation.operation_id != producer.operation_id
            || observation.grant_id.as_ref() != Some(&producer.grant_id)
            || observation.owner_binding_hash != producer.owner_binding_hash
            || observation.measurement_ref != producer.measurement
            || original.provenance_ref != producer.measurement
            || stop.session_id != producer.session_id
            || stop.world_binding_hash != producer.world_binding_hash
            || stop.activation_id != producer.activation_id
            || stop.world_generation != producer.world_generation
            || !stop.extensions.is_empty()
            || stop.participant_ids != [original.source.node_id.clone()]
            || stop.observation_batch != producer.observation_batch
            || stop.physical_measurement_ref != producer.measurement
            || stop.execution_owner_id != producer.execution_owner_id
            || stop.incarnation_id != producer.incarnation_id
            || stop.owner_generation != producer.owner_generation
            || stop.owner_binding_hash != producer.owner_binding_hash
            || stop.operation_id != producer.operation_id
            || stop.grant_id.as_ref() != Some(&producer.grant_id)
            || stop.mode != OperatingMode::Quantized
        {
            return Err(invalid());
        }
        self.check_event_row(&entry.published, &original)?;
        self.check_event_row(&entry.delivered, delivered)?;

        // The native relation reader separately checks every actually consumed
        // source input against this publication's tick. Merely parsing source
        // labels here cannot establish that ordered native consumption premise.
        Ok(())
    }

    fn check_event_row(&self, reference: &ContentRef, event: &Event) -> Result<(), ProviderError> {
        let row = &self.dependencies[locate(&self.dependencies, reference)?];
        let expected: Vec<_> =
            BTreeSet::from([event.payload.clone(), event.provenance_ref.clone()])
                .into_iter()
                .collect();
        if row.dependencies != expected {
            return Err(invalid());
        }
        Ok(())
    }
}

fn json_body<'a, T: serde::de::DeserializeOwned + Validate>(
    reference: &ContentRef,
    resolve: &impl Fn(&ContentRef) -> Result<&'a [u8], ProviderError>,
) -> Result<T, ProviderError> {
    if reference.media_type != "application/json" || reference.length.get() > 65_536 {
        return Err(invalid());
    }
    Ok(canonical::decode(resolve(reference)?, 65_536)?)
}

fn locate(rows: &[InputLineageRow], object: &ContentRef) -> Result<usize, ProviderError> {
    rows.binary_search_by(|row| row.object.cmp(object))
        .map_err(|_| invalid())
}

fn validate_graph(
    roots: &BTreeSet<ContentRef>,
    rows: &[InputLineageRow],
) -> Result<(), ProviderError> {
    let mut remaining: Vec<_> = rows.iter().map(|row| row.dependencies.len()).collect();
    let mut parents = vec![Vec::new(); rows.len()];
    let mut ready = VecDeque::new();
    for (parent, row) in rows.iter().enumerate() {
        for child in &row.dependencies {
            parents[locate(rows, child)?].push(parent);
        }
        if remaining[parent] == 0 {
            ready.push_back(parent);
        }
    }
    let mut processed = 0usize;
    while let Some(child) = ready.pop_front() {
        processed += 1;
        for &parent in &parents[child] {
            remaining[parent] -= 1;
            if remaining[parent] == 0 {
                ready.push_back(parent);
            }
        }
    }
    if processed != rows.len() {
        return Err(invalid());
    }
    let mut visited = BTreeSet::new();
    let mut pending = VecDeque::new();
    for root in roots {
        pending.push_back(locate(rows, root)?);
    }
    while let Some(index) = pending.pop_front() {
        if visited.insert(index) {
            for child in &rows[index].dependencies {
                pending.push_back(locate(rows, child)?);
            }
        }
    }
    if visited.len() != rows.len() {
        return Err(invalid());
    }
    Ok(())
}

fn invalid() -> ProviderError {
    ProviderError::Correlation("selected original input lineage inventory differs")
}

fn credit() -> ProviderError {
    ProviderError::ResourceExhausted("selected original input lineage inventory credit")
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- These data-codec regressions panic only on a violated original body/row invariant.
#[allow(clippy::unwrap_used)]
#[path = "input_inventory_tests.rs"]
mod tests;

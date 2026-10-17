//! Retains authenticated original permissions across fresh coordinator epochs.
//!
//! Edition-two rows refer to separately retained canonical source objects. They
//! are portable history, not capabilities: the installed native verifier must
//! authenticate their archive provenance and the complete fresh owner mapping.
//!
//! ```json
//! { "schema_version": 1, "coordinator": {}, "scheduler": {}, "runtime": {}, "policy": {}, "reservations": [] }
//! ```

use std::collections::BTreeSet;

use crucible_node_contract::{ContentRef, Id, Position, Repeatability, U64, Validate, canonical};
use serde::{Deserialize, Serialize};

use crate::{node_admission::AdmittedGraph, node_contract::RuntimeSnapshot};

use super::{
    InputPayload, SavedPosition, SavedProducer, SavedReservation, SchedulingError,
    SchedulingSnapshot,
};

impl SchedulingSnapshot {
    /// Hashes the exact selected scheduler edition without reinterpreting legacy bytes.
    ///
    /// # Errors
    /// Refuses unknown editions or noncanonical serialization.
    pub fn continuation_hash(&self) -> Result<crucible_node_contract::HashRef, SchedulingError> {
        let domain = match self.schema_version {
            1 => "cnp.scheduler-continuation.v1",
            2 => "cnp.scheduler-continuation.v2",
            3 => "cnp.scheduler-continuation.v3",
            4 => "cnp.scheduler-continuation.v4",
            _ => return Err(SchedulingError::InvalidSnapshot),
        };
        Ok(canonical::json_hash(domain, self)?)
    }
}

/// Defines the first closed installed Clock/SE scheduling-epoch preservation policy.
pub const SCHEDULING_EPOCH_POLICY_SPECIFICATION: &str = "crucible.closed-clock-se-scheduling-epochs.v1: independently installed x86_64 closed SE and integer Clock world; no ingress, connection, input batch, external source or fault conversion; retain exact original signed coordinator, scheduler and runtime bodies and source owner map; only original still-Pending ExactRun reservations may retain their unchanged cursor below a later true activation boundary; the fixed native codec verifies original permission and current publication curfew; every fresh peer requires its own current unchanged-cut audit and independent exact authority; portable rows never issue permission";

/// Returns the exact installed epoch policy identity without issuing authority.
///
/// # Errors
/// Refuses content identity construction failure.
pub fn closed_scheduling_epoch_policy() -> Result<ContentRef, SchedulingError> {
    Ok(canonical::content_ref(
        SCHEDULING_EPOCH_POLICY_SPECIFICATION.as_bytes(),
        "text/plain",
    )?)
}

/// Bounds all retained original epoch bodies independently of native images.
pub const MAXIMUM_SCHEDULING_EPOCH_BYTES: usize = 16 * 1024 * 1024;

/// Bounds original captured epochs and inherited owner reservations.
pub const MAXIMUM_SCHEDULING_EPOCHS: usize = 64;

/// Preserves one original reservation and its corresponding coordinator cursor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedEpochReservation {
    /// Retains the original unresolved operation without widening its grant.
    pub reservation: SavedReservation,
    /// Retains that owner's exact original common cursor.
    pub position: SavedPosition,
    /// Retains the same logical producer's original closure and sequence prefix.
    pub producer: SavedProducer,
}

/// Refers to one authenticated captured scheduling epoch and installed policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedSchedulingEpoch {
    /// Selects the closed original-epoch row format.
    pub schema_version: u16,
    /// Binds the actual captured coordinator, which contains the pending grant.
    pub coordinator: ContentRef,
    /// Binds separately retained original canonical scheduling bytes.
    pub scheduler: ContentRef,
    /// Binds separately retained original canonical runtime bytes.
    pub runtime: ContentRef,
    /// Binds the independently installed selected preservation policy.
    pub policy: ContentRef,
    /// Retains the original committed source world generation.
    pub source_generation: U64,
    /// Enumerates exact inherited reservations in logical owner order.
    pub reservations: Vec<SavedEpochReservation>,
}

/// Returns original source bodies from a trusted installed native verifier.
///
/// This data does not grant authority. The runtime constructs its private
/// continuation seal only after checking it against the exact source snapshot,
/// authentic fresh native proof and complete target activation.
#[derive(Clone, Debug)]
pub struct SchedulingEpochEvidence {
    /// Retains the exact selected installed policy body.
    pub policy: InputPayload,
    /// Retains original rows authenticated under the selected source policy.
    pub rows: Vec<SavedSchedulingEpoch>,
    /// Retains every referenced source body once per full content identity.
    pub objects: Vec<InputPayload>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OriginalCoordinator {
    schema_version: u16,
    scheduler: SchedulingSnapshot,
    runtime: RuntimeSnapshot,
    world_repeatability: Repeatability,
}

impl SavedSchedulingEpoch {
    pub(super) fn validate_row(&self, current: &SchedulingSnapshot) -> Result<(), SchedulingError> {
        for reference in [
            &self.coordinator,
            &self.scheduler,
            &self.runtime,
            &self.policy,
        ] {
            reference.validate()?;
        }
        if self.schema_version != 1
            || self.source_generation.get() == 0
            || self.source_generation >= current.source_generation
            || self.reservations.is_empty()
            || self.reservations.len() > MAXIMUM_SCHEDULING_EPOCHS
            || self
                .reservations
                .windows(2)
                .any(|pair| pair[0].reservation.owner >= pair[1].reservation.owner)
        {
            return Err(SchedulingError::InvalidSnapshot);
        }
        for inherited in &self.reservations {
            if inherited.position.owner != inherited.reservation.owner
                || inherited.producer.node != inherited.reservation.node
                || !current.reservations.contains(&inherited.reservation)
                || !current.positions.contains(&inherited.position)
                || !current.producers.contains(&inherited.producer)
                || inherited.position.position >= current.source_boundary
            {
                return Err(SchedulingError::UnresolvedCustody);
            }
        }
        Ok(())
    }
}

/// Checks original source body identities and exact immutable reservation lineage.
///
/// The caller must independently authenticate signed source provenance and the
/// actual fresh native owner mapping. Successful data validation cannot mint a
/// live grant or select a preservation policy.
///
/// # Errors
/// Refuses missing, noncanonical or changed bodies, unknown source editions,
/// altered reservations or owner aliases, causal queues outside the first closed
/// policy, ambiguous mappings and exhausted body/object budgets.
pub fn validate_scheduling_epoch_bodies(
    graph: &AdmittedGraph,
    snapshot: &SchedulingSnapshot,
    evidence: &SchedulingEpochEvidence,
) -> Result<(), SchedulingError> {
    validate_evidence(evidence)?;
    if snapshot.schema_version != 2 || !closed_profile(graph, snapshot) {
        return Err(SchedulingError::InvalidSnapshot);
    }
    let rows = snapshot
        .original_epochs
        .as_ref()
        .ok_or(SchedulingError::InvalidSnapshot)?;
    if rows != &evidence.rows {
        return Err(SchedulingError::InvalidSnapshot);
    }
    let required: BTreeSet<_> = rows
        .iter()
        .flat_map(|row| [&row.coordinator, &row.scheduler, &row.runtime])
        .collect();
    if required.len() != evidence.objects.len()
        || evidence
            .objects
            .iter()
            .any(|object| !required.contains(&object.reference))
    {
        return Err(SchedulingError::UnresolvedCustody);
    }
    let mut inherited_owners = BTreeSet::new();
    for row in rows {
        row.validate_row(snapshot)?;
        if row.policy != evidence.policy.reference {
            return Err(SchedulingError::ForeignActivation);
        }
        let source: SchedulingSnapshot = decode(body(evidence, &row.scheduler)?)?;
        let runtime: RuntimeSnapshot = decode(body(evidence, &row.runtime)?)?;
        let coordinator: OriginalCoordinator = decode(body(evidence, &row.coordinator)?)?;
        if source.schema_version != 1
            || source.source_generation != row.source_generation
            || source.world_binding_hash != snapshot.world_binding_hash
            || source.maximum_microsteps != snapshot.maximum_microsteps
            || coordinator.schema_version != 1
            || coordinator.scheduler != source
            || coordinator.runtime != runtime
            || coordinator.world_repeatability != graph.world_repeatability()
            || runtime.capture_cut != source.capture_cut
            || runtime.capture_ordinal != source.capture_ordinal
            || runtime.source_activation.activation_id != source.source_activation_id
            || runtime.source_activation.generation != source.source_generation
            || runtime.source_activation.boundary != source.source_boundary
            || runtime.source_activation.world_binding_hash != source.world_binding_hash
            || !closed_profile(graph, &source)
        {
            return Err(SchedulingError::InvalidSnapshot);
        }
        super::validate_saved_source(graph, &source)?;
        crate::node_contract::PreparedRuntimeRestore::validate_source(
            graph,
            &source,
            &runtime,
            crate::node_contract::RuntimeLimits {
                maximum_nodes: MAXIMUM_SCHEDULING_EPOCHS,
                maximum_owners: MAXIMUM_SCHEDULING_EPOCHS,
                maximum_operations: 4096,
                maximum_retained_outputs: 4096,
            },
            MAXIMUM_SCHEDULING_EPOCH_BYTES,
        )
        .map_err(|_| SchedulingError::UnresolvedCustody)?;
        for inherited in &row.reservations {
            if !runtime.operations.iter().any(|operation| {
                operation.operation == inherited.reservation.operation
                    && operation.route.node == inherited.reservation.node
                    && operation.input_batch == inherited.reservation.input_batch
                    && matches!(
                        operation.result,
                        crate::node_contract::SavedRuntimeResult::Pending
                    )
            }) {
                return Err(SchedulingError::UnresolvedCustody);
            }
        }

        if source.source_owners.len() != snapshot.source_owners.len()
            || source
                .source_owners
                .iter()
                .zip(&snapshot.source_owners)
                .any(|(old, fresh)| {
                    old.owner != fresh.owner
                        || old.incarnation == fresh.incarnation
                        || old.generation >= fresh.generation
                })
            || runtime
                .source_activation
                .owners
                .iter()
                .zip(&source.source_owners)
                .any(|(owner, saved)| {
                    owner.owner != saved.owner
                        || owner.incarnation != saved.incarnation
                        || owner.generation != saved.generation
                })
            || runtime.source_activation.owners.len() != source.source_owners.len()
        {
            return Err(SchedulingError::ForeignActivation);
        }
        for inherited in &row.reservations {
            if !inherited_owners.insert(inherited.reservation.owner.clone())
                || !source.reservations.contains(&inherited.reservation)
                || !source.positions.contains(&inherited.position)
                || !source.producers.contains(&inherited.producer)
            {
                return Err(SchedulingError::UnresolvedCustody);
            }
        }
    }
    if snapshot.positions.iter().any(|saved| {
        saved.position < snapshot.source_boundary && !inherited_owners.contains(&saved.owner)
    }) {
        return Err(SchedulingError::UnresolvedCustody);
    }
    Ok(())
}

/// Checks epoch retention against the exact source and complete fresh target roster.
///
/// The installed verifier must authenticate source object provenance and actual
/// reconstructed native custody before returning this evidence. This function
/// performs the independent data checks beneath the runtime's private seal.
///
/// # Errors
/// Refuses changed original reservations, relabeled source scope, incomplete
/// owner maps, unknown body editions, unused origin rows and resource excess.
pub(crate) fn validate_restored_scheduling_epochs(
    graph: &AdmittedGraph,
    source: &SchedulingSnapshot,
    target: &crate::node_contract::ActivationRecord,
    evidence: &SchedulingEpochEvidence,
) -> Result<(), SchedulingError> {
    validate_evidence(evidence)?;
    if evidence.rows.is_empty()
        || evidence.rows.len() > MAXIMUM_SCHEDULING_EPOCHS
        || source.capture_cut != target.boundary
        || source.world_binding_hash != target.world_binding_hash
        || source.source_generation >= target.generation
        || source.source_owners.len() != target.owners.len()
        || source
            .source_owners
            .iter()
            .zip(&target.owners)
            .any(|(old, fresh)| {
                old.owner != fresh.owner
                    || old.incarnation == fresh.incarnation
                    || old.generation >= fresh.generation
            })
    {
        return Err(SchedulingError::ForeignActivation);
    }
    match source.schema_version {
        1 => {
            if evidence.rows.len() != 1
                || evidence.rows[0].scheduler.media_type
                    != "application/vnd.crucible.original-scheduler+json"
                || decode::<SchedulingSnapshot>(body(evidence, &evidence.rows[0].scheduler)?)?
                    != *source
            {
                return Err(SchedulingError::UnresolvedCustody);
            }
        }
        2 if source.original_epochs.as_ref() == Some(&evidence.rows) => {
            validate_scheduling_epoch_bodies(graph, source, evidence)?;
        }
        _ => return Err(SchedulingError::InvalidSnapshot),
    }
    let mut current = source.clone();
    current.schema_version = 2;
    current.original_epochs = Some(evidence.rows.clone());
    current.source_activation_id = target.activation_id.clone();
    current.source_generation = target.generation;
    current.source_boundary = target.boundary;
    current.source_owners = target
        .owners
        .iter()
        .map(|owner| super::SavedOwner {
            owner: owner.owner.clone(),
            incarnation: owner.incarnation.clone(),
            generation: owner.generation,
        })
        .collect();
    validate_scheduling_epoch_bodies(graph, &current, evidence)
}

pub(super) fn validate_evidence(evidence: &SchedulingEpochEvidence) -> Result<(), SchedulingError> {
    let mut references = BTreeSet::new();
    let mut total = evidence.policy.bytes.len();
    evidence.policy.reference.validate()?;
    evidence.policy.reference.verify(&evidence.policy.bytes)?;
    if evidence.policy.bytes.is_empty() || evidence.objects.len() > MAXIMUM_SCHEDULING_EPOCHS * 3 {
        return Err(SchedulingError::InvalidSnapshot);
    }
    for object in &evidence.objects {
        total = total
            .checked_add(object.bytes.len())
            .ok_or(SchedulingError::InvalidSnapshot)?;
        if total > MAXIMUM_SCHEDULING_EPOCH_BYTES || !references.insert(&object.reference) {
            return Err(SchedulingError::InvalidSnapshot);
        }
        object.reference.validate()?;
        object.reference.verify(&object.bytes)?;
    }
    if total > MAXIMUM_SCHEDULING_EPOCH_BYTES {
        return Err(SchedulingError::InvalidSnapshot);
    }
    Ok(())
}

pub(super) fn closed_profile(graph: &AdmittedGraph, snapshot: &SchedulingSnapshot) -> bool {
    graph.world().connections.is_empty()
        && graph.coordinator_policy().external_inputs.is_empty()
        && snapshot.pending_deliveries.is_empty()
        && snapshot.external_closed_prefixes.is_empty()
        && snapshot.input_batches.is_empty()
        && snapshot.used_input_batches.is_empty()
        && snapshot.payload_objects.is_empty()
        && snapshot.native_sequences.is_empty()
}

pub(super) fn rows_cover_position(
    snapshot: &SchedulingSnapshot,
    owner: &Id,
    position: Position,
) -> bool {
    snapshot.schema_version == 2
        && snapshot.original_epochs.as_ref().is_some_and(|rows| {
            rows.iter()
                .flat_map(|row| &row.reservations)
                .any(|inherited| {
                    &inherited.position.owner == owner && inherited.position.position == position
                })
        })
}

pub(super) fn body<'a>(
    evidence: &'a SchedulingEpochEvidence,
    reference: &ContentRef,
) -> Result<&'a [u8], SchedulingError> {
    evidence
        .objects
        .iter()
        .find(|object| &object.reference == reference)
        .map(|object| object.bytes.as_slice())
        .ok_or(SchedulingError::UnresolvedCustody)
}

pub(super) fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, SchedulingError> {
    let value = canonical::parse_json(bytes, MAXIMUM_SCHEDULING_EPOCH_BYTES)?;
    if canonical::canonical_json(&value)? != bytes {
        return Err(SchedulingError::InvalidSnapshot);
    }
    serde_json::from_value(value).map_err(|_| SchedulingError::InvalidSnapshot)
}

#[cfg(test)]
#[path = "epoch_tests.rs"]
mod tests;

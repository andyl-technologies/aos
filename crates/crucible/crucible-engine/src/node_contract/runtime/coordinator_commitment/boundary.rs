//! Derives a capture boundary from real settled Runtime and Scheduler custody.
//!
//! Requested coordinates select a candidate only. Every execution owner must
//! actually be at that coordinate, every pre-cut delivery must be consumed, and
//! authenticated output prefixes must close the cut. Native/Source currentness
//! and the genuine administrative ticket remain independent later checks.

use super::*;
use serde::Serialize;

/// Seals one actual current coordinator boundary without issuing Capture.
///
/// Only this defining Runtime constructs the value. The Window keeps the same
/// selected-action gate armed while Sources validate their actual current
/// native checkpoints. A matching scalar or deserialized checkpoint cannot
/// manufacture this sealed boundary.
#[derive(Clone, Copy)]
pub(crate) struct OriginalRestoredCoordinatorBoundary17 {
    runtime: *const NodeRuntime,
    cut: Position,
    sequence: U64,
    ordinal: U64,
    maximum_checkpoint_encoded: usize,
    construction: usize,
}

#[derive(Serialize)]
struct ActivationProjection<'a> {
    activation_id: &'a Id,
    world_generation: U64,
    world_binding: &'a crucible_node_format::HashRef,
    boundary: Position,
}

#[derive(Serialize)]
struct HashProjection {
    algorithm: &'static str,
    domain: &'static str,
    digest: &'static str,
}

#[derive(Serialize)]
struct ReferenceProjection {
    hash: HashProjection,
    length: U64,
    media_type: &'static str,
}

#[derive(Serialize)]
struct SafePointProjection {
    position: Position,
    event_ordinal: U64,
    prefix: HashProjection,
    runtime: ReferenceProjection,
    scheduling: ReferenceProjection,
}

#[derive(Serialize)]
struct CheckpointProjection<'a> {
    schema_version: u16,
    ordering_profile: &'static str,
    activation: ActivationProjection<'a>,
    parent: &'a Option<ContentRef>,
    maximum_records: U64,
    first_sequence: U64,
    next_sequence: U64,
    first_event_ordinal: U64,
    entries: &'a [CoordinatorCommitmentEntry17],
    safe_point: SafePointProjection,
}

#[derive(Serialize)]
struct PrefixProjection<'a> {
    schema_version: u16,
    ordering_profile: &'static str,
    activation: &'a ActivationProjection<'a>,
    parent: &'a Option<ContentRef>,
    maximum_records: U64,
    first_sequence: U64,
    next_sequence: U64,
    first_event_ordinal: U64,
    entries: &'a [CoordinatorCommitmentEntry17],
}

impl CheckpointProjection<'_> {
    fn prefix_data(&self) -> PrefixProjection<'_> {
        PrefixProjection {
            schema_version: self.schema_version,
            ordering_profile: self.ordering_profile,
            activation: &self.activation,
            parent: self.parent,
            maximum_records: self.maximum_records,
            first_sequence: self.first_sequence,
            next_sequence: self.next_sequence,
            first_event_ordinal: self.first_event_ordinal,
            entries: self.entries,
        }
    }
}

const MAX_DIGEST: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

fn reference_projection(media_type: &'static str) -> ReferenceProjection {
    ReferenceProjection {
        hash: HashProjection {
            algorithm: "blake3-256",
            domain: "cnp.blob.v1",
            digest: MAX_DIGEST,
        },
        length: U64::new(u64::MAX),
        media_type,
    }
}

impl CoordinatorCommitments17 {
    fn capture_projection_data<'a>(
        &'a self,
        activation: &'a ActivationRecord,
        cut: Position,
    ) -> Result<CheckpointProjection<'a>, RuntimeError> {
        self.require_settled_data()?;
        Ok(CheckpointProjection {
            schema_version: 17,
            ordering_profile: "coordinator-public-events-v17",
            activation: ActivationProjection {
                activation_id: &activation.activation_id,
                world_generation: activation.generation,
                world_binding: &activation.world_binding_hash,
                boundary: activation.boundary,
            },
            parent: &self.parent,
            maximum_records: U64::new(
                u64::try_from(self.policy.maximum_records)
                    .map_err(|_| RuntimeError::ResourceLimit)?,
            ),
            first_sequence: self.first_sequence,
            next_sequence: self.next_sequence,
            first_event_ordinal: self.first_event_ordinal,
            entries: &self.entries,
            safe_point: SafePointProjection {
                position: cut,
                event_ordinal: self.next_event_ordinal,
                prefix: HashProjection {
                    algorithm: "blake3-256",
                    domain: "crucible.coordinator-prefix.v17",
                    digest: MAX_DIGEST,
                },
                runtime: reference_projection(
                    "application/vnd.crucible.runtime-original-lineage+json;version=7",
                ),
                scheduling: reference_projection("application/json"),
            },
        })
    }

    pub(in crate::node_contract::runtime) fn authenticate_boundary_data(
        &self,
        boundary: &OriginalRestoredCoordinatorBoundary17,
    ) -> Result<(), RuntimeError> {
        self.require_settled_data()?;
        if self.next_sequence != boundary.sequence || self.next_event_ordinal != boundary.ordinal {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }
}

impl OriginalRestoredCoordinatorBoundary17 {
    pub(crate) fn cut_data(&self) -> Position {
        self.cut
    }

    pub(crate) fn ordinal_data(&self) -> U64 {
        self.ordinal
    }

    pub(crate) fn maximum_checkpoint_encoded_bytes_data(&self) -> usize {
        self.maximum_checkpoint_encoded
    }

    pub(crate) fn construction_requested_bytes_data(&self) -> usize {
        self.construction
    }

    pub(crate) fn authenticate_runtime_data(
        &self,
        runtime: &NodeRuntime,
        world: &WorldActivation,
        host: &crate::node_contract::HostSchedulingSource,
    ) -> Result<(), RuntimeError> {
        if !std::ptr::eq(self.runtime, runtime) {
            return Err(RuntimeError::ForeignAuthority);
        }
        runtime.authenticate_coordinator17_capture_owners_data(world, self.cut, host)?;
        runtime
            .scheduler
            .as_ref()
            .ok_or(RuntimeError::NotActivated)?
            .with_coordinator17_data(|log| {
                log.ok_or(RuntimeError::UnsupportedFacet)?
                    .authenticate_boundary_data(self)
            })
    }
}

impl NodeRuntime {
    fn authenticate_coordinator17_capture_owners_data(
        &self,
        world: &WorldActivation,
        cut: Position,
        host: &crate::node_contract::HostSchedulingSource,
    ) -> Result<(), RuntimeError> {
        self.validate_activation(world)?;
        self.authenticate_host_scheduling_source(host)?;
        let selected = host.selection();
        if !selected.descriptor.ports.is_empty() {
            return Err(RuntimeError::UnsupportedFacet);
        }
        if self.graceful_retirement
            || self.terminal.is_some()
            || self.condition_fenced()
            || self
                .owners
                .values()
                .any(|owner| owner.lifecycle != Lifecycle::Stopped || owner.operation.is_some())
            || self.operations.values().any(|entry| {
                !matches!(entry.result, RetainedResult::Acknowledged(_))
                    || entry.scheduling_commit.is_none()
            })
            || self.input_batches.values().any(|input| {
                !input.committed
                    || input.commit.is_none()
                    || input.acknowledgement.is_none()
                    || input.failure.is_some()
            })
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.scheduler
            .as_ref()
            .ok_or(RuntimeError::NotActivated)?
            .retained()?
            .authenticate_coordinator17_capture_boundary_data(
                cut,
                &selected.descriptor.id,
                &selected.owner.owner.id,
            )
    }

    /// Seals a known coordinator boundary after checking actual current owners.
    /// No effect is performed to bring a candidate cut into eligibility.
    pub(crate) fn original_restored_coordinator_capture_boundary_data(
        &self,
        world: &WorldActivation,
        cut: Position,
        ordinal: U64,
        host: &crate::node_contract::HostSchedulingSource,
        maximum: usize,
    ) -> Result<OriginalRestoredCoordinatorBoundary17, RuntimeError> {
        self.authenticate_coordinator17_capture_owners_data(world, cut, host)?;
        self.scheduler
            .as_ref()
            .ok_or(RuntimeError::NotActivated)?
            .with_coordinator17_data(|log| {
                let log = log.ok_or(RuntimeError::UnsupportedFacet)?;
                let projection = log.capture_projection_data(world.record(), cut)?;
                if ordinal != log.next_event_ordinal {
                    return Err(RuntimeError::InvalidReceipt);
                }
                let prefix_construction =
                    Self::original_runtime_constructor_serialization_storage_data(
                        &projection.prefix_data(),
                        maximum,
                    )?;
                let (body_construction, maximum_checkpoint_encoded) =
                    Self::original_restoration_coordinator_serialization_geometry_data(
                        &projection,
                        size_of::<CoordinatorCommitmentCheckpoint17>()
                            .max(size_of::<CoordinatorCommitmentEntry17>()),
                        maximum,
                    )?;
                let construction = prefix_construction
                    .checked_add(body_construction)
                    .filter(|bytes| *bytes <= maximum)
                    .ok_or(RuntimeError::ResourceLimit)?;
                Ok(OriginalRestoredCoordinatorBoundary17 {
                    runtime: self,
                    cut,
                    sequence: log.next_sequence,
                    ordinal,
                    maximum_checkpoint_encoded,
                    construction,
                })
            })
    }
}

pub(super) fn boundary_counter_scratch_data() -> usize {
    size_of::<OriginalRestoredCoordinatorBoundary17>()
        + size_of::<&OriginalRestoredCoordinatorBoundary17>()
        + size_of::<Result<OriginalRestoredCoordinatorBoundary17, RuntimeError>>()
        + size_of::<ActivationProjection<'static>>()
        + size_of::<HashProjection>() + size_of::<ReferenceProjection>()
        + size_of::<SafePointProjection>() + size_of::<CheckpointProjection<'static>>()
        + size_of::<PrefixProjection<'static>>()
        + size_of::<Result<CheckpointProjection<'static>, RuntimeError>>()
        + size_of::<Result<(usize, usize), RuntimeError>>()
        + size_of::<&WorldActivation>() + size_of::<&ActivationRecord>()
        + size_of::<std::collections::btree_map::Values<'static, Id, OwnerCustody>>()
        + size_of::<std::collections::btree_map::Values<'static, Id, RetainedOperation>>()
        + size_of::<std::collections::btree_map::Values<'static, Id, super::super::inputs::RetainedInput>>()
        + crate::node_scheduling::CausalScheduler::coordinator17_capture_boundary_counter_scratch_data()
        + NodeRuntime::capture_serialization_counter_scratch_data()
}

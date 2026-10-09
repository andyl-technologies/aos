//! Authenticates the fixed installed original scheduling-epoch preservation policy.
//!
//! Original coordinator bodies come from the signed archive; separately canonical
//! scheduler/runtime objects preserve that exact source context. This child never
//! creates native certificates or executes an inherited operation.

use std::{collections::BTreeMap, io::Write};

use crucible::{
    node_admission::AdmittedGraph,
    node_contract::{RuntimeSnapshot, SavedRuntimeResult},
    node_scheduling::{
        InputPayload, SavedEpochReservation, SavedSchedulingEpoch, SchedulingEpochEvidence,
        SchedulingSnapshot,
    },
    node_state::{NativeArchiveRecord, StateError, StateErrorCode},
};
use crucible_node_contract::{ContentRef, Position, canonical};

use super::profile::MixedProfile;

pub(super) fn installed_policy(profile: &MixedProfile) -> Result<InputPayload, StateError> {
    if !profile.scheduling_epochs || profile.isa != "x86_64" || !profile.public_continuation {
        return Err(refused(
            "original scheduling epochs are not this selected installed profile",
        ));
    }
    let bytes = crucible::node_scheduling::SCHEDULING_EPOCH_POLICY_SPECIFICATION
        .as_bytes()
        .to_vec();
    let reference = crucible::node_scheduling::closed_scheduling_epoch_policy().map_err(refused)?;
    if !profile
        .scenario
        .content
        .iter()
        .any(|body| body.reference == reference && body.bytes == bytes)
    {
        return Err(refused(
            "selected scheduling policy body is absent from immutable installed world",
        ));
    }
    Ok(InputPayload { reference, bytes })
}

pub(super) fn authenticate(
    profile: &MixedProfile,
    graph: &AdmittedGraph,
    runtime: &RuntimeSnapshot,
    snapshot: &SchedulingSnapshot,
    evidence: &SchedulingEpochEvidence,
) -> Result<(), StateError> {
    if graph.world() != &profile.scenario.world
        || installed_policy(profile)? != evidence.policy
        || runtime.source_activation.world_binding_hash != snapshot.world_binding_hash
        || runtime.source_activation.generation != snapshot.source_generation
        || runtime.source_activation.activation_id != snapshot.source_activation_id
        || runtime.source_activation.boundary != snapshot.source_boundary
        || runtime.capture_cut != snapshot.capture_cut
        || runtime.capture_ordinal != snapshot.capture_ordinal
        || !runtime.inputs.is_empty()
    {
        return Err(refused("installed original scheduling scope differs"));
    }
    crucible::node_scheduling::validate_scheduling_epoch_bodies(graph, snapshot, evidence)
        .map_err(refused)?;
    for row in &evidence.rows {
        for inherited in &row.reservations {
            if inherited.reservation.node.as_str() != "cpu"
                || inherited.reservation.owner.as_str() != "owner/cpu"
                || !runtime.operations.iter().any(|operation| {
                    operation.operation == inherited.reservation.operation
                        && operation.route.node == inherited.reservation.node
                        && operation.input_batch.is_none()
                        && operation.scheduling_commit.is_none()
                        && matches!(operation.result, SavedRuntimeResult::Pending)
                })
            {
                return Err(refused(
                    "epoch policy does not authenticate this original pending native operation",
                ));
            }
        }
    }
    Ok(())
}

pub(super) fn original_evidence(
    profile: &MixedProfile,
    archive: &NativeArchiveRecord,
    boundary: Position,
) -> Result<Option<SchedulingEpochEvidence>, StateError> {
    let policy = installed_policy(profile)?;
    let scheduling = archive.scheduling_snapshot()?;
    let mut objects = BTreeMap::new();
    let rows = match scheduling.schema_version {
        1 => {
            let mut reservations = Vec::new();
            for saved in &scheduling.positions {
                if saved.position >= boundary {
                    continue;
                }
                let reservation = scheduling
                    .reservations
                    .iter()
                    .find(|reservation| reservation.owner == saved.owner)
                    .ok_or_else(|| refused("lower original cursor has no retained permission"))?;
                let producer = scheduling
                    .producers
                    .iter()
                    .find(|producer| producer.node == reservation.node)
                    .ok_or_else(|| refused("original pending producer absent"))?;
                reservations.push(SavedEpochReservation {
                    reservation: reservation.clone(),
                    position: saved.clone(),
                    producer: producer.clone(),
                });
            }
            if reservations.is_empty() {
                return Ok(None);
            }
            let coordinator = archive.manifest().coordinator_state_ref.clone();
            let source_runtime = archive.runtime_snapshot()?;
            let mut credit = BodyCredit::new(policy.bytes.len())?;
            credit.reference(&coordinator)?;
            // Count both borrowed closed DTOs before canonical allocation or
            // copying the authenticated coordinator body. Their numeric fields
            // are bounded editions or string counters, so JCS ordering does not
            // increase this compact serialization length.
            serde_json::to_writer(&mut credit, &scheduling).map_err(refused)?;
            serde_json::to_writer(&mut credit, &source_runtime).map_err(refused)?;

            let scheduler = object(
                &scheduling,
                "application/vnd.crucible.original-scheduler+json",
            )?;
            let runtime = object(
                &source_runtime,
                "application/vnd.crucible.original-runtime+json",
            )?;
            objects.insert(
                coordinator.clone(),
                InputPayload {
                    bytes: archive.object_bytes(
                        &coordinator,
                        crucible::node_scheduling::MAXIMUM_SCHEDULING_EPOCH_BYTES,
                    )?,
                    reference: coordinator.clone(),
                },
            );
            objects.insert(scheduler.reference.clone(), scheduler.clone());
            objects.insert(runtime.reference.clone(), runtime.clone());
            vec![SavedSchedulingEpoch {
                schema_version: 1,
                source_generation: scheduling.source_generation,
                coordinator,
                scheduler: scheduler.reference,
                runtime: runtime.reference,
                policy: policy.reference.clone(),
                reservations,
            }]
        }
        2 => {
            let rows = scheduling
                .original_epochs
                .ok_or_else(|| refused("missing original epoch rows"))?;
            let mut references = std::collections::BTreeSet::new();
            if rows.is_empty() || rows.len() > crucible::node_scheduling::MAXIMUM_SCHEDULING_EPOCHS
            {
                return Err(refused("original epoch roster exceeds finite credit"));
            }
            for row in &rows {
                if row.policy != policy.reference {
                    return Err(refused(
                        "source epoch policy differs from independently installed policy",
                    ));
                }
                references.extend([&row.coordinator, &row.scheduler, &row.runtime]);
            }
            let mut credit = BodyCredit::new(policy.bytes.len())?;
            for reference in &references {
                credit.reference(reference)?;
            }
            for reference in references {
                objects.insert(
                    reference.clone(),
                    InputPayload {
                        reference: reference.clone(),
                        bytes: archive.object_bytes(
                            reference,
                            crucible::node_scheduling::MAXIMUM_SCHEDULING_EPOCH_BYTES,
                        )?,
                    },
                );
            }
            rows
        }
        _ => return Err(refused("unsupported original scheduler edition")),
    };
    Ok(Some(SchedulingEpochEvidence {
        policy,
        rows,
        objects: objects.into_values().collect(),
    }))
}

fn object<T: serde::Serialize>(value: &T, media: &str) -> Result<InputPayload, StateError> {
    let bytes = canonical::canonical_json(&serde_json::to_value(value).map_err(refused)?)
        .map_err(refused)?;
    if bytes.len() > crucible::node_scheduling::MAXIMUM_SCHEDULING_EPOCH_BYTES {
        return Err(refused(
            "original epoch body exceeds installed finite credit",
        ));
    }
    let reference = canonical::content_ref(&bytes, media).map_err(refused)?;
    Ok(InputPayload { reference, bytes })
}

struct BodyCredit {
    remaining: usize,
}

impl BodyCredit {
    fn new(policy_bytes: usize) -> Result<Self, StateError> {
        Ok(Self {
            remaining: crucible::node_scheduling::MAXIMUM_SCHEDULING_EPOCH_BYTES
                .checked_sub(policy_bytes)
                .ok_or_else(|| refused("original epoch policy exceeds body credit"))?,
        })
    }

    fn reference(&mut self, reference: &ContentRef) -> Result<(), StateError> {
        let length = usize::try_from(reference.length.get()).map_err(refused)?;
        self.remaining = self
            .remaining
            .checked_sub(length)
            .ok_or_else(|| refused("original epoch aggregate body credit exhausted"))?;
        Ok(())
    }
}

impl Write for BodyCredit {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.remaining = self
            .remaining
            .checked_sub(bytes.len())
            .ok_or_else(|| std::io::Error::other("original epoch body credit exhausted"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
#[path = "scheduling_epochs_tests.rs"]
mod tests;

fn refused(error: impl std::fmt::Display) -> StateError {
    StateError::new(
        StateErrorCode::NativeEvidence,
        "installed scheduling epochs",
        error.to_string(),
    )
}

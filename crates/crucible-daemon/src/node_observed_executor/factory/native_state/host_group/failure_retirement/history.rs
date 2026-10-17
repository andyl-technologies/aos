//! Keeps actual whole-world failure history under the prebirth original source credit.
//!
//! This operational index names positive byte-owning model and native readers.
//! It does not reuse a capture DTO, infer dependency edges from JSON shape, or
//! certify Shutdown, group emptiness, reaping or supervisor release.
//!
//! ```text
//! original-failure-history.1 = source credit + complete original activation +
//!   actual Runtime/Scheduler + prepared owners/Ready + native history bodies
//! ```

use crucible::{
    node_contract::{NodeRuntime, RetainedRetirementHistory, RuntimeSnapshot, WorldActivation},
    node_scheduling::{InputPayload, SchedulingSnapshot},
};
use crucible_node_contract::{Position, PreparedOwner, U64};
use serde::{Deserialize, ser::SerializeSeq};

use super::*;

pub(in crate::node_observed_executor::factory::native_state) struct OriginalFailureHistory {
    metadata: InputPayload,
    native: Vec<RetainedRetirementHistory>,
}

#[derive(Serialize)]
struct Metadata<'a> {
    format: &'static str,
    version: u16,
    source_credit: &'a ContentRef,
    activation: crucible::node_contract::SavedRuntimeActivation,
    runtime: &'a RuntimeSnapshot,
    scheduler: &'a SchedulingSnapshot,
    owners: &'a [PreparedOwner],
    coordinator: &'a InputPayload,
    nodes: Nodes<'a>,
    histories: Histories<'a>,
}

struct Nodes<'a>(&'a [crucible::node_contract::ValidatedNodePreparation]);

impl Serialize for Nodes<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for node in self.0 {
            sequence.serialize_element(&(node.node(), node.readiness(), node.prepared_owners()))?;
        }
        sequence.end()
    }
}

struct Histories<'a>(&'a [RetainedRetirementHistory]);

impl Serialize for Histories<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for history in self.0 {
            sequence.serialize_element(&(&history.route, References(&history.bodies)))?;
        }
        sequence.end()
    }
}

struct References<'a>(&'a [InputPayload]);

impl Serialize for References<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for body in self.0 {
            sequence.serialize_element(&body.reference)?;
        }
        sequence.end()
    }
}

impl FailureRetirementPreparation {
    pub(in crate::node_observed_executor::factory::native_state) fn retain_history(
        &self,
        runtime: &NodeRuntime,
        activation: &WorldActivation,
        cut: Position,
        ordinal: U64,
    ) -> Result<OriginalFailureHistory, NodeObservedError> {
        if activation.record().world_binding_hash != self.world
            || activation
                .prepared_owners()
                .is_none_or(|owners| owners.len() != 4)
            || activation.node_preparations().len() != 4
        {
            return Err(refused(
                "original failure history names another complete source",
            ));
        }
        let coordinator = activation
            .coordinator_snapshot()
            .ok_or_else(|| refused("original complete coordinator body is absent"))?;
        coordinator.reference.verify(&coordinator.bytes)?;
        let saved = runtime
            .runtime_snapshot(cut, ordinal, RUNTIME_BYTES)
            .map_err(error)?;
        let scheduler = runtime
            .retirement_scheduler_snapshot(activation, cut, ordinal)
            .map_err(error)?;
        let native_credit = 3 * HOST_RECORD_BYTES + NATIVE_RECORD_BYTES + PRIVATE_ACK_BYTES;
        // The common runtime first verifies this exact opaque activation, then
        // charges every selected native upper bound before any history copy.
        let native = runtime
            .retirement_histories(activation, native_credit)
            .map_err(error)?;
        if native.len() != 4 {
            return Err(refused("complete original native history roster differs"));
        }
        let metadata = Metadata {
            format: "crucible.independent-group.original-failure-history",
            version: 1,
            source_credit: &self.reference,
            activation: activation.record().into(),
            runtime: &saved,
            scheduler: &scheduler,
            owners: activation
                .prepared_owners()
                .ok_or_else(|| refused("original complete preparation owners absent"))?,
            coordinator,
            nodes: Nodes(activation.node_preparations()),
            histories: Histories(&native),
        };
        // Runtime snapshots have their existing per-record ceiling. This
        // separate complete combined metadata count precedes outer allocation;
        // it does not claim allocator-wide transient parser/copy peak credit.
        serde_json::to_writer(IndexCredit(RUNTIME_BYTES), &metadata)?;
        let bytes = serde_json::to_vec(&metadata)?;
        let reference = canonical::content_ref(&bytes, "application/json")?;
        Ok(OriginalFailureHistory {
            metadata: InputPayload { reference, bytes },
            native,
        })
    }
}

impl OriginalFailureHistory {
    pub(in crate::node_observed_executor::factory::native_state) fn objects(
        &self,
    ) -> impl Iterator<Item = &InputPayload> {
        std::iter::once(&self.metadata)
            .chain(self.native.iter().flat_map(|history| history.bodies.iter()))
    }

    pub(in crate::node_observed_executor::factory::native_state) fn authenticate_activation(
        &self,
        target: &crucible::node_contract::ActivationRecord,
    ) -> Result<(), NodeObservedError> {
        #[derive(Deserialize)]
        struct OriginalScope {
            activation: crucible::node_contract::SavedRuntimeActivation,
        }
        self.metadata.reference.verify(&self.metadata.bytes)?;
        if self.metadata.bytes.len() > RUNTIME_BYTES {
            return Err(refused("original scope metadata exceeds prebirth credit"));
        }
        let source: OriginalScope = serde_json::from_slice(&self.metadata.bytes)?;
        if source.activation != target.into() {
            return Err(refused("same original complete activation scope differs"));
        }
        Ok(())
    }

    pub(in crate::node_observed_executor::factory::native_state) fn authenticate_retired(
        &self,
        retired: &crucible::node_contract::QuarantinedRuntime,
        activation: &WorldActivation,
    ) -> Result<(), NodeObservedError> {
        #[derive(Deserialize)]
        struct OriginalLedger {
            activation: crucible::node_contract::SavedRuntimeActivation,
            runtime: RuntimeSnapshot,
        }

        self.metadata.reference.verify(&self.metadata.bytes)?;
        if self.metadata.bytes.len() > RUNTIME_BYTES {
            return Err(refused(
                "original retired ledger exceeds its prebirth credit",
            ));
        }
        // This bounded operational parse reads our own exact original metadata.
        // Unknown outer members are the independently retained scheduler/model
        // roster, not alternative authority. No standalone DTO is admitted.
        let saved: OriginalLedger = serde_json::from_slice(&self.metadata.bytes)?;
        if saved.activation != activation.record().into() {
            return Err(refused("original retired activation differs"));
        }
        retired
            .authenticate_retired_ledger(&saved.runtime, RUNTIME_BYTES)
            .map_err(error)?;
        let actual = retired
            .retirement_histories(
                activation,
                3 * HOST_RECORD_BYTES + NATIVE_RECORD_BYTES + PRIVATE_ACK_BYTES,
            )
            .map_err(error)?;
        if actual.len() != self.native.len()
            || actual.iter().zip(&self.native).any(|(actual, original)| {
                actual.route != original.route || actual.bodies != original.bodies
            })
        {
            return Err(refused(
                "same original Host/native history changed during retirement",
            ));
        }
        Ok(())
    }

    pub(in crate::node_observed_executor::factory::native_state) fn supervision_references(
        &self,
    ) -> Result<super::super::super::custody::FailedHistoryReferences, NodeObservedError> {
        let cpu = self
            .native
            .iter()
            .find(|entry| entry.route.node.as_str() == "cpu")
            .ok_or_else(|| refused("original CPU history absent"))?;
        if self.native.len() != 4
            || cpu.bodies.len() != 3
            || self
                .native
                .iter()
                .filter(|entry| entry.route.node.as_str() != "cpu")
                .any(|entry| entry.bodies.len() != 1)
        {
            return Err(refused("closed four-owner failure history roles differ"));
        }
        Ok(super::super::super::custody::FailedHistoryReferences {
            metadata: self.metadata.reference.clone(),
            native: cpu.bodies[1].reference.clone(),
            acknowledgements: cpu.bodies[2].reference.clone(),
        })
    }
}

fn error(value: impl std::fmt::Display) -> NodeObservedError {
    refused(&value.to_string())
}

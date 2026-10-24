//! Borrows complete common owner values without serializing live permissions.

use super::*;
use serde::ser::SerializeStruct;

/// Lends inert history for a real retained common owner.
///
/// The matching capacity walk records shared edges separately. This wrapper
/// serializes no pointer, token constructor, Rc control block or live claim.
pub(crate) enum OriginalRestoredOwnerHistory<'a> {
    Admission(&'a OperationAdmission),
    World(&'a WorldActivation),
    InputBatch(&'a RuntimeInputBatch),
}

impl Serialize for OriginalRestoredOwnerHistory<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error;
        match self {
            Self::Admission(original) => {
                OriginalRestoredOwnerCapacityRows(*original).metadata_demand_data()
            }
            Self::World(original) => {
                OriginalRestoredOwnerCapacityRows(*original).metadata_demand_data()
            }
            Self::InputBatch(original) => {
                OriginalRestoredOwnerCapacityRows(*original).metadata_demand_data()
            }
        }
        .map_err(S::Error::custom)?;
        let mut value = serializer.serialize_struct("RestoredCommonOwnerHistory", 2)?;
        match self {
            Self::Admission(original) => {
                value.serialize_field("kind", "admission")?;
                value.serialize_field("value", &Admission(original))?;
            }
            Self::World(original) => {
                value.serialize_field("kind", "world")?;
                value.serialize_field("value", &World(original))?;
            }
            Self::InputBatch(original) => {
                value.serialize_field("kind", "input_batch")?;
                value.serialize_field("value", &Batch(original))?;
            }
        }
        value.end()
    }
}

struct Admission<'a>(&'a OperationAdmission);

impl Serialize for Admission<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let OperationAdmission {
            token,
            request,
            activation,
            inputs,
        } = self.0;
        let OperationToken {
            authority: _,
            operation,
            route,
        } = token;
        let mut value = serializer.serialize_struct("RestoredAdmissionHistory", 5)?;
        value.serialize_field("operation", operation)?;
        value.serialize_field("route", route)?;
        value.serialize_field("request", request)?;
        value.serialize_field("activation", &World(activation))?;
        value.serialize_field("inputs", &inputs.as_deref().map(Batch))?;
        value.end()
    }
}

struct World<'a>(&'a WorldActivation);

impl Serialize for World<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let WorldActivation {
            authority: _,
            record,
            nodes,
            preparation,
        } = self.0;
        let mut value = serializer.serialize_struct("RestoredWorldHistory", 3)?;
        value.serialize_field("record", &Activation(record))?;
        value.serialize_field("nodes", &Nodes(nodes))?;
        value.serialize_field("preparation", &preparation.as_deref().map(Publication))?;
        value.end()
    }
}

struct Activation<'a>(&'a ActivationRecord);

impl Serialize for Activation<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let ActivationRecord {
            generation,
            activation_id,
            world_binding_hash,
            owners,
            boundary,
        } = self.0;
        let mut value = serializer.serialize_struct("RestoredActivationHistory", 5)?;
        value.serialize_field("generation", generation)?;
        value.serialize_field("activation_id", activation_id)?;
        value.serialize_field("world_binding_hash", world_binding_hash)?;
        value.serialize_field("owners", owners)?;
        value.serialize_field("boundary", boundary)?;
        value.end()
    }
}

struct Nodes<'a>(&'a [ValidatedNodePreparation]);

impl Serialize for Nodes<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for node in self.0 {
            sequence.serialize_element(&Node(node))?;
        }
        sequence.end()
    }
}

struct Node<'a>(&'a ValidatedNodePreparation);

impl Serialize for Node<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let ValidatedNodePreparation {
            node,
            readiness,
            prepared_owners,
        } = self.0;
        let mut value = serializer.serialize_struct("RestoredNodePreparationHistory", 3)?;
        value.serialize_field("node", node)?;
        value.serialize_field("readiness", &Readiness(readiness))?;
        value.serialize_field("prepared_owners", prepared_owners)?;
        value.end()
    }
}

struct Readiness<'a>(&'a ReadyAttestation);

impl Serialize for Readiness<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let ReadyAttestation {
            owners,
            boundary,
            state_inventory,
            ready_receipt,
        } = self.0;
        let mut value = serializer.serialize_struct("RestoredReadinessHistory", 4)?;
        value.serialize_field("owners", owners)?;
        value.serialize_field("boundary", boundary)?;
        value.serialize_field("state_inventory", state_inventory)?;
        value.serialize_field("ready_receipt", ready_receipt)?;
        value.end()
    }
}

struct Publication<'a>(&'a PreparedWorldPublication);

impl Serialize for Publication<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let PreparedWorldPublication {
            nodes,
            owners,
            coordinator,
        } = self.0;
        let mut value = serializer.serialize_struct("RestoredWorldPublicationHistory", 3)?;
        value.serialize_field("nodes", &Nodes(nodes))?;
        value.serialize_field("owners", owners)?;
        value.serialize_field("coordinator", coordinator)?;
        value.end()
    }
}

struct Batch<'a>(&'a RuntimeInputBatch);

impl Serialize for Batch<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let RuntimeInputBatch {
            activation,
            node,
            stage_operation,
            batch,
            owners,
            cutoff,
            inventory,
            deliveries,
            payloads,
        } = self.0;
        let mut value = serializer.serialize_struct("RestoredInputBatchHistory", 9)?;
        value.serialize_field("activation", &World(activation))?;
        value.serialize_field("node", node)?;
        value.serialize_field("stage_operation", stage_operation)?;
        value.serialize_field("batch", batch)?;
        value.serialize_field("owners", owners)?;
        value.serialize_field("cutoff", cutoff)?;
        value.serialize_field("inventory", inventory)?;
        value.serialize_field("deliveries", deliveries)?;
        value.serialize_field("payloads", payloads)?;
        value.end()
    }
}

pub(super) fn counter_scratch_data() -> usize {
    size_of::<OriginalRestoredOwnerHistory<'static>>()
        + size_of::<Admission<'static>>()
        + size_of::<World<'static>>()
        + size_of::<Activation<'static>>()
        + size_of::<Nodes<'static>>()
        + size_of::<Node<'static>>()
        + size_of::<Readiness<'static>>()
        + size_of::<Publication<'static>>()
        + size_of::<Batch<'static>>()
        + size_of::<Option<Batch<'static>>>()
        + size_of::<Option<Publication<'static>>>()
        + size_of::<Option<&RuntimeInputBatch>>()
        + size_of::<Option<&PreparedWorldPublication>>()
        + size_of::<&Option<Batch<'static>>>()
        + size_of::<&Option<Publication<'static>>>()
        + size_of::<std::slice::Iter<'static, ValidatedNodePreparation>>()
}

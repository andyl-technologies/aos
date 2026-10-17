//! Immutable staged input cuts and separately authenticated native custody.

use serde::{Deserialize, Serialize};

use crucible_node_contract::{ContentRef, Id, Position};

use crate::node_contract::{OwnerIdentity, WorldActivation};

use super::event::Delivery;

/// Transfers one retained immutable payload into native staging custody.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputPayload {
    /// Binds the exact original immutable bytes and media type.
    pub reference: ContentRef,
    /// Carries checked bytes rather than a reference to released native storage.
    pub bytes: Vec<u8>,
}

/// Carries a coordinator-authorized immutable input cut before native execution.
///
/// This handle has no public constructor or clone operation. Staging it must not
/// consume modeled input, execute a reaction or change guest-visible clocks.
#[derive(Debug)]
pub struct RuntimeInputBatch {
    pub(crate) activation: WorldActivation,
    pub(crate) node: Id,
    pub(crate) stage_operation: Id,
    pub(crate) batch: Id,
    pub(crate) owners: Vec<OwnerIdentity>,
    pub(crate) cutoff: Position,
    pub(crate) inventory: ContentRef,
    pub(crate) deliveries: Vec<Delivery>,
    pub(crate) payloads: Vec<InputPayload>,
}

impl RuntimeInputBatch {
    /// Returns the original complete committed world authority.
    pub fn activation(&self) -> &WorldActivation {
        &self.activation
    }

    /// Returns the original target logical node.
    pub fn node(&self) -> &Id {
        &self.node
    }

    /// Returns the distinct original staging operation identity.
    pub fn stage_operation(&self) -> &Id {
        &self.stage_operation
    }

    /// Returns the immutable batch identity carried by subsequent execution.
    pub fn batch(&self) -> &Id {
        &self.batch
    }

    /// Returns the complete original native owner incarnation roster.
    pub fn owners(&self) -> &[OwnerIdentity] {
        &self.owners
    }

    /// Returns the exclusive superdense input cut, independent of modeled execution.
    pub fn cutoff(&self) -> Position {
        self.cutoff
    }

    /// Returns the authenticated complete canonical delivery-inventory commitment.
    pub fn inventory(&self) -> &ContentRef {
        &self.inventory
    }

    /// Returns all retained inputs in deterministic delivery order.
    pub fn deliveries(&self) -> &[Delivery] {
        &self.deliveries
    }

    /// Returns readable immutable payload objects under coordinator custody.
    pub fn payloads(&self) -> &[InputPayload] {
        &self.payloads
    }

    pub(crate) fn retained_copy(&self) -> Self {
        Self {
            activation: self.activation.clone(),
            node: self.node.clone(),
            stage_operation: self.stage_operation.clone(),
            batch: self.batch.clone(),
            owners: self.owners.clone(),
            cutoff: self.cutoff,
            inventory: self.inventory.clone(),
            deliveries: self.deliveries.clone(),
            payloads: self.payloads.clone(),
        }
    }
}

/// Reports native staging readiness without claiming semantic input consumption.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeInputAcknowledgement {
    /// Names the unchanged original staging operation.
    pub stage_operation: Id,
    /// Names the original batch rather than a newly sampled replacement.
    pub batch: Id,
    /// Names the original logical target.
    pub node: Id,
    /// Retains the actual current native owner generations.
    pub owners: Vec<OwnerIdentity>,
    /// Retains the exclusive staged input cut.
    pub cutoff: Position,
    /// Commits to the complete unchanged ordered original inventory.
    pub inventory: ContentRef,
    /// Binds authentic native buffer readiness and input custody evidence.
    pub proof_ref: ContentRef,
}

/// Carries native staging evidence authenticated by the retaining runtime.
#[derive(Debug)]
pub struct ValidatedInputAcknowledgement {
    pub(crate) activation: WorldActivation,
    pub(crate) acknowledgement: NativeInputAcknowledgement,
}

impl ValidatedInputAcknowledgement {
    pub(crate) fn new(
        activation: WorldActivation,
        acknowledgement: NativeInputAcknowledgement,
    ) -> Self {
        Self {
            activation,
            acknowledgement,
        }
    }

    /// Returns the original immutable batch identity.
    pub fn batch(&self) -> &Id {
        &self.acknowledgement.batch
    }
}

/// Carries the coordinator commitment to original authenticated native staging.
#[derive(Debug)]
pub struct InputCustodyCommit {
    pub(crate) activation: WorldActivation,
    pub(crate) node: Id,
    pub(crate) stage_operation: Id,
    pub(crate) batch: Id,
    pub(crate) inventory: ContentRef,
    pub(crate) cutoff: Position,
}

impl InputCustodyCommit {
    /// Returns the unchanged complete world authority.
    pub fn activation(&self) -> &WorldActivation {
        &self.activation
    }
    /// Returns the original logical target.
    pub fn node(&self) -> &Id {
        &self.node
    }
    /// Returns the original staging operation.
    pub fn stage_operation(&self) -> &Id {
        &self.stage_operation
    }
    /// Returns the original immutable input batch.
    pub fn batch(&self) -> &Id {
        &self.batch
    }
    /// Returns the complete frozen delivery commitment.
    pub fn inventory(&self) -> &ContentRef {
        &self.inventory
    }
    /// Returns the original exclusive input cut.
    pub fn cutoff(&self) -> Position {
        self.cutoff
    }
    pub(crate) fn retained_copy(&self) -> Self {
        Self {
            activation: self.activation.clone(),
            node: self.node.clone(),
            stage_operation: self.stage_operation.clone(),
            batch: self.batch.clone(),
            inventory: self.inventory.clone(),
            cutoff: self.cutoff,
        }
    }
}

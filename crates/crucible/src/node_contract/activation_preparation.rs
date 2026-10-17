//! Original validated readiness and bounded public whole-world publication data.
//!
//! These records preserve preparation evidence as data. Only the activation
//! barrier can attach them to its opaque, durably committed local authority.
//! Prepared tokens come from actual adapter custody; coordinator bytes come
//! from the trusted publisher's complete prepared state.

use std::{collections::BTreeMap, rc::Rc};

use crucible_node_contract::{HashRef, Id, PreparedOwner, Validate};

use super::{ReadyAttestation, RuntimeError};
use crate::node_scheduling::InputPayload;

/// Bounds the complete coordinator object retained for public world activation.
pub const MAXIMUM_ACTIVATION_COORDINATOR_BYTES: usize = 16 * 1024 * 1024;

/// Retains one node's original independently validated closed-gate preparation.
#[derive(Clone, Debug, PartialEq, serde::Serialize)]
pub struct ValidatedNodePreparation {
    pub(crate) node: Id,
    pub(crate) readiness: ReadyAttestation,
    pub(crate) prepared_owners: Option<Vec<PreparedOwner>>,
}

impl ValidatedNodePreparation {
    /// Returns the actual public node whose preparation was validated.
    pub fn node(&self) -> &Id {
        &self.node
    }

    /// Borrows the original native readiness at the activation boundary.
    ///
    /// This historical evidence does not establish current physical suspension
    /// after the world has executed or grant another activation permission.
    pub fn readiness(&self) -> &ReadyAttestation {
        &self.readiness
    }

    /// Borrows original public owner records, or explicit unsupported mapping.
    pub fn prepared_owners(&self) -> Option<&[PreparedOwner]> {
        self.prepared_owners.as_deref()
    }
}

/// Retains complete original preparation and coordinator bytes for publication.
///
/// The trusted publisher must durably bind these exact bytes and owner records
/// to the supplied activation. A committed scalar activation record alone is
/// insufficient for this public preparation contract.
#[derive(Clone, Debug, PartialEq)]
pub struct PreparedWorldPublication {
    pub(crate) nodes: Rc<[ValidatedNodePreparation]>,
    pub(crate) owners: Vec<PreparedOwner>,
    pub(crate) coordinator: InputPayload,
}

/// Validates complete owner aliases against the actual admitted graph bindings.
pub(crate) fn validate_owner_mapping(
    preparation: &ValidatedNodePreparation,
    bindings: &BTreeMap<Id, Vec<HashRef>>,
) -> Result<(), RuntimeError> {
    let Some(owners) = &preparation.prepared_owners else {
        return Ok(());
    };
    if owners.len() != preparation.readiness.owners.len() || owners.is_empty() {
        return Err(RuntimeError::InvalidReceipt);
    }

    for (owner, original) in owners.iter().zip(&preparation.readiness.owners) {
        owner.validate().map_err(|_| RuntimeError::InvalidReceipt)?;
        if owner.owner_id != original.owner
            || owner.incarnation_id != original.incarnation
            || owner.owner_generation != original.generation
            || owner.ready_receipt != preparation.readiness.ready_receipt
            || bindings.get(&original.owner) != Some(&owner.binding_hashes)
        {
            return Err(RuntimeError::InvalidReceipt);
        }
    }
    Ok(())
}

impl PreparedWorldPublication {
    /// Borrows every original validated node preparation in node-ID order.
    pub fn nodes(&self) -> &[ValidatedNodePreparation] {
        &self.nodes
    }

    /// Borrows the complete original public owner roster in owner-ID order.
    pub fn prepared_owners(&self) -> &[PreparedOwner] {
        &self.owners
    }

    /// Borrows the actual complete prepared coordinator object and its identity.
    pub fn coordinator_snapshot(&self) -> &InputPayload {
        &self.coordinator
    }

    pub(crate) fn validate_coordinator(&self) -> Result<(), RuntimeError> {
        if self.coordinator.bytes.is_empty()
            || self.coordinator.bytes.len() > MAXIMUM_ACTIVATION_COORDINATOR_BYTES
        {
            return Err(RuntimeError::ResourceLimit);
        }

        self.coordinator
            .reference
            .verify(&self.coordinator.bytes)
            .map_err(|_| RuntimeError::InvalidReceipt)
    }
}

//! Borrows the saved activation representation for operational history encoding.
//!
//! The live activation record remains unserializable. This view contains only
//! the same inert fields as SavedRuntimeActivation and copies no owner roster.
//!
//! ```text
//! saved activation = generation + activation_id + world_binding_hash + owners + boundary
//! ```

use crucible_node_contract::{HashRef, Id, Position, U64};
use serde::Serialize;

use super::{ActivationRecord, OwnerIdentity};

/// Borrows saved identity data without exposing process-local authority.
#[derive(Serialize)]
pub(crate) struct RetirementActivation<'a> {
    generation: U64,
    activation_id: &'a Id,
    world_binding_hash: &'a HashRef,
    owners: &'a [OwnerIdentity],
    boundary: Position,
}

impl<'a> From<&'a ActivationRecord> for RetirementActivation<'a> {
    fn from(record: &'a ActivationRecord) -> Self {
        Self {
            generation: record.generation,
            activation_id: &record.activation_id,
            world_binding_hash: &record.world_binding_hash,
            owners: &record.owners,
            boundary: record.boundary,
        }
    }
}

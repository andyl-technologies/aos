//! Authenticates ordered producer publications without changing legacy sidecars.
//!
//! Claims and direct rows are inert codec data. Only the owning runtime issues
//! an opaque input view after matching actual terminal permissions and validating
//! every source row through the original native adapter. No continuation codec
//! currently preserves this view; capture must refuse rather than omit it.

use super::*;
use crate::node_scheduling::{InputPayload, RuntimeInputBatch};
use crucible_node_contract::*;
use serde::{Deserialize, Serialize};
use std::rc::Rc;

/// Bounds a complete selected lineage lookup before consumer-native effects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OriginalInputLineageLimits {
    /// Bounds distinct complete typed body roles.
    pub maximum_objects: usize,
    /// Bounds original body bytes, counting each typed role.
    pub maximum_bytes: usize,
    /// Bounds aggregate declared direct edges and derived transitive edges.
    pub maximum_edges: usize,
}

impl Default for OriginalInputLineageLimits {
    fn default() -> Self {
        Self {
            maximum_objects: 4096,
            maximum_bytes: 64 * 1024 * 1024,
            maximum_edges: 65_536,
        }
    }
}

/// Describes inert original native scope, separately from producer-local IDs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginalPublicationOrigin {
    /// Binds the complete original owner compatibility.
    pub owner_binding_hash: HashRef,
    /// Names the original source owner.
    pub execution_owner_id: Id,
    /// Retains the original source control session.
    pub session_id: Id,
    /// Binds the original complete source world.
    pub world_binding_hash: HashRef,
    /// Retains the original committed activation.
    pub activation_id: Id,
    /// Retains the original world generation.
    pub world_generation: U64,
    /// Retains the original native incarnation.
    pub incarnation_id: Id,
    /// Retains the original owner generation.
    pub owner_generation: U64,
    /// Names the original admitted operation.
    pub operation_id: Id,
    /// Names the original admitted window.
    pub grant_id: Id,
    /// Retains the complete source observation body.
    pub observation_batch: ContentRef,
    /// Retains its original stop and native custody scope.
    pub stop_receipt: ContentRef,
    /// Retains the actual source proof root.
    pub measurement: ContentRef,
}

/// Declares one inert direct codec row; an empty row does not authenticate a leaf.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginalLineageRow {
    /// Preserves the complete original typed role.
    pub object: ContentRef,
    /// Preserves direct edges in strict full-reference order.
    pub dependencies: Vec<ContentRef>,
}

/// Carries a source codec claim that cannot itself authorize input or readiness.
///
/// The runtime checks it against its actual terminal publication and invokes the
/// same original source validator before and after body inspection. Implementors
/// must preflight the supplied aggregate limits before copying original bodies.
#[derive(Clone, Debug, PartialEq)]
pub struct OriginalPublicationClaim {
    /// Retains the actual source Event and producer-local FIFO unchanged.
    pub event: Event,
    /// Retains its explicit original source scope.
    pub origin: OriginalPublicationOrigin,
    /// Names the selected codec's exact standalone publication role.
    pub published: ContentRef,
    /// Retains every original typed body, including authenticated alias roles.
    pub objects: Vec<InputPayload>,
    /// Retains complete direct rows; missing rows are never inferred as leaves.
    pub rows: Vec<OriginalLineageRow>,
}

/// Carries runtime-sealed ordered original producer associations for one input.
///
/// Its fields are private and it has no serialized or caller-constructed form.
/// Equal IDs, payloads and publication coordinates retain separate occurrences
/// and producer scopes. This view grants no native source class or preservation.
#[derive(Debug)]
pub struct OriginalInputLineage {
    data: Rc<OriginalInputLineageData>,
}

#[derive(Debug)]
struct OriginalInputLineageData {
    source_scope: SavedOriginalInputScope,
    original: Rc<RuntimeInputBatch>,
    publications: Vec<OriginalPublicationClaim>,
}

impl OriginalInputLineage {
    /// Borrows the actual current opaque consumer input cut.
    ///
    /// Its runtime authority remains separate from the first source scope.
    pub fn original(&self) -> &RuntimeInputBatch {
        &self.data.original
    }

    /// Borrows one authenticated producer association per ordered delivery.
    pub fn publications(&self) -> &[OriginalPublicationClaim] {
        &self.data.publications
    }

    pub(crate) fn retained_copy(&self) -> Self {
        Self {
            // Sharing immutable runtime-issued originals does not allocate or
            // duplicate the bounded body inventory during consumer retention.
            data: Rc::clone(&self.data),
        }
    }
}

#[path = "runtime_original_input_lineage/assembly.rs"]
mod assembly;
#[path = "runtime_original_input_lineage/geometry.rs"]
mod geometry;

#[path = "runtime_original_input_lineage/preservation.rs"]
mod preservation;
pub use preservation::{
    SavedOriginalInputLineage, SavedOriginalInputScope, SavedOriginalPublication,
};

#[path = "runtime_original_input_lineage/record.rs"]
mod record;
pub use record::{
    OriginalLineageInputRecord, OriginalLineageProvenanceRecord, OriginalLineageRuntimeRecord,
};

#[path = "runtime_original_input_lineage/record_validation.rs"]
mod record_validation;

#[path = "runtime_original_input_lineage/body_validation.rs"]
mod body_validation;

#[path = "runtime_original_input_lineage/snapshot_credit.rs"]
pub(in crate::node_contract::runtime) mod snapshot_credit;

#[path = "runtime_original_input_lineage/snapshot.rs"]
mod snapshot;

#[path = "runtime_original_input_lineage/restoration.rs"]
mod restoration;
pub use restoration::{
    OriginalLineageJournal, OriginalLineageNativeScope, OriginalLineageOwnerMapping,
    OriginalLineageRestoration, OriginalLineageRestorationLimits,
};

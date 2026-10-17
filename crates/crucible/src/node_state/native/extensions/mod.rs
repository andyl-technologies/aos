//! Prepares an exact selected semantic closure without issuing native authority.
//!
//! The archive integration must separately authenticate actual native capture,
//! the original signed source, and each fresh backend reconstruction. These
//! records never qualify an imported graph or replace its installed semantics.
//!
//! ```json
//! {"schema_version":1,"world_binding_hash":{},"selection_identity":{},
//!  "policy":{},"applications":[],"definitions":[],"dependencies":[]}
//! ```

pub(super) mod archive;
pub(super) mod credits;
pub(super) mod evidence;
pub(super) mod graph_refs;
mod plan;
mod records;

#[cfg(test)]
mod tests;

use crucible_node_contract::ContentRef;

use crate::node_admission::AdmittedGraph;
use crate::node_state::StateError;

pub(crate) use graph_refs::SelectedGraphReferences;
pub(super) use plan::{PreparedExtensionClosure, prepare};
pub(super) use records::{ExtensionDependencyRecord, ExtensionInventory};

/// Resolves an installed preservation codec for actual selected native semantics.
///
/// Implementations belong to the trusted installation. A declaration digest,
/// source-issued feature name, or copied archive inventory cannot implement this
/// policy. Qualification covers the exact selected applications, handler code,
/// native profile restrictions, and declared timing/state effects.
pub trait NativeExtensionPreservationPolicy {
    /// Authenticates this codec's support for the exact selected semantic closure.
    ///
    /// # Errors
    /// Refuses unsupported scopes, handlers, native profiles, state effects,
    /// hidden dependencies, or unavailable installed preservation evidence.
    fn authenticate_selection(&self, graph: &AdmittedGraph) -> Result<(), StateError>;

    /// Reads the exact installed codec/preservation policy under a finite ceiling.
    ///
    /// # Errors
    /// Refuses absent policy bytes or a read exceeding the supplied allocation
    /// ceiling. The source must enforce that ceiling before allocating its result.
    fn policy(&self, maximum_bytes: usize) -> Result<(ContentRef, Vec<u8>), StateError>;

    /// Enumerates the complete dependencies of one actual selected original body.
    ///
    /// The returned sorted row is codec-authenticated. Empty rows require actual
    /// self-contained-body qualification; byte syntax and object counts cannot
    /// infer a leaf. Every dependency must belong to this selected closure.
    ///
    /// # Errors
    /// Refuses unknown body codecs, unresolved references, unavailable complete
    /// dependency evidence, or a result exceeding the supplied edge ceiling.
    fn dependencies(
        &self,
        graph: &AdmittedGraph,
        reference: &ContentRef,
        bytes: &[u8],
        maximum_dependencies: usize,
    ) -> Result<Vec<ContentRef>, StateError>;
}

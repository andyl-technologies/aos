//! Trusted native proof interfaces and independently bounded state operations.

use crucible_node_contract::{
    CaptureManifest, CapturedOwner, ContentRef, Id, Position, Repeatability,
};

use crate::node_admission::AdmittedGraph;
use crate::node_contract::OwnerIdentity;
use crate::node_scheduling::SchedulingSnapshot;

use super::{StateError, VerifiedStateContent};

/// Selects an explicit reconstruction strategy without automatic fallback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StateRestoreMode {
    /// Requires verified content sufficient after every source has terminated.
    DurableRestart,
    /// Requires current authenticated retained-source custody and branch isolation.
    LiveFork,
}

/// Selects the complete artifact contract required by the caller.
#[derive(Clone, Debug)]
pub struct StateRequirements {
    /// Names the explicitly selected preservation facet contract.
    pub preservation_contract: Id,
    /// Requires every modeled future-affecting object preserved without mutation.
    pub exact_model_continuation: bool,
    /// Requires qualified repeatable execution of the complete causal world.
    pub deterministic: bool,
    /// Selects durable reconstruction or separately qualified live branching.
    pub restore_mode: StateRestoreMode,
}

/// Bounds content and native reservations before staging allocates resources.
#[derive(Clone, Copy, Debug)]
pub struct StateLimits {
    /// Bounds each supplied manifest or coordinator snapshot before cloning.
    pub maximum_record_bytes: usize,
    /// Bounds distinct authoritative owners and state domains independently.
    pub maximum_owners_or_domains: usize,
    /// Bounds each content object before its fetch allocation.
    pub maximum_content_bytes: usize,
    /// Bounds total distinct authenticated content bytes retained in memory.
    pub maximum_total_content_bytes: usize,
    /// Bounds distinct content objects and queued closure references.
    pub maximum_content_objects: usize,
    /// Bounds dependency edges independently of distinct objects, including sharing.
    pub maximum_dependency_edges: usize,
    /// Bounds recursive selected-schema content dependencies.
    pub maximum_dependency_depth: usize,
    /// Bounds native memory reserved across the complete staged world.
    pub maximum_native_memory_bytes: u64,
    /// Bounds native writable storage reserved across the complete staged world.
    pub maximum_native_writable_bytes: u64,
    /// Bounds native processes reserved across the complete staged world.
    pub maximum_native_processes: u64,
    /// Bounds native descriptors reserved across the complete staged world.
    pub maximum_native_descriptors: u64,
}

impl Default for StateLimits {
    fn default() -> Self {
        Self {
            maximum_record_bytes: 8 * 1024 * 1024,
            maximum_owners_or_domains: 16_384,
            maximum_content_bytes: 64 * 1024 * 1024,
            maximum_total_content_bytes: 256 * 1024 * 1024,
            maximum_content_objects: 65_536,
            maximum_dependency_edges: 262_144,
            maximum_dependency_depth: 64,
            maximum_native_memory_bytes: 16 * 1024 * 1024 * 1024,
            maximum_native_writable_bytes: 64 * 1024 * 1024 * 1024,
            maximum_native_processes: 1024,
            maximum_native_descriptors: 65_536,
        }
    }
}

/// Reports native facts authenticated for one original owner capture.
#[derive(Clone, Debug)]
pub struct NativeOwnerCaptureProof {
    /// Names the exact authoritative capture owner whose original cut was checked.
    pub owner_id: Id,
    /// Enumerates the native proof's complete authoritative domain inventory.
    pub state_domain_ids: Vec<Id>,
    /// Gives the unchanged coherent world cut, independently of local idle cursors.
    pub cut: Position,
    /// Gives the preserved event ordinal without replaying a prefix.
    pub event_ordinal: crucible_node_contract::U64,
}

/// Reports complete coordinator and provenance facts authenticated by the adapter.
#[derive(Clone, Debug)]
pub struct NativeCoordinatorCaptureProof {
    /// Preserves every source owner incarnation for freshness checks, not execution.
    pub source_owners: Vec<OwnerIdentity>,
    /// Retains the complete graph-wide nondeterminism classification.
    pub world_repeatability: Repeatability,
    /// Decodes the bound scheduler continuation using its actual selected schema.
    pub scheduler: SchedulingSnapshot,
    /// Decodes the complete bound runtime operation and native input custody ledger.
    pub runtime: crate::node_contract::RuntimeSnapshot,
    /// Inventories completed native operations whose custody remains unacknowledged.
    ///
    /// This sorted unique inventory includes zero-output operations and committed
    /// coordinator publications. Empty scheduler reservations do not establish
    /// settled native acknowledgement custody. The complete original runtime
    /// ledger must remain preserved in the authenticated coordinator capture.
    pub pending_native_acknowledgements: Vec<Id>,
}

/// Authenticates selected native state schemas, unchanged cuts and full closures.
///
/// This is a trusted host boundary, not a provider-claim deserializer. Success
/// requires accepted proof for the exact installed implementation, model,
/// configuration and preservation facet. Adapters must authenticate pending
/// transfer custody, native event order, current PRNG state, coordinator/fault/
/// assertion state and omitted microstate. Merely comparing digests, draining a
/// simulator, or observing an architectural RAM image cannot satisfy this trait.
pub trait CaptureEvidence {
    /// Fetches exact immutable bytes while enforcing the ceiling before allocation.
    ///
    /// # Errors
    /// Rejects missing content, I/O failure, or a fetch above the supplied ceiling.
    fn content(&self, reference: &ContentRef, maximum_bytes: usize) -> Result<Vec<u8>, StateError>;

    /// Enumerates all dependencies under the supplied preallocation count ceiling.
    ///
    /// # Errors
    /// Rejects unsupported formats, malformed state, unknown object references,
    /// incomplete dependency inventories, or a count above the ceiling. Installed
    /// validators must enforce this bound before constructing the returned vector.
    /// Leaf bytes return an empty vector
    /// only when their selected format positively establishes that they are leaves.
    fn dependencies(
        &self,
        reference: &ContentRef,
        verified_bytes: &[u8],
        maximum_dependencies: usize,
    ) -> Result<Vec<ContentRef>, StateError>;

    /// Authenticates unchanged-cut domain closure and actual state-format support.
    ///
    /// # Errors
    /// Rejects incomplete/perturbing capture, incompatible native state schemas,
    /// unavailable retained leases, or unsupported reconstruction guarantees.
    /// Live-source validation must authenticate scope and expiry; durable mode
    /// must not depend on any original process, descriptor or kernel handle.
    fn verify_owner_capture(
        &self,
        graph: &AdmittedGraph,
        manifest: &CaptureManifest,
        owner: &CapturedOwner,
        requirements: &StateRequirements,
        content: &VerifiedStateContent,
    ) -> Result<NativeOwnerCaptureProof, StateError>;

    /// Authenticates cross-owner transfer custody, coordinator closure and provenance.
    ///
    /// # Errors
    /// Rejects missing or duplicated pending transfers, uncommitted-output
    /// promotion, omitted coordinator state, false guarantee metadata or stale
    /// provenance. The returned snapshot must decode the bound coordinator state;
    /// constructing a fresh scheduler is not restoration of its continuation.
    fn verify_coordinator_capture(
        &self,
        graph: &AdmittedGraph,
        manifest: &CaptureManifest,
        content: &VerifiedStateContent,
    ) -> Result<NativeCoordinatorCaptureProof, StateError>;
}

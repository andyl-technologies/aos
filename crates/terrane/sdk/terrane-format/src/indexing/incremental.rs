//! Discovers changed immutable namespace inputs for one registered index value.
//!
//! Preparation validates the reachable graph separately, without building an
//! occurrence inventory or index. Comparison starts at immutable node frontiers,
//! skips equal nodes and expands changed graft populations using local hops.
//! Results are ordinary data: they neither maintain I/P/G nor establish current
//! coverage, authority, same-commit publication or the complete DRV-29 bound.
//! Namespace boundary traces report physical divergence separately from logical
//! input and file-state changes; no auxiliary maintenance B is inferred.

mod accounting;
mod discovery;
mod frontier;
mod lookup;
mod prepared;

#[cfg(test)]
mod tests;

pub use lookup::{SourceLookup, SourceLookupWork};
pub use prepared::{PreparationWork, PreparedSource};

use super::carrier::SemanticContext;
use alloc::string::String;
use alloc::vec::Vec;

use crate::identity::Digest;
use crate::tree_format::{ContentRef, Entry, Property};

pub use super::evaluation::Error;

/// A root-local hop with its independently selected namespace root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Hop {
    /// Actual owner or graft target supplying this hop's key space.
    pub source: Digest,
    /// Local file or graft key, never a flattened view path.
    pub key: Vec<u8>,
}

/// An occurrence's ordered graft hops followed by its local terminal key.
pub type Address = Vec<Hop>;

/// One changed logical namespace entry after expanded graft descent.
///
/// Changed graft descriptors and expanded descendants count separately.
/// Addresses retain independent source roots on each side, while source digest changes alone
/// never create logical membership changes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InputChange<'a> {
    /// Previous occurrence address, absent for additions.
    pub old_address: Option<Address>,
    /// Replacement occurrence address, absent for removals.
    pub new_address: Option<Address>,
    /// Previous complete entry.
    pub old: Option<Entry<'a>>,
    /// Replacement complete entry.
    pub new: Option<Entry<'a>>,
}

/// One changed property binding at an independently selected local root.
///
/// Repeated graft occurrences retain separate binding transitions. A paired
/// named binding counts once regardless of how many fields change; the absent
/// versus present-empty map envelope contains zero named bindings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PropertyChange<'a> {
    /// Graft hops reaching the previous root, or empty for its owner.
    pub old_hops: Option<Address>,
    /// Graft hops reaching the replacement root, or empty for its owner.
    pub new_hops: Option<Address>,
    /// Previous root identity, absent for an added root occurrence.
    pub old_root: Option<Digest>,
    /// Replacement root identity, absent for a removed root occurrence.
    pub new_root: Option<Digest>,
    /// Previous binding.
    pub old: Option<Property<'a>>,
    /// Replacement binding.
    pub new: Option<Property<'a>>,
}

/// A changed physical property-map envelope, excluded from named-binding delta.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootEnvelopeChange {
    /// Previous independently expected namespace root.
    pub old_root: Digest,
    /// Replacement independently expected namespace root.
    pub new_root: Digest,
    /// Previous local graft-hop chain.
    pub old_hops: Address,
    /// Replacement local graft-hop chain.
    pub new_hops: Address,
    /// Whether the previous property-map field was present.
    pub old_present: bool,
    /// Whether the replacement property-map field is present.
    pub new_present: bool,
}

/// The immutable participating state of one regular-file occurrence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileState {
    /// Actual Chunk or Manifest reference, preserving its content tag.
    pub content: ContentRef,
    /// Complete canonical inline value; absence remains distinct from a value.
    pub value: Option<Vec<u8>>,
}

impl FileState {
    /// Returns the actual file content identity, never a route Node identity.
    pub fn object(&self) -> Digest {
        match self.content {
            ContentRef::Inline(object) | ContentRef::Manifest(object) => object,
        }
    }
}

/// One changed regular-file state or occurrence membership.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DataChange {
    /// Previous occurrence address.
    pub old_address: Option<Address>,
    /// Replacement occurrence address.
    pub new_address: Option<Address>,
    /// Previous participating state, absent when the occurrence was not a file.
    pub old: Option<FileState>,
    /// Replacement participating state.
    pub new: Option<FileState>,
}

/// Counts physical discovery events, independently of logical delta.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DiscoveryWork {
    /// Physical nodes opened for descent, including repeated graft occurrences.
    pub node_reads: usize,
    /// Leaf entries exposed by opened frontiers and repeated frontier key accesses.
    pub item_reads: usize,
    /// Direct bounded divergence-owner checks and updates.
    pub boundary_checks: usize,
    /// Individual root-property bindings read once by the merge.
    pub property_reads: usize,
    /// Child references exposed by opened internal frontiers.
    pub child_reads: usize,
    /// Actual key, entry and individual property-binding comparisons.
    pub comparisons: usize,
    /// Paired frontier identity/range checks, including equal skips.
    pub frontier_checks: usize,
    /// Immutable equal subtrees skipped without reading their entries.
    pub skipped_subtrees: usize,
}

impl DiscoveryWork {
    /// Accumulates actual independent event counts without hiding overflow.
    ///
    /// # Errors
    /// Rejects physical work counter overflow.
    pub(super) fn combine(&mut self, other: Self) -> Result<(), Error> {
        use frontier::add;
        add(&mut self.node_reads, other.node_reads)?;
        add(&mut self.item_reads, other.item_reads)?;
        add(&mut self.boundary_checks, other.boundary_checks)?;
        add(&mut self.property_reads, other.property_reads)?;
        add(&mut self.child_reads, other.child_reads)?;
        add(&mut self.comparisons, other.comparisons)?;
        add(&mut self.frontier_checks, other.frontier_checks)?;
        add(&mut self.skipped_subtrees, other.skipped_subtrees)?;
        Ok(())
    }
}

/// An actual discovery operation charged in item units.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhysicalEventKind {
    /// Opens or inspects a physical Node.
    NodeRead,
    /// Reads a physical leaf item, including repeated key accesses.
    ItemRead,
    /// Checks or updates one physical-level divergence owner.
    BoundaryCheck,
    /// Reads one root-property binding.
    PropertyRead,
    /// Reads an internal child reference.
    ChildRead,
    /// Compares a key, entry, value state or individual property binding.
    Comparison,
    /// Checks a paired immutable frontier.
    FrontierCheck,
    /// Skips an equal immutable subtree without exposing its entries.
    SkippedSubtree,
}

/// An exclusively attributed event at one actual physical level.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhysicalEvent {
    /// Actual Node level, zero for leaf entry/value comparisons.
    /// Root-property reads use their side's root level; binding comparisons
    /// use the lower participating root level before cut attribution opens.
    pub level: u8,
    /// Physical operation that occurred.
    pub kind: PhysicalEventKind,
    /// Actual number of items touched; repeated processing is charged again.
    pub amount: usize,
    /// Divergent boundary-region index, or ordinary frontier work when absent.
    pub boundary: Option<usize>,
}

/// One local namespace occurrence's independently measured discovery stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamWork {
    /// Previous independently expected source root, if present.
    pub old_root: Option<Digest>,
    /// Replacement independently expected source root, if present.
    pub new_root: Option<Digest>,
    /// Previous local graft-hop context.
    pub old_hops: Option<Address>,
    /// Replacement local graft-hop context.
    pub new_hops: Option<Address>,
    /// Exact exclusive event attribution; each event appears once.
    pub events: Vec<PhysicalEvent>,
    /// Scalar sum of the events in this local occurrence only.
    pub work: DiscoveryWork,
}

/// An actual physical frontier boundary in a local namespace stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Cut {
    /// Namespace source root whose physical node supplied the boundary.
    pub source: Digest,
    /// Physical node identity.
    pub node: Digest,
    /// Distance from leaves.
    pub level: u8,
    /// Last local key, absent for the empty root.
    pub last: Option<Vec<u8>>,
}

/// The observed end of a divergent physical comparison region.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Resynchronization {
    /// An equal immutable frontier with compatible old/new level and range.
    Equal(Cut),
    /// Canonical old/new node ranges align although their logical data differs.
    Aligned {
        /// Previous canonical cut at the recovered local range.
        old: Cut,
        /// Replacement canonical cut at the same recovered local range.
        new: Cut,
    },
    /// The compared local stream ended before a compatible equal frontier.
    Tail,
}

/// Records an actual old/new mismatched physical cut and its later frontier.
///
/// Work snapshots delimit the real traversal interval. Regions may overlap
/// across physical levels; their snapshot differences MUST NOT be summed as a
/// total B. Ordinary aligned-boundary descent and preparation are separate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundaryRegion {
    /// Local graft hops for the previous stream.
    pub old_hops: Address,
    /// Local graft hops for the replacement stream.
    pub new_hops: Address,
    /// Previous mismatched boundary.
    pub old: Cut,
    /// Replacement mismatched boundary.
    pub new: Cut,
    /// Local physical-stream work before the mismatched frontier was processed.
    pub start: DiscoveryWork,
    /// Local physical-stream work after resynchronization or stream-tail processing.
    pub end: DiscoveryWork,
    /// Actual compatible frontier or stream tail.
    pub resynchronization: Resynchronization,
}

/// Selects ordinary participation without interpreting current index policy.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum PopulationMode {
    /// Compares an existing selected attribute population on both sides.
    #[default]
    Existing,
    /// Introduces every new-side file occurrence into a newly enabled population.
    NewlyEnabled,
}

/// Reports explicit new-population enumeration separately from comparison.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct InitializationWork {
    /// Relevant-root lookups during explicit population enumeration.
    pub source_lookups: SourceLookupWork,
    /// Actual full new-population reads and checks, never boundary B.
    pub work: DiscoveryWork,
    /// Exclusive local-hop event attribution for population enumeration.
    pub streams: Vec<StreamWork>,
}

/// Binds calculated changes to their exact ordinary immutable source selection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoverySources {
    old: Digest,
    new: Digest,
    attribute: String,
    context: SemanticContext,
    minimum: u64,
    mode: PopulationMode,
}

impl DiscoverySources {
    /// Returns the exact previous prepared owner root.
    pub fn old_root(&self) -> Digest {
        self.old
    }

    /// Returns the exact replacement prepared owner root.
    pub fn new_root(&self) -> Digest {
        self.new
    }

    /// Borrows the registered selected inline attribute name.
    pub fn attribute(&self) -> &str {
        &self.attribute
    }

    /// Returns the explicitly checked carrier semantic context.
    pub fn context(&self) -> SemanticContext {
        self.context
    }

    /// Returns the selected supported chunk minimum.
    pub fn minimum(&self) -> u64 {
        self.minimum
    }

    /// Returns the ordinary population transition supplied by the caller.
    pub fn mode(&self) -> PopulationMode {
        self.mode
    }

    /// Returns the existing registered executable index profile.
    pub fn profile(&self) -> &'static str {
        super::INDEX_EVALUATION_PROFILE
    }
}

/// The changed immutable inputs and actual source-discovery work.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Discovery<'graph, 'a> {
    /// Changed entries after expanded changed, added and removed graft descent.
    inputs: Vec<InputChange<'a>>,
    /// Changed individual root-property bindings.
    properties: Vec<PropertyChange<'a>>,
    /// Changed root property-map field presence, never a named binding delta.
    envelopes: Vec<RootEnvelopeChange>,
    /// Changed participating occurrence states.
    data: Vec<DataChange>,
    /// Actual discovery events; excludes separately measured preparation.
    work: DiscoveryWork,
    /// Physical cut divergence, independently of logical delta.
    boundaries: Vec<BoundaryRegion>,
    /// Exclusive per-occurrence/per-level attribution conserving scalar work.
    streams: Vec<StreamWork>,
    /// Explicit new-population work, absent from ordinary discovery counters.
    initialization: InitializationWork,
    logical_inputs: usize,
    sources: DiscoverySources,
    old_lookup: SourceLookup<'graph, 'a>,
    new_lookup: SourceLookup<'graph, 'a>,
    source_lookups: SourceLookupWork,
}

impl<'graph, 'value> Discovery<'graph, 'value> {
    /// Borrows the exact previous selected immutable source snapshot.
    pub fn old_lookup(&self) -> &SourceLookup<'graph, 'value> {
        &self.old_lookup
    }

    /// Borrows the exact replacement selected immutable source snapshot.
    pub fn new_lookup(&self) -> &SourceLookup<'graph, 'value> {
        &self.new_lookup
    }

    /// Returns actual relevant-root lookup work, excluding preparation and initialization.
    pub fn source_lookup_work(&self) -> SourceLookupWork {
        self.source_lookups
    }

    /// Borrows the exact prepared-source selection bound to this calculation.
    pub fn sources(&self) -> &DiscoverySources {
        &self.sources
    }

    /// Borrows expanded logical entry transitions.
    pub fn inputs(&self) -> &[InputChange<'_>] {
        &self.inputs
    }

    /// Borrows occurrence-relative named property transitions.
    pub fn properties(&self) -> &[PropertyChange<'_>] {
        &self.properties
    }

    /// Borrows physical root-map envelope changes excluded from binding delta.
    pub fn envelopes(&self) -> &[RootEnvelopeChange] {
        &self.envelopes
    }

    /// Borrows exact participating file-state transitions.
    pub fn data(&self) -> &[DataChange] {
        &self.data
    }

    /// Returns actual comparison work, excluding preparation and initialization.
    pub fn work(&self) -> DiscoveryWork {
        self.work
    }

    /// Borrows actual physical cut-divergence diagnostics.
    pub fn boundaries(&self) -> &[BoundaryRegion] {
        &self.boundaries
    }

    /// Borrows exclusively attributed local physical-stream events.
    pub fn streams(&self) -> &[StreamWork] {
        &self.streams
    }

    /// Borrows separately measured explicit population-initialization work.
    pub fn initialization(&self) -> &InitializationWork {
        &self.initialization
    }

    /// Returns changed logical entries plus changed individual property bindings.
    pub fn delta_input(&self) -> usize {
        self.logical_inputs
    }

    /// Returns changed regular-file occurrence states, including membership.
    pub fn delta_data(&self) -> usize {
        self.data.len()
    }
}

/// Compares two independently prepared immutable sources for one attribute.
///
/// Equal identities skip entries, changed graft pairs recurse and added/removed
/// grafts expand fully. Root digest or physical repartitioning alone does not
/// create a file-state change. Preparation costs stay on each input token.
///
/// # Errors
/// Rejects different selected attributes, semantic contexts or chunk geometry,
/// unavailable source roots, traversal limits or invalid source values. No result establishes maintained I/P/G,
/// current policy, producer verification or complete incremental-maintenance B.
pub fn discover<'graph, 'a>(
    old: &PreparedSource<'graph, 'a>,
    new: &PreparedSource<'graph, 'a>,
) -> Result<Discovery<'graph, 'a>, Error> {
    discover_with_mode(old, new, PopulationMode::Existing)
}

/// Compares immutable inputs with an explicit ordinary population transition.
///
/// Newly enabled populations compare actual namespace inputs first, then expand
/// every new regular-file occurrence into an added participating state. That
/// enumeration is initialization, separately measured; it is not incremental
/// maintenance or boundary work. The caller's mode grants no policy authority.
///
/// # Errors
/// Rejects mismatched attributes, contexts or geometry, invalid sources and
/// traversal/work limits.
pub fn discover_with_mode<'graph, 'a>(
    old: &PreparedSource<'graph, 'a>,
    new: &PreparedSource<'graph, 'a>,
    mode: PopulationMode,
) -> Result<Discovery<'graph, 'a>, Error> {
    discovery::compare(old, new, mode)
}

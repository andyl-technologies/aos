//! Shares observed container counts and extents without observation authority.
//!
//! Only the original upper observer gathers these inert numeric facts. The
//! shared serializer consumes them without retaining or authenticating owners.

/// Reports observed backing capacities and independently charged metadata terms.
///
/// Shared owners are conservatively counted per view. Tree facts describe actual
/// containers and initialized entries, not their hidden node allocation sizes.
/// An empty tree may retain a root; callers reserve its node allowance as well.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RetainedProtocolMetadataFacts {
    /// Sums actual capacities of String and Id backing buffers.
    pub string_capacity_bytes: usize,
    /// Counts inspected String and Id backing buffers, including empty ones.
    pub string_banks: usize,
    /// Sums actual Vec capacities times their actual element layout.
    pub vector_capacity_bytes: usize,
    /// Counts inspected Vec and Bytes buffers, including empty ones.
    pub vector_banks: usize,
    /// Sums inline values retained in independently owned Boxes.
    pub boxed_value_bytes: usize,
    /// Sums inline values or slice elements behind retained Rc and Arc owners.
    pub shared_value_bytes: usize,
    /// Counts shared backing views whose control blocks need separate admission.
    pub shared_backing_views: usize,
    /// Counts tree containers, including possibly allocated empty roots.
    pub tree_containers: usize,
    /// Sums initialized tree entries across all observed containers.
    pub tree_entries: usize,
    /// Bounds one tree entry's actual key and value layout across this view.
    pub maximum_tree_key_value_bytes: usize,
    /// Reports the largest actual key/value alignment, including zero-sized keys.
    pub maximum_tree_entry_alignment: usize,
    /// Reports the largest actual shared payload or slice-element alignment.
    pub maximum_shared_value_alignment: usize,
    /// Counts visited fields and initialized rows for bounded traversal work.
    pub observed_nodes: usize,
    /// Counts exact capacity/container records required by this typed traversal.
    pub capacity_records: usize,
}

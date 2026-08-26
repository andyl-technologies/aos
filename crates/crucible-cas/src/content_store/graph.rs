//! Closed, bounded, introspectable store-graph admission and construction.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::sync::Arc;

use super::composition::{
    MetricsState, MetricsStore, ReadThroughStore, RoutedStore, TieredStore, VerifiedStore,
    WriteThroughStore,
};
use super::compressed_directory::CompressedDirectoryBlobBackend;
use super::directory::DirectoryBlobBackend;
use super::memory::MemoryBlobBackend;
use super::packed::PackedBlobBackend;
use super::quota::{LogicalQuotaStore, MAXIMUM_LOGICAL_QUOTA_OBJECTS};
use super::write_back::{
    StoreGraphWriteBackFence, WriteBackRetentionAdmin, WriteBackRetentionFence, WriteBackStore,
};
use super::*;

mod format;

use format::canonical_graph_configuration;

const MAX_GRAPH_NODES: usize = 256;
const MAX_GRAPH_DEPTH: usize = 64;
const MAX_NODE_ID_BYTES: usize = 64;
const MAX_ADMINISTRATIVE_PATH_BYTES: usize = 4_096;
const GRAPH_CONFIGURATION_ID_DOMAIN: &[u8] = b"crucible.content-store.graph-configuration-id.v1";

/// Content-derived identity of one exact admitted store-graph configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StoreGraphConfigurationId([u8; 32]);

impl StoreGraphConfigurationId {
    /// Returns the exact 32-byte configuration identity.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }

    fn for_config(config: &StoreGraphConfig) -> Result<Self, StoreError> {
        let canonical = canonical_graph_configuration(config)?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(&(GRAPH_CONFIGURATION_ID_DOMAIN.len() as u64).to_be_bytes());
        hasher.update(GRAPH_CONFIGURATION_ID_DOMAIN);
        hasher.update(&(canonical.len() as u64).to_be_bytes());
        hasher.update(&canonical);
        Ok(Self(*hasher.finalize().as_bytes()))
    }
}

/// Validated operational identifier of one configured store node.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StoreNodeId(String);

impl StoreNodeId {
    /// Validates a bounded ASCII node identifier.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidGraph`] when the identifier is empty, too
    /// long, or contains characters outside letters, digits, `.`, `_`, and `-`.
    pub fn new(value: impl Into<String>) -> Result<Self, StoreError> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.len() <= MAX_NODE_ID_BYTES
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
        if !valid {
            return Err(invalid_graph(&value, GraphViolation::InvalidNodeId));
        }
        Ok(Self(value))
    }

    /// Returns the validated spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Closed set of immutable-store leaves and composition layers.
#[derive(Clone, Debug)]
pub enum StoreNodeSpec {
    /// Bounded process-local memory leaf.
    Memory {
        /// Hard cap on retained authenticated logical bytes.
        max_logical_bytes: u64,
    },
    /// Crash-safe loose-object directory leaf.
    Directory {
        /// Trusted operator-owned filesystem root.
        root: PathBuf,
    },
    /// Crash-safe compressed loose-object directory leaf.
    CompressedDirectory {
        /// Trusted operator-owned filesystem root.
        root: PathBuf,
        /// Hard cap on one object's authenticated plaintext bytes.
        maximum_logical_object_bytes: u64,
    },
    /// Immutable physical packs with one crash-safe logical index.
    Packed {
        /// Trusted operator-owned pack and index root.
        root: PathBuf,
        /// Target physical bytes per deterministic replacement pack.
        target_pack_bytes: u64,
    },
    /// Logical verification facade.
    Verified {
        /// Child node.
        child: StoreNodeId,
    },
    /// Routes authenticated logical object kinds.
    Routed {
        /// Exact kind-to-child map.
        routes: BTreeMap<ObjectKind, StoreNodeId>,
    },
    /// Ordered read tiers with one write tier.
    Tiered {
        /// Children in read order.
        tiers: Vec<StoreNodeId>,
        /// Index of the child receiving ordinary writes.
        write_tier: usize,
        /// Whether verified lower-tier reads promote into preceding tiers.
        promote_reads: bool,
    },
    /// Reads through a cache and writes only to the authoritative source.
    ReadThrough {
        /// Faster optional cache receiving verified source reads.
        cache: StoreNodeId,
        /// Authoritative child receiving logical writes.
        source: StoreNodeId,
    },
    /// Requires every child placement before a write succeeds.
    WriteThrough {
        /// Mirrored children.
        children: Vec<StoreNodeId>,
    },
    /// Durably stages writes and journals deferred transfer to one destination.
    WriteBack {
        /// Durable child receiving acknowledged writes immediately.
        staging: StoreNodeId,
        /// Durable child receiving journaled transfers.
        destination: StoreNodeId,
        /// Trusted operator-owned journal directory.
        journal_root: PathBuf,
        /// Hard count bound for pending transfer roots.
        maximum_pending_objects: u64,
        /// Hard aggregate logical-byte bound for pending transfer roots.
        maximum_pending_bytes: u64,
    },
    /// Enforces a restart-safe aggregate logical quota around one owned leaf.
    LogicalQuota {
        /// Exclusively owned physical child leaf.
        child: StoreNodeId,
        /// Trusted operator-owned quota state directory.
        state_root: PathBuf,
        /// Hard aggregate logical-object count.
        maximum_objects: u64,
        /// Hard aggregate authenticated logical bytes.
        maximum_logical_bytes: u64,
    },
    /// Emits bounded operational counters around one child.
    Metrics {
        /// Child node whose synchronous operations are observed.
        child: StoreNodeId,
    },
}

impl StoreNodeSpec {
    fn child_ids(&self) -> Vec<&StoreNodeId> {
        match self {
            Self::Memory { .. }
            | Self::Directory { .. }
            | Self::CompressedDirectory { .. }
            | Self::Packed { .. } => Vec::new(),
            Self::Verified { child } => vec![child],
            Self::Routed { routes } => routes.values().collect(),
            Self::Tiered { tiers, .. } => tiers.iter().collect(),
            Self::ReadThrough { cache, source } => vec![cache, source],
            Self::WriteThrough { children } => children.iter().collect(),
            Self::WriteBack {
                staging,
                destination,
                ..
            } => vec![staging, destination],
            Self::LogicalQuota { child, .. } => vec![child],
            Self::Metrics { child } => vec![child],
        }
    }

    fn kind(&self) -> StoreNodeKind {
        match self {
            Self::Memory { .. } => StoreNodeKind::Memory,
            Self::Directory { .. } => StoreNodeKind::Directory,
            Self::CompressedDirectory { .. } => StoreNodeKind::CompressedDirectory,
            Self::Packed { .. } => StoreNodeKind::Packed,
            Self::Verified { .. } => StoreNodeKind::Verified,
            Self::Routed { .. } => StoreNodeKind::Routed,
            Self::Tiered { .. } => StoreNodeKind::Tiered,
            Self::ReadThrough { .. } => StoreNodeKind::ReadThrough,
            Self::WriteThrough { .. } => StoreNodeKind::WriteThrough,
            Self::WriteBack { .. } => StoreNodeKind::WriteBack,
            Self::LogicalQuota { .. } => StoreNodeKind::LogicalQuota,
            Self::Metrics { .. } => StoreNodeKind::Metrics,
        }
    }
}

/// Declarative closed store graph.
#[derive(Clone, Debug)]
pub struct StoreGraphConfig {
    /// Root node serving the logical immutable-store contract.
    pub root: StoreNodeId,
    /// Exact logical kinds admitted through the root.
    pub admitted_kinds: BTreeSet<ObjectKind>,
    /// Node definitions keyed by their validated operational IDs.
    pub nodes: BTreeMap<StoreNodeId, StoreNodeSpec>,
}

/// Stable layer kind returned by graph introspection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreNodeKind {
    /// Bounded memory leaf.
    Memory,
    /// Durable directory leaf.
    Directory,
    /// Durable compressed directory leaf.
    CompressedDirectory,
    /// Durable immutable-pack leaf.
    Packed,
    /// Verification facade.
    Verified,
    /// Kind router.
    Routed,
    /// Ordered tiers.
    Tiered,
    /// Two-child read-through cache.
    ReadThrough,
    /// Write-through mirror.
    WriteThrough,
    /// Durable deferred write-back transfer.
    WriteBack,
    /// Restart-safe aggregate logical quota.
    LogicalQuota,
    /// Operational metrics facade.
    Metrics,
}

/// Non-sensitive operational description of one admitted graph node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreNodeDescription {
    /// Validated operational node ID.
    pub id: StoreNodeId,
    /// Closed layer kind.
    pub kind: StoreNodeKind,
    /// Capabilities available through this node.
    pub capabilities: BackendCapabilities,
}

/// Saturating operational counters for one metrics node.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StoreNodeMetrics {
    /// `contains` operations attempted.
    pub contains_calls: u64,
    /// `contains` operations that found the requested object.
    pub contains_hits: u64,
    /// Host monotonic time spent in child `contains` operations.
    pub contains_elapsed_nanoseconds: u64,
    /// Logical read handles requested.
    pub read_calls: u64,
    /// Declared logical bytes made available by successful read calls.
    pub read_logical_bytes: u64,
    /// Host monotonic time spent acquiring child read handles.
    pub read_elapsed_nanoseconds: u64,
    /// Attempts to open streams from returned read handles.
    pub read_stream_opens: u64,
    /// Host monotonic time spent opening returned read streams.
    pub read_stream_open_elapsed_nanoseconds: u64,
    /// Streams drained through authenticated end-of-file.
    pub read_stream_completions: u64,
    /// Streams dropped before their authenticated end-of-file.
    pub read_stream_abandons: u64,
    /// Stream-open, read, length, or deferred-authentication failures.
    pub read_stream_failures: u64,
    /// Logical bytes actually delivered through opened read streams.
    pub read_stream_bytes: u64,
    /// Host monotonic time spent in underlying stream-read calls.
    pub read_stream_read_elapsed_nanoseconds: u64,
    /// Logical immutable puts attempted.
    pub put_calls: u64,
    /// Declared logical bytes accepted by successful put calls.
    pub put_logical_bytes: u64,
    /// Host monotonic time spent in child immutable puts.
    pub put_elapsed_nanoseconds: u64,
    /// Synchronous child operations that returned an error.
    pub failures: u64,
}

/// Metrics snapshot associated with one admitted graph node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreNodeMetricsDescription {
    /// Metrics node ID.
    pub id: StoreNodeId,
    /// Current saturating operational counters.
    pub metrics: StoreNodeMetrics,
}

/// Terminal result of one bounded write-back flush pass.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StoreWriteBackFlushSummary {
    completed: u32,
    pending: u64,
}

impl StoreWriteBackFlushSummary {
    /// Returns the number of transfers completed by this pass.
    #[must_use]
    pub const fn completed(self) -> u32 {
        self.completed
    }

    /// Returns the pending roots observed after the pass.
    #[must_use]
    pub const fn pending(self) -> u64 {
        self.pending
    }
}

/// Separate physical-placement administration returned during graph construction.
///
/// This capability is not retained by [`StoreGraph`]. A campaign repository
/// that receives only the ordinary graph therefore cannot inventory or delete
/// physical placements. The daemon maintenance owner may retain this value and
/// lend individual administrative boundaries to a generation-bound GC
/// operation. A logical-quota boundary owns and replaces its child leaf's
/// otherwise direct capability.
pub struct StoreGraphAdmin {
    configuration: StoreGraphConfigurationId,
    physical: BTreeMap<StoreNodeId, Arc<dyn BlobStoreAdmin>>,
}

impl StoreGraphAdmin {
    /// Returns the exact configuration identity shared with the admitted graph.
    #[must_use]
    pub const fn configuration_id(&self) -> StoreGraphConfigurationId {
        self.configuration
    }

    /// Returns physical administration boundaries in canonical node-ID order.
    #[must_use]
    pub fn physical(&self) -> Vec<StoreGraphPhysicalAdmin<'_>> {
        self.physical
            .iter()
            .map(|(node, admin)| StoreGraphPhysicalAdmin {
                node,
                admin: admin.as_ref(),
            })
            .collect()
    }
}

/// Borrowed administration capability for one exact admitted physical boundary.
#[derive(Clone, Copy)]
pub struct StoreGraphPhysicalAdmin<'a> {
    node: &'a StoreNodeId,
    admin: &'a dyn BlobStoreAdmin,
}

impl<'a> StoreGraphPhysicalAdmin<'a> {
    /// Returns the administrative boundary's exact graph node ID.
    #[must_use]
    pub const fn node(self) -> &'a StoreNodeId {
        self.node
    }

    /// Returns the separately held physical inventory/delete authority.
    #[must_use]
    pub const fn admin(self) -> &'a dyn BlobStoreAdmin {
        self.admin
    }
}

/// Admitted immutable-store graph with one root service.
pub struct StoreGraph {
    configuration: StoreGraphConfigurationId,
    root_id: StoreNodeId,
    admitted_kinds: BTreeSet<ObjectKind>,
    root: Arc<dyn ImmutableBlobBackend>,
    description: Vec<StoreNodeDescription>,
    metrics: BTreeMap<StoreNodeId, Arc<MetricsState>>,
    write_back: BTreeMap<StoreNodeId, Arc<WriteBackStore>>,
}

impl StoreGraph {
    /// Validates and constructs a closed graph.
    ///
    /// Admission rejects missing nodes, cycles, unreachable nodes, excessive
    /// size/depth, incomplete kind routing, invalid tiers, and unmet child
    /// capabilities before any campaign object is accessed.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidGraph`] or [`StoreError::InvalidComposition`]
    /// when the declarative graph cannot safely implement the logical store.
    pub fn build(config: StoreGraphConfig) -> Result<Self, StoreError> {
        let (graph, _admin) = Self::build_with_admin(config)?;
        Ok(graph)
    }

    /// Validates a graph and separately returns physical maintenance authority.
    ///
    /// The graph value carries only ordinary immutable-object operations. The
    /// second return value owns every physical inventory/delete boundary in
    /// canonical node-ID order and should be retained only by the daemon
    /// maintenance owner. A logical quota replaces its exclusively owned
    /// child's direct boundary.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidGraph`] or [`StoreError::InvalidComposition`]
    /// when the declarative graph cannot safely implement the logical store.
    pub fn build_with_admin(
        config: StoreGraphConfig,
    ) -> Result<(Self, StoreGraphAdmin), StoreError> {
        validate_structure(&config)?;
        validate_demands(&config)?;
        let configuration = StoreGraphConfigurationId::for_config(&config)?;

        let mut built = BTreeMap::new();
        let mut physical = BTreeMap::new();
        let mut metrics = BTreeMap::new();
        let mut write_back = BTreeMap::new();
        let root = instantiate(
            configuration,
            &config.root,
            &config.nodes,
            &mut built,
            &mut physical,
            &mut metrics,
            &mut write_back,
        )?;
        validate_capability_edges(&config.nodes, &built)?;
        let mut description = Vec::with_capacity(config.nodes.len());
        for (id, spec) in &config.nodes {
            let backend = built
                .get(id)
                .ok_or_else(|| invalid_graph(id.as_str(), GraphViolation::MissingNode))?;
            description.push(StoreNodeDescription {
                id: id.clone(),
                kind: spec.kind(),
                capabilities: backend.capabilities(),
            });
        }
        Ok((
            Self {
                configuration,
                root_id: config.root,
                admitted_kinds: config.admitted_kinds,
                root,
                description,
                metrics,
                write_back,
            },
            StoreGraphAdmin {
                configuration,
                physical,
            },
        ))
    }

    /// Returns the exact canonical configuration identity admitted at build.
    #[must_use]
    pub const fn configuration_id(&self) -> StoreGraphConfigurationId {
        self.configuration
    }

    /// Returns the admitted root node ID.
    #[must_use]
    pub fn root_id(&self) -> &StoreNodeId {
        &self.root_id
    }

    /// Returns the exact object kinds admitted through the root.
    #[must_use]
    pub fn admitted_kinds(&self) -> &BTreeSet<ObjectKind> {
        &self.admitted_kinds
    }

    /// Returns a deterministic, path-free graph description.
    #[must_use]
    pub fn describe(&self) -> &[StoreNodeDescription] {
        &self.description
    }

    /// Returns a deterministic snapshot of every admitted metrics node.
    ///
    /// Counters distinguish synchronous store-method outcomes from consumption
    /// of returned streams, including authenticated completion, partial-reader
    /// abandonment, and deferred failures.
    #[must_use]
    pub fn metrics(&self) -> Vec<StoreNodeMetricsDescription> {
        self.metrics
            .iter()
            .map(|(id, state)| {
                let snapshot = state.snapshot();
                StoreNodeMetricsDescription {
                    id: id.clone(),
                    metrics: StoreNodeMetrics {
                        contains_calls: snapshot.contains_calls,
                        contains_hits: snapshot.contains_hits,
                        contains_elapsed_nanoseconds: snapshot.contains_elapsed_nanoseconds,
                        read_calls: snapshot.read_calls,
                        read_logical_bytes: snapshot.read_logical_bytes,
                        read_elapsed_nanoseconds: snapshot.read_elapsed_nanoseconds,
                        read_stream_opens: snapshot.read_stream_opens,
                        read_stream_open_elapsed_nanoseconds: snapshot
                            .read_stream_open_elapsed_nanoseconds,
                        read_stream_completions: snapshot.read_stream_completions,
                        read_stream_abandons: snapshot.read_stream_abandons,
                        read_stream_failures: snapshot.read_stream_failures,
                        read_stream_bytes: snapshot.read_stream_bytes,
                        read_stream_read_elapsed_nanoseconds: snapshot
                            .read_stream_read_elapsed_nanoseconds,
                        put_calls: snapshot.put_calls,
                        put_logical_bytes: snapshot.put_logical_bytes,
                        put_elapsed_nanoseconds: snapshot.put_elapsed_nanoseconds,
                        failures: snapshot.failures,
                    },
                }
            })
            .collect()
    }

    /// Flushes at most `maximum_transfers` pending write-back objects.
    ///
    /// Nodes and their pending IDs are visited in canonical order. A transfer
    /// is complete only after the destination returns a durable placement and
    /// the journal durably removes its retention root.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidComposition`] for a zero limit or a child,
    /// journal, authentication, or durability error during transfer.
    pub fn flush_write_back(
        &self,
        maximum_transfers: u32,
    ) -> Result<StoreWriteBackFlushSummary, StoreError> {
        if maximum_transfers == 0 {
            return Err(StoreError::InvalidComposition {
                reason: "write-back flush limit is zero",
            });
        }
        let mut completed = 0_u32;
        'nodes: for store in self.write_back.values() {
            while completed < maximum_transfers {
                if !store.flush_one()? {
                    continue 'nodes;
                }
                completed += 1;
            }
            break;
        }

        let mut fence = self.acquire_write_back_retention_fence()?;
        let summary = fence.visit_roots(&mut |_root| Ok(()))?;
        Ok(StoreWriteBackFlushSummary {
            completed,
            pending: summary.roots(),
        })
    }
}

impl WriteBackRetentionAdmin for StoreGraph {
    fn acquire_write_back_retention_fence(
        &self,
    ) -> Result<Box<dyn WriteBackRetentionFence + '_>, StoreError> {
        let journals = self
            .write_back
            .iter()
            .map(|(id, store)| (id.as_str().to_owned(), store.journal()))
            .collect();
        Ok(Box::new(StoreGraphWriteBackFence::acquire(&journals)?))
    }
}

impl ImmutableBlobBackend for StoreGraph {
    fn name(&self) -> &str {
        self.root_id.as_str()
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.root.capabilities()
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        self.require_admitted(id)?;
        self.root.contains(id)
    }

    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        self.require_admitted(id)?;
        self.root.read(id, range)
    }

    fn put_if_absent(&self, id: ContentId, source: &BlobHandle) -> Result<PutReceipt, StoreError> {
        self.require_admitted(id)?;
        self.root.put_if_absent(id, source)
    }
}

impl StoreGraph {
    fn require_admitted(&self, id: ContentId) -> Result<(), StoreError> {
        if self.admitted_kinds.contains(&id.kind()) {
            Ok(())
        } else {
            Err(invalid_graph(
                self.root_id.as_str(),
                GraphViolation::RouteCoverage,
            ))
        }
    }
}

fn validate_structure(config: &StoreGraphConfig) -> Result<(), StoreError> {
    if config.nodes.is_empty() {
        return Err(invalid_graph("<graph>", GraphViolation::Empty));
    }
    if config.nodes.len() > MAX_GRAPH_NODES {
        return Err(invalid_graph("<graph>", GraphViolation::TooManyNodes));
    }
    if config.admitted_kinds.is_empty() {
        return Err(invalid_graph("<graph>", GraphViolation::NoAdmittedKinds));
    }
    if !config.nodes.contains_key(&config.root) {
        return Err(invalid_graph(
            config.root.as_str(),
            GraphViolation::MissingNode,
        ));
    }
    validate_administrative_paths(config)?;
    validate_logical_quota_ownership(config)?;

    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    visit(&config.root, &config.nodes, 0, &mut visiting, &mut visited)?;
    if visited.len() != config.nodes.len() {
        let unreachable = config
            .nodes
            .keys()
            .find(|id| !visited.contains(*id))
            .map_or("<graph>", StoreNodeId::as_str);
        return Err(invalid_graph(unreachable, GraphViolation::UnreachableNode));
    }
    Ok(())
}

fn validate_administrative_paths(config: &StoreGraphConfig) -> Result<(), StoreError> {
    let persistent = config
        .nodes
        .iter()
        .filter_map(|(id, node)| match node {
            StoreNodeSpec::Directory { root } => Some((id, root, false)),
            StoreNodeSpec::CompressedDirectory { root, .. } => Some((id, root, true)),
            StoreNodeSpec::Packed { root, .. } => Some((id, root, true)),
            StoreNodeSpec::WriteBack { journal_root, .. } => Some((id, journal_root, true)),
            StoreNodeSpec::LogicalQuota { state_root, .. } => Some((id, state_root, true)),
            _ => None,
        })
        .collect::<Vec<_>>();
    for left in 0..persistent.len() {
        let (node, path, _) = persistent[left];
        if path.as_os_str().as_bytes().len() > MAX_ADMINISTRATIVE_PATH_BYTES {
            return Err(invalid_graph(
                node.as_str(),
                GraphViolation::AdministrativePathTooLong,
            ));
        }
        if !path.is_absolute() {
            return Err(invalid_graph(
                node.as_str(),
                GraphViolation::RelativeAdministrativePath,
            ));
        }
        for right in left + 1..persistent.len() {
            let (left_id, left_path, left_journal) = persistent[left];
            let (right_id, right_path, right_journal) = persistent[right];
            if (left_journal || right_journal)
                && (left_path.starts_with(right_path) || right_path.starts_with(left_path))
            {
                let node = if left_journal { left_id } else { right_id };
                return Err(invalid_graph(
                    node.as_str(),
                    GraphViolation::OverlappingAdministrativePath,
                ));
            }
        }
    }
    Ok(())
}

fn validate_logical_quota_ownership(config: &StoreGraphConfig) -> Result<(), StoreError> {
    let mut inbound = BTreeMap::<StoreNodeId, u32>::new();
    for node in config.nodes.values() {
        for child in node.child_ids() {
            let count = inbound.entry(child.clone()).or_default();
            *count = count.checked_add(1).ok_or_else(|| {
                invalid_graph("<graph>", GraphViolation::InvalidLogicalQuotaChild)
            })?;
        }
    }
    for (id, node) in &config.nodes {
        let StoreNodeSpec::LogicalQuota { child, .. } = node else {
            continue;
        };
        let owned_leaf = matches!(
            config.nodes.get(child),
            Some(
                StoreNodeSpec::Directory { .. }
                    | StoreNodeSpec::CompressedDirectory { .. }
                    | StoreNodeSpec::Packed { .. }
            )
        );
        if !owned_leaf || inbound.get(child).copied() != Some(1) {
            return Err(invalid_graph(
                id.as_str(),
                GraphViolation::InvalidLogicalQuotaChild,
            ));
        }
    }
    Ok(())
}

fn visit(
    id: &StoreNodeId,
    nodes: &BTreeMap<StoreNodeId, StoreNodeSpec>,
    depth: usize,
    visiting: &mut BTreeSet<StoreNodeId>,
    visited: &mut BTreeSet<StoreNodeId>,
) -> Result<(), StoreError> {
    if depth > MAX_GRAPH_DEPTH {
        return Err(invalid_graph(id.as_str(), GraphViolation::TooDeep));
    }
    if visited.contains(id) {
        return Ok(());
    }
    if !visiting.insert(id.clone()) {
        return Err(invalid_graph(id.as_str(), GraphViolation::Cycle));
    }
    let node = nodes
        .get(id)
        .ok_or_else(|| invalid_graph(id.as_str(), GraphViolation::MissingNode))?;
    validate_local_shape(id, node)?;
    for child in node.child_ids() {
        visit(child, nodes, depth + 1, visiting, visited)?;
    }
    visiting.remove(id);
    visited.insert(id.clone());
    Ok(())
}

fn validate_local_shape(id: &StoreNodeId, node: &StoreNodeSpec) -> Result<(), StoreError> {
    match node {
        StoreNodeSpec::Routed { routes } if routes.is_empty() => {
            Err(invalid_graph(id.as_str(), GraphViolation::EmptyChildren))
        }
        StoreNodeSpec::Tiered { tiers, .. } if tiers.is_empty() => {
            Err(invalid_graph(id.as_str(), GraphViolation::EmptyChildren))
        }
        StoreNodeSpec::Tiered {
            tiers, write_tier, ..
        } if *write_tier >= tiers.len() => {
            Err(invalid_graph(id.as_str(), GraphViolation::InvalidWriteTier))
        }
        StoreNodeSpec::WriteThrough { children } if children.is_empty() => {
            Err(invalid_graph(id.as_str(), GraphViolation::EmptyChildren))
        }
        StoreNodeSpec::WriteBack {
            maximum_pending_objects,
            maximum_pending_bytes,
            ..
        } if *maximum_pending_objects == 0 || *maximum_pending_bytes == 0 => Err(invalid_graph(
            id.as_str(),
            GraphViolation::InvalidWriteBackBounds,
        )),
        StoreNodeSpec::CompressedDirectory {
            maximum_logical_object_bytes,
            ..
        } if *maximum_logical_object_bytes == 0 => Err(invalid_graph(
            id.as_str(),
            GraphViolation::InvalidCompressedObjectLimit,
        )),
        StoreNodeSpec::LogicalQuota {
            maximum_objects,
            maximum_logical_bytes,
            ..
        } if *maximum_objects == 0
            || *maximum_objects > MAXIMUM_LOGICAL_QUOTA_OBJECTS
            || *maximum_logical_bytes == 0 =>
        {
            Err(invalid_graph(
                id.as_str(),
                GraphViolation::InvalidLogicalQuotaBounds,
            ))
        }
        _ => Ok(()),
    }
}

fn validate_demands(config: &StoreGraphConfig) -> Result<(), StoreError> {
    let mut demands = BTreeMap::<StoreNodeId, BTreeSet<ObjectKind>>::new();
    demands.insert(config.root.clone(), config.admitted_kinds.clone());
    let mut queue = VecDeque::from([config.root.clone()]);
    while let Some(id) = queue.pop_front() {
        let kinds = demands
            .get(&id)
            .cloned()
            .ok_or_else(|| invalid_graph(id.as_str(), GraphViolation::MissingNode))?;
        let node = config
            .nodes
            .get(&id)
            .ok_or_else(|| invalid_graph(id.as_str(), GraphViolation::MissingNode))?;
        match node {
            StoreNodeSpec::Memory { .. }
            | StoreNodeSpec::Directory { .. }
            | StoreNodeSpec::CompressedDirectory { .. }
            | StoreNodeSpec::Packed { .. } => {}
            StoreNodeSpec::Verified { child } => {
                extend_demand(child, &kinds, &mut demands, &mut queue);
            }
            StoreNodeSpec::Routed { routes } => {
                for kind in &kinds {
                    let child = routes
                        .get(kind)
                        .ok_or_else(|| invalid_graph(id.as_str(), GraphViolation::RouteCoverage))?;
                    extend_demand(child, &BTreeSet::from([*kind]), &mut demands, &mut queue);
                }
            }
            StoreNodeSpec::Tiered { tiers, .. } => {
                for child in tiers {
                    extend_demand(child, &kinds, &mut demands, &mut queue);
                }
            }
            StoreNodeSpec::ReadThrough { cache, source } => {
                extend_demand(cache, &kinds, &mut demands, &mut queue);
                extend_demand(source, &kinds, &mut demands, &mut queue);
            }
            StoreNodeSpec::WriteThrough { children } => {
                for child in children {
                    extend_demand(child, &kinds, &mut demands, &mut queue);
                }
            }
            StoreNodeSpec::WriteBack {
                staging,
                destination,
                ..
            } => {
                extend_demand(staging, &kinds, &mut demands, &mut queue);
                extend_demand(destination, &kinds, &mut demands, &mut queue);
            }
            StoreNodeSpec::LogicalQuota { child, .. } => {
                extend_demand(child, &kinds, &mut demands, &mut queue);
            }
            StoreNodeSpec::Metrics { child } => {
                extend_demand(child, &kinds, &mut demands, &mut queue);
            }
        }
    }
    for (id, node) in &config.nodes {
        if let StoreNodeSpec::Routed { routes } = node {
            let required = demands.get(id).cloned().unwrap_or_default();
            if routes.keys().copied().collect::<BTreeSet<_>>() != required {
                return Err(invalid_graph(id.as_str(), GraphViolation::RouteCoverage));
            }
        }
    }
    Ok(())
}

fn extend_demand(
    child: &StoreNodeId,
    kinds: &BTreeSet<ObjectKind>,
    demands: &mut BTreeMap<StoreNodeId, BTreeSet<ObjectKind>>,
    queue: &mut VecDeque<StoreNodeId>,
) {
    let demand = demands.entry(child.clone()).or_default();
    let prior = demand.len();
    demand.extend(kinds);
    if demand.len() != prior {
        queue.push_back(child.clone());
    }
}

fn instantiate(
    configuration: StoreGraphConfigurationId,
    id: &StoreNodeId,
    nodes: &BTreeMap<StoreNodeId, StoreNodeSpec>,
    built: &mut BTreeMap<StoreNodeId, Arc<dyn ImmutableBlobBackend>>,
    physical: &mut BTreeMap<StoreNodeId, Arc<dyn BlobStoreAdmin>>,
    metrics: &mut BTreeMap<StoreNodeId, Arc<MetricsState>>,
    write_back: &mut BTreeMap<StoreNodeId, Arc<WriteBackStore>>,
) -> Result<Arc<dyn ImmutableBlobBackend>, StoreError> {
    if let Some(backend) = built.get(id) {
        return Ok(backend.clone());
    }
    let node = nodes
        .get(id)
        .ok_or_else(|| invalid_graph(id.as_str(), GraphViolation::MissingNode))?;
    let backend: Arc<dyn ImmutableBlobBackend> = match node {
        StoreNodeSpec::Memory { max_logical_bytes } => {
            let leaf = Arc::new(MemoryBlobBackend::new(id.as_str(), *max_logical_bytes));
            physical.insert(id.clone(), leaf.clone());
            leaf
        }
        StoreNodeSpec::Directory { root } => {
            let leaf = Arc::new(DirectoryBlobBackend::new(id.as_str(), root.clone()));
            physical.insert(id.clone(), leaf.clone());
            leaf
        }
        StoreNodeSpec::CompressedDirectory {
            root,
            maximum_logical_object_bytes,
        } => {
            let leaf = Arc::new(CompressedDirectoryBlobBackend::new(
                id.as_str(),
                root.clone(),
                *maximum_logical_object_bytes,
            )?);
            physical.insert(id.clone(), leaf.clone());
            leaf
        }
        StoreNodeSpec::Packed {
            root,
            target_pack_bytes,
        } => {
            let leaf = Arc::new(PackedBlobBackend::open(
                id.as_str(),
                root.clone(),
                *target_pack_bytes,
            )?);
            physical.insert(id.clone(), leaf.clone());
            leaf
        }
        StoreNodeSpec::Verified { child } => Arc::new(VerifiedStore::new(
            id.as_str(),
            instantiate(
                configuration,
                child,
                nodes,
                built,
                physical,
                metrics,
                write_back,
            )?,
        )),
        StoreNodeSpec::Routed { routes } => {
            let routes = routes
                .iter()
                .map(|(kind, child)| {
                    Ok((
                        *kind,
                        instantiate(
                            configuration,
                            child,
                            nodes,
                            built,
                            physical,
                            metrics,
                            write_back,
                        )?,
                    ))
                })
                .collect::<Result<BTreeMap<_, _>, StoreError>>()?;
            Arc::new(RoutedStore::new(id.as_str(), routes)?)
        }
        StoreNodeSpec::Tiered {
            tiers,
            write_tier,
            promote_reads,
        } => {
            let tiers = tiers
                .iter()
                .map(|child| {
                    instantiate(
                        configuration,
                        child,
                        nodes,
                        built,
                        physical,
                        metrics,
                        write_back,
                    )
                })
                .collect::<Result<Vec<_>, _>>()?;
            Arc::new(TieredStore::new(
                id.as_str(),
                tiers,
                *write_tier,
                *promote_reads,
            )?)
        }
        StoreNodeSpec::ReadThrough { cache, source } => Arc::new(ReadThroughStore::new(
            id.as_str(),
            instantiate(
                configuration,
                cache,
                nodes,
                built,
                physical,
                metrics,
                write_back,
            )?,
            instantiate(
                configuration,
                source,
                nodes,
                built,
                physical,
                metrics,
                write_back,
            )?,
        )),
        StoreNodeSpec::WriteThrough { children } => {
            let children = children
                .iter()
                .map(|child| {
                    instantiate(
                        configuration,
                        child,
                        nodes,
                        built,
                        physical,
                        metrics,
                        write_back,
                    )
                })
                .collect::<Result<Vec<_>, _>>()?;
            Arc::new(WriteThroughStore::new(id.as_str(), children)?)
        }
        StoreNodeSpec::WriteBack {
            staging,
            destination,
            journal_root,
            maximum_pending_objects,
            maximum_pending_bytes,
        } => {
            let store = Arc::new(WriteBackStore::new(
                id.as_str(),
                instantiate(
                    configuration,
                    staging,
                    nodes,
                    built,
                    physical,
                    metrics,
                    write_back,
                )?,
                instantiate(
                    configuration,
                    destination,
                    nodes,
                    built,
                    physical,
                    metrics,
                    write_back,
                )?,
                journal_root.clone(),
                *maximum_pending_objects,
                *maximum_pending_bytes,
            )?);
            write_back.insert(id.clone(), Arc::clone(&store));
            store
        }
        StoreNodeSpec::Metrics { child } => {
            let child = instantiate(
                configuration,
                child,
                nodes,
                built,
                physical,
                metrics,
                write_back,
            )?;
            let (backend, state) = MetricsStore::new(id.as_str(), child);
            metrics.insert(id.clone(), state);
            Arc::new(backend)
        }
        StoreNodeSpec::LogicalQuota {
            child,
            state_root,
            maximum_objects,
            maximum_logical_bytes,
        } => {
            let child_backend = instantiate(
                configuration,
                child,
                nodes,
                built,
                physical,
                metrics,
                write_back,
            )?;
            let child_admin = physical.remove(child).ok_or_else(|| {
                invalid_graph(id.as_str(), GraphViolation::InvalidLogicalQuotaChild)
            })?;
            let store = Arc::new(LogicalQuotaStore::open(
                id.as_str(),
                state_root.clone(),
                *maximum_objects,
                *maximum_logical_bytes,
                configuration,
                child_backend,
                child_admin,
            )?);
            physical.insert(id.clone(), store.clone());
            store
        }
    };
    built.insert(id.clone(), backend.clone());
    Ok(backend)
}

fn validate_capability_edges(
    nodes: &BTreeMap<StoreNodeId, StoreNodeSpec>,
    built: &BTreeMap<StoreNodeId, Arc<dyn ImmutableBlobBackend>>,
) -> Result<(), StoreError> {
    for (id, node) in nodes {
        let children: Vec<&StoreNodeId> = match node {
            StoreNodeSpec::Tiered {
                tiers,
                promote_reads: true,
                ..
            } => tiers.iter().collect(),
            StoreNodeSpec::ReadThrough { cache, .. } => vec![cache],
            StoreNodeSpec::WriteThrough { children } => children.iter().collect(),
            StoreNodeSpec::WriteBack {
                staging,
                destination,
                ..
            } => vec![staging, destination],
            _ => continue,
        };
        for child in children {
            let backend = built
                .get(child)
                .ok_or_else(|| invalid_graph(child.as_str(), GraphViolation::MissingNode))?;
            if !backend.capabilities().conditional_create {
                return Err(invalid_graph(id.as_str(), GraphViolation::UnsupportedChild));
            }
        }
    }
    Ok(())
}

fn invalid_graph(node: &str, violation: GraphViolation) -> StoreError {
    StoreError::InvalidGraph {
        node: node.to_owned(),
        violation,
    }
}

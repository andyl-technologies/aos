//! Authenticated streaming replay views over exact-checkpoint closures.

use super::*;

/// One immutable object in a portable production exact-checkpoint closure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProductionExactCheckpointObject {
    pub(super) identity: ContentHash,
    pub(super) length: u64,
}

impl ProductionExactCheckpointObject {
    /// Creates one portable immutable-object inventory entry.
    #[must_use]
    pub const fn new(identity: ContentHash, length: u64) -> Self {
        Self { identity, length }
    }

    /// Returns the BLAKE3 content identity used by the production closure manifest.
    #[must_use]
    pub const fn identity(self) -> ContentHash {
        self.identity
    }

    /// Returns the exact logical byte length of this stored object.
    #[must_use]
    pub const fn length(self) -> u64 {
        self.length
    }
}

/// Read-only portable view of one complete production exact-checkpoint closure.
///
/// The value exposes no directory or mutation authority. Its manifest is the
/// canonical `crucible.production-exact-closure.v5` body, and its object list
/// is the exact deduplicated set named by that manifest. Large overlay and
/// VMState artifacts remain represented by their bounded content-addressed
/// chunks rather than by RAM-sized buffers.
#[derive(Clone)]
pub struct ProductionExactCheckpointClosure {
    pub(super) identity: ContentHash,
    pub(super) scenario: ContentHash,
    pub(super) configuration: ContentHash,
    pub(super) manifest: Vec<u8>,
    pub(super) run_state_root: PathBuf,
    pub(super) source: ScenarioDefForm,
    pub(super) object_directory: PathBuf,
    pub(super) objects: Vec<ProductionExactCheckpointObject>,
}

/// One raw live-node snapshot streamed from a production checkpoint closure.
///
/// The value owns only one decoded snapshot. Callers advance the corresponding
/// [`ProductionExactCheckpointReplayTargets`] cursor before loading another,
/// which keeps additional decoded-target memory to one snapshot at a time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductionExactCheckpointReplayTarget {
    node: NodeId,
    snapshot: ExactSnapshotHandle,
    overlay: ProductionExactCheckpointReplayArtifact,
    vmstate: ProductionExactCheckpointReplayArtifact,
}

/// Read-only streaming capability for one authenticated replay target artifact.
///
/// The value exposes no path or store mutation authority. It retains the exact
/// chunk manifest needed to stream one artifact with fixed temporary memory and
/// reauthenticate both its declared length and content identity.
#[derive(Clone)]
pub struct ProductionExactCheckpointReplayArtifact {
    object_directory: PathBuf,
    identity: ContentHash,
    length: u64,
    chunks: Vec<ContentHash>,
    role: &'static str,
}

impl std::fmt::Debug for ProductionExactCheckpointReplayArtifact {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProductionExactCheckpointReplayArtifact")
            .field("identity", &self.identity)
            .field("length", &self.length)
            .field("chunk_count", &self.chunks.len())
            .field("role", &self.role)
            .finish_non_exhaustive()
    }
}

impl PartialEq for ProductionExactCheckpointReplayArtifact {
    fn eq(&self, other: &Self) -> bool {
        self.identity == other.identity
            && self.length == other.length
            && self.chunks == other.chunks
            && self.role == other.role
    }
}

impl Eq for ProductionExactCheckpointReplayArtifact {}

/// Bounded cursor over the raw live-node snapshots in one production closure.
///
/// Construction completely authenticates the closure and retains only its
/// compact target descriptors. Each call to [`Self::next_target`] opens,
/// authenticates, and decodes at most one configured fat-checkpoint body.
pub struct ProductionExactCheckpointReplayTargets<'a> {
    closure: &'a ProductionExactCheckpointClosure,
    targets: Vec<ProductionExactCheckpointReplayDescriptor>,
    next: usize,
    snapshot_limit: u64,
}

/// Random-access catalog of compact targets in one authenticated closure.
///
/// The catalog shares the immutable closure through an [`Arc`] and retains
/// only its bounded node/artifact descriptors. Opening one node authenticates
/// and decodes only that node's snapshot body, so a replay factory neither
/// rescans the complete closure for every World VM nor retains every fat
/// snapshot in memory.
#[derive(Clone)]
pub struct ProductionExactCheckpointReplayCatalog {
    closure: Arc<ProductionExactCheckpointClosure>,
    targets: BTreeMap<NodeId, ProductionExactCheckpointReplayDescriptor>,
    snapshot_limit: u64,
}

#[derive(Clone)]
struct ProductionExactCheckpointReplayDescriptor {
    node: NodeId,
    snapshot: ContentHash,
    overlay: ProductionExactCheckpointReplayArtifact,
    vmstate: ProductionExactCheckpointReplayArtifact,
}

impl ProductionExactCheckpointReplayCatalog {
    /// Returns the number of exact node targets in the catalog.
    #[must_use]
    pub fn len(&self) -> usize {
        self.targets.len()
    }

    /// Reports whether the catalog contains no live-node targets.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.targets.is_empty()
    }

    /// Returns the exact ordered node set without opening snapshot bodies.
    pub fn nodes(&self) -> impl ExactSizeIterator<Item = &NodeId> {
        self.targets.keys()
    }

    /// Opens and authenticates one raw live-node target.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] when `node` is absent or its snapshot is
    /// unavailable, corrupt, outside the configured byte bound, or no longer a
    /// raw `NotRun` replay-oracle source.
    pub fn open_target(
        &self,
        node: &NodeId,
    ) -> Result<ProductionExactCheckpointReplayTarget, LifecycleApiError> {
        self.open_target_with_boundary(node, &mut || Ok(()))
    }

    /// Opens one target while observing a bounded operational callback.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::open_target`], including the exact
    /// [`LifecycleApiError`] returned by `boundary`.
    pub fn open_target_with_boundary(
        &self,
        node: &NodeId,
        boundary: &mut dyn FnMut() -> Result<(), LifecycleApiError>,
    ) -> Result<ProductionExactCheckpointReplayTarget, LifecycleApiError> {
        boundary()?;
        let target = self.targets.get(node).ok_or_else(|| {
            loop_factory_error(format!(
                "production replay-oracle catalog has no target for `{}`",
                node.name
            ))
        })?;
        let snapshot = read_portable_snapshot(
            self.closure.as_ref(),
            target.snapshot,
            self.snapshot_limit,
            boundary,
        )?;
        if snapshot.replay_oracle_validation() != QemuReplayOracleValidation::NotRun {
            return Err(loop_factory_error(format!(
                "production replay-oracle source for `{}` is not raw",
                target.node.name
            )));
        }
        boundary()?;
        Ok(ProductionExactCheckpointReplayTarget {
            node: target.node.clone(),
            snapshot,
            overlay: target.overlay.clone(),
            vmstate: target.vmstate.clone(),
        })
    }
}

impl ProductionExactCheckpointReplayArtifact {
    /// Returns the exact content identity of the artifact.
    #[must_use]
    pub const fn identity(&self) -> ContentHash {
        self.identity
    }

    /// Returns the authenticated logical artifact length.
    #[must_use]
    pub const fn length(&self) -> u64 {
        self.length
    }

    /// Streams and authenticates the artifact into `destination`.
    ///
    /// Temporary memory is bounded independently of artifact size. The
    /// destination may contain a partial prefix after failure, so callers must
    /// use a linear staging authority before making output visible.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError::LoopFactory`] when a source chunk is
    /// missing or corrupt, the destination rejects a write, or the complete
    /// length and identity do not match the authenticated manifest.
    pub fn stream_into(
        &self,
        destination: &mut impl std::io::Write,
    ) -> Result<(), LifecycleApiError> {
        stream_chunked_checkpoint_artifact(
            &self.object_directory,
            &self.chunks,
            self.length,
            self.identity,
            destination,
            self.role,
        )
    }

    /// Streams and authenticates the artifact under an operational boundary.
    ///
    /// `boundary` runs before and after every bounded source/destination I/O
    /// quantum, including before the first read and after final
    /// authentication. Blocking I/O itself must still obey the owner's bounded
    /// storage contract.
    ///
    /// # Errors
    ///
    /// Returns the exact [`LifecycleApiError`] returned by `boundary`.
    /// Otherwise returns [`LifecycleApiError::LoopFactory`] under the same
    /// conditions as [`Self::stream_into`].
    pub fn stream_into_with_boundary(
        &self,
        destination: &mut impl std::io::Write,
        boundary: &mut dyn FnMut() -> Result<(), LifecycleApiError>,
    ) -> Result<(), LifecycleApiError> {
        stream_chunked_checkpoint_artifact_with_boundary(
            &self.object_directory,
            &self.chunks,
            self.length,
            self.identity,
            destination,
            self.role,
            boundary,
        )
    }
}

impl ProductionExactCheckpointReplayTarget {
    /// Returns the exact live node that owns this snapshot.
    #[must_use]
    pub const fn node(&self) -> &NodeId {
        &self.node
    }

    /// Returns the authenticated raw snapshot for this node.
    #[must_use]
    pub const fn snapshot(&self) -> &ExactSnapshotHandle {
        &self.snapshot
    }

    /// Returns the authenticated writable-root overlay artifact.
    #[must_use]
    pub const fn overlay(&self) -> &ProductionExactCheckpointReplayArtifact {
        &self.overlay
    }

    /// Returns the authenticated QEMU VMState artifact.
    #[must_use]
    pub const fn vmstate(&self) -> &ProductionExactCheckpointReplayArtifact {
        &self.vmstate
    }

    /// Consumes the target into its node and snapshot values.
    #[must_use]
    pub fn into_parts(self) -> (NodeId, ExactSnapshotHandle) {
        (self.node, self.snapshot)
    }

    /// Consumes the target into its metadata and both artifact capabilities.
    #[must_use]
    pub fn into_complete_parts(
        self,
    ) -> (
        NodeId,
        ExactSnapshotHandle,
        ProductionExactCheckpointReplayArtifact,
        ProductionExactCheckpointReplayArtifact,
    ) {
        (self.node, self.snapshot, self.overlay, self.vmstate)
    }
}

impl ProductionExactCheckpointReplayTargets<'_> {
    /// Returns the number of target descriptors not yet decoded.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.targets.len().saturating_sub(self.next)
    }

    /// Opens and authenticates the next raw live-node snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] when the next snapshot is unavailable,
    /// corrupt, outside its configured byte bound, or already carries durable
    /// replay-oracle evidence instead of the required raw `NotRun` state.
    pub fn next_target(
        &mut self,
    ) -> Result<Option<ProductionExactCheckpointReplayTarget>, LifecycleApiError> {
        self.next_target_with_boundary(&mut || Ok(()))
    }

    /// Opens the next target while observing an operational boundary.
    ///
    /// The callback runs before and throughout the bounded object read and
    /// after canonical decoding.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::next_target`], including the exact
    /// [`LifecycleApiError`] returned by `boundary`.
    pub fn next_target_with_boundary(
        &mut self,
        boundary: &mut dyn FnMut() -> Result<(), LifecycleApiError>,
    ) -> Result<Option<ProductionExactCheckpointReplayTarget>, LifecycleApiError> {
        boundary()?;
        let Some(target) = self.targets.get(self.next) else {
            return Ok(None);
        };
        let snapshot =
            read_portable_snapshot(self.closure, target.snapshot, self.snapshot_limit, boundary)?;
        if snapshot.replay_oracle_validation() != QemuReplayOracleValidation::NotRun {
            return Err(loop_factory_error(format!(
                "production replay-oracle source for `{}` is not raw",
                target.node.name
            )));
        }
        boundary()?;
        self.next = self
            .next
            .checked_add(1)
            .ok_or_else(|| loop_factory_error("production replay-oracle target cursor overflow"))?;
        Ok(Some(ProductionExactCheckpointReplayTarget {
            node: target.node.clone(),
            snapshot,
            overlay: target.overlay.clone(),
            vmstate: target.vmstate.clone(),
        }))
    }
}

/// Authenticated modeled continuation recovered from one production closure.
///
/// The value contains no filesystem or QEMU launch authority. It is the exact
/// configuration and scheduler continuation established by the complete
/// scenario-aware restore validator and is suitable for binding an operational
/// resume request before any guest process is launched.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductionExactCheckpointResumeBasis {
    pub(super) identity: ContentHash,
    pub(super) configuration: Configuration,
    pub(super) scheduler: SingleSchedulerCheckpoint,
    pub(super) replay_oracle_ready: bool,
}

/// No-write portable replacement carrying matching per-node replay evidence.
///
/// The value borrows no process, run-directory, or destination-store authority.
/// It implements [`ProductionExactCheckpointSource`] by delegating unchanged
/// objects to the authenticated raw closure and regenerating each promoted
/// snapshot object from its exact source-bound [`QemuReplayOracleCheck`] on
/// demand. Large snapshot continuations are therefore processed one node at a
/// time rather than retained for the complete World.
pub struct PreparedProductionReplayOraclePromotion {
    pub(super) source: ContentHash,
    pub(super) promoted: ContentHash,
    pub(super) scenario: ContentHash,
    pub(super) configuration: ContentHash,
    pub(super) manifest: Vec<u8>,
    pub(super) objects: Vec<ProductionExactCheckpointObject>,
    pub(super) raw: ProductionExactCheckpointClosure,
    pub(super) promoted_snapshots: BTreeMap<ContentHash, PreparedPromotedSnapshot>,
    pub(super) fat_checkpoint_bytes: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct PreparedPromotedSnapshot {
    pub(super) raw_object: ContentHash,
    pub(super) check: QemuReplayOracleCheck,
    pub(super) length: u64,
}

impl std::fmt::Debug for PreparedProductionReplayOraclePromotion {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedProductionReplayOraclePromotion")
            .field("source", &self.source)
            .field("promoted", &self.promoted)
            .field("target_count", &self.promoted_snapshots.len())
            .finish_non_exhaustive()
    }
}

impl PreparedProductionReplayOraclePromotion {
    /// Returns the exact raw version-four closure that was compared.
    #[must_use]
    pub const fn source(&self) -> ContentHash {
        self.source
    }

    /// Returns the derived replacement closure identity.
    #[must_use]
    pub const fn promoted(&self) -> ContentHash {
        self.promoted
    }
}

impl ProductionExactCheckpointResumeBasis {
    /// Returns the authenticated native production-closure identity.
    #[must_use]
    pub const fn identity(&self) -> ContentHash {
        self.identity
    }

    /// Returns the exact configuration at the restored scheduler boundary.
    #[must_use]
    pub const fn configuration(&self) -> &Configuration {
        &self.configuration
    }

    /// Returns the complete scheduler continuation at that boundary.
    #[must_use]
    pub const fn scheduler(&self) -> &SingleSchedulerCheckpoint {
        &self.scheduler
    }

    /// Returns whether every live snapshot carries source-bound matching evidence.
    #[must_use]
    pub const fn replay_oracle_ready(&self) -> bool {
        self.replay_oracle_ready
    }

    /// Consumes the basis into its modeled continuation.
    #[must_use]
    pub fn into_parts(self) -> (Configuration, SingleSchedulerCheckpoint) {
        (self.configuration, self.scheduler)
    }
}

impl ProductionExactCheckpointClosure {
    /// Returns the authenticated production closure identity.
    #[must_use]
    pub const fn identity(&self) -> ContentHash {
        self.identity
    }

    /// Returns the exact scenario named by the closure manifest.
    #[must_use]
    pub const fn scenario(&self) -> ContentHash {
        self.scenario
    }

    /// Returns the exact modeled configuration named by the closure manifest.
    #[must_use]
    pub const fn configuration(&self) -> ContentHash {
        self.configuration
    }

    /// Returns the canonical version-four production closure manifest bytes.
    #[must_use]
    pub fn manifest(&self) -> &[u8] {
        &self.manifest
    }

    /// Returns the exact sorted and deduplicated immutable object inventory.
    #[must_use]
    pub fn objects(&self) -> &[ProductionExactCheckpointObject] {
        &self.objects
    }

    /// Authenticates a bounded cursor over every raw live-node snapshot.
    ///
    /// The complete production closure is validated before the cursor is
    /// returned. Only compact node/object descriptors are retained; snapshot
    /// bodies are opened and decoded one at a time by the cursor.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] when the closure is incomplete, corrupt,
    /// semantically inconsistent, or outside its authored bounds.
    pub fn replay_oracle_targets(
        &self,
    ) -> Result<ProductionExactCheckpointReplayTargets<'_>, LifecycleApiError> {
        self.replay_oracle_targets_with_boundary(&mut || Ok(()))
    }

    /// Builds the raw-target cursor under an operational boundary callback.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::replay_oracle_targets`], including
    /// the exact [`LifecycleApiError`] returned by `boundary`.
    pub fn replay_oracle_targets_with_boundary(
        &self,
        boundary: &mut dyn FnMut() -> Result<(), LifecycleApiError>,
    ) -> Result<ProductionExactCheckpointReplayTargets<'_>, LifecycleApiError> {
        self.validate_complete_with_boundary(boundary)?;
        let limits = self.source.plan().fault_signals().resource_limits();
        let manifest = decode::decode_manifest_with_limits(self.manifest(), limits)?;
        let targets = manifest
            .targets
            .into_iter()
            .map(|target| ProductionExactCheckpointReplayDescriptor {
                node: NodeId { name: target.node },
                snapshot: target.snapshot,
                overlay: ProductionExactCheckpointReplayArtifact {
                    object_directory: self.object_directory.clone(),
                    identity: target.overlay.identity,
                    length: target.overlay.length,
                    chunks: target.overlay.chunks,
                    role: "replay-oracle root overlay",
                },
                vmstate: ProductionExactCheckpointReplayArtifact {
                    object_directory: self.object_directory.clone(),
                    identity: target.vmstate.identity,
                    length: target.vmstate.length,
                    chunks: target.vmstate.chunks,
                    role: "replay-oracle VMState",
                },
            })
            .collect();
        boundary()?;
        Ok(ProductionExactCheckpointReplayTargets {
            closure: self,
            targets,
            next: 0,
            snapshot_limit: limits.fat_checkpoint_bytes,
        })
    }

    /// Builds a shared random-access target catalog.
    ///
    /// The complete closure is authenticated once. The returned catalog owns a
    /// shared immutable reference to this exact closure and retains only compact
    /// descriptors; it opens at most one fat snapshot body per target request.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] when the closure is incomplete, corrupt,
    /// semantically inconsistent, outside its authored bounds, or repeats one
    /// live-node identity.
    pub fn replay_oracle_catalog(
        self: &Arc<Self>,
    ) -> Result<ProductionExactCheckpointReplayCatalog, LifecycleApiError> {
        self.replay_oracle_catalog_with_boundary(&mut || Ok(()))
    }

    /// Builds a shared target catalog under an operational boundary callback.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::replay_oracle_catalog`], including
    /// the exact [`LifecycleApiError`] returned by `boundary`.
    pub fn replay_oracle_catalog_with_boundary(
        self: &Arc<Self>,
        boundary: &mut dyn FnMut() -> Result<(), LifecycleApiError>,
    ) -> Result<ProductionExactCheckpointReplayCatalog, LifecycleApiError> {
        self.validate_complete_with_boundary(boundary)?;
        let limits = self.source.plan().fault_signals().resource_limits();
        let manifest = decode::decode_manifest_with_limits(self.manifest(), limits)?;
        let mut targets = BTreeMap::new();
        for target in manifest.targets {
            let node = NodeId { name: target.node };
            let descriptor = ProductionExactCheckpointReplayDescriptor {
                node: node.clone(),
                snapshot: target.snapshot,
                overlay: ProductionExactCheckpointReplayArtifact {
                    object_directory: self.object_directory.clone(),
                    identity: target.overlay.identity,
                    length: target.overlay.length,
                    chunks: target.overlay.chunks,
                    role: "replay-oracle root overlay",
                },
                vmstate: ProductionExactCheckpointReplayArtifact {
                    object_directory: self.object_directory.clone(),
                    identity: target.vmstate.identity,
                    length: target.vmstate.length,
                    chunks: target.vmstate.chunks,
                    role: "replay-oracle VMState",
                },
            };
            if targets.insert(node.clone(), descriptor).is_some() {
                return Err(loop_factory_error(format!(
                    "production replay-oracle catalog repeats node `{}`",
                    node.name
                )));
            }
        }
        boundary()?;
        Ok(ProductionExactCheckpointReplayCatalog {
            closure: Arc::clone(self),
            targets,
            snapshot_limit: limits.fat_checkpoint_bytes,
        })
    }

    /// Opens one exact object at its first byte.
    ///
    /// Callers must drain the stream and authenticate its exact declared length
    /// and complete content identity before publishing or executing any bytes.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] when `identity` is not in this closure,
    /// or the retained object is unavailable or has changed length.
    pub fn open_object(
        &self,
        identity: ContentHash,
    ) -> Result<Box<dyn Read + Send>, LifecycleApiError> {
        let object = self
            .objects
            .binary_search_by_key(&identity, |object| object.identity)
            .ok()
            .and_then(|index| self.objects.get(index))
            .ok_or_else(|| loop_factory_error("exact checkpoint object is not in the manifest"))?;
        let path = object_path(&self.object_directory, identity);
        let source = File::open(&path).map_err(|error| {
            loop_factory_error(format!(
                "open exact checkpoint object {}: {error}",
                identity.to_hex()
            ))
        })?;
        let observed_length = source
            .metadata()
            .map_err(|error| {
                loop_factory_error(format!(
                    "inspect exact checkpoint object {}: {error}",
                    identity.to_hex()
                ))
            })?
            .len();
        if observed_length != object.length {
            return Err(loop_factory_error(format!(
                "exact checkpoint object {} length changed from {} to {observed_length}",
                identity.to_hex(),
                object.length
            )));
        }
        Ok(Box::new(source))
    }

    /// Reapplies the complete scenario-aware production restore validator.
    ///
    /// This authenticates every canonical continuation, artifact aggregate,
    /// node set, scheduler projection, and fault/network state under the exact
    /// source scenario. It performs no closure publication.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] when any retained object is unavailable,
    /// corrupt, semantically inconsistent, or outside the authored bounds.
    pub fn validate_complete(&self) -> Result<(), LifecycleApiError> {
        self.validate_complete_with_boundary(&mut || Ok(()))
    }

    /// Reapplies complete validation while observing an operational boundary.
    ///
    /// The callback runs between object reads and between bounded chunks of
    /// every admitted continuation read. Callers can therefore stop closure
    /// authentication without waiting for the complete aggregate byte limit.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::validate_complete`], including the
    /// exact [`LifecycleApiError`] returned by `boundary`.
    pub fn validate_complete_with_boundary(
        &self,
        boundary: &mut dyn FnMut() -> Result<(), LifecycleApiError>,
    ) -> Result<(), LifecycleApiError> {
        boundary()?;
        let restored = load_exact_checkpoint_set_with_boundary(
            &self.run_state_root,
            &self.source.scenario_def(),
            &self.source,
            self.identity,
            boundary,
        )?;
        boundary()?;
        if restored.configuration.id() != self.configuration {
            return Err(loop_factory_error(
                "portable checkpoint restored a different configuration",
            ));
        }
        Ok(())
    }

    /// Authenticates and reconstructs the modeled production-resume basis.
    ///
    /// This applies the same complete scenario-aware validator used by
    /// [`Self::validate_complete`] and retains only its exact configuration and
    /// scheduler continuation. It performs no closure publication and grants
    /// no QEMU launch authority.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] when any closure object is unavailable,
    /// corrupt, semantically inconsistent, or outside the authored bounds.
    pub fn authenticate_resume_basis(
        &self,
    ) -> Result<ProductionExactCheckpointResumeBasis, LifecycleApiError> {
        self.authenticate_resume_basis_with_boundary(&mut || Ok(()))
    }

    /// Reconstructs the modeled resume basis under an operational boundary.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::authenticate_resume_basis`],
    /// including the exact [`LifecycleApiError`] returned by `boundary`.
    pub fn authenticate_resume_basis_with_boundary(
        &self,
        boundary: &mut dyn FnMut() -> Result<(), LifecycleApiError>,
    ) -> Result<ProductionExactCheckpointResumeBasis, LifecycleApiError> {
        boundary()?;
        let restored = load_exact_checkpoint_set_with_boundary(
            &self.run_state_root,
            &self.source.scenario_def(),
            &self.source,
            self.identity,
            boundary,
        )?;
        if restored.configuration.id() != self.configuration {
            return Err(loop_factory_error(
                "portable checkpoint restored a different configuration",
            ));
        }
        let basis = ProductionExactCheckpointResumeBasis {
            identity: restored.identity,
            configuration: restored.configuration,
            scheduler: restored.scheduler,
            replay_oracle_ready: restored.targets.values().all(|target| {
                matches!(
                    target.snapshot.replay_oracle_validation(),
                    QemuReplayOracleValidation::Match { .. }
                )
            }),
        };
        boundary()?;
        Ok(basis)
    }

    /// Prepares a source-bound replay-oracle replacement without writes.
    ///
    /// `checks` must contain exactly one result for every live target in this
    /// closure and no result for a permanently failed node. The raw closure is
    /// completely reauthenticated before each check promotes its exact
    /// snapshot. The returned portable source changes only per-node oracle
    /// evidence and the identities derived from those bytes.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] when this closure is invalid or already
    /// promoted, the check set is incomplete or contains a foreign node, a
    /// check belongs to another snapshot, a comparison was not a match, or the
    /// replacement cannot be encoded within the authored checkpoint bounds.
    pub fn prepare_replay_oracle_promotion(
        &self,
        checks: &BTreeMap<NodeId, QemuReplayOracleCheck>,
    ) -> Result<PreparedProductionReplayOraclePromotion, LifecycleApiError> {
        self.prepare_replay_oracle_promotion_with_boundary(checks, &mut || Ok(()))
    }

    /// Prepares a no-write promotion under an operational boundary callback.
    ///
    /// The callback runs throughout complete source validation and between
    /// every bounded snapshot decode, promotion, and canonical encode.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::prepare_replay_oracle_promotion`],
    /// including the exact [`LifecycleApiError`] returned by `boundary`.
    pub fn prepare_replay_oracle_promotion_with_boundary(
        &self,
        checks: &BTreeMap<NodeId, QemuReplayOracleCheck>,
        boundary: &mut dyn FnMut() -> Result<(), LifecycleApiError>,
    ) -> Result<PreparedProductionReplayOraclePromotion, LifecycleApiError> {
        self.validate_complete_with_boundary(boundary)?;
        prepare_production_replay_oracle_promotion_source(self, checks, boundary)
    }

    /// Authenticates an exact source-bound replay-oracle promotion.
    ///
    /// Both closures first pass the complete scenario-aware production
    /// validator. Their manifests must then be identical except for closure
    /// identity and one QEMU snapshot object per live node. Every source
    /// snapshot must carry `NotRun`, every replacement must carry `Match`, and
    /// the replacement must derive the exact raw snapshot identity of its
    /// paired source. No scheduler, host-I/O, node-continuation, artifact,
    /// lifecycle, fault, event-log, generation, or service-state field may
    /// change.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] when either closure is incomplete or
    /// invalid, the roots do not share one exact production basis, a target is
    /// missing or reordered, or any snapshot pair is not an exact raw-to-match
    /// replay-oracle promotion.
    pub fn authenticate_replay_oracle_promotion(
        &self,
        promoted: &Self,
    ) -> Result<(), LifecycleApiError> {
        self.authenticate_replay_oracle_promotion_with_boundary(promoted, &mut || Ok(()))
    }

    /// Authenticates a replay-oracle promotion under an operational boundary.
    ///
    /// The callback runs throughout both complete closure validations and
    /// between bounded snapshot reads. Snapshot pairs are reduced to compact
    /// source identities one at a time, so retained memory does not grow with
    /// the number of production nodes.
    ///
    /// # Errors
    ///
    /// Returns the same errors as
    /// [`Self::authenticate_replay_oracle_promotion`], including the exact
    /// [`LifecycleApiError`] returned by `boundary`.
    pub fn authenticate_replay_oracle_promotion_with_boundary(
        &self,
        promoted: &Self,
        boundary: &mut dyn FnMut() -> Result<(), LifecycleApiError>,
    ) -> Result<(), LifecycleApiError> {
        boundary()?;
        if self.identity == promoted.identity {
            return Err(loop_factory_error(
                "production replay-oracle promotion did not change the closure identity",
            ));
        }
        if self.scenario != promoted.scenario
            || self.source.scenario_def() != promoted.source.scenario_def()
        {
            return Err(loop_factory_error(
                "production replay-oracle promotion belongs to a different scenario",
            ));
        }

        self.validate_complete_with_boundary(boundary)?;
        promoted.validate_complete_with_boundary(boundary)?;
        boundary()?;

        let limits = self.source.plan().fault_signals().resource_limits();
        let source_manifest = decode::decode_manifest_with_limits(self.manifest(), limits)?;
        let promoted_manifest = decode::decode_manifest_with_limits(promoted.manifest(), limits)?;
        let source_fault_identity = read_portable_fault_checkpoint_identity(
            self,
            source_manifest.fault_checkpoint,
            &self.source,
            boundary,
        )?;
        let promoted_fault_identity = read_portable_fault_checkpoint_identity(
            promoted,
            promoted_manifest.fault_checkpoint,
            &self.source,
            boundary,
        )?;
        if source_fault_identity != promoted_fault_identity {
            return Err(loop_factory_error(
                "production replay-oracle promotion changed the fault-runtime identity",
            ));
        }

        authenticate_replay_oracle_source_pair(
            self,
            promoted,
            limits,
            source_fault_identity,
            boundary,
        )
    }

    /// Streams and authenticates one exact object into `destination`.
    ///
    /// No bytes from an unlisted object can be read through this capability.
    /// The complete source length and BLAKE3 identity are checked after EOF;
    /// callers must treat a partially written destination as untrusted on
    /// failure.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] when `identity` is not in this closure,
    /// the retained object is unavailable or changed, destination I/O fails,
    /// or the final length or identity differs.
    pub fn copy_object_to(
        &self,
        identity: ContentHash,
        destination: &mut dyn Write,
    ) -> Result<u64, LifecycleApiError> {
        let object = self
            .objects
            .binary_search_by_key(&identity, |object| object.identity)
            .ok()
            .and_then(|index| self.objects.get(index))
            .ok_or_else(|| loop_factory_error("exact checkpoint object is not in the manifest"))?;
        let mut source = self.open_object(identity)?;

        let mut hasher = blake3::Hasher::new();
        let mut copied = 0_u64;
        let mut buffer = [0_u8; CLOSURE_EXPORT_COPY_BUFFER_BYTES];
        loop {
            let count = source.read(&mut buffer).map_err(|error| {
                loop_factory_error(format!(
                    "read exact checkpoint object {}: {error}",
                    identity.to_hex()
                ))
            })?;
            if count == 0 {
                break;
            }
            destination.write_all(&buffer[..count]).map_err(|error| {
                loop_factory_error(format!(
                    "write exact checkpoint object {}: {error}",
                    identity.to_hex()
                ))
            })?;
            hasher.update(&buffer[..count]);
            copied = copied
                .checked_add(u64::try_from(count).map_err(|_| {
                    loop_factory_error("exact checkpoint copy length is not representable")
                })?)
                .ok_or_else(|| loop_factory_error("exact checkpoint copy length overflow"))?;
        }
        let observed = ContentHash {
            bytes: *hasher.finalize().as_bytes(),
        };
        if copied != object.length || observed != identity {
            return Err(loop_factory_error(format!(
                "exact checkpoint object {} failed streaming authentication",
                identity.to_hex()
            )));
        }
        Ok(copied)
    }
}

pub(super) fn validate_replay_oracle_manifest_basis(
    source: &ClosureManifest,
    promoted: &ClosureManifest,
) -> Result<(), LifecycleApiError> {
    let common_basis_matches = source.scenario == promoted.scenario
        && source.configuration == promoted.configuration
        && source.schedule == promoted.schedule
        && source.frontier == promoted.frontier
        && source.scheduler == promoted.scheduler
        && source.event_log_segments == promoted.event_log_segments
        && source.signal_artifacts == promoted.signal_artifacts
        && source.trigger_state == promoted.trigger_state
        && source.assertion_state == promoted.assertion_state
        && source.lifecycle_state == promoted.lifecycle_state
        && source.fault_checkpoint == promoted.fault_checkpoint
        && source.node_generations == promoted.node_generations
        && source.node_service_states == promoted.node_service_states
        && source.targets.len() == promoted.targets.len();
    if !common_basis_matches {
        return Err(loop_factory_error(
            "production replay-oracle promotion changed non-snapshot closure state",
        ));
    }

    let mut changed = false;
    for (source_target, promoted_target) in source.targets.iter().zip(&promoted.targets) {
        if source_target.node != promoted_target.node
            || source_target.counter != promoted_target.counter
            || source_target.scheduler_time != promoted_target.scheduler_time
            || source_target.overlay != promoted_target.overlay
            || source_target.vmstate != promoted_target.vmstate
        {
            return Err(loop_factory_error(
                "production replay-oracle promotion changed a target basis",
            ));
        }
        changed |= source_target.snapshot != promoted_target.snapshot;
    }
    if !changed {
        return Err(loop_factory_error(
            "production replay-oracle promotion changed no target snapshot",
        ));
    }
    Ok(())
}

fn prepare_production_replay_oracle_promotion_source(
    raw: &ProductionExactCheckpointClosure,
    checks: &BTreeMap<NodeId, QemuReplayOracleCheck>,
    boundary: &mut dyn FnMut() -> Result<(), LifecycleApiError>,
) -> Result<PreparedProductionReplayOraclePromotion, LifecycleApiError> {
    boundary()?;
    let limits = raw.source.plan().fault_signals().resource_limits();
    let mut manifest = decode::decode_manifest_with_limits(raw.manifest(), limits)?;
    if checks.len() != manifest.targets.len() {
        return Err(loop_factory_error(
            "production replay-oracle check set does not match the live target set",
        ));
    }

    let configuration = manifest.configuration;
    let fault_checkpoint = manifest.fault_checkpoint;
    let fault_identity =
        read_portable_fault_checkpoint_identity(raw, fault_checkpoint, &raw.source, boundary)?;
    let mut promoted_snapshots = BTreeMap::new();
    for target in &mut manifest.targets {
        boundary()?;
        let node = NodeId {
            name: target.node.clone(),
        };
        let check = checks.get(&node).copied().ok_or_else(|| {
            loop_factory_error(format!(
                "production replay-oracle check is absent for `{}`",
                target.node
            ))
        })?;
        let snapshot =
            read_portable_snapshot(raw, target.snapshot, limits.fat_checkpoint_bytes, boundary)?;
        if snapshot.replay_oracle_validation() != QemuReplayOracleValidation::NotRun {
            return Err(loop_factory_error(format!(
                "production replay-oracle source for `{}` is not raw",
                target.node
            )));
        }
        let promoted = check.promote(&snapshot).map_err(|error| {
            loop_factory_error(format!(
                "promote production replay-oracle snapshot for `{}`: {error}",
                target.node
            ))
        })?;
        let promoted_semantic_identity = promoted.id();
        drop(snapshot);
        let bytes = promoted
            .to_canonical_bytes_with_limit(limits.fat_checkpoint_bytes)
            .map_err(|error| {
                loop_factory_error(format!(
                    "encode promoted production snapshot for `{}`: {error}",
                    target.node
                ))
            })?;
        let identity = ContentHash::from_bytes(&bytes);
        let length = u64::try_from(bytes.len()).map_err(|_| {
            loop_factory_error("promoted production snapshot length is not representable")
        })?;
        let descriptor = PreparedPromotedSnapshot {
            raw_object: target.snapshot,
            check,
            length,
        };
        if promoted_snapshots
            .insert(identity, descriptor)
            .is_some_and(|prior| prior != descriptor)
        {
            return Err(loop_factory_error(
                "distinct production snapshots collided after replay-oracle promotion",
            ));
        }
        target.snapshot = identity;
        target.manifest_identity =
            exact_checkpoint_target_manifest_identity(ExactCheckpointTargetManifestBasis {
                configuration,
                node: &node,
                counter: target.counter,
                scheduler_time: VirtualTime {
                    ticks: target.scheduler_time,
                },
                snapshot: promoted_semantic_identity,
                fault_identity,
                overlay: target.overlay.identity,
                vmstate: target.vmstate.identity,
            });
    }

    manifest.identity =
        closure_identity(&manifest).map_err(|error| loop_factory_error(error.to_string()))?;
    if manifest.identity == raw.identity {
        return Err(loop_factory_error(
            "production replay-oracle checks changed no closure identity",
        ));
    }
    let manifest_bytes =
        encode_manifest(&manifest).map_err(|error| loop_factory_error(error.to_string()))?;
    let raw_lengths = raw
        .objects
        .iter()
        .map(|object| (object.identity(), object.length()))
        .collect::<BTreeMap<_, _>>();
    let mut objects = Vec::new();
    let identities = manifest_object_identities(&manifest);
    objects
        .try_reserve_exact(identities.len())
        .map_err(|error| loop_factory_error(format!("reserve promoted inventory: {error}")))?;
    for identity in identities {
        let length = promoted_snapshots
            .get(&identity)
            .map(|snapshot| snapshot.length)
            .or_else(|| raw_lengths.get(&identity).copied())
            .ok_or_else(|| {
                loop_factory_error("promoted production closure lost an immutable object")
            })?;
        objects.push(ProductionExactCheckpointObject::new(identity, length));
    }

    let prepared = PreparedProductionReplayOraclePromotion {
        source: raw.identity,
        promoted: manifest.identity,
        scenario: manifest.scenario,
        configuration: manifest.configuration,
        manifest: manifest_bytes,
        objects,
        raw: raw.clone(),
        promoted_snapshots,
        fat_checkpoint_bytes: limits.fat_checkpoint_bytes,
    };
    authenticate_replay_oracle_source_pair(raw, &prepared, limits, fault_identity, boundary)?;
    Ok(prepared)
}

pub(super) fn authenticate_replay_oracle_source_pair(
    source: &dyn ProductionExactCheckpointSource,
    promoted: &dyn ProductionExactCheckpointSource,
    limits: FaultResourceLimits,
    fault_identity: ContentHash,
    boundary: &mut dyn FnMut() -> Result<(), LifecycleApiError>,
) -> Result<(), LifecycleApiError> {
    let source_manifest = decode::decode_manifest_with_limits(source.manifest(), limits)?;
    let promoted_manifest = decode::decode_manifest_with_limits(promoted.manifest(), limits)?;
    validate_replay_oracle_manifest_basis(&source_manifest, &promoted_manifest)?;

    for (source_target, promoted_target) in source_manifest
        .targets
        .iter()
        .zip(&promoted_manifest.targets)
    {
        boundary()?;
        let source_snapshot = read_portable_snapshot(
            source,
            source_target.snapshot,
            limits.fat_checkpoint_bytes,
            boundary,
        )?;
        if source_snapshot.replay_oracle_validation() != QemuReplayOracleValidation::NotRun {
            return Err(loop_factory_error(format!(
                "production replay-oracle source for `{}` is not raw",
                source_target.node
            )));
        }
        let source_identity = source_snapshot.id();
        let node = NodeId {
            name: source_target.node.clone(),
        };
        let expected_source_manifest =
            exact_checkpoint_target_manifest_identity(ExactCheckpointTargetManifestBasis {
                configuration: source_manifest.configuration,
                node: &node,
                counter: source_target.counter,
                scheduler_time: VirtualTime {
                    ticks: source_target.scheduler_time,
                },
                snapshot: source_identity,
                fault_identity,
                overlay: source_target.overlay.identity,
                vmstate: source_target.vmstate.identity,
            });
        if source_target.manifest_identity != expected_source_manifest {
            return Err(loop_factory_error(format!(
                "production replay-oracle source target `{}` failed manifest authentication",
                source_target.node
            )));
        }
        drop(source_snapshot);

        let promoted_snapshot = read_portable_snapshot(
            promoted,
            promoted_target.snapshot,
            limits.fat_checkpoint_bytes,
            boundary,
        )?;
        let promoted_identity = promoted_snapshot.id();
        let expected_promoted_manifest =
            exact_checkpoint_target_manifest_identity(ExactCheckpointTargetManifestBasis {
                configuration: promoted_manifest.configuration,
                node: &node,
                counter: promoted_target.counter,
                scheduler_time: VirtualTime {
                    ticks: promoted_target.scheduler_time,
                },
                snapshot: promoted_identity,
                fault_identity,
                overlay: promoted_target.overlay.identity,
                vmstate: promoted_target.vmstate.identity,
            });
        if promoted_target.manifest_identity != expected_promoted_manifest
            || !matches!(
                promoted_snapshot.replay_oracle_validation(),
                QemuReplayOracleValidation::Match { .. }
            )
            || promoted_snapshot
                .replay_oracle_source_identity()
                .map_err(|error| {
                    loop_factory_error(format!(
                        "derive production replay-oracle source for `{}`: {error}",
                        promoted_target.node
                    ))
                })?
                != source_identity
        {
            return Err(loop_factory_error(format!(
                "production target `{}` is not an exact replay-oracle promotion",
                source_target.node
            )));
        }
    }
    boundary()?;
    Ok(())
}

pub(super) fn read_portable_snapshot(
    closure: &dyn ProductionExactCheckpointSource,
    identity: ContentHash,
    limit: u64,
    boundary: &mut dyn FnMut() -> Result<(), LifecycleApiError>,
) -> Result<ExactSnapshotHandle, LifecycleApiError> {
    let bytes = read_portable_object(closure, identity, limit, "target snapshot", boundary)?;
    boundary()?;
    ExactSnapshotHandle::from_canonical_bytes_with_limit(&bytes, limit).map_err(|error| {
        loop_factory_error(format!(
            "decode production replay-oracle snapshot {}: {error}",
            identity.to_hex()
        ))
    })
}

pub(super) fn read_portable_fault_checkpoint_identity(
    closure: &dyn ProductionExactCheckpointSource,
    identity: ContentHash,
    source: &ScenarioDefForm,
    boundary: &mut dyn FnMut() -> Result<(), LifecycleApiError>,
) -> Result<ContentHash, LifecycleApiError> {
    let limit = source
        .plan()
        .fault_signals()
        .resource_limits()
        .fat_checkpoint_bytes;
    let bytes = read_portable_object(closure, identity, limit, "fault checkpoint", boundary)?;
    boundary()?;
    ProductionFaultRuntimeCheckpoint::from_canonical_bytes(
        &bytes,
        source.plan().fault_signals(),
        source.scenario_def().id(),
    )
    .map(|checkpoint| checkpoint.id())
    .map_err(|error| {
        loop_factory_error(format!(
            "decode production fault checkpoint {}: {error}",
            identity.to_hex()
        ))
    })
}

fn read_portable_object(
    closure: &dyn ProductionExactCheckpointSource,
    identity: ContentHash,
    limit: u64,
    role: &str,
    boundary: &mut dyn FnMut() -> Result<(), LifecycleApiError>,
) -> Result<Vec<u8>, LifecycleApiError> {
    boundary()?;
    let object = closure
        .objects()
        .binary_search_by_key(&identity, |object| object.identity())
        .ok()
        .and_then(|index| closure.objects().get(index))
        .ok_or_else(|| loop_factory_error("production target snapshot is absent from closure"))?;
    if object.length() > limit {
        return Err(loop_factory_error(format!(
            "production {role} exceeds its authored byte limit {limit}"
        )));
    }
    let length = usize::try_from(object.length()).map_err(|_| {
        loop_factory_error("production target snapshot length is not representable")
    })?;
    let mut destination = ExactObjectBuffer::new(length)?;
    let copied = closure.copy_object_to(identity, &mut destination)?;
    if copied != object.length()
        || destination.bytes().len() != length
        || ContentHash::from_bytes(destination.bytes()) != identity
    {
        return Err(loop_factory_error(
            "production target snapshot failed streaming authentication",
        ));
    }
    Ok(destination.bytes)
}

struct ExactObjectBuffer {
    bytes: Vec<u8>,
    expected: usize,
}

impl ExactObjectBuffer {
    fn new(expected: usize) -> Result<Self, LifecycleApiError> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(expected)
            .map_err(|error| loop_factory_error(format!("reserve snapshot object: {error}")))?;
        Ok(Self { bytes, expected })
    }

    fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Write for ExactObjectBuffer {
    fn write(&mut self, buffer: &[u8]) -> Result<usize, std::io::Error> {
        let next = self
            .bytes
            .len()
            .checked_add(buffer.len())
            .ok_or_else(|| std::io::Error::other("snapshot object length overflow"))?;
        if next > self.expected {
            return Err(std::io::Error::other(
                "snapshot object grew beyond its authenticated length",
            ));
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> Result<(), std::io::Error> {
        Ok(())
    }
}

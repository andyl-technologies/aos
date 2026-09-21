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
/// canonical `crucible.production-exact-closure.v9` body, and its object list
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

/// Random-access catalog of modeled snapshots in one authenticated closure.
///
/// The catalog shares the immutable closure through an [`Arc`] and retains
/// only the bounded node-to-snapshot identity map. Opening one node
/// authenticates and decodes only that modeled snapshot body. The catalog does
/// not expose root-overlay, RAM, device-state, or object-stream capabilities.
#[derive(Clone)]
pub struct ProductionBakedSnapshotCatalog {
    closure: Arc<ProductionExactCheckpointClosure>,
    snapshots: BTreeMap<NodeId, ContentHash>,
    snapshot_limit: u64,
}

impl ProductionBakedSnapshotCatalog {
    /// Returns the number of modeled node snapshots in the catalog.
    #[must_use]
    pub fn len(&self) -> usize {
        self.snapshots.len()
    }

    /// Reports whether the catalog contains no modeled node snapshots.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.snapshots.is_empty()
    }

    /// Returns the ordered modeled node set without opening snapshot bodies.
    pub fn nodes(&self) -> impl ExactSizeIterator<Item = &NodeId> {
        self.snapshots.keys()
    }

    /// Opens and authenticates one modeled snapshot under an operational boundary.
    ///
    /// This is the sole baked-genesis input required by the independent fresh
    /// replay leg. It does not expose VMState, RAM, or root-overlay streams.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] when `node` is absent, its snapshot is
    /// unavailable, corrupt, or outside the configured byte bound, or
    /// `boundary` stops the bounded read.
    pub fn open_snapshot(
        &self,
        node: &NodeId,
        boundary: &mut dyn FnMut() -> Result<(), LifecycleApiError>,
    ) -> Result<crucible_qemu::QemuVmSnapshot, LifecycleApiError> {
        let snapshot = self.snapshots.get(node).ok_or_else(|| {
            loop_factory_error(format!(
                "production baked snapshot catalog has no snapshot for `{}`",
                node.name
            ))
        })?;
        read_portable_snapshot(
            self.closure.as_ref(),
            *snapshot,
            self.snapshot_limit,
            boundary,
        )
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
}

/// No-write production promotion carrying source-bound replay evidence.
///
/// Snapshot bytes remain ordinary runtime state and never carry validation
/// authority. This opaque value keeps the authenticated raw closure unchanged
/// and binds one concrete replay comparison result to every target. The
/// campaign exact-store owner persists that evidence in a distinct root whose
/// source child names the raw root.
pub struct PreparedProductionReplayOraclePromotion {
    pub(super) source: ContentHash,
    pub(super) raw: ProductionExactCheckpointClosure,
    pub(super) evidence: Vec<u8>,
    pub(super) target_count: usize,
}

impl std::fmt::Debug for PreparedProductionReplayOraclePromotion {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedProductionReplayOraclePromotion")
            .field("source", &self.source)
            .field("target_count", &self.target_count)
            .finish_non_exhaustive()
    }
}

impl PreparedProductionReplayOraclePromotion {
    /// Returns the authenticated source production-closure identity that was compared.
    #[must_use]
    pub const fn source(&self) -> ContentHash {
        self.source
    }

    /// Returns the unchanged production closure identity bound by the promotion.
    #[must_use]
    pub const fn promoted(&self) -> ContentHash {
        self.source
    }

    /// Returns canonical source-bound evidence for the exact-store root.
    #[must_use]
    pub fn evidence(&self) -> &[u8] {
        &self.evidence
    }

    /// Returns opaque authority to retire the attempt-local native source catalog.
    ///
    /// The caller may exercise this only after the promoted campaign-CAS root
    /// is durable or after the owning publication phase has been abandoned.
    #[must_use]
    pub fn native_retirement(&self) -> ProductionExactCheckpointRetirement {
        self.raw.native_retirement()
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

    /// Returns the canonical version-nine production closure manifest bytes.
    #[must_use]
    pub fn manifest(&self) -> &[u8] {
        &self.manifest
    }

    /// Returns the exact sorted and deduplicated immutable object inventory.
    #[must_use]
    pub fn objects(&self) -> &[ProductionExactCheckpointObject] {
        &self.objects
    }

    /// Returns opaque authority to retire this attempt-local native catalog.
    ///
    /// Reading the closure remains valid until the returned authority is
    /// exercised. The retirement operation requires exclusive lifecycle-store
    /// ownership and is intended for the executor publication owner after QEMU
    /// teardown, not for ordinary replay consumers.
    #[must_use]
    pub fn native_retirement(&self) -> ProductionExactCheckpointRetirement {
        ProductionExactCheckpointRetirement::new(self.run_state_root.clone(), self.scenario)
    }

    /// Builds a modeled-snapshot catalog under an operational boundary callback.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] when the closure is incomplete, corrupt,
    /// semantically inconsistent, outside its authored bounds, repeats one
    /// live-node identity, or `boundary` stops validation.
    pub fn baked_snapshot_catalog_with_boundary(
        self: &Arc<Self>,
        boundary: &mut dyn FnMut() -> Result<(), LifecycleApiError>,
    ) -> Result<ProductionBakedSnapshotCatalog, LifecycleApiError> {
        self.validate_complete_with_boundary(boundary)?;
        let limits = self.source.plan().fault_signals().resource_limits();
        let manifest = decode::decode_manifest_with_limits(self.manifest(), limits)?;
        let mut snapshots = BTreeMap::new();
        for target in manifest.targets {
            let node = NodeId {
                name: target.node.into_string(),
            };
            if snapshots.insert(node.clone(), target.snapshot).is_some() {
                return Err(loop_factory_error(format!(
                    "production baked snapshot catalog repeats node `{}`",
                    node.name
                )));
            }
        }
        boundary()?;
        Ok(ProductionBakedSnapshotCatalog {
            closure: Arc::clone(self),
            snapshots,
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

    /// Reconstructs the modeled resume basis under an operational boundary.
    ///
    /// This applies the same complete scenario-aware validator used by
    /// [`Self::validate_complete`] and retains only its exact configuration and
    /// scheduler continuation. It performs no closure publication and grants
    /// no QEMU launch authority.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] when a closure object is unavailable,
    /// corrupt, semantically inconsistent, or outside the authored bounds, or
    /// when `boundary` rejects an operational chunk boundary.
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
        };
        boundary()?;
        Ok(basis)
    }

    /// Prepares a source-bound replay-oracle replacement without writes.
    ///
    /// `matches` must contain exactly one result for every live target in this
    /// closure and no result for a permanently failed node. The raw closure is
    /// completely reauthenticated before each check promotes its exact
    /// snapshot. The returned opaque preparation retains the closure unchanged
    /// and carries the source-bound comparison certificate separately.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] when this closure is invalid or already
    /// promoted, the check set is incomplete or contains a foreign node, a
    /// check belongs to another snapshot, a comparison was not a match, or the
    /// replacement cannot be encoded within the authored checkpoint bounds.
    ///
    /// The callback runs throughout complete source validation and between
    /// every bounded snapshot decode, promotion, and canonical encode.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] when this closure is invalid or already
    /// promoted, the check set is incomplete or contains a foreign node, a
    /// check belongs to another snapshot, a comparison was not a match, the
    /// replacement exceeds its authored bounds, or `boundary` fails.
    pub fn prepare_replay_oracle_promotion_with_boundary(
        &self,
        repository_root: crucible_campaign::ExactCheckpointId,
        matches: BTreeMap<NodeId, QemuReplayOracleMatch>,
        boundary: &mut dyn FnMut() -> Result<(), LifecycleApiError>,
    ) -> Result<PreparedProductionReplayOraclePromotion, LifecycleApiError> {
        self.validate_complete_with_boundary(boundary)?;
        prepare_production_replay_oracle_promotion_source(self, repository_root, matches, boundary)
    }
}

const REPLAY_ORACLE_EVIDENCE_MAGIC: &[u8] = b"crucible.production-replay-oracle.v1\0";

fn prepare_production_replay_oracle_promotion_source(
    raw: &ProductionExactCheckpointClosure,
    repository_root: crucible_campaign::ExactCheckpointId,
    mut matches: BTreeMap<NodeId, QemuReplayOracleMatch>,
    boundary: &mut dyn FnMut() -> Result<(), LifecycleApiError>,
) -> Result<PreparedProductionReplayOraclePromotion, LifecycleApiError> {
    boundary()?;
    let limits = raw.source.plan().fault_signals().resource_limits();
    let manifest = decode::decode_manifest_with_limits(raw.manifest(), limits)?;
    if matches.len() != manifest.targets.len() {
        return Err(loop_factory_error(
            "production replay-oracle match set does not match the live target set",
        ));
    }

    let mut evidence = Vec::new();
    evidence.extend_from_slice(REPLAY_ORACLE_EVIDENCE_MAGIC);
    evidence.extend_from_slice(&raw.identity.bytes);
    evidence.extend_from_slice(
        &u32::try_from(manifest.targets.len())
            .map_err(|_| loop_factory_error("replay-oracle target count is not representable"))?
            .to_be_bytes(),
    );
    for target in &manifest.targets {
        boundary()?;
        let node = NodeId {
            name: target.node.to_string(),
        };
        let matched = matches.remove(&node).ok_or_else(|| {
            loop_factory_error(format!(
                "production replay-oracle match is absent for `{}`",
                target.node
            ))
        })?;
        let snapshot =
            read_portable_snapshot(raw, target.snapshot, limits.fat_checkpoint_bytes, boundary)?;
        let runtime_hash = matched
            .into_authenticated_source(
                repository_root,
                raw.identity,
                target.manifest_identity,
                &node,
                &snapshot,
            )
            .map_err(|error| {
                loop_factory_error(format!(
                    "authenticate production replay-oracle snapshot for `{}`: {error}",
                    target.node
                ))
            })?;
        append_replay_oracle_evidence_entry(
            &mut evidence,
            target.node.as_str(),
            target.snapshot,
            target.manifest_identity,
            runtime_hash,
        )?;
    }
    Ok(PreparedProductionReplayOraclePromotion {
        source: raw.identity,
        raw: raw.clone(),
        evidence,
        target_count: manifest.targets.len(),
    })
}

fn append_replay_oracle_evidence_entry(
    evidence: &mut Vec<u8>,
    node: &str,
    snapshot: ContentHash,
    target_manifest: ContentHash,
    runtime: ContentHash,
) -> Result<(), LifecycleApiError> {
    let node = node.as_bytes();
    evidence.extend_from_slice(
        &u32::try_from(node.len())
            .map_err(|_| loop_factory_error("replay-oracle node name is too long"))?
            .to_be_bytes(),
    );
    evidence.extend_from_slice(node);
    evidence.extend_from_slice(&snapshot.bytes);
    evidence.extend_from_slice(&target_manifest.bytes);
    evidence.extend_from_slice(&runtime.bytes);
    Ok(())
}

pub(super) fn read_portable_snapshot(
    closure: &ProductionExactCheckpointClosure,
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

pub(super) fn read_portable_object(
    closure: &ProductionExactCheckpointClosure,
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
    let mut source = closure.open_object(identity)?;
    boundary()?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|error| loop_factory_error(format!("reserve snapshot object: {error}")))?;
    bytes.resize(length, 0);
    boundary()?;
    for chunk in bytes.chunks_mut(super::io::MAX_BOUNDED_READ_CHUNK_BYTES) {
        boundary()?;
        source.read_exact(chunk).map_err(|error| {
            loop_factory_error(format!(
                "read production {role} {}: {error}",
                identity.to_hex()
            ))
        })?;
    }
    boundary()?;
    let mut trailing = [0_u8; 1];
    if source.read(&mut trailing).map_err(|error| {
        loop_factory_error(format!(
            "authenticate production {role} EOF {}: {error}",
            identity.to_hex()
        ))
    })? != 0
    {
        return Err(loop_factory_error(format!(
            "production {role} {} grew beyond its authenticated length",
            identity.to_hex()
        )));
    }
    boundary()?;
    if bytes.len() != length || ContentHash::from_bytes(&bytes) != identity {
        return Err(loop_factory_error(
            "production target snapshot failed streaming authentication",
        ));
    }
    Ok(bytes)
}

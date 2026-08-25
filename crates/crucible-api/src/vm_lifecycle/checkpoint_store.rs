//! Durable content-addressed closure store for exact production checkpoints.

use super::*;
use crucible::LocalDagStore;
use crucible::model::FaultResourceLimits;
use std::collections::BTreeSet;
use std::io::{Read, Seek, SeekFrom, Write};

mod decode;
mod io;
use io::{BoundedReadError, read_bounded_file_with_boundary};
mod paths;
use paths::{closure_parent, object_parent};
mod portable;
pub use portable::{
    ProductionExactCheckpointSource,
    authenticate_portable_exact_checkpoint_replay_oracle_promotion,
    authenticate_portable_exact_checkpoint_replay_oracle_promotion_with_boundary,
    install_exact_checkpoint_closure, install_exact_checkpoint_closure_with_boundary,
    install_exact_checkpoint_closure_with_boundary_and_admission,
};
mod publication;
pub(super) use publication::{PersistExactCheckpointError, PreparedExactCheckpointPublication};
use publication::{enforce_published_checkpoint_count, scheduler_resource_limit};
mod read_budget;
use read_budget::CheckpointReadBudget;
mod recovery;
pub(super) use recovery::{
    reconcile_indeterminate_publication, recover_published_checkpoint_catalog,
};

const MANIFEST_MAGIC: &[u8] = b"crucible.production-exact-closure.v4\0";
const MANIFEST_FILE: &str = "manifest.cbor";
const MAX_MANIFEST_BYTES: usize = 64 * 1024 * 1024;
const MAX_MANIFEST_BYTES_U64: u64 = 64 * 1024 * 1024;
const ARTIFACT_CHUNK_BYTES: usize = 4 * 1024 * 1024;
const ARTIFACT_CHUNK_BYTES_U64: u64 = 4 * 1024 * 1024;
const SPARSE_COPY_BUFFER_BYTES: usize = 1024 * 1024;
const CLOSURE_EXPORT_COPY_BUFFER_BYTES: usize = 1024 * 1024;
const SMALL_CONTINUATION_MAX_BYTES: u64 = 268_435_456;
const LARGE_CONTINUATION_MAX_BYTES: u64 = 1_610_612_800;

/// One immutable object in a portable production exact-checkpoint closure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProductionExactCheckpointObject {
    identity: ContentHash,
    length: u64,
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
/// canonical `crucible.production-exact-closure.v4` body, and its object list
/// is the exact deduplicated set named by that manifest. Large overlay and
/// VMState artifacts remain represented by their bounded content-addressed
/// chunks rather than by RAM-sized buffers.
#[derive(Clone)]
pub struct ProductionExactCheckpointClosure {
    identity: ContentHash,
    scenario: ContentHash,
    configuration: ContentHash,
    manifest: Vec<u8>,
    run_state_root: PathBuf,
    source: ScenarioDefForm,
    object_directory: PathBuf,
    objects: Vec<ProductionExactCheckpointObject>,
}

/// Authenticated modeled continuation recovered from one production closure.
///
/// The value contains no filesystem or QEMU launch authority. It is the exact
/// configuration and scheduler continuation established by the complete
/// scenario-aware restore validator and is suitable for binding an operational
/// resume request before any guest process is launched.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductionExactCheckpointResumeBasis {
    identity: ContentHash,
    configuration: Configuration,
    scheduler: SingleSchedulerCheckpoint,
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
    source: ContentHash,
    promoted: ContentHash,
    scenario: ContentHash,
    configuration: ContentHash,
    manifest: Vec<u8>,
    objects: Vec<ProductionExactCheckpointObject>,
    raw: ProductionExactCheckpointClosure,
    promoted_snapshots: BTreeMap<ContentHash, PreparedPromotedSnapshot>,
    fat_checkpoint_bytes: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct PreparedPromotedSnapshot {
    raw_object: ContentHash,
    check: QemuReplayOracleCheck,
    length: u64,
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

fn validate_replay_oracle_manifest_basis(
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

fn authenticate_replay_oracle_source_pair(
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

fn read_portable_snapshot(
    closure: &dyn ProductionExactCheckpointSource,
    identity: ContentHash,
    limit: u64,
    boundary: &mut dyn FnMut() -> Result<(), LifecycleApiError>,
) -> Result<QemuVmSnapshot, LifecycleApiError> {
    let bytes = read_portable_object(closure, identity, limit, "target snapshot", boundary)?;
    boundary()?;
    QemuVmSnapshot::from_canonical_bytes_with_limit(&bytes, limit).map_err(|error| {
        loop_factory_error(format!(
            "decode production replay-oracle snapshot {}: {error}",
            identity.to_hex()
        ))
    })
}

fn read_portable_fault_checkpoint_identity(
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

#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ClosureManifest {
    scenario: ContentHash,
    configuration: ContentHash,
    schedule: ContentHash,
    frontier: u64,
    scheduler: ContentHash,
    #[serde(deserialize_with = "decode::deserialize_vec")]
    event_log_segments: Vec<ContentHash>,
    #[serde(deserialize_with = "decode::deserialize_vec")]
    signal_artifacts: Vec<ContentHash>,
    trigger_state: ContentHash,
    assertion_state: ContentHash,
    lifecycle_state: ContentHash,
    fault_checkpoint: ContentHash,
    #[serde(deserialize_with = "decode::deserialize_vec")]
    targets: Vec<TargetManifest>,
    #[serde(deserialize_with = "decode::deserialize_vec")]
    node_generations: Vec<(String, u64)>,
    #[serde(deserialize_with = "decode::deserialize_vec")]
    node_service_states: Vec<(String, u8)>,
    identity: ContentHash,
}

#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetManifest {
    node: String,
    counter: u64,
    scheduler_time: u64,
    snapshot: ContentHash,
    overlay: ArtifactManifest,
    vmstate: ArtifactManifest,
    manifest_identity: ContentHash,
}

#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactManifest {
    identity: ContentHash,
    length: u64,
    #[serde(deserialize_with = "decode::deserialize_vec")]
    chunks: Vec<ContentHash>,
}

struct ClosureObjects {
    schedule: Vec<u8>,
    scheduler: Vec<u8>,
    event_log_segments: BTreeMap<ContentHash, Vec<u8>>,
    signal_artifacts: BTreeMap<ContentHash, Vec<u8>>,
    trigger_state: Vec<u8>,
    assertion_state: Vec<u8>,
    lifecycle_state: Vec<u8>,
    fault_checkpoint: Vec<u8>,
    snapshots: BTreeMap<NodeId, Vec<u8>>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct LifecycleWire {
    terminal: Option<TerminalWire>,
    terminal_cause: Option<TerminalCauseWire>,
    initial_lifecycle_observations_pending: bool,
    branch: Option<BranchWire>,
    #[serde(deserialize_with = "decode::deserialize_vec")]
    recorded_controls: Vec<RecordedControlWire>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum TerminalWire {
    Passed,
    Failed(#[serde(deserialize_with = "decode::deserialize_vec")] Vec<String>),
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum TerminalCauseWire {
    Passed,
    Failed(#[serde(deserialize_with = "decode::deserialize_vec")] Vec<String>),
    BudgetExhausted,
    BackendCrash(String),
    OperatorStop,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BranchWire {
    #[serde(deserialize_with = "decode::deserialize_vec")]
    base_schedule: Vec<u8>,
    frontier: u64,
    #[serde(deserialize_with = "decode::deserialize_vec")]
    decisions: Vec<Decision>,
    seed: Option<[u8; 32]>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordedControlWire {
    #[serde(deserialize_with = "decode::deserialize_vec")]
    configuration_schedule: Vec<u8>,
    #[serde(deserialize_with = "decode::deserialize_vec")]
    node_times: Vec<(String, u64)>,
    #[serde(deserialize_with = "decode::deserialize_vec")]
    control: Vec<ControlOperation>,
}

#[cfg(test)]
pub(super) fn prepare_exact_checkpoint_set(
    run_state_root: &Path,
    scenario: ContentHash,
    resource_limits: FaultResourceLimits,
    checkpoint: &mut ProductionVmExactCheckpointSet,
) -> Result<PreparedExactCheckpointPublication, PersistExactCheckpointError> {
    prepare_exact_checkpoint_set_with_boundary(
        run_state_root,
        scenario,
        resource_limits,
        checkpoint,
        &mut || Ok(()),
    )
}

pub(super) fn prepare_exact_checkpoint_set_with_boundary(
    run_state_root: &Path,
    scenario: ContentHash,
    resource_limits: FaultResourceLimits,
    checkpoint: &mut ProductionVmExactCheckpointSet,
    boundary: &mut dyn FnMut() -> Result<(), SchedulerError>,
) -> Result<PreparedExactCheckpointPublication, PersistExactCheckpointError> {
    boundary()?;
    validate_checkpoint_set(scenario, checkpoint)?;
    boundary()?;
    let (mut manifest, objects) =
        manifest_and_objects_with_boundary(scenario, resource_limits, checkpoint, boundary)?;
    boundary()?;
    manifest.identity = closure_identity(&manifest)?;
    checkpoint.identity = manifest.identity;
    let manifest_bytes = encode_manifest(&manifest)?;
    enforce_persist_limits(
        run_state_root,
        scenario,
        resource_limits,
        &manifest,
        &objects,
        checkpoint,
        manifest_bytes.len(),
    )?;
    boundary()?;

    let scenario_directory = run_state_root.join(scenario.to_hex());
    fs::create_dir_all(&scenario_directory).map_err(|error| {
        store_error(format!(
            "create exact checkpoint scenario directory {}: {error}",
            scenario_directory.display()
        ))
    })?;
    sync_directory(run_state_root)?;
    let closure_parent = scenario_directory.join("checkpoint-closures");
    let object_directory = scenario_directory.join("checkpoint-objects");
    fs::create_dir_all(&closure_parent).map_err(|error| {
        store_error(format!(
            "create exact checkpoint closure directory {}: {error}",
            closure_parent.display()
        ))
    })?;
    fs::create_dir_all(&object_directory).map_err(|error| {
        store_error(format!(
            "create exact checkpoint object directory {}: {error}",
            object_directory.display()
        ))
    })?;
    sync_directory(&scenario_directory)?;
    let destination = closure_parent.join(manifest.identity.to_hex());
    if destination.exists() {
        boundary()?;
        authenticate_existing_publication_with_boundary(
            &destination,
            &object_directory,
            &manifest,
            &objects,
            checkpoint,
            boundary,
        )
        .map_err(|source| PersistExactCheckpointError::Indeterminate {
            identity: manifest.identity,
            source,
        })?;
        enforce_published_checkpoint_count(&closure_parent, resource_limits).map_err(|source| {
            PersistExactCheckpointError::Indeterminate {
                identity: manifest.identity,
                source,
            }
        })?;
        install_persisted_artifact_paths(&object_directory, &manifest, checkpoint).map_err(
            |source| PersistExactCheckpointError::Indeterminate {
                identity: manifest.identity,
                source,
            },
        )?;
        boundary()?;
        return Ok(PreparedExactCheckpointPublication::Existing {
            identity: manifest.identity,
            closure_parent,
        });
    }
    let staging = tempfile::Builder::new()
        .prefix(".closure-")
        .tempdir_in(&closure_parent)
        .map_err(|error| {
            store_error(format!(
                "create exact checkpoint closure staging directory: {error}"
            ))
        })?;
    persist_object_with_boundary(
        &object_directory,
        manifest.schedule,
        &objects.schedule,
        boundary,
    )?;
    persist_object_with_boundary(
        &object_directory,
        manifest.scheduler,
        &objects.scheduler,
        boundary,
    )?;
    let checkpoint_dag = checkpoint_dag_store(run_state_root, scenario);
    for (identity, bytes) in objects
        .event_log_segments
        .iter()
        .chain(objects.signal_artifacts.iter())
    {
        boundary()?;
        persist_object_with_boundary(&object_directory, *identity, bytes, boundary)?;
        let stored = checkpoint_dag
            .put(bytes)
            .map_err(|error| store_error(format!("persist checkpoint DAG object: {error}")))?;
        if stored != *identity {
            return Err(PersistExactCheckpointError::Unpublished(store_error(
                "checkpoint DAG returned a different content identity",
            )));
        }
    }
    persist_object_with_boundary(
        &object_directory,
        manifest.trigger_state,
        &objects.trigger_state,
        boundary,
    )?;
    persist_object_with_boundary(
        &object_directory,
        manifest.assertion_state,
        &objects.assertion_state,
        boundary,
    )?;
    persist_object_with_boundary(
        &object_directory,
        manifest.lifecycle_state,
        &objects.lifecycle_state,
        boundary,
    )?;
    persist_object_with_boundary(
        &object_directory,
        manifest.fault_checkpoint,
        &objects.fault_checkpoint,
        boundary,
    )?;
    for target in &manifest.targets {
        boundary()?;
        let node = NodeId {
            name: target.node.clone(),
        };
        let snapshot = objects
            .snapshots
            .get(&node)
            .ok_or_else(|| store_error("closure snapshot object disappeared"))?;
        persist_object_with_boundary(&object_directory, target.snapshot, snapshot, boundary)?;
        let source = checkpoint
            .targets
            .get(&node)
            .ok_or_else(|| store_error("closure target disappeared"))?;
        persist_chunked_artifact_with_boundary(
            &object_directory,
            &target.overlay,
            &source.overlay_artifact,
            boundary,
        )?;
        persist_chunked_artifact_with_boundary(
            &object_directory,
            &target.vmstate,
            &source.vmstate_artifact,
            boundary,
        )?;
    }
    boundary()?;
    sync_directory(&object_directory)?;

    persist_file_bytes_with_boundary(
        &staging.path().join(MANIFEST_FILE),
        &manifest_bytes,
        boundary,
    )?;
    sync_directory(staging.path())?;
    install_persisted_artifact_paths(&object_directory, &manifest, checkpoint)?;
    Ok(PreparedExactCheckpointPublication::Staged {
        identity: manifest.identity,
        staging,
        destination,
        closure_parent,
        resource_limits: Box::new(resource_limits),
    })
}

pub(super) fn load_exact_checkpoint_set(
    run_state_root: &Path,
    scenario: &ScenarioDef,
    source: &ScenarioDefForm,
    identity: ContentHash,
) -> Result<ProductionVmExactCheckpointSet, LifecycleApiError> {
    load_exact_checkpoint_set_with_boundary(run_state_root, scenario, source, identity, &mut || {
        Ok(())
    })
}

fn load_exact_checkpoint_set_with_boundary(
    run_state_root: &Path,
    scenario: &ScenarioDef,
    source: &ScenarioDefForm,
    identity: ContentHash,
    boundary: &mut dyn FnMut() -> Result<(), LifecycleApiError>,
) -> Result<ProductionVmExactCheckpointSet, LifecycleApiError> {
    boundary()?;
    let root = closure_parent(run_state_root, scenario.id()).join(identity.to_hex());
    let object_directory = object_parent(run_state_root, scenario.id());
    let limits = source.plan().fault_signals().resource_limits();
    let mut budget = CheckpointReadBudget::new(limits.fat_checkpoint_bytes);
    let manifest_path = root.join(MANIFEST_FILE);
    let manifest_length = fs::metadata(&manifest_path)
        .map_err(|error| {
            loop_factory_error(format!(
                "inspect exact checkpoint closure {}: {error}",
                identity.to_hex()
            ))
        })?
        .len();
    if manifest_length > MAX_MANIFEST_BYTES_U64 {
        return Err(loop_factory_error(format!(
            "exact checkpoint manifest exceeds its role-specific byte limit {MAX_MANIFEST_BYTES_U64}"
        )));
    }
    let manifest_bytes = budget.read_admitted(manifest_length, || {
        read_bounded_file_with_boundary(&manifest_path, manifest_length, boundary)
    })?;
    boundary()?;
    let manifest = decode::decode_manifest_with_limits(&manifest_bytes, limits)?;
    if manifest.identity != identity
        || manifest.identity
            != closure_identity(&manifest).map_err(|error| loop_factory_error(error.to_string()))?
        || manifest.scenario != scenario.id()
    {
        return Err(loop_factory_error(
            "exact checkpoint closure failed identity authentication",
        ));
    }

    let schedule = Schedule::from_compact_binary(&read_object(
        &object_directory,
        manifest.schedule,
        &mut budget,
        SMALL_CONTINUATION_MAX_BYTES,
        boundary,
    )?)
    .map_err(|error| loop_factory_error(format!("decode checkpoint schedule: {error}")))?;
    let configuration = Configuration {
        def: scenario.clone(),
        schedule,
    };
    if configuration.id() != manifest.configuration {
        return Err(loop_factory_error(
            "exact checkpoint closure configuration does not authenticate",
        ));
    }
    boundary()?;
    let scheduler = SingleSchedulerCheckpoint::from_canonical_bytes(&read_object(
        &object_directory,
        manifest.scheduler,
        &mut budget,
        LARGE_CONTINUATION_MAX_BYTES,
        boundary,
    )?)
    .map_err(|error| loop_factory_error(format!("decode scheduler continuation: {error}")))?;
    if scheduler.configuration_for(scenario).map_err(|error| {
        loop_factory_error(format!("authenticate scheduler configuration: {error}"))
    })? != configuration
        || scheduler.frontier().ticks != manifest.frontier
    {
        return Err(loop_factory_error(
            "exact checkpoint scheduler continuation does not match its manifest",
        ));
    }
    if scheduler.event_log_segment_dependencies() != manifest.event_log_segments {
        return Err(loop_factory_error(
            "exact checkpoint event-log dependencies do not match the scheduler continuation",
        ));
    }
    let mut event_log_objects = BTreeMap::new();
    for identity in &manifest.event_log_segments {
        boundary()?;
        let bytes = read_object(
            &object_directory,
            *identity,
            &mut budget,
            LARGE_CONTINUATION_MAX_BYTES,
            boundary,
        )?;
        if event_log_objects.insert(*identity, bytes).is_some() {
            return Err(loop_factory_error(
                "exact checkpoint contains duplicate event-log segment identities",
            ));
        }
    }
    let mut signal_artifact_objects = BTreeMap::new();
    for identity in &manifest.signal_artifacts {
        boundary()?;
        let bytes = read_object(
            &object_directory,
            *identity,
            &mut budget,
            LARGE_CONTINUATION_MAX_BYTES,
            boundary,
        )?;
        if signal_artifact_objects.insert(*identity, bytes).is_some() {
            return Err(loop_factory_error(
                "exact checkpoint contains duplicate signal artifact identities",
            ));
        }
    }
    let checkpoint_dag = checkpoint_dag_store(run_state_root, scenario.id());
    for (identity, bytes) in event_log_objects
        .iter()
        .chain(signal_artifact_objects.iter())
    {
        boundary()?;
        let stored = checkpoint_dag.put(bytes).map_err(|error| {
            loop_factory_error(format!("reconstruct checkpoint DAG object: {error}"))
        })?;
        if stored != *identity {
            return Err(loop_factory_error(
                "checkpoint DAG reconstructed a different content identity",
            ));
        }
    }
    let trigger_state = EventGraphState::from_compact_binary(&read_object(
        &object_directory,
        manifest.trigger_state,
        &mut budget,
        SMALL_CONTINUATION_MAX_BYTES,
        boundary,
    )?)
    .map_err(|error| loop_factory_error(format!("decode trigger continuation: {error}")))?;
    let assertion_state = HostAssertionEvaluatorCheckpoint::from_canonical_bytes(&read_object(
        &object_directory,
        manifest.assertion_state,
        &mut budget,
        SMALL_CONTINUATION_MAX_BYTES,
        boundary,
    )?)
    .map_err(|error| loop_factory_error(format!("decode assertion continuation: {error}")))?;
    let lifecycle = decode_lifecycle(
        &read_object(
            &object_directory,
            manifest.lifecycle_state,
            &mut budget,
            SMALL_CONTINUATION_MAX_BYTES,
            boundary,
        )?,
        scenario,
        limits,
    )?;
    let signal_plan = source.plan().fault_signals();
    let expected_signal_artifacts =
        collect_signal_artifact_objects(signal_plan, checkpoint_dag.as_ref())?;
    if expected_signal_artifacts != signal_artifact_objects {
        return Err(loop_factory_error(
            "exact checkpoint signal-artifact closure is incomplete or contains unreferenced objects",
        ));
    }
    let fault_checkpoint = ProductionFaultRuntimeCheckpoint::from_canonical_bytes(
        &read_object(
            &object_directory,
            manifest.fault_checkpoint,
            &mut budget,
            limits.fat_checkpoint_bytes,
            boundary,
        )?,
        signal_plan,
        scenario.id(),
    )
    .map_err(|error| loop_factory_error(format!("decode fault continuation: {error}")))?;

    let mut targets = BTreeMap::new();
    for target in &manifest.targets {
        boundary()?;
        let node = NodeId {
            name: target.node.clone(),
        };
        let snapshot = QemuVmSnapshot::from_canonical_bytes_with_limit(
            &read_object(
                &object_directory,
                target.snapshot,
                &mut budget,
                limits.fat_checkpoint_bytes,
                boundary,
            )?,
            limits.fat_checkpoint_bytes,
        )
        .map_err(|error| {
            loop_factory_error(format!(
                "decode QEMU snapshot for `{}`: {error}",
                target.node
            ))
        })?;
        let restored = ProductionVmExactCheckpointTarget {
            configuration: configuration.clone(),
            counter: target.counter,
            scheduler_time: VirtualTime {
                ticks: target.scheduler_time,
            },
            snapshot,
            overlay_artifact: ProductionCheckpointArtifact {
                source: ProductionCheckpointArtifactSource::ChunkStore(object_directory.clone()),
                identity: target.overlay.identity,
                length: target.overlay.length,
                chunks: target.overlay.chunks.clone(),
            },
            vmstate_artifact: ProductionCheckpointArtifact {
                source: ProductionCheckpointArtifactSource::ChunkStore(object_directory.clone()),
                identity: target.vmstate.identity,
                length: target.vmstate.length,
                chunks: target.vmstate.chunks.clone(),
            },
            manifest_identity: target.manifest_identity,
        };
        budget.reserve_identity_once(
            restored.overlay_artifact.identity,
            restored.overlay_artifact.length,
        )?;
        budget.reserve_identity_once(
            restored.vmstate_artifact.identity,
            restored.vmstate_artifact.length,
        )?;
        validate_exact_checkpoint_target(&node, &restored, fault_checkpoint.id())?;
        if targets.insert(node, restored).is_some() {
            return Err(loop_factory_error(
                "exact checkpoint closure contains duplicate node targets",
            ));
        }
    }
    let node_generations = decode_generations(&manifest.node_generations)?;
    boundary()?;
    let node_service_states = decode_service_states(&manifest.node_service_states)?;
    validate_restored_node_sets(source, &targets, &node_generations, &node_service_states)?;
    let restored = ProductionVmExactCheckpointSet {
        identity,
        configuration,
        scheduler,
        event_log_objects,
        signal_artifact_objects,
        trigger_state,
        assertion_state,
        terminal_verdict: lifecycle.terminal,
        terminal_cause: lifecycle.terminal_cause,
        initial_lifecycle_observations_pending: lifecycle.initial_lifecycle_observations_pending,
        branch: lifecycle.branch,
        recorded_controls: lifecycle.recorded_controls,
        fault_checkpoint: Some(fault_checkpoint),
        targets,
        node_generations,
        node_service_states,
    };
    validate_checkpoint_set(scenario.id(), &restored)
        .map_err(|error| loop_factory_error(error.to_string()))?;
    boundary()?;
    Ok(restored)
}

/// Opens one published production checkpoint as a portable read-only closure.
///
/// This operation authenticates the canonical manifest, its closure identity,
/// scenario binding, exact object names, object types, and aggregate retained
/// bytes without loading large objects into memory. Each object is
/// independently reauthenticated when streamed through
/// [`ProductionExactCheckpointClosure::copy_object_to`].
///
/// # Errors
///
/// Returns [`LifecycleApiError`] when the closure manifest is unavailable,
/// malformed, noncanonical, over its scenario-authored bounds, names another
/// scenario or identity, or any required object is absent or not a regular
/// file.
pub fn open_exact_checkpoint_closure(
    run_state_root: &Path,
    source: &ScenarioDefForm,
    identity: ContentHash,
) -> Result<ProductionExactCheckpointClosure, LifecycleApiError> {
    open_exact_checkpoint_closure_with_boundary(run_state_root, source, identity, &mut || Ok(()))
}

/// Opens one portable closure while observing an operational boundary.
///
/// # Errors
///
/// Returns the same errors as [`open_exact_checkpoint_closure`], including the
/// exact [`LifecycleApiError`] returned by `boundary`.
pub(super) fn open_exact_checkpoint_closure_with_boundary(
    run_state_root: &Path,
    source: &ScenarioDefForm,
    identity: ContentHash,
    boundary: &mut dyn FnMut() -> Result<(), LifecycleApiError>,
) -> Result<ProductionExactCheckpointClosure, LifecycleApiError> {
    boundary()?;
    let scenario = source.scenario_def().id();
    let limits = source.plan().fault_signals().resource_limits();
    let root = closure_parent(run_state_root, scenario).join(identity.to_hex());
    let manifest_path = root.join(MANIFEST_FILE);
    let manifest =
        read_bounded_file_with_boundary(&manifest_path, MAX_MANIFEST_BYTES_U64, boundary).map_err(
            |error| match error {
                BoundedReadError::Boundary(error) => *error,
                error => loop_factory_error(format!(
                    "read portable exact checkpoint manifest {}: {error}",
                    identity.to_hex()
                )),
            },
        )?;
    boundary()?;
    let decoded = decode::decode_manifest_with_limits(&manifest, limits)?;
    if decoded.identity != identity
        || closure_identity(&decoded).map_err(|error| loop_factory_error(error.to_string()))?
            != identity
        || decoded.scenario != scenario
    {
        return Err(loop_factory_error(
            "portable exact checkpoint manifest failed identity or scenario authentication",
        ));
    }

    let object_directory = object_parent(run_state_root, scenario);
    let identities = manifest_object_identities(&decoded);
    let mut total = u64::try_from(manifest.len())
        .map_err(|_| loop_factory_error("checkpoint manifest length is not representable"))?;
    let mut objects = Vec::new();
    objects
        .try_reserve_exact(identities.len())
        .map_err(|_| loop_factory_error("reserve portable checkpoint object inventory"))?;
    for object_identity in identities {
        boundary()?;
        let path = object_path(&object_directory, object_identity);
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            loop_factory_error(format!(
                "inspect portable checkpoint object {}: {error}",
                object_identity.to_hex()
            ))
        })?;
        if !metadata.file_type().is_file() {
            return Err(loop_factory_error(format!(
                "portable checkpoint object {} is not a regular file",
                object_identity.to_hex()
            )));
        }
        let length = metadata.len();
        total = add_checkpoint_bytes(total, length)
            .map_err(|error| loop_factory_error(error.to_string()))?;
        objects.push(ProductionExactCheckpointObject {
            identity: object_identity,
            length,
        });
    }
    limits
        .reserve("fat_checkpoint_bytes", 0, total)
        .map_err(|error| match error {
            crucible::model::FaultResourceLimitError::Exceeded {
                field,
                current,
                requested,
                configured,
                hard,
            }
            | crucible::model::FaultResourceLimitError::UsageOverflow {
                field,
                current,
                requested,
                configured,
                hard,
            } => LifecycleApiError::ResourceLimit(crate::LifecycleResourceLimit {
                field,
                current,
                requested,
                configured,
                hard,
            }),
            error => loop_factory_error(error.to_string()),
        })?;
    boundary()?;

    Ok(ProductionExactCheckpointClosure {
        identity,
        scenario,
        configuration: decoded.configuration,
        manifest,
        run_state_root: run_state_root.to_path_buf(),
        source: source.clone(),
        object_directory,
        objects,
    })
}

fn manifest_object_identities(manifest: &ClosureManifest) -> BTreeSet<ContentHash> {
    let mut identities = BTreeSet::from([
        manifest.schedule,
        manifest.scheduler,
        manifest.trigger_state,
        manifest.assertion_state,
        manifest.lifecycle_state,
        manifest.fault_checkpoint,
    ]);
    identities.extend(manifest.event_log_segments.iter().copied());
    identities.extend(manifest.signal_artifacts.iter().copied());
    for target in &manifest.targets {
        identities.insert(target.snapshot);
        identities.extend(target.overlay.chunks.iter().copied());
        identities.extend(target.vmstate.chunks.iter().copied());
    }
    identities
}

fn validate_checkpoint_set(
    scenario: ContentHash,
    checkpoint: &ProductionVmExactCheckpointSet,
) -> Result<(), SchedulerError> {
    let fault_checkpoint = checkpoint
        .fault_checkpoint
        .as_ref()
        .ok_or_else(|| store_error("exact checkpoint set has no production fault continuation"))?;
    if checkpoint.configuration.def.id() != scenario
        || checkpoint
            .scheduler
            .configuration_for(&checkpoint.configuration.def)
            .map_err(|error| {
                store_error(format!("authenticate scheduler configuration: {error}"))
            })?
            != checkpoint.configuration
    {
        return Err(store_error(
            "exact checkpoint scheduler configuration does not match its scenario",
        ));
    }
    if !terminal_cause_matches_verdict(
        checkpoint.terminal_cause.as_ref(),
        checkpoint.terminal_verdict.as_ref(),
    ) {
        return Err(store_error(
            "exact checkpoint terminal cause disagrees with its trigger verdict",
        ));
    }
    if checkpoint.scheduler.event_log_segment_dependencies().len()
        != checkpoint.event_log_objects.len()
        || checkpoint
            .scheduler
            .event_log_segment_dependencies()
            .iter()
            .any(|identity| !checkpoint.event_log_objects.contains_key(identity))
    {
        return Err(store_error(
            "exact checkpoint event-log closure is incomplete or out of order",
        ));
    }
    for (identity, bytes) in &checkpoint.event_log_objects {
        if ContentHash::from_bytes(bytes) != *identity {
            return Err(store_error(
                "exact checkpoint event-log object failed content authentication",
            ));
        }
    }
    for (identity, bytes) in &checkpoint.signal_artifact_objects {
        if ContentHash::from_bytes(bytes) != *identity {
            return Err(store_error(
                "exact checkpoint signal artifact failed content authentication",
            ));
        }
    }
    match (
        checkpoint.scheduler.branch_frontier_cap(),
        checkpoint.branch.as_ref(),
    ) {
        (None, None) => {}
        (Some(cap), Some(branch))
            if cap == branch.frontier
                && branch.base.def.id() == scenario
                && branch.base == checkpoint.configuration => {}
        _ => {
            return Err(store_error(
                "exact checkpoint active branch disagrees with scheduler continuation",
            ));
        }
    }
    if checkpoint
        .node_generations
        .keys()
        .ne(checkpoint.node_service_states.keys())
        || checkpoint
            .node_generations
            .values()
            .any(|generation| *generation == 0)
        || checkpoint
            .targets
            .keys()
            .any(|node| !checkpoint.node_service_states.contains_key(node))
    {
        return Err(store_error(
            "exact checkpoint node generations and service states are incomplete",
        ));
    }
    for (node, state) in &checkpoint.node_service_states {
        let target = checkpoint.targets.get(node);
        if matches!(state, ProductionNodeServiceState::PermanentlyFailed) != target.is_none() {
            return Err(store_error(format!(
                "exact checkpoint target disagrees with service state for `{}`",
                node.name
            )));
        }
        if let Some(target) = target {
            if target.configuration != checkpoint.configuration {
                return Err(store_error(format!(
                    "exact checkpoint target state disagrees for `{}`",
                    node.name
                )));
            }
            if fault_checkpoint.qemu_fingerprint(node).is_none() {
                return Err(store_error(format!(
                    "exact checkpoint target for `{}` has no paired fault-runtime fingerprint",
                    node.name
                )));
            }
            validate_exact_checkpoint_target(node, target, fault_checkpoint.id())
                .map_err(|error| store_error(error.to_string()))?;
        } else if fault_checkpoint.qemu_fingerprint(node).is_some() {
            return Err(store_error(format!(
                "permanently failed exact-checkpoint node `{}` retains a live fault-runtime fingerprint",
                node.name
            )));
        }
    }
    validate_recorded_controls(checkpoint)?;
    Ok(())
}

fn validate_recorded_controls(
    checkpoint: &ProductionVmExactCheckpointSet,
) -> Result<(), SchedulerError> {
    let current = checkpoint.configuration.schedule.decisions();
    let mut prior_schedule_len = 0_usize;
    let mut prior_sequence = None;
    for record in &checkpoint.recorded_controls {
        let recorded = record.configuration.schedule.decisions();
        if record.configuration.def.id() != checkpoint.configuration.def.id()
            || recorded.len() < prior_schedule_len
            || !current.starts_with(recorded)
            || record.control.is_empty()
            || record
                .node_times
                .keys()
                .any(|node| !checkpoint.node_service_states.contains_key(node))
            || record
                .node_times
                .values()
                .any(|time| *time > checkpoint.scheduler.frontier())
        {
            return Err(store_error(
                "exact checkpoint recorded-control history is inconsistent with its frontier",
            ));
        }
        for control in &record.control {
            if prior_sequence.is_some_and(|sequence| control.sequence <= sequence) {
                return Err(store_error(
                    "exact checkpoint control sequences are not strictly increasing",
                ));
            }
            prior_sequence = Some(control.sequence);
        }
        prior_schedule_len = recorded.len();
    }
    Ok(())
}

fn validate_restored_node_sets(
    source: &ScenarioDefForm,
    targets: &BTreeMap<NodeId, ProductionVmExactCheckpointTarget>,
    generations: &BTreeMap<NodeId, u64>,
    service_states: &BTreeMap<NodeId, ProductionNodeServiceState>,
) -> Result<(), LifecycleApiError> {
    let expected = source
        .world()
        .vm_nodes()
        .iter()
        .map(|node| node.id.clone())
        .collect::<std::collections::BTreeSet<_>>();
    let generation_nodes = generations
        .keys()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let service_nodes = service_states
        .keys()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let expected_targets = expected
        .iter()
        .filter(|node| {
            service_states.get(*node) != Some(&ProductionNodeServiceState::PermanentlyFailed)
        })
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let target_nodes = targets
        .keys()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    if generation_nodes != expected
        || service_nodes != expected
        || target_nodes != expected_targets
        || generations.values().any(|generation| *generation == 0)
    {
        return Err(loop_factory_error(
            "exact checkpoint closure has an incomplete World node set",
        ));
    }
    Ok(())
}

fn enforce_persist_limits(
    run_state_root: &Path,
    scenario: ContentHash,
    limits: FaultResourceLimits,
    manifest: &ClosureManifest,
    objects: &ClosureObjects,
    checkpoint: &ProductionVmExactCheckpointSet,
    manifest_bytes: usize,
) -> Result<(), SchedulerError> {
    let parent = closure_parent(run_state_root, scenario);
    let destination = parent.join(manifest.identity.to_hex());
    if !destination.exists() && parent.exists() {
        let count = fs::read_dir(&parent)
            .map_err(|error| store_error(format!("count exact checkpoint closures: {error}")))?
            .filter_map(Result::ok)
            .filter(|entry| {
                entry.file_type().is_ok_and(|kind| kind.is_dir())
                    && entry.file_name().to_str().is_some_and(|name| {
                        name.len() == 64
                            && name
                                .bytes()
                                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
                    })
            })
            .count();
        limits
            .reserve(
                "checkpoint_count",
                u64::try_from(count)
                    .map_err(|_| store_error("checkpoint count is not representable"))?,
                1,
            )
            .map_err(|error| store_error(error.to_string()))?;
    }

    let mut identities = BTreeSet::new();
    let mut bytes = u64::try_from(manifest_bytes)
        .map_err(|_| store_error("checkpoint manifest size is not representable"))?;
    for (identity, size) in [
        (manifest.schedule, objects.schedule.len()),
        (manifest.scheduler, objects.scheduler.len()),
        (manifest.trigger_state, objects.trigger_state.len()),
        (manifest.assertion_state, objects.assertion_state.len()),
        (manifest.lifecycle_state, objects.lifecycle_state.len()),
        (manifest.fault_checkpoint, objects.fault_checkpoint.len()),
    ] {
        if identities.insert(identity) {
            bytes = add_checkpoint_bytes(
                bytes,
                u64::try_from(size)
                    .map_err(|_| store_error("checkpoint object size is not representable"))?,
            )?;
        }
    }
    for (identity, object) in &objects.event_log_segments {
        if identities.insert(*identity) {
            bytes = add_checkpoint_bytes(
                bytes,
                u64::try_from(object.len()).map_err(|_| {
                    store_error("event-log checkpoint object size is not representable")
                })?,
            )?;
        }
    }
    for (identity, object) in &objects.signal_artifacts {
        if identities.insert(*identity) {
            bytes = add_checkpoint_bytes(
                bytes,
                u64::try_from(object.len()).map_err(|_| {
                    store_error("signal checkpoint object size is not representable")
                })?,
            )?;
        }
    }
    for target in &manifest.targets {
        let node = NodeId {
            name: target.node.clone(),
        };
        let snapshot = objects
            .snapshots
            .get(&node)
            .ok_or_else(|| store_error("closure snapshot object disappeared"))?;
        if identities.insert(target.snapshot) {
            bytes = add_checkpoint_bytes(
                bytes,
                u64::try_from(snapshot.len())
                    .map_err(|_| store_error("checkpoint snapshot size is not representable"))?,
            )?;
        }
        let source = checkpoint
            .targets
            .get(&node)
            .ok_or_else(|| store_error("closure target disappeared"))?;
        for (identity, size) in [
            (target.overlay.identity, source.overlay_artifact.length),
            (target.vmstate.identity, source.vmstate_artifact.length),
        ] {
            if identities.insert(identity) {
                bytes = add_checkpoint_bytes(bytes, size)?;
            }
        }
    }
    limits
        .reserve("fat_checkpoint_bytes", 0, bytes)
        .map_err(scheduler_resource_limit)
}

fn add_checkpoint_bytes(current: u64, requested: u64) -> Result<u64, SchedulerError> {
    current
        .checked_add(requested)
        .ok_or_else(|| store_error("checkpoint byte accounting overflow"))
}

fn authenticate_existing_publication_with_boundary(
    destination: &Path,
    object_directory: &Path,
    expected: &ClosureManifest,
    objects: &ClosureObjects,
    checkpoint: &ProductionVmExactCheckpointSet,
    boundary: &mut dyn FnMut() -> Result<(), SchedulerError>,
) -> Result<(), SchedulerError> {
    boundary()?;
    let bytes = read_bounded_file_with_scheduler_boundary(
        &destination.join(MANIFEST_FILE),
        MAX_MANIFEST_BYTES_U64,
        boundary,
    )?;
    boundary()?;
    let observed = decode_manifest(&bytes).map_err(store_error)?;
    if &observed != expected {
        return Err(store_error(
            "existing exact checkpoint publication has different authenticated content",
        ));
    }
    for (identity, bytes) in [
        (expected.schedule, objects.schedule.as_slice()),
        (expected.scheduler, objects.scheduler.as_slice()),
        (expected.trigger_state, objects.trigger_state.as_slice()),
        (expected.assertion_state, objects.assertion_state.as_slice()),
        (expected.lifecycle_state, objects.lifecycle_state.as_slice()),
        (
            expected.fault_checkpoint,
            objects.fault_checkpoint.as_slice(),
        ),
    ] {
        if hash_bytes_with_boundary(bytes, boundary)? != identity {
            return Err(store_error("checkpoint object changed before retry"));
        }
        validate_file_hash_with_boundary(
            &object_path(object_directory, identity),
            identity,
            boundary,
        )?;
    }
    for identity in &expected.event_log_segments {
        let bytes = objects
            .event_log_segments
            .get(identity)
            .ok_or_else(|| store_error("event-log closure object disappeared"))?;
        if hash_bytes_with_boundary(bytes, boundary)? != *identity {
            return Err(store_error(
                "event-log checkpoint object changed before retry",
            ));
        }
        validate_file_hash_with_boundary(
            &object_path(object_directory, *identity),
            *identity,
            boundary,
        )?;
    }
    for identity in &expected.signal_artifacts {
        let bytes = objects
            .signal_artifacts
            .get(identity)
            .ok_or_else(|| store_error("signal-artifact closure object disappeared"))?;
        if hash_bytes_with_boundary(bytes, boundary)? != *identity {
            return Err(store_error(
                "signal-artifact checkpoint object changed before retry",
            ));
        }
        validate_file_hash_with_boundary(
            &object_path(object_directory, *identity),
            *identity,
            boundary,
        )?;
    }
    for target in &expected.targets {
        boundary()?;
        let node = NodeId {
            name: target.node.clone(),
        };
        let snapshot = objects
            .snapshots
            .get(&node)
            .ok_or_else(|| store_error("closure snapshot object disappeared"))?;
        if hash_bytes_with_boundary(snapshot, boundary)? != target.snapshot {
            return Err(store_error("checkpoint snapshot changed before retry"));
        }
        validate_file_hash_with_boundary(
            &object_path(object_directory, target.snapshot),
            target.snapshot,
            boundary,
        )?;
        validate_artifact_manifest_with_scheduler_boundary(
            object_directory,
            &target.overlay,
            boundary,
        )?;
        validate_artifact_manifest_with_scheduler_boundary(
            object_directory,
            &target.vmstate,
            boundary,
        )?;
        let source = checkpoint
            .targets
            .get(&node)
            .ok_or_else(|| store_error("closure target disappeared"))?;
        validate_exact_checkpoint_artifact_with_boundary(&source.overlay_artifact, boundary)?;
        validate_exact_checkpoint_artifact_with_boundary(&source.vmstate_artifact, boundary)?;
    }
    Ok(())
}

fn validate_exact_checkpoint_artifact_with_boundary(
    artifact: &ProductionCheckpointArtifact,
    boundary: &mut dyn FnMut() -> Result<(), SchedulerError>,
) -> Result<(), SchedulerError> {
    match &artifact.source {
        ProductionCheckpointArtifactSource::File(path) => {
            validate_file_hash_with_boundary(path, artifact.identity, boundary)?;
        }
        ProductionCheckpointArtifactSource::ChunkStore(directory) => {
            let manifest = ArtifactManifest {
                identity: artifact.identity,
                length: artifact.length,
                chunks: artifact.chunks.clone(),
            };
            validate_artifact_manifest_with_scheduler_boundary(directory, &manifest, boundary)?;
        }
    }
    boundary()?;
    Ok(())
}

fn install_persisted_artifact_paths(
    object_directory: &Path,
    manifest: &ClosureManifest,
    checkpoint: &mut ProductionVmExactCheckpointSet,
) -> Result<(), SchedulerError> {
    for (node, target) in &mut checkpoint.targets {
        let manifest_target = manifest
            .targets
            .iter()
            .find(|candidate| candidate.node == node.name)
            .ok_or_else(|| store_error("published closure target disappeared"))?;
        target.overlay_artifact = ProductionCheckpointArtifact {
            source: ProductionCheckpointArtifactSource::ChunkStore(object_directory.to_path_buf()),
            identity: manifest_target.overlay.identity,
            length: manifest_target.overlay.length,
            chunks: manifest_target.overlay.chunks.clone(),
        };
        target.vmstate_artifact = ProductionCheckpointArtifact {
            source: ProductionCheckpointArtifactSource::ChunkStore(object_directory.to_path_buf()),
            identity: manifest_target.vmstate.identity,
            length: manifest_target.vmstate.length,
            chunks: manifest_target.vmstate.chunks.clone(),
        };
    }
    Ok(())
}

fn encode_lifecycle(
    checkpoint: &ProductionVmExactCheckpointSet,
) -> Result<Vec<u8>, SchedulerError> {
    let wire = LifecycleWire {
        terminal: checkpoint
            .terminal_verdict
            .as_ref()
            .map(|terminal| match terminal {
                QuantumTerminalVerdict::Passed => TerminalWire::Passed,
                QuantumTerminalVerdict::Failed(failures) => TerminalWire::Failed(failures.clone()),
            }),
        terminal_cause: checkpoint.terminal_cause.as_ref().map(|cause| match cause {
            CheckpointTerminalCause::Passed => TerminalCauseWire::Passed,
            CheckpointTerminalCause::Failed(failures) => {
                TerminalCauseWire::Failed(failures.clone())
            }
            CheckpointTerminalCause::BudgetExhausted => TerminalCauseWire::BudgetExhausted,
            CheckpointTerminalCause::BackendCrash(detail) => {
                TerminalCauseWire::BackendCrash(detail.clone())
            }
            CheckpointTerminalCause::OperatorStop => TerminalCauseWire::OperatorStop,
        }),
        initial_lifecycle_observations_pending: checkpoint.initial_lifecycle_observations_pending,
        branch: checkpoint.branch.as_ref().map(|branch| BranchWire {
            base_schedule: branch.base.schedule.to_compact_binary(),
            frontier: branch.frontier.ticks,
            decisions: branch.decisions.clone(),
            seed: branch.seed.map(Seed::bytes),
        }),
        recorded_controls: checkpoint
            .recorded_controls
            .iter()
            .map(|record| RecordedControlWire {
                configuration_schedule: record.configuration.schedule.to_compact_binary(),
                node_times: record
                    .node_times
                    .iter()
                    .map(|(node, time)| (node.name.clone(), time.ticks))
                    .collect(),
                control: record.control.clone(),
            })
            .collect(),
    };
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&wire, &mut bytes)
        .map_err(|_| store_error("encode exact lifecycle continuation"))?;
    Ok(bytes)
}

struct DecodedLifecycle {
    terminal: Option<QuantumTerminalVerdict>,
    terminal_cause: Option<CheckpointTerminalCause>,
    initial_lifecycle_observations_pending: bool,
    branch: Option<ProductionVmBranchConfig>,
    recorded_controls: Vec<ProductionVmRecordedControl>,
}

fn decode_lifecycle(
    bytes: &[u8],
    scenario: &ScenarioDef,
    limits: FaultResourceLimits,
) -> Result<DecodedLifecycle, LifecycleApiError> {
    let _budget = decode::DecodeBudgetGuard::enter(limits);
    let wire: LifecycleWire = ciborium::de::from_reader(bytes).map_err(|error| {
        decode::map_decode_resource_error(&error)
            .unwrap_or_else(|| loop_factory_error("decode exact lifecycle continuation"))
    })?;
    let canonical = {
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&wire, &mut encoded)
            .map_err(|_| loop_factory_error("re-encode exact lifecycle continuation"))?;
        encoded
    };
    if canonical != bytes {
        return Err(loop_factory_error(
            "exact lifecycle continuation is not canonical",
        ));
    }
    let terminal = wire.terminal.map(|terminal| match terminal {
        TerminalWire::Passed => QuantumTerminalVerdict::Passed,
        TerminalWire::Failed(failures) => QuantumTerminalVerdict::Failed(failures),
    });
    let terminal_cause = wire.terminal_cause.map(|cause| match cause {
        TerminalCauseWire::Passed => CheckpointTerminalCause::Passed,
        TerminalCauseWire::Failed(failures) => CheckpointTerminalCause::Failed(failures),
        TerminalCauseWire::BudgetExhausted => CheckpointTerminalCause::BudgetExhausted,
        TerminalCauseWire::BackendCrash(detail) => CheckpointTerminalCause::BackendCrash(detail),
        TerminalCauseWire::OperatorStop => CheckpointTerminalCause::OperatorStop,
    });
    if !terminal_cause_matches_verdict(terminal_cause.as_ref(), terminal.as_ref()) {
        return Err(loop_factory_error(
            "exact lifecycle terminal cause disagrees with its trigger verdict",
        ));
    }
    let branch = wire
        .branch
        .map(
            |branch| -> Result<ProductionVmBranchConfig, LifecycleApiError> {
                let schedule =
                    Schedule::from_compact_binary(&branch.base_schedule).map_err(|error| {
                        loop_factory_error(format!("decode checkpoint branch schedule: {error}"))
                    })?;
                Ok(ProductionVmBranchConfig {
                    base: Configuration {
                        def: scenario.clone(),
                        schedule,
                    },
                    frontier: VirtualTime {
                        ticks: branch.frontier,
                    },
                    decisions: branch.decisions,
                    seed: branch.seed.map(Seed::from_bytes),
                })
            },
        )
        .transpose()?;
    let mut recorded_controls = Vec::with_capacity(wire.recorded_controls.len());
    for record in wire.recorded_controls {
        if !record
            .node_times
            .windows(2)
            .all(|pair| pair[0].0 < pair[1].0)
        {
            return Err(loop_factory_error(
                "checkpoint recorded-control nodes are not strictly sorted",
            ));
        }
        let schedule =
            Schedule::from_compact_binary(&record.configuration_schedule).map_err(|error| {
                loop_factory_error(format!("decode recorded control schedule: {error}"))
            })?;
        recorded_controls.push(ProductionVmRecordedControl {
            configuration: Configuration {
                def: scenario.clone(),
                schedule,
            },
            node_times: record
                .node_times
                .into_iter()
                .map(|(name, ticks)| (NodeId { name }, VirtualTime { ticks }))
                .collect(),
            control: record.control,
        });
    }
    Ok(DecodedLifecycle {
        terminal,
        terminal_cause,
        initial_lifecycle_observations_pending: wire.initial_lifecycle_observations_pending,
        branch,
        recorded_controls,
    })
}

fn terminal_cause_matches_verdict(
    cause: Option<&CheckpointTerminalCause>,
    verdict: Option<&QuantumTerminalVerdict>,
) -> bool {
    match (cause, verdict) {
        (Some(CheckpointTerminalCause::Passed), Some(QuantumTerminalVerdict::Passed)) => true,
        (
            Some(CheckpointTerminalCause::Failed(cause)),
            Some(QuantumTerminalVerdict::Failed(verdict)),
        ) => cause == verdict,
        (Some(CheckpointTerminalCause::BudgetExhausted), None)
        | (Some(CheckpointTerminalCause::BackendCrash(_)), None)
        | (Some(CheckpointTerminalCause::OperatorStop), None)
        | (None, None) => true,
        _ => false,
    }
}

fn manifest_and_objects_with_boundary(
    scenario: ContentHash,
    resource_limits: FaultResourceLimits,
    checkpoint: &ProductionVmExactCheckpointSet,
    boundary: &mut dyn FnMut() -> Result<(), SchedulerError>,
) -> Result<(ClosureManifest, ClosureObjects), SchedulerError> {
    boundary()?;
    let schedule = checkpoint.configuration.schedule.to_compact_binary();
    boundary()?;
    let scheduler = checkpoint
        .scheduler
        .canonical_bytes()
        .map_err(|error| store_error(format!("encode scheduler continuation: {error}")))?;
    boundary()?;
    let trigger_state = checkpoint.trigger_state.to_compact_binary();
    let assertion_state = checkpoint
        .assertion_state
        .canonical_bytes()
        .map_err(|error| store_error(format!("encode assertion continuation: {error}")))?;
    let lifecycle_state = encode_lifecycle(checkpoint)?;
    let fault_checkpoint = checkpoint
        .fault_checkpoint
        .as_ref()
        .ok_or_else(|| store_error("exact checkpoint set has no production fault continuation"))?
        .to_canonical_bytes_with_limit(resource_limits.fat_checkpoint_bytes)
        .map_err(|error| store_error(format!("encode fault continuation: {error}")))?;
    boundary()?;
    let mut snapshots = BTreeMap::new();
    let mut targets = Vec::new();
    targets
        .try_reserve_exact(checkpoint.targets.len())
        .map_err(|error| store_error(format!("reserve checkpoint target manifest: {error}")))?;
    for (node, target) in &checkpoint.targets {
        boundary()?;
        let bytes = target
            .snapshot
            .to_canonical_bytes_with_limit(resource_limits.fat_checkpoint_bytes)
            .map_err(|error| {
                store_error(format!("encode QEMU snapshot for `{}`: {error}", node.name))
            })?;
        boundary()?;
        let snapshot = hash_bytes_with_boundary(&bytes, boundary)?;
        snapshots.insert(node.clone(), bytes);
        targets.push(TargetManifest {
            node: node.name.clone(),
            counter: target.counter,
            scheduler_time: target.scheduler_time.ticks,
            snapshot,
            overlay: artifact_manifest_with_boundary(&target.overlay_artifact, boundary)?,
            vmstate: artifact_manifest_with_boundary(&target.vmstate_artifact, boundary)?,
            manifest_identity: target.manifest_identity,
        });
    }
    let manifest = ClosureManifest {
        scenario,
        configuration: checkpoint.configuration.id(),
        schedule: hash_bytes_with_boundary(&schedule, boundary)?,
        frontier: checkpoint.scheduler.frontier().ticks,
        scheduler: hash_bytes_with_boundary(&scheduler, boundary)?,
        event_log_segments: checkpoint
            .scheduler
            .event_log_segment_dependencies()
            .to_vec(),
        signal_artifacts: checkpoint.signal_artifact_objects.keys().copied().collect(),
        trigger_state: hash_bytes_with_boundary(&trigger_state, boundary)?,
        assertion_state: hash_bytes_with_boundary(&assertion_state, boundary)?,
        lifecycle_state: hash_bytes_with_boundary(&lifecycle_state, boundary)?,
        fault_checkpoint: hash_bytes_with_boundary(&fault_checkpoint, boundary)?,
        targets,
        node_generations: checkpoint
            .node_generations
            .iter()
            .map(|(node, generation)| (node.name.clone(), *generation))
            .collect(),
        node_service_states: checkpoint
            .node_service_states
            .iter()
            .map(|(node, state)| (node.name.clone(), service_state_tag(*state)))
            .collect(),
        identity: ContentHash::default(),
    };
    Ok((
        manifest,
        ClosureObjects {
            schedule,
            scheduler,
            event_log_segments: checkpoint.event_log_objects.clone(),
            signal_artifacts: checkpoint.signal_artifact_objects.clone(),
            trigger_state,
            assertion_state,
            lifecycle_state,
            fault_checkpoint,
            snapshots,
        },
    ))
}

fn closure_identity(manifest: &ClosureManifest) -> Result<ContentHash, SchedulerError> {
    let material = ClosureManifest {
        scenario: manifest.scenario,
        configuration: manifest.configuration,
        schedule: manifest.schedule,
        frontier: manifest.frontier,
        scheduler: manifest.scheduler,
        event_log_segments: manifest.event_log_segments.clone(),
        signal_artifacts: manifest.signal_artifacts.clone(),
        trigger_state: manifest.trigger_state,
        assertion_state: manifest.assertion_state,
        lifecycle_state: manifest.lifecycle_state,
        fault_checkpoint: manifest.fault_checkpoint,
        targets: manifest
            .targets
            .iter()
            .map(|target| TargetManifest {
                node: target.node.clone(),
                counter: target.counter,
                scheduler_time: target.scheduler_time,
                snapshot: target.snapshot,
                overlay: target.overlay.clone(),
                vmstate: target.vmstate.clone(),
                manifest_identity: target.manifest_identity,
            })
            .collect(),
        node_generations: manifest.node_generations.clone(),
        node_service_states: manifest.node_service_states.clone(),
        identity: ContentHash::default(),
    };
    let bytes = encode_manifest(&material)?;
    Ok(ContentHash::from_canonical_material(
        "crucible.production-exact-closure.v4",
        &hex_bytes(&bytes),
    ))
}

fn encode_manifest(manifest: &ClosureManifest) -> Result<Vec<u8>, SchedulerError> {
    let mut payload = Vec::new();
    ciborium::ser::into_writer(manifest, &mut payload)
        .map_err(|_| store_error("encode exact checkpoint closure manifest"))?;
    if payload.len() > MAX_MANIFEST_BYTES {
        return Err(store_error(
            "exact checkpoint closure manifest exceeds its size limit",
        ));
    }
    let mut bytes = Vec::with_capacity(MANIFEST_MAGIC.len() + payload.len());
    bytes.extend_from_slice(MANIFEST_MAGIC);
    bytes.extend_from_slice(&payload);
    Ok(bytes)
}

// crucible-lint: allow stringly-error -- the private canonical decoder returns bounded diagnostics that the store boundary immediately wraps in CheckpointStoreError.
fn decode_manifest(bytes: &[u8]) -> Result<ClosureManifest, String> {
    let payload = bytes
        .strip_prefix(MANIFEST_MAGIC)
        .ok_or_else(|| String::from("unsupported closure manifest version"))?;
    if payload.len() > MAX_MANIFEST_BYTES {
        return Err(String::from("closure manifest exceeds its size limit"));
    }
    let manifest: ClosureManifest = ciborium::de::from_reader(payload)
        .map_err(|_| String::from("malformed closure manifest"))?;
    let canonical = encode_manifest(&manifest).map_err(|error| error.to_string())?;
    if canonical != bytes {
        return Err(String::from("noncanonical closure manifest"));
    }
    validate_manifest_shape(&manifest)?;
    Ok(manifest)
}

// crucible-lint: allow stringly-error -- the private shape validator returns bounded diagnostics that the store boundary immediately wraps in CheckpointStoreError.
fn validate_manifest_shape(manifest: &ClosureManifest) -> Result<(), String> {
    if !manifest
        .signal_artifacts
        .windows(2)
        .all(|pair| pair[0] < pair[1])
        || manifest
            .event_log_segments
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            != manifest.event_log_segments.len()
        || !manifest
            .targets
            .windows(2)
            .all(|pair| pair[0].node < pair[1].node)
        || !manifest
            .node_generations
            .windows(2)
            .all(|pair| pair[0].0 < pair[1].0)
        || !manifest
            .node_service_states
            .windows(2)
            .all(|pair| pair[0].0 < pair[1].0)
    {
        return Err(String::from(
            "closure manifest node collections are not strictly sorted",
        ));
    }
    if manifest.targets.iter().any(|target| target.node.is_empty())
        || manifest.targets.iter().any(|target| {
            (target.overlay.length == 0) != target.overlay.chunks.is_empty()
                || (target.vmstate.length == 0) != target.vmstate.chunks.is_empty()
        })
        || manifest
            .node_generations
            .iter()
            .any(|(node, generation)| node.is_empty() || *generation == 0)
        || manifest
            .node_service_states
            .iter()
            .any(|(node, state)| node.is_empty() || !matches!(state, 1..=3))
    {
        return Err(String::from(
            "closure manifest contains an invalid node record",
        ));
    }
    let snapshot_count = manifest
        .targets
        .iter()
        .map(|target| target.snapshot)
        .collect::<BTreeSet<_>>()
        .len();
    if snapshot_count != manifest.targets.len() {
        return Err(String::from(
            "closure manifest aliases a node-specific QEMU snapshot",
        ));
    }
    for artifact in manifest
        .targets
        .iter()
        .flat_map(|target| [&target.overlay, &target.vmstate])
    {
        let chunk_count = u64::try_from(artifact.chunks.len())
            .map_err(|_| String::from("artifact chunk count is not representable"))?;
        let minimum = chunk_count
            .saturating_sub(1)
            .checked_mul(ARTIFACT_CHUNK_BYTES_U64)
            .and_then(|bytes| bytes.checked_add(u64::from(chunk_count != 0)))
            .ok_or_else(|| String::from("artifact chunk geometry overflows"))?;
        let maximum = chunk_count
            .checked_mul(ARTIFACT_CHUNK_BYTES_U64)
            .ok_or_else(|| String::from("artifact chunk geometry overflows"))?;
        if artifact.length < minimum || artifact.length > maximum {
            return Err(String::from(
                "closure manifest contains invalid artifact chunk geometry",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
fn persist_object(
    directory: &Path,
    expected: ContentHash,
    bytes: &[u8],
) -> Result<(), SchedulerError> {
    persist_object_with_boundary(directory, expected, bytes, &mut || Ok(()))
}

fn persist_object_with_boundary(
    directory: &Path,
    expected: ContentHash,
    bytes: &[u8],
    boundary: &mut dyn FnMut() -> Result<(), SchedulerError>,
) -> Result<(), SchedulerError> {
    if hash_bytes_with_boundary(bytes, boundary)? != expected {
        return Err(store_error(
            "checkpoint object content hash mismatch before persistence",
        ));
    }
    let destination = object_path(directory, expected);
    if destination.exists() {
        return sync_existing_object_with_boundary(&destination, expected, boundary);
    }
    let staging_directory = destination
        .parent()
        .ok_or_else(|| store_error("checkpoint object path has no parent directory"))?;
    fs::create_dir_all(staging_directory)
        .map_err(|error| store_error(format!("create checkpoint object prefix: {error}")))?;
    let mut staging = tempfile::Builder::new()
        .prefix(".object-")
        .tempfile_in(staging_directory)
        .map_err(|error| store_error(format!("stage checkpoint object: {error}")))?;
    for chunk in bytes.chunks(SPARSE_COPY_BUFFER_BYTES) {
        boundary()?;
        staging
            .write_all(chunk)
            .map_err(|error| store_error(format!("write staged checkpoint object: {error}")))?;
    }
    boundary()?;
    staging
        .as_file()
        .sync_all()
        .map_err(|error| store_error(format!("flush staged checkpoint object: {error}")))?;
    match staging.persist_noclobber(&destination) {
        Ok(_) => sync_directory(staging_directory),
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
            sync_existing_object_with_boundary(&destination, expected, boundary)
        }
        Err(error) => Err(store_error(format!(
            "publish checkpoint object {}: {}",
            expected.to_hex(),
            error.error
        ))),
    }
}

fn persist_file_object_with_boundary(
    directory: &Path,
    expected: ContentHash,
    source: &Path,
    boundary: &mut dyn FnMut() -> Result<(), SchedulerError>,
) -> Result<(), SchedulerError> {
    validate_file_hash_with_boundary(source, expected, boundary)?;
    let destination = object_path(directory, expected);
    if destination.exists() {
        return sync_existing_object_with_boundary(&destination, expected, boundary);
    }
    let staging_directory = destination
        .parent()
        .ok_or_else(|| store_error("checkpoint object path has no parent directory"))?;
    fs::create_dir_all(staging_directory)
        .map_err(|error| store_error(format!("create checkpoint object prefix: {error}")))?;
    let mut staging = tempfile::Builder::new()
        .prefix(".object-")
        .tempfile_in(staging_directory)
        .map_err(|error| store_error(format!("stage checkpoint file object: {error}")))?;
    let source_length = fs::metadata(source)
        .map_err(|error| store_error(format!("inspect checkpoint file object: {error}")))?
        .len();
    let source_file = File::open(source)
        .map_err(|error| store_error(format!("open checkpoint file object: {error}")))?;
    copy_sparse_authenticated_with_boundary(
        source_file,
        staging.as_file_mut(),
        source_length,
        expected,
        boundary,
    )?;
    staging
        .as_file()
        .sync_all()
        .map_err(|error| store_error(format!("flush staged checkpoint object: {error}")))?;
    match staging.persist_noclobber(&destination) {
        Ok(_) => {
            validate_file_hash_with_boundary(&destination, expected, boundary)?;
            sync_directory(staging_directory)
        }
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
            sync_existing_object_with_boundary(&destination, expected, boundary)
        }
        Err(error) => Err(store_error(format!(
            "publish checkpoint object {}: {}",
            expected.to_hex(),
            error.error
        ))),
    }
}

fn sync_existing_object_with_boundary(
    path: &Path,
    expected: ContentHash,
    boundary: &mut dyn FnMut() -> Result<(), SchedulerError>,
) -> Result<(), SchedulerError> {
    validate_file_hash_with_boundary(path, expected, boundary)?;
    boundary()?;
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|error| store_error(format!("flush checkpoint object: {error}")))?;
    let parent = path
        .parent()
        .ok_or_else(|| store_error("checkpoint object path has no parent directory"))?;
    sync_directory(parent)
}

#[cfg(test)]
fn artifact_manifest(
    artifact: &ProductionCheckpointArtifact,
) -> Result<ArtifactManifest, SchedulerError> {
    artifact_manifest_with_boundary(artifact, &mut || Ok(()))
}

fn artifact_manifest_with_boundary(
    artifact: &ProductionCheckpointArtifact,
    boundary: &mut dyn FnMut() -> Result<(), SchedulerError>,
) -> Result<ArtifactManifest, SchedulerError> {
    boundary()?;
    if !artifact.chunks.is_empty() {
        return Ok(ArtifactManifest {
            identity: artifact.identity,
            length: artifact.length,
            chunks: artifact.chunks.clone(),
        });
    }
    let ProductionCheckpointArtifactSource::File(path) = &artifact.source else {
        return Err(store_error(
            "chunk-store artifact is missing its canonical chunk sequence",
        ));
    };
    validate_file_hash_with_boundary(path, artifact.identity, boundary)?;
    let observed_length = fs::metadata(path)
        .map_err(|error| store_error(format!("inspect checkpoint artifact: {error}")))?
        .len();
    if observed_length != artifact.length {
        return Err(store_error(
            "checkpoint artifact length changed before persistence",
        ));
    }
    let mut file = File::open(path)
        .map_err(|error| store_error(format!("open checkpoint artifact: {error}")))?;
    let mut buffer = vec![0_u8; ARTIFACT_CHUNK_BYTES];
    let mut chunks = Vec::new();
    loop {
        boundary()?;
        let mut filled = 0;
        while filled < buffer.len() {
            boundary()?;
            let read = file
                .read(&mut buffer[filled..])
                .map_err(|error| store_error(format!("read checkpoint artifact: {error}")))?;
            if read == 0 {
                break;
            }
            filled += read;
        }
        if filled == 0 {
            break;
        }
        chunks.push(hash_bytes_with_boundary(&buffer[..filled], boundary)?);
        if filled < buffer.len() {
            break;
        }
    }
    Ok(ArtifactManifest {
        identity: artifact.identity,
        length: artifact.length,
        chunks,
    })
}

#[cfg(test)]
fn persist_chunked_artifact(
    directory: &Path,
    manifest: &ArtifactManifest,
    artifact: &ProductionCheckpointArtifact,
) -> Result<(), SchedulerError> {
    persist_chunked_artifact_with_boundary(directory, manifest, artifact, &mut || Ok(()))
}

fn persist_chunked_artifact_with_boundary(
    directory: &Path,
    manifest: &ArtifactManifest,
    artifact: &ProductionCheckpointArtifact,
    boundary: &mut dyn FnMut() -> Result<(), SchedulerError>,
) -> Result<(), SchedulerError> {
    boundary()?;
    match &artifact.source {
        ProductionCheckpointArtifactSource::ChunkStore(source) => {
            validate_artifact_manifest(source, manifest)
                .map_err(|error| store_error(error.to_string()))?;
            for chunk in &manifest.chunks {
                boundary()?;
                let source_path = object_path(source, *chunk);
                let destination = object_path(directory, *chunk);
                if source_path != destination && !destination.exists() {
                    persist_file_object_with_boundary(directory, *chunk, &source_path, boundary)?;
                }
            }
        }
        ProductionCheckpointArtifactSource::File(path) => {
            let mut file = File::open(path)
                .map_err(|error| store_error(format!("open checkpoint artifact: {error}")))?;
            let mut buffer = vec![0_u8; ARTIFACT_CHUNK_BYTES];
            for expected in &manifest.chunks {
                boundary()?;
                let mut filled = 0;
                while filled < buffer.len() {
                    boundary()?;
                    let read = file.read(&mut buffer[filled..]).map_err(|error| {
                        store_error(format!("read checkpoint artifact chunk: {error}"))
                    })?;
                    if read == 0 {
                        break;
                    }
                    filled += read;
                }
                if filled == 0 || ContentHash::from_bytes(&buffer[..filled]) != *expected {
                    return Err(store_error(
                        "checkpoint artifact chunk changed before persistence",
                    ));
                }
                persist_object_with_boundary(directory, *expected, &buffer[..filled], boundary)?;
            }
            let mut trailing = [0_u8; 1];
            boundary()?;
            if file
                .read(&mut trailing)
                .map_err(|error| store_error(format!("finish checkpoint artifact: {error}")))?
                != 0
            {
                return Err(store_error(
                    "checkpoint artifact grew while it was being persisted",
                ));
            }
        }
    }
    boundary()?;
    validate_artifact_manifest_with_scheduler_boundary(directory, manifest, boundary)
}

pub(super) fn validate_chunked_artifact(
    directory: &Path,
    artifact: &ProductionCheckpointArtifact,
) -> Result<ContentHash, LifecycleApiError> {
    let manifest = ArtifactManifest {
        identity: artifact.identity,
        length: artifact.length,
        chunks: artifact.chunks.clone(),
    };
    validate_artifact_manifest(directory, &manifest)?;
    Ok(manifest.identity)
}

fn validate_artifact_manifest(
    directory: &Path,
    manifest: &ArtifactManifest,
) -> Result<(), LifecycleApiError> {
    let mut reader = ChunkSequenceReader::new(directory, &manifest.chunks)?;
    let observed = ContentHash::from_reader(&mut reader).map_err(|error| {
        loop_factory_error(format!("read chunked checkpoint artifact: {error}"))
    })?;
    if reader.bytes_read != manifest.length || observed != manifest.identity {
        return Err(loop_factory_error(
            "chunked checkpoint artifact failed length or content authentication",
        ));
    }
    Ok(())
}

fn validate_artifact_manifest_with_scheduler_boundary(
    directory: &Path,
    manifest: &ArtifactManifest,
    boundary: &mut dyn FnMut() -> Result<(), SchedulerError>,
) -> Result<(), SchedulerError> {
    boundary()?;
    let mut reader = ChunkSequenceReader::new(directory, &manifest.chunks)
        .map_err(|error| store_error(error.to_string()))?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0_u8; SPARSE_COPY_BUFFER_BYTES];
    loop {
        boundary()?;
        let read = reader
            .read(&mut buffer)
            .map_err(|error| store_error(format!("read chunked checkpoint artifact: {error}")))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    boundary()?;
    let observed = ContentHash {
        bytes: *hasher.finalize().as_bytes(),
    };
    if reader.bytes_read != manifest.length || observed != manifest.identity {
        return Err(store_error(
            "chunked checkpoint artifact failed length or content authentication",
        ));
    }
    Ok(())
}

pub(super) fn materialize_checkpoint_artifact(
    artifact: &ProductionCheckpointArtifact,
    destination: &Path,
    role: &str,
) -> Result<(), LifecycleApiError> {
    let parent = destination.parent().ok_or_else(|| {
        loop_factory_error(format!(
            "exact checkpoint {role} destination has no parent directory"
        ))
    })?;
    let mut staging = tempfile::Builder::new()
        .prefix(".artifact-")
        .tempfile_in(parent)
        .map_err(|error| {
            loop_factory_error(format!(
                "stage exact checkpoint {role} under {}: {error}",
                parent.display()
            ))
        })?;

    match &artifact.source {
        ProductionCheckpointArtifactSource::File(source) => {
            let source_file = File::open(source).map_err(|error| {
                loop_factory_error(format!(
                    "open exact checkpoint {role} {}: {error}",
                    source.display()
                ))
            })?;
            copy_sparse_authenticated(
                source_file,
                staging.as_file_mut(),
                artifact.length,
                artifact.identity,
            )
            .map_err(|error| {
                loop_factory_error(format!(
                    "materialize exact checkpoint {role} {} as {}: {error}",
                    source.display(),
                    destination.display()
                ))
            })?;
        }
        ProductionCheckpointArtifactSource::ChunkStore(directory) => {
            let reader = ChunkSequenceReader::new(directory, &artifact.chunks)?;
            copy_sparse_authenticated(
                reader,
                staging.as_file_mut(),
                artifact.length,
                artifact.identity,
            )
            .map_err(|error| {
                loop_factory_error(format!(
                    "materialize exact checkpoint {role} {}: {error}",
                    destination.display()
                ))
            })?;
        }
    }
    staging.as_file().sync_all().map_err(|error| {
        loop_factory_error(format!(
            "flush exact checkpoint {role} {}: {error}",
            destination.display()
        ))
    })?;
    staging.persist_noclobber(destination).map_err(|error| {
        loop_factory_error(format!(
            "publish exact checkpoint {role} {}: {}",
            destination.display(),
            error.error
        ))
    })?;
    sync_directory(parent).map_err(|error| loop_factory_error(error.to_string()))
}

pub(super) fn stream_checkpoint_artifact(
    artifact: &ProductionCheckpointArtifact,
    destination: &mut impl Write,
    role: &str,
) -> Result<(), LifecycleApiError> {
    match &artifact.source {
        ProductionCheckpointArtifactSource::File(source) => {
            let reader = File::open(source).map_err(|error| {
                loop_factory_error(format!(
                    "open exact checkpoint {role} {}: {error}",
                    source.display()
                ))
            })?;
            copy_authenticated(reader, destination, artifact.length, artifact.identity).map_err(
                |error| {
                    loop_factory_error(format!(
                        "stream exact checkpoint {role} {}: {error}",
                        source.display()
                    ))
                },
            )
        }
        ProductionCheckpointArtifactSource::ChunkStore(directory) => {
            let reader = ChunkSequenceReader::new(directory, &artifact.chunks)?;
            copy_authenticated(reader, destination, artifact.length, artifact.identity).map_err(
                |error| {
                    loop_factory_error(format!(
                        "stream chunked exact checkpoint {role} from {}: {error}",
                        directory.display()
                    ))
                },
            )
        }
    }
}

fn copy_authenticated(
    mut source: impl Read,
    destination: &mut impl Write,
    expected_length: u64,
    expected_identity: ContentHash,
) -> Result<(), std::io::Error> {
    let mut buffer = vec![0_u8; SPARSE_COPY_BUFFER_BYTES];
    let mut hasher = blake3::Hasher::new();
    let mut copied = 0_u64;
    loop {
        let read = source.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let read_u64 = u64::try_from(read).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "checkpoint copy length is not representable",
            )
        })?;
        copied = copied.checked_add(read_u64).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "checkpoint copy length overflowed",
            )
        })?;
        if copied > expected_length {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "checkpoint artifact exceeds its declared length",
            ));
        }
        let bytes = &buffer[..read];
        hasher.update(bytes);
        destination.write_all(bytes)?;
    }
    let observed = ContentHash {
        bytes: *hasher.finalize().as_bytes(),
    };
    if copied != expected_length || observed != expected_identity {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "checkpoint artifact failed length or content authentication",
        ));
    }
    Ok(())
}

fn copy_sparse_authenticated(
    mut source: impl Read,
    destination: &mut File,
    expected_length: u64,
    expected_identity: ContentHash,
) -> Result<(), std::io::Error> {
    let mut buffer = vec![0_u8; SPARSE_COPY_BUFFER_BYTES];
    let mut hasher = blake3::Hasher::new();
    let mut copied = 0_u64;
    loop {
        let read = source.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let read_u64 = u64::try_from(read).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "checkpoint copy length is not representable",
            )
        })?;
        copied = copied.checked_add(read_u64).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "checkpoint copy length overflowed",
            )
        })?;
        if copied > expected_length {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "checkpoint artifact exceeds its declared length",
            ));
        }
        let bytes = &buffer[..read];
        hasher.update(bytes);
        if bytes.iter().all(|byte| *byte == 0) {
            let offset = i64::try_from(read).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "checkpoint sparse extent is not representable",
                )
            })?;
            destination.seek(SeekFrom::Current(offset))?;
        } else {
            destination.write_all(bytes)?;
        }
    }
    if copied != expected_length {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "checkpoint artifact is shorter than its declared length",
        ));
    }
    destination.set_len(expected_length)?;
    let observed = ContentHash {
        bytes: *hasher.finalize().as_bytes(),
    };
    if observed != expected_identity {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "checkpoint artifact failed content authentication while streaming",
        ));
    }
    Ok(())
}

fn copy_sparse_authenticated_with_boundary(
    mut source: impl Read,
    destination: &mut File,
    expected_length: u64,
    expected_identity: ContentHash,
    boundary: &mut dyn FnMut() -> Result<(), SchedulerError>,
) -> Result<(), SchedulerError> {
    let mut buffer = vec![0_u8; SPARSE_COPY_BUFFER_BYTES];
    let mut hasher = blake3::Hasher::new();
    let mut copied = 0_u64;
    loop {
        boundary()?;
        let read = source
            .read(&mut buffer)
            .map_err(|error| store_error(format!("read checkpoint sparse extent: {error}")))?;
        if read == 0 {
            break;
        }
        let read_u64 = u64::try_from(read)
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "checkpoint copy length is not representable",
                )
            })
            .map_err(|error| store_error(error.to_string()))?;
        copied = copied
            .checked_add(read_u64)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "checkpoint copy length overflowed",
                )
            })
            .map_err(|error| store_error(error.to_string()))?;
        if copied > expected_length {
            return Err(store_error(
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "checkpoint artifact exceeds its declared length",
                )
                .to_string(),
            ));
        }
        let bytes = &buffer[..read];
        hasher.update(bytes);
        if bytes.iter().all(|byte| *byte == 0) {
            let offset = i64::try_from(read)
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "checkpoint sparse extent is not representable",
                    )
                })
                .map_err(|error| store_error(error.to_string()))?;
            destination
                .seek(SeekFrom::Current(offset))
                .map_err(|error| store_error(format!("seek sparse checkpoint extent: {error}")))?;
        } else {
            destination
                .write_all(bytes)
                .map_err(|error| store_error(format!("write checkpoint extent: {error}")))?;
        }
    }
    if copied != expected_length {
        return Err(store_error(
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "checkpoint artifact is shorter than its declared length",
            )
            .to_string(),
        ));
    }
    destination
        .set_len(expected_length)
        .map_err(|error| store_error(format!("size sparse checkpoint extent: {error}")))?;
    let observed = ContentHash {
        bytes: *hasher.finalize().as_bytes(),
    };
    if observed != expected_identity {
        return Err(store_error(
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "checkpoint artifact failed content authentication while streaming",
            )
            .to_string(),
        ));
    }
    boundary()?;
    Ok(())
}

struct ChunkSequenceReader {
    directory: PathBuf,
    chunks: Vec<ContentHash>,
    index: usize,
    current: Option<File>,
    bytes_read: u64,
}

impl ChunkSequenceReader {
    fn new(directory: &Path, chunks: &[ContentHash]) -> Result<Self, LifecycleApiError> {
        for (index, identity) in chunks.iter().enumerate() {
            let path = object_path(directory, *identity);
            let length = fs::metadata(&path)
                .map_err(|error| {
                    loop_factory_error(format!(
                        "inspect checkpoint chunk {}: {error}",
                        path.display()
                    ))
                })?
                .len();
            let expected = if index + 1 == chunks.len() {
                1..=ARTIFACT_CHUNK_BYTES_U64
            } else {
                ARTIFACT_CHUNK_BYTES_U64..=ARTIFACT_CHUNK_BYTES_U64
            };
            if !expected.contains(&length) {
                return Err(loop_factory_error(
                    "checkpoint artifact has invalid chunk geometry",
                ));
            }
            validate_file_hash(&path, *identity)
                .map_err(|error| loop_factory_error(error.to_string()))?;
        }
        Ok(Self {
            directory: directory.to_path_buf(),
            chunks: chunks.to_vec(),
            index: 0,
            current: None,
            bytes_read: 0,
        })
    }
}

impl std::io::Read for ChunkSequenceReader {
    fn read(&mut self, buffer: &mut [u8]) -> Result<usize, std::io::Error> {
        loop {
            if self.current.is_none() {
                let Some(identity) = self.chunks.get(self.index).copied() else {
                    return Ok(0);
                };
                self.current = Some(File::open(object_path(&self.directory, identity))?);
            }
            let read = self
                .current
                .as_mut()
                .map_or(Ok(0), |file| file.read(buffer))?;
            if read != 0 {
                self.bytes_read = self
                    .bytes_read
                    .saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
                return Ok(read);
            }
            self.current = None;
            self.index = self.index.saturating_add(1);
        }
    }
}

fn read_bounded_file_with_scheduler_boundary(
    path: &Path,
    limit: u64,
    boundary: &mut dyn FnMut() -> Result<(), SchedulerError>,
) -> Result<Vec<u8>, SchedulerError> {
    boundary()?;
    let mut file =
        File::open(path).map_err(|error| store_error(format!("open checkpoint file: {error}")))?;
    let length = file
        .metadata()
        .map_err(|error| store_error(format!("inspect checkpoint file: {error}")))?
        .len();
    if length > limit {
        return Err(store_error(format!(
            "checkpoint file length {length} exceeds limit {limit}"
        )));
    }
    let length = usize::try_from(length)
        .map_err(|_| store_error("checkpoint file length is not representable"))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|error| store_error(format!("reserve checkpoint file bytes: {error}")))?;
    bytes.resize(length, 0);
    for chunk in bytes.chunks_mut(SPARSE_COPY_BUFFER_BYTES) {
        boundary()?;
        file.read_exact(chunk)
            .map_err(|error| store_error(format!("read checkpoint file: {error}")))?;
    }
    boundary()?;
    let mut trailing = [0_u8; 1];
    if file
        .read(&mut trailing)
        .map_err(|error| store_error(format!("finish checkpoint file read: {error}")))?
        != 0
    {
        return Err(store_error("checkpoint file grew while it was read"));
    }
    boundary()?;
    Ok(bytes)
}

fn persist_file_bytes_with_boundary(
    path: &Path,
    bytes: &[u8],
    boundary: &mut dyn FnMut() -> Result<(), SchedulerError>,
) -> Result<(), SchedulerError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            store_error(format!(
                "create checkpoint object {}: {error}",
                path.display()
            ))
        })?;
    for chunk in bytes.chunks(SPARSE_COPY_BUFFER_BYTES) {
        boundary()?;
        file.write_all(chunk).map_err(|error| {
            store_error(format!(
                "write checkpoint object {}: {error}",
                path.display()
            ))
        })?;
    }
    boundary()?;
    file.sync_all().map_err(|error| {
        store_error(format!(
            "flush checkpoint object {}: {error}",
            path.display()
        ))
    })
}

fn read_object(
    root: &Path,
    expected: ContentHash,
    budget: &mut CheckpointReadBudget,
    role_limit: u64,
    boundary: &mut dyn FnMut() -> Result<(), LifecycleApiError>,
) -> Result<Vec<u8>, LifecycleApiError> {
    boundary()?;
    let path = object_path(root, expected);
    let size = fs::metadata(&path)
        .map_err(|error| {
            loop_factory_error(format!(
                "inspect checkpoint object {}: {error}",
                path.display()
            ))
        })?
        .len();
    if size > role_limit {
        return Err(loop_factory_error(format!(
            "checkpoint object {} exceeds its role-specific byte limit {}",
            expected.to_hex(),
            role_limit
        )));
    }
    let bytes = budget.read_identity(expected, size, || {
        read_bounded_file_with_boundary(&path, size, boundary)
    })?;
    boundary()?;
    if hash_bytes_with_lifecycle_boundary(&bytes, boundary)? != expected {
        return Err(loop_factory_error(format!(
            "checkpoint object {} failed content authentication",
            expected.to_hex()
        )));
    }
    Ok(bytes)
}

fn validate_file_hash(path: &Path, expected: ContentHash) -> Result<(), SchedulerError> {
    validate_file_hash_with_boundary(path, expected, &mut || Ok(()))
}

fn validate_file_hash_with_boundary(
    path: &Path,
    expected: ContentHash,
    boundary: &mut dyn FnMut() -> Result<(), SchedulerError>,
) -> Result<(), SchedulerError> {
    boundary()?;
    let mut file = File::open(path).map_err(|error| {
        store_error(format!(
            "open checkpoint object {}: {error}",
            path.display()
        ))
    })?;
    let mut buffer = vec![0_u8; SPARSE_COPY_BUFFER_BYTES];
    let mut hasher = blake3::Hasher::new();
    loop {
        boundary()?;
        let read = file.read(&mut buffer).map_err(|error| {
            store_error(format!(
                "hash checkpoint object {}: {error}",
                path.display()
            ))
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    boundary()?;
    let actual = ContentHash {
        bytes: *hasher.finalize().as_bytes(),
    };
    if actual != expected {
        return Err(store_error(format!(
            "checkpoint object {} changed before persistence",
            path.display()
        )));
    }
    Ok(())
}

fn hash_bytes_with_boundary(
    bytes: &[u8],
    boundary: &mut dyn FnMut() -> Result<(), SchedulerError>,
) -> Result<ContentHash, SchedulerError> {
    let mut hasher = blake3::Hasher::new();
    for chunk in bytes.chunks(SPARSE_COPY_BUFFER_BYTES) {
        boundary()?;
        hasher.update(chunk);
    }
    boundary()?;
    Ok(ContentHash {
        bytes: *hasher.finalize().as_bytes(),
    })
}

fn hash_bytes_with_lifecycle_boundary(
    bytes: &[u8],
    boundary: &mut dyn FnMut() -> Result<(), LifecycleApiError>,
) -> Result<ContentHash, LifecycleApiError> {
    let mut hasher = blake3::Hasher::new();
    for chunk in bytes.chunks(SPARSE_COPY_BUFFER_BYTES) {
        boundary()?;
        hasher.update(chunk);
    }
    boundary()?;
    Ok(ContentHash {
        bytes: *hasher.finalize().as_bytes(),
    })
}

fn decode_generations(
    values: &[(String, u64)],
) -> Result<BTreeMap<NodeId, u64>, LifecycleApiError> {
    let mut decoded = BTreeMap::new();
    for (node, generation) in values {
        if decoded
            .insert(NodeId { name: node.clone() }, *generation)
            .is_some()
        {
            return Err(loop_factory_error("duplicate checkpoint node generation"));
        }
    }
    Ok(decoded)
}

fn decode_service_states(
    values: &[(String, u8)],
) -> Result<BTreeMap<NodeId, ProductionNodeServiceState>, LifecycleApiError> {
    let mut decoded = BTreeMap::new();
    for (node, state) in values {
        let state = match state {
            1 => ProductionNodeServiceState::Running,
            2 => ProductionNodeServiceState::PoweredOff,
            3 => ProductionNodeServiceState::PermanentlyFailed,
            _ => return Err(loop_factory_error("invalid checkpoint node service state")),
        };
        if decoded
            .insert(NodeId { name: node.clone() }, state)
            .is_some()
        {
            return Err(loop_factory_error(
                "duplicate checkpoint node service state",
            ));
        }
    }
    Ok(decoded)
}

const fn service_state_tag(state: ProductionNodeServiceState) -> u8 {
    match state {
        ProductionNodeServiceState::Running => 1,
        ProductionNodeServiceState::PoweredOff => 2,
        ProductionNodeServiceState::PermanentlyFailed => 3,
    }
}

pub(super) fn checkpoint_dag_store(
    run_state_root: &Path,
    scenario: ContentHash,
) -> Arc<dyn DagStore> {
    Arc::new(LocalDagStore::new(object_parent(run_state_root, scenario)))
}

fn object_path(root: &Path, identity: ContentHash) -> PathBuf {
    LocalDagStore::new(root).object_path(&identity)
}

fn sync_directory(path: &Path) -> Result<(), SchedulerError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| {
            store_error(format!(
                "flush checkpoint directory {}: {error}",
                path.display()
            ))
        })
}

fn store_error(message: impl Into<String>) -> SchedulerError {
    SchedulerError::BoundaryViolation {
        message: message.into(),
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
    #![allow(clippy::expect_used)]

    use super::*;

    #[cfg(target_os = "linux")]
    use std::os::unix::fs::MetadataExt as _;

    fn manifest() -> ClosureManifest {
        ClosureManifest {
            scenario: ContentHash::default(),
            configuration: ContentHash::default(),
            schedule: ContentHash::default(),
            frontier: 0,
            scheduler: ContentHash::default(),
            event_log_segments: Vec::new(),
            signal_artifacts: Vec::new(),
            trigger_state: ContentHash::default(),
            assertion_state: ContentHash::default(),
            lifecycle_state: ContentHash::default(),
            fault_checkpoint: ContentHash::default(),
            targets: Vec::new(),
            node_generations: Vec::new(),
            node_service_states: Vec::new(),
            identity: ContentHash::default(),
        }
    }

    fn target(node: &str) -> TargetManifest {
        let artifact = ArtifactManifest {
            identity: ContentHash::from_bytes(b"artifact"),
            length: 8,
            chunks: vec![ContentHash::from_bytes(b"artifact")],
        };
        TargetManifest {
            node: String::from(node),
            counter: 0,
            scheduler_time: 0,
            snapshot: ContentHash::from_bytes(node.as_bytes()),
            overlay: artifact.clone(),
            vmstate: artifact,
            manifest_identity: ContentHash::default(),
        }
    }

    struct MemoryPortable {
        identity: ContentHash,
        scenario: ContentHash,
        configuration: ContentHash,
        manifest: Vec<u8>,
        objects: Vec<ProductionExactCheckpointObject>,
        bodies: BTreeMap<ContentHash, Vec<u8>>,
    }

    impl ProductionExactCheckpointSource for MemoryPortable {
        fn identity(&self) -> ContentHash {
            self.identity
        }

        fn scenario(&self) -> ContentHash {
            self.scenario
        }

        fn configuration(&self) -> ContentHash {
            self.configuration
        }

        fn manifest(&self) -> &[u8] {
            &self.manifest
        }

        fn objects(&self) -> &[ProductionExactCheckpointObject] {
            &self.objects
        }

        fn open_object(
            &self,
            identity: ContentHash,
        ) -> Result<Box<dyn Read + Send>, LifecycleApiError> {
            let bytes = self
                .bodies
                .get(&identity)
                .ok_or_else(|| loop_factory_error("memory portable object is absent"))?
                .clone();
            Ok(Box::new(std::io::Cursor::new(bytes)))
        }
    }

    fn snapshot_portable(
        mut manifest: ClosureManifest,
        snapshot: &QemuVmSnapshot,
    ) -> MemoryPortable {
        let bytes = snapshot
            .to_canonical_bytes()
            .expect("encode production snapshot fixture");
        let object = ContentHash::from_bytes(&bytes);
        manifest.targets[0].snapshot = object;
        let configuration = manifest.configuration;
        let fault_checkpoint = manifest.fault_checkpoint;
        let target = &mut manifest.targets[0];
        let node = NodeId {
            name: target.node.clone(),
        };
        target.manifest_identity =
            exact_checkpoint_target_manifest_identity(ExactCheckpointTargetManifestBasis {
                configuration,
                node: &node,
                counter: target.counter,
                scheduler_time: VirtualTime {
                    ticks: target.scheduler_time,
                },
                snapshot: snapshot.id(),
                fault_identity: fault_checkpoint,
                overlay: target.overlay.identity,
                vmstate: target.vmstate.identity,
            });
        manifest.identity = closure_identity(&manifest).expect("derive snapshot closure identity");
        MemoryPortable {
            identity: manifest.identity,
            scenario: manifest.scenario,
            configuration: manifest.configuration,
            manifest: encode_manifest(&manifest).expect("encode snapshot closure fixture"),
            objects: vec![ProductionExactCheckpointObject::new(
                object,
                u64::try_from(bytes.len()).expect("snapshot fixture length fits"),
            )],
            bodies: BTreeMap::from([(object, bytes)]),
        }
    }

    fn refresh_target_manifest_identities(manifest: &mut ClosureManifest) {
        let configuration = manifest.configuration;
        let fault_checkpoint = manifest.fault_checkpoint;
        for target in &mut manifest.targets {
            let node = NodeId {
                name: target.node.clone(),
            };
            target.manifest_identity =
                exact_checkpoint_target_manifest_identity(ExactCheckpointTargetManifestBasis {
                    configuration,
                    node: &node,
                    counter: target.counter,
                    scheduler_time: VirtualTime {
                        ticks: target.scheduler_time,
                    },
                    snapshot: target.snapshot,
                    fault_identity: fault_checkpoint,
                    overlay: target.overlay.identity,
                    vmstate: target.vmstate.identity,
                });
        }
    }

    fn publish_one_node_raw_checkpoint(
        run_state_root: &Path,
    ) -> (ScenarioDefForm, ContentHash, NodeId, ContentHash) {
        let node = NodeId {
            name: String::from("vm-a"),
        };
        let world = World::from_nodes(vec![crucible::WorldNode {
            id: node.clone(),
            arch: VmArchitecture::X86_64,
            memory_mib: 128,
            cmdline: String::new(),
            ready_point: crucible::ReadyPoint::FixedIcount {
                icount: Icount { retired: 0 },
            },
            white_box: crucible::WhiteBoxPolicy::Disabled,
            smp_vcpus: 1,
            icount_shift: 0,
            kernel: None,
            root_image: None,
            initrd: None,
        }])
        .expect("build one-node checkpoint world");
        let source = ScenarioDefForm::from_components_with_app_random_draw_cap(
            &world,
            &crucible::Plan::empty(),
            &crucible::Properties::empty(),
            Seed::from_u64(0x4f52_4143),
            0,
        )
        .expect("build one-node checkpoint scenario");
        let scenario = source.scenario_def();
        let runtime_scenario = SchedulerLivenessScenario::from_runnable_world(
            &scenario.id().to_hex(),
            Shift::new(0).expect("zero shift validates"),
            4,
            SimInstant { nanos: 4 },
            0,
            source.world(),
        )
        .with_scenario_def(scenario.clone());
        let scheduler = SingleScheduler::new(runtime_scenario).expect("build one-node scheduler");
        let scheduler_checkpoint = scheduler
            .checkpoint()
            .expect("checkpoint one-node scheduler");

        let nodes = ProductionNodeSet::new();
        let fault_runtime = ProductionFaultRuntime::new(
            source.plan().fault_signals().clone(),
            None,
            SignalBoundarySnapshot::default(),
            scenario.id(),
            super::super::fault_implementation::test_host_manifests(),
            &nodes,
        )
        .expect("build inert one-node fault runtime");
        let fault_checkpoint = fault_runtime
            .checkpoint(&mut ProductionNodeSet::new())
            .expect("checkpoint inert fault runtime")
            .with_unvalidated_test_node(
                source.plan().fault_signals(),
                node.clone(),
                ContentHash::from_bytes(b"one-node execution fingerprint"),
            )
            .expect("bind synthetic node fingerprint");

        let configuration = Configuration {
            def: scenario.clone(),
            schedule: Schedule::empty(),
        };
        let modeled_checkpoint = Checkpoint::from_recorded_configuration(
            &configuration,
            None,
            VirtualTime { ticks: 0 },
            BTreeMap::from([(node.clone(), Icount { retired: 0 })]),
            CheckpointKind::Fat,
            BTreeMap::new(),
        )
        .expect("build one-node modeled checkpoint");
        let snapshot =
            QemuVmSnapshot::diskless(modeled_checkpoint, QemuReplayOracleValidation::NotRun)
                .expect("build raw one-node QEMU snapshot");
        let snapshot_identity = snapshot.id();

        let overlay = run_state_root.join("raw-overlay.qcow2");
        let vmstate = run_state_root.join("raw-vmstate.bin");
        fs::write(&overlay, b"overlay fixture").expect("write overlay fixture");
        fs::write(&vmstate, b"vmstate fixture").expect("write VMState fixture");
        let overlay_artifact = ProductionCheckpointArtifact {
            source: ProductionCheckpointArtifactSource::File(overlay.clone()),
            identity: hash_file(&overlay).expect("hash overlay fixture"),
            length: fs::metadata(&overlay)
                .expect("inspect overlay fixture")
                .len(),
            chunks: Vec::new(),
        };
        let vmstate_artifact = ProductionCheckpointArtifact {
            source: ProductionCheckpointArtifactSource::File(vmstate.clone()),
            identity: hash_file(&vmstate).expect("hash VMState fixture"),
            length: fs::metadata(&vmstate)
                .expect("inspect VMState fixture")
                .len(),
            chunks: Vec::new(),
        };
        let manifest_identity =
            exact_checkpoint_target_manifest_identity(ExactCheckpointTargetManifestBasis {
                configuration: configuration.id(),
                node: &node,
                counter: 0,
                scheduler_time: VirtualTime { ticks: 0 },
                snapshot: snapshot_identity,
                fault_identity: fault_checkpoint.id(),
                overlay: overlay_artifact.identity,
                vmstate: vmstate_artifact.identity,
            });
        let mut checkpoint = ProductionVmExactCheckpointSet {
            identity: ContentHash::default(),
            configuration,
            scheduler: scheduler_checkpoint,
            event_log_objects: BTreeMap::new(),
            signal_artifact_objects: BTreeMap::new(),
            trigger_state: EventGraphState::default(),
            assertion_state: HostAssertionEvaluator::new(source.properties()).checkpoint(),
            terminal_verdict: None,
            terminal_cause: None,
            initial_lifecycle_observations_pending: true,
            branch: None,
            recorded_controls: Vec::new(),
            fault_checkpoint: Some(fault_checkpoint),
            targets: BTreeMap::from([(
                node.clone(),
                ProductionVmExactCheckpointTarget {
                    configuration: Configuration {
                        def: scenario,
                        schedule: Schedule::empty(),
                    },
                    counter: 0,
                    scheduler_time: VirtualTime { ticks: 0 },
                    snapshot,
                    overlay_artifact,
                    vmstate_artifact,
                    manifest_identity,
                },
            )]),
            node_generations: BTreeMap::from([(node.clone(), 1)]),
            node_service_states: BTreeMap::from([(
                node.clone(),
                ProductionNodeServiceState::Running,
            )]),
        };
        let prepared = prepare_exact_checkpoint_set(
            run_state_root,
            source.scenario_def().id(),
            source.plan().fault_signals().resource_limits(),
            &mut checkpoint,
        )
        .expect("prepare one-node production checkpoint");
        let identity = prepared.identity();
        prepared
            .publish()
            .expect("publish one-node production checkpoint");
        (source, identity, node, snapshot_identity)
    }

    fn regular_file_count(path: &Path) -> usize {
        let Ok(entries) = fs::read_dir(path) else {
            return 0;
        };
        entries
            .filter_map(Result::ok)
            .map(|entry| {
                if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                    regular_file_count(&entry.path())
                } else {
                    usize::from(entry.file_type().is_ok_and(|kind| kind.is_file()))
                }
            })
            .sum()
    }

    #[test]
    fn closure_manifest_round_trip_is_canonical() {
        let mut original = manifest();
        original.targets = vec![target("a"), target("b")];
        original.node_generations = vec![(String::from("a"), 1), (String::from("b"), 2)];
        original.node_service_states = vec![(String::from("a"), 1), (String::from("b"), 2)];

        let bytes = encode_manifest(&original).expect("encode canonical closure manifest");
        let decoded = decode_manifest(&bytes).expect("decode canonical closure manifest");

        assert_eq!(
            encode_manifest(&decoded).expect("re-encode canonical closure manifest"),
            bytes
        );
    }

    #[test]
    fn closure_manifest_rejects_unsorted_or_trailing_records() {
        let mut unsorted = manifest();
        unsorted.targets = vec![target("b"), target("a")];
        let bytes = encode_manifest(&unsorted).expect("encode fixture");
        assert!(decode_manifest(&bytes).is_err());

        let mut trailing = encode_manifest(&manifest()).expect("encode fixture");
        trailing.push(0);
        assert!(decode_manifest(&trailing).is_err());
    }

    #[test]
    fn closure_identity_excludes_only_its_identity_field() {
        let mut original = manifest();
        let identity = closure_identity(&original).expect("derive closure identity");
        original.identity = ContentHash::from_bytes(b"ignored identity field");
        assert_eq!(
            closure_identity(&original).expect("derive closure identity again"),
            identity
        );
        original.frontier = 1;
        assert_ne!(
            closure_identity(&original).expect("derive changed closure identity"),
            identity
        );
    }

    #[test]
    fn replay_oracle_manifest_promotion_changes_only_target_snapshots() {
        let mut source = manifest();
        source.targets = vec![target("a"), target("b")];
        refresh_target_manifest_identities(&mut source);
        source.identity = closure_identity(&source).expect("derive raw closure identity");
        let mut promoted = source.clone();
        promoted.targets[0].snapshot = ContentHash::from_bytes(b"promoted-a");
        promoted.targets[1].snapshot = ContentHash::from_bytes(b"promoted-b");
        refresh_target_manifest_identities(&mut promoted);
        promoted.identity = closure_identity(&promoted).expect("derive promoted closure identity");

        validate_replay_oracle_manifest_basis(&source, &promoted)
            .expect("snapshot-only promotion should preserve the production basis");

        let mut changed_artifact = promoted.clone();
        changed_artifact.targets[0].overlay.length += 1;
        assert!(validate_replay_oracle_manifest_basis(&source, &changed_artifact).is_err());

        let unchanged = source.clone();
        assert!(validate_replay_oracle_manifest_basis(&source, &unchanged).is_err());

        let mut missing_target = promoted;
        missing_target.targets.pop();
        assert!(validate_replay_oracle_manifest_basis(&source, &missing_target).is_err());
    }

    #[test]
    fn replay_oracle_source_pair_is_bound_to_every_exact_snapshot() {
        let scenario = ScenarioDef::from_canonical_material(
            "crucible.test.production-replay-oracle-pair",
            "scenario",
        );
        let configuration = Configuration::genesis(scenario.clone());
        let checkpoint = Checkpoint::from_recorded_configuration(
            &configuration,
            None,
            VirtualTime::default(),
            BTreeMap::new(),
            CheckpointKind::Fat,
            BTreeMap::new(),
        )
        .expect("build replay-oracle checkpoint fixture");
        let raw = QemuVmSnapshot::diskless(checkpoint.clone(), QemuReplayOracleValidation::NotRun)
            .expect("build raw production snapshot");
        let runtime_hash = ContentHash::from_bytes(b"matching production runtime");
        let promoted = QemuVmSnapshot::diskless(
            checkpoint,
            QemuReplayOracleValidation::Match { runtime_hash },
        )
        .expect("build promoted production snapshot");
        let mut basis = manifest();
        basis.scenario = scenario.id();
        basis.configuration = configuration.id();
        basis.targets = vec![target("vm-a")];
        let source = snapshot_portable(basis.clone(), &raw);
        let promoted = snapshot_portable(basis, &promoted);

        authenticate_replay_oracle_source_pair(
            &source,
            &promoted,
            FaultResourceLimits::default(),
            ContentHash::default(),
            &mut || Ok(()),
        )
        .expect("exact raw-to-match source pair should authenticate");

        let foreign_configuration = Configuration::genesis(ScenarioDef::from_canonical_material(
            "crucible.test.production-replay-oracle-pair",
            "foreign",
        ));
        let foreign_checkpoint = Checkpoint::from_recorded_configuration(
            &foreign_configuration,
            None,
            VirtualTime::default(),
            BTreeMap::new(),
            CheckpointKind::Fat,
            BTreeMap::new(),
        )
        .expect("build foreign checkpoint fixture");
        let foreign = QemuVmSnapshot::diskless(
            foreign_checkpoint,
            QemuReplayOracleValidation::Match { runtime_hash },
        )
        .expect("build foreign promoted snapshot");
        let foreign = snapshot_portable(
            decode::decode_manifest_with_limits(source.manifest(), FaultResourceLimits::default())
                .expect("decode source manifest fixture"),
            &foreign,
        );
        assert!(
            authenticate_replay_oracle_source_pair(
                &source,
                &foreign,
                FaultResourceLimits::default(),
                ContentHash::default(),
                &mut || Ok(()),
            )
            .is_err()
        );
    }

    #[test]
    fn production_replay_oracle_promotion_is_no_write_and_restart_authenticatable() {
        std::thread::Builder::new()
            .name(String::from("production-replay-oracle-promotion"))
            .stack_size(32 * 1024 * 1024)
            .spawn(run_production_replay_oracle_promotion_test)
            .expect("spawn large-stack production promotion test")
            .join()
            .expect("production promotion test should not panic");
    }

    fn run_production_replay_oracle_promotion_test() {
        let source_store = tempfile::tempdir().expect("create raw production store");
        let (source, raw_identity, node, raw_snapshot) =
            publish_one_node_raw_checkpoint(source_store.path());
        let raw = open_exact_checkpoint_closure(source_store.path(), &source, raw_identity)
            .expect("open raw production closure");
        raw.validate_complete()
            .expect("raw production closure should authenticate");
        let files_before = regular_file_count(source_store.path());
        let checks = BTreeMap::from([(
            node.clone(),
            QemuReplayOracleCheck::from_unvalidated_test_result(
                raw_snapshot,
                QemuReplayOracleValidation::Match {
                    runtime_hash: ContentHash::from_bytes(b"matching production runtime"),
                },
            ),
        )]);

        let promotion = raw
            .prepare_replay_oracle_promotion(&checks)
            .expect("prepare source-bound production promotion");
        assert_eq!(promotion.source(), raw_identity);
        assert_ne!(promotion.promoted(), raw_identity);
        assert_eq!(regular_file_count(source_store.path()), files_before);

        let promoted_store = tempfile::tempdir().expect("create promoted production store");
        let promoted_identity = promotion.promoted();
        install_exact_checkpoint_closure(promoted_store.path(), &source, &promotion)
            .expect("install promoted production closure");
        let promoted =
            open_exact_checkpoint_closure(promoted_store.path(), &source, promoted_identity)
                .expect("open promoted production closure");
        raw.authenticate_replay_oracle_promotion(&promoted)
            .expect("restart validation should authenticate the exact root pair");
        authenticate_portable_exact_checkpoint_replay_oracle_promotion(&source, &raw, &promoted)
            .expect("portable restart validator should authenticate the exact root pair");

        let foreign_check = BTreeMap::from([(
            node,
            QemuReplayOracleCheck::from_unvalidated_test_result(
                ContentHash::from_bytes(b"foreign source snapshot"),
                QemuReplayOracleValidation::Match {
                    runtime_hash: ContentHash::from_bytes(b"matching production runtime"),
                },
            ),
        )]);
        assert!(raw.prepare_replay_oracle_promotion(&foreign_check).is_err());
        assert_eq!(regular_file_count(source_store.path()), files_before);
    }

    #[test]
    fn portable_closure_inventory_streams_only_authenticated_manifest_objects() {
        let root = tempfile::tempdir().expect("create portable closure root");
        let source = crucible::happy_path_scenario()
            .expect("build portable closure scenario")
            .scenario;
        let scenario = source.scenario_def().id();
        let bytes = b"deduplicated portable checkpoint object";
        let object_identity = ContentHash::from_bytes(bytes);
        let mut manifest = manifest();
        manifest.scenario = scenario;
        manifest.configuration = ContentHash::from_bytes(b"portable configuration");
        manifest.schedule = object_identity;
        manifest.scheduler = object_identity;
        manifest.trigger_state = object_identity;
        manifest.assertion_state = object_identity;
        manifest.lifecycle_state = object_identity;
        manifest.fault_checkpoint = object_identity;
        manifest.identity = closure_identity(&manifest).expect("derive portable closure identity");

        let object_directory = object_parent(root.path(), scenario);
        fs::create_dir_all(&object_directory).expect("create portable object directory");
        persist_object(&object_directory, object_identity, bytes).expect("persist portable object");
        let publication = closure_parent(root.path(), scenario).join(manifest.identity.to_hex());
        fs::create_dir_all(&publication).expect("create portable publication directory");
        fs::write(
            publication.join(MANIFEST_FILE),
            encode_manifest(&manifest).expect("encode portable manifest"),
        )
        .expect("write portable manifest");

        let closure = open_exact_checkpoint_closure(root.path(), &source, manifest.identity)
            .expect("open portable checkpoint closure");
        assert_eq!(closure.identity(), manifest.identity);
        assert_eq!(closure.scenario(), scenario);
        assert_eq!(closure.configuration(), manifest.configuration);
        assert_eq!(closure.objects().len(), 1);
        assert_eq!(closure.objects()[0].identity(), object_identity);
        let object_length = u64::try_from(bytes.len()).expect("fixture length fits");
        assert_eq!(closure.objects()[0].length(), object_length);
        let mut copied = Vec::new();
        assert_eq!(
            closure
                .copy_object_to(object_identity, &mut copied)
                .expect("stream portable object"),
            object_length
        );
        assert_eq!(copied, bytes);
        assert!(
            closure
                .copy_object_to(ContentHash::from_bytes(b"unlisted"), &mut Vec::new())
                .is_err()
        );

        fs::write(object_path(&object_directory, object_identity), b"changed")
            .expect("replace portable object fixture");
        assert!(
            closure
                .copy_object_to(object_identity, &mut Vec::new())
                .is_err()
        );
    }

    #[test]
    fn content_store_deduplicates_equal_objects() {
        let directory = tempfile::tempdir().expect("create object directory");
        let bytes = b"same object";
        let identity = ContentHash::from_bytes(bytes);

        persist_object(directory.path(), identity, bytes).expect("persist first object");
        persist_object(directory.path(), identity, bytes).expect("reuse equal object");
        let dag_store = LocalDagStore::new(directory.path());
        assert_eq!(
            dag_store
                .get(&identity)
                .expect("read exact object as DAG object"),
            bytes
        );
        assert!(!directory.path().join(identity.to_hex()).exists());
    }

    #[test]
    fn concurrent_equal_object_publishers_converge_atomically() {
        let directory = std::sync::Arc::new(tempfile::tempdir().expect("create object directory"));
        let bytes = b"concurrent object".to_vec();
        let identity = ContentHash::from_bytes(&bytes);
        let publishers = (0..8)
            .map(|_| {
                let directory = std::sync::Arc::clone(&directory);
                let bytes = bytes.clone();
                std::thread::spawn(move || persist_object(directory.path(), identity, &bytes))
            })
            .collect::<Vec<_>>();

        for publisher in publishers {
            publisher
                .join()
                .expect("publisher thread should not panic")
                .expect("equal publisher should converge");
        }
        validate_file_hash(&object_path(directory.path(), identity), identity)
            .expect("published object should authenticate");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn file_artifact_materialization_streams_and_preserves_sparse_zero_extents() {
        let root = tempfile::tempdir().expect("create sparse materialization fixture");
        let source = root.path().join("source");
        let restored = root.path().join("restored");
        let length = 16 * 1024 * 1024_u64;
        let mut source_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&source)
            .expect("create sparse source");
        source_file.write_all(b"head").expect("write sparse head");
        source_file
            .seek(SeekFrom::Start(length - 4))
            .expect("seek sparse tail");
        source_file.write_all(b"tail").expect("write sparse tail");
        source_file.sync_all().expect("flush sparse source");
        drop(source_file);

        let identity = hash_file(&source).expect("hash sparse source");
        let artifact = ProductionCheckpointArtifact {
            source: ProductionCheckpointArtifactSource::File(source.clone()),
            identity,
            length,
            chunks: Vec::new(),
        };
        materialize_checkpoint_artifact(&artifact, &restored, "sparse test")
            .expect("materialize sparse source");

        assert_eq!(hash_file(&restored).expect("hash sparse result"), identity);
        let metadata = fs::metadata(&restored).expect("inspect sparse result");
        assert_eq!(metadata.len(), length);
        assert!(metadata.blocks().saturating_mul(512) < length);

        fs::remove_file(&restored).expect("remove sparse result");
        let mut changed = OpenOptions::new()
            .write(true)
            .open(source)
            .expect("reopen sparse source");
        changed.write_all(b"fail").expect("change sparse source");
        changed.sync_all().expect("flush changed sparse source");
        assert!(
            materialize_checkpoint_artifact(&artifact, &restored, "changed sparse test").is_err()
        );
        assert!(!restored.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn chunked_artifact_materialization_recreates_sparse_zero_extents() {
        let root = tempfile::tempdir().expect("create sparse chunk fixture");
        let source = root.path().join("source");
        let restored = root.path().join("restored");
        let object_directory = root.path().join("objects");
        fs::create_dir(&object_directory).expect("create object directory");
        let length = 16 * 1024 * 1024_u64;
        let mut source_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&source)
            .expect("create sparse source");
        source_file.write_all(b"head").expect("write sparse head");
        source_file
            .seek(SeekFrom::Start(length - 4))
            .expect("seek sparse tail");
        source_file.write_all(b"tail").expect("write sparse tail");
        source_file.sync_all().expect("flush sparse source");
        drop(source_file);

        let identity = hash_file(&source).expect("hash sparse source");
        let source_artifact = ProductionCheckpointArtifact {
            source: ProductionCheckpointArtifactSource::File(source),
            identity,
            length,
            chunks: Vec::new(),
        };
        let manifest = artifact_manifest(&source_artifact).expect("derive sparse chunk manifest");
        persist_chunked_artifact(&object_directory, &manifest, &source_artifact)
            .expect("persist sparse chunks");
        let chunked = ProductionCheckpointArtifact {
            source: ProductionCheckpointArtifactSource::ChunkStore(object_directory),
            identity,
            length,
            chunks: manifest.chunks,
        };
        materialize_checkpoint_artifact(&chunked, &restored, "sparse chunk test")
            .expect("materialize sparse chunks");

        assert_eq!(hash_file(&restored).expect("hash sparse result"), identity);
        let metadata = fs::metadata(&restored).expect("inspect sparse result");
        assert_eq!(metadata.len(), length);
        assert!(metadata.blocks().saturating_mul(512) < length);
    }

    #[test]
    fn chunk_store_deduplicates_and_materializes_complete_artifacts() {
        let root = tempfile::tempdir().expect("create chunk-store fixture");
        let source = root.path().join("source");
        let restored = root.path().join("restored");
        let object_directory = root.path().join("objects");
        fs::create_dir(&object_directory).expect("create object directory");
        let mut bytes = vec![0x5a; ARTIFACT_CHUNK_BYTES];
        bytes.extend_from_slice(b"tail");
        fs::write(&source, &bytes).expect("write source artifact");
        let artifact = ProductionCheckpointArtifact {
            source: ProductionCheckpointArtifactSource::File(source),
            identity: ContentHash::from_bytes(&bytes),
            length: u64::try_from(bytes.len()).expect("fixture length fits"),
            chunks: Vec::new(),
        };
        let manifest = artifact_manifest(&artifact).expect("derive chunk manifest");

        persist_chunked_artifact(&object_directory, &manifest, &artifact)
            .expect("persist first artifact");
        persist_chunked_artifact(&object_directory, &manifest, &artifact)
            .expect("deduplicate second artifact");
        let stored_count = fs::read_dir(&object_directory)
            .expect("read object directory")
            .map(|entry| {
                fs::read_dir(entry.expect("read object prefix entry").path())
                    .expect("read object prefix directory")
                    .count()
            })
            .sum::<usize>();
        assert_eq!(stored_count, 2);

        let chunked = ProductionCheckpointArtifact {
            source: ProductionCheckpointArtifactSource::ChunkStore(object_directory.clone()),
            identity: manifest.identity,
            length: manifest.length,
            chunks: manifest.chunks.clone(),
        };
        let mut streamed = Vec::new();
        ProductionVmNodeCheckpointArtifact {
            artifact: &chunked,
            role: "test",
        }
        .stream_into(&mut streamed)
        .expect("stream authenticated chunked artifact");
        assert_eq!(streamed, bytes);
        materialize_checkpoint_artifact(&chunked, &restored, "test")
            .expect("materialize chunked artifact");
        assert_eq!(fs::read(&restored).expect("read restored artifact"), bytes);

        let first_chunk = object_path(&object_directory, manifest.chunks[0]);
        fs::write(&first_chunk, vec![0; ARTIFACT_CHUNK_BYTES])
            .expect("corrupt first checkpoint chunk");
        let mut rejected_stream = Vec::new();
        assert!(
            ProductionVmNodeCheckpointArtifact {
                artifact: &chunked,
                role: "corrupt test",
            }
            .stream_into(&mut rejected_stream)
            .is_err()
        );
        fs::remove_file(&restored).expect("remove prior materialization");
        assert!(materialize_checkpoint_artifact(&chunked, &restored, "test").is_err());
        assert!(!restored.exists());
        fs::write(&first_chunk, &bytes[..ARTIFACT_CHUNK_BYTES])
            .expect("restore first checkpoint chunk");

        let last_chunk = object_path(
            &object_directory,
            *manifest.chunks.last().expect("fixture has a tail chunk"),
        );
        fs::remove_file(last_chunk).expect("remove tail checkpoint chunk");
        assert!(!restored.exists());
        assert!(materialize_checkpoint_artifact(&chunked, &restored, "test").is_err());
        assert!(!restored.exists());
    }

    #[test]
    fn lifecycle_wire_restores_terminal_branch_and_controls() {
        let scenario = crucible::happy_path_scenario()
            .expect("build lifecycle wire scenario")
            .scenario
            .scenario_def();
        let schedule = Schedule::empty().to_compact_binary();
        let wire = LifecycleWire {
            terminal: Some(TerminalWire::Failed(vec![String::from("failed")])),
            terminal_cause: Some(TerminalCauseWire::Failed(vec![String::from("failed")])),
            initial_lifecycle_observations_pending: false,
            branch: Some(BranchWire {
                base_schedule: schedule.clone(),
                frontier: 7,
                decisions: Vec::new(),
                seed: Some(Seed::from_u64(9).bytes()),
            }),
            recorded_controls: vec![RecordedControlWire {
                configuration_schedule: schedule,
                node_times: Vec::new(),
                control: vec![ControlOperation {
                    sequence: 1,
                    kind: crucible::ControlOperationKind::Snapshot,
                }],
            }],
        };
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&wire, &mut bytes).expect("encode lifecycle fixture");

        let decoded = decode_lifecycle(&bytes, &scenario, FaultResourceLimits::default())
            .expect("decode lifecycle fixture");

        assert_eq!(
            decoded.terminal,
            Some(QuantumTerminalVerdict::Failed(vec![String::from("failed")]))
        );
        assert!(!decoded.initial_lifecycle_observations_pending);
        assert_eq!(
            decoded.terminal_cause,
            Some(CheckpointTerminalCause::Failed(vec![String::from(
                "failed"
            )]))
        );
        let branch = decoded.branch.expect("branch should restore");
        assert_eq!(branch.frontier, VirtualTime { ticks: 7 });
        assert_eq!(branch.seed, Some(Seed::from_u64(9)));
        assert_eq!(decoded.recorded_controls.len(), 1);
        assert_eq!(decoded.recorded_controls[0].control[0].sequence, 1);
    }
}

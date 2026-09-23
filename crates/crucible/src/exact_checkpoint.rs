//! Canonical exact-checkpoint relations shared by storage and launch.
//!
//! Storage uses the private canonical codecs in this module while consuming an
//! independently selected repository root. The resulting opaque relation binds
//! one target to the recomputed closure root, target manifest, snapshot,
//! artifacts, and ordered RAM chain. Persisted records alone carry no live
//! process authority.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{Checkpoint, Configuration, ContentHash, NodeId, SingleSchedulerCheckpoint};
pub use crucible_campaign::ExactCheckpointId;
use crucible_cas::content_envelope::ContentEnvelope;
use crucible_cas::content_store::{ContentId, ObjectKind};

mod codec;
mod decode;
mod repository;
mod semantics;
mod streams;

pub use repository::authenticate_exact_checkpoint_repository;
pub use semantics::ExactCheckpointSemanticObjectRole;
pub use streams::ExactCheckpointRestoreStreams;

use codec::*;

/// Maximum number of RAM layers in one authenticated production checkpoint.
pub const MAX_EXACT_CHECKPOINT_RAM_LAYERS: usize = 8;

/// Maximum canonical v9 closure-manifest size.
pub const MAX_EXACT_CHECKPOINT_MANIFEST_BYTES: usize = 64 * 1024 * 1024;

/// Current production exact-closure manifest schema version.
pub const PRODUCTION_EXACT_CLOSURE_SCHEMA_VERSION: u8 = 9;

const MANIFEST_MAGIC: &[u8] = b"crucible.production-exact-closure.v9\0";
const CLOSURE_DOMAIN: &str = "crucible.production-exact-closure.v9";
const TARGET_DOMAIN: &str = "crucible.production-vm-exact-checkpoint.v3";
const RAM_TARGET_DOMAIN: &str = "crucible.production-vm-exact-checkpoint.v2";
const SPARSE_ARTIFACT_DOMAIN: &str = "crucible.production-exact-sparse-artifact.v1";
const ARTIFACT_CHUNK_BYTES: u64 = 4 * 1024 * 1024;
const ROOT_SCHEMA: &str = "crucible.executor.exact-checkpoint-root";
const ROOT_SCHEMA_VERSION: u32 = 5;
const ROOT_BODY_BYTES: usize = 124;
const MANIFEST_ROLE: &str = "production-manifest";
const MANIFEST_SCHEMA_VERSION: u32 = 4;
const PROMOTION_SOURCE_ROLE: &str = "replay-oracle-source";
const PROMOTION_EVIDENCE_ROLE: &str = "replay-oracle-evidence";
const PROMOTION_EVIDENCE_SCHEMA_VERSION: u32 = 1;
const CHOICE_CLOSURE_ROLE: &str = "checkpoint-choice-closure";
const CHOICE_CLOSURE_SCHEMA_VERSION: u32 = 1;
const INDEX_ROLE_PREFIX: &str = "production-object-index-";
const INDEX_SCHEMA: &str = "crucible.executor.production-checkpoint-index";
const INDEX_SCHEMA_VERSION: u32 = 1;
const INDEX_MAGIC: &[u8; 8] = b"CRUCPIDX";
const INDEX_PAGE_OBJECTS: usize = 4_096;
const MAX_INDEX_BYTES: usize = 4 * 1024 * 1024;
const OBJECT_ROLE_PREFIX: &str = "object-";
const OBJECT_SCHEMA_VERSION: u32 = 5;

/// Direct or parent-relative RAM content in an exact checkpoint.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ExactCheckpointRamKind {
    /// Complete RAM image.
    Direct,
    /// Delta relative to the preceding exact RAM identity.
    Delta,
}

/// QEMU checkpoint, target, and scheduler-frontier identity.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct ExactCheckpointIdentity {
    /// Checkpoint identity.
    pub checkpoint: ContentHash,
    /// QEMU target identity.
    pub target: ContentHash,
    /// Scheduler-frontier identity.
    pub frontier: ContentHash,
}

/// One canonical sparse-artifact extent.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct ExactCheckpointArtifactExtent {
    /// First logical chunk in this extent.
    pub start_chunk: u64,
    /// Consecutive content-addressed chunks.
    #[serde(deserialize_with = "decode::deserialize_vec")]
    pub chunks: Vec<ContentHash>,
}

/// Content-addressed artifact geometry recorded by a closure manifest.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct ExactCheckpointArtifactRecord {
    /// Canonical artifact identity.
    pub identity: ContentHash,
    /// Logical artifact length.
    pub length: u64,
    /// Dense artifact chunks in logical order.
    #[serde(deserialize_with = "decode::deserialize_vec")]
    pub chunks: Vec<ContentHash>,
    /// Whether omitted chunks have the canonical meaning of zeroes.
    #[serde(default, skip_serializing_if = "is_false")]
    pub sparse: bool,
    /// Sparse changed-chunk extents.
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "decode::deserialize_vec"
    )]
    pub extents: Vec<ExactCheckpointArtifactExtent>,
}

/// One RAM layer and its authenticated artifact relation.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct ExactCheckpointRamLayerRecord {
    /// Direct or delta encoding.
    pub kind: ExactCheckpointRamKind,
    /// Identity committed by QEMU for this layer.
    pub identity: ExactCheckpointIdentity,
    /// Required preceding identity for a delta.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<ExactCheckpointIdentity>,
    /// Canonical RAMBlock topology identity.
    pub topology: ContentHash,
    /// Number of RAMBlock regions.
    pub ram_regions: u64,
    /// Number of encoded RAM records.
    pub ram_records: u64,
    /// SHA-256 QEMU must authenticate while restoring.
    pub content_sha256: ContentHash,
    /// Content-addressed RAM artifact.
    pub artifact: ExactCheckpointArtifactRecord,
}

/// Direct-plus-delta RAM and device-state relation.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct ExactCheckpointRamRecord {
    /// Retained ancestor closure when the chain contains deltas.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_closure: Option<ContentHash>,
    /// SHA-256 QEMU must authenticate for device VMState.
    pub device_content_sha256: ContentHash,
    /// Content-addressed device VMState artifact.
    pub device: ExactCheckpointArtifactRecord,
    /// Ordered direct-then-delta RAM layers.
    #[serde(deserialize_with = "decode::deserialize_vec")]
    pub layers: Vec<ExactCheckpointRamLayerRecord>,
}

/// Per-node target relation embedded in a closure manifest.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct ExactCheckpointTargetRecord {
    /// Node name.
    #[serde(deserialize_with = "decode::deserialize_string")]
    pub node: String,
    /// Immutable root-image identity.
    pub immutable_backing: ContentHash,
    /// Node instruction counter.
    pub counter: u64,
    /// Scheduler virtual-time tick.
    pub scheduler_time: u64,
    /// Canonical QEMU snapshot identity.
    pub snapshot: ContentHash,
    /// Sparse writable-root overlay.
    pub overlay: ExactCheckpointArtifactRecord,
    /// Exact device and RAM relation.
    pub exact_ram: ExactCheckpointRamRecord,
    /// Claimed per-node manifest identity.
    pub manifest_identity: ContentHash,
}

/// Failed-node host-I/O relation embedded in a closure manifest.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct ExactCheckpointFailedHostIoRecord {
    /// Node name.
    #[serde(deserialize_with = "decode::deserialize_string")]
    pub node: String,
    /// Failed execution binding.
    pub execution_binding: ContentHash,
    /// Host-I/O checkpoint identity.
    pub checkpoint: ContentHash,
    /// Fingerprint coordinate.
    pub fingerprint_at: u64,
    /// Fingerprint identity.
    pub fingerprint: ContentHash,
}

/// One authenticated native object in the complete closure inventory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ExactCheckpointObjectRecord {
    /// Native BLAKE3 content identity referenced by the closure manifest.
    pub identity: ContentHash,
    /// Exact immutable object length.
    pub length: u64,
}

/// Complete canonical v9 closure record used to authenticate a target.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct ExactCheckpointClosureRecord {
    /// Scenario identity.
    pub scenario: ContentHash,
    /// Configuration identity.
    pub configuration: ContentHash,
    /// Schedule identity.
    pub schedule: ContentHash,
    /// Scheduler frontier.
    pub frontier: u64,
    /// Scheduler continuation identity.
    pub scheduler: ContentHash,
    /// Ordered event-log segment identities.
    #[serde(deserialize_with = "decode::deserialize_vec")]
    pub event_log_segments: Vec<ContentHash>,
    /// Sorted signal-artifact identities.
    #[serde(deserialize_with = "decode::deserialize_vec")]
    pub signal_artifacts: Vec<ContentHash>,
    /// Trigger continuation identity.
    pub trigger_state: ContentHash,
    /// Assertion continuation identity.
    pub assertion_state: ContentHash,
    /// VM lifecycle continuation identity.
    pub lifecycle_state: ContentHash,
    /// Fault continuation identity.
    pub fault_checkpoint: ContentHash,
    /// Strictly node-sorted exact targets.
    #[serde(deserialize_with = "decode::deserialize_vec")]
    pub targets: Vec<ExactCheckpointTargetRecord>,
    /// Strictly node-sorted failed host-I/O records.
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "decode::deserialize_vec"
    )]
    pub failed_host_io: Vec<ExactCheckpointFailedHostIoRecord>,
    /// Strictly node-sorted generation counters.
    #[serde(deserialize_with = "decode::deserialize_string_u64_vec")]
    pub node_generations: Vec<(String, u64)>,
    /// Strictly node-sorted service-state tags.
    #[serde(deserialize_with = "decode::deserialize_string_u8_vec")]
    pub node_service_states: Vec<(String, u8)>,
    /// Claimed canonical closure identity.
    pub identity: ContentHash,
    /// Complete sorted immutable-object inventory authenticated beside the manifest.
    #[serde(skip)]
    pub objects: Vec<ExactCheckpointObjectRecord>,
}

/// Repository-authenticated closure awaiting one semantic-object traversal.
#[derive(Debug, PartialEq, Eq)]
pub struct ExactCheckpointClosureBinding {
    repository: Arc<ExactCheckpointRepositoryBinding>,
    closure: ExactCheckpointClosureRecord,
    targets: Vec<Option<ExactCheckpointTargetRecord>>,
    target_index: BTreeMap<ContentHash, usize>,
}

/// Closure whose semantic object bytes were authenticated and traversed once.
#[derive(Debug, PartialEq, Eq)]
pub struct ExactCheckpointTraversedClosureBinding {
    closure: ExactCheckpointClosureBinding,
    fault_semantic_identity: ContentHash,
}

/// Structural repository relation for one exact-checkpoint target.
///
/// This claim carries no process or launch authority. The API restore
/// coordinator must pair it with concretely decoded semantic state, and QEMU
/// must consume the resulting execution binding with a presealed process
/// contract.
#[derive(Debug, PartialEq, Eq)]
pub struct ExactCheckpointStructuralTargetClaim {
    repository: Arc<ExactCheckpointRepositoryBinding>,
    configuration: ContentHash,
    fault_semantic_identity: ContentHash,
    target: Arc<ExactCheckpointTargetRecord>,
}

/// Structurally verified node relation and its final producer identity.
///
/// This value carries no process or launch authority. The API coordinator must
/// combine it with its private concrete semantic admission, and QEMU must also
/// require the supervisor-presealed process contract for the same root.
#[derive(Debug, PartialEq, Eq)]
pub struct ExactCheckpointVerifiedNode {
    target: ExactCheckpointStructuralTargetClaim,
}

/// Incremental verifier for one repository-bound sparse root overlay.
///
/// The verifier reconstructs the canonical sparse extent map from the logical
/// byte stream. It hashes every nonzero 4 MiB chunk and compares the resulting
/// sparse artifact identity with the target relation at completion.
#[derive(Debug)]
pub struct ExactCheckpointRootOverlayVerifier {
    target: Arc<ExactCheckpointTargetRecord>,
    expected_length: u64,
    observed_length: u64,
    next_chunk: u64,
    chunk: Vec<u8>,
    expected_extent: usize,
    expected_extent_chunk: usize,
}

/// Repository-authenticated production root and complete object inventory.
#[derive(Debug, PartialEq, Eq)]
pub struct ExactCheckpointRepositoryBinding {
    root: ExactCheckpointId,
    production_identity: ContentHash,
    scenario: ContentHash,
    configuration: ContentHash,
    manifest_id: ContentId,
    manifest_bytes: u64,
    objects: Vec<RepositoryObjectBinding>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RepositoryObjectBinding {
    identity: ContentHash,
    content: ContentId,
    length: u64,
}

impl ExactCheckpointClosureBinding {
    /// Consumes and visits every authenticated semantic object once.
    ///
    /// Each object is opened, bounded, hashed, delivered, and closed before
    /// the next object is opened. Shared object identities count once against
    /// `byte_limit` while each semantic role is still delivered.
    /// The visitor returns the decoded semantic identity for the fault
    /// continuation and `None` for every other role. The resulting target
    /// claims retain that identity for QMP RAM provenance authentication.
    ///
    /// # Errors
    ///
    /// Returns [`ExactCheckpointExecutionSourceError`] when an object is
    /// unavailable, has the wrong length or identity, exceeds the aggregate
    /// limit, or either callback rejects the operation.
    pub fn visit_semantic_objects(
        self,
        byte_limit: u64,
        boundary: impl FnMut() -> std::io::Result<()>,
        open: impl FnMut(ContentHash) -> std::io::Result<Box<dyn std::io::Read + Send>>,
        visit: impl FnMut(
            ExactCheckpointSemanticObjectRole<'_>,
            &[u8],
        ) -> std::io::Result<Option<ContentHash>>,
    ) -> Result<ExactCheckpointTraversedClosureBinding, ExactCheckpointExecutionSourceError> {
        let fault_semantic_identity = semantics::visit_authenticated_semantic_objects(
            &self.repository,
            &self.closure,
            &self.targets,
            byte_limit,
            boundary,
            open,
            visit,
        )?;

        Ok(ExactCheckpointTraversedClosureBinding {
            closure: self,
            fault_semantic_identity,
        })
    }
}

impl ExactCheckpointTraversedClosureBinding {
    /// Removes the one authenticated target claim for `node`.
    ///
    /// # Errors
    ///
    /// Returns [`ExactCheckpointRelationError::TargetMembership`] when the
    /// node has no remaining target claim in this closure.
    pub fn take_target(
        &mut self,
        node: &NodeId,
    ) -> Result<ExactCheckpointStructuralTargetClaim, ExactCheckpointRelationError> {
        let identity = ContentHash::from_canonical_material(
            "crucible.exact-checkpoint.target-node-index.v1",
            &node.name,
        );
        let index = self
            .closure
            .target_index
            .remove(&identity)
            .ok_or(ExactCheckpointRelationError::TargetMembership)?;
        let target = self
            .closure
            .targets
            .get_mut(index)
            .and_then(Option::take)
            .filter(|target| target.node == node.name)
            .ok_or(ExactCheckpointRelationError::TargetMembership)?;

        Ok(ExactCheckpointStructuralTargetClaim {
            repository: Arc::clone(&self.closure.repository),
            configuration: self.closure.closure.configuration,
            fault_semantic_identity: self.fault_semantic_identity,
            target: Arc::new(target),
        })
    }
}

impl ExactCheckpointStructuralTargetClaim {
    /// Converts an authenticated structural claim into test-only replay evidence.
    ///
    /// This bypasses concrete execution-state authentication so process-free
    /// lifecycle tests can exercise consumers of a repository-bound claim.
    #[cfg(any(test, feature = "test-double"))]
    #[must_use]
    pub fn into_verified_node_for_test(self) -> ExactCheckpointVerifiedNode {
        ExactCheckpointVerifiedNode { target: self }
    }

    /// Returns the authenticated repository root enclosing this closure.
    #[must_use]
    fn repository_root(&self) -> ExactCheckpointId {
        self.repository.root
    }

    /// Returns the recomputed closure root.
    #[must_use]
    fn root(&self) -> ContentHash {
        self.repository.production_identity
    }

    /// Returns the recomputed target-manifest identity.
    #[must_use]
    fn target_manifest(&self) -> ContentHash {
        self.target.manifest_identity
    }

    /// Returns the bound node name.
    #[must_use]
    fn node(&self) -> &str {
        &self.target.node
    }

    /// Returns the bound configuration identity.
    #[must_use]
    fn snapshot(&self) -> ContentHash {
        self.target.snapshot
    }

    /// Returns the bound root-overlay identity and logical length.
    #[must_use]
    fn root_overlay(&self) -> (ContentHash, u64) {
        (self.target.overlay.identity, self.target.overlay.length)
    }

    /// Creates a verifier for the exact logical root-overlay byte stream.
    ///
    /// # Errors
    ///
    /// Returns [`ExactCheckpointRelationError::ResourceExhausted`] when the
    /// fixed chunk buffer cannot be allocated.
    fn root_overlay_verifier(
        &self,
    ) -> Result<ExactCheckpointRootOverlayVerifier, ExactCheckpointRelationError> {
        let mut chunk = Vec::new();
        chunk
            .try_reserve_exact(ARTIFACT_CHUNK_BYTES as usize)
            .map_err(|_| ExactCheckpointRelationError::ResourceExhausted)?;
        Ok(ExactCheckpointRootOverlayVerifier {
            target: self.target.clone(),
            expected_length: self.target.overlay.length,
            observed_length: 0,
            next_chunk: 0,
            chunk,
            expected_extent: 0,
            expected_extent_chunk: 0,
        })
    }

    /// Consumes this target after rederiving its final producer identity.
    ///
    /// # Errors
    ///
    /// Returns [`ExactCheckpointRelationError::TargetManifestMismatch`] when
    /// snapshot or scheduler semantics differ from the repository relation, or
    /// when the final checkpoint, target, or frontier digest differs.
    fn authenticate_execution(
        self,
        configuration: &Configuration,
        checkpoint: &Checkpoint,
        scheduler: &SingleSchedulerCheckpoint,
    ) -> Result<ExactCheckpointVerifiedNode, ExactCheckpointRelationError> {
        let node = NodeId {
            name: self.target.node.clone(),
        };
        let checkpoint_node_counter = checkpoint
            .node_icounts
            .get(&node)
            .map(|counter| counter.retired);
        let scheduler_configuration = scheduler
            .configuration_for(&configuration.def)
            .map_err(|_| ExactCheckpointRelationError::TargetManifestMismatch)?;
        if configuration.id() != self.configuration
            || checkpoint.configuration != self.configuration
            || checkpoint.scenario_ref != self.repository.scenario
            || checkpoint.virtual_time.ticks != self.target.scheduler_time
            || checkpoint_node_counter != Some(self.target.counter)
            || scheduler_configuration.id() != self.configuration
            || scheduler.frontier().ticks != self.target.scheduler_time
        {
            return Err(ExactCheckpointRelationError::TargetManifestMismatch);
        }

        let expected = final_ram_identity(
            self.configuration,
            &self.target,
            self.fault_semantic_identity,
            checkpoint.id,
            scheduler,
        )?;
        if self
            .target
            .exact_ram
            .layers
            .last()
            .map(|layer| layer.identity)
            != Some(expected)
        {
            return Err(ExactCheckpointRelationError::TargetManifestMismatch);
        }

        Ok(ExactCheckpointVerifiedNode { target: self })
    }

    /// Returns the bound device-state identity, SHA-256, and logical length.
    #[must_use]
    fn device_state(&self) -> (ContentHash, ContentHash, u64) {
        (
            self.target.exact_ram.device.identity,
            self.target.exact_ram.device_content_sha256,
            self.target.exact_ram.device.length,
        )
    }

    /// Returns the number of ordered RAM layers.
    #[must_use]
    fn ram_layer_count(&self) -> usize {
        self.target.exact_ram.layers.len()
    }

    /// Returns one ordered RAM-layer view.
    #[must_use]
    fn ram_layer(&self, index: usize) -> Option<ExactCheckpointRamLayerBinding<'_>> {
        self.target
            .exact_ram
            .layers
            .get(index)
            .map(|layer| ExactCheckpointRamLayerBinding { layer })
    }
}

impl ExactCheckpointStructuralTargetClaim {
    /// Authenticates execution state and opens its logical artifact streams.
    ///
    /// The opener receives only identities authenticated by the repository
    /// root. Dense and sparse artifact geometry remains private to this module;
    /// the returned stream set reconstructs each logical artifact in order.
    /// Callers should perform their sticky cancellation check inside `open`
    /// before opening each object.
    ///
    /// # Errors
    ///
    /// Returns [`ExactCheckpointExecutionSourceError::Relation`] when execution
    /// state differs from the target, or
    /// [`ExactCheckpointExecutionSourceError::Open`] when an authenticated
    /// object cannot be opened.
    pub fn authenticate_execution_and_open_streams(
        self,
        configuration: &Configuration,
        checkpoint: &Checkpoint,
        scheduler: &SingleSchedulerCheckpoint,
        open: impl Fn(ContentHash) -> std::io::Result<Box<dyn std::io::Read + Send>>
        + Send
        + Sync
        + 'static,
    ) -> Result<
        (ExactCheckpointVerifiedNode, ExactCheckpointRestoreStreams),
        ExactCheckpointExecutionSourceError,
    > {
        let execution = self.authenticate_execution(configuration, checkpoint, scheduler)?;
        let streams = streams::open_target_streams(execution.target.target.clone(), open)?;
        Ok((execution, streams))
    }
}

impl ExactCheckpointVerifiedNode {
    /// Returns the authenticated repository root enclosing this execution.
    #[must_use]
    pub fn repository_root(&self) -> ExactCheckpointId {
        self.target.repository_root()
    }

    /// Returns the recomputed closure root.
    #[must_use]
    pub fn root(&self) -> ContentHash {
        self.target.root()
    }

    /// Returns the recomputed target-manifest identity.
    #[must_use]
    pub fn target_manifest(&self) -> ContentHash {
        self.target.target_manifest()
    }

    /// Returns the bound node name.
    #[must_use]
    pub fn node(&self) -> &str {
        self.target.node()
    }

    /// Returns the bound snapshot identity.
    #[must_use]
    pub fn snapshot(&self) -> ContentHash {
        self.target.snapshot()
    }

    /// Authenticates the complete source relation before replay evidence is recorded.
    ///
    /// # Errors
    ///
    /// Returns [`ExactCheckpointRelationError::TargetManifestMismatch`] when
    /// the selected repository root, embedded production identity, target
    /// manifest, node, or snapshot differs from this verified node.
    pub fn authenticate_replay_source_relation(
        &self,
        repository_root: ExactCheckpointId,
        production_identity: ContentHash,
        target_manifest: ContentHash,
        node: &NodeId,
        snapshot: ContentHash,
    ) -> Result<(), ExactCheckpointRelationError> {
        if self.repository_root() != repository_root
            || self.root() != production_identity
            || self.target_manifest() != target_manifest
            || self.node() != node.name
            || self.snapshot() != snapshot
        {
            return Err(ExactCheckpointRelationError::TargetManifestMismatch);
        }

        Ok(())
    }

    /// Authenticates the immutable guest backing selected for this execution.
    ///
    /// # Errors
    ///
    /// Returns [`ExactCheckpointRelationError::TargetManifestMismatch`] when
    /// the selected backing bytes do not match the repository-bound target.
    pub fn authenticate_immutable_backing(
        &self,
        observed: ContentHash,
    ) -> Result<(), ExactCheckpointRelationError> {
        if observed != self.target.target.immutable_backing {
            return Err(ExactCheckpointRelationError::TargetManifestMismatch);
        }
        Ok(())
    }

    /// Returns the bound root-overlay identity and logical length.
    #[must_use]
    pub fn root_overlay(&self) -> (ContentHash, u64) {
        self.target.root_overlay()
    }

    /// Creates a verifier for the exact logical root-overlay byte stream.
    ///
    /// # Errors
    ///
    /// Returns [`ExactCheckpointRelationError::ResourceExhausted`] when the
    /// fixed chunk buffer cannot be allocated.
    pub fn root_overlay_verifier(
        &self,
    ) -> Result<ExactCheckpointRootOverlayVerifier, ExactCheckpointRelationError> {
        self.target.root_overlay_verifier()
    }

    /// Returns the bound device-state identity, SHA-256, and logical length.
    #[must_use]
    pub fn device_state(&self) -> (ContentHash, ContentHash, u64) {
        self.target.device_state()
    }

    /// Returns the number of ordered RAM layers.
    #[must_use]
    pub fn ram_layer_count(&self) -> usize {
        self.target.ram_layer_count()
    }

    /// Returns one ordered RAM-layer view.
    #[must_use]
    pub fn ram_layer(&self, index: usize) -> Option<ExactCheckpointRamLayerBinding<'_>> {
        self.target.ram_layer(index)
    }
}

impl ExactCheckpointRootOverlayVerifier {
    /// Adds the next contiguous bytes from the materialized overlay.
    ///
    /// # Errors
    ///
    /// Returns [`ExactCheckpointRelationError::InvalidStructure`] when the
    /// stream exceeds the target's authenticated logical length.
    pub fn update(&mut self, mut bytes: &[u8]) -> Result<(), ExactCheckpointRelationError> {
        let incoming = u64::try_from(bytes.len())
            .map_err(|_| ExactCheckpointRelationError::InvalidStructure)?;
        self.observed_length = self
            .observed_length
            .checked_add(incoming)
            .filter(|length| *length <= self.expected_length)
            .ok_or(ExactCheckpointRelationError::InvalidStructure)?;

        while !bytes.is_empty() {
            let remaining = (ARTIFACT_CHUNK_BYTES as usize) - self.chunk.len();
            let copied = remaining.min(bytes.len());
            self.chunk.extend_from_slice(&bytes[..copied]);
            bytes = &bytes[copied..];

            if self.chunk.len() == ARTIFACT_CHUNK_BYTES as usize {
                self.finish_chunk()?;
            }
        }

        Ok(())
    }

    /// Finishes the stream and authenticates its sparse artifact identity.
    ///
    /// # Errors
    ///
    /// Returns [`ExactCheckpointRelationError::InvalidStructure`] when the
    /// stream length or reconstructed sparse identity differs from the target.
    pub fn finish(mut self) -> Result<(), ExactCheckpointRelationError> {
        if self.observed_length != self.expected_length {
            return Err(ExactCheckpointRelationError::InvalidStructure);
        }
        if !self.chunk.is_empty() {
            self.finish_chunk()?;
        }

        if self.expected_nonzero_chunk().is_some() {
            return Err(ExactCheckpointRelationError::InvalidStructure);
        }

        Ok(())
    }

    fn finish_chunk(&mut self) -> Result<(), ExactCheckpointRelationError> {
        let chunk_index = self.next_chunk;
        self.next_chunk = self
            .next_chunk
            .checked_add(1)
            .ok_or(ExactCheckpointRelationError::InvalidStructure)?;
        let expected = self.expected_nonzero_chunk();
        if self.chunk.iter().all(|byte| *byte == 0) {
            if expected.is_some_and(|(index, _)| index == chunk_index) {
                return Err(ExactCheckpointRelationError::InvalidStructure);
            }
        } else {
            let identity = ContentHash::from_bytes(&self.chunk);
            if expected != Some((chunk_index, identity)) {
                return Err(ExactCheckpointRelationError::InvalidStructure);
            }
            self.advance_expected_nonzero_chunk()?;
        }
        self.chunk.clear();

        Ok(())
    }

    fn expected_nonzero_chunk(&self) -> Option<(u64, ContentHash)> {
        let extent = self.target.overlay.extents.get(self.expected_extent)?;
        let offset = u64::try_from(self.expected_extent_chunk).ok()?;
        let index = extent.start_chunk.checked_add(offset)?;
        extent
            .chunks
            .get(self.expected_extent_chunk)
            .copied()
            .map(|identity| (index, identity))
    }

    fn advance_expected_nonzero_chunk(&mut self) -> Result<(), ExactCheckpointRelationError> {
        let extent = self
            .target
            .overlay
            .extents
            .get(self.expected_extent)
            .ok_or(ExactCheckpointRelationError::InvalidStructure)?;
        self.expected_extent_chunk = self
            .expected_extent_chunk
            .checked_add(1)
            .ok_or(ExactCheckpointRelationError::InvalidStructure)?;
        if self.expected_extent_chunk == extent.chunks.len() {
            self.expected_extent = self
                .expected_extent
                .checked_add(1)
                .ok_or(ExactCheckpointRelationError::InvalidStructure)?;
            self.expected_extent_chunk = 0;
        }
        Ok(())
    }
}

/// Borrowed authenticated RAM-layer relation.
#[derive(Clone, Copy, Debug)]
pub struct ExactCheckpointRamLayerBinding<'a> {
    layer: &'a ExactCheckpointRamLayerRecord,
}

impl ExactCheckpointRamLayerBinding<'_> {
    /// Returns the checkpoint, target, and frontier identities.
    #[must_use]
    pub const fn identity(self) -> (ContentHash, ContentHash, ContentHash) {
        (
            self.layer.identity.checkpoint,
            self.layer.identity.target,
            self.layer.identity.frontier,
        )
    }

    /// Returns the RAMBlock topology identity.
    #[must_use]
    pub const fn topology(self) -> ContentHash {
        self.layer.topology
    }

    /// Returns the artifact identity, SHA-256, and logical length.
    #[must_use]
    pub const fn artifact(self) -> (ContentHash, ContentHash, u64) {
        (
            self.layer.artifact.identity,
            self.layer.content_sha256,
            self.layer.artifact.length,
        )
    }
}

/// Exact-checkpoint relation authentication failure.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ExactCheckpointRelationError {
    /// The closure collections or target geometry are malformed.
    #[error("exact-checkpoint closure has invalid canonical structure")]
    InvalidStructure,
    /// Canonical closure serialization exceeded its fixed bound.
    #[error("exact-checkpoint closure exceeds its canonical byte bound")]
    ManifestTooLarge,
    /// The claimed closure root does not match canonical content.
    #[error("exact-checkpoint closure root authentication failed")]
    RootMismatch,
    /// The repository root envelope does not authenticate this closure.
    #[error("exact-checkpoint repository root authentication failed")]
    RepositoryRootMismatch,
    /// The requested node is absent or appears more than once.
    #[error("exact-checkpoint target membership authentication failed")]
    TargetMembership,
    /// The selected target manifest does not match its complete relation.
    #[error("exact-checkpoint target-manifest authentication failed")]
    TargetManifestMismatch,
    /// Canonical CBOR serialization failed.
    #[error("exact-checkpoint canonical serialization failed")]
    CanonicalEncoding,
    /// A bounded verification buffer could not be allocated.
    #[error("exact-checkpoint verification buffer allocation failed")]
    ResourceExhausted,
}

/// Failure while binding canonical execution state to immutable object streams.
#[derive(Debug, Error)]
pub enum ExactCheckpointExecutionSourceError {
    /// The decoded execution state differs from the repository-rooted target.
    #[error(transparent)]
    Relation(#[from] ExactCheckpointRelationError),
    /// An authenticated immutable object could not be opened.
    #[error("open exact-checkpoint immutable object")]
    Open(#[from] std::io::Error),
}

/// Recomputes a closure root and authenticates every complete target relation.
///
/// The returned proof owns the complete target catalog. Callers cannot
/// substitute a snapshot, artifact, RAM layer, parent, or geometry value after
/// validation.
/// The decoder admits every owned allocation against `owned_byte_limit`, then
/// requires the input bytes to match the canonical v9 encoding exactly.
/// Storage separately authenticates the bytes named by each artifact; QEMU
/// rechecks those identities while consuming the proof.
///
/// # Errors
///
/// Returns [`ExactCheckpointRelationError`] for malformed collection or
/// artifact geometry, a noncanonical root, missing target membership, or a
/// target-manifest mismatch.
pub fn authenticate_exact_checkpoint_closure(
    repository: ExactCheckpointRepositoryBinding,
    manifest_bytes: &[u8],
    owned_byte_limit: u64,
) -> Result<ExactCheckpointClosureBinding, ExactCheckpointRelationError> {
    let payload = manifest_bytes
        .strip_prefix(MANIFEST_MAGIC)
        .ok_or(ExactCheckpointRelationError::InvalidStructure)?;
    if payload.len() > MAX_EXACT_CHECKPOINT_MANIFEST_BYTES
        || u64::try_from(manifest_bytes.len()).unwrap_or(u64::MAX) > owned_byte_limit
    {
        return Err(ExactCheckpointRelationError::ResourceExhausted);
    }
    let mut closure: ExactCheckpointClosureRecord =
        decode::decode_cbor_with_limit(payload, owned_byte_limit)?;
    closure
        .objects
        .try_reserve_exact(repository.objects.len())
        .map_err(|_| ExactCheckpointRelationError::ResourceExhausted)?;
    closure.objects.extend(
        repository
            .objects
            .iter()
            .map(|object| ExactCheckpointObjectRecord {
                identity: object.identity,
                length: object.length,
            }),
    );

    let canonical_manifest = exact_checkpoint_closure_bytes(&closure, manifest_bytes.len())?;
    if canonical_manifest != manifest_bytes {
        return Err(ExactCheckpointRelationError::InvalidStructure);
    }
    validate_closure_structure(&closure)?;

    let root = exact_checkpoint_closure_identity(&mut closure)?;
    if closure.identity != root {
        return Err(ExactCheckpointRelationError::RootMismatch);
    }
    authenticate_repository_manifest(&repository, &closure, root, &canonical_manifest)?;

    for target in &closure.targets {
        let observed = exact_checkpoint_target_manifest_identity(
            closure.configuration,
            closure.fault_checkpoint,
            target,
        );
        if target.manifest_identity != observed {
            return Err(ExactCheckpointRelationError::TargetManifestMismatch);
        }
    }

    let mut targets = Vec::new();
    targets
        .try_reserve_exact(closure.targets.len())
        .map_err(|_| ExactCheckpointRelationError::ResourceExhausted)?;
    let mut target_index = BTreeMap::new();
    for target in std::mem::take(&mut closure.targets) {
        let identity = ContentHash::from_canonical_material(
            "crucible.exact-checkpoint.target-node-index.v1",
            &target.node,
        );
        let index = targets.len();
        if target_index.insert(identity, index).is_some() {
            return Err(ExactCheckpointRelationError::InvalidStructure);
        }
        targets.push(Some(target));
    }

    Ok(ExactCheckpointClosureBinding {
        repository: Arc::new(repository),
        closure,
        targets,
        target_index,
    })
}

#[cfg(test)]
mod tests;

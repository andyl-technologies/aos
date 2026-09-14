//! Canonical bounded encodings for hierarchy export, snapshot, and view facts.
//!
//! These encoders retain opaque commitments instead of decoding them into
//! authority. A future durable adapter must verify protected or signed evidence
//! before reconstructing the crate-private evidence types.

use aos_sandbox_core::{ObjectDescriptor, ObjectDigest};
use sha2::{Digest as _, Sha256};

use super::exports::{ExportSourceV1, SubtreeExportClosureV1};
use super::history::{HierarchyHistoryCheckpointV1, RetainedHierarchyHeadV1};
use super::realizer::{AttachmentRealizationV1, ReplacementTransactionV1, ViewRealizationPlanV1};
use super::recovery::{
    CommittedHierarchySnapshotV1, DurableDetachProgressV1, DurableRealizationProgressV1,
    DurableRealizationTransactionV1, PreparedHierarchySnapshotV1, RetainedDetachHeadV1,
    RetainedRealizationHeadV1, RetainedRealizationTransactionHeadV1,
};

const EXPORT_MAGIC: &[u8; 8] = b"AOSHEX01";
const SNAPSHOT_MAGIC: &[u8; 8] = b"AOSHSS01";
const REALIZATION_MAGIC: &[u8; 8] = b"AOSHRP01";
const HIERARCHY_HEAD_MAGIC: &[u8; 8] = b"AOSHHD01";
const REALIZATION_HEAD_MAGIC: &[u8; 8] = b"AOSHRH01";
const HISTORY_CHECKPOINT_MAGIC: &[u8; 8] = b"AOSHCP01";
const COMMITTED_SNAPSHOT_MAGIC: &[u8; 8] = b"AOSHSC01";
const REALIZATION_PROGRESS_MAGIC: &[u8; 8] = b"AOSHRG01";
const DETACH_PROGRESS_MAGIC: &[u8; 8] = b"AOSHDG01";
const TRANSACTION_STATE_MAGIC: &[u8; 8] = b"AOSHTS01";
const DETACH_HEAD_MAGIC: &[u8; 8] = b"AOSHDH01";
const TRANSACTION_HEAD_MAGIC: &[u8; 8] = b"AOSHTH01";
const VERSION: u16 = 1;

/// Maximum bytes in one hierarchy artifact encoding.
pub const MAXIMUM_HIERARCHY_ARTIFACT_BYTES: usize = 64 * 1024 * 1024;

/// Encodes one complete reachable export closure in canonical field order.
///
/// # Errors
///
/// Returns [`HierarchyArtifactCodecError::Capacity`] on checked length or
/// bounded allocation exhaustion.
pub fn encode_export_closure_v1(
    closure: &SubtreeExportClosureV1,
) -> Result<Vec<u8>, HierarchyArtifactCodecError> {
    let mut writer = ArtifactWriter::new(EXPORT_MAGIC)?;
    writer.bytes(closure.project().as_bytes())?;
    writer.u64(closure.tree_generation().get())?;
    writer.bytes(closure.root().as_bytes())?;
    writer.count(closure.subtree_exports().len())?;
    for export in closure.subtree_exports() {
        writer.bytes(export.as_bytes())?;
    }
    writer.count(closure.reachable_definitions().len())?;
    for definition in closure.reachable_definitions() {
        writer.bytes(definition.export().as_bytes())?;
        writer.bytes(definition.sandbox().as_bytes())?;
        writer.u64(definition.sandbox_generation().get())?;
        writer.length_prefixed(definition.name().as_bytes())?;
        match definition.source() {
            ExportSourceV1::Immutable {
                view,
                revision,
                commitment,
            } => {
                writer.u8(0)?;
                writer.bytes(view.as_bytes())?;
                writer.u64(revision.get())?;
                writer.bytes(commitment.as_bytes())?;
            }
            ExportSourceV1::LiveKernelCoupled {
                incarnation,
                generation,
                commitment,
            } => {
                writer.u8(1)?;
                writer.bytes(incarnation.as_bytes())?;
                writer.u64(generation.get())?;
                writer.bytes(commitment.as_bytes())?;
            }
        }
        writer.count(definition.dependencies().len())?;
        for dependency in definition.dependencies() {
            writer.bytes(dependency.as_bytes())?;
        }
    }
    writer.count(closure.external_roots().len())?;
    for external in closure.external_roots() {
        writer.bytes(external.export().as_bytes())?;
        writer.optional_u64(external.source_generation().map(|value| value.get()))?;
        writer.bytes(external.source_commitment().as_bytes())?;
    }
    writer.count(closure.references().len())?;
    for reference in closure.references() {
        writer.bytes(reference.from().as_bytes())?;
        writer.bytes(reference.to().as_bytes())?;
    }
    writer.bytes(closure.commitment().as_bytes())?;
    Ok(writer.finish())
}

/// Encodes one validated portable snapshot preparation canonically.
///
/// # Errors
///
/// Returns [`HierarchyArtifactCodecError::Capacity`] on checked length or
/// bounded allocation exhaustion.
pub fn encode_prepared_snapshot_v1(
    prepared: &PreparedHierarchySnapshotV1,
) -> Result<Vec<u8>, HierarchyArtifactCodecError> {
    let mut writer = ArtifactWriter::new(SNAPSHOT_MAGIC)?;
    writer.bytes(prepared.project().as_bytes())?;
    writer.bytes(prepared.snapshot().as_bytes())?;
    writer.bytes(prepared.subtree_root().as_bytes())?;
    writer.u64(prepared.captured_tree_generation().get())?;
    writer.u64(prepared.captured_sandbox_generation().get())?;
    writer.bytes(prepared.tree_commitment().as_bytes())?;
    writer.bytes(prepared.export_closure_commitment().as_bytes())?;
    writer.descriptor(prepared.manifest())?;
    let portable = aos_sandbox_core::format::encode_snapshot(prepared.portable_snapshot());
    writer.length_prefixed(&portable)?;
    writer.bytes(prepared.retention_plan_commitment().as_bytes())?;
    writer.bytes(prepared.preparation_commitment().as_bytes())?;
    Ok(writer.finish())
}

/// Encodes one complete multi-action realization plan canonically.
///
/// The encoding retains the portable intent and opaque verified evidence
/// commitments. It contains no path, descriptor, or file-descriptor authority.
///
/// # Errors
///
/// Returns [`HierarchyArtifactCodecError::Capacity`] on checked length or
/// bounded allocation exhaustion.
pub fn encode_realization_plan_v1(
    plan: &ViewRealizationPlanV1,
) -> Result<Vec<u8>, HierarchyArtifactCodecError> {
    let mut writer = ArtifactWriter::new(REALIZATION_MAGIC)?;
    writer.bytes(plan.project().as_bytes())?;
    writer.u64(plan.tree_generation().get())?;
    writer.bytes(plan.observation_set_commitment().as_bytes())?;
    writer.count(plan.publications().len())?;
    for publication in plan.publications() {
        encode_publication(&mut writer, publication)?;
    }
    writer.count(plan.detaches().len())?;
    for detach in plan.detaches() {
        writer.bytes(detach.attachment().as_bytes())?;
        writer.u64(detach.generation().get())?;
        writer.bytes(detach.consumer().as_bytes())?;
        writer.bytes(detach.consumer_incarnation().as_bytes())?;
        writer.bytes(detach.consumer_node().as_bytes())?;
        writer.u64(detach.assignment_epoch().get())?;
        writer.bytes(detach.observation_set_commitment().as_bytes())?;
        writer.u64(detach.namespace_generation().get())?;
        writer.bytes(detach.destination_slot().as_bytes())?;
        writer.bytes(detach.recipe_commitment().as_bytes())?;
        writer.bytes(detach.assignment_commitment().as_bytes())?;
        writer.bytes(detach.request_commitment().as_bytes())?;
        writer.bytes(detach.policy_commitment().as_bytes())?;
        writer.bytes(detach.inventory_commitment().as_bytes())?;
        writer.count(detach.detach_after().len())?;
        for dependency in detach.detach_after() {
            writer.bytes(dependency.as_bytes())?;
        }
        writer.bytes(detach.detach_commitment().as_bytes())?;
    }
    writer.count(plan.publication_postorder().len())?;
    for attachment in plan.publication_postorder() {
        writer.bytes(attachment.as_bytes())?;
    }
    writer.count(plan.detach_postorder().len())?;
    for attachment in plan.detach_postorder() {
        writer.bytes(attachment.as_bytes())?;
    }
    writer.count(plan.execution_order().len())?;
    for action in plan.execution_order() {
        writer.u8(action.discriminant())?;
        writer.bytes(action.attachment().as_bytes())?;
    }
    writer.bytes(plan.plan_commitment().as_bytes())?;
    Ok(writer.finish())
}

/// Encodes one protected hierarchy head as a fixed canonical fact.
///
/// # Errors
///
/// Returns [`HierarchyArtifactCodecError::Capacity`] only if bounded
/// allocation cannot be admitted.
pub fn encode_protected_hierarchy_head_v1(
    head: RetainedHierarchyHeadV1,
) -> Result<Vec<u8>, HierarchyArtifactCodecError> {
    if head.project().as_bytes() == &[0; 16]
        || head.tree_commitment().as_bytes() == &[0; 32]
        || head.protected_head_commitment().as_bytes() == &[0; 32]
        || head
            .record_commitment()
            .is_some_and(|commitment| commitment.as_bytes() == &[0; 32])
        || (head.record_count() == 0) != head.record_commitment().is_none()
    {
        return Err(HierarchyArtifactCodecError::InvalidModel);
    }
    let mut writer = ArtifactWriter::new(HIERARCHY_HEAD_MAGIC)?;
    writer.bytes(head.project().as_bytes())?;
    writer.u64(head.record_count())?;
    writer.optional_digest(head.record_commitment())?;
    writer.bytes(head.tree_commitment().as_bytes())?;
    writer.bytes(head.protected_head_commitment().as_bytes())?;
    Ok(writer.finish())
}

/// Encodes one protected realization head as a fixed canonical fact.
///
/// # Errors
///
/// Returns [`HierarchyArtifactCodecError::Capacity`] only if bounded
/// allocation cannot be admitted.
pub fn encode_protected_realization_head_v1(
    head: RetainedRealizationHeadV1,
) -> Result<Vec<u8>, HierarchyArtifactCodecError> {
    if head.attachment().as_bytes() == &[0; 16]
        || head.project().as_bytes() == &[0; 16]
        || head.tree_generation().get() == 0
        || head.attachment_generation().get() == 0
        || head.plan_commitment().as_bytes() == &[0; 32]
        || head.recipe_commitment().as_bytes() == &[0; 32]
        || head.sequence() == 0
        || head.inventory_commitment().as_bytes() == &[0; 32]
        || head.history_commitment().as_bytes() == &[0; 32]
        || head.protected_head_commitment().as_bytes() == &[0; 32]
    {
        return Err(HierarchyArtifactCodecError::InvalidModel);
    }
    let mut writer = ArtifactWriter::new(REALIZATION_HEAD_MAGIC)?;
    writer.bytes(head.project().as_bytes())?;
    writer.u64(head.tree_generation().get())?;
    writer.bytes(head.attachment().as_bytes())?;
    writer.u64(head.attachment_generation().get())?;
    writer.bytes(head.plan_commitment().as_bytes())?;
    writer.bytes(head.recipe_commitment().as_bytes())?;
    writer.u64(head.sequence())?;
    writer.u8(head.stage() as u8)?;
    writer.bytes(head.inventory_commitment().as_bytes())?;
    writer.bytes(head.history_commitment().as_bytes())?;
    writer.bytes(head.protected_head_commitment().as_bytes())?;
    Ok(writer.finish())
}

/// Encodes one protected history-compaction checkpoint canonically.
///
/// # Errors
///
/// Returns [`HierarchyArtifactCodecError`] for zero fields or bounded
/// allocation exhaustion.
pub fn encode_history_checkpoint_v1(
    checkpoint: HierarchyHistoryCheckpointV1,
) -> Result<Vec<u8>, HierarchyArtifactCodecError> {
    if checkpoint.project().as_bytes() == &[0; 16]
        || checkpoint.through_sequence() == 0
        || checkpoint.through_record_commitment().as_bytes() == &[0; 32]
        || checkpoint.state_commitment().as_bytes() == &[0; 32]
        || checkpoint.checkpoint_commitment().as_bytes() == &[0; 32]
        || checkpoint.protected_checkpoint_commitment().as_bytes() == &[0; 32]
    {
        return Err(HierarchyArtifactCodecError::InvalidModel);
    }
    let mut writer = ArtifactWriter::new(HISTORY_CHECKPOINT_MAGIC)?;
    writer.bytes(checkpoint.project().as_bytes())?;
    writer.u64(checkpoint.through_sequence())?;
    writer.bytes(checkpoint.through_record_commitment().as_bytes())?;
    writer.bytes(checkpoint.state_commitment().as_bytes())?;
    writer.bytes(checkpoint.checkpoint_commitment().as_bytes())?;
    writer.bytes(checkpoint.protected_checkpoint_commitment().as_bytes())?;
    Ok(writer.finish())
}

/// Encodes a committed snapshot and its retained-manifest proof.
///
/// # Errors
///
/// Returns [`HierarchyArtifactCodecError::Capacity`] on bounded encoding failure.
pub fn encode_committed_snapshot_v1(
    committed: &CommittedHierarchySnapshotV1,
) -> Result<Vec<u8>, HierarchyArtifactCodecError> {
    let prepared = encode_prepared_snapshot_v1(committed.prepared())?;
    let retained = committed.retained();
    let mut writer = ArtifactWriter::new(COMMITTED_SNAPSHOT_MAGIC)?;
    writer.length_prefixed(&prepared)?;
    writer.bytes(retained.project().as_bytes())?;
    writer.bytes(retained.sandbox().as_bytes())?;
    writer.bytes(retained.snapshot().as_bytes())?;
    writer.u64(retained.captured_generation().get())?;
    writer.descriptor(retained.manifest())?;
    writer.bytes(retained.export_closure_commitment().as_bytes())?;
    writer.bytes(retained.retention_plan_commitment().as_bytes())?;
    writer.bytes(retained.preparation_commitment().as_bytes())?;
    writer.bytes(retained.retention_proof_commitment().as_bytes())?;
    writer.bytes(committed.commit_commitment().as_bytes())?;
    Ok(writer.finish())
}

/// Encodes complete durable realization observations and recipe identity.
///
/// # Errors
///
/// Returns [`HierarchyArtifactCodecError::Capacity`] on bounded encoding failure.
pub fn encode_realization_progress_v1(
    progress: &DurableRealizationProgressV1,
) -> Result<Vec<u8>, HierarchyArtifactCodecError> {
    let mut writer = ArtifactWriter::new(REALIZATION_PROGRESS_MAGIC)?;
    writer.bytes(progress.project().as_bytes())?;
    writer.u64(progress.tree_generation().get())?;
    writer.bytes(progress.attachment().as_bytes())?;
    writer.u64(progress.attachment_generation().get())?;
    writer.bytes(progress.plan_commitment().as_bytes())?;
    writer.bytes(progress.recipe_commitment().as_bytes())?;
    encode_replacement(&mut writer, progress.replacement())?;
    writer.count(progress.observations().len())?;
    for observation in progress.observations() {
        writer.u64(observation.sequence())?;
        writer.u8(observation.stage() as u8)?;
        writer.bytes(observation.inventory_commitment().as_bytes())?;
    }
    writer.bytes(progress.history_commitment().as_bytes())?;
    Ok(writer.finish())
}

/// Encodes complete durable detach observations and recipe identity.
///
/// # Errors
///
/// Returns [`HierarchyArtifactCodecError::Capacity`] on bounded encoding failure.
pub fn encode_detach_progress_v1(
    progress: &DurableDetachProgressV1,
) -> Result<Vec<u8>, HierarchyArtifactCodecError> {
    let mut writer = ArtifactWriter::new(DETACH_PROGRESS_MAGIC)?;
    writer.bytes(progress.project().as_bytes())?;
    writer.u64(progress.tree_generation().get())?;
    writer.bytes(progress.attachment().as_bytes())?;
    writer.u64(progress.attachment_generation().get())?;
    writer.bytes(progress.detach_commitment().as_bytes())?;
    writer.count(progress.observations().len())?;
    for observation in progress.observations() {
        writer.u64(observation.sequence())?;
        writer.u8(observation.stage() as u8)?;
        writer.bytes(observation.inventory_commitment().as_bytes())?;
    }
    writer.bytes(progress.history_commitment().as_bytes())?;
    Ok(writer.finish())
}

/// Encodes one protected multi-action terminal-observation subset.
///
/// # Errors
///
/// Returns [`HierarchyArtifactCodecError::Capacity`] on bounded encoding failure.
pub fn encode_realization_transaction_state_v1(
    state: &DurableRealizationTransactionV1,
) -> Result<Vec<u8>, HierarchyArtifactCodecError> {
    let mut writer = ArtifactWriter::new(TRANSACTION_STATE_MAGIC)?;
    writer.bytes(state.project().as_bytes())?;
    writer.u64(state.tree_generation().get())?;
    writer.bytes(state.plan_commitment().as_bytes())?;
    writer.count(state.actions().len())?;
    for action in state.actions() {
        writer.bytes(action.attachment().as_bytes())?;
        writer.bytes(action.action_commitment().as_bytes())?;
        writer.u8(action.outcome().discriminant())?;
        writer.bytes(action.inventory_commitment().as_bytes())?;
    }
    writer.bytes(state.state_commitment().as_bytes())?;
    Ok(writer.finish())
}

/// Encodes one verifier-issued protected detach head.
///
/// # Errors
///
/// Returns [`HierarchyArtifactCodecError`] for invalid fields or bounded failure.
pub fn encode_protected_detach_head_v1(
    head: RetainedDetachHeadV1,
) -> Result<Vec<u8>, HierarchyArtifactCodecError> {
    if head.project().as_bytes() == &[0; 16]
        || head.tree_generation().get() == 0
        || head.attachment().as_bytes() == &[0; 16]
        || head.attachment_generation().get() == 0
        || head.detach_commitment().as_bytes() == &[0; 32]
        || head.history_commitment().as_bytes() == &[0; 32]
        || head.protected_head_commitment().as_bytes() == &[0; 32]
    {
        return Err(HierarchyArtifactCodecError::InvalidModel);
    }
    let mut writer = ArtifactWriter::new(DETACH_HEAD_MAGIC)?;
    writer.bytes(head.project().as_bytes())?;
    writer.u64(head.tree_generation().get())?;
    writer.bytes(head.attachment().as_bytes())?;
    writer.u64(head.attachment_generation().get())?;
    writer.bytes(head.detach_commitment().as_bytes())?;
    writer.bytes(head.history_commitment().as_bytes())?;
    writer.bytes(head.protected_head_commitment().as_bytes())?;
    Ok(writer.finish())
}

/// Encodes one verifier-issued protected transaction head.
///
/// # Errors
///
/// Returns [`HierarchyArtifactCodecError`] for invalid fields or bounded failure.
pub fn encode_protected_transaction_head_v1(
    head: RetainedRealizationTransactionHeadV1,
) -> Result<Vec<u8>, HierarchyArtifactCodecError> {
    if head.project().as_bytes() == &[0; 16]
        || head.tree_generation().get() == 0
        || head.plan_commitment().as_bytes() == &[0; 32]
        || head.state_commitment().as_bytes() == &[0; 32]
        || head.protected_head_commitment().as_bytes() == &[0; 32]
    {
        return Err(HierarchyArtifactCodecError::InvalidModel);
    }
    let mut writer = ArtifactWriter::new(TRANSACTION_HEAD_MAGIC)?;
    writer.bytes(head.project().as_bytes())?;
    writer.u64(head.tree_generation().get())?;
    writer.bytes(head.plan_commitment().as_bytes())?;
    writer.bytes(head.state_commitment().as_bytes())?;
    writer.bytes(head.protected_head_commitment().as_bytes())?;
    Ok(writer.finish())
}

/// Returns a domain-separated commitment to canonical artifact bytes.
///
/// # Errors
///
/// Returns [`HierarchyArtifactCodecError::Capacity`] when the byte slice
/// exceeds the hierarchy artifact ceiling.
pub fn hierarchy_artifact_digest_v1(
    bytes: &[u8],
) -> Result<ObjectDigest, HierarchyArtifactCodecError> {
    if bytes.len() > MAXIMUM_HIERARCHY_ARTIFACT_BYTES {
        return Err(HierarchyArtifactCodecError::Capacity);
    }
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.hierarchy-artifact.v1\0");
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    Ok(ObjectDigest::from_bytes(hasher.finalize().into()))
}

/// Verifies bytes as the exact canonical encoding of one export closure.
///
/// This comparison-based decode endpoint cannot fabricate export definitions
/// or current ownership evidence from untrusted bytes.
///
/// # Errors
///
/// Returns [`HierarchyArtifactCodecError`] for excessive bytes, encoding
/// failure, or any mismatch from the supplied validated closure.
pub fn verify_export_closure_encoding_v1(
    bytes: &[u8],
    closure: &SubtreeExportClosureV1,
) -> Result<ObjectDigest, HierarchyArtifactCodecError> {
    verify_exact(bytes, encode_export_closure_v1(closure)?)
}

/// Verifies bytes as the exact canonical encoding of one snapshot preparation.
///
/// # Errors
///
/// Returns [`HierarchyArtifactCodecError`] for excessive bytes, encoding
/// failure, or any mismatch from the supplied validated preparation.
pub fn verify_prepared_snapshot_encoding_v1(
    bytes: &[u8],
    prepared: &PreparedHierarchySnapshotV1,
) -> Result<ObjectDigest, HierarchyArtifactCodecError> {
    verify_exact(bytes, encode_prepared_snapshot_v1(prepared)?)
}

/// Verifies bytes as the exact canonical encoding of one realization plan.
///
/// # Errors
///
/// Returns [`HierarchyArtifactCodecError`] for excessive bytes, encoding
/// failure, or any mismatch from the supplied validated plan.
pub fn verify_realization_plan_encoding_v1(
    bytes: &[u8],
    plan: &ViewRealizationPlanV1,
) -> Result<ObjectDigest, HierarchyArtifactCodecError> {
    verify_exact(bytes, encode_realization_plan_v1(plan)?)
}

/// Verifies bytes as the exact encoding of one protected hierarchy head.
///
/// # Errors
///
/// Returns [`HierarchyArtifactCodecError`] for invalid head fields, excessive
/// bytes, or a noncanonical encoding.
pub fn verify_protected_hierarchy_head_encoding_v1(
    bytes: &[u8],
    head: RetainedHierarchyHeadV1,
) -> Result<ObjectDigest, HierarchyArtifactCodecError> {
    verify_exact(bytes, encode_protected_hierarchy_head_v1(head)?)
}

/// Verifies bytes as the exact encoding of one protected realization head.
///
/// # Errors
///
/// Returns [`HierarchyArtifactCodecError`] for invalid head fields, excessive
/// bytes, or a noncanonical encoding.
pub fn verify_protected_realization_head_encoding_v1(
    bytes: &[u8],
    head: RetainedRealizationHeadV1,
) -> Result<ObjectDigest, HierarchyArtifactCodecError> {
    verify_exact(bytes, encode_protected_realization_head_v1(head)?)
}

/// Verifies bytes as the exact encoding of one protected history checkpoint.
///
/// # Errors
///
/// Returns [`HierarchyArtifactCodecError`] for invalid checkpoint fields,
/// excessive bytes, or a noncanonical encoding.
pub fn verify_history_checkpoint_encoding_v1(
    bytes: &[u8],
    checkpoint: HierarchyHistoryCheckpointV1,
) -> Result<ObjectDigest, HierarchyArtifactCodecError> {
    verify_exact(bytes, encode_history_checkpoint_v1(checkpoint)?)
}

/// Verifies bytes as the exact committed-snapshot retention encoding.
///
/// # Errors
///
/// Returns [`HierarchyArtifactCodecError`] for bounded or canonical mismatch.
pub fn verify_committed_snapshot_encoding_v1(
    bytes: &[u8],
    committed: &CommittedHierarchySnapshotV1,
) -> Result<ObjectDigest, HierarchyArtifactCodecError> {
    verify_exact(bytes, encode_committed_snapshot_v1(committed)?)
}

/// Verifies bytes as the exact durable realization-progress encoding.
///
/// # Errors
///
/// Returns [`HierarchyArtifactCodecError`] for bounded or canonical mismatch.
pub fn verify_realization_progress_encoding_v1(
    bytes: &[u8],
    progress: &DurableRealizationProgressV1,
) -> Result<ObjectDigest, HierarchyArtifactCodecError> {
    verify_exact(bytes, encode_realization_progress_v1(progress)?)
}

/// Verifies bytes as the exact durable detach-progress encoding.
///
/// # Errors
///
/// Returns [`HierarchyArtifactCodecError`] for bounded or canonical mismatch.
pub fn verify_detach_progress_encoding_v1(
    bytes: &[u8],
    progress: &DurableDetachProgressV1,
) -> Result<ObjectDigest, HierarchyArtifactCodecError> {
    verify_exact(bytes, encode_detach_progress_v1(progress)?)
}

/// Verifies bytes as the exact multi-action transaction-state encoding.
///
/// # Errors
///
/// Returns [`HierarchyArtifactCodecError`] for bounded or canonical mismatch.
pub fn verify_realization_transaction_state_encoding_v1(
    bytes: &[u8],
    state: &DurableRealizationTransactionV1,
) -> Result<ObjectDigest, HierarchyArtifactCodecError> {
    verify_exact(bytes, encode_realization_transaction_state_v1(state)?)
}

/// Verifies bytes as the exact protected detach-head encoding.
///
/// # Errors
///
/// Returns [`HierarchyArtifactCodecError`] for invalid or noncanonical bytes.
pub fn verify_protected_detach_head_encoding_v1(
    bytes: &[u8],
    head: RetainedDetachHeadV1,
) -> Result<ObjectDigest, HierarchyArtifactCodecError> {
    verify_exact(bytes, encode_protected_detach_head_v1(head)?)
}

/// Verifies bytes as the exact protected transaction-head encoding.
///
/// # Errors
///
/// Returns [`HierarchyArtifactCodecError`] for invalid or noncanonical bytes.
pub fn verify_protected_transaction_head_encoding_v1(
    bytes: &[u8],
    head: RetainedRealizationTransactionHeadV1,
) -> Result<ObjectDigest, HierarchyArtifactCodecError> {
    verify_exact(bytes, encode_protected_transaction_head_v1(head)?)
}

fn verify_exact(
    supplied: &[u8],
    canonical: Vec<u8>,
) -> Result<ObjectDigest, HierarchyArtifactCodecError> {
    if supplied.len() > MAXIMUM_HIERARCHY_ARTIFACT_BYTES {
        return Err(HierarchyArtifactCodecError::Capacity);
    }
    if supplied != canonical {
        return Err(HierarchyArtifactCodecError::NonCanonical);
    }
    hierarchy_artifact_digest_v1(supplied)
}

fn encode_publication(
    writer: &mut ArtifactWriter,
    publication: &AttachmentRealizationV1,
) -> Result<(), HierarchyArtifactCodecError> {
    let intent = aos_sandbox_core::encode_attachment_intent_v1(publication.intent());
    writer.length_prefixed(&intent)?;
    writer.bytes(publication.consumer_node().as_bytes())?;
    writer.u64(publication.assignment_epoch().get())?;
    writer.bytes(publication.observation_set_commitment().as_bytes())?;
    writer.bytes(publication.assignment_commitment().as_bytes())?;
    writer.bytes(publication.source_owner().as_bytes())?;
    writer.u64(publication.source_owner_generation().get())?;
    writer.bytes(publication.source_export().as_bytes())?;
    writer.optional_bytes(
        publication
            .source_node()
            .map(|value| value.into_bytes())
            .as_ref(),
    )?;
    writer.optional_u64(
        publication
            .source_namespace_generation()
            .map(|value| value.get()),
    )?;
    writer.optional_u64(
        publication
            .source_assignment_epoch()
            .map(|value| value.get()),
    )?;
    writer.bytes(publication.source_handle_commitment().as_bytes())?;
    writer.bytes(publication.source_retention_commitment().as_bytes())?;
    writer.bytes(publication.request_commitment().as_bytes())?;
    writer.bytes(publication.policy_commitment().as_bytes())?;
    writer.bytes(publication.lease_commitment().as_bytes())?;
    writer.bytes(publication.inventory_commitment().as_bytes())?;
    encode_replacement(writer, publication.replacement())?;
    writer.count(publication.dependencies().len())?;
    for dependency in publication.dependencies() {
        writer.bytes(dependency.as_bytes())?;
    }
    writer.bytes(publication.recipe_commitment().as_bytes())
}

fn encode_replacement(
    writer: &mut ArtifactWriter,
    replacement: Option<ReplacementTransactionV1>,
) -> Result<(), HierarchyArtifactCodecError> {
    let Some(replacement) = replacement else {
        return writer.u8(0);
    };
    writer.u8(1)?;
    writer.bytes(replacement.predecessor().as_bytes())?;
    writer.bytes(replacement.successor().as_bytes())?;
    writer.u64(replacement.predecessor_generation().get())?;
    writer.bytes(replacement.predecessor_recipe_commitment().as_bytes())?;
    writer.bytes(replacement.transaction_commitment().as_bytes())
}

struct ArtifactWriter {
    bytes: Vec<u8>,
}

impl ArtifactWriter {
    fn new(magic: &[u8; 8]) -> Result<Self, HierarchyArtifactCodecError> {
        let mut writer = Self { bytes: Vec::new() };
        writer.bytes(magic)?;
        writer.bytes(&VERSION.to_be_bytes())?;
        writer.bytes(&[0; 2])?;
        Ok(writer)
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }

    fn u8(&mut self, value: u8) -> Result<(), HierarchyArtifactCodecError> {
        self.bytes(&[value])
    }

    fn u64(&mut self, value: u64) -> Result<(), HierarchyArtifactCodecError> {
        self.bytes(&value.to_be_bytes())
    }

    fn count(&mut self, value: usize) -> Result<(), HierarchyArtifactCodecError> {
        let value = u32::try_from(value).map_err(|_| HierarchyArtifactCodecError::Capacity)?;
        self.bytes(&value.to_be_bytes())
    }

    fn length_prefixed(&mut self, value: &[u8]) -> Result<(), HierarchyArtifactCodecError> {
        self.count(value.len())?;
        self.bytes(value)
    }

    fn optional_u64(&mut self, value: Option<u64>) -> Result<(), HierarchyArtifactCodecError> {
        match value {
            Some(value) => {
                self.u8(1)?;
                self.u64(value)
            }
            None => {
                self.u8(0)?;
                self.u64(0)
            }
        }
    }

    fn optional_digest(
        &mut self,
        value: Option<ObjectDigest>,
    ) -> Result<(), HierarchyArtifactCodecError> {
        match value {
            Some(value) => {
                self.u8(1)?;
                self.bytes(value.as_bytes())
            }
            None => {
                self.u8(0)?;
                self.bytes(&[0; 32])
            }
        }
    }

    fn optional_bytes<const N: usize>(
        &mut self,
        value: Option<&[u8; N]>,
    ) -> Result<(), HierarchyArtifactCodecError> {
        match value {
            Some(value) => {
                self.u8(1)?;
                self.bytes(value)
            }
            None => {
                self.u8(0)?;
                self.bytes(&[0; N])
            }
        }
    }

    fn descriptor(
        &mut self,
        descriptor: &ObjectDescriptor,
    ) -> Result<(), HierarchyArtifactCodecError> {
        self.length_prefixed(descriptor.media_type().as_str().as_bytes())?;
        self.bytes(descriptor.digest().as_bytes())?;
        self.u64(descriptor.encoded_size())
    }

    fn bytes(&mut self, value: &[u8]) -> Result<(), HierarchyArtifactCodecError> {
        let next = self
            .bytes
            .len()
            .checked_add(value.len())
            .ok_or(HierarchyArtifactCodecError::Capacity)?;
        if next > MAXIMUM_HIERARCHY_ARTIFACT_BYTES {
            return Err(HierarchyArtifactCodecError::Capacity);
        }
        self.bytes
            .try_reserve(value.len())
            .map_err(|_| HierarchyArtifactCodecError::Capacity)?;
        self.bytes.extend_from_slice(value);
        Ok(())
    }
}

/// Reports bounded canonical hierarchy artifact encoding failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum HierarchyArtifactCodecError {
    /// A supposedly validated source model contains an invalid sentinel.
    #[error("hierarchy artifact source model is invalid")]
    InvalidModel,
    /// Supplied bytes differ from the exact canonical model encoding.
    #[error("hierarchy artifact encoding is not canonical for the validated model")]
    NonCanonical,
    /// Checked length or bounded allocation capacity was exhausted.
    #[error("hierarchy artifact encoding capacity is exhausted")]
    Capacity,
}

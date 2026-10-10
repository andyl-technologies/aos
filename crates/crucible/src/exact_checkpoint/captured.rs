//! Authenticates retained capture possession before durable root publication.
//!
//! The capture has no repository root or restore claims. It shares the canonical
//! manifest verifier and one-shot semantic byte traversal with stored closures.

use super::*;

/// Authenticated attempt-local manifest and its retained immutable object roster.
///
/// This proves only the supplied capture relation. It grants no durable CAS
/// placement, repository restore admission, or native execution authority.
#[derive(Debug)]
pub struct ExactCheckpointCaptureBinding {
    closure: ExactCheckpointClosureRecord,
    targets: Vec<Option<ExactCheckpointTargetRecord>>,
}

impl ExactCheckpointCaptureBinding {
    /// Visits complete RAM bindings before any semantic object is delivered.
    ///
    /// # Errors
    /// Rejects a malformed root record or an actual visitor refusal.
    pub fn visit_paged_ram_roots(
        &self,
        mut visitor: impl FnMut(
            &str,
            &ExactCheckpointPagedRamBinding,
        ) -> Result<(), ExactCheckpointRelationError>,
    ) -> Result<(), ExactCheckpointRelationError> {
        for target in self.targets.iter().flatten() {
            let binding = decode_paged_ram(&target.exact_ram.paged)?;
            visitor(&target.node, &binding)?;
        }
        Ok(())
    }

    /// Authenticates every unique semantic body before ordered role delivery.
    ///
    /// The reader type can retain its own original descriptor loan outside the
    /// underlying file. All readers close before the next open; the authenticated
    /// body buffers coexist until their roles have been delivered.
    ///
    /// # Errors
    /// Rejects missing, changed, short, extra or corrupt objects, aggregate-limit
    /// overflow, or an actual boundary/visitor refusal.
    pub fn visit_semantic_objects<R: std::io::Read>(
        self,
        byte_limit: u64,
        boundary: impl FnMut() -> std::io::Result<()>,
        open: impl FnMut(ContentHash) -> std::io::Result<R>,
        visit: impl FnMut(
            ExactCheckpointSemanticObjectRole<'_>,
            &[u8],
        ) -> std::io::Result<Option<ContentHash>>,
    ) -> Result<(), ExactCheckpointExecutionSourceError> {
        semantics::visit_authenticated_semantic_objects(
            &self.closure,
            &self.targets,
            byte_limit,
            boundary,
            open,
            visit,
        )?;
        Ok(())
    }
}

/// Authenticates a complete retained capture without inventing a repository root.
///
/// The supplied inventory belongs to the actual retained capture, and every
/// semantic body is independently authenticated during the one-shot traversal.
/// The scenario/configuration and canonical closure identity must all agree.
///
/// # Errors
/// Rejects unsupported or noncanonical manifests, incomplete/reordered object
/// inventories, malformed target relations, mismatched identities, or exhausted
/// active original allocation custody.
pub fn authenticate_captured_exact_checkpoint(
    manifest: &[u8],
    identity: ContentHash,
    scenario: ContentHash,
    configuration: ContentHash,
    objects: impl ExactSizeIterator<Item = (ContentHash, u64)>,
    owned_byte_limit: u64,
) -> Result<ExactCheckpointCaptureBinding, ExactCheckpointRelationError> {
    let mut closure = decode_canonical_closure(manifest, owned_byte_limit, objects)?;
    if closure.identity != identity
        || closure.scenario != scenario
        || closure.configuration != configuration
    {
        return Err(ExactCheckpointRelationError::RootMismatch);
    }
    validate_target_identities(&closure)?;
    crate::owned_decode::charge_array::<Option<ExactCheckpointTargetRecord>>(closure.targets.len())
        .map_err(|_| ExactCheckpointRelationError::ResourceExhausted)?;
    let mut targets = Vec::new();
    targets
        .try_reserve_exact(closure.targets.len())
        .map_err(|_| ExactCheckpointRelationError::ResourceExhausted)?;
    targets.extend(std::mem::take(&mut closure.targets).into_iter().map(Some));
    Ok(ExactCheckpointCaptureBinding { closure, targets })
}

//! Durable exact-checkpoint repository authentication.

use super::*;

/// Authenticates a durable production root and every canonical index page.
///
/// `index_pages` and `observed_objects` must be in root/index order. Each
/// observed pair contains the immutable object ID and the backend-reported
/// logical length. The operation recomputes every envelope ID and rejects an
/// extra, missing, reordered, or length-mismatched object before returning an
/// opaque repository binding.
///
/// # Errors
///
/// Returns [`ExactCheckpointRelationError::RepositoryRootMismatch`] for any
/// schema, child, index, object, count, byte-total, or content-ID mismatch.
pub fn authenticate_exact_checkpoint_repository(
    root: ExactCheckpointId,
    root_envelope_bytes: &[u8],
    index_pages: &[Vec<u8>],
    observed_objects: &[(ContentId, u64)],
) -> Result<ExactCheckpointRepositoryBinding, ExactCheckpointRelationError> {
    if root_envelope_bytes.len() > MAX_EXACT_CHECKPOINT_MANIFEST_BYTES {
        return Err(ExactCheckpointRelationError::RepositoryRootMismatch);
    }
    let envelope = ContentEnvelope::from_canonical_bytes(root_envelope_bytes)
        .map_err(|_| ExactCheckpointRelationError::RepositoryRootMismatch)?;
    if envelope.schema_name() != ROOT_SCHEMA
        || envelope.schema_version() != ROOT_SCHEMA_VERSION
        || envelope.content_id(ObjectKind::ExactManifest) != root.content_id()
        || envelope.body().len() != ROOT_BODY_BYTES
    {
        return Err(ExactCheckpointRelationError::RepositoryRootMismatch);
    }
    let body = decode_root_body(envelope.body())?;
    let expected_indexes = body.object_count.div_ceil(INDEX_PAGE_OBJECTS as u64);
    if body.manifest_bytes == 0
        || body.manifest_bytes > MAX_EXACT_CHECKPOINT_MANIFEST_BYTES as u64
        || body.object_count == 0
        || u64::from(body.index_count) != expected_indexes
        || body.manifest_bytes.checked_add(body.object_bytes).is_none()
    {
        return Err(ExactCheckpointRelationError::RepositoryRootMismatch);
    }
    let children = decode_root_children(&envelope, body.index_count)?;
    if children.indexes.len() != index_pages.len() {
        return Err(ExactCheckpointRelationError::RepositoryRootMismatch);
    }

    let mut inventory = Vec::new();
    inventory
        .try_reserve_exact(observed_objects.len())
        .map_err(|_| ExactCheckpointRelationError::RepositoryRootMismatch)?;
    let mut observed_cursor = 0_usize;
    let mut object_bytes = 0_u64;
    let mut previous = None;
    for (ordinal, (expected_id, bytes)) in children.indexes.iter().zip(index_pages).enumerate() {
        if bytes.len() > MAX_INDEX_BYTES {
            return Err(ExactCheckpointRelationError::RepositoryRootMismatch);
        }
        let index = ContentEnvelope::from_canonical_bytes(bytes)
            .map_err(|_| ExactCheckpointRelationError::RepositoryRootMismatch)?;
        if index.schema_name() != INDEX_SCHEMA
            || index.schema_version() != INDEX_SCHEMA_VERSION
            || index.content_id(ObjectKind::ExactManifest) != *expected_id
        {
            return Err(ExactCheckpointRelationError::RepositoryRootMismatch);
        }
        let page = decode_index_page(&index)?;
        if ordinal + 1 != index_pages.len() && page.len() != INDEX_PAGE_OBJECTS {
            return Err(ExactCheckpointRelationError::RepositoryRootMismatch);
        }
        for (identity, content, length) in page {
            if previous.is_some_and(|prior| prior >= identity)
                || observed_objects.get(observed_cursor) != Some(&(content, length))
            {
                return Err(ExactCheckpointRelationError::RepositoryRootMismatch);
            }
            previous = Some(identity);
            observed_cursor += 1;
            inventory.push(RepositoryObjectBinding {
                identity,
                content,
                length,
            });
            object_bytes = object_bytes
                .checked_add(length)
                .ok_or(ExactCheckpointRelationError::RepositoryRootMismatch)?;
        }
    }
    if observed_cursor != observed_objects.len()
        || observed_cursor != usize::try_from(body.object_count).unwrap_or(usize::MAX)
        || object_bytes != body.object_bytes
    {
        return Err(ExactCheckpointRelationError::RepositoryRootMismatch);
    }

    Ok(ExactCheckpointRepositoryBinding {
        root,
        production_identity: body.production_identity,
        scenario: body.scenario,
        configuration: body.configuration,
        manifest_id: children.manifest,
        manifest_bytes: body.manifest_bytes,
        objects: inventory,
    })
}

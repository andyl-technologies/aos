//! PostgreSQL tuple fences with bounded VALUES relations instead of long OR trees.
//!
//! EXISTS preserves one returned row per locked source, just like the portable
//! UPDATE predicate. The caller retains the same parameters and exact row count.

fn values_relation(rows: usize, columns: &[(&str, &str)]) -> String {
    let tuples = (0..rows)
        .map(|row| {
            let values = columns
                .iter()
                .enumerate()
                .map(|(column, (_, sql_type))| {
                    let index = row * columns.len() + column + 1;
                    format!("CAST(?{index} AS {sql_type})")
                })
                .collect::<Vec<_>>()
                .join(", ");
            format!("({values})")
        })
        .collect::<Vec<_>>()
        .join(", ");
    let names = columns
        .iter()
        .map(|(name, _)| *name)
        .collect::<Vec<_>>()
        .join(", ");
    format!("(VALUES {tuples}) AS expected ({names})")
}

pub(super) fn copy_locks(rows: usize) -> String {
    let expected = values_relation(
        rows,
        &[
            ("surface_object_id", "BIGINT"),
            ("placement_id", "BIGINT"),
            ("session_id", "VARCHAR"),
            ("sha256", "VARCHAR"),
            ("byte_size", "BIGINT"),
            ("etag", "VARCHAR"),
            ("provider_version", "VARCHAR"),
            ("placement_version", "BIGINT"),
            ("write_spec_version", "BIGINT"),
            ("binding_version", "BIGINT"),
        ],
    );
    format!(
        "SELECT 1 FROM object_placements presence
         WHERE presence.state = 'present' AND EXISTS (
           SELECT 1 FROM {expected}
           WHERE presence.surface_object_id = expected.surface_object_id
             AND presence.placement_id = expected.placement_id
             AND presence.direct_upload_session_id = expected.session_id
             AND presence.observed_hash = expected.sha256
             AND presence.observed_size = expected.byte_size
             AND presence.etag = expected.etag
             AND presence.provider_version IS NOT DISTINCT FROM expected.provider_version
             AND presence.observed_placement_resource_version = expected.placement_version
             AND presence.observed_write_spec_version = expected.write_spec_version
             AND presence.observed_binding_resource_version = expected.binding_version)
         FOR UPDATE OF presence"
    )
}

pub(super) fn source_locks(rows: usize) -> String {
    let expected = values_relation(
        rows,
        &[
            ("session_id", "VARCHAR"),
            ("logical_fingerprint", "VARCHAR"),
            ("resource_version", "BIGINT"),
            ("evidence_digest", "VARCHAR"),
        ],
    );
    format!(
        "SELECT 1 FROM direct_upload_sessions source
         WHERE source.state = 'committed' AND EXISTS (
           SELECT 1 FROM {expected}
           JOIN direct_upload_completion_receipts receipt
             ON receipt.session_id = expected.session_id
             AND receipt.evidence_digest = expected.evidence_digest
           WHERE source.session_id = expected.session_id
             AND source.logical_fingerprint = expected.logical_fingerprint
             AND source.resource_version = expected.resource_version)
         FOR UPDATE OF source"
    )
}

#[cfg(all(test, feature = "postgres", not(target_arch = "wasm32")))]
mod tests;

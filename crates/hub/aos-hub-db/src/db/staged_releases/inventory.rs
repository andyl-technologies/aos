//! Paged staged-inventory admission under the Worker SQL binding limit.
//!
//! Each page retains the immutable-object and pending-repair guards inside the
//! same checked transaction as its draft revision.

use anyhow::{Context, Result};
use aos_registry_format::staging::StageObject;

use crate::backend::CheckedStatement;

use super::super::SNAPSHOT_MAX_BOUND_PARAMETERS;

/// Builds guarded inventory inserts without exceeding positional binding limits.
///
/// # Errors
///
/// Returns an error if an object digest lacks its algorithm prefix or an object
/// size exceeds the SQL integer range.
pub(super) fn inventory_statements(
    registry_id: i64,
    stage_id: &str,
    revision_number: i64,
    objects: &[StageObject],
) -> Result<Vec<CheckedStatement>> {
    // Worker SQLite binds every placeholder occurrence: the three projected
    // identities plus the registry identity repeated in both retention guards.
    let page_size = (SNAPSHOT_MAX_BOUND_PARAMETERS - 5) / 4;
    let mut statements = Vec::new();

    for page in objects.chunks(page_size) {
        let mut params = vals![registry_id, stage_id, revision_number];
        let mut tuples = Vec::with_capacity(page.len());
        for (index, object) in page.iter().enumerate() {
            let hash = object
                .sha256
                .strip_prefix("sha256:")
                .context("invalid stage digest")?;
            let size = i64::try_from(object.byte_size).context("stage object is too large")?;
            let first = 4 + index * 4;
            tuples.push(format!(
                "(?{first}, ?{}, ?{}, ?{})",
                first + 1,
                first + 2,
                first + 3
            ));
            params.extend(vals![object.path, hash, size, object.media_type]);
        }

        statements.push(CheckedStatement::exact(
            format!("WITH input(object_key, sha256, byte_size, media_type) AS (VALUES {})
              INSERT INTO staged_release_objects (registry_id, stage_id, revision, object_key, sha256, byte_size, media_type)
              SELECT ?1, ?2, ?3, input.object_key, input.sha256, input.byte_size, input.media_type
                FROM input WHERE NOT EXISTS (SELECT 1 FROM surface_objects object
                  WHERE object.registry_id = ?1 AND object.object_key = input.object_key
                    AND (object.lifecycle_state <> 'active' OR EXISTS (
                      SELECT 1 FROM object_deletion_jobs job
                       WHERE job.surface_object_id = object.id AND job.active_slot IS NOT NULL)))
                  AND NOT EXISTS (SELECT 1 FROM oci_untracked_repair_plans repair
                    WHERE repair.registry_id = ?1 AND repair.object_key = input.object_key
                      AND repair.state IN('pending', 'claimed', 'failed'))", tuples.join(", ")),
            params, u64::try_from(page.len())?,
        ));
    }

    Ok(statements)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::prepare;
    use crate::dialect::Dialect;

    #[test]
    fn inventory_pages_fit_worker_positional_binding_limit() {
        let objects = (0..49)
            .map(|index| StageObject {
                path: format!("nar/{index:064x}.nar.zst"),
                sha256: format!("sha256:{index:064x}"),
                byte_size: 1_000,
                kind: "nar".into(),
                media_type: "application/x-nix-nar".into(),
            })
            .collect::<Vec<_>>();

        let statements = inventory_statements(1, "stage", 1, &objects).unwrap();

        let mut admitted = 0;
        for checked in statements {
            // MySQL and Worker SQLite both bind each placeholder occurrence,
            // including repeats of the registry identity in the write guards.
            let (_, positional) = prepare(
                Dialect::Mysql,
                &checked.statement.sql,
                &checked.statement.params,
            )
            .unwrap();
            assert!(
                positional.len() <= 100,
                "inventory page requires {} positional bindings",
                positional.len()
            );
            admitted += checked.expected_rows.unwrap();
        }
        assert_eq!(admitted, objects.len() as u64);
    }
}

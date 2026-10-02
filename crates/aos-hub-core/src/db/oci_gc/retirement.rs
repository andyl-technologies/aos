//! Reviewed OCI catalog retirement ahead of registry deletion.
//!
//! Registry deletion requires an empty OCI catalog, but signed releases and
//! tags are permanent hard roots of ordinary garbage collection. A retiring GC
//! run drops those catalog-owned roots and collects without grace, so repeated
//! plan/apply rounds drain the catalog level by level while every physical
//! deletion still flows through the exact inventory, capability, and
//! conditional-delete fences of an ordinary run.
//!
//! Retirement is fail-closed on two independent guards:
//!
//! - planning and apply both require that no enabled route serves the
//!   registry's OCI surface, so nothing a client can still resolve is deleted;
//! - the indexer refuses to project container-release roots for a registry
//!   whose retiring run is applying or complete, so a re-index cannot resurrect
//!   signed-release roots underneath the collector.

use crate::backend::{CheckedStatement, Statement};

/// SQL predicate selecting enabled routes that serve registry `?1`'s OCI
/// surface. Callers bind the registry id as parameter one.
pub(super) const ENABLED_OCI_ROUTE_PREDICATE: &str = "route.registry_id = ?1
                       AND route.enabled = 1
                       AND EXISTS (SELECT 1 FROM route_oci_capabilities capability
                         WHERE capability.route_id = route.id)";

/// Guards a retiring apply transaction against a route re-enabled after review.
pub(super) fn oci_route_disabled_guard_statement(registry_id: i64) -> CheckedStatement {
    Statement::new(
        format!(
            "UPDATE oci_registry_state SET updated_at = updated_at
             WHERE registry_id = ?1
               AND NOT EXISTS (SELECT 1 FROM routes route
                 WHERE {ENABLED_OCI_ROUTE_PREDICATE})"
        ),
        vals![registry_id],
    )
    .expecting(1)
}

/// Retires every catalog projection that keeps one candidate digest alive.
///
/// The rows are ordered so each statement removes what restricts the next:
/// release evidence cascades from provenance, projections and layers release
/// their `ON DELETE RESTRICT` references to the object, and tags and release
/// roots go last so the ordinary candidate guards that follow observe an
/// unreferenced object. Tag deletions deliberately write no tag history: the
/// repositories are deleted with the registry, and history rows cascade with
/// them.
pub(super) fn retire_catalog_root_statements(
    registry_id: i64,
    digest: &str,
) -> Vec<CheckedStatement> {
    let scoped = |sql: &str| Statement::new(sql, vals![registry_id, digest]).unchecked();
    vec![
        scoped(
            "DELETE FROM oci_release_evidence
             WHERE registry_id = ?1
               AND (root_digest = ?2 OR referrer_digest = ?2 OR digest = ?2)",
        ),
        scoped(
            "DELETE FROM oci_release_provenance
             WHERE registry_id = ?1 AND root_digest = ?2",
        ),
        scoped(
            "DELETE FROM oci_release_layers
             WHERE registry_id = ?1
               AND (root_digest = ?2 OR manifest_digest = ?2 OR digest = ?2)",
        ),
        scoped(
            "DELETE FROM oci_image_config_projections
             WHERE registry_id = ?1
               AND (root_digest = ?2 OR manifest_digest = ?2 OR config_digest = ?2)",
        ),
        scoped(
            "DELETE FROM oci_admin_projection_reconciliations
             WHERE registry_id = ?1
               AND (root_digest = ?2 OR manifest_digest = ?2 OR config_digest = ?2)",
        ),
        scoped("DELETE FROM oci_tags WHERE registry_id = ?1 AND digest = ?2"),
        scoped("DELETE FROM oci_release_roots WHERE registry_id = ?1 AND index_digest = ?2"),
    ]
}

//! Routes mutations in the topology capability.

use super::*;

impl Database {
    /// Lists route-probe operations eligible for a controller claim.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn due_route_probe_operations(
        &self,
        stale_before: i64,
        limit: usize,
    ) -> Result<Vec<TopologyOperationRecord>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        self.backend
            .query(
                &format!(
                    "SELECT {OPERATION_COLUMNS} FROM topology_operations o
                     WHERE o.operation_kind = 'route_probe'
                       AND (o.state = 'pending'
                         OR (o.state = 'running' AND o.started_at <= ?1))
                     ORDER BY o.created_at, o.operation_id LIMIT ?2"
                ),
                &vals![stale_before, i64::try_from(limit)?],
            )
            .await?
            .iter()
            .map(row_to_topology_operation)
            .collect()
    }

    /// Claims a pending or stale-running delivery-route probe under CAS.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid lease or database failure.
    pub async fn claim_route_probe_operation(
        &self,
        operation_id: &str,
        expected_version: i64,
        lease_seconds: i64,
    ) -> Result<Option<TopologyOperationRecord>> {
        if lease_seconds <= 0 {
            bail!("delivery-route probe claim lease must be positive");
        }
        let now = unix_now();
        let changed = self
            .backend
            .execute(
                "UPDATE topology_operations SET state = 'running', started_at = ?3,
                   finished_at = NULL, error = NULL, resource_version = resource_version + 1
                 WHERE operation_id = ?1 AND operation_kind = 'route_probe'
                   AND resource_version = ?2
                   AND (state = 'pending' OR (state = 'running' AND started_at <= ?4))",
                &vals![operation_id, expected_version, now, now - lease_seconds],
            )
            .await?;
        if changed == 0 {
            return Ok(None);
        }
        self.topology_operation(operation_id).await
    }
}

impl Database {
    pub(in crate::db) async fn due_physical_placement_operations(
        &self,
        now: i64,
        limit: usize,
        include_copies: bool,
    ) -> Result<Vec<TopologyOperationRecord>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let operation_filter = if include_copies {
            "IN ('scan_placement', 'replicate_placement', 'repair_placement')"
        } else {
            "= 'scan_placement'"
        };
        self.backend
            .query(
                &format!(
                    "SELECT {OPERATION_COLUMNS} FROM topology_operations operation
                     WHERE operation.operation_kind {operation_filter}
                       AND (operation.state = 'pending'
                         OR (operation.state = 'running' AND (
                           NOT EXISTS (SELECT 1 FROM placement_scan_claims claim
                             WHERE claim.operation_id = operation.operation_id)
                           OR EXISTS (SELECT 1 FROM placement_scan_claims claim
                             WHERE claim.operation_id = operation.operation_id
                               AND claim.lease_expires_at <= ?1))))
                     ORDER BY operation.created_at, operation.operation_id LIMIT ?2"
                ),
                &vals![now, i64::try_from(limit)?],
            )
            .await?
            .iter()
            .map(row_to_topology_operation)
            .collect()
    }
}

//! Operations reads in the topology capability.

use super::*;

impl Database {
    /// Lists plans in one authorization scope, newest first.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_topology_plans(&self, scope: &str) -> Result<Vec<TopologyPlanRecord>> {
        self.backend.query(&format!("SELECT {PLAN_COLUMNS} FROM topology_plans WHERE scope = ?1 ORDER BY created_at DESC, plan_id"), &vals![scope]).await?.iter().map(row_to_topology_plan).collect()
    }

    /// Lists operations for a surface using a stable newest-first keyset.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_topology_operations_page(
        &self,
        target_kind: &str,
        stable_id: &str,
        state: Option<&str>,
        page_size: u32,
        after_operation_id: Option<&str>,
    ) -> Result<TopologyOperationPage> {
        let state = state.unwrap_or("");
        if !state.is_empty()
            && !matches!(
                state,
                "pending" | "running" | "succeeded" | "failed" | "cancelled"
            )
        {
            bail!("invalid operation state filter '{state}'");
        }
        let after_created_at = if let Some(cursor) = after_operation_id {
            validate_key_bytes(cursor, "operation page token", 64)?;
            Some(
                self.backend
                    .query_opt(
                        "SELECT o.created_at FROM topology_operations o
                          WHERE o.operation_id = ?1 AND o.primary_target_kind = ?2
                            AND o.primary_target_stable_id = ?3
                            AND (?4 = '' OR o.state = ?4)",
                        &vals![cursor, target_kind, stable_id, state],
                    )
                    .await?
                    .context("operation page token does not belong to this inventory")?
                    .get::<i64>(0)?,
            )
        } else {
            None
        };
        let limit = if page_size == 0 {
            100_i64
        } else {
            i64::from(page_size.min(500))
        };
        let rows = self
            .backend
            .query(
                &format!(
                    "SELECT {OPERATION_COLUMNS} FROM topology_operations o
                      WHERE o.primary_target_kind = ?1 AND o.primary_target_stable_id = ?2
                        AND (?3 = '' OR o.state = ?3)
                        AND (?4 IS NULL OR o.created_at < ?4
                          OR (o.created_at = ?4 AND o.operation_id > ?5))
                      ORDER BY o.created_at DESC, o.operation_id
                      LIMIT ?6"
                ),
                &vals![
                    target_kind,
                    stable_id,
                    state,
                    after_created_at,
                    after_operation_id,
                    limit + 1
                ],
            )
            .await?;
        let mut records = rows
            .iter()
            .map(row_to_topology_operation)
            .collect::<Result<Vec<_>>>()?;
        let next_cursor = if records.len() > limit as usize {
            records.pop();
            records.last().map(|record| record.operation_id.clone())
        } else {
            None
        };
        Ok(TopologyOperationPage {
            records,
            next_cursor,
        })
    }

    /// Lists operations owned by a scope or any of its descendants.
    ///
    /// The inventory is ordered newest first with a stable operation-id
    /// tiebreaker. The cursor is accepted only when its operation belongs to
    /// the same scope closure and state filter.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure, an invalid state, or a cursor
    /// that does not belong to the requested inventory.
    pub async fn list_scope_topology_operations_page(
        &self,
        authorization_scope_key: &str,
        state: Option<&str>,
        page_size: u32,
        after_operation_id: Option<&str>,
    ) -> Result<TopologyOperationPage> {
        let state = state.unwrap_or("");
        if !state.is_empty()
            && !matches!(
                state,
                "pending" | "running" | "succeeded" | "failed" | "cancelled"
            )
        {
            bail!("invalid operation state filter '{state}'");
        }

        let after_created_at = if let Some(cursor) = after_operation_id {
            validate_key_bytes(cursor, "operation page token", 64)?;
            Some(
                self.backend
                    .query_opt(
                        "SELECT o.created_at
                           FROM topology_operations o
                           JOIN authorization_scope_ancestors ancestry
                             ON ancestry.descendant_scope_key = o.authorization_scope_key
                          WHERE o.operation_id = ?1
                            AND ancestry.ancestor_scope_key = ?2
                            AND (?3 = '' OR o.state = ?3)",
                        &vals![cursor, authorization_scope_key, state],
                    )
                    .await?
                    .context("operation page token does not belong to this inventory")?
                    .get::<i64>(0)?,
            )
        } else {
            None
        };
        let limit = if page_size == 0 {
            100_i64
        } else {
            i64::from(page_size.min(500))
        };
        let rows = self
            .backend
            .query(
                &format!(
                    "SELECT {OPERATION_COLUMNS}
                       FROM topology_operations o
                       JOIN authorization_scope_ancestors ancestry
                         ON ancestry.descendant_scope_key = o.authorization_scope_key
                      WHERE ancestry.ancestor_scope_key = ?1
                        AND (?2 = '' OR o.state = ?2)
                        AND (?3 IS NULL OR o.created_at < ?3
                          OR (o.created_at = ?3 AND o.operation_id > ?4))
                      ORDER BY o.created_at DESC, o.operation_id
                      LIMIT ?5"
                ),
                &vals![
                    authorization_scope_key,
                    state,
                    after_created_at,
                    after_operation_id,
                    limit + 1
                ],
            )
            .await?;
        let mut records = rows
            .iter()
            .map(row_to_topology_operation)
            .collect::<Result<Vec<_>>>()?;
        let next_cursor = if records.len() > limit as usize {
            records.pop();
            records.last().map(|record| record.operation_id.clone())
        } else {
            None
        };

        Ok(TopologyOperationPage {
            records,
            next_cursor,
        })
    }

    /// Lists every operation for an internal controller projection.
    ///
    /// User-facing inventory must use [`Database::list_topology_operations_page`].
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_topology_operations(
        &self,
        target_kind: &str,
        stable_id: &str,
    ) -> Result<Vec<TopologyOperationRecord>> {
        self.backend
            .query(
                &format!(
                    "SELECT {OPERATION_COLUMNS} FROM topology_operations o
                      WHERE o.primary_target_kind = ?1 AND o.primary_target_stable_id = ?2
                      ORDER BY o.created_at DESC, o.operation_id"
                ),
                &vals![target_kind, stable_id],
            )
            .await?
            .iter()
            .map(row_to_topology_operation)
            .collect()
    }
}

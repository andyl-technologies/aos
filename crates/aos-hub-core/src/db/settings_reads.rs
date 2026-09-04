//! Scoped delivery inventories used by settings and workflow selectors.
//!
//! These queries preserve resource ownership while exposing explicitly granted
//! resources to their consumer scope. Pagination precedes resource expansion.

use anyhow::{bail, Result};

use super::{Database, DeliveryIdentityPage, GatewayRecord};

impl Database {
    /// Lists a stable page of owned gateways and optionally granted generations.
    ///
    /// A grant only exposes a gateway when it covers its current desired
    /// generation. Historical grants cannot authorize a successor generation.
    /// Callers must authorize read access to `owner_scope_key` before querying.
    ///
    /// # Errors
    ///
    /// Returns an error for a noncanonical scope, database failure, or malformed
    /// persisted gateway data.
    pub async fn list_gateways_page(
        &self,
        owner_scope_key: &str,
        page_size: u32,
        after_id: Option<&str>,
        include_granted: bool,
    ) -> Result<DeliveryIdentityPage<GatewayRecord>> {
        if !crate::domain::Scope::is_canonical(owner_scope_key) {
            bail!("scope must be an immutable instance, organization, or project scope");
        }
        let limit = i64::from(if page_size == 0 {
            50
        } else {
            page_size.min(200)
        });
        let rows = self
            .backend
            .query(
                "SELECT g.id, g.owner_scope_key, g.enabled, g.desired_generation,
                        g.observed_generation, g.reconciliation_state, g.reconciliation_error,
                        g.resource_version, g.created_at, g.updated_at
                   FROM gateways g
                  WHERE (g.owner_scope_key = ?1 OR (?4 AND EXISTS (
                      SELECT 1 FROM gateway_revision_route_scopes grant_record
                       WHERE grant_record.gateway_id = g.id
                         AND grant_record.generation = g.desired_generation
                         AND grant_record.consumer_scope_key = ?1
                         AND grant_record.state = 'active'
                  ))) AND g.id > ?2
                  ORDER BY g.id LIMIT ?3",
                &vals![
                    owner_scope_key,
                    after_id.unwrap_or(""),
                    limit + 1,
                    include_granted
                ],
            )
            .await?;
        let mut records = rows
            .iter()
            .map(|row| {
                Ok(GatewayRecord {
                    id: row.get(0)?,
                    owner_scope_key: row.get(1)?,
                    enabled: row.get(2)?,
                    desired_generation: row.get(3)?,
                    observed_generation: row.get(4)?,
                    reconciliation_state: row.get(5)?,
                    reconciliation_error: row.get(6)?,
                    resource_version: row.get(7)?,
                    created_at: row.get(8)?,
                    updated_at: row.get(9)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let next_cursor = if records.len() > limit as usize {
            records.pop();
            records.last().map(|record| record.id.clone())
        } else {
            None
        };
        Ok(DeliveryIdentityPage {
            records,
            next_cursor,
        })
    }
}

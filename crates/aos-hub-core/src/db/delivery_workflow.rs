//! Durable delivery workflow progress and atomic verified advertisement changes.
//!
//! Intent is immutable JSON owned by the service's versioned Rust schema.
//! Progress contains replayable child plans and completed resource identities.
//! All requested audience changes and workflow activation share one transaction.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::backend::{Row, Statement};

use super::{unix_now, Database, DeliveryIdentityPage, SurfaceTarget};

#[cfg(test)]
#[path = "delivery_workflow_tests.rs"]
mod tests;

const COLUMNS: &str = "workflow_id, owner_scope_key, registry_id, cache_id,
    intent_json, progress_json, resource_version, created_at, updated_at";

// Readiness is rechecked inside the activation transaction. An earlier healthy
// probe cannot authorize a changed manifest, endpoint, gateway, or route head.
const READY_ROUTE: &str = "SELECT 1 FROM routes r
    JOIN route_heads h ON h.route_id = r.id
    JOIN route_observations ro ON ro.route_id = r.id
      AND ro.configuration_generation = h.configuration_generation
      AND ro.configuration_digest = h.configuration_digest AND ro.state = 'healthy'
    JOIN route_access_observations ao ON ao.route_id = r.id
      AND ao.configuration_generation = h.configuration_generation
      AND ao.configuration_digest = h.configuration_digest
      AND ao.access_policy_digest = h.access_policy_digest AND ao.state = 'verified'
    JOIN direct_route_evidence de ON de.route_id = r.id
      AND de.configuration_generation = h.configuration_generation
      AND de.configuration_digest = h.configuration_digest
      AND de.endpoint_id = r.endpoint_id AND de.endpoint_generation = r.endpoint_generation
      AND de.placement_id = r.placement_id
      AND de.gateway_id = r.gateway_id AND de.gateway_generation = r.gateway_generation
    JOIN placement_delivery_manifest_heads mh ON mh.placement_id = de.placement_id
      AND mh.manifest_id = de.publication_manifest_id
    JOIN gateways g ON g.id = de.gateway_id AND g.enabled = 1
      AND g.desired_generation = de.gateway_generation
      AND g.observed_generation = de.gateway_generation AND g.reconciliation_state = 'ready'
    JOIN endpoints e ON e.id = de.endpoint_id
    JOIN endpoint_revisions er ON er.endpoint_id = e.id
      AND er.generation = de.endpoint_generation
    JOIN network_policy_revision_lifecycle nl ON nl.boundary_id = e.network_policy_id
      AND nl.revision = er.boundary_revision AND nl.state = 'active'
    JOIN network_policy_observations no ON no.boundary_id = e.network_policy_id
      AND no.revision = er.boundary_revision AND no.state = 'verified'
    JOIN endpoint_route_scopes eg ON eg.endpoint_id = r.endpoint_id
      AND eg.endpoint_generation = r.endpoint_generation
      AND eg.consumer_scope_key = r.consumer_scope_key AND eg.state = 'active'
    JOIN gateway_revision_route_scopes gg ON gg.gateway_id = r.gateway_id
      AND gg.generation = r.gateway_generation
      AND gg.consumer_scope_key = r.consumer_scope_key AND gg.state = 'active'
    JOIN binding_consumer_scopes bg ON bg.binding_id = r.target_binding_id
      AND bg.consumer_scope_key = r.consumer_scope_key AND bg.state = 'active'
    JOIN network_policy_consumer_scopes ng ON ng.boundary_id = e.network_policy_id
      AND ng.consumer_scope_key = e.owner_scope_key AND ng.state = 'active'
    JOIN endpoint_observations eo ON eo.endpoint_id = de.endpoint_id
      AND eo.observed_generation = de.endpoint_generation AND eo.state = 'healthy'
      AND eo.listener_observed = 1 AND (e.scheme = 'http' OR eo.tls_observed = 1)
    WHERE r.id = ?1 AND r.enabled = 1 AND r.mode = 'direct'
      AND h.configuration_generation = ?2 AND h.configuration_digest = ?3
      AND r.resource_version = ?4
      AND (r.access_boundary_id IS NULL OR EXISTS (
        SELECT 1 FROM network_policy_consumer_scopes ag
        JOIN network_policy_revision_lifecycle al ON al.boundary_id = ag.boundary_id
          AND al.revision = r.access_boundary_revision AND al.state = 'active'
        JOIN network_policy_observations ao ON ao.boundary_id = ag.boundary_id
          AND ao.revision = r.access_boundary_revision AND ao.state = 'verified'
        WHERE ag.boundary_id = r.access_boundary_id
          AND ag.consumer_scope_key = r.consumer_scope_key AND ag.state = 'active'))";

/// One durable delivery destination workflow.
#[derive(Debug, Clone)]
pub struct DeliveryWorkflowRecord {
    /// Stable workflow identifier.
    pub workflow_id: String,
    /// Immutable authorized owner scope.
    pub owner_scope_key: String,
    /// Consumer surface.
    pub surface: SurfaceTarget,
    /// Immutable reviewed intent and prerequisite seals.
    pub intent_json: String,
    /// Resumable step state.
    pub progress_json: String,
    /// Optimistic concurrency token.
    pub resource_version: i64,
    /// Creation time in Unix seconds.
    pub created_at: i64,
    /// Last update time in Unix seconds.
    pub updated_at: i64,
}

/// One reviewed audience selection baseline for atomic activation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryAudienceBaseline {
    /// Audience being changed.
    pub audience: String,
    /// Existing selection version, or absence when creating a selection.
    pub resource_version: Option<i64>,
}

/// Exact route identity sealed by a reviewed activation plan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryActivationRoute {
    /// Route identifier.
    pub route_id: String,
    /// Immutable configuration generation.
    pub generation: i64,
    /// Immutable configuration digest.
    pub digest: String,
    /// Route concurrency token.
    pub resource_version: i64,
}

fn from_row(row: &Row) -> Result<DeliveryWorkflowRecord> {
    let registry_id: Option<i64> = row.get(2)?;
    let cache_id: Option<i64> = row.get(3)?;
    let surface = match (registry_id, cache_id) {
        (Some(id), None) => SurfaceTarget::Registry(id),
        (None, Some(id)) => SurfaceTarget::BinaryCache(id),
        _ => anyhow::bail!("workflow has invalid surface"),
    };
    Ok(DeliveryWorkflowRecord {
        workflow_id: row.get(0)?,
        owner_scope_key: row.get(1)?,
        surface,
        intent_json: row.get(4)?,
        progress_json: row.get(5)?,
        resource_version: row.get(6)?,
        created_at: row.get(7)?,
        updated_at: row.get(8)?,
    })
}

impl Database {
    /// Reserves a resume request or identifies a completed exact replay.
    ///
    /// # Errors
    /// Returns an error for stale initial progress, idempotency-key reuse with
    /// different input, or database failure.
    pub async fn begin_delivery_resumption(
        &self,
        actor_kind: &str,
        actor_id: i64,
        key: &str,
        workflow_id: &str,
        expected: i64,
    ) -> Result<bool> {
        self.backend
            .execute(
                "INSERT INTO delivery_workflow_resumptions
            (actor_kind, actor_id, request_key, workflow_id, expected_resource_version)
            SELECT ?1, ?2, ?3, workflow_id, ?5 FROM delivery_workflows
            WHERE workflow_id = ?4 AND resource_version = ?5
            ON CONFLICT(actor_kind, actor_id, request_key) DO NOTHING",
                &vals![actor_kind, actor_id, key, workflow_id, expected],
            )
            .await?;
        let row = self.backend.query_opt("SELECT workflow_id, expected_resource_version, completed
            FROM delivery_workflow_resumptions WHERE actor_kind = ?1 AND actor_id = ?2 AND request_key = ?3",
            &vals![actor_kind, actor_id, key]).await?.context("workflow changed; reload before resuming")?;
        anyhow::ensure!(
            row.get::<String>(0)? == workflow_id && row.get::<i64>(1)? == expected,
            "resume idempotency key has different workflow or resource version"
        );
        row.get(2)
    }

    /// Marks a resume request complete after its progress is durably saved.
    ///
    /// # Errors
    /// Returns an error on database failure.
    pub async fn complete_delivery_resumption(
        &self,
        actor_kind: &str,
        actor_id: i64,
        key: &str,
    ) -> Result<()> {
        self.backend
            .execute(
                "UPDATE delivery_workflow_resumptions SET completed = 1
            WHERE actor_kind = ?1 AND actor_id = ?2 AND request_key = ?3",
                &vals![actor_kind, actor_id, key],
            )
            .await?;
        Ok(())
    }
    /// Loads a workflow by immutable identity.
    ///
    /// # Errors
    /// Returns an error on database failure or malformed persisted state.
    pub async fn delivery_workflow(&self, id: &str) -> Result<Option<DeliveryWorkflowRecord>> {
        self.backend
            .query_opt(
                &format!("SELECT {COLUMNS} FROM delivery_workflows WHERE workflow_id = ?1"),
                &vals![id],
            )
            .await?
            .as_ref()
            .map(from_row)
            .transpose()
    }

    /// Persists a reviewed workflow once without replacing its intent.
    ///
    /// # Errors
    /// Returns an error on an identity collision with different intent or database failure.
    pub async fn create_delivery_workflow(
        &self,
        id: &str,
        scope: &str,
        surface: SurfaceTarget,
        intent: &str,
        progress: &str,
    ) -> Result<DeliveryWorkflowRecord> {
        let (registry, cache) = surface.ids();
        let now = unix_now();
        self.backend.execute("INSERT INTO delivery_workflows
            (workflow_id, owner_scope_key, registry_id, cache_id, intent_json, progress_json, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7) ON CONFLICT(workflow_id) DO NOTHING",
            &vals![id, scope, registry, cache, intent, progress, now]).await?;
        let record = self
            .delivery_workflow(id)
            .await?
            .context("workflow creation disappeared")?;
        anyhow::ensure!(
            record.intent_json == intent
                && record.owner_scope_key == scope
                && record.surface == surface,
            "workflow identity has different intent"
        );
        Ok(record)
    }

    /// Advances workflow progress under optimistic concurrency.
    ///
    /// # Errors
    /// Returns an error when the workflow changed or on database failure.
    pub async fn update_delivery_workflow(
        &self,
        id: &str,
        expected: i64,
        progress: &str,
    ) -> Result<DeliveryWorkflowRecord> {
        let changed = self
            .backend
            .execute(
                "UPDATE delivery_workflows SET progress_json = ?3,
            resource_version = resource_version + 1, updated_at = ?4
            WHERE workflow_id = ?1 AND resource_version = ?2",
                &vals![id, expected, progress, unix_now()],
            )
            .await?;
        anyhow::ensure!(changed == 1, "workflow changed; reload before resuming");
        self.delivery_workflow(id)
            .await?
            .context("workflow disappeared")
    }

    /// Lists one bounded surface workflow page in stable identity order.
    ///
    /// # Errors
    /// Returns an error on database failure or malformed state.
    pub async fn list_delivery_workflows(
        &self,
        surface: SurfaceTarget,
        size: u32,
        after: &str,
    ) -> Result<DeliveryIdentityPage<DeliveryWorkflowRecord>> {
        let (registry, cache) = surface.ids();
        let limit = i64::from(if size == 0 { 50 } else { size.min(200) });
        let rows = self.backend.query(&format!("SELECT {COLUMNS} FROM delivery_workflows
            WHERE (registry_id = ?1 OR cache_id = ?2) AND workflow_id > ?3 ORDER BY workflow_id LIMIT ?4"),
            &vals![registry, cache, after, limit + 1]).await?;
        let mut records = rows.iter().map(from_row).collect::<Result<Vec<_>>>()?;
        let next_cursor = if records.len() > limit as usize {
            records.pop();
            records.last().map(|r| r.workflow_id.clone())
        } else {
            None
        };
        Ok(DeliveryIdentityPage {
            records,
            next_cursor,
        })
    }

    /// Checks current exact direct-delivery evidence before offering activation.
    ///
    /// # Errors
    /// Returns an error on database failure.
    pub async fn delivery_workflow_route_ready(
        &self,
        route: &DeliveryActivationRoute,
    ) -> Result<bool> {
        Ok(self
            .backend
            .query_opt(
                READY_ROUTE,
                &vals![
                    route.route_id,
                    route.generation,
                    route.digest,
                    route.resource_version
                ],
            )
            .await?
            .is_some())
    }

    /// Atomically activates every reviewed audience and advances workflow state.
    ///
    /// # Errors
    /// Returns an error for stale progress, stale advertisement baselines, changed
    /// route identity, missing current verification, incompatible audiences, or database failure.
    pub async fn activate_delivery_workflow(
        &self,
        record: &DeliveryWorkflowRecord,
        route: &DeliveryActivationRoute,
        audiences: &[DeliveryAudienceBaseline],
        progress: &str,
    ) -> Result<()> {
        let now = unix_now();
        let (registry, cache) = record.surface.ids();
        let mut statements = vec![Statement::new(
            &format!(
                "UPDATE delivery_workflows
            SET progress_json = ?5, resource_version = resource_version + 1, updated_at = ?6
            WHERE workflow_id = ?7 AND resource_version = ?8 AND EXISTS ({READY_ROUTE})"
            ),
            vals![
                route.route_id,
                route.generation,
                route.digest,
                route.resource_version,
                progress,
                now,
                record.workflow_id,
                record.resource_version
            ],
        )
        .expecting(1)];
        for baseline in audiences {
            let capability = match baseline.audience.as_str() {
                "git" => "r.serves_git",
                "nix_cache" => "r.serves_cache",
                "web" => "r.serves_web",
                _ => anyhow::bail!("invalid delivery audience"),
            };
            let surface_predicate = "((registry_id = ?1 AND cache_id IS NULL) OR (registry_id IS NULL AND cache_id = ?2))";
            let eligible = format!("EXISTS (SELECT 1 FROM routes r WHERE r.id = ?4 AND {capability} = 1
                AND ((r.registry_id = ?1 AND r.cache_id IS NULL) OR (r.registry_id IS NULL AND r.cache_id = ?2)))");
            let statement = if let Some(version) = baseline.resource_version {
                Statement::new(&format!("UPDATE route_advertisements SET route_id = ?4,
                    resource_version = resource_version + 1, updated_at = ?5
                    WHERE {surface_predicate} AND audience = ?3 AND resource_version = ?6 AND {eligible}"),
                    vals![registry, cache, baseline.audience, route.route_id, now, version])
            } else {
                Statement::new(&format!("INSERT INTO route_advertisements (registry_id, cache_id, audience, route_id, resource_version, created_at, updated_at)
                    SELECT ?1, ?2, ?3, ?4, 1, ?5, ?5 WHERE {eligible}"),
                    vals![registry, cache, baseline.audience, route.route_id, now])
            };
            statements.push(statement.expecting(1));
        }
        self.backend.checked_batch(&statements).await
    }
}

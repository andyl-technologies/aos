//! Grants mutations in the topology capability.

use super::*;

impl Database {
    // -- tenancy: memberships ------------------------------------------------

    /// Grant (or update) a principal's role at a scope.
    ///
    /// A principal has at most one role per scope; re-granting the same
    /// `(principal_kind, principal_id, scope)` overwrites the role. The
    /// `scope` and `role` strings are the wire forms produced by
    /// [`aos_hub_model::domain::Scope::as_str`] and [`aos_hub_model::domain::Role::as_str`].
    ///
    /// As a persistence-layer backstop (sec CR-2), `scope` is required to be
    /// in canonical form ([`aos_hub_model::domain::Scope::is_canonical`]): a
    /// human slug, arbitrary path, uppercase variant, or malformed stable key
    /// is rejected. Accepted forms are `instance` and the globally stable
    /// `org:`, `project:`, `registry:`, and `cache:` identities; the row must exist
    /// in [`authorization_scopes`](crate::db::Database).
    ///
    /// # Errors
    ///
    /// Returns an error when `scope` is not in canonical form, and on
    /// database failure.
    pub async fn grant_membership(
        &self,
        principal_kind: &str,
        principal_id: i64,
        scope: &str,
        role: &str,
    ) -> Result<()> {
        if !aos_hub_model::domain::Scope::is_canonical(scope) {
            bail!("refusing to grant membership at non-canonical scope '{scope}'");
        }
        if aos_hub_model::domain::PrincipalKind::parse(principal_kind).is_none() {
            bail!("unknown membership principal kind '{principal_kind}'");
        }
        if aos_hub_model::domain::Role::parse(role).is_none() {
            bail!("unknown membership role '{role}'");
        }
        if !self.principal_is_live(principal_kind, principal_id).await? {
            bail!("membership principal does not identify a live principal");
        }
        if role != aos_hub_model::domain::Role::Owner.as_str() {
            return self
                .set_membership_role_owner_safe(principal_kind, principal_id, scope, role)
                .await;
        }
        self.upsert_live_membership_role(principal_kind, principal_id, scope, role)
            .await
    }

    /// Lists durable grant revocations eligible for a controller claim.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn due_consumer_scope_grant_revocation_operations(
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
                     WHERE o.operation_kind = 'consumer_scope_grant_revocation'
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

    /// Claims one pending or stale-running durable grant revocation.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid lease or database failure.
    pub async fn claim_consumer_scope_grant_revocation_operation(
        &self,
        operation_id: &str,
        expected_version: i64,
        lease_seconds: i64,
    ) -> Result<Option<TopologyOperationRecord>> {
        if lease_seconds <= 0 {
            bail!("grant revocation claim lease must be positive");
        }
        let now = unix_now();
        let changed = self
            .backend
            .execute(
                "UPDATE topology_operations SET state = 'running', started_at = ?3,
                 finished_at = NULL, error = NULL, resource_version = resource_version + 1
                 WHERE operation_id = ?1
                   AND operation_kind = 'consumer_scope_grant_revocation'
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

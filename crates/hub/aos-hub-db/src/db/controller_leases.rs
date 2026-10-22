//! Durable controller lease ownership and generation fences.
//!
//! A lease is scoped to one typed observation target and one service account.
//! The first generation starts at one. A live holder may renew only the exact
//! lease identity and generation; after expiry, a different lease identity may
//! take over with exactly the next generation.

use anyhow::{bail, Result};

use crate::backend::{CheckedStatement, Statement};

use super::{unix_now, Database};

/// Lifetime granted to an active controller lease.
pub const CONTROLLER_LEASE_TTL_SECONDS: i64 = 300;

/// Identity presented by one controller observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControllerLeaseFence<'a> {
    /// Stable kind of resource protected by the lease.
    pub target_kind: &'a str,
    /// Stable resource identity within `target_kind`.
    pub target_id: &'a str,
    /// Opaque identity chosen for this lease incarnation.
    pub lease_id: &'a str,
    /// Monotonic target-local lease generation.
    pub generation: i64,
    /// Authenticated service account that owns the lease.
    pub owner_service_account_id: i64,
}

impl Database {
    /// Acquires or renews the exact controller lease fence.
    ///
    /// An absent target accepts generation one. A live target accepts only its
    /// current lease identity, generation, and owner. An expired target accepts
    /// a different lease identity at exactly the next generation.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed identities, a non-positive owner, a live
    /// conflicting lease, a skipped generation, lease reuse on another target,
    /// or a database failure.
    pub async fn claim_controller_lease(&self, fence: &ControllerLeaseFence<'_>) -> Result<()> {
        validate_controller_fence(fence)?;
        let now = unix_now();
        let expires_at = now
            .checked_add(CONTROLLER_LEASE_TTL_SECONDS)
            .ok_or_else(|| anyhow::anyhow!("controller lease expiry overflow"))?;

        self.backend
            .checked_batch(&[
                Statement::new(
                    "INSERT INTO controller_leases(
                       target_kind, target_id, lease_id, generation,
                       owner_service_account_id, expires_at, serial, created_at, updated_at)
                     SELECT ?1, ?2, ?3, ?4, ?5, ?6, 0, ?7, ?7
                     WHERE ?4 = 1
                     ON CONFLICT(target_kind, target_id) DO NOTHING",
                    vals![
                        fence.target_kind,
                        fence.target_id,
                        fence.lease_id,
                        fence.generation,
                        fence.owner_service_account_id,
                        expires_at,
                        now
                    ],
                )
                .unchecked(),
                controller_lease_claim_statement(fence, now, expires_at),
            ])
            .await
    }

    /// Builds a transactional guard for a controller-owned mutation.
    ///
    /// Put this statement in the same checked batch as the observation write so
    /// lease takeover and observation CAS cannot interleave.
    pub(crate) fn controller_lease_guard_statement(
        fence: &ControllerLeaseFence<'_>,
    ) -> Result<CheckedStatement> {
        validate_controller_fence(fence)?;
        let now = unix_now();
        let expires_at = now
            .checked_add(CONTROLLER_LEASE_TTL_SECONDS)
            .ok_or_else(|| anyhow::anyhow!("controller lease expiry overflow"))?;

        Ok(Statement::new(
            "UPDATE controller_leases
             SET expires_at = ?6, serial = serial + 1, updated_at = ?7
             WHERE target_kind = ?1 AND target_id = ?2 AND lease_id = ?3
               AND generation = ?4 AND owner_service_account_id = ?5
               AND expires_at > ?7",
            vals![
                fence.target_kind,
                fence.target_id,
                fence.lease_id,
                fence.generation,
                fence.owner_service_account_id,
                expires_at,
                now
            ],
        )
        .expecting(1))
    }
}

fn controller_lease_claim_statement(
    fence: &ControllerLeaseFence<'_>,
    now: i64,
    expires_at: i64,
) -> CheckedStatement {
    Statement::new(
        "UPDATE controller_leases
         SET lease_id = ?3, generation = ?4, owner_service_account_id = ?5,
             expires_at = ?6, serial = serial + 1, updated_at = ?7
         WHERE target_kind = ?1 AND target_id = ?2
           AND ((lease_id = ?3 AND generation = ?4
                 AND owner_service_account_id = ?5 AND expires_at > ?7)
             OR (expires_at <= ?7 AND lease_id <> ?3
                 AND generation + 1 = ?4))",
        vals![
            fence.target_kind,
            fence.target_id,
            fence.lease_id,
            fence.generation,
            fence.owner_service_account_id,
            expires_at,
            now
        ],
    )
    .expecting(1)
}

fn validate_controller_fence(fence: &ControllerLeaseFence<'_>) -> Result<()> {
    validate_opaque_component(fence.target_kind, 32, "controller target kind")?;
    validate_opaque_component(fence.target_id, 255, "controller target id")?;
    validate_opaque_component(fence.lease_id, 64, "controller lease id")?;
    if fence.generation <= 0 {
        bail!("controller lease generation must be positive");
    }
    if fence.owner_service_account_id <= 0 {
        bail!("controller lease owner must be positive");
    }
    Ok(())
}

fn validate_opaque_component(value: &str, maximum: usize, label: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > maximum
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-/".contains(&byte))
    {
        bail!("invalid {label}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::value::Row;

    use super::*;

    async fn fixture() -> (Database, i64, i64) {
        let database = Database::open_in_memory().await.unwrap();
        let organization = database
            .create_org("controller-leases", "Controller leases")
            .await
            .unwrap();
        let first = database
            .create_service_account(organization, "first")
            .await
            .unwrap();
        let second = database
            .create_service_account(organization, "second")
            .await
            .unwrap();
        (database, first, second)
    }

    fn fence<'a>(
        lease_id: &'a str,
        generation: i64,
        owner_service_account_id: i64,
    ) -> ControllerLeaseFence<'a> {
        ControllerLeaseFence {
            target_kind: "network_policy_revision",
            target_id: "boundary-one/1",
            lease_id,
            generation,
            owner_service_account_id,
        }
    }

    async fn lease_row(database: &Database) -> Row {
        database
            .backend
            .query_opt(
                "SELECT lease_id, generation, owner_service_account_id, serial
                 FROM controller_leases
                 WHERE target_kind = 'network_policy_revision'
                   AND target_id = 'boundary-one/1'",
                &[],
            )
            .await
            .unwrap()
            .unwrap()
    }

    #[tokio::test]
    async fn live_lease_accepts_only_its_owner_identity_and_generation() {
        let (database, first, second) = fixture().await;
        database
            .claim_controller_lease(&fence("lease-one", 1, first))
            .await
            .unwrap();
        database
            .claim_controller_lease(&fence("lease-one", 1, first))
            .await
            .unwrap();

        for rejected in [
            fence("lease-two", 1, first),
            fence("lease-one", 2, first),
            fence("lease-one", 1, second),
        ] {
            assert!(database.claim_controller_lease(&rejected).await.is_err());
        }

        let row = lease_row(&database).await;
        assert_eq!(row.get::<String>(0).unwrap(), "lease-one");
        assert_eq!(row.get::<i64>(1).unwrap(), 1);
        assert_eq!(row.get::<i64>(2).unwrap(), first);
    }

    #[tokio::test]
    async fn expired_lease_requires_a_new_identity_and_next_generation() {
        let (database, first, second) = fixture().await;
        database
            .claim_controller_lease(&fence("lease-one", 1, first))
            .await
            .unwrap();
        database
            .backend
            .execute(
                "UPDATE controller_leases SET created_at = ?1, expires_at = ?2",
                &vals![unix_now() - 2, unix_now() - 1],
            )
            .await
            .unwrap();

        assert!(database
            .claim_controller_lease(&fence("lease-one", 1, first))
            .await
            .is_err());
        assert!(database
            .claim_controller_lease(&fence("lease-two", 3, second))
            .await
            .is_err());
        database
            .claim_controller_lease(&fence("lease-two", 2, second))
            .await
            .unwrap();

        let row = lease_row(&database).await;
        assert_eq!(row.get::<String>(0).unwrap(), "lease-two");
        assert_eq!(row.get::<i64>(1).unwrap(), 2);
        assert_eq!(row.get::<i64>(2).unwrap(), second);
    }

    #[tokio::test]
    async fn lease_identity_cannot_be_reused_for_another_target() {
        let (database, first, _) = fixture().await;
        database
            .claim_controller_lease(&fence("lease-one", 1, first))
            .await
            .unwrap();
        let other_target = ControllerLeaseFence {
            target_kind: "endpoint",
            target_id: "endpoint-one",
            lease_id: "lease-one",
            generation: 1,
            owner_service_account_id: first,
        };

        assert!(database
            .claim_controller_lease(&other_target)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn transactional_guard_rejects_a_delayed_previous_holder() {
        let (database, first, second) = fixture().await;
        let old = fence("lease-one", 1, first);
        database.claim_controller_lease(&old).await.unwrap();
        database
            .backend
            .execute(
                "UPDATE controller_leases SET created_at = ?1, expires_at = ?2",
                &vals![unix_now() - 2, unix_now() - 1],
            )
            .await
            .unwrap();
        let current = fence("lease-two", 2, second);
        database.claim_controller_lease(&current).await.unwrap();

        assert!(database
            .backend
            .checked_batch(&[Database::controller_lease_guard_statement(&old).unwrap()])
            .await
            .is_err());
        database
            .backend
            .checked_batch(&[Database::controller_lease_guard_statement(&current).unwrap()])
            .await
            .unwrap();
    }
}

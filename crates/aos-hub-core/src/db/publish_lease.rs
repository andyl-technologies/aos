//! Database-backed publication leases shared by Native Hub replicas.
//!
//! The schema already reserves `publish_leases` for one holder per registry.
//! The guarded update and conflict-ignoring insert keep acquisition atomic
//! across independent SQL connections without relying on process memory.

use anyhow::{bail, Context as _, Result};

use crate::lease::LEASE_TTL_SECS;

use super::{validate_key_bytes, Database};

impl Database {
    /// Acquires or refreshes one registry's publication lease.
    ///
    /// Returns `None` for the holder and `Some(other_holder)` for a live
    /// conflict. A database failure is distinct from a conflict and blocks
    /// publication.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid identity or clock, a missing registry,
    /// or a failed database operation.
    pub async fn acquire_publish_lease(
        &self,
        registry_id: i64,
        token_id: &str,
        now: i64,
    ) -> Result<Option<String>> {
        if registry_id <= 0 || now < 0 {
            bail!("invalid publication lease registry or time");
        }
        validate_key_bytes(token_id, "publication lease token", 128)?;
        let deadline = now
            .checked_add(LEASE_TTL_SECS)
            .context("publication lease deadline overflowed")?;

        self.backend
            .execute(
                "UPDATE publish_leases
                    SET holder_token_id = ?2,
                        deadline = CASE WHEN deadline > ?3 THEN deadline ELSE ?3 END
                  WHERE registry_id = ?1
                    AND (holder_token_id = ?2 OR deadline <= ?4)",
                &vals![registry_id, token_id, deadline, now],
            )
            .await?;
        self.backend
            .execute(
                "INSERT INTO publish_leases(registry_id, holder_token_id, deadline)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(registry_id) DO NOTHING",
                &vals![registry_id, token_id, deadline],
            )
            .await?;

        let lease = self
            .backend
            .query_opt(
                "SELECT holder_token_id, deadline
                   FROM publish_leases WHERE registry_id = ?1",
                &vals![registry_id],
            )
            .await?
            .context("publication lease disappeared during acquisition")?;
        let holder: String = lease.get(0)?;
        let observed_deadline: i64 = lease.get(1)?;
        if holder == token_id && observed_deadline > now {
            return Ok(None);
        }
        if observed_deadline > now {
            return Ok(Some(holder));
        }
        bail!("publication lease changed during acquisition")
    }

    /// Releases a registry's publication lease only for its current holder.
    ///
    /// # Errors
    ///
    /// Returns an error if the database rejects the deletion.
    pub async fn release_publish_lease(&self, registry_id: i64, token_id: &str) -> Result<()> {
        self.backend
            .execute(
                "DELETE FROM publish_leases
                  WHERE registry_id = ?1 AND holder_token_id = ?2",
                &vals![registry_id, token_id],
            )
            .await?;
        Ok(())
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::Database;

    #[tokio::test]
    async fn lease_is_shared_across_database_handles_and_fenced_on_release() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("hub.db");
        let first = Database::open(&path).await.unwrap();
        let second = Database::open(&path).await.unwrap();
        let registry_id = first
            .register_registry("shared-lease", &[], false)
            .await
            .unwrap();

        assert_eq!(
            first
                .acquire_publish_lease(registry_id, "a", 100)
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            second
                .acquire_publish_lease(registry_id, "b", 101)
                .await
                .unwrap(),
            Some("a".into())
        );

        second
            .release_publish_lease(registry_id, "b")
            .await
            .unwrap();
        assert_eq!(
            second
                .acquire_publish_lease(registry_id, "b", 102)
                .await
                .unwrap(),
            Some("a".into())
        );

        first.release_publish_lease(registry_id, "a").await.unwrap();
        assert_eq!(
            second
                .acquire_publish_lease(registry_id, "b", 103)
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            first
                .acquire_publish_lease(registry_id, "a", 103)
                .await
                .unwrap(),
            Some("b".into())
        );
    }

    #[tokio::test]
    async fn expired_lease_can_be_taken_without_shortening_a_refresh() {
        let db = Database::open_in_memory().await.unwrap();
        let registry_id = db
            .register_registry("expiring-lease", &[], false)
            .await
            .unwrap();

        assert_eq!(
            db.acquire_publish_lease(registry_id, "a", 100)
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            db.acquire_publish_lease(registry_id, "a", 110)
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            db.acquire_publish_lease(registry_id, "a", 105)
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            db.acquire_publish_lease(registry_id, "b", 405)
                .await
                .unwrap(),
            Some("a".into())
        );
        assert_eq!(
            db.acquire_publish_lease(registry_id, "b", 410)
                .await
                .unwrap(),
            None
        );
    }
}

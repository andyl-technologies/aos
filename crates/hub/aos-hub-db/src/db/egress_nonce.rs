//! Durable, cross-replica replay admission for hardened egress.
//!
//! The gateway authenticates a request first, then calls
//! [`Database::admit_egress_request`] before it performs any upstream side
//! effect. The nonce primary key is the single-use boundary. All gateway
//! replicas therefore have to share one strongly-consistent database (for
//! example PostgreSQL); a file-backed SQLite database is suitable only for a
//! singleton gateway, while still preserving admission across restarts.

use anyhow::{bail, Result};

use super::Database;

impl Database {
    /// Atomically admits one authenticated egress request exactly once.
    ///
    /// Expired rows are reclaimed before the guarded insert. The insert itself
    /// is one database statement whose primary-key conflict is reported as
    /// `Ok(false)`, so two replicas cannot both observe admission. Callers must
    /// not start an upstream request unless this method returns `Ok(true)`.
    ///
    /// # Errors
    ///
    /// Returns an error when the nonce or request digest is malformed, the
    /// expiry is not after admission, or the database operation fails.
    pub async fn admit_egress_request(
        &self,
        nonce: &str,
        request_digest: &str,
        accepted_at: i64,
        expires_at: i64,
    ) -> Result<bool> {
        if !(32..=128).contains(&nonce.len())
            || nonce.chars().any(|character| character.is_control())
        {
            bail!("hardened-egress nonce is malformed");
        }
        if request_digest.len() != 64
            || !request_digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            bail!("hardened-egress request digest is malformed");
        }
        if expires_at <= accepted_at {
            bail!("hardened-egress nonce expiry must be in the future at admission");
        }

        self.backend
            .execute(
                "DELETE FROM egress_request_nonces WHERE expires_at <= ?1",
                &vals![accepted_at],
            )
            .await?;
        let changed = self
            .backend
            .execute(
                "INSERT INTO egress_request_nonces
                   (nonce, request_digest, accepted_at, expires_at)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(nonce) DO NOTHING",
                &vals![nonce, request_digest, accepted_at, expires_at],
            )
            .await?;
        Ok(changed == 1)
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use super::*;

    #[tokio::test]
    async fn admission_is_single_effect_across_instances_and_restart() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("egress.db");
        let left = Arc::new(Database::open(&path).await.unwrap());
        let right = Arc::new(Database::open(&path).await.unwrap());
        let effects = Arc::new(AtomicUsize::new(0));
        let nonce = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";
        let digest = "a".repeat(64);

        let attempt = |database: Arc<Database>, effects: Arc<AtomicUsize>, digest: String| async move {
            if database
                .admit_egress_request(nonce, &digest, 1_700_000_000, 1_700_000_060)
                .await
                .unwrap()
            {
                effects.fetch_add(1, Ordering::SeqCst);
            }
        };
        tokio::join!(
            attempt(Arc::clone(&left), Arc::clone(&effects), digest.clone()),
            attempt(Arc::clone(&right), Arc::clone(&effects), digest.clone()),
        );
        assert_eq!(effects.load(Ordering::SeqCst), 1);

        drop(left);
        drop(right);
        let restarted = Database::open(&path).await.unwrap();
        assert!(!restarted
            .admit_egress_request(nonce, &digest, 1_700_000_001, 1_700_000_061)
            .await
            .unwrap());
        assert_eq!(effects.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn admission_rejects_non_future_expiry_on_every_instance() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("egress-future.db");
        let left = Database::open(&path).await.unwrap();
        let right = Database::open(&path).await.unwrap();
        let digest = "b".repeat(64);
        for database in [&left, &right] {
            assert!(database
                .admit_egress_request(
                    "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
                    &digest,
                    1_700_000_060,
                    1_700_000_060,
                )
                .await
                .is_err());
        }
    }
}

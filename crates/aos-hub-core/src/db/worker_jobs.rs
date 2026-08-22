//! Durable admission and completion records for at-least-once queue jobs.
//!
//! The queue message's v2 operation identity is the primary key. A consumer
//! claims that identity before executing side effects, completes it only after
//! the handler succeeds, and releases it to `pending` on an ordinary failure.
//! Expired `running` leases are reclaimable after isolate termination.

use anyhow::{bail, Result};

use crate::backend::CheckedStatement;

use super::Database;

/// Outcome of attempting to claim one stable queue operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkerJobClaim {
    /// This consumer owns the operation until the returned lease expires.
    Acquired {
        /// Random token fencing completion and release writes.
        claim_token: String,
        /// One-based execution attempt number.
        attempt: i64,
    },
    /// A previous delivery already committed the operation successfully.
    Completed,
    /// Another live consumer currently owns the operation lease.
    Busy,
}

impl Database {
    /// Claims a stable queue operation or reports its terminal/live state.
    ///
    /// Reusing an operation identity with another kind or payload is rejected
    /// instead of being mistaken for a harmless replay.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed identity data, invalid timing, an
    /// idempotency-key collision, or a persistence failure.
    pub async fn claim_worker_job(
        &self,
        operation_id: &str,
        job_kind: &str,
        payload_digest: &str,
        now: i64,
        lease_seconds: i64,
    ) -> Result<WorkerJobClaim> {
        validate_hex_identity(operation_id, "worker job operation identity", &[32, 64])?;
        validate_key(job_kind, "worker job kind", 64)?;
        validate_hex_identity(payload_digest, "worker job payload digest", &[64])?;
        if now < 0 || !(1..=900).contains(&lease_seconds) {
            bail!("worker job claim timing is invalid");
        }
        let lease_expires_at = now
            .checked_add(lease_seconds)
            .ok_or_else(|| anyhow::anyhow!("worker job lease expiry overflowed"))?;

        self.backend
            .execute(
                "INSERT INTO worker_job_executions
                   (operation_id, job_kind, payload_digest, state, claim_token,
                    attempt_count, lease_expires_at, last_error, created_at,
                    updated_at, completed_at)
                 VALUES (?1, ?2, ?3, 'pending', NULL, 0, NULL, NULL, ?4, ?4, NULL)
                 ON CONFLICT(operation_id) DO NOTHING",
                &vals![operation_id, job_kind, payload_digest, now],
            )
            .await?;

        let row = self
            .backend
            .query_opt(
                "SELECT job_kind, payload_digest, state, lease_expires_at,
                        attempt_count
                   FROM worker_job_executions WHERE operation_id = ?1",
                &vals![operation_id],
            )
            .await?
            .ok_or_else(|| anyhow::anyhow!("worker job admission disappeared"))?;
        let stored_kind: String = row.get(0)?;
        let stored_digest: String = row.get(1)?;
        let state: String = row.get(2)?;
        let current_lease: Option<i64> = row.get(3)?;
        let attempt: i64 = row.get(4)?;
        if stored_kind != job_kind || stored_digest != payload_digest {
            bail!("worker job operation identity is already used by another payload");
        }
        if state == "completed" {
            return Ok(WorkerJobClaim::Completed);
        }
        if state == "running" && current_lease.is_some_and(|lease| lease > now) {
            return Ok(WorkerJobClaim::Busy);
        }
        if state != "pending" && state != "running" {
            bail!("worker job has an invalid persisted state");
        }

        let claim_token = uuid::Uuid::new_v4().simple().to_string();
        let changed = self
            .backend
            .execute(
                "UPDATE worker_job_executions
                    SET state = 'running', claim_token = ?2,
                        attempt_count = attempt_count + 1,
                        lease_expires_at = ?3, last_error = NULL, updated_at = ?4
                  WHERE operation_id = ?1
                    AND (state = 'pending'
                         OR (state = 'running' AND lease_expires_at <= ?4))",
                &vals![operation_id, claim_token, lease_expires_at, now],
            )
            .await?;
        if changed == 0 {
            return Ok(WorkerJobClaim::Busy);
        }
        if changed != 1 {
            bail!("worker job claim changed an unexpected number of rows");
        }
        Ok(WorkerJobClaim::Acquired {
            claim_token,
            attempt: attempt + 1,
        })
    }

    /// Commits successful completion under the active claim fence.
    ///
    /// # Errors
    ///
    /// Returns an error if the claim is stale or persistence fails.
    pub async fn complete_worker_job(
        &self,
        operation_id: &str,
        claim_token: &str,
        completed_at: i64,
    ) -> Result<()> {
        validate_hex_identity(operation_id, "worker job operation identity", &[32, 64])?;
        validate_hex_identity(claim_token, "worker job claim token", &[32])?;
        if completed_at < 0 {
            bail!("worker job completion time is invalid");
        }
        self.backend
            .checked_batch(&[CheckedStatement::exact(
                "UPDATE worker_job_executions
                    SET state = 'completed', claim_token = NULL,
                        lease_expires_at = NULL, last_error = NULL,
                        updated_at = ?3, completed_at = ?3
                  WHERE operation_id = ?1 AND state = 'running'
                    AND claim_token = ?2",
                vals![operation_id, claim_token, completed_at],
                1,
            )])
            .await
    }

    /// Releases a failed execution for a later queue retry.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid input, a stale claim, or persistence
    /// failure.
    pub async fn release_worker_job(
        &self,
        operation_id: &str,
        claim_token: &str,
        error: &str,
        now: i64,
    ) -> Result<()> {
        validate_hex_identity(operation_id, "worker job operation identity", &[32, 64])?;
        validate_hex_identity(claim_token, "worker job claim token", &[32])?;
        if error.is_empty() || error.len() > 8_192 || now < 0 {
            bail!("worker job failure evidence is invalid");
        }
        self.backend
            .checked_batch(&[CheckedStatement::exact(
                "UPDATE worker_job_executions
                    SET state = 'pending', claim_token = NULL,
                        lease_expires_at = NULL, last_error = ?3,
                        updated_at = ?4, completed_at = NULL
                  WHERE operation_id = ?1 AND state = 'running'
                    AND claim_token = ?2",
                vals![operation_id, claim_token, error, now],
                1,
            )])
            .await
    }
}

fn validate_hex_identity(value: &str, label: &str, lengths: &[usize]) -> Result<()> {
    if !lengths.contains(&value.len())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{label} is malformed");
    }
    Ok(())
}

fn validate_key(value: &str, label: &str, max_bytes: usize) -> Result<()> {
    if value.is_empty()
        || value.len() > max_bytes
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        bail!("{label} is malformed");
    }
    Ok(())
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn completed_jobs_deduplicate_and_expired_claims_resume() {
        let db = Database::open_in_memory().await.unwrap();
        let operation = "a".repeat(32);
        let digest = "b".repeat(64);

        let first = db
            .claim_worker_job(&operation, "reindex", &digest, 100, 60)
            .await
            .unwrap();
        let WorkerJobClaim::Acquired {
            claim_token,
            attempt,
        } = first
        else {
            panic!("first delivery did not acquire the job")
        };
        assert_eq!(attempt, 1);
        assert_eq!(
            db.claim_worker_job(&operation, "reindex", &digest, 101, 60)
                .await
                .unwrap(),
            WorkerJobClaim::Busy
        );

        let reclaimed = db
            .claim_worker_job(&operation, "reindex", &digest, 161, 60)
            .await
            .unwrap();
        let WorkerJobClaim::Acquired {
            claim_token: reclaimed_token,
            attempt,
        } = reclaimed
        else {
            panic!("expired delivery was not reclaimed")
        };
        assert_eq!(attempt, 2);
        assert!(db
            .complete_worker_job(&operation, &claim_token, 162)
            .await
            .is_err());
        db.complete_worker_job(&operation, &reclaimed_token, 162)
            .await
            .unwrap();
        assert_eq!(
            db.claim_worker_job(&operation, "reindex", &digest, 200, 60)
                .await
                .unwrap(),
            WorkerJobClaim::Completed
        );
    }

    #[tokio::test]
    async fn operation_identity_cannot_alias_another_payload() {
        let db = Database::open_in_memory().await.unwrap();
        let operation = "c".repeat(32);
        db.claim_worker_job(&operation, "reindex", &"d".repeat(64), 100, 60)
            .await
            .unwrap();
        assert!(db
            .claim_worker_job(&operation, "reindex", &"e".repeat(64), 101, 60)
            .await
            .is_err());
    }
}

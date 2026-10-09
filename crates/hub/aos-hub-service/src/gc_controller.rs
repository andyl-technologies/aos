//! Durable physical-deletion controller for cache garbage collection.
//!
//! A controller pass claims database jobs, persists the exact backend request,
//! performs an identity-checked delete, persists the backend response, and only
//! then finalizes presence, accounting, and operation progress. Running jobs
//! and responded receipts are deliberately included in later passes, making
//! every crash boundary recoverable without inventing a second backend request.

use std::sync::Arc;

use anyhow::{Context, Result};
use sha2::{Digest as _, Sha256};

use crate::db::{
    Database, ObjectDeletionAttemptReceipt, ObjectDeletionJobRecord,
    RecordObjectDeletionAttemptResponse,
};
use crate::surface_write::{SurfaceDeleteOutcome, SurfaceDeletePrecondition, SurfaceWriteProvider};

/// Aggregate result of one bounded controller pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DeletionControllerStats {
    /// Jobs examined by the pass.
    pub examined: u64,
    /// Jobs finalized successfully.
    pub succeeded: u64,
    /// Attempts finalized as retryable or blocked failures.
    pub failed: u64,
    /// Jobs skipped because another controller won their CAS.
    pub contended: u64,
}

/// Runs durable placement-scoped physical deletion jobs.
pub struct CacheGcDeletionController {
    db: Arc<Database>,
    storage: Arc<dyn SurfaceWriteProvider>,
}

impl CacheGcDeletionController {
    /// Builds a controller over shared database and placement-write ports.
    #[must_use]
    pub fn new(db: Arc<Database>, storage: Arc<dyn SurfaceWriteProvider>) -> Self {
        Self { db, storage }
    }

    /// Processes up to `limit` due or crash-recoverable jobs.
    ///
    /// One job's stale CAS or backend failure does not abort the pass.
    ///
    /// # Errors
    ///
    /// Returns an error only when the runnable-job scan itself fails.
    pub async fn run_due(&self, now: i64, limit: i64) -> Result<DeletionControllerStats> {
        let jobs = self
            .db
            .list_runnable_object_deletion_jobs(now, limit)
            .await?;
        let mut stats = DeletionControllerStats::default();
        for job in jobs {
            stats.examined = stats.examined.saturating_add(1);
            match self.process_job(job, now).await {
                Ok(true) => stats.succeeded = stats.succeeded.saturating_add(1),
                Ok(false) => stats.failed = stats.failed.saturating_add(1),
                Err(_) => stats.contended = stats.contended.saturating_add(1),
            }
        }
        Ok(stats)
    }

    async fn process_job(&self, mut job: ObjectDeletionJobRecord, now: i64) -> Result<bool> {
        let receipt = if job.state == "running" {
            self.db
                .current_object_deletion_attempt_receipt(job.cache_id, &job.job_id)
                .await?
                .context("running deletion job has no durable request receipt")?
        } else {
            let request_id = deletion_request_id(&job);
            job = self
                .db
                .claim_cache_gc_deletion_job(
                    job.cache_id,
                    &job.job_id,
                    job.resource_version,
                    &request_id,
                    now,
                )
                .await?;
            self.db
                .object_deletion_attempt_receipt(&request_id)
                .await?
                .context("claimed deletion request receipt disappeared")?
        };

        let receipt = if receipt.state == "requested" {
            let response = self.perform_backend_delete(&receipt).await;
            self.db
                .record_object_deletion_attempt_response(&RecordObjectDeletionAttemptResponse {
                    request_id: receipt.request_id.clone(),
                    cache_id: receipt.cache_id,
                    job_id: receipt.job_id.clone(),
                    outcome: response.0,
                    response_etag: response.1,
                    response_hash: response.2,
                    response_size: response.3,
                    error_class: response.4,
                    response_detail: response.5,
                    responded_at: now,
                })
                .await?
        } else {
            receipt
        };

        match receipt.outcome.as_deref() {
            Some("deleted" | "not_found") => {
                self.db
                    .succeed_cache_gc_deletion_job(
                        job.cache_id,
                        &job.job_id,
                        job.resource_version,
                        &receipt.request_id,
                        now,
                    )
                    .await?;
                Ok(true)
            }
            Some("precondition_failed" | "backend_error") => {
                let policy = self
                    .db
                    .cache_gc_policy_topology(job.cache_id)
                    .await?
                    .context("deletion job cache has no GC policy")?;
                let delay = retry_delay(
                    policy.retry_initial_secs,
                    policy.retry_max_secs,
                    job.attempt_count,
                );
                let next_attempt_at = now.checked_add(delay).unwrap_or(i64::MAX);
                self.db
                    .fail_cache_gc_deletion_job(
                        job.cache_id,
                        &job.job_id,
                        job.resource_version,
                        &receipt.request_id,
                        receipt.error_class.as_deref().unwrap_or("backend_error"),
                        receipt
                            .response_detail
                            .as_deref()
                            .unwrap_or("physical deletion failed"),
                        next_attempt_at,
                        now,
                    )
                    .await?;
                Ok(false)
            }
            _ => anyhow::bail!("deletion attempt has no final backend outcome"),
        }
    }

    #[allow(clippy::type_complexity)]
    async fn perform_backend_delete(
        &self,
        receipt: &ObjectDeletionAttemptReceipt,
    ) -> (
        String,
        Option<String>,
        Option<String>,
        Option<i64>,
        Option<String>,
        Option<String>,
    ) {
        let placement = match self.db.surface_placement(receipt.placement_id).await {
            Ok(Some(placement))
                if placement.cache_id == Some(receipt.cache_id)
                    && placement.binding_id == receipt.binding_id =>
            {
                placement
            }
            Ok(_) => {
                return backend_failure(
                    "topology_mismatch",
                    "deletion placement is missing or belongs to another cache",
                );
            }
            Err(error) => return backend_failure("database_error", &format!("{error:#}")),
        };
        let deleter = match self
            .storage
            .placement_deleter(
                &placement,
                receipt.binding_resource_version,
                receipt.delete_credential_generation,
            )
            .await
        {
            Ok(deleter) => deleter,
            Err(error) => return backend_failure("unsupported_backend", &format!("{error:#}")),
        };
        let expected = SurfaceDeletePrecondition {
            etag: receipt.expected_etag.clone(),
            content_hash: receipt.expected_hash.clone(),
            size: receipt.expected_size,
        };
        match deleter
            .delete_if_matches(&receipt.object_key, &expected)
            .await
        {
            Ok(outcome @ SurfaceDeleteOutcome::Deleted { .. })
            | Ok(outcome @ SurfaceDeleteOutcome::ConditionalDeleteAcknowledged { .. }) => {
                verified_delete_response(outcome, &expected)
            }
            Ok(SurfaceDeleteOutcome::NotFound) => {
                ("not_found".to_string(), None, None, None, None, None)
            }
            Ok(SurfaceDeleteOutcome::PreconditionFailed { detail }) => (
                "precondition_failed".to_string(),
                None,
                None,
                None,
                Some("identity_mismatch".to_string()),
                Some(sanitize_detail(&detail)),
            ),
            Err(error) => backend_failure("backend_error", &format!("{error:#}")),
        }
    }
}

#[allow(clippy::type_complexity)]
fn verified_delete_response(
    outcome: SurfaceDeleteOutcome,
    expected: &SurfaceDeletePrecondition,
) -> (
    String,
    Option<String>,
    Option<String>,
    Option<i64>,
    Option<String>,
    Option<String>,
) {
    match outcome {
        SurfaceDeleteOutcome::Deleted {
            etag,
            content_hash,
            size,
        } if expected
            .etag
            .as_ref()
            .is_none_or(|expected| etag.as_ref() == Some(expected))
            && expected
                .content_hash
                .as_ref()
                .is_none_or(|expected| content_hash.as_ref() == Some(expected))
            && expected.size.is_none_or(|expected| size == Some(expected)) =>
        {
            ("deleted".to_string(), etag, content_hash, size, None, None)
        }
        SurfaceDeleteOutcome::ConditionalDeleteAcknowledged { etag }
            if expected
                .etag
                .as_deref()
                .and_then(|value| crate::surface_write::strong_if_match_etag(value).ok())
                .as_deref()
                == Some(etag.as_str())
                && expected.content_hash.is_some()
                && expected.size.is_some() =>
        {
            ("deleted".to_string(), Some(etag), None, None, None, None)
        }
        SurfaceDeleteOutcome::Deleted { .. }
        | SurfaceDeleteOutcome::ConditionalDeleteAcknowledged { .. }
        | SurfaceDeleteOutcome::NotFound
        | SurfaceDeleteOutcome::PreconditionFailed { .. } => (
            "precondition_failed".to_string(),
            None,
            None,
            None,
            Some("identity_mismatch".to_string()),
            Some("backend deletion proof did not match the frozen inventory identity".to_string()),
        ),
    }
}

fn deletion_request_id(job: &ObjectDeletionJobRecord) -> String {
    hex::encode(Sha256::digest(
        format!("delete:{}:{}", job.job_id, job.attempt_count + 1).as_bytes(),
    ))
}

fn retry_delay(initial: i64, maximum: i64, attempt: i64) -> i64 {
    let shift = u32::try_from(attempt.saturating_sub(1).min(62)).unwrap_or(62);
    initial.checked_shl(shift).unwrap_or(maximum).min(maximum)
}

#[allow(clippy::type_complexity)]
fn backend_failure(
    class: &str,
    detail: &str,
) -> (
    String,
    Option<String>,
    Option<String>,
    Option<i64>,
    Option<String>,
    Option<String>,
) {
    (
        "backend_error".to_string(),
        None,
        None,
        None,
        Some(class.to_string()),
        Some(sanitize_detail(detail)),
    )
}

fn sanitize_detail(detail: &str) -> String {
    detail.chars().take(4096).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_delay_is_bounded_without_overflow() {
        assert_eq!(retry_delay(5, 60, 1), 5);
        assert_eq!(retry_delay(5, 60, 4), 40);
        assert_eq!(retry_delay(5, 60, i64::MAX), 60);
    }

    #[test]
    fn cache_delete_distinguishes_observed_identity_from_s3_acknowledgment() {
        let expected = SurfaceDeletePrecondition {
            etag: Some("\"etag-1\"".into()),
            content_hash: Some("sha256:object".into()),
            size: Some(12),
        };
        let local = verified_delete_response(
            SurfaceDeleteOutcome::Deleted {
                etag: Some("\"etag-1\"".into()),
                content_hash: Some("sha256:object".into()),
                size: Some(12),
            },
            &expected,
        );
        assert_eq!(local.0, "deleted");
        assert_eq!(local.2.as_deref(), Some("sha256:object"));
        assert_eq!(local.3, Some(12));

        let acknowledged = verified_delete_response(
            SurfaceDeleteOutcome::ConditionalDeleteAcknowledged {
                etag: "\"etag-1\"".into(),
            },
            &expected,
        );
        assert_eq!(acknowledged.0, "deleted");
        assert_eq!(acknowledged.1.as_deref(), Some("\"etag-1\""));
        assert_eq!(acknowledged.2, None);
        assert_eq!(acknowledged.3, None);

        let mismatch = verified_delete_response(
            SurfaceDeleteOutcome::Deleted {
                etag: Some("\"etag-1\"".into()),
                content_hash: Some("sha256:replacement".into()),
                size: Some(12),
            },
            &expected,
        );
        assert_eq!(mismatch.0, "precondition_failed");
        assert_eq!(mismatch.4.as_deref(), Some("identity_mismatch"));
    }
}

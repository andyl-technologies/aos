//! Durable execution of reviewed OCI placement-deletion actions.
//!
//! The database claim is the deletion fence: it rechecks the active run,
//! candidate tombstone, hard roots, topology, credential, inventory, and
//! conditional-delete capability immediately before this controller performs
//! provider I/O. Provider adapters receive only [`FrozenSurfaceAccess`]; this
//! module never selects a current writer or reconstructs an address from live
//! topology. Actions that were absent from the reviewed inventory still get a
//! live exact-address probe before absence evidence is persisted.

use std::sync::Arc;

use anyhow::Result;
use sha2::{Digest as _, Sha256};

use crate::db::{
    Database, OciGcDeleteOutcome, OciGcPlacementActionClaim, RecordOciGcDeletionFailure,
    RecordOciGcDeletionSuccess,
};
use crate::fetch::{SurfaceFetch, SurfaceProvider};
use crate::jobs::redacted_job_failure;
use crate::surface_write::{
    FrozenSurfaceAccess, SurfaceDeleteOutcome, SurfaceDeletePrecondition, SurfaceWrite,
    SurfaceWriteProvider,
};

// LocalFS may hash, quarantine, unlink, and fsync one inventory-bounded 1 GiB
// object. The database's maximum one-hour lease keeps that bounded operation
// under one owner even on degraded storage.
const CLAIM_LEASE_SECONDS: i64 = 60 * 60;
const MAX_ACTIONS_PER_PASS: usize = 100;

/// Aggregate result of one bounded OCI GC controller pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OciGcControllerStats {
    /// Placement actions claimed from durable storage.
    pub claimed: u64,
    /// Provider absences durably confirmed.
    pub confirmed_absent: u64,
    /// Provider attempts durably retained for retry or operator repair.
    pub failed: u64,
    /// Candidates promoted after all frozen placements confirmed absence.
    pub finalized_candidates: u64,
    /// Applied runs whose catalog and quota identity was released.
    pub finalized_runs: u64,
    /// Unapplied reviewed plans expired by the pass.
    pub aborted_plans: u64,
    /// Snapshot lease-attribution holds released after lease drain.
    pub released_snapshot_holds: u64,
}

/// Executes exact placement actions from applied OCI GC runs.
pub struct OciGcDeletionController {
    db: Arc<Database>,
    surfaces: Arc<dyn SurfaceProvider>,
    writes: Arc<dyn SurfaceWriteProvider>,
}

impl OciGcDeletionController {
    /// Builds a controller over shared exact read/write provider ports.
    #[must_use]
    pub fn new(
        db: Arc<Database>,
        surfaces: Arc<dyn SurfaceProvider>,
        writes: Arc<dyn SurfaceWriteProvider>,
    ) -> Self {
        Self {
            db,
            surfaces,
            writes,
        }
    }

    /// Processes at most `limit` currently runnable placement actions.
    ///
    /// Transport failures are durably retried. Identity or topology failures
    /// move immediately to operator-visible repair because repeating the same
    /// frozen delete cannot make them safe. Neither path releases the candidate
    /// tombstone or registry deletion fence.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid bound or when claiming or recording a
    /// durable action fails. Provider failures are recorded and do not abort a
    /// pass.
    pub async fn run_due(
        &self,
        worker_id: &str,
        now: i64,
        limit: usize,
    ) -> Result<OciGcControllerStats> {
        anyhow::ensure!(
            now >= 0 && (1..=MAX_ACTIONS_PER_PASS).contains(&limit),
            "invalid OCI GC execution bound"
        );
        let mut stats = OciGcControllerStats::default();
        let maintenance_now = controller_now(now);
        let maintenance_limit = u32::try_from(limit)?;
        stats.aborted_plans = self
            .db
            .abort_expired_oci_gc_plans(maintenance_now, maintenance_limit)
            .await?;
        stats.released_snapshot_holds = self
            .db
            .release_drained_oci_gc_snapshot_holds(maintenance_now, maintenance_limit)
            .await?;
        for _ in 0..limit {
            let claim_now = controller_now(now);
            let claim_token = uuid::Uuid::new_v4().simple().to_string();
            let Some(claim) = self
                .db
                .claim_oci_gc_placement_action(
                    worker_id,
                    &claim_token,
                    claim_now,
                    CLAIM_LEASE_SECONDS,
                )
                .await?
            else {
                break;
            };
            stats.claimed = stats.claimed.saturating_add(1);

            match self.perform_provider_action(&claim).await {
                Ok(success) => {
                    let record = success_record(&claim, success, controller_now(claim_now))?;
                    self.db
                        .record_oci_gc_placement_action_success(&record)
                        .await?;
                    stats.confirmed_absent = stats.confirmed_absent.saturating_add(1);
                }
                Err(failure) => {
                    self.db
                        .record_oci_gc_placement_action_failure(&RecordOciGcDeletionFailure {
                            action_id: claim.action_id.clone(),
                            claim_token: claim.claim_token.clone(),
                            error: redacted_job_failure(&format!("{:#}", failure.error)),
                            // Identity/topology failures go directly to the
                            // maintenance requeue path. Transient I/O uses
                            // bounded retry. Neither releases the digest.
                            retryable: failure.retryable,
                            now: controller_now(claim_now),
                        })
                        .await?;
                    stats.failed = stats.failed.saturating_add(1);
                }
            }
        }
        let finalization = self
            .db
            .finalize_ready_oci_gc(controller_now(now), maintenance_limit)
            .await?;
        stats.finalized_candidates = finalization.finalized_candidates;
        stats.finalized_runs = finalization.finalized_generations;
        Ok(stats)
    }

    async fn perform_provider_action(
        &self,
        claim: &OciGcPlacementActionClaim,
    ) -> std::result::Result<ProviderSuccess, ProviderFailure> {
        let access = frozen_access(claim);
        access.validate().map_err(ProviderFailure::repair)?;

        if !claim.inventory_entry_present {
            let fetch = self
                .surfaces
                .frozen_placement_fetcher(&access)
                .await
                .map_err(ProviderFailure::repair)?;
            return live_absence(fetch.as_ref(), &claim.object_key).await;
        }

        let expected_etag = claim.expected_strong_etag.clone().ok_or_else(|| {
            ProviderFailure::repair(anyhow::anyhow!(
                "reviewed present inventory entry has no strong ETag"
            ))
        })?;
        let expected_size = i64::try_from(claim.expected_size)
            .map_err(|error| ProviderFailure::repair(error.into()))?;
        let deleter = self
            .writes
            .frozen_placement_deleter(&access)
            .await
            .map_err(ProviderFailure::repair)?;
        conditional_delete(
            deleter.as_ref(),
            &claim.object_key,
            SurfaceDeletePrecondition {
                etag: Some(expected_etag.clone()),
                content_hash: Some(claim.expected_hash.to_string()),
                size: Some(expected_size),
            },
        )
        .await
    }
}

fn controller_now(floor: i64) -> i64 {
    crate::clock::now_unix_secs().max(floor)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProviderSuccess {
    outcome: OciGcDeleteOutcome,
    conditional_etag: Option<String>,
}

#[derive(Debug)]
struct ProviderFailure {
    retryable: bool,
    error: anyhow::Error,
}

impl ProviderFailure {
    fn retry(error: anyhow::Error) -> Self {
        Self {
            retryable: true,
            error,
        }
    }

    fn repair(error: anyhow::Error) -> Self {
        Self {
            retryable: false,
            error,
        }
    }
}

fn frozen_access(claim: &OciGcPlacementActionClaim) -> FrozenSurfaceAccess {
    FrozenSurfaceAccess {
        registry_id: claim.registry_id,
        placement_id: claim.placement_id,
        placement_name: claim.placement_name.clone(),
        placement_prefix: claim.placement_prefix.clone(),
        placement_resource_version: claim.placement_resource_version,
        placement_write_spec_version: claim.placement_write_spec_version,
        placement_observation_version: claim.placement_observation_version,
        binding_id: claim.binding_id,
        binding_resource_version: claim.binding_resource_version,
        binding_write_revision: claim.binding_write_revision,
        delete_credential_purpose: claim.delete_credential_purpose.clone(),
        delete_credential_generation: claim.delete_credential_generation,
        delete_capability_fingerprint: claim.delete_capability_fingerprint.clone(),
        delete_capability_resource_version: claim.delete_capability_resource_version,
    }
}

async fn live_absence(
    fetch: &dyn SurfaceFetch,
    object_key: &str,
) -> std::result::Result<ProviderSuccess, ProviderFailure> {
    let size = fetch
        .size(object_key)
        .await
        .map_err(ProviderFailure::retry)?;
    if size.is_some() {
        return Err(ProviderFailure::repair(anyhow::anyhow!(
            "object appeared after the reviewed inventory; operator repair required"
        )));
    }
    Ok(ProviderSuccess {
        outcome: OciGcDeleteOutcome::AlreadyAbsent,
        conditional_etag: None,
    })
}

async fn conditional_delete(
    deleter: &dyn SurfaceWrite,
    object_key: &str,
    precondition: SurfaceDeletePrecondition,
) -> std::result::Result<ProviderSuccess, ProviderFailure> {
    let outcome = deleter
        .delete_if_matches(object_key, &precondition)
        .await
        .map_err(ProviderFailure::retry)?;
    match outcome {
        SurfaceDeleteOutcome::Deleted {
            etag,
            content_hash,
            size,
        } => {
            if etag != precondition.etag
                || content_hash != precondition.content_hash
                || size != precondition.size
            {
                return Err(ProviderFailure::repair(anyhow::anyhow!(
                    "provider deletion evidence did not match the frozen object identity"
                )));
            }
            Ok(ProviderSuccess {
                outcome: OciGcDeleteOutcome::Deleted,
                // Persist independently observed backend evidence only after
                // exact comparison; never synthesize it from the request.
                conditional_etag: etag,
            })
        }
        SurfaceDeleteOutcome::ConditionalDeleteAcknowledged { etag } => {
            if precondition.etag.as_deref() != Some(etag.as_str())
                || precondition.content_hash.is_none()
                || precondition.size.is_none()
            {
                return Err(ProviderFailure::repair(anyhow::anyhow!(
                    "conditional delete acknowledgment did not bind the frozen inventory identity"
                )));
            }
            // S3 returns no deleted-object hash or size. The reviewed provider
            // inventory binds both to this strong ETag, while the exact
            // capability probe establishes atomic If-Match semantics for the
            // frozen binding revision.
            Ok(ProviderSuccess {
                outcome: OciGcDeleteOutcome::Deleted,
                conditional_etag: Some(etag),
            })
        }
        SurfaceDeleteOutcome::NotFound => Ok(ProviderSuccess {
            outcome: OciGcDeleteOutcome::AlreadyAbsent,
            conditional_etag: None,
        }),
        SurfaceDeleteOutcome::PreconditionFailed { .. } => Err(ProviderFailure::repair(
            anyhow::anyhow!("provider object identity changed; operator repair required"),
        )),
    }
}

fn success_record(
    claim: &OciGcPlacementActionClaim,
    success: ProviderSuccess,
    confirmed_at: i64,
) -> Result<RecordOciGcDeletionSuccess> {
    let response_idempotency_key = hex::encode(Sha256::digest(
        format!(
            "aos-oci-gc-provider-response-v1\0{}\0{}",
            claim.action_id, claim.claim_token
        )
        .as_bytes(),
    ));
    let evidence_digest = crate::db::oci_gc_deletion_evidence_digest(
        &claim.action_id,
        &response_idempotency_key,
        success.outcome,
        success.conditional_etag.as_deref(),
        None,
        confirmed_at,
    )?;
    Ok(RecordOciGcDeletionSuccess {
        action_id: claim.action_id.clone(),
        claim_token: claim.claim_token.clone(),
        response_idempotency_key,
        outcome: success.outcome,
        conditional_etag: success.conditional_etag,
        provider_request_id: None,
        evidence_digest,
        confirmed_at,
    })
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use async_trait::async_trait;

    use super::*;

    #[test]
    fn action_timestamps_never_predate_the_claim_floor() {
        let future_floor = i64::MAX - 1;
        assert_eq!(controller_now(future_floor), future_floor);
        assert!(controller_now(0) >= 0);
        assert_eq!(CLAIM_LEASE_SECONDS, 3_600);
    }

    #[derive(Default)]
    struct MemorySurface {
        objects: Mutex<BTreeMap<String, Vec<u8>>>,
        delete_calls: Mutex<u64>,
        omit_deletion_evidence: bool,
        acknowledge_only: bool,
    }

    #[async_trait]
    impl SurfaceFetch for MemorySurface {
        async fn fetch(&self, path: &str) -> Result<Option<Vec<u8>>> {
            Ok(self.objects.lock().unwrap().get(path).cloned())
        }

        async fn size(&self, path: &str) -> Result<Option<u64>> {
            Ok(self
                .objects
                .lock()
                .unwrap()
                .get(path)
                .map(|bytes| bytes.len() as u64))
        }

        fn describe(&self) -> String {
            "memory OCI GC surface".into()
        }
    }

    #[async_trait]
    impl SurfaceWrite for MemorySurface {
        async fn write(&self, path: &str, bytes: &[u8]) -> Result<()> {
            self.objects
                .lock()
                .unwrap()
                .insert(path.to_string(), bytes.to_vec());
            Ok(())
        }

        async fn delete(&self, path: &str) -> Result<()> {
            self.objects.lock().unwrap().remove(path);
            Ok(())
        }

        async fn delete_if_matches(
            &self,
            path: &str,
            expected: &SurfaceDeletePrecondition,
        ) -> Result<SurfaceDeleteOutcome> {
            *self.delete_calls.lock().unwrap() += 1;
            let mut objects = self.objects.lock().unwrap();
            let Some(bytes) = objects.get(path) else {
                return Ok(SurfaceDeleteOutcome::NotFound);
            };
            let actual = format!("\"{}\"", hex::encode(Sha256::digest(bytes)));
            if expected.etag.as_deref() != Some(actual.as_str()) {
                return Ok(SurfaceDeleteOutcome::PreconditionFailed {
                    detail: "changed".into(),
                });
            }
            let bytes = objects.remove(path).unwrap();
            if self.acknowledge_only {
                return Ok(SurfaceDeleteOutcome::ConditionalDeleteAcknowledged { etag: actual });
            }
            Ok(SurfaceDeleteOutcome::Deleted {
                etag: (!self.omit_deletion_evidence).then_some(actual),
                content_hash: (!self.omit_deletion_evidence)
                    .then(|| format!("sha256:{}", hex::encode(Sha256::digest(&bytes)))),
                size: (!self.omit_deletion_evidence).then_some(bytes.len() as i64),
            })
        }
    }

    #[tokio::test]
    async fn conditional_etag_acknowledgment_uses_inventory_hash_and_size_proof() {
        let surface = MemorySurface {
            acknowledge_only: true,
            ..MemorySurface::default()
        };
        let bytes = b"provider bytes".to_vec();
        let etag = format!("\"{}\"", hex::encode(Sha256::digest(&bytes)));
        let hash = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
        surface
            .objects
            .lock()
            .unwrap()
            .insert("oci/object".into(), bytes.clone());

        let success = conditional_delete(
            &surface,
            "oci/object",
            SurfaceDeletePrecondition {
                etag: Some(etag.clone()),
                content_hash: Some(hash),
                size: Some(bytes.len() as i64),
            },
        )
        .await
        .unwrap();
        assert_eq!(success.outcome, OciGcDeleteOutcome::Deleted);
        assert_eq!(success.conditional_etag, Some(etag));
        assert!(!surface.objects.lock().unwrap().contains_key("oci/object"));
    }

    #[tokio::test]
    async fn absent_inventory_requires_a_live_absence_proof() {
        let surface = MemorySurface::default();
        surface
            .objects
            .lock()
            .unwrap()
            .insert("oci/object".into(), b"created after inventory".to_vec());

        let error = live_absence(&surface, "oci/object").await.unwrap_err();
        assert!(error.error.to_string().contains("appeared after"));
        assert_eq!(*surface.delete_calls.lock().unwrap(), 0);
        assert!(surface.objects.lock().unwrap().contains_key("oci/object"));
    }

    #[tokio::test]
    async fn absent_inventory_records_only_live_provider_absence() {
        let surface = MemorySurface::default();
        assert_eq!(
            live_absence(&surface, "oci/object").await.unwrap(),
            ProviderSuccess {
                outcome: OciGcDeleteOutcome::AlreadyAbsent,
                conditional_etag: None,
            }
        );
        assert_eq!(*surface.delete_calls.lock().unwrap(), 0);
    }

    #[tokio::test]
    async fn conditional_mismatch_never_deletes_the_replacement() {
        let surface = MemorySurface::default();
        surface
            .objects
            .lock()
            .unwrap()
            .insert("oci/object".into(), b"replacement".to_vec());
        let result = conditional_delete(
            &surface,
            "oci/object",
            SurfaceDeletePrecondition {
                etag: Some("\"reviewed\"".into()),
                content_hash: None,
                size: None,
            },
        )
        .await;
        assert!(result.is_err());
        assert!(surface.objects.lock().unwrap().contains_key("oci/object"));
    }

    #[tokio::test]
    async fn incomplete_provider_evidence_is_never_synthesized_from_the_request() {
        let surface = MemorySurface {
            omit_deletion_evidence: true,
            ..Default::default()
        };
        let bytes = b"reviewed";
        let etag = format!("\"{}\"", hex::encode(Sha256::digest(bytes)));
        let hash = format!("sha256:{}", hex::encode(Sha256::digest(bytes)));
        surface
            .objects
            .lock()
            .unwrap()
            .insert("oci/object".into(), bytes.to_vec());

        let failure = conditional_delete(
            &surface,
            "oci/object",
            SurfaceDeletePrecondition {
                etag: Some(etag),
                content_hash: Some(hash),
                size: Some(bytes.len() as i64),
            },
        )
        .await
        .unwrap_err();
        assert!(!failure.retryable);
        assert!(failure.error.to_string().contains("evidence"));
    }
}

//! Durable, bounded observation of provider conditional-delete semantics.
//!
//! OCI GC never infers deletion safety from a provider kind. This controller
//! exercises a service-reserved non-OCI key through the actual placement ports,
//! then records the exact binding revision, credential generation, and semantic
//! fingerprint that passed. Probe keys are deterministic per binding revision;
//! a retry overwrites and removes any bytes left by a crashed prior attempt.

use std::future::Future;
use std::sync::Arc;

use anyhow::{Context as _, Result};
use sha2::{Digest as _, Sha256};

use crate::db::{Database, RecordOciConditionalDeleteCapability, SurfacePlacementRecord};
use crate::fetch::{SurfaceFetch, SurfaceProvider};
use crate::surface_write::{
    SurfaceDeleteOutcome, SurfaceDeletePrecondition, SurfaceWrite, SurfaceWriteProvider,
};

const PROBE_MAX_BYTES: u64 = 4 * 1024;

/// Executes bounded conditional-delete capability observations.
pub struct ConditionalDeleteProbeController {
    db: Arc<Database>,
    surfaces: Arc<dyn SurfaceProvider>,
    writes: Arc<dyn SurfaceWriteProvider>,
}

impl ConditionalDeleteProbeController {
    /// Creates a probe controller over shared read/write provider ports.
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

    /// Probes at most `limit` distinct current binding revisions.
    ///
    /// Existing fresh observations are skipped. Provider errors leave the prior
    /// observation unchanged and return an error for durable job retry. A
    /// completed semantic failure records `invalid` before a failed reserved-
    /// key cleanup is returned for durable retry.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid bound, database failure, topology drift,
    /// provider I/O failure, or reserved-key cleanup failure.
    pub async fn run_due(&self, now: i64, limit: usize) -> Result<usize> {
        anyhow::ensure!(
            now >= 0 && (1..=100).contains(&limit),
            "invalid probe bound"
        );
        let mut completed = 0_usize;
        for frozen in self
            .db
            .list_due_oci_conditional_delete_placements(now, u32::try_from(limit)?)
            .await?
        {
            let placement = self
                .db
                .surface_placement(frozen.placement_id)
                .await?
                .context("due conditional-delete placement disappeared")?;
            anyhow::ensure!(
                placement.registry_id == Some(frozen.registry_id)
                    && placement.name == frozen.placement_name
                    && placement.resource_version == frozen.placement_resource_version
                    && placement.write_spec_version == frozen.placement_write_spec_version
                    && placement.observation_version == Some(frozen.placement_observation_version)
                    && placement.binding_id == frozen.binding_id,
                "conditional-delete placement topology drifted after due selection"
            );
            let binding = self
                .db
                .binding(frozen.binding_id)
                .await?
                .context("due conditional-delete binding disappeared")?;
            let write_state = self
                .db
                .binding_write_state(frozen.binding_id)
                .await?
                .context("due conditional-delete binding state disappeared")?;
            anyhow::ensure!(
                binding.resource_version == frozen.binding_resource_version
                    && write_state.current_write_revision == Some(frozen.binding_write_revision),
                "conditional-delete binding drifted after due selection"
            );
            let existing = self
                .db
                .oci_conditional_delete_capability(frozen.binding_id, frozen.binding_write_revision)
                .await?;
            self.probe_placement(
                &placement,
                frozen.binding_write_revision,
                existing.as_ref(),
                now,
            )
            .await?;
            completed += 1;
        }
        Ok(completed)
    }

    async fn probe_placement(
        &self,
        placement: &SurfacePlacementRecord,
        binding_write_revision: i64,
        existing: Option<&crate::db::OciConditionalDeleteCapabilityRecord>,
        now: i64,
    ) -> Result<()> {
        let binding = self
            .db
            .binding(placement.binding_id)
            .await?
            .context("conditional-delete probe binding disappeared")?;
        let delete_credential = if matches!(binding.kind.as_str(), "s3" | "r2") {
            self.db
                .current_binding_credential(binding.id, "delete")
                .await?
        } else {
            None
        };
        let purpose = delete_credential.as_ref().map(|_| "delete".to_string());
        let generation = delete_credential
            .as_ref()
            .map(|credential| credential.generation);
        let capability_fingerprint = capability_fingerprint(&binding.kind, binding_write_revision);
        let expected_resource_version = existing.map(|capability| capability.resource_version);

        if binding.kind == "deployment_r2" {
            self.record(
                &binding,
                binding_write_revision,
                None,
                None,
                capability_fingerprint,
                "invalid",
                expected_resource_version,
                now,
            )
            .await?;
            return Ok(());
        }
        if matches!(binding.kind.as_str(), "s3" | "r2") && delete_credential.is_none() {
            self.record(
                &binding,
                binding_write_revision,
                None,
                None,
                capability_fingerprint,
                "invalid",
                expected_resource_version,
                now,
            )
            .await?;
            return Ok(());
        }

        let revision = self
            .db
            .binding_write_revision(binding.id, binding_write_revision)
            .await?
            .context("conditional-delete probe binding revision disappeared")?;
        let fetch = self.surfaces.placement_fetcher(placement).await?;
        let writer = self
            .writes
            .placement_writer_at_revision(placement, &revision)
            .await?;
        let deleter = self
            .writes
            .placement_deleter(placement, binding.resource_version, generation.unwrap_or(1))
            .await?;
        let key = format!(
            ".aos-internal/conditional-delete-probes/{}-{}",
            binding.id, binding_write_revision
        );
        let execution =
            probe_schedule(fetch.as_ref(), writer.as_ref(), deleter.as_ref(), &key).await?;
        let state = execution.state;
        complete_semantic_probe(
            execution,
            self.record(
                &binding,
                binding_write_revision,
                purpose,
                generation,
                capability_fingerprint,
                if state == ProbeState::Valid {
                    "valid"
                } else {
                    "invalid"
                },
                expected_resource_version,
                now,
            ),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn record(
        &self,
        binding: &crate::db::BindingRecord,
        binding_write_revision: i64,
        delete_credential_purpose: Option<String>,
        delete_credential_generation: Option<i64>,
        capability_fingerprint: String,
        state: &str,
        expected_resource_version: Option<i64>,
        observed_at: i64,
    ) -> Result<()> {
        self.db
            .record_oci_conditional_delete_capability(&RecordOciConditionalDeleteCapability {
                binding_id: binding.id,
                binding_write_revision,
                binding_resource_version: binding.resource_version,
                delete_credential_purpose,
                delete_credential_generation,
                capability_fingerprint,
                state: state.to_string(),
                expected_resource_version,
                observed_at,
            })
            .await?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbeState {
    Valid,
    Invalid,
}

struct ProbeExecution {
    state: ProbeState,
    cleanup_error: Option<anyhow::Error>,
}

async fn complete_semantic_probe<F>(execution: ProbeExecution, record: F) -> Result<()>
where
    F: Future<Output = Result<()>>,
{
    // Revocation is the safety effect. Persist it before reporting cleanup so
    // a stale prior `valid` observation cannot remain usable during retries.
    record.await?;
    if let Some(error) = execution.cleanup_error {
        return Err(error);
    }
    Ok(())
}

async fn probe_schedule(
    fetch: &dyn SurfaceFetch,
    writer: &dyn SurfaceWrite,
    deleter: &dyn SurfaceWrite,
    key: &str,
) -> Result<ProbeExecution> {
    let nonce = uuid::Uuid::new_v4().simple().to_string();
    let first = format!("aos conditional delete probe A {nonce}").into_bytes();
    let second = format!("aos conditional delete probe B {nonce}").into_bytes();

    let result: Result<ProbeState> = async {
        writer.write(key, &first).await?;
        let first_evidence = exact_evidence(fetch, key, &first).await?;
        writer.write(key, &second).await?;
        match deleter
            .delete_if_matches(key, &precondition(&first_evidence))
            .await?
        {
            SurfaceDeleteOutcome::PreconditionFailed { .. } => {}
            SurfaceDeleteOutcome::Deleted { .. }
            | SurfaceDeleteOutcome::ConditionalDeleteAcknowledged { .. }
            | SurfaceDeleteOutcome::NotFound => {
                return Ok(ProbeState::Invalid);
            }
        }

        let second_evidence = exact_evidence(fetch, key, &second).await?;
        let second_precondition = precondition(&second_evidence);
        let exact_delete = deleter.delete_if_matches(key, &second_precondition).await?;
        let exact_delete_confirmed = match exact_delete {
            SurfaceDeleteOutcome::Deleted {
                etag,
                content_hash,
                size,
            } => {
                etag == second_precondition.etag
                    && content_hash == second_precondition.content_hash
                    && size == second_precondition.size
            }
            SurfaceDeleteOutcome::ConditionalDeleteAcknowledged { etag } => {
                second_precondition.etag.as_deref() == Some(etag.as_str())
            }
            SurfaceDeleteOutcome::NotFound | SurfaceDeleteOutcome::PreconditionFailed { .. } => {
                false
            }
        };
        if !exact_delete_confirmed {
            return Ok(ProbeState::Invalid);
        }
        if fetch.size(key).await?.is_some() {
            return Ok(ProbeState::Invalid);
        }
        Ok(ProbeState::Valid)
    }
    .await;

    match result {
        Ok(ProbeState::Valid) => Ok(ProbeExecution {
            state: ProbeState::Valid,
            cleanup_error: None,
        }),
        Ok(ProbeState::Invalid) => {
            // The key is reserved exclusively to this service and deterministic
            // per binding revision, so cleanup cannot remove user data. A
            // cleanup failure must not delay capability revocation.
            let cleanup_error = writer
                .delete(key)
                .await
                .context("cleaning invalid conditional-delete probe bytes")
                .err();
            Ok(ProbeExecution {
                state: ProbeState::Invalid,
                cleanup_error,
            })
        }
        Err(error) => {
            // Transport failures have no semantic conclusion. Best-effort
            // cleanup is folded into the retry error and the prior observation
            // remains subject to its normal freshness expiry.
            if let Err(cleanup_error) = writer.delete(key).await {
                return Err(error.context(format!(
                    "conditional-delete probe cleanup also failed: {cleanup_error:#}"
                )));
            }
            Err(error)
        }
    }
}

async fn exact_evidence(
    fetch: &dyn SurfaceFetch,
    key: &str,
    expected: &[u8],
) -> Result<crate::fetch::SurfaceObjectEvidence> {
    let evidence = fetch
        .inventory_evidence_bounded(key, PROBE_MAX_BYTES)
        .await?
        .context("conditional-delete probe object disappeared")?;
    let expected_sha256: [u8; 32] = Sha256::digest(expected).into();
    anyhow::ensure!(
        evidence.size == expected.len() as i64
            && evidence.sha256 == expected_sha256
            && evidence.strong_etag.is_some(),
        "conditional-delete probe read returned another object identity"
    );
    Ok(evidence)
}

fn precondition(evidence: &crate::fetch::SurfaceObjectEvidence) -> SurfaceDeletePrecondition {
    SurfaceDeletePrecondition {
        etag: evidence.strong_etag.clone(),
        content_hash: Some(format!("sha256:{}", hex::encode(evidence.sha256))),
        size: Some(evidence.size),
    }
}

fn capability_fingerprint(kind: &str, revision: i64) -> String {
    hex::encode(Sha256::digest(
        format!("aos-hub-conditional-delete-probe-v1\0{kind}\0{revision}").as_bytes(),
    ))
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use async_trait::async_trait;

    use super::*;

    #[derive(Default)]
    struct MemoryProvider {
        objects: Mutex<BTreeMap<String, Vec<u8>>>,
        ignores_precondition: bool,
        fails_cleanup: bool,
    }

    #[async_trait]
    impl SurfaceFetch for MemoryProvider {
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

        async fn inventory_evidence_bounded(
            &self,
            path: &str,
            _maximum_bytes: u64,
        ) -> Result<Option<crate::fetch::SurfaceObjectEvidence>> {
            Ok(self.objects.lock().unwrap().get(path).map(|bytes| {
                crate::fetch::SurfaceObjectEvidence {
                    sha256: Sha256::digest(bytes).into(),
                    size: bytes.len() as i64,
                    strong_etag: Some(format!("\"{}\"", hex::encode(Sha256::digest(bytes)))),
                }
            }))
        }

        fn describe(&self) -> String {
            "memory probe".into()
        }
    }

    #[async_trait]
    impl SurfaceWrite for MemoryProvider {
        async fn write(&self, path: &str, bytes: &[u8]) -> Result<()> {
            self.objects
                .lock()
                .unwrap()
                .insert(path.to_string(), bytes.to_vec());
            Ok(())
        }

        async fn delete(&self, path: &str) -> Result<()> {
            if self.fails_cleanup {
                anyhow::bail!("injected cleanup failure");
            }
            self.objects.lock().unwrap().remove(path);
            Ok(())
        }

        async fn delete_if_matches(
            &self,
            path: &str,
            expected: &SurfaceDeletePrecondition,
        ) -> Result<SurfaceDeleteOutcome> {
            let mut objects = self.objects.lock().unwrap();
            let Some(bytes) = objects.get(path) else {
                return Ok(SurfaceDeleteOutcome::NotFound);
            };
            let etag = format!("\"{}\"", hex::encode(Sha256::digest(bytes)));
            if !self.ignores_precondition && expected.etag.as_deref() != Some(&etag) {
                return Ok(SurfaceDeleteOutcome::PreconditionFailed {
                    detail: "changed".into(),
                });
            }
            let bytes = objects.remove(path).unwrap();
            Ok(SurfaceDeleteOutcome::Deleted {
                etag: Some(etag),
                content_hash: Some(format!("sha256:{}", hex::encode(Sha256::digest(&bytes)))),
                size: Some(bytes.len() as i64),
            })
        }
    }

    #[tokio::test]
    async fn probe_is_restart_safe_and_removes_reserved_bytes() {
        let provider = MemoryProvider::default();
        let key = ".aos-internal/conditional-delete-probes/1-1";
        provider
            .write(key, b"bytes left before crash")
            .await
            .unwrap();
        let execution = probe_schedule(&provider, &provider, &provider, key)
            .await
            .unwrap();
        assert_eq!(execution.state, ProbeState::Valid);
        assert!(execution.cleanup_error.is_none());
        assert!(provider.fetch(key).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn probe_rejects_a_backend_that_deletes_the_replacement() {
        let provider = MemoryProvider {
            ignores_precondition: true,
            ..Default::default()
        };
        let key = ".aos-internal/conditional-delete-probes/1-1";
        let execution = probe_schedule(&provider, &provider, &provider, key)
            .await
            .unwrap();
        assert_eq!(execution.state, ProbeState::Invalid);
        assert!(execution.cleanup_error.is_none());
        assert!(provider.fetch(key).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn semantic_failure_revokes_prior_valid_before_cleanup_retry() {
        let provider = MemoryProvider {
            ignores_precondition: true,
            fails_cleanup: true,
            ..Default::default()
        };
        let key = ".aos-internal/conditional-delete-probes/1-1";
        let execution = probe_schedule(&provider, &provider, &provider, key)
            .await
            .unwrap();
        assert_eq!(execution.state, ProbeState::Invalid);
        assert!(execution.cleanup_error.is_some());

        let persisted = Mutex::new(ProbeState::Valid);
        let result = complete_semantic_probe(execution, async {
            *persisted.lock().unwrap() = ProbeState::Invalid;
            Ok(())
        })
        .await;
        assert!(result.is_err());
        assert_eq!(*persisted.lock().unwrap(), ProbeState::Invalid);
    }
}

//! Connects publication inventory to private direct staging and final barriers.
//!
//! Every independent object, including mutable narinfo leaves, stages before
//! final completion. Native derives the authenticated dependency graph; the
//! client never treats path shape or a parallel HTTP write as leaf authority.

use std::os::fd::OwnedFd;
use std::time::Duration;

use anyhow::{Context as _, Result};
use aos_net::direct_upload::{
    AdmittedSource, DirectTransferMetrics, DirectTransferSummary, SourceWaveBudget,
};
use aos_remote::hub_types::direct_upload::{
    DirectDependencyPhase, DirectUploadTarget, WireInteger,
};
use aos_remote::{DirectStageFile, DirectUploadOptions, HubClient, hub_types};

use super::inventory::open_publication_object;
use crate::cli::HubAccessArgs;

pub(super) async fn upload_if_required(
    options: &DirectUploadOptions,
    hub: &HubClient,
    prepared: &aos_remote::PreparedDirectPublication,
    root: &OwnedFd,
    declared: &[hub_types::RegistryPublicationObjectInput],
    objects: &[&hub_types::RegistryPublicationObject],
) -> Result<bool> {
    let publication_id = &prepared.publication.publication_id;
    let coordinator = prepared.open_coordinator(hub, options).await?;

    let declared: std::collections::BTreeMap<_, _> = declared
        .iter()
        .map(|input| (input.path.as_str(), input))
        .collect();
    anyhow::ensure!(
        declared.len() == objects.len(),
        "publication direct inventory count differs"
    );
    let mut seen_paths = std::collections::BTreeSet::new();
    let mut seen_ids = std::collections::BTreeSet::new();
    for object in objects {
        let input = declared
            .get(object.path.as_str())
            .copied()
            .context("publication direct response introduced a path")?;
        anyhow::ensure!(
            seen_paths.insert(object.path.as_str())
                && seen_ids.insert(object.object_id)
                && object.object_id > 0
                && input.sha256 == object.sha256
                && input.byte_size == object.byte_size
                && input.kind == object.kind
                && input.media_type == object.media_type,
            "publication direct response changed the exact declared object set"
        );
    }

    let mut pending = objects
        .iter()
        .copied()
        .filter(|object| !object.verified)
        .peekable();
    let mut staged = false;
    while pending.peek().is_some() {
        let mut files = Vec::new();
        let mut budget = SourceWaveBudget::default();
        while let Some(object) = pending.peek().copied() {
            let byte_size = u64::try_from(object.byte_size)
                .context("publication direct object size is invalid")?;
            // Large descriptors do not retain whole-file body buffers. Reserve
            // the actual fixed-width part catalogue and descriptor count.
            if !budget.reserve(byte_size, coordinator.part_size())? {
                break;
            }
            let input = declared
                .get(object.path.as_str())
                .copied()
                .context("publication response introduced an undeclared direct object")?;
            anyhow::ensure!(
                input.sha256 == object.sha256
                    && input.byte_size == object.byte_size
                    && input.kind == object.kind
                    && input.media_type == object.media_type,
                "publication response changed a declared direct object"
            );
            let path = input.path.clone();
            let source_root = root.try_clone()?;
            let file =
                tokio::task::spawn_blocking(move || open_publication_object(&source_root, &path))
                    .await
                    .context("publication source worker failed")??;
            let source =
                AdmittedSource::admit(file, byte_size, &object.sha256, coordinator.part_size())
                    .await?;
            files.push(DirectStageFile {
                target: DirectUploadTarget::PublicationObject {
                    publication_id: publication_id.to_owned(),
                    surface_object_id: WireInteger::new(
                        u64::try_from(object.object_id)
                            .context("publication direct object ID is invalid")?,
                    ),
                    path: object.path.clone(),
                },
                source,
                phase: if object.kind == "immutable" {
                    DirectDependencyPhase::Content
                } else {
                    DirectDependencyPhase::Visibility
                },
            });
            pending.next();
        }
        coordinator.stage(files).await?;
        staged = true;
    }
    if staged {
        coordinator.finish(Duration::from_secs(3600)).await?;
    }
    Ok(true)
}

/// Reports the invocation's shared counters after its terminal result or failure.
pub(super) fn report_on_completion(
    options: &DirectUploadOptions,
) -> InvocationReport<impl FnOnce(DirectTransferSummary)> {
    InvocationReport::new(options, |summary| {
        eprintln!("Direct upload client: {summary}");
    })
}

/// Retains original metrics across early errors and final publication controls.
pub(super) struct InvocationReport<F: FnOnce(DirectTransferSummary)> {
    metrics: std::sync::Arc<DirectTransferMetrics>,
    report: Option<F>,
}

impl<F: FnOnce(DirectTransferSummary)> InvocationReport<F> {
    fn new(options: &DirectUploadOptions, report: F) -> Self {
        Self {
            metrics: std::sync::Arc::clone(&options.metrics),
            report: Some(report),
        }
    }

    /// Suppresses direct diagnostics after positive Legacy policy discovery.
    pub(super) fn suppress(&mut self) {
        self.report = None;
    }
}

impl<F: FnOnce(DirectTransferSummary)> Drop for InvocationReport<F> {
    fn drop(&mut self) {
        if let Some(report) = self.report.take() {
            report(self.metrics.snapshot());
        }
    }
}

struct PublicationAuthentication(HubAccessArgs);

impl std::fmt::Debug for PublicationAuthentication {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PublicationAuthentication([redacted])")
    }
}

#[async_trait::async_trait]
impl aos_remote::DirectHubAuthentication for PublicationAuthentication {
    async fn authenticate(
        &self,
        canonical_hub: &str,
    ) -> Result<HubClient, aos_net::direct_upload::DirectClientError> {
        crate::commands::hub::client::hub_client(canonical_hub, self.0.token.as_deref())
            .await
            .map_err(|_| aos_net::direct_upload::DirectClientError::Denied)
    }
}

pub(super) fn options(access: &HubAccessArgs) -> DirectUploadOptions {
    DirectUploadOptions {
        authentication: Some(std::sync::Arc::new(PublicationAuthentication(
            access.clone(),
        ))),
        journal: access.direct_upload_journal.clone(),
        provider_policy: access.direct_provider_policy.clone(),
        new_run: access.new_direct_upload_run,
        ..DirectUploadOptions::default()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use aos_net::direct_upload::DirectControlKind;

    use super::*;

    #[tokio::test]
    async fn invocation_summary_observes_terminal_commit_after_staging() {
        let options = DirectUploadOptions::default();
        let observed = Arc::new(Mutex::new(Vec::new()));
        let summaries = Arc::clone(&observed);

        let result: Result<()> = async {
            let _report = InvocationReport::new(&options, move |summary| {
                summaries.lock().unwrap().push(summary);
            });
            options
                .metrics
                .record_control_attempt(DirectControlKind::Complete);
            assert!(observed.lock().unwrap().is_empty());
            assert_eq!(
                options
                    .metrics
                    .snapshot()
                    .control_attempts(DirectControlKind::PublicationCommit),
                0
            );

            tokio::task::yield_now().await;
            options
                .metrics
                .record_control_attempt(DirectControlKind::PublicationCommit);
            assert!(observed.lock().unwrap().is_empty());
            Ok(())
        }
        .await;

        result.unwrap();
        let summaries = observed.lock().unwrap();
        assert_eq!(summaries.len(), 1);
        assert_eq!(
            summaries[0].control_attempts(DirectControlKind::Complete),
            1
        );
        assert_eq!(
            summaries[0].control_attempts(DirectControlKind::PublicationCommit),
            1
        );
        assert_eq!(
            options
                .metrics
                .snapshot()
                .control_attempts(DirectControlKind::PublicationCommit),
            1
        );
    }

    #[tokio::test]
    async fn invocation_summary_preserves_original_attempts_on_early_and_terminal_failures() {
        for failed_control in [
            DirectControlKind::ManifestBegin,
            DirectControlKind::PublicationCommit,
        ] {
            let options = DirectUploadOptions::default();
            let observed = Arc::new(Mutex::new(Vec::new()));
            let summaries = Arc::clone(&observed);

            let result: Result<()> = async {
                let _report = InvocationReport::new(&options, move |summary| {
                    summaries.lock().unwrap().push(summary);
                });
                options
                    .metrics
                    .record_control_attempt(DirectControlKind::Identity);
                tokio::task::yield_now().await;
                options.metrics.record_control_attempt(failed_control);
                anyhow::bail!("publication control was refused")
            }
            .await;

            assert!(result.is_err());
            let summaries = observed.lock().unwrap();
            assert_eq!(summaries.len(), 1);
            assert_eq!(
                summaries[0].control_attempts(DirectControlKind::Identity),
                1
            );
            assert_eq!(summaries[0].control_attempts(failed_control), 1);
            assert_eq!(summaries[0].provider_successes, 0);
            assert_eq!(summaries[0].acknowledged_payload_bytes, 0);
            assert_eq!(
                options.metrics.snapshot().control_attempts(failed_control),
                1
            );
        }
    }

    #[test]
    fn positive_legacy_policy_suppresses_direct_invocation_summary() {
        let options = DirectUploadOptions::default();
        let mut report = InvocationReport::new(&options, |_| {
            panic!("Legacy policy emitted direct upload diagnostics");
        });

        report.suppress();
        drop(report);
    }
}

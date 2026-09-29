//! Connects public discovery, durable waves and server-owned visibility barriers.
//!
//! The same coordinator and provider pool serve publication, cache and OCI
//! adapters. Private staging may finish before the authoritative graph allows
//! final promotion. Only actual Committed replies permit a caller's release
//! visibility step; StagedVerified never satisfies that barrier.

use std::fmt;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aos_net::direct_upload::{
    AdmittedSource, DirectClientError, DirectUploadControl, DirectUploadObject, ProviderOptions,
    ProviderTransport, SourceWaveBudget, SqliteDirectCheckpoints, upload_direct_batch,
};
use aos_proto_types::direct_upload::*;
use sha2::{Digest as _, Sha256};

use super::{super::HubClient, DirectHubControl};

/// One original admitted descriptor to stage under its canonical logical owner.
#[derive(Debug)]
pub struct DirectStageFile {
    /// Cache path, publication object identity or retained OCI upload identity.
    pub target: DirectUploadTarget,
    /// Original full/part hash catalogue and position-independent descriptor.
    pub source: AdmittedSource,
    /// Conservative client hint; Native independently derives final authority.
    pub phase: DirectDependencyPhase,
}

/// Reuses private retry custody and one provider pool across packed file waves.
pub struct DirectUploadCoordinator {
    control: super::refresh::RefreshingControl,
    store: SqliteDirectCheckpoints,
    provider: ProviderTransport,
    capabilities: DirectUploadCapabilities,
    metrics: std::sync::Arc<aos_net::direct_upload::DirectTransferMetrics>,
    started: std::time::Instant,
    stage_millis: std::sync::atomic::AtomicU64,
    barrier_millis: std::sync::atomic::AtomicU64,
}

impl fmt::Debug for DirectUploadCoordinator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DirectUploadCoordinator")
            .field("provider", &self.provider)
            .finish_non_exhaustive()
    }
}

impl DirectUploadCoordinator {
    /// Opens an explicit private run using already-authenticated direct discovery.
    ///
    /// The fixed namespace commits the canonical Hub, stable deployment and
    /// principal IDs, and canonical resource owner. The caller selects a local
    /// journal pathname in an admitted mode0700 directory. An existing file is
    /// resumed exactly; it is never truncated, migrated or silently reset.
    /// Explicit new runs select a new pathname and preserve old journals and
    /// unresolved server fences. No provider body is sent by this constructor.
    ///
    /// # Errors
    /// Refuses legacy/expired discovery, invalid actor identity, unsafe provider
    /// policy, changed private journal identity or file custody failures.
    pub async fn open(
        hub: &HubClient,
        capabilities: DirectUploadCapabilities,
        checkpoint: &Path,
        options: ProviderOptions,
    ) -> Result<Self, DirectClientError> {
        Self::open_with_authentication(hub, capabilities, checkpoint, options, None).await
    }

    /// Opens a run with its original, origin-pinned renewable credentials.
    ///
    /// # Errors
    /// Refuses the same custody and discovery failures as [`Self::open`].
    pub async fn open_with_authentication(
        hub: &HubClient,
        capabilities: DirectUploadCapabilities,
        checkpoint: &Path,
        options: ProviderOptions,
        authentication: Option<std::sync::Arc<dyn super::DirectHubAuthentication>>,
    ) -> Result<Self, DirectClientError> {
        Self::open_with_metrics(
            hub,
            capabilities,
            checkpoint,
            options,
            authentication,
            std::sync::Arc::new(aos_net::direct_upload::DirectTransferMetrics::default()),
        )
        .await
    }

    pub(super) async fn open_with_metrics(
        hub: &HubClient,
        capabilities: DirectUploadCapabilities,
        checkpoint: &Path,
        options: ProviderOptions,
        authentication: Option<std::sync::Arc<dyn super::DirectHubAuthentication>>,
        metrics: std::sync::Arc<aos_net::direct_upload::DirectTransferMetrics>,
    ) -> Result<Self, DirectClientError> {
        capabilities
            .validate_at_for(&discovery_target(&capabilities), now()?)
            .map_err(|_| DirectClientError::Invalid)?;
        if capabilities.transfer_mode != DirectAdvertisedTransferMode::DirectRequired {
            return Err(DirectClientError::Invalid);
        }
        let namespace = checkpoint_namespace(hub, &capabilities)?;
        let create = match std::fs::symlink_metadata(checkpoint) {
            Ok(_) => false,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
            Err(_) => return Err(DirectClientError::Checkpoint),
        };
        let store = SqliteDirectCheckpoints::open(checkpoint, &namespace, create).await?;
        let provider = ProviderTransport::new(capabilities.profiles.clone(), options)
            .map_err(|_| DirectClientError::Invalid)?
            .with_metrics(metrics.clone());
        Ok(Self {
            control: super::refresh::RefreshingControl::new(
                hub,
                capabilities.clone(),
                authentication,
                metrics.clone(),
            )?,
            store,
            provider,
            capabilities,
            metrics,
            started: std::time::Instant::now(),
            stage_millis: std::sync::atomic::AtomicU64::new(0),
            barrier_millis: std::sync::atomic::AtomicU64::new(0),
        })
    }

    /// Returns a compact value-free diagnostic observation, including failures.
    ///
    /// This is client instrumentation only; provider/Native logs must separately
    /// prove effects, byte confinement and throughput for the actual workload.
    pub fn diagnostic_summary(&self) -> String {
        use std::sync::atomic::Ordering;
        format!(
            "{} wall_ms={} stage_ms={} barrier_ms={}",
            self.metrics.snapshot(),
            self.started.elapsed().as_millis(),
            self.stage_millis.load(Ordering::Relaxed),
            self.barrier_millis.load(Ordering::Relaxed)
        )
    }

    /// Returns conservative geometry admitted by the current owner policy.
    pub fn part_size(&self) -> u64 {
        (8 * 1024 * 1024)
            .max(self.capabilities.minimum_part_bytes.get())
            .min(self.capabilities.maximum_part_bytes.get())
    }

    /// Returns the authenticated canonical owner, including resolved cache ID.
    pub fn target(&self) -> &DirectCapabilitiesTarget {
        &self.capabilities.target
    }

    /// Stages at most64 admitted files in count/byte packed before-effect waves.
    ///
    /// A returned StagedVerified projection allows subsequent independent waves
    /// to proceed. Call [`Self::finish`] after all files have been staged before
    /// any public root/channel/tag commit. No request uses a proxy body fallback.
    ///
    /// # Errors
    /// Refuses changed source/owner/geometry, stale discovery, persistence,
    /// provider control fences, malformed replies or exhausted bounded retries.
    pub async fn stage(&self, files: Vec<DirectStageFile>) -> Result<(), DirectClientError> {
        let _phase_clock = PhaseClock {
            started: std::time::Instant::now(),
            total: &self.stage_millis,
        };
        if files.is_empty() || files.len() > MAX_DIRECT_BATCH_ITEMS {
            return Err(DirectClientError::Invalid);
        }
        let mut budget = SourceWaveBudget::default();
        for file in &files {
            if !budget
                .reserve(file.source.byte_size(), file.source.part_size())
                .map_err(|_| DirectClientError::Invalid)?
            {
                return Err(DirectClientError::Invalid);
            }
        }
        let discovery = self.control.snapshot().await?;
        let mut objects = std::collections::VecDeque::with_capacity(files.len());
        for file in files {
            let target =
                encode_direct_control(&file.target).map_err(|_| DirectClientError::Invalid)?;
            let intent = DirectUploadIntent {
                version: 1,
                client_operation_id: commitment(
                    "object-operation",
                    &[self.store.run_id().as_bytes(), &target],
                ),
                target: file.target,
                expected_sha256: file.source.sha256().to_owned(),
                byte_size: WireInteger::new(file.source.byte_size()),
                part_size: WireInteger::new(file.source.part_size()),
                dependency_phase: file.phase,
                transfer_mode: DirectTransferMode::DirectRequired,
            };
            intent.validate().map_err(|_| DirectClientError::Invalid)?;
            if !target_matches(&intent.target, &self.capabilities.target)
                || intent.byte_size.get() > self.capabilities.maximum_object_bytes.get()
                || intent.part_size.get() != self.part_size()
            {
                return Err(DirectClientError::Invalid);
            }
            objects.push_back(DirectUploadObject {
                intent,
                source: file.source,
                placements: Vec::new(),
                discovery: discovery.clone(),
            });
        }
        while !objects.is_empty() {
            let discovery = self.control.snapshot().await?;
            let mut wave = Vec::new();
            while wave.len() < self.capabilities.maximum_batch_items as usize {
                let Some(next) = objects.front() else {
                    break;
                };
                let mut intents: Vec<_> = wave
                    .iter()
                    .map(|object: &DirectUploadObject| object.intent.clone())
                    .collect();
                intents.push(next.intent.clone());
                let request = DirectBeginBatch {
                    operation_id: "00".repeat(32),
                    items: intents,
                };
                let bytes =
                    encode_direct_control(&request).map_err(|_| DirectClientError::Invalid)?;
                if bytes.len() > self.capabilities.maximum_control_bytes as usize {
                    break;
                }
                wave.push(objects.pop_front().ok_or(DirectClientError::Invalid)?);
            }
            if wave.is_empty() {
                return Err(DirectClientError::Invalid);
            }
            for object in &mut wave {
                object.discovery = discovery.clone();
            }
            let statuses =
                upload_direct_batch(&self.control, &self.store, &self.provider, wave).await?;
            if statuses.iter().any(|status| {
                !matches!(
                    status.state,
                    DirectSessionState::StagedVerified | DirectSessionState::Committed
                )
            }) {
                return Err(DirectClientError::Blocked);
            }
        }
        Ok(())
    }

    /// Replays all original completions until actual server-owned final commit.
    ///
    /// Callers stop adding files before invoking this barrier. Each compact
    /// request keeps its original operation, manifest and expected resource
    /// version even after logical progress. A timeout preserves the journal;
    /// it neither aborts nor authorizes an alternative provider effect.
    ///
    /// # Errors
    /// Refuses stale/changed discovery, source/placement mismatches, unknown or
    /// refused control state, unexpected responses, journal failures or timeout.
    pub async fn finish(&self, timeout: Duration) -> Result<(), DirectClientError> {
        let _phase_clock = PhaseClock {
            started: std::time::Instant::now(),
            total: &self.barrier_millis,
        };
        if timeout.is_zero() || timeout > Duration::from_secs(60 * 60) {
            return Err(DirectClientError::Invalid);
        }
        let deadline = tokio::time::Instant::now()
            .checked_add(timeout)
            .ok_or(DirectClientError::Invalid)?;
        loop {
            let mut after = None;
            let mut pending = false;
            let mut count = 0u64;
            loop {
                let discovery = self.control.snapshot().await?;
                let page = self
                    .store
                    .completion_page(
                        after.as_deref(),
                        self.capabilities.maximum_batch_items as usize,
                    )
                    .await?;
                if !page.items.is_empty() {
                    let mut requests = Vec::with_capacity(page.items.len());
                    for item in &page.items {
                        let placements: Vec<_> = item
                            .request
                            .manifests
                            .iter()
                            .map(|manifest| manifest.placement.clone())
                            .collect();
                        discovery
                            .validate_placements_for(
                                &discovery_target(&discovery),
                                &placements,
                                now()?,
                            )
                            .map_err(|_| DirectClientError::Invalid)?;
                        requests.push(item.request.clone());
                    }
                    let members: Vec<_> = requests
                        .iter()
                        .map(|request| request.operation_id.as_bytes())
                        .collect();
                    let batch = DirectBatch {
                        operation_id: commitment("completion-barrier-wave", &members),
                        items: requests,
                    };
                    if encode_direct_control(&batch)
                        .map_err(|_| DirectClientError::Invalid)?
                        .len()
                        > self.capabilities.maximum_control_bytes as usize
                    {
                        return Err(DirectClientError::Invalid);
                    }
                    let request = DirectUploadRequest::CompleteBatch(batch);
                    let response = execute_retry(&self.control, &request).await?;
                    if response.sessions.len() != page.items.len() || !response.grants.is_empty() {
                        return Err(DirectClientError::Invalid);
                    }
                    for status in &response.sessions {
                        let item = page
                            .items
                            .iter()
                            .find(|item| item.request.session == status.session)
                            .ok_or(DirectClientError::Invalid)?;
                        let placements: Vec<_> = item
                            .request
                            .manifests
                            .iter()
                            .map(|manifest| manifest.placement.clone())
                            .collect();
                        status
                            .validate_for(&item.request.session, &item.intent, &placements)
                            .map_err(|_| DirectClientError::Invalid)?;
                        match status.state {
                            DirectSessionState::Committed => {}
                            DirectSessionState::StagedVerified => pending = true,
                            _ => return Err(DirectClientError::Blocked),
                        }
                    }
                    count = count
                        .checked_add(page.items.len() as u64)
                        .ok_or(DirectClientError::Invalid)?;
                }
                let Some(next) = page.next_after else {
                    break;
                };
                after = Some(next);
                if tokio::time::Instant::now() >= deadline {
                    return Err(DirectClientError::ControlUnavailable);
                }
            }
            if count == 0 {
                return Err(DirectClientError::Invalid);
            }
            if !pending {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(DirectClientError::ControlUnavailable);
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }
}

/// Commits authenticated source identity for a selected local retry journal.
///
/// # Errors
/// Refuses malformed/stale capability metadata or unsafe configured Hub URLs.
pub fn checkpoint_namespace(
    hub: &HubClient,
    capabilities: &DirectUploadCapabilities,
) -> Result<String, DirectClientError> {
    capabilities
        .validate_at_for(&discovery_target(&capabilities), now()?)
        .map_err(|_| DirectClientError::Invalid)?;
    let _ = DirectHubControl::new(hub)?;
    let owner =
        encode_direct_control(&capabilities.target).map_err(|_| DirectClientError::Invalid)?;
    Ok(commitment(
        "journal-namespace",
        &[
            hub.base.as_bytes(),
            capabilities.deployment_id.as_bytes(),
            capabilities.principal_id.as_bytes(),
            &owner,
        ],
    ))
}

fn target_matches(target: &DirectUploadTarget, owner: &DirectCapabilitiesTarget) -> bool {
    match (target, owner) {
        (
            DirectUploadTarget::CacheObject { cache_id, .. },
            DirectCapabilitiesTarget::Cache { cache_id: expected },
        ) => cache_id == expected,
        (
            DirectUploadTarget::PublicationObject { publication_id, .. },
            DirectCapabilitiesTarget::Publication {
                publication_id: expected,
            },
        ) => publication_id == expected,
        (DirectUploadTarget::OciBlob { .. }, DirectCapabilitiesTarget::OciRepository { .. }) => {
            true
        }
        _ => false,
    }
}

fn commitment(domain: &str, members: &[&[u8]]) -> String {
    let mut hash = Sha256::new();
    hash.update(b"aos.direct.adapter-operation.v1\0");
    for member in std::iter::once(domain.as_bytes()).chain(members.iter().copied()) {
        hash.update((member.len() as u64).to_be_bytes());
        hash.update(member);
    }
    hex::encode(hash.finalize())
}

fn now() -> Result<u64, DirectClientError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs().saturating_add(10))
        .map_err(|_| DirectClientError::Invalid)
}

async fn execute_retry(
    control: &impl DirectUploadControl,
    request: &DirectUploadRequest,
) -> Result<DirectUploadResponse, DirectClientError> {
    let mut result = Err(DirectClientError::ControlUnavailable);
    for _ in 0..3 {
        result = control.execute(request).await;
        if result != Err(DirectClientError::ControlUnavailable) {
            break;
        }
    }
    let response = result?;
    if !response.errors.is_empty() {
        return Err(DirectClientError::Blocked);
    }
    Ok(response)
}

pub(super) fn discovery_target(
    capabilities: &DirectUploadCapabilities,
) -> DirectCapabilitiesTarget {
    capabilities.requested_delivery_url.as_ref().map_or_else(
        || capabilities.target.clone(),
        |delivery_url| DirectCapabilitiesTarget::CacheDelivery {
            delivery_url: delivery_url.clone(),
        },
    )
}

impl DirectUploadCoordinator {
    /// Commits original OCI logical allocation custody before a bodyless POST.
    ///
    /// # Errors
    /// Refuses a non-OCI authenticated owner, changed source or journal failure.
    pub async fn prepare_oci_allocation(
        &self,
        sha256: &str,
        byte_size: u64,
    ) -> Result<aos_net::direct_upload::DirectOciAllocation, DirectClientError> {
        self.control.snapshot().await?;
        if !matches!(
            self.target(),
            DirectCapabilitiesTarget::OciRepository { .. }
        ) {
            return Err(DirectClientError::Invalid);
        }
        self.store.prepare_oci_allocation(sha256, byte_size).await
    }

    /// Retains a logical OCI owner after exact original allocation URI replay.
    ///
    /// # Errors
    /// Refuses changed original operation/source/owner or private custody failure.
    pub async fn retain_oci_allocation(
        &self,
        original: &aos_net::direct_upload::DirectOciAllocation,
        upload_id: &str,
    ) -> Result<aos_net::direct_upload::DirectOciAllocation, DirectClientError> {
        if !matches!(
            self.target(),
            DirectCapabilitiesTarget::OciRepository { .. }
        ) {
            return Err(DirectClientError::Invalid);
        }
        self.store.retain_oci_allocation(original, upload_id).await
    }
}

// Whole-call clocks include failed and cancelled work; no per-part hot-loop
// timestamps or object labels are retained.
struct PhaseClock<'a> {
    started: std::time::Instant,
    total: &'a std::sync::atomic::AtomicU64,
}

impl Drop for PhaseClock<'_> {
    fn drop(&mut self) {
        let millis = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let _ = self.total.fetch_update(
            std::sync::atomic::Ordering::Relaxed,
            std::sync::atomic::Ordering::Relaxed,
            |old| Some(old.saturating_add(millis)),
        );
    }
}

//! Connects public discovery, durable waves and server-owned visibility barriers.
//!
//! The same coordinator and provider pool serve publication, cache and OCI
//! adapters. Private staging may finish before the authoritative graph allows
//! final promotion. Only actual Committed replies permit a caller's release
//! visibility step; neither CompletingStaging nor StagedVerified satisfies it.

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
    /// A returned CompletingStaging or StagedVerified state allows independent waves
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
        let mut objects = Vec::with_capacity(files.len());
        let mut identities = std::collections::BTreeSet::new();
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
            if !identities.insert(intent.client_operation_id.clone())
                || !target_matches(&intent.target, &self.capabilities.target)
                || intent.byte_size.get() < self.capabilities.minimum_object_bytes.get()
                || intent.byte_size.get() > self.capabilities.maximum_object_bytes.get()
                || intent.part_size.get() != self.part_size()
            {
                return Err(DirectClientError::Invalid);
            }
            objects.push(DirectUploadObject {
                intent,
                source: file.source,
                placements: Vec::new(),
                discovery: discovery.clone(),
            });
        }
        let original_intents: Vec<_> = objects.iter().map(|object| object.intent.clone()).collect();
        let completions = self.store.retained_completions(&original_intents).await?;
        if completions.len() != objects.len() {
            return Err(DirectClientError::Checkpoint);
        }
        let mut remaining = std::collections::VecDeque::with_capacity(objects.len());
        for (object, completion) in objects.into_iter().zip(completions) {
            if let Some(completion) = completion {
                let placements: Vec<_> = completion
                    .request
                    .manifests
                    .iter()
                    .map(|manifest| manifest.placement.clone())
                    .collect();
                discovery
                    .validate_placements_for(&discovery_target(&discovery), &placements, now()?)
                    .map_err(|_| DirectClientError::Invalid)?;
            } else {
                remaining.push_back(object);
            }
        }
        let mut objects = remaining;
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
                    DirectSessionState::CompletingStaging
                        | DirectSessionState::StagedVerified
                        | DirectSessionState::Committed
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
                let discovery = before_deadline(deadline, self.control.snapshot()).await?;
                let page = before_deadline(
                    deadline,
                    self.store.completion_page(
                        after.as_deref(),
                        self.capabilities.maximum_batch_items as usize,
                    ),
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
                    let response =
                        before_deadline(deadline, execute_retry(&self.control, &request)).await?;
                    if response.sessions.len() != page.items.len() || !response.grants.is_empty() {
                        return Err(DirectClientError::Invalid);
                    }
                    let mut seen = std::collections::BTreeSet::new();
                    for status in &response.sessions {
                        if !seen.insert(&status.session.session_id) {
                            return Err(DirectClientError::Invalid);
                        }
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
                            DirectSessionState::CompletingStaging
                            | DirectSessionState::StagedVerified => pending = true,
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
            let next = tokio::time::Instant::now()
                .checked_add(Duration::from_millis(250))
                .unwrap_or(deadline)
                .min(deadline);
            tokio::time::sleep_until(next).await;
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
    response
        .validate()
        .map_err(|_| DirectClientError::Invalid)?;
    let DirectUploadRequest::CompleteBatch(batch) = request else {
        return Err(DirectClientError::Invalid);
    };
    if response.operation_id != batch.operation_id {
        return Err(DirectClientError::Invalid);
    }
    if !response.errors.is_empty() {
        return Err(DirectClientError::Blocked);
    }
    Ok(response)
}

async fn before_deadline<T>(
    deadline: tokio::time::Instant,
    future: impl std::future::Future<Output = Result<T, DirectClientError>>,
) -> Result<T, DirectClientError> {
    if tokio::time::Instant::now() >= deadline {
        return Err(DirectClientError::ControlUnavailable);
    }
    tokio::time::timeout_at(deadline, future)
        .await
        .map_err(|_| DirectClientError::ControlUnavailable)?
}

#[cfg(test)]
mod deadline_tests {
    use super::*;

    #[tokio::test]
    async fn held_snapshot_and_page_futures_end_at_original_finish_deadline() {
        for _ in 0..2 {
            let deadline = tokio::time::Instant::now() + Duration::from_millis(20);
            let held = std::future::pending::<Result<(), DirectClientError>>();
            let result =
                tokio::time::timeout(Duration::from_secs(1), before_deadline(deadline, held))
                    .await
                    .unwrap();
            assert_eq!(result, Err(DirectClientError::ControlUnavailable));
        }
    }

    #[tokio::test]
    async fn elapsed_deadline_never_polls_a_new_control_effect() {
        let expired = tokio::time::Instant::now() - Duration::from_millis(1);
        let late = std::future::poll_fn(|_| -> std::task::Poll<Result<(), DirectClientError>> {
            panic!("expired finish dispatched a new control effect");
        });
        assert_eq!(
            before_deadline(expired, late).await,
            Err(DirectClientError::ControlUnavailable)
        );
    }
}

#[cfg(test)]
mod pending_restart_tests {
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;
    use std::os::unix::fs::PermissionsExt as _;

    use aos_net::direct_upload::DirectCheckpointStore as _;

    use super::*;

    #[tokio::test]
    async fn restarted_pending_wave_sends_no_begin_or_provider_body_and_finishes_original() {
        let directory =
            std::env::temp_dir().join(format!("aos-direct-pending-test-{}", rand::random::<u64>()));
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let source_path = directory.join("source.nar");
        std::fs::write(&source_path, b"abc").unwrap();
        let checkpoint = directory.join("direct.sqlite");

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let hub = HubClient::connect_with_token(&origin, "original-owned-bearer").unwrap();
        let profile = DirectProviderProfile {
            placement_id: WireInteger::new(1),
            placement_resource_version: WireInteger::new(1),
            write_spec_version: WireInteger::new(1),
            binding_id: WireInteger::new(1),
            binding_resource_version: WireInteger::new(1),
            binding_write_revision: WireInteger::new(1),
            checksum_algorithm: DirectChecksumAlgorithm::Sha256,
            provider_origin: "https://provider.invalid".into(),
            profile_fingerprint: "af".repeat(32),
            private_policy_digest: "fe".repeat(32),
        };
        let capabilities = DirectUploadCapabilities {
            target: DirectCapabilitiesTarget::Cache {
                cache_id: "cache-1".into(),
            },
            requested_delivery_url: None,
            deployment_id: "deployment".into(),
            principal_id: "de".repeat(32),
            version: 1,
            capability: DIRECT_UPLOAD_CAPABILITY.into(),
            transfer_mode: DirectAdvertisedTransferMode::DirectRequired,
            config_generation: WireInteger::new(1),
            valid_until: WireInteger::new(now().unwrap() + 600),
            maximum_control_bytes: MAX_DIRECT_CONTROL_BYTES as u32,
            maximum_batch_items: 64,
            maximum_batch_parts: 64,
            maximum_object_bytes: WireInteger::new(MAX_DIRECT_OBJECT_BYTES),
            minimum_object_bytes: WireInteger::new(0),
            minimum_part_bytes: WireInteger::new(MIN_DIRECT_PART_BYTES),
            maximum_part_bytes: WireInteger::new(MAX_DIRECT_PART_BYTES),
            profiles: vec![profile.clone()],
        };
        let target = DirectUploadTarget::CacheObject {
            cache_id: "cache-1".into(),
            path: "nar/source.nar".into(),
        };
        let first = DirectUploadCoordinator::open(
            &hub,
            capabilities.clone(),
            &checkpoint,
            ProviderOptions::default(),
        )
        .await
        .unwrap();
        let target_bytes = encode_direct_control(&target).unwrap();
        let intent = DirectUploadIntent {
            version: 1,
            client_operation_id: commitment(
                "object-operation",
                &[first.store.run_id().as_bytes(), &target_bytes],
            ),
            target: target.clone(),
            expected_sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
                .into(),
            byte_size: WireInteger::new(3),
            part_size: WireInteger::new(first.part_size()),
            dependency_phase: DirectDependencyPhase::Content,
            transfer_mode: DirectTransferMode::DirectRequired,
        };
        let placement = DirectPlacementRef {
            placement_id: profile.placement_id,
            placement_fingerprint: "ab".repeat(32),
            placement_resource_version: profile.placement_resource_version,
            write_spec_version: profile.write_spec_version,
            binding_id: profile.binding_id,
            binding_resource_version: profile.binding_resource_version,
            binding_write_revision: profile.binding_write_revision,
            profile_fingerprint: profile.profile_fingerprint,
            private_policy_digest: profile.private_policy_digest,
            checksum_algorithm: profile.checksum_algorithm,
        };
        let session = DirectSessionRef {
            session_id: "original-session".into(),
            logical_fingerprint: intent.fingerprint().unwrap(),
        };
        let original_status = DirectSessionStatus {
            session: session.clone(),
            resource_version: WireInteger::new(1),
            intent: intent.clone(),
            placements: vec![placement.clone()],
            state: DirectSessionState::Active,
            parts: Vec::new(),
            next_cursor: None,
            outstanding_grants: false,
        };
        first.store.admit_intent(&intent).await.unwrap();
        first.store.admit_session(&original_status).await.unwrap();
        let observed = DirectManifestPart {
            part: DirectPart {
                part_number: 1,
                offset: WireInteger::new(0),
                byte_size: WireInteger::new(3),
                sha256: intent.expected_sha256.clone(),
                checksum: DirectPartChecksum {
                    algorithm: DirectChecksumAlgorithm::Sha256,
                    value: "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=".into(),
                },
            },
            etag: "\"original-etag\"".into(),
        };
        first
            .store
            .record_server_part(&session, &placement, &observed)
            .await
            .unwrap();
        let manifest_digest = canonical_manifest_digest(&intent, &placement, &[observed]).unwrap();
        let manifests = vec![DirectManifestCommitment {
            placement,
            manifest_digest,
            part_count: 1,
        }];
        let manifest_bytes = encode_direct_control(&manifests).unwrap();
        let manifest_commitment = hex::encode(Sha256::digest(&manifest_bytes));
        let original_complete = DirectCompleteRequest {
            session: session.clone(),
            operation_id: commitment(
                "complete",
                &[
                    session.session_id.as_bytes(),
                    session.logical_fingerprint.as_bytes(),
                    manifest_commitment.as_bytes(),
                ],
            ),
            expected_resource_version: WireInteger::new(1),
            manifests,
        };
        first
            .store
            .admit_complete(&original_complete)
            .await
            .unwrap();
        drop(first);

        let second = DirectUploadCoordinator::open(
            &hub,
            capabilities,
            &checkpoint,
            ProviderOptions::default(),
        )
        .await
        .unwrap();
        // Only the original Complete request may reach the Hub, twice: pending
        // verification, then final committed evidence. No Begin/grant/body path.
        let worker = std::thread::spawn(move || {
            let mut captured = Vec::new();
            for state in [
                DirectSessionState::CompletingStaging,
                DirectSessionState::Committed,
            ] {
                let started = std::time::Instant::now();
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(started.elapsed() < Duration::from_secs(5));
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(error) => panic!("local HTTP accept failed: {error}"),
                    }
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut request = Vec::new();
                loop {
                    let mut chunk = [0u8; 4096];
                    let count = stream.read(&mut chunk).unwrap();
                    assert!(count > 0);
                    request.extend_from_slice(&chunk[..count]);
                    assert!(request.len() <= MAX_DIRECT_CONTROL_BYTES);
                    let Some(headers_end) =
                        request.windows(4).position(|bytes| bytes == b"\r\n\r\n")
                    else {
                        continue;
                    };
                    let headers = String::from_utf8_lossy(&request[..headers_end]);
                    let length = headers
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length: ")
                                .and_then(|value| value.parse::<usize>().ok())
                        })
                        .unwrap();
                    if request.len() >= headers_end + 4 + length {
                        let body: DirectBatch<DirectCompleteRequest> = decode_direct_control(
                            &request[headers_end + 4..headers_end + 4 + length],
                        )
                        .unwrap();
                        assert_eq!(body.items, vec![original_complete.clone()]);
                        assert!(
                            headers
                                .starts_with("POST /aos.hub.v1.DirectUploadService/CompleteBatch ")
                        );
                        assert!(!request.windows(3).any(|bytes| bytes == b"abc"));
                        captured.push(body.clone());
                        let response = DirectUploadResponse {
                            operation_id: body.operation_id,
                            sessions: vec![DirectSessionStatus {
                                state,
                                resource_version: WireInteger::new(2),
                                ..original_status.clone()
                            }],
                            grants: Vec::new(),
                            errors: Vec::new(),
                        };
                        let bytes = encode_direct_control(&response).unwrap();
                        write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", bytes.len()).unwrap();
                        stream.write_all(&bytes).unwrap();
                        break;
                    }
                }
            }
            captured
        });

        second
            .stage_paths(vec![super::super::DirectStagePath {
                source: source_path,
                expected_sha256: Some(intent.expected_sha256.clone()),
                target,
                phase: DirectDependencyPhase::Content,
            }])
            .await
            .unwrap();
        second.finish(Duration::from_secs(5)).await.unwrap();
        let captured = worker.join().unwrap();
        assert_eq!(captured.len(), 2);
        assert_eq!(captured[0], captured[1]);
        drop(second);
        std::fs::remove_dir_all(directory).unwrap();
    }
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
        ) || byte_size < self.capabilities.minimum_object_bytes.get()
            || byte_size > self.capabilities.maximum_object_bytes.get()
        {
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

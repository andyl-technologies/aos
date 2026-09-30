//! Actual descriptor-stream scheduling and durable-custody protocol tests.
//!
//! The control/provider doubles prove client scheduling and replay. They do not
//! qualify SigV4, TLS, real provider settlement or the complete product adapters.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::sync::{
    Mutex,
    atomic::{AtomicUsize, Ordering},
};

use futures_util::TryStreamExt as _;
use sha2::{Digest as _, Sha256};

use super::*;
use crate::direct_upload::{ProviderContext, ProviderError, provider::portable_part};

type PartKey = (String, u64, u32);

fn key(session: &DirectSessionRef, placement: &DirectPlacementRef, number: u32) -> PartKey {
    (
        session.session_id.clone(),
        placement.placement_id.get(),
        number,
    )
}

#[derive(Default)]
struct Stored {
    intents: BTreeMap<String, DirectUploadIntent>,
    sessions: BTreeMap<String, DirectSessionStatus>,
    attempts: BTreeMap<PartKey, u64>,
    receipts: BTreeMap<PartKey, DirectPartReceipt>,
    observed: BTreeMap<PartKey, DirectManifestPart>,
    complete: BTreeMap<String, DirectCompleteRequest>,
}

#[derive(Default)]
struct Store(Mutex<Stored>);

#[async_trait]
impl DirectCheckpointStore for Store {
    async fn admit_intent(&self, intent: &DirectUploadIntent) -> Result<(), DirectClientError> {
        let mut state = self.0.lock().unwrap();
        if state
            .intents
            .get(&intent.client_operation_id)
            .is_some_and(|previous| previous != intent)
        {
            return Err(DirectClientError::Invalid);
        }
        state
            .intents
            .insert(intent.client_operation_id.clone(), intent.clone());
        Ok(())
    }

    async fn admit_session(&self, status: &DirectSessionStatus) -> Result<(), DirectClientError> {
        let mut state = self.0.lock().unwrap();
        if state
            .sessions
            .get(&status.session.session_id)
            .is_some_and(|previous| {
                previous.session != status.session
                    || previous.intent != status.intent
                    || previous.placements != status.placements
            })
        {
            return Err(DirectClientError::Invalid);
        }
        state
            .sessions
            .insert(status.session.session_id.clone(), status.clone());
        Ok(())
    }

    async fn grant_attempt(
        &self,
        session: &DirectSessionRef,
        placement: &DirectPlacementRef,
        number: u32,
        refresh: bool,
    ) -> Result<u64, DirectClientError> {
        let mut state = self.0.lock().unwrap();
        let counter = state
            .attempts
            .entry(key(session, placement, number))
            .or_insert(0);
        if refresh {
            *counter = counter
                .checked_add(1)
                .ok_or(DirectClientError::Checkpoint)?;
        }
        Ok(*counter)
    }

    async fn receipt(
        &self,
        session: &DirectSessionRef,
        placement: &DirectPlacementRef,
        number: u32,
    ) -> Result<Option<DirectPartReceipt>, DirectClientError> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .receipts
            .get(&key(session, placement, number))
            .cloned())
    }

    async fn record_receipt(&self, receipt: &DirectPartReceipt) -> Result<(), DirectClientError> {
        self.0.lock().unwrap().receipts.insert(
            key(
                &receipt.session,
                &receipt.placement,
                receipt.observed.part.part_number,
            ),
            receipt.clone(),
        );
        Ok(())
    }

    async fn record_server_part(
        &self,
        session: &DirectSessionRef,
        placement: &DirectPlacementRef,
        observed: &DirectManifestPart,
    ) -> Result<(), DirectClientError> {
        self.0.lock().unwrap().observed.insert(
            key(session, placement, observed.part.part_number),
            observed.clone(),
        );
        Ok(())
    }

    async fn observed_part(
        &self,
        session: &DirectSessionRef,
        placement: &DirectPlacementRef,
        number: u32,
    ) -> Result<Option<DirectManifestPart>, DirectClientError> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .observed
            .get(&key(session, placement, number))
            .cloned())
    }

    async fn admit_complete(
        &self,
        request: &DirectCompleteRequest,
    ) -> Result<DirectCompleteRequest, DirectClientError> {
        let mut state = self.0.lock().unwrap();
        if let Some(previous) = state.complete.get(&request.session.session_id) {
            if previous.session != request.session
                || previous.operation_id != request.operation_id
                || previous.manifests != request.manifests
            {
                return Err(DirectClientError::Invalid);
            }
            return Ok(previous.clone());
        }
        state
            .complete
            .insert(request.session.session_id.clone(), request.clone());
        Ok(request.clone())
    }

    async fn retained_complete(
        &self,
        session: &DirectSessionRef,
    ) -> Result<Option<DirectCompleteRequest>, DirectClientError> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .complete
            .get(&session.session_id)
            .cloned())
    }
}

struct Server {
    sessions: BTreeMap<String, DirectSessionStatus>,
    observed: BTreeMap<PartKey, DirectManifestPart>,
    grants: BTreeMap<String, DirectPartGrant>,
    controls: Vec<DirectUploadRequest>,
    fail_reports: usize,
    pending_completions: usize,
    blocked_begin: bool,
}

struct Control {
    state: Mutex<Server>,
    placements: Vec<DirectPlacementRef>,
}

impl Control {
    fn new(placements: Vec<DirectPlacementRef>) -> Self {
        Self {
            placements,
            state: Mutex::new(Server {
                sessions: BTreeMap::new(),
                observed: BTreeMap::new(),
                grants: BTreeMap::new(),
                controls: Vec::new(),
                fail_reports: 0,
                pending_completions: 0,
                blocked_begin: false,
            }),
        }
    }
}

fn fixture_session_key(session: &DirectSessionRef) -> &str {
    session.session_id.strip_prefix("session-").unwrap()
}

#[async_trait]
impl DirectUploadControl for Control {
    async fn execute(
        &self,
        request: &DirectUploadRequest,
    ) -> Result<DirectUploadResponse, DirectClientError> {
        let mut state = self.state.lock().unwrap();
        state.controls.push(request.clone());
        let mut response = DirectUploadResponse {
            operation_id: helpers::request_operation(request).into(),
            sessions: Vec::new(),
            grants: Vec::new(),
            errors: Vec::new(),
        };
        match request {
            DirectUploadRequest::BeginBatch(batch) => {
                let blocked = state.blocked_begin;
                for intent in &batch.items {
                    let status = state
                        .sessions
                        .entry(intent.client_operation_id.clone())
                        .or_insert_with(|| DirectSessionStatus {
                            session: DirectSessionRef {
                                session_id: format!("session-{}", intent.client_operation_id),
                                logical_fingerprint: intent.fingerprint().unwrap(),
                            },
                            resource_version: WireInteger::new(1),
                            intent: intent.clone(),
                            placements: self.placements.clone(),
                            state: if blocked {
                                DirectSessionState::BlockedUnknown
                            } else {
                                DirectSessionState::Active
                            },
                            parts: Vec::new(),
                            next_cursor: None,
                            outstanding_grants: false,
                        });
                    response.sessions.push(status.clone());
                }
            }
            DirectUploadRequest::StatusBatch(batch) => {
                for query in &batch.items {
                    let mut status = state
                        .sessions
                        .get(fixture_session_key(&query.session))
                        .unwrap()
                        .clone();
                    status.parts.clear();
                    status.next_cursor = None;
                    let after = query
                        .after
                        .as_ref()
                        .map(|cursor| (cursor.placement.placement_id.get(), cursor.part_number))
                        .unwrap_or((0, 0));
                    let matching: Vec<_> = state
                        .observed
                        .iter()
                        .filter(|((session, placement, number), _)| {
                            session == &query.session.session_id && (*placement, *number) > after
                        })
                        .collect();
                    for ((_, placement_id, number), observed) in
                        matching.iter().take(query.maximum_parts as usize)
                    {
                        status.parts.push(DirectPartStatus {
                            placement: self
                                .placements
                                .iter()
                                .find(|placement| placement.placement_id.get() == *placement_id)
                                .unwrap()
                                .clone(),
                            part_number: *number,
                            observed: Some((*observed).clone()),
                            pending_operation_id: None,
                            unknown: false,
                        });
                    }
                    if matching.len() > query.maximum_parts as usize {
                        let last = status.parts.last().unwrap();
                        status.next_cursor = Some(DirectPartCursor {
                            placement: last.placement.clone(),
                            part_number: last.part_number,
                        });
                    }
                    response.sessions.push(status);
                }
            }
            DirectUploadRequest::GrantPartsBatch(batch) => {
                for item in &batch.items {
                    let grant = state
                        .grants
                        .entry(item.operation_id.clone())
                        .or_insert_with(|| DirectPartGrant {
                            session_id: item.session.session_id.clone(),
                            logical_fingerprint: item.session.logical_fingerprint.clone(),
                            placement: item.placement.clone(),
                            grant_id: item.operation_id.clone(),
                            grant_revision: WireInteger::new(1),
                            part: item.part.clone(),
                            method: "PUT".into(),
                            url: "https://provider.invalid/stage?X-Amz-Signature=bearer-canary"
                                .into(),
                            required_headers: Vec::new(),
                            expires_at: WireInteger::new(1),
                        });
                    response.grants.push(grant.clone());
                }
            }
            DirectUploadRequest::ReportPartsBatch(batch) => {
                if state.fail_reports > 0 {
                    state.fail_reports -= 1;
                    return Err(DirectClientError::ControlUnavailable);
                }
                for item in &batch.items {
                    let grant = state.grants.get(&item.grant_id).unwrap();
                    assert_eq!(grant.part, item.observed.part);
                    assert_eq!(grant.placement, item.placement);
                    state.observed.insert(
                        key(
                            &item.session,
                            &item.placement,
                            item.observed.part.part_number,
                        ),
                        item.observed.clone(),
                    );
                }
            }
            DirectUploadRequest::CompleteBatch(batch) => {
                for item in &batch.items {
                    let status = state
                        .sessions
                        .get(fixture_session_key(&item.session))
                        .unwrap()
                        .clone();
                    for manifest in &item.manifests {
                        let mut hash =
                            DirectManifestHasher::new(&status.intent, &manifest.placement).unwrap();
                        for number in 1..=manifest.part_count {
                            hash.push(
                                state
                                    .observed
                                    .get(&key(&item.session, &manifest.placement, number))
                                    .unwrap(),
                            )
                            .unwrap();
                        }
                        assert_eq!(hash.finish().unwrap(), manifest.manifest_digest);
                    }
                    let pending = state.pending_completions > 0;
                    state.pending_completions = state.pending_completions.saturating_sub(1);
                    let current = state
                        .sessions
                        .get_mut(fixture_session_key(&item.session))
                        .unwrap();
                    current.state = if pending {
                        DirectSessionState::CompletingStaging
                    } else {
                        DirectSessionState::StagedVerified
                    };
                    current.resource_version = WireInteger::new(2);
                    response.sessions.push(current.clone());
                }
            }
            DirectUploadRequest::Abort(_) => {
                panic!("client must not invent an abort after transport failure")
            }
        }
        Ok(response)
    }
}

#[derive(Default)]
struct Provider {
    active: AtomicUsize,
    maximum: AtomicUsize,
    attempts: AtomicUsize,
    bytes: AtomicUsize,
    deny_first: AtomicUsize,
    unavailable_first: AtomicUsize,
}

#[async_trait]
impl DirectPartTransport for Provider {
    async fn send_part(
        &self,
        context: &ProviderContext,
        source: &PartSource,
        grant: &DirectPartGrant,
    ) -> Result<DirectManifestPart, ProviderError> {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        if self
            .deny_first
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            return Err(ProviderError::Expired);
        }
        if self
            .unavailable_first
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            return Err(ProviderError::Unavailable);
        }
        assert_eq!(grant.placement, context.placement);
        assert_eq!(grant.part, portable_part(source));
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.maximum.fetch_max(active, Ordering::SeqCst);
        tokio::task::yield_now().await;
        let mut body = source.stream();
        let mut hash = Sha256::new();
        let mut length = 0;
        while let Some(chunk) = body.try_next().await.map_err(|_| ProviderError::Rejected)? {
            assert!(chunk.len() <= crate::direct_upload::SOURCE_CHUNK_BYTES);
            hash.update(&chunk);
            length += chunk.len();
            tokio::task::yield_now().await;
        }
        self.active.fetch_sub(1, Ordering::SeqCst);
        assert_eq!(length as u64, grant.part.byte_size.get());
        assert_eq!(hex::encode(hash.finalize()), grant.part.sha256);
        self.bytes.fetch_add(length, Ordering::SeqCst);
        Ok(DirectManifestPart {
            part: grant.part.clone(),
            etag: format!("\"{}\"", grant.part.sha256),
        })
    }
}

fn placements(count: u64) -> Vec<DirectPlacementRef> {
    (1..=count)
        .map(|id| DirectPlacementRef {
            placement_id: WireInteger::new(id),
            placement_fingerprint: format!("{id:064x}"),
            placement_resource_version: WireInteger::new(1),
            write_spec_version: WireInteger::new(1),
            binding_id: WireInteger::new(id),
            binding_resource_version: WireInteger::new(1),
            binding_write_revision: WireInteger::new(1),
            profile_fingerprint: format!("{id:064x}"),
            private_policy_digest: "a3".repeat(32),
            checksum_algorithm: if id % 2 == 0 {
                DirectChecksumAlgorithm::Sha256
            } else {
                DirectChecksumAlgorithm::Md5
            },
        })
        .collect()
}

fn discovery(destinations: &[DirectPlacementRef]) -> DirectUploadCapabilities {
    DirectUploadCapabilities {
        target: DirectCapabilitiesTarget::Publication {
            publication_id: "publication".into(),
        },
        requested_delivery_url: None,
        deployment_id: "deployment-test".into(),
        principal_id: "df".repeat(32),
        version: 1,
        capability: DIRECT_UPLOAD_CAPABILITY.into(),
        transfer_mode: DirectAdvertisedTransferMode::DirectRequired,
        config_generation: WireInteger::new(1),
        valid_until: WireInteger::new(u64::MAX),
        maximum_control_bytes: MAX_DIRECT_CONTROL_BYTES as u32,
        maximum_batch_items: MAX_DIRECT_BATCH_ITEMS as u32,
        maximum_batch_parts: MAX_DIRECT_BATCH_PARTS as u32,
        maximum_object_bytes: WireInteger::new(MAX_DIRECT_OBJECT_BYTES),
        minimum_object_bytes: WireInteger::new(0),
        minimum_part_bytes: WireInteger::new(MIN_DIRECT_PART_BYTES),
        maximum_part_bytes: WireInteger::new(MAX_DIRECT_PART_BYTES),
        profiles: destinations
            .iter()
            .map(|placement| DirectProviderProfile {
                placement_id: placement.placement_id,
                placement_resource_version: placement.placement_resource_version,
                write_spec_version: placement.write_spec_version,
                binding_id: placement.binding_id,
                binding_resource_version: placement.binding_resource_version,
                binding_write_revision: placement.binding_write_revision,
                checksum_algorithm: placement.checksum_algorithm,
                provider_origin: "https://provider.invalid".into(),
                profile_fingerprint: placement.profile_fingerprint.clone(),
                private_policy_digest: placement.private_policy_digest.clone(),
            })
            .collect(),
    }
}

async fn objects(
    count: usize,
    bytes: &[u8],
    destinations: &[DirectPlacementRef],
    start: usize,
) -> Vec<DirectUploadObject> {
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(bytes).unwrap();
    let source = AdmittedSource::admit(
        file,
        bytes.len() as u64,
        &hex::encode(Sha256::digest(bytes)),
        8 * 1024 * 1024,
    )
    .await
    .unwrap();
    (start..start + count)
        .map(|index| DirectUploadObject {
            source: source.clone(),
            placements: destinations.to_vec(),
            discovery: discovery(destinations),
            intent: DirectUploadIntent {
                version: 1,
                client_operation_id: format!("{:064x}", index + 1),
                target: DirectUploadTarget::PublicationObject {
                    publication_id: "publication".into(),
                    surface_object_id: WireInteger::new(index as u64 + 1),
                    path: format!("object-{index}.narinfo"),
                },
                expected_sha256: source.sha256().into(),
                byte_size: WireInteger::new(bytes.len() as u64),
                part_size: WireInteger::new(source.part_size()),
                dependency_phase: DirectDependencyPhase::LeafMetadata,
                transfer_mode: DirectTransferMode::DirectRequired,
            },
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multipart_and_multiplacement_streams_are_bounded_parallel_and_exact() {
    let destinations = placements(2);
    let bytes: Vec<_> = (0..9 * 1024 * 1024 + 17)
        .map(|index| ((index * 17 + index / 97) % 251) as u8)
        .collect();
    let source = objects(10, &bytes, &destinations, 0).await;
    let control = Control::new(destinations);
    let store = Store::default();
    let provider = Provider::default();

    let result = upload_direct_batch(&control, &store, &provider, source)
        .await
        .unwrap();

    assert_eq!(result.len(), 10);
    assert!(
        result
            .iter()
            .all(|status| status.state == DirectSessionState::StagedVerified)
    );
    assert_eq!(provider.bytes.load(Ordering::SeqCst), bytes.len() * 20);
    assert!((2..=32).contains(&provider.maximum.load(Ordering::SeqCst)));
    assert_eq!(provider.attempts.load(Ordering::SeqCst), 40);
}

#[tokio::test]
async fn object_minimum_refuses_empty_before_admission_begin_or_provider_upload() {
    let destinations = placements(1);
    let mut source = objects(1, b"", &destinations, 0).await;
    source[0].discovery.minimum_object_bytes = WireInteger::new(1);
    let control = Control::new(destinations);
    let store = Store::default();
    let provider = Provider::default();

    assert_eq!(
        upload_direct_batch(&control, &store, &provider, source).await,
        Err(DirectClientError::Invalid)
    );

    assert!(store.0.lock().unwrap().intents.is_empty());
    assert!(control.state.lock().unwrap().controls.is_empty());
    assert_eq!(provider.attempts.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn zero_object_minimum_stages_empty_without_provider_parts() {
    let destinations = placements(1);
    let source = objects(1, b"", &destinations, 0).await;
    let control = Control::new(destinations);
    let store = Store::default();
    let provider = Provider::default();

    let result = upload_direct_batch(&control, &store, &provider, source)
        .await
        .unwrap();

    assert_eq!(result.len(), 1);
    assert_eq!(result[0].state, DirectSessionState::StagedVerified);
    assert_eq!(result[0].intent.byte_size.get(), 0);
    assert_eq!(store.0.lock().unwrap().intents.len(), 1);
    assert_eq!(provider.attempts.load(Ordering::SeqCst), 0);
    let state = control.state.lock().unwrap();
    assert!(
        state
            .controls
            .iter()
            .any(|request| matches!(request, DirectUploadRequest::BeginBatch(_)))
    );
    assert!(
        state
            .controls
            .iter()
            .all(|request| !matches!(request, DirectUploadRequest::GrantPartsBatch(_)))
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn twelve_thousand_small_metadata_objects_use_batched_controls_and_overlap() {
    let destinations = placements(1);
    let control = Control::new(destinations.clone());
    let store = Store::default();
    let provider = Provider::default();
    let payload = b"private-metadata-payload-canary";
    let all = 12_535usize;
    for start in (0..all).step_by(64) {
        let source = objects((all - start).min(64), payload, &destinations, start).await;
        let result = upload_direct_batch(&control, &store, &provider, source)
            .await
            .unwrap();
        assert!(
            result
                .iter()
                .all(|status| status.state == DirectSessionState::StagedVerified)
        );
    }

    assert_eq!(provider.bytes.load(Ordering::SeqCst), all * payload.len());
    assert_eq!(provider.attempts.load(Ordering::SeqCst), all);
    assert!((2..=32).contains(&provider.maximum.load(Ordering::SeqCst)));
    let state = control.state.lock().unwrap();
    let waves = all.div_ceil(64);
    assert_eq!(
        state
            .controls
            .iter()
            .filter(|request| matches!(request, DirectUploadRequest::BeginBatch(_)))
            .count(),
        waves
    );
    assert_eq!(
        state
            .controls
            .iter()
            .filter(|request| matches!(request, DirectUploadRequest::CompleteBatch(_)))
            .count(),
        waves
    );
    assert_eq!(
        state
            .controls
            .iter()
            .filter(|request| matches!(request, DirectUploadRequest::GrantPartsBatch(_)))
            .count(),
        all.div_ceil(32)
    );
    for request in &state.controls {
        let encoded = encode_direct_control(request).unwrap();
        assert!(encoded.len() <= MAX_DIRECT_CONTROL_BYTES);
        assert!(
            !String::from_utf8(encoded)
                .unwrap()
                .contains("private-metadata-payload-canary")
        );
    }
}

#[tokio::test]
async fn lost_report_reply_restarts_from_exact_private_receipts_without_more_bytes() {
    let destinations = placements(1);
    let source = objects(3, b"retained-body", &destinations, 0).await;
    let control = Control::new(destinations);
    control.state.lock().unwrap().fail_reports = 3;
    let store = Store::default();
    let provider = Provider::default();

    assert_eq!(
        upload_direct_batch(&control, &store, &provider, source.clone())
            .await
            .unwrap_err(),
        DirectClientError::ControlUnavailable
    );
    let before = provider.attempts.load(Ordering::SeqCst);
    let result = upload_direct_batch(&control, &store, &provider, source)
        .await
        .unwrap();

    assert_eq!(result.len(), 3);
    assert_eq!(provider.attempts.load(Ordering::SeqCst), before);
    let reports: Vec<_> = control
        .state
        .lock()
        .unwrap()
        .controls
        .iter()
        .filter_map(|request| match request {
            DirectUploadRequest::ReportPartsBatch(batch) => Some(batch.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(reports.len(), 4);
    assert!(reports.windows(2).all(|pair| pair[0] == pair[1]));
}

#[tokio::test]
async fn lost_part_reply_replays_grant_but_expiry_refresh_advances_durable_ordinal() {
    for expired in [false, true] {
        let destinations = placements(1);
        let source = objects(1, b"same-original-bytes", &destinations, 0).await;
        let control = Control::new(destinations);
        let store = Store::default();
        let provider = Provider::default();
        if expired {
            provider.deny_first.store(1, Ordering::SeqCst);
        } else {
            provider.unavailable_first.store(1, Ordering::SeqCst);
        }

        upload_direct_batch(&control, &store, &provider, source)
            .await
            .unwrap();

        let grants: Vec<_> = control
            .state
            .lock()
            .unwrap()
            .controls
            .iter()
            .filter_map(|request| match request {
                DirectUploadRequest::GrantPartsBatch(batch) => Some(batch.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(grants.len(), 2);
        assert_eq!(grants[0].items[0].part, grants[1].items[0].part);
        assert_eq!(
            grants[0].items[0].operation_id == grants[1].items[0].operation_id,
            !expired
        );
        assert_eq!(
            store
                .0
                .lock()
                .unwrap()
                .attempts
                .values()
                .copied()
                .collect::<Vec<_>>(),
            vec![u64::from(expired)]
        );
    }
}

#[tokio::test]
async fn changed_declarations_unknown_controls_and_corrupt_receipts_fail_without_fallback() {
    let destinations = placements(1);
    let source = objects(1, b"retained-body", &destinations, 0).await;
    let control = Control::new(destinations.clone());
    let store = Store::default();
    let provider = Provider::default();
    store.admit_intent(&source[0].intent).await.unwrap();
    let mut changed = source.clone();
    changed[0].intent.target = DirectUploadTarget::CacheObject {
        cache_id: "foreign".into(),
        path: "other.nar".into(),
    };
    assert_eq!(
        upload_direct_batch(&control, &store, &provider, changed)
            .await
            .unwrap_err(),
        DirectClientError::Invalid
    );
    assert!(control.state.lock().unwrap().controls.is_empty());
    control.state.lock().unwrap().blocked_begin = true;
    assert_eq!(
        upload_direct_batch(&control, &store, &provider, source)
            .await
            .unwrap_err(),
        DirectClientError::Blocked
    );
    assert_eq!(provider.attempts.load(Ordering::SeqCst), 0);
    assert!(
        control
            .state
            .lock()
            .unwrap()
            .controls
            .iter()
            .all(|request| matches!(request, DirectUploadRequest::BeginBatch(_)))
    );
    let source = objects(1, b"retained-body", &destinations, 0).await;
    let control = Control::new(destinations.clone());
    let store = Store::default();
    let session = DirectSessionRef {
        session_id: format!("session-{}", source[0].intent.client_operation_id),
        logical_fingerprint: source[0].intent.fingerprint().unwrap(),
    };
    let mut observed = DirectManifestPart {
        part: portable_part(
            &status::source_part(&source[0], &destinations[0], 1)
                .await
                .unwrap(),
        ),
        etag: "\"original\"".into(),
    };
    observed.part.sha256 = "aa".repeat(32);
    store
        .record_server_part(&session, &destinations[0], &observed)
        .await
        .unwrap();
    assert_eq!(
        upload_direct_batch(&control, &store, &provider, source)
            .await
            .unwrap_err(),
        DirectClientError::Invalid
    );
    assert_eq!(provider.attempts.load(Ordering::SeqCst), 0);
    for error in [
        DirectClientError::Invalid,
        DirectClientError::Blocked,
        DirectClientError::PartUnavailable,
    ] {
        assert!(std::error::Error::source(&error).is_none());
        assert!(!format!("{error:?} {error}").contains("bearer-canary"));
    }
}

#[tokio::test]
async fn staged_resume_replays_original_completion_version_without_more_provider_bytes() {
    let destinations = placements(1);
    let source = objects(1, b"retained-completion", &destinations, 0).await;
    let control = Control::new(destinations);
    let store = Store::default();
    let provider = Provider::default();

    let first = upload_direct_batch(&control, &store, &provider, source.clone())
        .await
        .unwrap();
    assert_eq!(first[0].state, DirectSessionState::StagedVerified);
    assert_eq!(first[0].resource_version.get(), 2);
    let attempts = provider.attempts.load(Ordering::SeqCst);
    let resumed = upload_direct_batch(&control, &store, &provider, source)
        .await
        .unwrap();

    assert_eq!(resumed[0].state, DirectSessionState::StagedVerified);
    assert_eq!(provider.attempts.load(Ordering::SeqCst), attempts);
    let state = control.state.lock().unwrap();
    let complete: Vec<_> = state
        .controls
        .iter()
        .filter_map(|request| match request {
            DirectUploadRequest::CompleteBatch(batch) => Some(batch),
            _ => None,
        })
        .collect();
    assert_eq!(complete.len(), 2);
    assert_eq!(complete[0], complete[1]);
    assert_eq!(complete[1].items[0].expected_resource_version.get(), 1);
}

#[tokio::test]
async fn pending_verification_replays_original_complete_without_part_or_owner_replacement() {
    let destinations = placements(1);
    let source = objects(2, b"retained-pending-content", &destinations, 0).await;
    let control = Control::new(destinations);
    control.state.lock().unwrap().pending_completions = 2;
    let store = Store::default();
    let provider = Provider::default();

    let pending = upload_direct_batch(&control, &store, &provider, source.clone())
        .await
        .unwrap();
    assert!(
        pending
            .iter()
            .all(|item| item.state == DirectSessionState::CompletingStaging)
    );
    let attempts = provider.attempts.load(Ordering::SeqCst);

    let verified = upload_direct_batch(&control, &store, &provider, source)
        .await
        .unwrap();
    assert!(
        verified
            .iter()
            .all(|item| item.state == DirectSessionState::StagedVerified)
    );
    assert_eq!(provider.attempts.load(Ordering::SeqCst), attempts);
    let state = control.state.lock().unwrap();
    let requests: Vec<_> = state
        .controls
        .iter()
        .filter_map(|request| match request {
            DirectUploadRequest::CompleteBatch(batch) => Some(batch),
            _ => None,
        })
        .collect();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0], requests[1]);
    assert!(
        requests[1]
            .items
            .iter()
            .all(|item| item.expected_resource_version.get() == 1)
    );
    assert_eq!(state.sessions.len(), 2);
}

#[tokio::test]
async fn pending_server_state_without_original_completion_refuses_before_provider_effects() {
    let destinations = placements(1);
    let source = objects(1, b"retained-pending-content", &destinations, 0).await;
    let control = Control::new(destinations.clone());
    let store = Store::default();
    let provider = Provider::default();
    let intent = source[0].intent.clone();
    control.state.lock().unwrap().sessions.insert(
        intent.client_operation_id.clone(),
        DirectSessionStatus {
            session: DirectSessionRef {
                session_id: format!("session-{}", intent.client_operation_id),
                logical_fingerprint: intent.fingerprint().unwrap(),
            },
            resource_version: WireInteger::new(2),
            intent,
            placements: destinations,
            state: DirectSessionState::CompletingStaging,
            parts: vec![],
            next_cursor: None,
            outstanding_grants: false,
        },
    );

    assert_eq!(
        upload_direct_batch(&control, &store, &provider, source)
            .await
            .unwrap_err(),
        DirectClientError::Checkpoint
    );
    assert_eq!(provider.attempts.load(Ordering::SeqCst), 0);
    assert_eq!(store.0.lock().unwrap().complete.len(), 0);
    assert!(
        control
            .state
            .lock()
            .unwrap()
            .controls
            .iter()
            .all(|request| matches!(request, DirectUploadRequest::BeginBatch(_)))
    );
}

#[tokio::test]
async fn sparse_status_pages_reconcile_original_parts_without_provider_resend() {
    let destinations = placements(16);
    let source = objects(1, &vec![97u8; 33 * 1024 * 1024], &destinations, 0).await;
    let object = &source[0];
    let control = Control::new(destinations.clone());
    let store = Store::default();
    let provider = Provider::default();
    let session = DirectSessionRef {
        session_id: format!("session-{}", object.intent.client_operation_id),
        logical_fingerprint: object.intent.fingerprint().unwrap(),
    };
    let mut statuses = Vec::new();
    for placement in &destinations {
        for number in 1..=object.intent.part_count().unwrap() {
            let part = portable_part(
                &status::source_part(object, placement, number)
                    .await
                    .unwrap(),
            );
            let observed = DirectManifestPart {
                etag: format!("\"{}\"", part.sha256),
                part,
            };
            control
                .state
                .lock()
                .unwrap()
                .observed
                .insert(key(&session, placement, number), observed.clone());
            statuses.push(DirectPartStatus {
                placement: placement.clone(),
                part_number: number,
                observed: Some(observed),
                pending_operation_id: None,
                unknown: false,
            });
        }
    }
    assert_eq!(statuses.len(), 80);
    let last = &statuses[63];
    let initial = DirectSessionStatus {
        session,
        resource_version: WireInteger::new(1),
        intent: object.intent.clone(),
        placements: destinations,
        state: DirectSessionState::Active,
        parts: statuses[..64].to_vec(),
        next_cursor: Some(DirectPartCursor {
            placement: last.placement.clone(),
            part_number: last.part_number,
        }),
        outstanding_grants: true,
    };
    control
        .state
        .lock()
        .unwrap()
        .sessions
        .insert(object.intent.client_operation_id.clone(), initial);

    let result = upload_direct_batch(&control, &store, &provider, source)
        .await
        .unwrap();

    assert_eq!(result[0].state, DirectSessionState::StagedVerified);
    assert_eq!(provider.attempts.load(Ordering::SeqCst), 0);
    assert_eq!(store.0.lock().unwrap().observed.len(), 80);
    assert_eq!(
        control
            .state
            .lock()
            .unwrap()
            .controls
            .iter()
            .filter(|request| matches!(request, DirectUploadRequest::StatusBatch(_)))
            .count(),
        1
    );
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn actual_sqlite_wave_commit_survives_lost_report_and_preserves_original_close() {
    use std::os::unix::fs::PermissionsExt as _;
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = directory.path().join("direct.sqlite");
    let namespace = "a1".repeat(32);
    let store = crate::direct_upload::SqliteDirectCheckpoints::open(&path, &namespace, true)
        .await
        .unwrap();
    let destinations = placements(1);
    let control = Control::new(destinations.clone());
    control.state.lock().unwrap().fail_reports = 3;
    let provider = Provider::default();
    let source = objects(64, b"private-journal-body-canary", &destinations, 0).await;
    assert_eq!(
        upload_direct_batch(&control, &store, &provider, source.clone())
            .await
            .unwrap_err(),
        DirectClientError::ControlUnavailable
    );
    let body_attempts = provider.attempts.load(Ordering::SeqCst);
    assert_eq!(body_attempts, 32);
    drop(store);
    let store = crate::direct_upload::SqliteDirectCheckpoints::open(&path, &namespace, false)
        .await
        .unwrap();
    let result = upload_direct_batch(&control, &store, &provider, source.clone())
        .await
        .unwrap();
    assert_eq!(result.len(), 64);
    // Only the other 32 unissued parts need bytes after restart.
    assert_eq!(provider.attempts.load(Ordering::SeqCst), 64);
    let again = upload_direct_batch(&control, &store, &provider, source)
        .await
        .unwrap();
    assert_eq!(again.len(), 64);
    assert_eq!(provider.attempts.load(Ordering::SeqCst), 64);
    let bytes = std::fs::read(path).unwrap();
    for forbidden in [
        b"private-journal-body-canary".as_slice(),
        b"X-Amz-Signature=",
        b"uploadId=",
        b"https://",
    ] {
        assert!(
            !bytes
                .windows(forbidden.len())
                .any(|window| window == forbidden)
        );
    }
}

#[tokio::test]
async fn discovery_count_and_control_byte_limits_refuse_before_effects() {
    let destinations = placements(1);
    let control = Control::new(destinations.clone());
    let store = Store::default();
    let provider = Provider::default();
    let mut source = objects(2, b"bounded", &destinations, 0).await;
    for object in &mut source {
        object.discovery.maximum_batch_items = 1;
    }
    assert_eq!(
        upload_direct_batch(&control, &store, &provider, source)
            .await
            .unwrap_err(),
        DirectClientError::Invalid
    );
    assert!(control.state.lock().unwrap().controls.is_empty());
    assert_eq!(provider.bytes.load(Ordering::SeqCst), 0);
    let mut source = objects(1, b"bounded", &destinations, 0).await;
    source[0].discovery.maximum_control_bytes = 100;
    assert_eq!(
        upload_direct_batch(&control, &store, &provider, source)
            .await
            .unwrap_err(),
        DirectClientError::Invalid
    );
    assert!(control.state.lock().unwrap().controls.is_empty());
    assert_eq!(provider.bytes.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn authenticated_delivery_discovery_keeps_exact_locator_echo_and_canonical_cache_owner() {
    let destinations = placements(1);
    let control = Control::new(destinations.clone());
    let store = Store::default();
    let provider = Provider::default();
    let mut source = objects(1, b"cache-body", &destinations, 0).await;
    source[0].intent.target = DirectUploadTarget::CacheObject {
        cache_id: "cache-1".into(),
        path: "nar/cache.nar".into(),
    };
    source[0].discovery.target = DirectCapabilitiesTarget::Cache {
        cache_id: "cache-1".into(),
    };
    source[0].discovery.requested_delivery_url = Some("http://cache.fleet.test/cache".into());
    let result = upload_direct_batch(&control, &store, &provider, source)
        .await
        .unwrap();
    assert_eq!(
        result[0].intent.target,
        DirectUploadTarget::CacheObject {
            cache_id: "cache-1".into(),
            path: "nar/cache.nar".into()
        }
    );
    assert_eq!(provider.bytes.load(Ordering::SeqCst), b"cache-body".len());
}

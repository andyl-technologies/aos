//! Real logical Begin shape, sparse physical pages and aggregate resume fences.
//!
//! These doubles exercise the production scheduler and actual SQLite custody.
//! They do not qualify provider effects, TLS or release throughput.

use super::*;

#[derive(Clone, Copy, Default)]
enum Fault {
    #[default]
    None,
    Version,
    State,
    Foreign,
    Intent,
    Placement,
    Checksum,
    Duplicate,
    Missing,
    Refused,
    Cursor,
    ExcessParts,
    ReplyBytes,
    UnknownPart,
}

struct PhysicalControl {
    inner: Control,
    fault: Fault,
    lost_status: AtomicUsize,
    status_requests: Mutex<Vec<DirectUploadRequest>>,
}

impl PhysicalControl {
    fn new(destinations: Vec<DirectPlacementRef>) -> Self {
        Self {
            inner: Control::new(destinations),
            fault: Fault::None,
            lost_status: AtomicUsize::new(0),
            status_requests: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait]
impl DirectUploadControl for PhysicalControl {
    async fn execute(
        &self,
        request: &DirectUploadRequest,
    ) -> Result<DirectUploadResponse, DirectClientError> {
        let mut response = self.inner.execute(request).await?;
        if matches!(request, DirectUploadRequest::BeginBatch(_)) {
            // The real Core summary and Worker Begin handler have no physical
            // page. Retained provider observations are available only to Status.
            for status in &mut response.sessions {
                status.parts.clear();
                status.next_cursor = None;
            }
        }
        let DirectUploadRequest::StatusBatch(batch) = request else {
            return Ok(response);
        };
        self.status_requests.lock().unwrap().push(request.clone());
        if self
            .lost_status
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                left.checked_sub(1)
            })
            .is_ok()
        {
            return Err(DirectClientError::ControlUnavailable);
        }

        // Positive reply ordering is not part of the correlation contract.
        response.sessions.reverse();
        match self.fault {
            Fault::None => {}
            Fault::Version => response.sessions[0].resource_version = WireInteger::new(2),
            Fault::State => response.sessions[0].state = DirectSessionState::BlockedUnknown,
            Fault::Foreign => response.sessions[0].session.session_id = "foreign-session".into(),
            Fault::Intent => {
                response.sessions[0].intent.expected_sha256 = "de".repeat(32);
            }
            Fault::Placement => {
                response.sessions[0].placements[0].binding_resource_version = WireInteger::new(2);
            }
            Fault::Checksum => {
                let observed = response.sessions[0].parts[0].observed.as_mut().unwrap();
                observed.part.sha256 = "de".repeat(32);
            }
            Fault::Duplicate => response.sessions.push(response.sessions[0].clone()),
            Fault::Missing => {
                response.sessions.pop();
            }
            Fault::Refused => response.errors.push(DirectItemError {
                item_id: batch.items[0].session.session_id.clone(),
                code: DirectItemErrorCode::Denied,
            }),
            Fault::Cursor => {
                let placement = response.sessions[0].parts[0].placement.clone();
                response.sessions[0].next_cursor = Some(DirectPartCursor {
                    placement,
                    part_number: 0,
                });
            }
            Fault::ExcessParts => {
                let part = response.sessions[0].parts[0].clone();
                response.sessions[0].parts.push(part);
            }
            Fault::UnknownPart => {
                let part = &mut response.sessions[0].parts[0];
                part.observed = None;
                part.pending_operation_id = Some("ac".repeat(32));
                part.unknown = true;
            }
            Fault::ReplyBytes => {
                // A matching legal page fits the reserved budget. Extra closed
                // records model an oversized peer reply without invalid paths.
                while encode_direct_control(&response).unwrap().len() <= 8192 {
                    let mut extra = response.sessions[0].clone();
                    extra.session.session_id =
                        format!("excess-session-{}", response.sessions.len());
                    response.sessions.push(extra);
                }
                response.validate().unwrap();
                assert!(encode_direct_control(&response).unwrap().len() > 8192);
            }
        }
        Ok(response)
    }
}

fn summary(object: &DirectUploadObject) -> DirectSessionStatus {
    DirectSessionStatus {
        session: DirectSessionRef {
            session_id: format!("session-{}", object.intent.client_operation_id),
            logical_fingerprint: object.intent.fingerprint().unwrap(),
        },
        resource_version: WireInteger::new(1),
        intent: object.intent.clone(),
        placements: object.placements.clone(),
        state: DirectSessionState::Active,
        parts: Vec::new(),
        next_cursor: None,
        outstanding_grants: true,
    }
}

async fn seed<S: DirectCheckpointStore>(
    control: &PhysicalControl,
    store: &S,
    objects: &[DirectUploadObject],
) {
    for object in objects {
        let status = summary(object);
        store.admit_intent(&object.intent).await.unwrap();
        store.admit_session(&status).await.unwrap();
        control
            .inner
            .state
            .lock()
            .unwrap()
            .sessions
            .insert(object.intent.client_operation_id.clone(), status.clone());
        for placement in &object.placements {
            for number in 1..=object.intent.part_count().unwrap() {
                let part = portable_part(
                    &status::source_part(object, placement, number)
                        .await
                        .unwrap(),
                );
                control.inner.state.lock().unwrap().observed.insert(
                    key(&status.session, placement, number),
                    DirectManifestPart {
                        etag: format!("\"{}\"", part.sha256),
                        part,
                    },
                );
            }
        }
    }
}

#[tokio::test]
async fn sixty_four_resumed_empty_begin_summaries_use_one_status_wave_and_no_provider_resend() {
    let destinations = placements(1);
    let source = objects(64, b"retained-small-metadata", &destinations, 0).await;
    let control = PhysicalControl::new(destinations);
    let store = Store::default();
    seed(&control, &store, &source).await;
    let provider = Provider::default();

    let result = upload_direct_batch(&control, &store, &provider, source)
        .await
        .unwrap();

    assert_eq!(result.len(), 64);
    assert_eq!(provider.attempts.load(Ordering::SeqCst), 0);
    assert_eq!(store.0.lock().unwrap().observed.len(), 64);
    let requests = control.status_requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    let DirectUploadRequest::StatusBatch(batch) = &requests[0] else {
        panic!("expected status wave")
    };
    assert_eq!(batch.items.len(), 64);
    assert!(
        batch
            .items
            .iter()
            .all(|query| query.after.is_none() && query.maximum_parts == 1)
    );
}

#[tokio::test]
async fn fresh_originals_have_no_extra_status_call() {
    let destinations = placements(1);
    let source = objects(64, b"fresh-small-metadata", &destinations, 0).await;
    let control = PhysicalControl::new(destinations);
    let store = Store::default();
    let provider = Provider::default();

    upload_direct_batch(&control, &store, &provider, source)
        .await
        .unwrap();

    assert!(control.status_requests.lock().unwrap().is_empty());
    assert_eq!(provider.attempts.load(Ordering::SeqCst), 64);
}

#[tokio::test]
async fn mixed_multi_page_resume_correlates_reordered_replies_with_aggregate_part_limit() {
    let destinations = placements(2);
    let mut source = objects(10, &vec![97; 9 * 1024 * 1024 + 17], &destinations, 0).await;
    source.extend(objects(3, b"small", &destinations, 20).await);
    for object in &mut source {
        object.discovery.maximum_batch_parts = 7;
    }
    let control = PhysicalControl::new(destinations);
    let store = Store::default();
    seed(&control, &store, &source).await;
    let provider = Provider::default();

    let result = upload_direct_batch(&control, &store, &provider, source)
        .await
        .unwrap();

    assert_eq!(result.len(), 13);
    assert_eq!(provider.attempts.load(Ordering::SeqCst), 0);
    assert_eq!(store.0.lock().unwrap().observed.len(), 46);
    let requests = control.status_requests.lock().unwrap();
    assert!(requests.len() > 1);
    assert!(requests.iter().any(|request| matches!(request,
        DirectUploadRequest::StatusBatch(batch) if batch.items.iter().any(|query| query.after.is_some()))));
    for request in requests.iter() {
        request.validate().unwrap();
        let DirectUploadRequest::StatusBatch(batch) = request else {
            panic!("expected status wave")
        };
        assert!(
            batch
                .items
                .iter()
                .map(|query| query.maximum_parts)
                .sum::<u32>()
                <= 7
        );
    }
}

#[tokio::test]
async fn stale_foreign_duplicate_missing_refused_and_bad_cursor_pages_prevent_all_provider_work() {
    for fault in [
        Fault::Version,
        Fault::State,
        Fault::Foreign,
        Fault::Intent,
        Fault::Placement,
        Fault::Checksum,
        Fault::Duplicate,
        Fault::Missing,
        Fault::Refused,
        Fault::Cursor,
        Fault::ExcessParts,
    ] {
        let destinations = placements(1);
        let source = objects(2, b"retained", &destinations, 0).await;
        let mut control = PhysicalControl::new(destinations);
        control.fault = fault;
        let store = Store::default();
        seed(&control, &store, &source).await;
        let provider = Provider::default();

        assert!(
            upload_direct_batch(&control, &store, &provider, source)
                .await
                .is_err()
        );
        assert_eq!(provider.attempts.load(Ordering::SeqCst), 0);
        assert!(store.0.lock().unwrap().observed.is_empty());
        assert!(
            !control
                .inner
                .state
                .lock()
                .unwrap()
                .controls
                .iter()
                .any(|request| matches!(
                    request,
                    DirectUploadRequest::GrantPartsBatch(_) | DirectUploadRequest::CompleteBatch(_)
                ))
        );
    }
}

#[tokio::test]
async fn checksum_bound_unknown_part_keeps_existing_retry_rule_without_unknown_control_permission()
{
    let destinations = placements(1);
    let source = objects(1, b"same-original-part", &destinations, 0).await;
    let mut control = PhysicalControl::new(destinations);
    control.fault = Fault::UnknownPart;
    let store = Store::default();
    seed(&control, &store, &source).await;
    let provider = Provider::default();

    upload_direct_batch(&control, &store, &provider, source)
        .await
        .unwrap();

    assert_eq!(provider.attempts.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn reply_reservations_split_metadata_waves_before_dispatch() {
    let destinations = placements(1);
    let mut source = objects(16, b"metadata", &destinations, 0).await;
    for object in &mut source {
        object.discovery.maximum_control_bytes = 32 * 1024;
    }
    let control = PhysicalControl::new(destinations);
    let store = Store::default();
    seed(&control, &store, &source).await;
    let provider = Provider::default();

    upload_direct_batch(&control, &store, &provider, source)
        .await
        .unwrap();

    let requests = control.status_requests.lock().unwrap().clone();
    assert!(requests.len() > 1);
    for request in &requests {
        assert!(helpers::request_bytes(request).unwrap() <= 32 * 1024);
        let reply = control.inner.execute(request).await.unwrap();
        assert!(encode_direct_control(&reply).unwrap().len() <= 32 * 1024);
    }
    assert_eq!(provider.attempts.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn reopened_sqlite_resume_lost_status_reply_replays_identical_request_without_part_bytes() {
    use std::os::unix::fs::PermissionsExt as _;
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = directory.path().join("resume.sqlite");
    let namespace = "a2".repeat(32);
    let store = crate::direct_upload::SqliteDirectCheckpoints::open(&path, &namespace, true)
        .await
        .unwrap();
    let destinations = placements(1);
    let source = objects(8, b"retained-small-metadata", &destinations, 0).await;
    let control = PhysicalControl::new(destinations);
    seed(&control, &store, &source).await;
    drop(store);
    let store = crate::direct_upload::SqliteDirectCheckpoints::open(&path, &namespace, false)
        .await
        .unwrap();
    control.lost_status.store(1, Ordering::SeqCst);
    let provider = Provider::default();

    upload_direct_batch(&control, &store, &provider, source)
        .await
        .unwrap();

    assert_eq!(provider.attempts.load(Ordering::SeqCst), 0);
    let requests = control.status_requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0], requests[1]);
}

#[tokio::test]
async fn oversized_actual_reply_refuses_before_any_provider_effect() {
    let destinations = placements(1);
    let mut source = objects(2, b"metadata", &destinations, 0).await;
    for object in &mut source {
        object.discovery.maximum_control_bytes = 8192;
    }
    let mut control = PhysicalControl::new(destinations);
    control.fault = Fault::ReplyBytes;
    let store = Store::default();
    seed(&control, &store, &source).await;
    let provider = Provider::default();

    assert_eq!(
        upload_direct_batch(&control, &store, &provider, source)
            .await
            .unwrap_err(),
        DirectClientError::Invalid
    );

    assert_eq!(control.status_requests.lock().unwrap().len(), 1);
    assert_eq!(provider.attempts.load(Ordering::SeqCst), 0);
}

/// Deliberately supplies no optimized resume admission method.
struct ConservativeStore(Store);

#[async_trait]
impl DirectCheckpointStore for ConservativeStore {
    async fn admit_intent(&self, intent: &DirectUploadIntent) -> Result<(), DirectClientError> {
        self.0.admit_intent(intent).await
    }

    async fn admit_session(&self, status: &DirectSessionStatus) -> Result<(), DirectClientError> {
        self.0.admit_session(status).await
    }

    async fn grant_attempt(
        &self,
        session: &DirectSessionRef,
        placement: &DirectPlacementRef,
        number: u32,
        refresh: bool,
    ) -> Result<u64, DirectClientError> {
        self.0
            .grant_attempt(session, placement, number, refresh)
            .await
    }

    async fn receipt(
        &self,
        session: &DirectSessionRef,
        placement: &DirectPlacementRef,
        number: u32,
    ) -> Result<Option<DirectPartReceipt>, DirectClientError> {
        self.0.receipt(session, placement, number).await
    }

    async fn record_receipt(&self, receipt: &DirectPartReceipt) -> Result<(), DirectClientError> {
        self.0.record_receipt(receipt).await
    }

    async fn record_server_part(
        &self,
        session: &DirectSessionRef,
        placement: &DirectPlacementRef,
        observed: &DirectManifestPart,
    ) -> Result<(), DirectClientError> {
        self.0
            .record_server_part(session, placement, observed)
            .await
    }

    async fn observed_part(
        &self,
        session: &DirectSessionRef,
        placement: &DirectPlacementRef,
        number: u32,
    ) -> Result<Option<DirectManifestPart>, DirectClientError> {
        self.0.observed_part(session, placement, number).await
    }

    async fn admit_complete(
        &self,
        request: &DirectCompleteRequest,
    ) -> Result<DirectCompleteRequest, DirectClientError> {
        self.0.admit_complete(request).await
    }
}

#[tokio::test]
async fn generic_store_without_atomic_freshness_decision_reconciles_conservatively() {
    let destinations = placements(1);
    let source = objects(2, b"fresh-original", &destinations, 0).await;
    let control = PhysicalControl::new(destinations);
    let store = ConservativeStore(Store::default());
    let provider = Provider::default();

    upload_direct_batch(&control, &store, &provider, source)
        .await
        .unwrap();

    assert_eq!(control.status_requests.lock().unwrap().len(), 1);
    assert_eq!(provider.attempts.load(Ordering::SeqCst), 2);
}

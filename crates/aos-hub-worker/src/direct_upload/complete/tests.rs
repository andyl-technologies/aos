//! Complete phase tests using the production scheduler and signed HTTP exchange.

use std::{
    cell::{Cell, RefCell},
    collections::BTreeSet,
    rc::Rc,
};

use anyhow::{ensure, Result};
use aos_hub_core::{direct_upload::*, storage_work::StorageWorkKey};
use sha2::{Digest as _, Sha256};

use super::{finish, run, LogicalReply, Published, Ready, Reserved, Runtime};
use crate::direct_upload::control;

mod http;

const DEPLOYMENT: &str = "fixture-deployment";
const ORIGIN: &str = "https://executor.example";
const BULK: &[u8] = b"original-provider-object-bytes-do-not-enter-control-transport";

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct Fixture {
    admission: DirectUploadAdmission,
    complete: DirectCompleteRequest,
    stage: DirectVerifiedStageEvidence,
    baseline: DirectDestinationBaselineEvidence,
    settled: DirectSettledPlacement,
}

fn digest(value: impl AsRef<[u8]>) -> String {
    hex::encode(Sha256::digest(value.as_ref()))
}

fn fixture(index: usize) -> Fixture {
    let mut owner = crate::direct_guard::fixture::reservation(
        DEPLOYMENT,
        &format!(".aos-direct-guard-fixture/object-{index}"),
    );
    owner.admission.session_id = digest(format!("session-{index}"));
    owner.admission.intent.client_operation_id = digest(format!("begin-{index}"));
    owner.admission.intent.target = DirectUploadTarget::CacheObject {
        cache_id: "fixture-cache".into(),
        path: format!("fixture-object-{index}"),
    };
    owner.admission.intent.expected_sha256 = digest(BULK);
    owner.admission.intent.byte_size = WireInteger::new(BULK.len() as u64);
    owner.admission.logical_fingerprint = owner.admission.fingerprint(DEPLOYMENT).unwrap();
    owner.complete.session = DirectSessionRef {
        session_id: owner.admission.session_id.clone(),
        logical_fingerprint: owner.admission.logical_fingerprint.clone(),
    };
    owner.complete.operation_id = digest(format!("complete-{index}"));
    owner.selected.session = owner.complete.session.clone();
    owner.selected.operation_id = owner.complete.operation_id.clone();
    owner.selected.complete_intent_digest = owner.complete.fingerprint().unwrap();
    owner.binding.session = owner.complete.session.clone();
    owner.binding.complete_operation_id = owner.complete.operation_id.clone();
    owner.binding.complete_intent_digest = owner.complete.fingerprint().unwrap();
    owner.binding.reservation_operation_id = direct_destination_promotion_operation_id(
        &owner.complete.session,
        WireInteger::new(1),
        &owner.complete.operation_id,
    )
    .unwrap();
    owner.baseline.as_mut().unwrap().binding = owner.binding.clone();
    owner.source.sha256 = digest(BULK);
    owner.source.byte_size = owner.admission.intent.byte_size;
    owner.validate().unwrap();

    let guard = crate::direct_guard::fixture::final_record(&owner);
    let placement = &owner.admission.placements[0];
    let evidence = DirectPlacementEvidence {
        placement_id: placement.placement_id,
        placement_resource_version: placement.placement_resource_version,
        write_spec_version: placement.write_spec_version,
        binding_id: placement.binding_id,
        binding_resource_version: placement.binding_resource_version,
        binding_write_revision: placement.binding_write_revision,
        manifest: owner.complete.manifests[0].clone(),
        promotion_operation_id: guard.reservation.reservation_operation_id.clone(),
        staging_incarnation: guard.source_incarnation.clone(),
        final_incarnation: guard.final_incarnation.clone(),
        final_etag: guard.final_etag.clone(),
    };
    guard
        .validate_placement_for(&owner.admission, &owner.complete, &evidence, DEPLOYMENT)
        .unwrap();
    let stage = DirectVerifiedStageEvidence {
        session_id: owner.admission.session_id.clone(),
        logical_fingerprint: owner.admission.logical_fingerprint.clone(),
        operation_id: owner.complete.operation_id.clone(),
        part_count: 1,
        sha256: owner.source.sha256.clone(),
        byte_size: owner.source.byte_size,
        placements: vec![DirectStagePlacementEvidence {
            placement: owner.complete.manifests[0].placement.clone(),
            manifest: owner.complete.manifests[0].clone(),
            verification_operation_id: digest(format!("verify-{index}")),
            staging_incarnation: owner.source.incarnation,
        }],
        projection: None,
    };
    stage
        .validate_against(&owner.admission, DEPLOYMENT)
        .unwrap();

    Fixture {
        admission: owner.admission,
        complete: owner.complete,
        stage,
        baseline: owner.baseline.unwrap(),
        settled: DirectSettledPlacement { evidence, guard },
    }
}

fn public(fixtures: &[Fixture]) -> (DirectRequestContext, Vec<u8>) {
    let bytes = encode_direct_control(&DirectBatch {
        operation_id: digest("batch"),
        items: fixtures.iter().map(|item| item.complete.clone()).collect(),
    })
    .unwrap();
    let context = DirectRequestContext {
        deployment_id: DEPLOYMENT.into(),
        executor_public_origin: ORIGIN.into(),
        public_authority: "executor.example".into(),
        foreground: DirectForegroundBudget {
            invocation_id: digest("invocation"),
            issued_at: WireInteger::new(100),
            expires_at: WireInteger::new(130),
        },
        request_nonce: digest("public"),
        request_body_sha256: digest(&bytes),
        public_method: "POST".into(),
        public_path: "/aos.hub.v1.DirectUploadService/CompleteBatch".into(),
        issued_at: WireInteger::new(100),
        expires_at: WireInteger::new(130),
    };
    context.validate(DEPLOYMENT, ORIGIN, 111).unwrap();
    (context, bytes)
}

fn response() -> DirectUploadResponse {
    DirectUploadResponse {
        operation_id: digest("batch"),
        sessions: Vec::new(),
        grants: Vec::new(),
        errors: Vec::new(),
    }
}

struct PhysicalFixture {
    metadata_only: bool,
    store: Rc<FixtureStore>,
    transport: http::HttpTransport,
    nonce: Cell<u64>,
    inflight: Rc<Cell<usize>>,
    peak: Rc<Cell<usize>>,
    prepared_order: RefCell<Vec<String>>,
    promotion_inflight: Cell<usize>,
    promotion_peak: Cell<usize>,
    promotion_order: RefCell<Vec<String>>,
    acknowledged: RefCell<BTreeSet<String>>,
}

struct FixtureStore {
    path: std::path::PathBuf,
}

impl FixtureStore {
    fn new(fixtures: &[Fixture]) -> Self {
        let path =
            std::env::temp_dir().join(format!("aos-direct-batch-fixture-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&path).unwrap();
        let store = Self { path };
        for item in fixtures {
            std::fs::write(
                store
                    .path
                    .join(format!("original-{}", item.complete.session.session_id)),
                encode_direct_control(item).unwrap(),
            )
            .unwrap();
        }
        store
    }

    fn original(&self, session: &DirectSessionRef) -> Fixture {
        decode_direct_control(
            &std::fs::read(self.path.join(format!("original-{}", session.session_id))).unwrap(),
        )
        .unwrap()
    }

    fn published(&self, session: &DirectSessionRef) -> Option<DirectSettledPlacement> {
        let path = self.path.join(format!("published-{}", session.session_id));
        match std::fs::read(path) {
            Ok(bytes) => Some(decode_direct_control(&bytes).unwrap()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => panic!("fixture publication read failed: {error}"),
        }
    }

    fn publish(&self, session: &DirectSessionRef, settled: &DirectSettledPlacement) -> Result<()> {
        let path = self.path.join(format!("published-{}", session.session_id));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        use std::io::Write as _;
        let mut file = options.open(path)?;
        file.write_all(&encode_direct_control(settled)?)?;
        file.sync_all()?;
        Ok(())
    }

    fn count(&self) -> usize {
        std::fs::read_dir(&self.path)
            .unwrap()
            .filter(|entry| {
                entry
                    .as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with("published-")
            })
            .count()
    }
}

impl Drop for FixtureStore {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.path).unwrap();
    }
}

impl PhysicalFixture {
    fn new(fixtures: Vec<Fixture>, transport: http::HttpTransport) -> Self {
        Self::reopen(Rc::new(FixtureStore::new(&fixtures)), transport)
    }

    fn reopen(store: Rc<FixtureStore>, transport: http::HttpTransport) -> Self {
        Self {
            metadata_only: false,
            store,
            transport,
            nonce: Cell::new(0),
            inflight: Rc::new(Cell::new(0)),
            peak: Rc::new(Cell::new(0)),
            prepared_order: RefCell::new(Vec::new()),
            promotion_inflight: Cell::new(0),
            promotion_peak: Cell::new(0),
            promotion_order: RefCell::new(Vec::new()),
            acknowledged: RefCell::new(BTreeSet::new()),
        }
    }

    fn original(&self, session: &DirectSessionRef) -> Fixture {
        self.store.original(session)
    }
}

#[async_trait::async_trait(?Send)]
impl Runtime for PhysicalFixture {
    fn maximum(&self) -> usize {
        3
    }

    fn fresh_context(&self, original: &DirectRequestContext) -> Result<DirectRequestContext> {
        self.nonce.set(self.nonce.get() + 1);
        let mut context = original.clone();
        context.request_nonce = digest(format!("phase-{}", self.nonce.get()));
        context.issued_at = WireInteger::new(110);
        Ok(context)
    }

    async fn logical(
        &self,
        context: &DirectRequestContext,
        value: DirectUploadLogicalRequest,
    ) -> Result<LogicalReply> {
        control::exchange(
            &self.transport,
            &StorageWorkKey::new(http::KEY).unwrap(),
            context,
            value,
            || Ok(111),
        )
        .await
    }

    async fn prepare(
        &self,
        _: &DirectRequestContext,
        admission: DirectUploadAdmission,
        complete: DirectCompleteRequest,
    ) -> Result<Option<Ready>> {
        let original = self.original(&complete.session);
        super::require_historical_original(
            &admission,
            &complete,
            &original.admission,
            Some(&original.complete),
        )?;
        self.inflight.set(self.inflight.get() + 1);
        self.peak.set(self.peak.get().max(self.inflight.get()));
        let ticks = if admission.intent.client_operation_id == digest("begin-0") {
            20
        } else {
            1
        };
        for _ in 0..ticks {
            tokio::task::yield_now().await;
        }
        self.inflight.set(self.inflight.get() - 1);
        self.prepared_order
            .borrow_mut()
            .push(complete.session.session_id.clone());

        let settled = self
            .store
            .published(&complete.session)
            .into_iter()
            .collect();
        let ready = Ready {
            admission,
            complete,
            stage: original.stage.clone(),
            settled,
        };
        if self.metadata_only {
            super::require_historical_publication(&ready)?;
        }
        Ok(Some(ready))
    }

    async fn reserve(&self, context: &DirectRequestContext, ready: Ready) -> Result<Reserved> {
        ensure!(
            !self.metadata_only,
            "historical provider reservation refused"
        );
        let baseline = self.original(&ready.complete.session).baseline.clone();
        let witness = DirectDestinationBaselineWitness {
            binding: baseline.binding.clone(),
            baseline_digest: baseline.fingerprint()?,
            observation_operation_id: digest(format!(
                "witness-{}",
                ready.complete.session.session_id
            )),
            issued_at: WireInteger::new(111),
            expires_at: context.expires_at,
        };
        Ok(Reserved {
            ready,
            baselines: vec![baseline],
            witnesses: vec![witness],
        })
    }

    async fn promote(
        &self,
        mut reserved: Reserved,
        permission: &LogicalReply,
    ) -> Result<Published> {
        ensure!(!self.metadata_only, "historical provider promotion refused");
        let baseline = &reserved.baselines[0];
        let allowed = permission
            .reply
            .baseline_permissions
            .iter()
            .find(|item| item.binding == baseline.binding)
            .unwrap();
        allowed.validate_for(baseline, &reserved.witnesses[0], &permission.context, 111)?;
        let original = self.original(&reserved.ready.complete.session);
        self.promotion_inflight
            .set(self.promotion_inflight.get() + 1);
        self.promotion_peak
            .set(self.promotion_peak.get().max(self.promotion_inflight.get()));
        let ticks = if original.admission.intent.client_operation_id == digest("begin-0") {
            20
        } else {
            1
        };
        for _ in 0..ticks {
            tokio::task::yield_now().await;
        }
        self.store
            .publish(&reserved.ready.complete.session, &original.settled)?;
        self.promotion_order
            .borrow_mut()
            .push(reserved.ready.complete.session.session_id.clone());
        self.promotion_inflight
            .set(self.promotion_inflight.get() - 1);
        reserved.ready.settled.push(original.settled);
        finish(reserved.ready, &permission.context)
    }

    async fn acknowledge(
        &self,
        item: &Published,
        committed: &LogicalReply,
        public_bytes: &[u8],
    ) -> Result<()> {
        ensure!(
            digest(public_bytes) == committed.context.request_body_sha256,
            "ACK original public bytes differ"
        );
        verify_direct_logical_reply(
            &StorageWorkKey::new(http::KEY)?,
            &committed.signed.signature,
            &committed.signed.body,
            &committed.context,
            111,
        )?;
        self.acknowledged
            .borrow_mut()
            .insert(item.ready.complete.session.session_id.clone());
        Ok(())
    }
}

#[tokio::test]
async fn batches_use_four_actual_http_phase_calls_and_keep_partial_errors() {
    let fixtures = (0..7).map(fixture).collect::<Vec<_>>();
    let original = fixtures
        .iter()
        .map(|item| item.complete.clone())
        .collect::<Vec<_>>();
    let (context, public_bytes) = public(&fixtures);
    let server = http::Server::start(
        fixtures.clone(),
        Some(fixtures[3].complete.session.session_id.clone()),
        false,
    )
    .await;
    let runtime = PhysicalFixture::new(fixtures.clone(), server.transport());
    let mut output = response();

    run(
        &runtime,
        &context,
        &public_bytes,
        fixtures.iter().map(|item| item.complete.clone()).collect(),
        &mut output,
    )
    .await;

    assert_eq!(runtime.peak.get(), 3);
    assert_eq!(runtime.inflight.get(), 0);
    assert_eq!(runtime.promotion_peak.get(), 3);
    assert_eq!(runtime.promotion_inflight.get(), 0);
    assert_ne!(
        runtime.promotion_order.borrow()[0],
        original[0].session.session_id
    );
    assert_ne!(
        *runtime.prepared_order.borrow(),
        original
            .iter()
            .map(|item| item.session.session_id.clone())
            .collect::<Vec<_>>()
    );
    assert_eq!(runtime.store.count(), 6);
    assert_eq!(runtime.acknowledged.borrow().len(), 6);
    assert_eq!(
        output.errors,
        vec![DirectItemError {
            item_id: original[3].session.session_id.clone(),
            code: DirectItemErrorCode::Denied
        }]
    );
    assert_eq!(
        output
            .sessions
            .iter()
            .map(|item| &item.session)
            .collect::<Vec<_>>(),
        original
            .iter()
            .map(|item| &item.session)
            .collect::<Vec<_>>()
    );
    assert_eq!(output.sessions[3].state, DirectSessionState::Freezing);
    output.validate().unwrap();

    let captured = server.captured();
    assert_eq!(captured.requests.len(), 4);
    assert!(
        matches!(&captured.requests[0].request, DirectUploadLogicalRequest::Authorize { complete_step: Some(DirectCompleteStep::Freeze), sessions, .. } if sessions.len() == 7)
    );
    assert!(
        matches!(&captured.requests[1].request, DirectUploadLogicalRequest::Authorize { complete_step: Some(DirectCompleteStep::Baseline), sessions, .. } if sessions.len() == 7)
    );
    assert!(
        matches!(&captured.requests[2].request, DirectUploadLogicalRequest::Authorize { complete_step: Some(DirectCompleteStep::Promote), sessions, .. } if sessions.len() == 6)
    );
    assert!(
        matches!(&captured.requests[3].request, DirectUploadLogicalRequest::Commit { evidence, .. } if evidence.len() == 6)
    );
    for envelope in &captured.requests {
        assert_eq!(envelope.context.foreground, context.foreground);
        assert_eq!(envelope.context.request_body_sha256, digest(&public_bytes));
        if let DirectUploadLogicalRequest::Authorize { sessions, .. } = &envelope.request {
            for session in sessions {
                assert!(original.contains(session.complete_intent.as_ref().unwrap()));
            }
        }
    }
    for body in &captured.bodies {
        assert!(body.len() <= MAX_DIRECT_CONTROL_BYTES);
        assert!(!body.windows(BULK.len()).any(|window| window == BULK));
    }
    server.stop().await;
}

#[tokio::test]
async fn lost_http_commit_reply_holds_guards_and_replays_exact_old_complete() {
    let fixtures = (0..4).map(fixture).collect::<Vec<_>>();
    let (context, public_bytes) = public(&fixtures);
    let server = http::Server::start(fixtures.clone(), None, true).await;
    let runtime = PhysicalFixture::new(fixtures.clone(), server.transport());
    let items = || fixtures.iter().map(|item| item.complete.clone()).collect();
    let mut first = response();

    run(&runtime, &context, &public_bytes, items(), &mut first).await;

    assert_eq!(server.captured().requests.len(), 4);
    assert_eq!(first.errors.len(), 4);
    assert_eq!(runtime.store.count(), 4);
    assert!(runtime.acknowledged.borrow().is_empty());

    let store = Rc::clone(&runtime.store);
    drop(runtime);
    let mut runtime = PhysicalFixture::reopen(store, server.transport());
    let expired =
        crate::direct_upload::acceptance_window::AcceptedProducerWindow::new(100, 110, 1).unwrap();
    assert!(expired.latest_now(110).is_err());
    runtime.metadata_only = true;
    // A fresh broker invocation receives Native originals again over HTTP;
    // its physical ports reload retained proof bytes from the durable fixture.
    runtime.nonce.set(100);
    let mut context = context.clone();
    context.foreground.invocation_id = digest("restarted-invocation");
    let mut replay = response();
    run(&runtime, &context, &public_bytes, items(), &mut replay).await;

    assert!(replay.errors.is_empty());
    assert_eq!(runtime.store.count(), 4);
    assert_eq!(runtime.acknowledged.borrow().len(), 4);
    assert!(runtime.promotion_order.borrow().is_empty());
    let captured = server.captured();
    assert_eq!(captured.requests.len(), 6);
    assert_eq!(captured.requests[3].request, captured.requests[5].request);
    assert_ne!(
        captured.requests[3].context.request_nonce,
        captured.requests[5].context.request_nonce
    );

    let mut changed = fixtures[0].complete.clone();
    changed.expected_resource_version = WireInteger::new(8);
    let mut refused = response();
    run(
        &runtime,
        &context,
        &public_bytes,
        vec![changed],
        &mut refused,
    )
    .await;

    assert_eq!(refused.errors.len(), 1);
    assert_eq!(server.captured().requests.len(), 7);
    assert_eq!(runtime.store.count(), 4);
    server.stop().await;
}

#[tokio::test]
async fn historical_complete_missing_positive_never_enters_provider_phases() {
    let fixtures = vec![fixture(0)];
    let (context, public_bytes) = public(&fixtures);
    let server = http::Server::start(fixtures.clone(), None, false).await;
    let mut runtime = PhysicalFixture::new(fixtures.clone(), server.transport());
    runtime.metadata_only = true;
    let mut output = response();

    run(
        &runtime,
        &context,
        &public_bytes,
        vec![fixtures[0].complete.clone()],
        &mut output,
    )
    .await;

    assert_eq!(output.errors.len(), 1);
    assert_eq!(server.captured().requests.len(), 1);
    assert_eq!(runtime.store.count(), 0);
    assert!(runtime.promotion_order.borrow().is_empty());
    assert!(runtime.acknowledged.borrow().is_empty());
    assert!(super::require_historical_original(
        &fixtures[0].admission,
        &fixtures[0].complete,
        &fixtures[0].admission,
        None,
    )
    .is_err());
    server.stop().await;
}

#[tokio::test]
async fn full_metadata_batch_keeps_four_bounded_http_calls() {
    let _ = crate::direct_upload::observation::take_events();
    let fixtures = (0..MAX_DIRECT_BATCH_ITEMS).map(fixture).collect::<Vec<_>>();
    let (context, public_bytes) = public(&fixtures);
    let server = http::Server::start(fixtures.clone(), None, false).await;
    let runtime = PhysicalFixture::new(fixtures.clone(), server.transport());
    let mut output = response();

    run(
        &runtime,
        &context,
        &public_bytes,
        fixtures.iter().map(|item| item.complete.clone()).collect(),
        &mut output,
    )
    .await;

    let capture = server.captured();
    eprintln!(
        "Complete64 HTTP bytes: requests={:?}, replies={:?}",
        capture.bodies.iter().map(Vec::len).collect::<Vec<_>>(),
        capture.reply_bytes
    );
    assert!(
        output.errors.is_empty(),
        "batch errors={}, captured requests={}",
        output.errors.len(),
        server.captured().requests.len()
    );
    assert_eq!(runtime.acknowledged.borrow().len(), MAX_DIRECT_BATCH_ITEMS);
    assert_eq!(capture.requests.len(), 4);
    assert_eq!(capture.reply_bytes.len(), 4);
    assert!(capture
        .reply_bytes
        .iter()
        .all(|bytes| *bytes <= MAX_DIRECT_CONTROL_BYTES));
    assert!(capture
        .bodies
        .iter()
        .all(|bytes| bytes.len() <= MAX_DIRECT_CONTROL_BYTES));
    assert!(capture
        .bodies
        .iter()
        .all(|bytes| !bytes.windows(BULK.len()).any(|window| window == BULK)));
    output.validate().unwrap();
    use crate::direct_upload::observation::{Direction, Kind, Outcome, Scope, Step};
    let events = crate::direct_upload::observation::take_events();
    let requests = events
        .iter()
        .filter(|event| event.kind == Kind::ControlRequest)
        .collect::<Vec<_>>();
    let replies = events
        .iter()
        .filter(|event| event.kind == Kind::ControlReply)
        .collect::<Vec<_>>();
    assert_eq!(requests.len(), 4);
    assert_eq!(replies.len(), 4);
    let steps = [Step::Freeze, Step::Baseline, Step::Promote, Step::Commit];
    for (index, (request, reply)) in requests.iter().zip(&replies).enumerate() {
        assert_eq!(request.scope, Scope::NativeControl);
        assert_eq!(request.direction, Some(Direction::WorkerToNative));
        assert_eq!(reply.direction, Some(Direction::NativeToWorker));
        assert_eq!(reply.outcome, Outcome::Positive);
        assert_eq!(
            request.bytes,
            Some(WireInteger::new(capture.bodies[index].len() as u64))
        );
        assert_eq!(
            reply.bytes,
            Some(WireInteger::new(capture.reply_bytes[index] as u64))
        );
        assert_eq!(request.control.as_ref().unwrap().step, steps[index]);
        assert_eq!(
            request.control.as_ref().unwrap().sessions.len(),
            MAX_DIRECT_BATCH_ITEMS
        );
        assert_eq!(request.attempt_digest, reply.attempt_digest);
        assert!(reply.control.as_ref().unwrap().reply_body_digest.is_some());
        assert!(
            request.encoded().unwrap().len() <= crate::direct_upload::observation::MAX_EVENT_BYTES
        );
    }
    assert!(!events
        .iter()
        .any(|event| event.direction == Some(Direction::ProviderToWorker)));
    server.stop().await;
}

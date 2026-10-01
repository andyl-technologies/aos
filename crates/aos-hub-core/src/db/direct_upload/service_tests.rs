//! Logical stage advancement requires an independent configured authority.

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use async_trait::async_trait;

use super::*;
use crate::auth::jwt::{Claims, JwtKeys};
use crate::domain::{Permission, Principal};

struct RefusedStorageAuthority {
    latest_time: i64,
    stage_calls: Arc<AtomicUsize>,
    invocation_calls: Arc<AtomicUsize>,
    active_stage: Arc<AtomicUsize>,
    peak_stage: Arc<AtomicUsize>,
    stage_barrier: Option<Arc<tokio::sync::Barrier>>,
}

impl RefusedStorageAuthority {
    fn new(latest_time: i64) -> Self {
        Self {
            latest_time,
            stage_calls: Arc::new(AtomicUsize::new(0)),
            invocation_calls: Arc::new(AtomicUsize::new(0)),
            active_stage: Arc::new(AtomicUsize::new(0)),
            peak_stage: Arc::new(AtomicUsize::new(0)),
            stage_barrier: None,
        }
    }
}

#[async_trait]
impl DirectUploadAuthority for RefusedStorageAuthority {
    fn invocation(&self) -> Arc<dyn DirectUploadAuthority> {
        self.invocation_calls.fetch_add(1, Ordering::SeqCst);
        Arc::new(Self {
            latest_time: self.latest_time,
            stage_calls: Arc::clone(&self.stage_calls),
            invocation_calls: Arc::clone(&self.invocation_calls),
            active_stage: Arc::clone(&self.active_stage),
            peak_stage: Arc::clone(&self.peak_stage),
            stage_barrier: self.stage_barrier.clone(),
        })
    }

    fn current_time(&self) -> Result<i64> {
        Ok(self.latest_time)
    }

    async fn capabilities(
        &self,
        _claims: &Claims,
        _target: &DirectCapabilitiesTarget,
        _now: i64,
    ) -> Result<DirectUploadCapabilities> {
        anyhow::bail!("qualified target profiles unavailable")
    }

    async fn resolve_admission(
        &self,
        _claims: &Claims,
        _context: &DirectRequestContext,
        _intent: &DirectUploadIntent,
        _now: i64,
    ) -> Result<ResolvedDirectAdmission> {
        anyhow::bail!("storage admission unavailable")
    }

    async fn authorize_session(
        &self,
        _claims: &Claims,
        _context: &DirectRequestContext,
        _record: &DirectUploadSessionRecord,
        _action: DirectLogicalAction,
        _metadata_phase: Option<DirectPositiveMetadataPhase>,
        _now: i64,
    ) -> Result<()> {
        Ok(())
    }

    async fn verify_stage(
        &self,
        _context: &DirectRequestContext,
        _record: &DirectUploadSessionRecord,
        _evidence: &DirectVerifiedStageEvidence,
        _now: i64,
    ) -> Result<DirectDependencyPhase> {
        self.stage_calls.fetch_add(1, Ordering::SeqCst);
        let active = self.active_stage.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak_stage.fetch_max(active, Ordering::SeqCst);
        if let Some(barrier) = &self.stage_barrier {
            barrier.wait().await;
        }
        self.active_stage.fetch_sub(1, Ordering::SeqCst);
        anyhow::bail!("independent stage receipt unavailable")
    }

    async fn baseline_permissions(
        &self,
        _claims: &Claims,
        _context: &DirectRequestContext,
        _record: &DirectUploadSessionRecord,
        _evidence: &[DirectDestinationBaselineEvidence],
        _witnesses: &[DirectDestinationBaselineWitness],
        _settled: &[DirectSettledPlacement],
        _now: i64,
    ) -> Result<Vec<DirectDestinationBaselinePermission>> {
        anyhow::bail!("independent baseline receipt unavailable")
    }

    async fn verify_final(
        &self,
        _claims: &Claims,
        _context: &DirectRequestContext,
        _record: &DirectUploadSessionRecord,
        _evidence: &DirectCompletionEvidence,
        _guards: &[DirectFinalGuardRecord],
        _now: i64,
    ) -> Result<Vec<CheckedStatement>> {
        anyhow::bail!("independent final receipt unavailable")
    }

    async fn verify_abort(
        &self,
        _claims: &Claims,
        _context: &DirectRequestContext,
        _record: &DirectUploadSessionRecord,
        _evidence: &DirectAbortEvidence,
        _now: i64,
    ) -> Result<Vec<CheckedStatement>> {
        anyhow::bail!("independent abort receipt unavailable")
    }
}

#[tokio::test]
async fn signed_structural_stage_proof_cannot_advance_without_independent_readback() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let admitted = original(&db).await;
    let user = i64::try_from(admitted.admission.actor_slot.numeric_id.get()).unwrap();
    db.grant_membership("user", user, "instance", "owner")
        .await
        .unwrap();
    let (_, secret) = db
        .create_token(
            Principal::user(user),
            "instance",
            &[Permission::Publish],
            None,
            None,
        )
        .await
        .unwrap();
    let token = db.validate_token(&secret).await.unwrap().unwrap();
    let keys = JwtKeys::from_secret(b"logical-readback-regression-key");
    let mut claims = keys.verify(&keys.mint(&token, 300).unwrap()).unwrap();
    // The authority fixture uses an explicit protocol clock, independent of JWT mint time.
    claims.iat = 10;
    let complete = complete(&admitted);
    let proof = stage(&admitted, &complete);
    let request = DirectLogicalRequestEnvelope {
        context: DirectRequestContext {
            deployment_id: "deployment".into(),
            executor_public_origin: "https://executor.test".into(),
            public_authority: "hub.test".into(),
            foreground: DirectForegroundBudget {
                invocation_id: "7".repeat(64),
                issued_at: WireInteger::new(10),
                expires_at: WireInteger::new(30),
            },
            request_nonce: "8".repeat(64),
            request_body_sha256: "9".repeat(64),
            public_method: "POST".into(),
            public_path: "/aos.hub.v1.DirectUploadService/CompleteBatch".into(),
            issued_at: WireInteger::new(10),
            expires_at: WireInteger::new(30),
        },
        request: DirectUploadLogicalRequest::Authorize {
            action: DirectLogicalAction::Complete,
            complete_step: Some(DirectCompleteStep::Baseline),
            stage_evidence: vec![proof],
            retained_stage_digests: Vec::new(),
            baseline_evidence: Vec::new(),
            baseline_witnesses: Vec::new(),
            baseline_witness_refs: Vec::new(),
            settled_placements: Vec::new(),
            sessions: vec![DirectSessionAuthorization {
                session: complete.session.clone(),
                expected_resource_version: Some(complete.expected_resource_version),
                operation_id: complete.operation_id.clone(),
                complete_intent: Some(complete.clone()),
            }],
        },
    };
    let broker_key = crate::storage_work::StorageWorkKey::new([7; 32]).unwrap();
    let signed = sign_direct_logical_request(&broker_key, &request).unwrap();
    let verified = verify_direct_logical_request(
        &broker_key,
        &signed.signature,
        &signed.body,
        "deployment",
        "https://executor.test",
        11,
    )
    .unwrap();
    let expired_authority = Arc::new(RefusedStorageAuthority::new(30));
    let expired = DirectUploadService::new(Arc::clone(&db), expired_authority.clone());
    let refused = expired.dispatch(&claims, &verified, 11).await.unwrap();
    assert_eq!(refused.errors.len(), 1);
    assert_eq!(expired_authority.stage_calls.load(Ordering::SeqCst), 0);
    assert!(db
        .direct_upload_session("deployment", &admitted.admission.session_id)
        .await
        .unwrap()
        .unwrap()
        .complete_intent
        .is_none());

    let authority = Arc::new(RefusedStorageAuthority::new(11));
    let service = DirectUploadService::new(Arc::clone(&db), authority.clone());

    let reply = service.dispatch(&claims, &verified, 11).await.unwrap();
    assert_eq!(reply.errors.len(), 1);
    assert!(reply.sessions.is_empty());
    assert!(reply.authorizations.is_empty());
    assert_eq!(authority.stage_calls.load(Ordering::SeqCst), 1);
    let retained = db
        .direct_upload_session("deployment", &admitted.admission.session_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retained.complete_intent, Some(complete.clone()));
    assert_eq!(retained.state, DirectSessionState::Creating);
    assert_eq!(retained.resource_version, WireInteger::new(1));
    assert!(retained.stage_evidence.is_none());
    assert!(retained.completion_evidence.is_none());

    let mut freeze = verified.clone();
    if let DirectUploadLogicalRequest::Authorize {
        complete_step,
        stage_evidence,
        ..
    } = &mut freeze.request
    {
        *complete_step = Some(DirectCompleteStep::Freeze);
        stage_evidence.clear();
    }
    let signed = sign_direct_logical_request(&broker_key, &freeze).unwrap();
    let freeze = verify_direct_logical_request(
        &broker_key,
        &signed.signature,
        &signed.body,
        "deployment",
        "https://executor.test",
        11,
    )
    .unwrap();
    let frozen = service.dispatch(&claims, &freeze, 11).await.unwrap();
    assert!(frozen.errors.is_empty());
    assert!(frozen.sessions.is_empty());
    assert_eq!(frozen.session_summaries.len(), 1);
    assert_eq!(
        frozen.session_summaries[0]
            .status(&frozen.admissions[0], "deployment")
            .unwrap(),
        retained.status("deployment").unwrap()
    );
    let mut substituted = frozen.clone();
    substituted.session_summaries[0].session.logical_fingerprint = "f".repeat(64);
    assert!(substituted.validate("deployment").is_err());
}

#[tokio::test]
async fn full_logical_batch_uses_one_invocation_and_eight_independent_reads_at_a_time() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let original = original(&db).await;
    let user = i64::try_from(original.admission.actor_slot.numeric_id.get()).unwrap();
    db.grant_membership("user", user, "instance", "owner")
        .await
        .unwrap();
    let (_, secret) = db
        .create_token(
            Principal::user(user),
            "instance",
            &[Permission::Publish],
            None,
            None,
        )
        .await
        .unwrap();
    let token = db.validate_token(&secret).await.unwrap().unwrap();
    let keys = JwtKeys::from_secret(b"logical-batch-readback-key");
    let mut claims = keys.verify(&keys.mint(&token, 300).unwrap()).unwrap();
    // The authority fixture uses an explicit protocol clock, independent of JWT mint time.
    claims.iat = 10;

    let mut sessions = Vec::new();
    let mut proofs = Vec::new();
    for index in 0..64 {
        let mut admission = original.admission.clone();
        admission.session_id = format!("batch-session-{index}");
        admission.intent.client_operation_id = format!("{index:064x}");
        admission.logical_fingerprint = admission.fingerprint("deployment").unwrap();
        let record = db
            .admit_direct_upload(
                "deployment",
                &admission,
                &original.owner_scope_key,
                &original.owner,
                10,
            )
            .await
            .unwrap();
        let intent = complete(&record);
        proofs.push(stage(&record, &intent));
        sessions.push(DirectSessionAuthorization {
            session: intent.session.clone(),
            expected_resource_version: Some(intent.expected_resource_version),
            operation_id: intent.operation_id.clone(),
            complete_intent: Some(intent),
        });
    }
    let request = DirectLogicalRequestEnvelope {
        context: DirectRequestContext {
            deployment_id: "deployment".into(),
            executor_public_origin: "https://executor.test".into(),
            public_authority: "hub.test".into(),
            foreground: DirectForegroundBudget {
                invocation_id: "7".repeat(64),
                issued_at: WireInteger::new(10),
                expires_at: WireInteger::new(30),
            },
            request_nonce: "8".repeat(64),
            request_body_sha256: "9".repeat(64),
            public_method: "POST".into(),
            public_path: "/aos.hub.v1.DirectUploadService/CompleteBatch".into(),
            issued_at: WireInteger::new(10),
            expires_at: WireInteger::new(30),
        },
        request: DirectUploadLogicalRequest::Authorize {
            action: DirectLogicalAction::Complete,
            complete_step: Some(DirectCompleteStep::Baseline),
            stage_evidence: proofs,
            retained_stage_digests: Vec::new(),
            baseline_evidence: Vec::new(),
            baseline_witnesses: Vec::new(),
            baseline_witness_refs: Vec::new(),
            settled_placements: Vec::new(),
            sessions,
        },
    };
    let broker_key = crate::storage_work::StorageWorkKey::new([23; 32]).unwrap();
    let signed = sign_direct_logical_request(&broker_key, &request).unwrap();
    let verified = verify_direct_logical_request(
        &broker_key,
        &signed.signature,
        &signed.body,
        "deployment",
        "https://executor.test",
        11,
    )
    .unwrap();
    let mut authority = RefusedStorageAuthority::new(11);
    authority.stage_barrier = Some(Arc::new(tokio::sync::Barrier::new(8)));
    let authority = Arc::new(authority);
    let service = DirectUploadService::new(db, authority.clone());

    // A serial implementation cannot release the barrier; unbounded work exceeds
    // the observed peak. Independent refusals must remain per-item refusals.
    let reply = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        service.dispatch(&claims, &verified, 11),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(authority.invocation_calls.load(Ordering::SeqCst), 1);
    assert_eq!(authority.stage_calls.load(Ordering::SeqCst), 64);
    assert_eq!(authority.peak_stage.load(Ordering::SeqCst), 8);
    assert_eq!(reply.errors.len(), 64);
    assert!(reply.sessions.is_empty());
}

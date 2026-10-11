//! Real CLI observation of durable scans, bounded reads and conflicting adapters.
//!
//! The isolated transport fixture does not grant public assessment permissions.
//! All scan state and results use the production SQL journal and evaluator.

use anyhow::{Context as _, Result};
use aos_assessment_runtime::application::ScanReceiptV1;
use aos_assessment_runtime::control::ScanLookupV1;
use aos_assessment_runtime::scan::ScanState;
use aos_proto_types as pb;
use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use crate::db::{AssessmentScanRecord, Database};

#[derive(Clone, Copy, Debug)]
enum Observation {
    Complete,
    Idle,
    InitialStall,
    ForeignInitial,
    ForeignSuccessor,
    Cancelled,
}

#[derive(Clone)]
struct Fixture {
    db: Arc<Database>,
    registry: i64,
    scan_id: String,
    foreign_id: Option<String>,
    observation: Observation,
    reads: Arc<AtomicUsize>,
}

fn receipt(scan: AssessmentScanRecord) -> ScanReceiptV1 {
    ScanReceiptV1 {
        schema: "aos.assessment-scan-receipt/v1".into(),
        scan_id: scan.scan_id,
        request: scan.request,
        request_digest: scan.request_digest,
        generation: scan.generation,
        state: scan.state,
        admission_complete: scan.admission_complete,
        usage: scan.usage,
        created_at: scan.created_at,
        resource_version: scan.resource_version,
        assessment_digest: scan.assessment_digest,
        failure_code: scan.failure_code,
    }
}

async fn read(
    State(fixture): State<Fixture>,
    Json(request): Json<pb::AssessmentControlRequest>,
) -> std::result::Result<Json<pb::AssessmentDocumentResponse>, (StatusCode, String)> {
    let result = async {
        anyhow::ensure!(
            request.registry_slug == "fixture",
            "foreign fixture registry"
        );
        let lookup = ScanLookupV1::from_slice(&request.document_json)?;
        anyhow::ensure!(
            lookup.scan_id == fixture.scan_id,
            "fixture lookup changed operation"
        );
        let read = fixture.reads.fetch_add(1, Ordering::SeqCst);
        if matches!(fixture.observation, Observation::InitialStall) {
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        }
        if matches!(fixture.observation, Observation::Complete) && read == 1 {
            let claim = fixture
                .db
                .claim_assessment_scan(fixture.registry, &fixture.scan_id, 60)
                .await?;
            let data = fixture
                .db
                .assessment_evaluation_base(fixture.registry, &claim)
                .await?;
            let input = fixture
                .db
                .freeze_assessment_evaluation(fixture.registry, &claim, &data)
                .await?;
            let result = aos_assessment::evaluator::evaluate(&input, &data)?;
            fixture
                .db
                .commit_assessment_evaluation(fixture.registry, &claim, &result)
                .await?;
        }
        let foreign = matches!(fixture.observation, Observation::ForeignInitial)
            || (matches!(fixture.observation, Observation::ForeignSuccessor) && read > 0);
        let identity = if foreign {
            fixture
                .foreign_id
                .as_deref()
                .context("foreign fixture operation")?
        } else {
            &fixture.scan_id
        };
        let scan = fixture
            .db
            .assessment_scan(fixture.registry, identity)
            .await?
            .context("retained fixture scan")?;
        Ok::<_, anyhow::Error>(Json(pb::AssessmentDocumentResponse {
            document_json: receipt(scan).to_bytes()?,
        }))
    }
    .await;
    result.map_err(|error| (StatusCode::PRECONDITION_FAILED, error.to_string()))
}

async fn qualify(observation: Observation) -> Result<()> {
    let binary = std::env::var_os("AOS_ASSESSMENT_CLI").context("packaged aos CLI required")?;
    let temporary = tempfile::tempdir()?;
    let path = temporary.path().join("scan-wait.sqlite");
    let (db, registry, mut request) =
        super::scans_tests::setup_database(Database::open(&path).await?).await?;
    let scan = db.request_assessment_scan(registry, &request).await?;
    let foreign_id = if matches!(
        observation,
        Observation::ForeignInitial | Observation::ForeignSuccessor
    ) {
        request.idempotency_key = "foreign-operation".into();
        Some(
            db.request_assessment_scan(registry, &request)
                .await?
                .scan_id,
        )
    } else {
        None
    };
    if matches!(observation, Observation::Cancelled) {
        db.cancel_assessment_scan(registry, &scan.scan_id, scan.resource_version)
            .await?;
    }
    drop(db);
    let db = Arc::new(Database::open(&path).await?);
    let before = receipt(
        db.assessment_scan(registry, &scan.scan_id)
            .await?
            .context("reopened scan")?,
    );
    let reads = Arc::new(AtomicUsize::new(0));
    let fixture = Fixture {
        db: Arc::clone(&db),
        registry,
        scan_id: scan.scan_id.clone(),
        foreign_id,
        observation,
        reads: Arc::clone(&reads),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let hub = format!("http://{}", listener.local_addr()?);
    let router = Router::new()
        .route(pb::SCAN_SERVICE_GET_SCAN_PATH, post(read))
        .with_state(fixture);
    let server = tokio::spawn(async move { axum::serve(listener, router).await });
    let result = async {
        let timeout = if matches!(observation, Observation::Idle | Observation::InitialStall) {
            "1"
        } else {
            "20"
        };
        let mut command = tokio::process::Command::new(binary);
        command.kill_on_drop(true).args([
            "--json",
            "hub",
            "maintain",
            "scans",
            "wait",
            &scan.scan_id,
            "--hub",
            &hub,
            "--token",
            "public-fixture-token",
            "--registry",
            "fixture",
            "--timeout",
            timeout,
        ]);
        let started = tokio::time::Instant::now();
        let output =
            tokio::time::timeout(std::time::Duration::from_secs(30), command.output()).await??;
        let stdout = String::from_utf8(output.stdout)?;
        let stderr = String::from_utf8(output.stderr)?;
        let mut receipts = Vec::new();
        for line in stdout.lines() {
            let envelope: serde_json::Value = serde_json::from_str(line)?;
            if envelope["kind"] == "assessment-scan" {
                assert_eq!(envelope["schema_version"], "aos.hub.cli/v1");
                receipts.push(ScanReceiptV1::from_slice(&serde_json::to_vec(
                    &envelope["data"],
                )?)?);
            }
        }
        let after = receipt(
            db.assessment_scan(registry, &scan.scan_id)
                .await?
                .context("scan after wait")?,
        );
        match observation {
            Observation::Complete => {
                assert!(output.status.success(), "{stdout}\n{stderr}");
                assert_eq!(receipts, [after.clone()]);
                assert_eq!(after.state, ScanState::Partial);
                assert!(after.assessment_digest.is_some());
                assert_eq!(reads.load(Ordering::SeqCst), 2);
                assert_eq!(after.generation, before.generation);
                assert_eq!(after.request_digest, before.request_digest);
            }
            Observation::Cancelled => {
                assert!(!output.status.success());
                assert_eq!(receipts, [before.clone()]);
                assert_eq!(after, before);
                assert_eq!(reads.load(Ordering::SeqCst), 1);
                assert!(
                    stdout.contains("ended in cancelled") || stderr.contains("ended in cancelled")
                );
            }
            Observation::Idle | Observation::InitialStall => {
                assert!(!output.status.success());
                assert!(receipts.is_empty());
                assert_eq!(after, before);
                assert!(
                    started.elapsed() < std::time::Duration::from_secs(5),
                    "initial lookup exceeded wait deadline"
                );
                assert!(stdout.contains("timed out") || stderr.contains("timed out"));
                let maximum_reads = if matches!(observation, Observation::InitialStall) {
                    1
                } else {
                    2
                };
                assert!(reads.load(Ordering::SeqCst) <= maximum_reads);
            }
            Observation::ForeignInitial | Observation::ForeignSuccessor => {
                assert!(!output.status.success());
                assert!(receipts.is_empty());
                assert_eq!(after, before);
                let expected = if matches!(observation, Observation::ForeignInitial) {
                    "different operation"
                } else {
                    "conflicting identity"
                };
                assert!(
                    stdout.contains(expected) || stderr.contains(expected),
                    "{stdout}\n{stderr}"
                );
            }
        }
        // No observation allocates another operation or a new desired generation.
        let resource = db
            .assessment_resource(registry)
            .await?
            .context("resource after wait")?;
        assert_eq!(
            resource.next_generation,
            if matches!(
                observation,
                Observation::ForeignInitial | Observation::ForeignSuccessor
            ) {
                3
            } else {
                2
            }
        );
        Ok(())
    }
    .await;
    server.abort();
    result
}

#[tokio::test]
#[ignore = "requires the real packaged aos CLI"]
async fn actual_cli_wait_observes_durable_scan_without_implicit_mutation() -> Result<()> {
    for observation in [
        Observation::Complete,
        Observation::Idle,
        Observation::InitialStall,
        Observation::ForeignInitial,
        Observation::ForeignSuccessor,
        Observation::Cancelled,
    ] {
        qualify(observation)
            .await
            .with_context(|| format!("CLI wait fixture: {observation:?}"))?;
    }
    println!("PASS: actual CLI wait observes completion and refuses unbounded or foreign reads without mutation");
    Ok(())
}

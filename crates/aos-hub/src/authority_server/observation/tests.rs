//! Private recording, genuine journal acknowledgments and cancellation ownership.

use std::os::unix::fs::PermissionsExt as _;

use super::*;
use crate::authority_journal::tests::{cohort, integer, profile, publication, Fixture};
use aos_hub_core::storage_authority::lease::{
    control::IssuerOperation, BoundedLeaseRevocationPolicy,
};

struct Recording {
    _directory: tempfile::TempDir,
    fixture: Fixture,
    authority: AuthorityConfiguration,
    selected: LocalIssuerObservationConfiguration,
}

impl Recording {
    fn new() -> Self {
        let fixture = Fixture::new();
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let authority = AuthorityConfiguration {
            format_version: 1,
            listen: "127.0.0.1:0".parse().unwrap(),
            journal_file: fixture.path.clone(),
            installation: fixture.marker.clone(),
            hub_root: fixture.boundary.hub_root.clone(),
            hub_sqlite_file: None,
            policy: BoundedLeaseRevocationPolicy {
                timing_profile: profile(),
            },
            clock_uncertainty: integer(0),
            clock_commit_latency: integer(1),
            clock_recovery: None,
            issuance_enabled: false,
            publisher_key_file: directory.path().join("publisher"),
            renewal_key_file: directory.path().join("renewal"),
            signing_seed_file: directory.path().join("seed"),
            signing_key_id: "fixture-authority-signing-v1".into(),
            tls: None,
        };
        let selected = LocalIssuerObservationConfiguration {
            run_id: "a".repeat(32),
            selected_source_sha256: "b".repeat(64),
            executable_sha256: running_executable_digest().unwrap(),
            authority_configuration_sha256: hex::encode(Sha256::digest(
                serde_json::to_vec(&authority).unwrap(),
            )),
            output: directory.path().join("observations.jsonl"),
        };
        Self {
            _directory: directory,
            fixture,
            authority,
            selected,
        }
    }

    fn open(&self) -> Observation {
        Observation::open(&self.selected, &self.authority).unwrap()
    }

    fn request(&self) -> IssuerRequest {
        IssuerRequest {
            protocol_version: 1,
            installation: self.fixture.marker.clone(),
            nonce: "c".repeat(64),
            issued_at: integer(100),
            expires_at: integer(130),
            operation: IssuerOperation::Issue {
                cohort: cohort(&publication()),
                requested_not_after: integer(130),
            },
        }
    }

    fn rows(&self) -> Vec<serde_json::Value> {
        std::fs::read_to_string(&self.selected.output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
}

#[test]
fn private_recording_refuses_reuse_public_directory_and_changed_executable() {
    let recording = Recording::new();
    let observer = recording.open();
    observer.finish().unwrap();
    assert_eq!(recording.rows().last().unwrap()["event"], "finished");
    assert!(Observation::open(&recording.selected, &recording.authority).is_err());

    let mut changed = Recording::new();
    changed.selected.executable_sha256 = "f".repeat(64);
    assert!(Observation::open(&changed.selected, &changed.authority).is_err());
    assert!(!changed.selected.output.exists());
    changed.selected.executable_sha256 = running_executable_digest().unwrap();
    std::fs::set_permissions(
        changed.selected.output.parent().unwrap(),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    assert!(Observation::open(&changed.selected, &changed.authority).is_err());
    assert!(!changed.selected.output.exists());
}

#[test]
fn replacement_and_bounds_never_emit_a_healthy_terminal_marker() {
    let recording = Recording::new();
    let observer = recording.open();
    std::fs::rename(
        &recording.selected.output,
        recording.selected.output.with_extension("retained"),
    )
    .unwrap();
    std::fs::write(&recording.selected.output, []).unwrap();
    observer.record("request_started", json!({}));
    assert!(observer.finish().is_err());
    assert!(!observer.healthy());

    let recording = Recording::new();
    let observer = recording.open();
    observer.record(
        "test_oversize",
        json!({ "value": "x".repeat(MAX_RECORD_BYTES) }),
    );
    assert!(observer.finish().is_err());
    assert!(!observer.healthy());
    assert_eq!(recording.rows().len(), 1);
}

#[tokio::test]
async fn actual_sqlite_acknowledgment_keeps_original_nonce_and_stale_cas_has_no_commit() {
    let recording = Recording::new();
    let observer = recording.open();
    let request = recording.request();
    let bytes = serde_json::to_vec(&request).unwrap();
    let context = observer.for_request(&request, &bytes).unwrap();
    let journal = recording
        .fixture
        .initialize()
        .with_observation(Some(context.clone()));
    let state = journal.load().unwrap();
    let prepared = state
        .journal
        .prepare_issue(
            &state.publication,
            cohort(&publication()),
            "fixture-authority-signing-v1",
            130,
            crate::authority_journal::tests::clock(100),
        )
        .unwrap();
    let transition = prepared.transition().clone();
    journal.commit_lease(transition.clone()).await.unwrap();
    assert!(journal.commit_lease(transition).await.is_err());
    drop(journal);
    drop(context);
    observer.finish().unwrap();

    let rows = recording.rows();
    let commits: Vec<_> = rows
        .iter()
        .filter(|row| row["event"] == "transaction_commit" && row["fields"]["kind"] == "lease")
        .collect();
    assert_eq!(commits.len(), 1);
    assert_eq!(commits[0]["fields"]["outcome"], "acknowledged");
    assert_eq!(commits[0]["request"]["nonce"], request.nonce);
    assert_eq!(
        commits[0]["request"]["receivedBodySha256"],
        hex::encode(Sha256::digest(&bytes))
    );
    assert_eq!(rows.last().unwrap()["event"], "finished");
}

#[test]
fn abandoned_request_with_late_owned_work_cannot_claim_a_drained_footer() {
    let recording = Recording::new();
    let observer = recording.open();
    let request = recording.request();
    let context = observer
        .for_request(&request, &serde_json::to_vec(&request).unwrap())
        .unwrap();
    let retained_by_blocking_work = context.clone();
    let outcome = RequestOutcome::new(Some(context));
    drop(outcome);
    assert!(observer.finish().is_err());

    assert!(!observer.healthy());
    assert!(
        recording
            .rows()
            .iter()
            .any(|row| row["event"] == "request_abandoned"
                && row["fields"]["settlement"] == "unknown")
    );
    assert!(!recording
        .rows()
        .iter()
        .any(|row| row["event"] == "finished"));
    drop(retained_by_blocking_work);
}

#[tokio::test]
async fn actual_server_gate_wait_is_observed_without_changing_current_reply() {
    let recording = Recording::new();
    recording.fixture.initialize();
    for (path, bytes) in [
        (&recording.authority.publisher_key_file, [11; 32]),
        (&recording.authority.renewal_key_file, [12; 32]),
        (&recording.authority.signing_seed_file, [13; 32]),
    ] {
        std::fs::write(path, bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let server = super::super::AuthorityServer::open_with_local_observation(
        &recording.authority,
        None,
        &recording.selected,
    )
    .unwrap();
    let now = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap();
    let mut request = recording.request();
    request.issued_at = integer(now);
    request.expires_at = integer(now + 30);
    request.operation = IssuerOperation::Current;
    let context = server
        .inner
        .observation
        .as_ref()
        .unwrap()
        .for_request(&request, &serde_json::to_vec(&request).unwrap())
        .unwrap();
    let held = server.inner.gate.lock().await;
    let future = server.execute_observed(&request, Some(context));
    tokio::pin!(future);
    assert!(futures_util::poll!(&mut future).is_pending());
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    drop(held);
    let bytes = future.await.unwrap();
    aos_hub_core::storage_authority::lease::control::verify_issuer_reply(
        &server.inner.verifier,
        &request,
        &bytes,
    )
    .unwrap();

    let rows = recording.rows();
    let queue = rows
        .iter()
        .find(|row| row["event"] == "gate_acquired")
        .unwrap();
    assert!(queue["fields"]["queueWaitNs"].as_u64().unwrap() >= 20_000_000);
    assert!(rows
        .iter()
        .any(|row| row["event"] == "signature" && row["fields"]["purpose"] == "reply"));
    assert!(rows
        .iter()
        .any(|row| row["event"] == "request_completed" && row["fields"]["outcome"] == "success"));
}

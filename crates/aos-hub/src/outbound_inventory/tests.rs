//! Controlled window lifecycle and helpers for actual transport integration tests.

use std::{
    future::Future,
    sync::Arc,
    time::{Duration, Instant},
};

use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use super::{Image, Observation, Owner, TEST_WINDOW, policy::Policy, window::Window};

fn window() -> Arc<Window> {
    let now = Instant::now();
    Window::new(
        Policy {
            version: 1,
            run_id: "a".repeat(64),
            window_id: "b".repeat(32),
            start_unix_millis: "1".into(),
            end_unix_millis: "2".into(),
        },
        now - Duration::from_secs(1),
        now + Duration::from_secs(60),
    )
    .unwrap()
}

/// Selects a task-local source window without changing process environment.
pub(crate) async fn capture<F: Future>(future: F) -> (F::Output, Vec<String>) {
    let window = window();
    window.begin();
    let result = TEST_WINDOW.scope(Arc::clone(&window), future).await;
    window.close();
    let records = window.records.lock().unwrap().clone();
    (result, records)
}

/// Drops the actual transport future only after its first consumed chunk.
pub(crate) async fn capture_until_exposed<F: Future>(future: F) -> Vec<String> {
    let window = window();
    TEST_WINDOW
        .scope(Arc::clone(&window), async {
            let mut pending = Box::pin(future);
            tokio::time::timeout(Duration::from_secs(10), async {
                tokio::select! {
                    _ = &mut pending => panic!("transport finished before the partial-body rendezvous"),
                    _ = window.exposed.notified() => {},
                }
            })
            .await
            .unwrap();
            drop(pending);
        })
        .await;
    window.close();
    let records = window.records.lock().unwrap().clone();
    records
}

/// Selects actual emitted record images by their fixed event discriminator.
pub(crate) fn rows(records: &[String], event: &str) -> Vec<Value> {
    records
        .iter()
        .map(|raw| serde_json::from_str::<Value>(raw).unwrap())
        .filter(|row| row["event"] == event)
        .collect()
}

fn chain(records: &[String]) -> String {
    let mut chain = [0_u8; 32];
    for raw in records {
        if serde_json::from_str::<Value>(raw).unwrap()["event"] == "end" {
            break;
        }
        let mut hash = Sha256::new();
        hash.update(b"aos.native.remote-storage-window-chain.v1\0");
        hash.update(chain);
        hash.update(raw.as_bytes());
        chain = hash.finalize().into();
    }
    hex::encode(chain)
}

/// Owns one local HTTP acceptor with explicit abort and join on normal exit.
pub(crate) struct Loopback {
    /// Records the actual ephemeral loopback origin.
    pub(crate) origin: String,
    child: Option<tokio::task::JoinHandle<()>>,
}

impl Loopback {
    /// Starts a local server for production transport calls.
    pub(crate) async fn start(app: axum::Router) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let child = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self {
            origin,
            child: Some(child),
        }
    }

    /// Cancels and joins the owned acceptor.
    pub(crate) async fn retire(mut self) {
        if let Some(child) = self.child.take() {
            child.abort();
            assert!(child.await.unwrap_err().is_cancelled());
        }
    }
}

impl Drop for Loopback {
    fn drop(&mut self) {
        if let Some(child) = &self.child {
            child.abort();
        }
    }
}

#[tokio::test]
async fn closed_pending_owner_never_becomes_complete_after_drop() {
    let window = window();
    TEST_WINDOW
        .scope(Arc::clone(&window), async {
            let owner = Observation::start(Owner::Execute, Image::Nonsecret(b"original"), None);
            window.close();
            let before = window.records.lock().unwrap().clone();
            drop(owner);
            let after = window.records.lock().unwrap().clone();
            assert_eq!(rows(&after, "end"), rows(&before, "end"));
            assert_eq!(rows(&after, "late_terminal").len(), 1);
            let end = rows(&before, "end");
            assert_eq!(end[0]["pending"], "1");
            assert_eq!(end[0]["terminal"], "0");
        })
        .await;
}

#[tokio::test]
async fn concurrent_owners_have_gap_free_ordered_chain() {
    let window = window();
    let futures = (0..32).map(|_| {
        TEST_WINDOW.scope(Arc::clone(&window), async {
            let mut owner = Observation::start(Owner::Execute, Image::Nonsecret(b"original"), None);
            tokio::task::yield_now().await;
            owner.response(200);
            owner.exposed(b"reply");
            owner.eof();
        })
    });
    futures_util::future::join_all(futures).await;
    window.close();

    let records = window.records.lock().unwrap().clone();
    for (index, raw) in records.iter().enumerate() {
        let row: Value = serde_json::from_str(raw).unwrap();
        assert_eq!(row["eventOrdinal"], (index + 1).to_string());
        assert!(raw.len() <= 4096);
    }
    let end = rows(&records, "end");
    assert_eq!(end[0]["offered"], "32");
    assert_eq!(end[0]["terminal"], "32");
    assert_eq!(end[0]["pending"], "0");
    assert_eq!(end[0]["chainSha256"], chain(&records));

    let mut missing = records.clone();
    missing.remove(1);
    assert_ne!(end[0]["chainSha256"], chain(&missing));
    let mut substituted = records;
    // Substitute an actual committed field rather than an unlogged body.
    let mut row: Value = serde_json::from_str(&substituted[1]).unwrap();
    row["offeredRequestBytes"] = json!("999");
    substituted[1] = serde_json::to_string(&row).unwrap();
    assert_ne!(end[0]["chainSha256"], chain(&substituted));
}

#[tokio::test]
async fn pending_cap_poisons_completeness_without_a_false_terminal() {
    let window = window();
    TEST_WINDOW
        .scope(Arc::clone(&window), async {
            let held: Vec<_> = (0..4096)
                .map(|_| Observation::start(Owner::Execute, Image::Nonsecret(b"bounded"), None))
                .collect();
            let untracked =
                Observation::start(Owner::Execute, Image::Nonsecret(b"untracked"), None);
            drop(untracked);
            window.close();
            drop(held);
        })
        .await;
    let records = window.records.lock().unwrap().clone();
    let end = rows(&records, "end");
    assert_eq!(end[0]["offered"], "4096");
    assert_eq!(end[0]["pending"], "4096");
    assert_eq!(end[0]["overflowOrFailure"], true);
    assert_eq!(rows(&records, "late_terminal").len(), 4096);
}

#[test]
fn oversized_record_failure_stays_unknown_without_panicking() {
    let window = window();
    assert!(
        window
            .offer(json!({"unexpected": "x".repeat(4097)}))
            .is_some()
    );
    window.close();
    let records = window.records.lock().unwrap().clone();
    let end = rows(&records, "end");
    assert_eq!(end[0]["overflowOrFailure"], true);
    assert_eq!(end[0]["pending"], "1");
    assert!(records.iter().all(|raw| raw.len() <= 4096));
}

#[test]
fn closed_policy_refuses_unknown_fields_noncanonical_and_past_times() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let valid = json!({
        "version": 1,
        "runId": "a".repeat(64),
        "windowId": "b".repeat(32),
        "startUnixMillis": (now + 1000).to_string(),
        "endUnixMillis": (now + 60_000).to_string(),
    });
    assert!(super::policy::select(&valid.to_string()).is_ok());

    let mut unknown = valid.clone();
    unknown["ready"] = json!(true);
    assert!(super::policy::select(&unknown.to_string()).is_err());

    let mut noncanonical = valid.clone();
    noncanonical["startUnixMillis"] = json!(format!("0{}", now + 1000));
    assert!(super::policy::select(&noncanonical.to_string()).is_err());

    let mut past = valid;
    past["startUnixMillis"] = json!("1");
    assert!(super::policy::select(&past.to_string()).is_err());
}

#[tokio::test]
async fn completed_history_does_not_exhaust_concurrent_pending_limit() {
    let window = window();
    TEST_WINDOW
        .scope(Arc::clone(&window), async {
            for _ in 0..8193 {
                let mut owner =
                    Observation::start(Owner::Execute, Image::Nonsecret(b"metadata"), None);
                owner.response(200);
                owner.exposed(b"reply");
                owner.eof();
            }
        })
        .await;
    window.close();

    let records = window.records.lock().unwrap().clone();
    let end = rows(&records, "end");
    assert_eq!(end[0]["offered"], "8193");
    assert_eq!(end[0]["terminal"], "8193");
    assert_eq!(end[0]["pending"], "0");
    assert_eq!(end[0]["overflowOrFailure"], false);
    assert_eq!(end[0]["chainSha256"], chain(&records));
}

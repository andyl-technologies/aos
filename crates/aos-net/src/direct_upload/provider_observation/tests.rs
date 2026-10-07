//! Actual stream polling, cancellation, reply and privacy regressions.

use super::*;
use aos_proto_types::direct_upload::*;
use futures_util::{stream, StreamExt};

fn attempt() -> Attempt {
    let intent: DirectUploadIntent = serde_json::from_value(serde_json::json!({
        "version":1, "clientOperationId":"11".repeat(32),
        "target":{"kind":"cache_object","cacheId":"cache","path":"nar/canary"},
        "expectedSha256":"22".repeat(32), "byteSize":"3", "partSize":"8388608",
        "dependencyPhase":"content", "transferMode":"direct_required"
    }))
    .unwrap();
    let placement: DirectPlacementRef = serde_json::from_value(serde_json::json!({
        "placementId":"1", "placementFingerprint":"33".repeat(32),
        "placementResourceVersion":"1", "writeSpecVersion":"1", "bindingId":"1",
        "bindingResourceVersion":"1", "bindingWriteRevision":"1",
        "profileFingerprint":"44".repeat(32), "privatePolicyDigest":"55".repeat(32), "checksumAlgorithm":"md5"
    })).unwrap();
    let part: DirectPart = serde_json::from_value(serde_json::json!({
        "partNumber":1,"offset":"0","byteSize":"3","sha256":"22".repeat(32),
        "checksum":{"algorithm":"md5","value":"kAFQmDzST7DWlj99KOF/cg=="}
    }))
    .unwrap();
    Attempt::new(
        &ProviderContext {
            session: DirectSessionRef {
                session_id: "private-session-canary".into(),
                logical_fingerprint: "66".repeat(32),
            },
            placement,
            intent,
        },
        &part,
        &Url::parse("https://provider.test/private-path-canary?token=secret-query-canary").unwrap(),
    )
}

fn terminal(capture: &Arc<Mutex<Vec<String>>>) -> serde_json::Value {
    let lines = capture.lock().unwrap();
    assert!(lines
        .iter()
        .all(|line| line.len() <= MAX_RECORD_BYTES && !line.contains("canary")));
    serde_json::from_str(lines.last().unwrap()).unwrap()
}

#[tokio::test]
async fn hashes_actual_offered_chunks_and_existing_reply_prefix_not_declared_size() {
    let mut attempt = attempt();
    let capture = Arc::clone(&attempt.captured);
    attempt.dispatch();
    let mut offered = attempt.offered(stream::iter([
        Ok(Bytes::from_static(b"a")),
        Ok(Bytes::from_static(b"bc")),
    ]));
    assert_eq!(offered.next().await.unwrap().unwrap(), b"a"[..]);
    assert_eq!(offered.next().await.unwrap().unwrap(), b"bc"[..]);
    assert!(offered.next().await.is_none());
    attempt.status(200);
    attempt.etag("\"private-etag-canary\"");
    attempt.reply_chunk(b"ack");
    attempt.reply_eof();
    attempt.accepted();
    drop(offered);
    drop(attempt);

    let record = terminal(&capture);
    assert_eq!(record["version"], 2);
    let first = record["offeredFirstElapsedNs"]
        .as_str()
        .unwrap()
        .parse::<u64>()
        .unwrap();
    let last = record["offeredLastElapsedNs"]
        .as_str()
        .unwrap()
        .parse::<u64>()
        .unwrap();
    let finished = record["monotonicElapsedNs"]
        .as_str()
        .unwrap()
        .parse::<u64>()
        .unwrap();
    assert!(first <= last && last <= finished);
    let initial: serde_json::Value = serde_json::from_str(&capture.lock().unwrap()[0]).unwrap();
    assert!(initial["offeredFirstElapsedNs"].is_null());
    assert!(initial["offeredLastElapsedNs"].is_null());
    assert_eq!(record["offered"]["bytes"], 3);
    assert_eq!(record["offered"]["sha256"], digest(b"abc"));
    assert_eq!(record["offered"]["eof"], true);
    assert_eq!(record["reply"]["bytes"], 3);
    assert_eq!(record["reply"]["sha256"], digest(b"ack"));
    assert_eq!(record["outcome"], "accepted");
}

#[tokio::test]
async fn source_error_and_partial_drop_keep_unknown_and_actual_prefix() {
    let mut attempt = attempt();
    let capture = Arc::clone(&attempt.captured);
    attempt.dispatch();
    let mut offered = attempt.offered(stream::iter([
        Ok(Bytes::from_static(b"a")),
        Err(std::io::Error::other("secret-error-canary")),
    ]));
    assert_eq!(offered.next().await.unwrap().unwrap(), b"a"[..]);
    assert_eq!(
        offered.next().await.unwrap().unwrap_err().to_string(),
        "secret-error-canary"
    );
    drop(offered);
    attempt.reply_chunk(b"r");
    attempt.reply_failed();
    drop(attempt);

    let record = terminal(&capture);
    assert_eq!(record["offered"]["bytes"], 1);
    assert_eq!(record["offered"]["failed"], true);
    assert_eq!(record["offered"]["eof"], false);
    assert_eq!(record["reply"]["bytes"], 1);
    assert_eq!(record["reply"]["failed"], true);
    assert_eq!(record["outcome"], "unknown");
    assert_eq!(
        record["offeredFirstElapsedNs"],
        record["offeredLastElapsedNs"]
    );
}

#[tokio::test]
async fn unpolled_or_empty_stream_does_not_invent_an_offering_interval() {
    for poll_empty in [false, true] {
        let mut attempt = attempt();
        let capture = Arc::clone(&attempt.captured);
        attempt.dispatch();
        let mut offered = attempt.offered(stream::iter([Ok(Bytes::new())]));
        if poll_empty {
            assert!(offered.next().await.unwrap().unwrap().is_empty());
            assert!(offered.next().await.is_none());
        }
        drop(offered);
        drop(attempt);

        let record = terminal(&capture);
        assert_eq!(record["offered"]["bytes"], 0);
        assert!(record["offeredFirstElapsedNs"].is_null());
        assert!(record["offeredLastElapsedNs"].is_null());
        assert_eq!(record["outcome"], "unknown");
    }
}

#[test]
fn refused_unread_reply_and_undispatched_validation_are_distinct() {
    let mut attempt = attempt();
    let capture = Arc::clone(&attempt.captured);
    attempt.dispatch();
    attempt.status(403);
    drop(attempt);
    let record = terminal(&capture);
    assert_eq!(record["outcome"], "refused");
    assert_eq!(record["reply"]["eof"], false);
    assert_eq!(record["reply"]["bytes"], 0);

    let prepared = self::attempt();
    let capture = Arc::clone(&prepared.captured);
    drop(prepared);
    assert!(capture.lock().unwrap().is_empty());
}

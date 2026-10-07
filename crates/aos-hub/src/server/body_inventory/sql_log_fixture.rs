//! Test-only export of genuine full SQL children through the Native logger.
//!
//! The selected directory receives exact production-encoded child/member bytes.
//! These synthetic source fixtures establish neither deployment authentication
//! nor prior SQL authority. Ordinary test invocations export nothing.

use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::Path;

use aos_hub_core::application_body_observation::{image, BodyEvidence};

use super::*;

// Compile the unchanged production formatter rather than a test approximation.
#[path = "../../logging.rs"]
mod production_logging;

fn write_exact(directory: &Path, name: &str, raw: &[u8]) {
    let path = directory.join(name);
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .unwrap();
    output.write_all(raw).unwrap();
    output.sync_all().unwrap();

    let metadata = output.metadata().unwrap();
    assert!(metadata.is_file());
    assert_eq!(metadata.nlink(), 1);
    assert_eq!(metadata.uid(), fs::metadata(directory).unwrap().uid());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    assert_eq!(metadata.len(), u64::try_from(raw.len()).unwrap());
}

/// Exports one exact synthetic child when the private fixture directory is set.
///
/// # Panics
/// Panics for changed source commitments, a non-private directory, an invalid
/// full aggregate or an existing output. The selected fixture cases must each
/// run in a fresh process so the production logger owns the global subscriber.
pub(crate) fn emit_fixture_child(
    kind: &str,
    projection: SqlProjection,
    evidence: BodyEvidence,
    request: &[u8],
    reply: &[u8],
) {
    let Some(directory) = std::env::var_os("AOS_SQL_CHILD_FIXTURE_DIRECTORY") else {
        return;
    };
    assert!(matches!(kind, "admission" | "append"));
    let request_image = image(request);
    let reply_image = image(reply);
    let observed_request = evidence.request.as_ref().unwrap();
    assert_eq!(observed_request.byte_size, request_image.byte_size);
    assert_eq!(observed_request.sha256, request_image.sha256);
    assert_eq!(evidence.reply.byte_size, reply_image.byte_size);
    assert_eq!(evidence.reply.sha256, reply_image.sha256);
    assert!(projection.matches_constructor(&evidence));

    let directory = Path::new(&directory);
    assert!(directory.is_absolute());
    assert_eq!(directory.canonicalize().unwrap(), directory);
    let before = fs::symlink_metadata(directory).unwrap();
    assert!(before.is_dir());
    assert_eq!(before.permissions().mode() & 0o777, 0o700);
    assert_eq!(before.uid(), fs::metadata("/proc/self").unwrap().uid());

    production_logging::init();
    let start = Instant::now();
    let window = Window::new(
        Policy {
            version: 1,
            window_id: "a".repeat(32),
            start_unix_millis: "1".into(),
            end_unix_millis: "2".into(),
        },
        start,
        start + Duration::from_secs(10),
    )
    .unwrap();
    let ordinal = window.admit().unwrap();
    let mut request_frames = ObservedFrames::default();
    request_frames.observe(request);
    request_frames.eof = true;
    let mut reply_frames = ObservedFrames::default();
    reply_frames.observe(reply);
    reply_frames.eof = true;

    drop(Member {
        window: Arc::clone(&window),
        ordinal,
        method: "POST".into(),
        path_sha256: image(format!("/synthetic-{kind}-fixture").as_bytes()).sha256,
        request_id: Some("b".repeat(32)),
        query_class: Some("absent".into()),
        transport_call_id: None,
        status: Some(200),
        returned: true,
        typed_evidence: Some(evidence),
        sql_projection: Some(projection),
        request: request_frames,
        reply: reply_frames,
    });

    let raw = window.raw_records.lock().unwrap();
    let selected = |event| {
        let records = raw
            .iter()
            .filter(|record| {
                serde_json::from_str::<serde_json::Value>(record).unwrap()["event"] == event
            })
            .collect::<Vec<_>>();
        assert_eq!(records.len(), 1);
        records[0]
    };
    let child = selected("sql_projection");
    let member = selected("member");
    let child_value: serde_json::Value = serde_json::from_str(child).unwrap();
    let member_value: serde_json::Value = serde_json::from_str(member).unwrap();
    let checkpoints = child_value["projection"]["checkpoints"].as_array().unwrap();
    assert_eq!(checkpoints.len(), 64);
    assert!(child.len() <= MAX_SQL_EVENT_BYTES);
    assert_eq!(
        member_value["sqlProjection"]["sha256"],
        image(child.as_bytes()).sha256,
    );
    assert_eq!(member_value["sqlProjection"]["byteSize"], child.len().to_string());
    assert_eq!(child_value["typedEvidence"], member_value["typedEvidence"]);

    if kind == "admission" {
        assert!(checkpoints.iter().all(|checkpoint| {
            checkpoint["kind"] == "admission_checked_transaction"
                && checkpoint["retainedOriginal"] == false
        }));
        let mut sessions = checkpoints
            .iter()
            .map(|checkpoint| checkpoint["sessionId"].as_str().unwrap())
            .collect::<Vec<_>>();
        sessions.sort_unstable();
        sessions.dedup();
        assert_eq!(sessions.len(), 64);
    } else {
        assert!(child.len() > 16 * 1024);
        assert_eq!(
            checkpoints.iter().filter(|checkpoint| {
                checkpoint["kind"] == "manifest_append_checked_transaction"
            }).count(),
            1,
        );
        assert_eq!(
            checkpoints.iter().filter(|checkpoint| {
                checkpoint["kind"] == "manifest_append_retained_receipt"
            }).count(),
            63,
        );
    }

    write_exact(directory, &format!("{kind}-child.json"), child.as_bytes());
    write_exact(directory, &format!("{kind}-member.json"), member.as_bytes());
    let receipt = serde_json::to_vec(&serde_json::json!({
        "version": 1,
        "fixture": "source_generated_sql_child",
        "kind": kind,
        "checkpoints": 64,
        "rawChild": image(child.as_bytes()),
        "rawMember": image(member.as_bytes()),
        "nativeProducerSha256": source_sha256(),
        "coreProducerSha256": child_value["projection"]["producerSha256"],
        "productionLoggerSourceSha256": image(include_bytes!("../../logging.rs")).sha256,
        "deploymentAuthentication": null,
        "priorSqlAuthority": null,
    }))
    .unwrap();
    write_exact(directory, &format!("{kind}-receipt.json"), &receipt);

    let after = fs::symlink_metadata(directory).unwrap();
    assert_eq!(
        (before.dev(), before.ino(), before.uid()),
        (after.dev(), after.ino(), after.uid()),
    );
    assert!(after.is_dir());
    assert_eq!(after.permissions().mode() & 0o777, 0o700);
}

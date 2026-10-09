//! Synthetic exchange tests for independent oracles and preserved failure evidence.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crucible_node_contract::{Bytes, Id};
use serde_json::{Value, json};

use crate::ProviderError;
use crate::bodies::EffectCertainty;
use crate::handshake::Limits;

use super::*;

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

struct SyntheticConnector {
    replies: Option<VecDeque<Option<Value>>>,
}

struct SyntheticSession {
    replies: VecDeque<Option<Value>>,
}

impl ProbeConnector for SyntheticConnector {
    fn connect(&mut self) -> Result<Box<dyn ProbeSession>, ProviderError> {
        Ok(Box::new(SyntheticSession {
            replies: self
                .replies
                .take()
                .ok_or(ProviderError::Frame("no second synthetic stream"))?,
        }))
    }
}

impl ProbeSession for SyntheticSession {
    fn measurement(&self) -> Option<EndpointMeasurement> {
        None
    }

    fn send(&mut self, _value: &Value, _limits: Limits) -> Result<(), ProviderError> {
        Ok(())
    }

    fn send_malformed(&mut self, _payload: &[u8]) -> Result<(), ProviderError> {
        Ok(())
    }

    fn receive(&mut self, _limits: Limits) -> Result<Option<Value>, ProviderError> {
        self.replies
            .pop_front()
            .ok_or(ProviderError::Frame("synthetic reply inventory exhausted"))
    }

    fn fence(&mut self) {}
}

fn envelope(method: &str, sequence: u64, body: Value) -> Value {
    json!({
        "protocol": "CNP/1", "message": "request", "session_id": "session",
        "incarnation_id": "incarnation", "node_id": null,
        "execution_owner_id": null, "capture_owner_id": null,
        "request_id": format!("request/{sequence}"), "operation_id": null,
        "sequence": sequence.to_string(), "method": method, "body": body, "extensions": {}
    })
}

fn hello_step() -> ProbeStep {
    let mut request = envelope(
        "hello",
        1,
        json!({
            "versions": ["CNP/1"], "session_id": "session",
            "controller_nonce": {"$binding":"private-controller-nonce"},
            "required_features": ["cnp.core/1"], "optional_features": [],
            "limits": {"frame_bytes":"65536","nesting":"64","requests":"16",
                       "journal_entries":"64","blob_chunk_bytes":"4096"},
            "admission_token": {"$binding":"private-launch-token"}, "extensions": {}
        }),
    );
    request["session_id"] = Value::Null;
    request["incarnation_id"] = Value::Null;
    ProbeStep::Exchange {
        id: id("hello"),
        check: CheckKind::Hello,
        request,
        expected: Expectation::Completed,
        assertions: Vec::new(),
        captures: BTreeMap::from([(
            "provider-incarnation".into(),
            "/body/result/incarnation_id".into(),
        )]),
    }
}

fn hello_reply() -> Value {
    let mut reply = envelope(
        "hello",
        1,
        json!({
            "status":"completed", "operation_state":"completed", "extensions":{},
            "result": {
                "version":"CNP/1", "session_id":"session", "incarnation_id":"incarnation",
                "controller_nonce": serde_json::to_value(Bytes::new(vec![3; 32])).unwrap(),
                "provider_nonce": serde_json::to_value(Bytes::new(vec![5; 32])).unwrap(),
                "selected_features":["cnp.core/1"],
                "limits":{"frame_bytes":"65536","nesting":"64","requests":"16",
                          "journal_entries":"64","blob_chunk_bytes":"4096"},
                "resume_token": null, "resumed_operations":[],
                "provider_identity": {
                    "schema_version":1,"provider_id":"synthetic-peer",
                    "implementation":{
                        "schema_version":1,"implementation_id":"synthetic-peer/1",
                        "artifacts":[],"model_definitions":[],"formats":[],"extensions":{}
                    },
                    "protocol_versions":["CNP/1"],"supported_profiles":[],
                    "extensions_supported":[],"qualification_refs":[],"extensions":{}
                }
            }
        }),
    );
    reply["message"] = json!("response");
    reply
}

fn private_bindings() -> BTreeMap<String, Value> {
    BTreeMap::from([
        (
            "private-launch-token".into(),
            serde_json::to_value(Bytes::new(vec![7; 32])).unwrap(),
        ),
        (
            "private-controller-nonce".into(),
            serde_json::to_value(Bytes::new(vec![3; 32])).unwrap(),
        ),
    ])
}

fn plan(steps: Vec<ProbeStep>, checks: BTreeSet<CheckKind>) -> ProbePlan {
    ProbePlan {
        schema_version: 1,
        fixture: id("synthetic-oracle/1"),
        required_checks: checks,
        steps,
    }
}

#[test]
fn private_bindings_are_excluded_from_reports_and_missing_checks_remain_visible() {
    let plan = plan(
        vec![hello_step()],
        BTreeSet::from([CheckKind::Hello, CheckKind::Reconnect]),
    );
    let mut connector = SyntheticConnector {
        replies: Some(VecDeque::from([Some(hello_reply())])),
    };
    let bindings = private_bindings();
    let private = bindings["private-launch-token"]
        .as_str()
        .unwrap()
        .to_owned();

    let report = run(&plan, &mut connector, bindings).unwrap();

    assert!(!report.passed());
    assert_eq!(report.results[0].disposition, CheckDisposition::Passed);
    assert_eq!(
        report.missing_checks,
        BTreeSet::from([CheckKind::Reconnect])
    );
    assert!(report.protocol_only);
    assert!(report.endpoints.is_empty());
    assert!(report.results[0].request_identity.is_none());
    assert!(report.results[0].response_identity.is_none());
    assert!(
        !String::from_utf8(report.canonical_bytes().unwrap())
            .unwrap()
            .contains(&private)
    );
}

#[test]
fn challenge_mismatch_retains_failure_and_does_not_retry_dependent_work() {
    let mut reply = hello_reply();
    reply["body"]["result"]["controller_nonce"] =
        serde_json::to_value(Bytes::new(vec![9; 32])).unwrap();
    let plan = plan(
        vec![
            hello_step(),
            ProbeStep::Disconnect {
                id: id("disconnect"),
            },
        ],
        BTreeSet::from([CheckKind::Hello]),
    );
    let mut connector = SyntheticConnector {
        replies: Some(VecDeque::from([Some(reply)])),
    };

    let report = run(&plan, &mut connector, private_bindings()).unwrap();

    assert_eq!(report.results[0].disposition, CheckDisposition::Failed);
    assert_eq!(report.results[1].disposition, CheckDisposition::NotExecuted);
    assert_eq!(report.missing_checks, BTreeSet::from([CheckKind::Hello]));
}

#[test]
fn typed_request_and_reply_correlation_reject_foreign_original_identity() {
    let discover = ProbeStep::Exchange {
        id: id("discover"),
        check: CheckKind::DescriptorBinding,
        request: envelope("discover", 2, json!({"profile_ids":[],"extensions":{}})),
        expected: Expectation::Error {
            code: id("UNSUPPORTED_FEATURE"),
            effect: EffectCertainty::NotStarted,
        },
        assertions: Vec::new(),
        captures: BTreeMap::new(),
    };
    let mut foreign = envelope(
        "discover",
        2,
        json!({
            "status":"error","operation_state":"not_started","extensions":{},
            "error":{"code":"UNSUPPORTED_FEATURE","message":"not installed","effect":"not_started",
                     "retryable":false,"details":{}}
        }),
    );
    foreign["message"] = json!("response");
    foreign["request_id"] = json!("foreign-request");
    let mut connector = SyntheticConnector {
        replies: Some(VecDeque::from([Some(hello_reply()), Some(foreign)])),
    };

    let report = run(
        &plan(
            vec![hello_step(), discover],
            BTreeSet::from([CheckKind::Hello, CheckKind::DescriptorBinding]),
        ),
        &mut connector,
        private_bindings(),
    )
    .unwrap();

    assert_eq!(report.results[0].disposition, CheckDisposition::Passed);
    assert_eq!(report.results[1].disposition, CheckDisposition::Failed);
    assert!(!report.passed());
}

#[test]
fn malformed_frame_closure_is_observed_without_fabricating_native_containment() {
    let malformed = ProbeStep::Malformed {
        id: id("duplicate-json-key"),
        payload: Bytes::new(br#"{"a":1,"a":2}"#.to_vec()),
        expected: Expectation::Disconnected,
    };
    let mut connector = SyntheticConnector {
        replies: Some(VecDeque::from([Some(hello_reply()), None])),
    };

    let report = run(
        &plan(
            vec![hello_step(), malformed],
            BTreeSet::from([CheckKind::Hello, CheckKind::Malformed]),
        ),
        &mut connector,
        private_bindings(),
    )
    .unwrap();

    assert!(report.passed());
    assert!(report.protocol_only);
    assert_eq!(report.results[1].response_identity, None);
}

#[test]
fn decoder_refuses_duplicate_case_identity_before_opening_a_stream() {
    let invalid = plan(
        vec![hello_step(), hello_step()],
        BTreeSet::from([CheckKind::Hello]),
    );
    let bytes = serde_json::to_vec(&invalid).unwrap();
    assert!(ProbePlan::decode(&bytes).is_err());
}

#[test]
fn inline_handshake_credentials_are_refused_before_plan_commitment() {
    let mut step = hello_step();
    if let ProbeStep::Exchange { request, .. } = &mut step {
        request["body"]["controller_nonce"] =
            serde_json::to_value(Bytes::new(vec![3; 32])).unwrap();
    }
    assert!(
        plan(vec![step], BTreeSet::from([CheckKind::Hello]))
            .validate()
            .is_err()
    );

    let mut step = hello_step();
    if let ProbeStep::Exchange { assertions, .. } = &mut step {
        assertions.push(ReplyAssertion {
            pointer: "/body/result".into(),
            equals: hello_reply()["body"]["result"].clone(),
        });
    }
    assert!(
        plan(vec![step], BTreeSet::from([CheckKind::Hello]))
            .validate()
            .is_err()
    );
}

#[test]
fn materialized_content_is_verified_before_independent_field_oracles() {
    let steps = vec![
        hello_step(),
        ProbeStep::CanonicalContent {
            id: id("build-record"),
            value: json!({"incarnation":{"$binding":"provider-incarnation"},"checksum":"259"}),
            reference_binding: id("record-ref"),
            bytes_binding: id("record-bytes"),
        },
        ProbeStep::InspectContent {
            id: id("verify-original-record"),
            reference: json!({"$binding":"record-ref"}),
            bytes: json!({"$binding":"record-bytes"}),
            assertions: vec![ReplyAssertion {
                pointer: "/checksum".into(),
                equals: json!("259"),
            }],
            captures: BTreeMap::new(),
        },
    ];
    let mut connector = SyntheticConnector {
        replies: Some(VecDeque::from([Some(hello_reply())])),
    };
    let report = run(
        &plan(steps, BTreeSet::from([CheckKind::Hello])),
        &mut connector,
        private_bindings(),
    )
    .unwrap();
    assert!(report.passed());
    assert!(report.results[1].check.is_none());
    assert!(report.results[2].check.is_none());
}

#[test]
fn provider_content_requires_complete_bytes_and_preserves_both_direction_sequences() {
    use crucible_node_contract::canonical;

    let bytes = canonical::canonical_json(&json!({"checksum":"259"})).unwrap();
    let reference = canonical::content_ref(&bytes, "application/json").unwrap();
    let begin = envelope(
        "blob_begin",
        2,
        json!({"transfer_id":"provider/blob/1","content":reference,"extensions":{}}),
    );
    let chunk = envelope(
        "blob_chunk",
        3,
        json!({"transfer_id":"provider/blob/1","offset":"0","bytes":Bytes::new(bytes),"extensions":{}}),
    );
    let finish = envelope(
        "blob_finish",
        4,
        json!({"transfer_id":"provider/blob/1","extensions":{}}),
    );
    let mut discover = envelope("discover", 5, json!({"profile_ids":[],"extensions":{}}));
    discover["sequence"] = json!({"$sequence":"outgoing"});
    let mut reply = envelope(
        "discover",
        5,
        json!({"status":"error","operation_state":"not_started","extensions":{},
        "error":{"code":"UNSUPPORTED_FEATURE","message":"unavailable","effect":"not_started","retryable":false,"details":{}}}),
    );
    reply["message"] = json!("response");
    let steps = vec![
        hello_step(),
        ProbeStep::ReceiveBlob {
            id: id("native-record"),
            reference: serde_json::to_value(reference).unwrap(),
            maximum_chunks: 4,
            reference_binding: id("record-ref"),
            bytes_binding: id("record-bytes"),
        },
        ProbeStep::InspectContent {
            id: id("checksum-oracle"),
            reference: json!({"$binding":"record-ref"}),
            bytes: json!({"$binding":"record-bytes"}),
            assertions: vec![ReplyAssertion {
                pointer: "/checksum".into(),
                equals: json!("259"),
            }],
            captures: BTreeMap::new(),
        },
        ProbeStep::Exchange {
            id: id("following-request"),
            check: CheckKind::DescriptorBinding,
            request: discover,
            expected: Expectation::Error {
                code: id("UNSUPPORTED_FEATURE"),
                effect: EffectCertainty::NotStarted,
            },
            assertions: Vec::new(),
            captures: BTreeMap::new(),
        },
    ];
    let mut connector = SyntheticConnector {
        replies: Some(VecDeque::from([
            Some(hello_reply()),
            Some(begin),
            Some(chunk),
            Some(finish),
            Some(reply),
        ])),
    };

    let report = run(
        &plan(
            steps,
            BTreeSet::from([CheckKind::Hello, CheckKind::DescriptorBinding]),
        ),
        &mut connector,
        private_bindings(),
    )
    .unwrap();
    assert!(report.passed());
    assert!(report.results[1].request_identity.is_some());
    assert!(report.results[1].response_identity.is_some());
}

#[cfg(target_os = "linux")]
mod unix_transport {
    //! Exercises actual framed sockets and OS identity, without native-model claims.

    use std::io::Write;
    use std::os::unix::fs::DirBuilderExt;
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;
    use std::time::Duration;

    use super::*;

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct PrivateDirectory(PathBuf);

    impl PrivateDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "cnp-probe-{}-{}",
                std::process::id(),
                NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .unwrap();
            Self(path)
        }

        fn socket(&self) -> PathBuf {
            self.0.join("control.sock")
        }
    }

    impl Drop for PrivateDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn actual_unix_probe_measures_peer_and_exercises_public_cnp_frames() {
        let directory = PrivateDirectory::new();
        let listener = UnixListener::bind(directory.socket()).unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = crate::transport::FrameReader::new(&mut stream, 65536)
                .unwrap()
                .read()
                .unwrap()
                .unwrap();
            assert_eq!(request["method"], "hello");
            crate::transport::write_frame(&mut stream, &hello_reply(), 65536).unwrap();
        });
        let mut connector = UnixProbeConnector::new(
            directory.socket(),
            rustix::process::geteuid().as_raw(),
            &std::env::current_exe().unwrap(),
            Duration::from_secs(1),
        )
        .unwrap();

        let report = run(
            &plan(vec![hello_step()], BTreeSet::from([CheckKind::Hello])),
            &mut connector,
            private_bindings(),
        )
        .unwrap();

        server.join().unwrap();
        assert!(report.passed());
        assert_eq!(report.endpoints.len(), 1);
        assert_eq!(
            report.endpoints[0].peer_pid.get(),
            u64::from(std::process::id())
        );
        assert_eq!(
            report.endpoints[0].peer_uid.get(),
            u64::from(rustix::process::geteuid().as_raw())
        );
        assert!(report.protocol_only);
    }

    #[test]
    fn a_timed_out_partial_reply_cannot_count_as_peer_disconnection() {
        let directory = PrivateDirectory::new();
        let listener = UnixListener::bind(directory.socket()).unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            crate::transport::FrameReader::new(&mut stream, 65536)
                .unwrap()
                .read()
                .unwrap();
            stream.write_all(&64_u32.to_be_bytes()).unwrap();
            stream.write_all(b"{").unwrap();
            thread::sleep(Duration::from_millis(250));
        });
        let mut step = hello_step();
        if let ProbeStep::Exchange { expected, .. } = &mut step {
            *expected = Expectation::Disconnected;
        }
        let mut connector = UnixProbeConnector::new(
            directory.socket(),
            rustix::process::geteuid().as_raw(),
            &std::env::current_exe().unwrap(),
            Duration::from_millis(50),
        )
        .unwrap();

        let report = run(
            &plan(vec![step], BTreeSet::from([CheckKind::Hello])),
            &mut connector,
            private_bindings(),
        )
        .unwrap();

        server.join().unwrap();
        assert!(!report.passed());
        assert_eq!(report.results[0].disposition, CheckDisposition::Failed);
        assert_eq!(report.results[0].response_identity, None);
    }
}

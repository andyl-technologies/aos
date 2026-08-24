//! Checks the guest-emitter third of `gate:abi-conformance`.

#![forbid(unsafe_code)]

use std::fmt::Display;
use std::path::Path;

use crucible_guest::{
    CRUCIBLE_GUEST_DEFAULT_RANDOM_REQUEST_ID, CRUCIBLE_GUEST_DEFAULT_RANDOM_STREAM_TAG,
    CRUCIBLE_GUEST_STATIC_RUSTFLAGS, CRUCIBLE_GUEST_SUPPORTED_ARCHITECTURES, DoorbellTransport,
    GuestCommand, GuestCommandOutcome, GuestEmitterError, WHITEBOX_DOORBELL_AARCH64_ABI,
    WHITEBOX_DOORBELL_AARCH64_RESERVED_HINT, WHITEBOX_DOORBELL_ABIS,
    WHITEBOX_DOORBELL_RANDOM_REQUEST_MAX_WIDTH_BYTES, WHITEBOX_DOORBELL_X86_64_ABI,
    WHITEBOX_DOORBELL_X86_64_RESERVED_PORT, WhiteboxAssertionMarkerBody,
    WhiteboxAssertionMarkerFlavor, WhiteboxCoverageMarkerBody, WhiteboxDoorbellArchitecture,
    WhiteboxDoorbellFrame, WhiteboxDoorbellTrapAbi, WhiteboxEventMarkerBody,
    WhiteboxLifecycleMarkerEvent, WhiteboxMarkerDetail, WhiteboxMarkerPayload,
    WhiteboxMeasurementBoundaryBody, WhiteboxMeasurementValue, WhiteboxMetricSampleBody,
    WhiteboxRandomRequestBody, WhiteboxSemanticMarkerBody, WhiteboxSemanticMarkerDetail,
    decode_whitebox_marker_payload, emit_command, parse_cli_args,
    whitebox_doorbell_abi_for_architecture,
};

#[test]
fn guest_cli_verbs_encode_shared_marker_payloads() {
    assert_eq!(
        payload_from_args(&["always", "a.always", "always holds", "1"]),
        WhiteboxMarkerPayload::Assertion(WhiteboxAssertionMarkerBody {
            flavor: WhiteboxAssertionMarkerFlavor::Always,
            condition: true,
            must_hit: true,
            id: String::from("a.always"),
            message: String::from("always holds"),
            location: String::from("crucible-guest:always"),
            details: Vec::new(),
        })
    );
    assert_eq!(
        payload_from_args(&["sometimes", "a.sometimes", "sometimes holds", "0"]),
        WhiteboxMarkerPayload::Assertion(WhiteboxAssertionMarkerBody {
            flavor: WhiteboxAssertionMarkerFlavor::Sometimes,
            condition: false,
            must_hit: true,
            id: String::from("a.sometimes"),
            message: String::from("sometimes holds"),
            location: String::from("crucible-guest:sometimes"),
            details: Vec::new(),
        })
    );
    assert_eq!(
        payload_from_args(&["reachable", "guest.ready", "guest reached readiness"]),
        WhiteboxMarkerPayload::Assertion(WhiteboxAssertionMarkerBody {
            flavor: WhiteboxAssertionMarkerFlavor::Reachable,
            condition: true,
            must_hit: true,
            id: String::from("guest.ready"),
            message: String::from("guest reached readiness"),
            location: String::from("crucible-guest:reachable"),
            details: Vec::new(),
        })
    );
    assert_eq!(
        payload_from_args(&["unreachable", "panic.path", "panic path stayed absent"]),
        WhiteboxMarkerPayload::Assertion(WhiteboxAssertionMarkerBody {
            flavor: WhiteboxAssertionMarkerFlavor::Unreachable,
            condition: true,
            must_hit: true,
            id: String::from("panic.path"),
            message: String::from("panic path stayed absent"),
            location: String::from("crucible-guest:unreachable"),
            details: Vec::new(),
        })
    );
    assert_eq!(
        payload_from_args(&["setup-complete"]),
        WhiteboxMarkerPayload::Lifecycle(WhiteboxLifecycleMarkerEvent::SetupComplete)
    );
    assert_eq!(
        payload_from_args(&["test-done"]),
        WhiteboxMarkerPayload::Lifecycle(WhiteboxLifecycleMarkerEvent::TestDone)
    );
    assert_eq!(
        payload_from_args(&["event", "phase", "node=a", "step=boot"]),
        WhiteboxMarkerPayload::Event(WhiteboxEventMarkerBody {
            name: String::from("phase"),
            details: vec![
                WhiteboxMarkerDetail::new("node", "a"),
                WhiteboxMarkerDetail::new("step", "boot"),
            ],
        })
    );
    assert_eq!(
        payload_from_args(&["coverage", "hot-path"]),
        WhiteboxMarkerPayload::Coverage(WhiteboxCoverageMarkerBody {
            point: String::from("hot-path"),
        })
    );
    assert_eq!(
        payload_from_args(&["measurement-begin", "latency", "request/1"]),
        WhiteboxMarkerPayload::MeasurementBegin(WhiteboxMeasurementBoundaryBody {
            measurement: String::from("latency"),
            instance: String::from("request/1"),
        })
    );
    assert_eq!(
        payload_from_args(&[
            "metric-sample",
            "latency",
            "request/1",
            "duration",
            "i64",
            "-7",
        ]),
        WhiteboxMarkerPayload::MetricSample(WhiteboxMetricSampleBody {
            measurement: String::from("latency"),
            instance: String::from("request/1"),
            metric: String::from("duration"),
            value: WhiteboxMeasurementValue::Signed(-7),
        })
    );
    assert_eq!(
        payload_from_args(&["measurement-end", "latency", "request/1"]),
        WhiteboxMarkerPayload::MeasurementEnd(WhiteboxMeasurementBoundaryBody {
            measurement: String::from("latency"),
            instance: String::from("request/1"),
        })
    );
    assert_eq!(
        payload_from_args(&[
            "semantic-marker",
            "converged",
            "epoch/1",
            "stable:bool=1",
            "epoch:u64=42",
        ]),
        WhiteboxMarkerPayload::SemanticMarker(WhiteboxSemanticMarkerBody {
            marker: String::from("converged"),
            instance: String::from("epoch/1"),
            details: vec![
                WhiteboxSemanticMarkerDetail {
                    key: String::from("epoch"),
                    value: WhiteboxMeasurementValue::Unsigned(42),
                },
                WhiteboxSemanticMarkerDetail {
                    key: String::from("stable"),
                    value: WhiteboxMeasurementValue::Boolean(true),
                },
            ],
        })
    );
    assert_eq!(
        payload_from_args(&["get-random", "4", "workload"]),
        WhiteboxMarkerPayload::RandomRequest(WhiteboxRandomRequestBody {
            request_id: CRUCIBLE_GUEST_DEFAULT_RANDOM_REQUEST_ID,
            width_bytes: 4,
            stream_tag: String::from("workload"),
        })
    );
    assert_eq!(
        payload_from_args(&["get-random", "1"]),
        WhiteboxMarkerPayload::RandomRequest(WhiteboxRandomRequestBody {
            request_id: CRUCIBLE_GUEST_DEFAULT_RANDOM_REQUEST_ID,
            width_bytes: 1,
            stream_tag: String::from(CRUCIBLE_GUEST_DEFAULT_RANDOM_STREAM_TAG),
        })
    );
}

#[test]
fn guest_emitter_uses_single_source_doorbell_abi_table() {
    assert_eq!(
        CRUCIBLE_GUEST_SUPPORTED_ARCHITECTURES,
        &[
            WhiteboxDoorbellArchitecture::X86_64,
            WhiteboxDoorbellArchitecture::Aarch64
        ]
    );
    assert_eq!(WHITEBOX_DOORBELL_ABIS.len(), 2);
    assert_eq!(
        WHITEBOX_DOORBELL_ABIS[0],
        whitebox_doorbell_abi_for_architecture(WhiteboxDoorbellArchitecture::X86_64)
    );
    assert_eq!(
        WHITEBOX_DOORBELL_ABIS[1],
        whitebox_doorbell_abi_for_architecture(WhiteboxDoorbellArchitecture::Aarch64)
    );
    assert_eq!(WHITEBOX_DOORBELL_ABIS[0], WHITEBOX_DOORBELL_X86_64_ABI);
    assert_eq!(WHITEBOX_DOORBELL_ABIS[1], WHITEBOX_DOORBELL_AARCH64_ABI);
    assert_eq!(
        WHITEBOX_DOORBELL_ABIS[0].trap(),
        WhiteboxDoorbellTrapAbi::X86PortIo {
            port: WHITEBOX_DOORBELL_X86_64_RESERVED_PORT,
        }
    );
    assert_eq!(
        WHITEBOX_DOORBELL_ABIS[1].trap(),
        WhiteboxDoorbellTrapAbi::Aarch64Hint {
            immediate: WHITEBOX_DOORBELL_AARCH64_RESERVED_HINT,
        }
    );
}

#[test]
fn guest_get_random_round_trip_reads_reply_from_payload_range() {
    let command = must(GuestCommand::get_random(3, "workload"));
    let mut transport = RecordingDoorbellTransport {
        reply: vec![0xaa, 0xbb, 0xcc],
        rings: Vec::new(),
    };

    let outcome = must(emit_command(&command, &mut transport));
    let request_frame = match outcome {
        GuestCommandOutcome::Random {
            request_frame,
            reply,
        } => {
            assert_eq!(reply, vec![0xaa, 0xbb, 0xcc]);
            request_frame
        }
        GuestCommandOutcome::Marker { frame } => {
            panic!("get-random should produce a random reply, got marker frame {frame:?}")
        }
    };

    assert_eq!(transport.rings, vec![request_frame.clone()]);
    assert_eq!(
        decode_payload(&request_frame),
        WhiteboxMarkerPayload::RandomRequest(WhiteboxRandomRequestBody {
            request_id: CRUCIBLE_GUEST_DEFAULT_RANDOM_REQUEST_ID,
            width_bytes: 3,
            stream_tag: String::from("workload"),
        })
    );
}

#[test]
fn guest_cli_rejects_malformed_inputs() {
    assert_usage_error(parse_cli_args(["always", "id", "msg", "true"]));
    assert_usage_error(parse_cli_args(["event", "phase", "missing-equals"]));
    assert_usage_error(parse_cli_args(["event", "phase", "=value"]));
    assert_usage_error(parse_cli_args([
        "get-random",
        &usize::from(WHITEBOX_DOORBELL_RANDOM_REQUEST_MAX_WIDTH_BYTES + 1).to_string(),
    ]));
    assert_usage_error(parse_cli_args(["coverage"]));
}

#[test]
fn guest_static_build_contract_is_declared_for_aos_package() {
    assert_eq!(
        CRUCIBLE_GUEST_STATIC_RUSTFLAGS,
        &["-C", "target-feature=+crt-static"]
    );
    let cargo_toml = manifest_file("Cargo.toml");
    assert!(cargo_toml.contains("name = \"crucible-guest\""));
    assert!(cargo_toml.contains("path = \"src/main.rs\""));
    assert!(!cargo_toml.contains("clap"));

    // The standalone `pkgs.aos` package intentionally copies only `crates/`
    // into its build source. The dedicated Crucible ABI gate copies the
    // repository packaging files too and exercises these assertions there.
    if let Some(package) = repo_file("pkgs/tools/crucible-guest.nix") {
        assert!(package.contains("CARGO_TARGET_"));
        assert!(package.contains("target-feature=+crt-static"));
        assert!(package.contains("-p crucible-guest --bin crucible-guest"));
        assert!(package.contains("patchelf --print-interpreter"));
        assert!(package.contains("packaged_guest_system=${lib.system}"));
        assert!(package.contains("instruction_abi_architectures=x86_64,aarch64"));
    }
}

fn payload_from_args(args: &[&str]) -> WhiteboxMarkerPayload {
    decode_payload(&must(
        must(parse_cli_args(args.iter().copied())).encode_frame(),
    ))
}

fn decode_payload(frame_bytes: &[u8]) -> WhiteboxMarkerPayload {
    let frame = must(WhiteboxDoorbellFrame::decode(frame_bytes));
    must(decode_whitebox_marker_payload(&frame))
}

fn assert_usage_error(result: Result<GuestCommand, GuestEmitterError>) {
    match result {
        Ok(command) => panic!("input should have failed, parsed {command:?}"),
        Err(GuestEmitterError::Usage { message }) => {
            assert!(message.contains("usage: crucible-guest"));
        }
        Err(error) => panic!("input should fail with usage error, got {error}"),
    }
}

fn manifest_file(path: &str) -> String {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    match std::fs::read_to_string(manifest_dir.join(path)) {
        Ok(content) => content,
        Err(error) => panic!("failed to read manifest file {path}: {error}"),
    }
}

fn repo_file(path: &str) -> Option<String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    std::fs::read_to_string(root.join(path)).ok()
}

fn must<T, E>(result: Result<T, E>) -> T
where
    E: Display,
{
    match result {
        Ok(value) => value,
        Err(error) => panic!("expected success, got {error}"),
    }
}

struct RecordingDoorbellTransport {
    reply: Vec<u8>,
    rings: Vec<Vec<u8>>,
}

impl DoorbellTransport for RecordingDoorbellTransport {
    fn ring(&mut self, frame: &mut [u8]) -> Result<(), GuestEmitterError> {
        self.rings.push(frame.to_vec());
        for (index, byte) in self.reply.iter().copied().enumerate() {
            if index < frame.len() {
                frame[index] = byte;
            }
        }
        Ok(())
    }
}

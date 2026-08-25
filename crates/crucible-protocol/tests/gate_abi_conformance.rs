//! Checks protocol frame vectors for `gate:abi-conformance`.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::panic::{AssertUnwindSafe, catch_unwind};

use crucible_protocol::selectable_catalog_plan::{
    SELECTABLE_CATALOG_PLAN_HEADER_BYTES, SELECTABLE_CATALOG_PLAN_MAGIC,
    SELECTABLE_CATALOG_PLAN_VERSION, SelectableCatalogPlan, SelectablePlanContinuation,
    SelectablePlanLimits,
};
use crucible_protocol::{
    CODEC_FUZZ_REGRESSION_CORPUS, CONTROL_PROTOCOL_VERSION, ControlCodecFuzzCase,
    ControlCodecFuzzOutcome, ControlDirection, ControlGoldenVector, ControlGoldenVectorMessage,
    ControlTag, GOLDEN_CONTROL_VECTORS, GOLDEN_VECTOR_PROTOCOL_VERSION,
    GOLDEN_VECTOR_REGENERATION_RULE, GOLDEN_WHITEBOX_DOORBELL_FRAME_VECTORS,
    GOLDEN_WHITEBOX_MARKER_PAYLOAD_VECTORS, HostMsg, PluginMsg, SELECTABLE_DIGEST_BYTES,
    SELECTABLE_GOLDEN_VECTOR_REGENERATION_RULE, SELECTABLE_MESSAGE_KIND_REGISTER,
    SELECTABLE_MESSAGE_KIND_REPLY, SELECTABLE_MESSAGE_KIND_REQUEST, SELECTABLE_PROTOCOL_VERSION,
    SelectableRegister, SelectionReply, SelectionRequest, WHITEBOX_DOORBELL_ASSERTION_FLAVOR_COUNT,
    WHITEBOX_DOORBELL_FRAME_MAGIC, WHITEBOX_DOORBELL_FRAME_REGENERATION_RULE,
    WHITEBOX_DOORBELL_KIND_METRIC_SAMPLE, WHITEBOX_DOORBELL_KIND_SEMANTIC_MARKER,
    WHITEBOX_DOORBELL_LIFECYCLE_EVENT_COUNT, WHITEBOX_DOORBELL_MARKER_KIND_COUNT,
    WHITEBOX_DOORBELL_PROTOCOL_VERSION, WHITEBOX_MARKER_BODY_MAX_BYTES,
    WHITEBOX_MEASUREMENT_VALUE_KIND_COUNT, WHITEBOX_MEASUREMENT_VECTOR_MAX_ELEMENTS,
    WhiteboxAssertionMarkerFlavor, WhiteboxDoorbellFrame, WhiteboxDoorbellFrameDecodeError,
    WhiteboxDoorbellMarkerKind, WhiteboxLifecycleMarkerEvent, WhiteboxMarkerPayload,
    WhiteboxMarkerPayloadDecodeError, WhiteboxMarkerPayloadEncodeError, WhiteboxMeasurementValue,
    WhiteboxMeasurementValueKind, WhiteboxMetricSampleBody, WhiteboxSemanticMarkerBody,
    WhiteboxSemanticMarkerDetail, control_decode_host_msg, control_decode_plugin_msg,
    control_encode_host_msg, control_encode_plugin_msg, decode_selectable_message_kind,
    decode_whitebox_marker_payload, encode_whitebox_doorbell_frame, encode_whitebox_marker_frame,
    encode_whitebox_marker_payload_body, run_control_codec_fuzz_target,
};

#[test]
fn protocol_abi_conformance_runs_named_checks() {
    assert_frozen_golden_vectors();
    assert_decode_encode_roundtrip();
    assert_abi_version_field();
    assert_version_bump_regenerates_vectors();
    assert_doorbell_frame_golden_vectors();
    assert_doorbell_marker_payload_golden_vectors();
    assert_doorbell_marker_kind_vocabulary();
    assert_doorbell_marker_subvocabularies();
    assert_selectable_v1_golden_vectors();
    assert_selectable_catalog_plan_v1_golden_vector();
    assert_doorbell_decoder_fuzz_corpus();
    assert_structure_aware_fuzz_corpus();
    assert_protocol_codec_fuzz_corpus();
}

#[test]
fn guest_selectable_catalog_plan_v1_golden_vector_matches_live_codec() {
    assert_selectable_catalog_plan_v1_golden_vector();
}

fn assert_selectable_catalog_plan_v1_golden_vector() {
    let plan = SelectableCatalogPlan::new(
        SelectablePlanLimits::new(1, 1, 1)
            .unwrap_or_else(|error| panic!("catalog plan limits must validate: {error}")),
        Vec::new(),
        SelectablePlanContinuation::cold(),
    )
    .unwrap_or_else(|error| panic!("empty catalog plan must validate: {error}"));
    let bytes = plan
        .encode()
        .unwrap_or_else(|error| panic!("empty catalog plan must encode: {error}"));
    let mut expected = vec![0_u8; SELECTABLE_CATALOG_PLAN_HEADER_BYTES];
    expected[..8].copy_from_slice(&SELECTABLE_CATALOG_PLAN_MAGIC);
    expected[8..12].copy_from_slice(&SELECTABLE_CATALOG_PLAN_VERSION.to_be_bytes());
    expected[12..16].copy_from_slice(&(96_u32).to_be_bytes());
    expected[16..20].copy_from_slice(&(96_u32).to_be_bytes());
    expected[24..28].copy_from_slice(&(1_u32).to_be_bytes());
    expected[40..48].copy_from_slice(&(1_u64).to_be_bytes());
    expected[48..56].copy_from_slice(&(1_u64).to_be_bytes());
    assert_eq!(bytes, expected);
    assert_eq!(SelectableCatalogPlan::decode(&bytes), Ok(plan));
}

#[test]
fn guest_selectable_v1_golden_vectors_match_live_codec_bytes() {
    assert_selectable_v1_golden_vectors();
}

fn assert_selectable_v1_golden_vectors() {
    assert!(SELECTABLE_GOLDEN_VECTOR_REGENERATION_RULE.contains("SELECTABLE_PROTOCOL_VERSION"));
    let registration = SelectableRegister::new(
        0x0102_0304_0506_0708,
        "net",
        vec![0xaa, 0xbb],
        vec![1],
        vec![String::from("a"), String::from("z")],
    )
    .unwrap_or_else(|error| panic!("selectable registration vector must build: {error}"));
    let registration_bytes = registration
        .encode()
        .unwrap_or_else(|error| panic!("selectable registration vector must encode: {error}"));
    assert_eq!(
        registration_bytes,
        [
            1, 0, 1, 0, 56, 0, 0, 0, 68, 0, 0, 0, 8, 7, 6, 5, 4, 3, 2, 1, 56, 0, 0, 0, 3, 0, 0, 0,
            59, 0, 0, 0, 2, 0, 0, 0, 61, 0, 0, 0, 1, 0, 0, 0, 62, 0, 0, 0, 6, 0, 0, 0, 2, 0, 0, 0,
            b'n', b'e', b't', 0xaa, 0xbb, 1, 1, 0, b'a', 1, 0, b'z',
        ]
    );
    assert_eq!(
        decode_selectable_message_kind(&registration_bytes)
            .map(|kind| (SELECTABLE_PROTOCOL_VERSION, kind.wire_value())),
        Ok((
            SELECTABLE_PROTOCOL_VERSION,
            SELECTABLE_MESSAGE_KIND_REGISTER
        ))
    );

    let request = SelectionRequest::new(9, "net", "epoch/1", Some(vec![0xaa]), 104)
        .unwrap_or_else(|error| panic!("selection request vector must build: {error}"));
    let request_bytes = request
        .encode()
        .unwrap_or_else(|error| panic!("selection request vector must encode: {error}"));
    assert_eq!(
        &request_bytes[..59],
        &[
            1, 0, 2, 0, 48, 0, 1, 0, 104, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 48, 0, 0, 0, 3, 0, 0, 0,
            51, 0, 0, 0, 7, 0, 0, 0, 58, 0, 0, 0, 1, 0, 0, 0, 59, 0, 0, 0, b'n', b'e', b't', b'e',
            b'p', b'o', b'c', b'h', b'/', b'1', 0xaa,
        ]
    );
    assert!(request_bytes[59..].iter().all(|byte| *byte == 0));
    assert_eq!(
        decode_selectable_message_kind(&request_bytes).map(|kind| kind.wire_value()),
        Ok(SELECTABLE_MESSAGE_KIND_REQUEST)
    );

    let reply = SelectionReply::selected(
        9,
        [1; SELECTABLE_DIGEST_BYTES],
        [2; SELECTABLE_DIGEST_BYTES],
        vec![3, 4],
    )
    .unwrap_or_else(|error| panic!("selection reply vector must build: {error}"));
    let reply_bytes = reply
        .encode()
        .unwrap_or_else(|error| panic!("selection reply vector must encode: {error}"));
    assert_eq!(
        &reply_bytes[..24],
        &[
            1, 0, 3, 0, 96, 0, 0, 0, 98, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ]
    );
    assert_eq!(&reply_bytes[24..56], &[1; SELECTABLE_DIGEST_BYTES]);
    assert_eq!(&reply_bytes[56..88], &[2; SELECTABLE_DIGEST_BYTES]);
    assert_eq!(&reply_bytes[88..], &[96, 0, 0, 0, 2, 0, 0, 0, 3, 4]);
    assert_eq!(
        decode_selectable_message_kind(&reply_bytes).map(|kind| kind.wire_value()),
        Ok(SELECTABLE_MESSAGE_KIND_REPLY)
    );
}

#[test]
fn guest_selectable_v1_schemas_are_registered_exactly() {
    let registry = include_str!("../../../docs/rfcs/0016-crucible-campaigns/schema-registry.tsv");
    for schema in [
        "crucible.guest-selectable.register",
        "crucible.guest-selectable.request",
        "crucible.guest-selectable.reply",
    ] {
        let expected = format!(
            "{schema}\t1\tcrucible-protocol::selectable\tprocess-protocol-message\tgate:typed-choice,gate:abi-conformance"
        );
        assert!(
            registry.lines().any(|line| line == expected),
            "missing exact selectable schema row {schema}"
        );
    }
    let catalog_plan = "crucible.guest-selectable.catalog-plan\t1\tcrucible-protocol::selectable_catalog_plan\tprocess-protocol-message\tgate:typed-choice,gate:abi-conformance";
    assert!(
        registry.lines().any(|line| line == catalog_plan),
        "missing exact selectable catalog-plan schema row"
    );
}

#[test]
fn protocol_golden_vector_versions_are_explicit() {
    assert_abi_version_field();
}

fn assert_abi_version_field() {
    assert_eq!(GOLDEN_VECTOR_PROTOCOL_VERSION, CONTROL_PROTOCOL_VERSION);
    assert!(GOLDEN_VECTOR_REGENERATION_RULE.contains("CONTROL_PROTOCOL_VERSION"));
    for vector in GOLDEN_CONTROL_VECTORS {
        assert_eq!(vector.protocol_version, GOLDEN_VECTOR_PROTOCOL_VERSION);
    }
}

#[test]
fn protocol_golden_vectors_cover_required_control_frames() {
    assert_frozen_golden_vectors();
}

fn assert_frozen_golden_vectors() {
    assert_eq!(
        GOLDEN_CONTROL_VECTORS.map(|vector| vector.name),
        ["hello", "hello-ack", "setup-payload", "setup-ack", "quit"],
    );
    assert_eq!(
        GOLDEN_CONTROL_VECTORS.map(|vector| (vector.direction, vector.tag)),
        [
            (ControlDirection::PluginToHost, ControlTag::Hello),
            (ControlDirection::HostToPlugin, ControlTag::HelloAck),
            (ControlDirection::HostToPlugin, ControlTag::Setup),
            (ControlDirection::PluginToHost, ControlTag::SetupAck),
            (ControlDirection::HostToPlugin, ControlTag::Quit),
        ],
    );
}

#[test]
fn protocol_golden_vectors_match_live_codec_bytes() {
    assert_decode_encode_roundtrip();
}

fn assert_decode_encode_roundtrip() {
    for vector in GOLDEN_CONTROL_VECTORS {
        assert_eq!(encode_vector(vector), vector.frame);
        assert_eq!(decode_vector(vector), vector.message);
    }
}

#[test]
fn protocol_golden_vectors_freeze_literal_frame_bytes() {
    assert_version_bump_regenerates_vectors();
}

fn assert_version_bump_regenerates_vectors() {
    assert_vector_bytes("hello", &[0, 0, 0, 9, 0xF0, 0, 0, 0, 2, 0, 0, 0, 1]);
    assert_vector_bytes(
        "hello-ack",
        &[
            0, 0, 0, 17, 0xF1, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 7, 0, 0, 0, 32,
        ],
    );
    assert_vector_bytes(
        "setup-payload",
        &[0, 0, 0, 9, 0x01, 0, 0, 0, 0, 0, 6, 0xE0, 0],
    );
    assert_vector_bytes("setup-ack", &[0, 0, 0, 2, 0x02, 0]);
    assert_vector_bytes("quit", &[0, 0, 0, 1, 0x12]);
}

#[test]
fn protocol_doorbell_frame_golden_vectors_match_live_codec_bytes() {
    assert_doorbell_frame_golden_vectors();
}

fn assert_doorbell_frame_golden_vectors() {
    assert!(
        WHITEBOX_DOORBELL_FRAME_REGENERATION_RULE.contains("WHITEBOX_DOORBELL_PROTOCOL_VERSION")
    );
    assert_eq!(
        GOLDEN_WHITEBOX_DOORBELL_FRAME_VECTORS.map(|vector| vector.name),
        ["marker-kind-1-empty", "random-request-kind-5"],
    );
    for vector in GOLDEN_WHITEBOX_DOORBELL_FRAME_VECTORS {
        assert_eq!(vector.protocol_version, WHITEBOX_DOORBELL_PROTOCOL_VERSION);
        assert_eq!(
            encode_whitebox_doorbell_frame(vector.kind, vector.payload),
            Ok(vector.frame.to_vec()),
        );
        let decoded = match WhiteboxDoorbellFrame::decode(vector.frame) {
            Ok(frame) => frame,
            Err(error) => panic!("doorbell golden vector should decode: {error}"),
        };
        assert_eq!(decoded.kind(), vector.kind);
        assert_eq!(decoded.payload(), vector.payload);
    }
    assert_doorbell_vector_bytes(
        "marker-kind-1-empty",
        &[0x43, 0x52, 0x42, 0x4c, 3, 0, 1, 0, 0, 0, 0, 0],
    );
    assert_doorbell_vector_bytes(
        "random-request-kind-5",
        &[
            0x43, 0x52, 0x42, 0x4c, 3, 0, 5, 0, 10, 0, 0, 0, 0x04, 0x03, 0x02, 0x01, 4, 3, 0, 0x72,
            0x6e, 0x67,
        ],
    );
}

#[test]
fn protocol_doorbell_marker_payload_golden_vectors_match_live_codec_bytes() {
    assert_doorbell_marker_payload_golden_vectors();
}

fn assert_doorbell_marker_payload_golden_vectors() {
    assert_eq!(
        GOLDEN_WHITEBOX_MARKER_PAYLOAD_VECTORS.map(|vector| vector.name),
        [
            "assert-always",
            "lifecycle-setup-complete",
            "event-note",
            "coverage-hot-path",
            "random-request",
            "measurement-begin",
            "metric-sample",
            "measurement-end",
            "semantic-marker",
        ],
    );
    for vector in GOLDEN_WHITEBOX_MARKER_PAYLOAD_VECTORS {
        assert_eq!(vector.protocol_version, WHITEBOX_DOORBELL_PROTOCOL_VERSION);
        let frame = match WhiteboxDoorbellFrame::decode(vector.frame) {
            Ok(frame) => frame,
            Err(error) => panic!("marker golden vector should decode as doorbell frame: {error}"),
        };
        assert_eq!(frame.kind(), vector.kind);
        assert_eq!(frame.payload(), vector.payload);
        let payload = match decode_whitebox_marker_payload(&frame) {
            Ok(payload) => payload,
            Err(error) => panic!("marker golden vector should decode as marker payload: {error}"),
        };
        assert_eq!(
            encode_whitebox_marker_frame(&payload),
            Ok(vector.frame.to_vec()),
        );
    }
    let unknown = match WhiteboxDoorbellFrame::new(0xffff, &[]) {
        Ok(frame) => frame,
        Err(error) => panic!("unknown-kind frame should build for decoder test: {error}"),
    };
    assert_eq!(
        decode_whitebox_marker_payload(&unknown),
        Err(WhiteboxMarkerPayloadDecodeError::UnknownKind { kind: 0xffff }),
    );
}

#[test]
fn protocol_doorbell_marker_kind_vocabulary_is_closed_and_versioned() {
    assert_doorbell_marker_kind_vocabulary();
}

#[test]
fn protocol_v3_rejects_the_pre_measurement_v2_doorbell_frame() {
    let frame = doorbell_frame_with_custom_header(WHITEBOX_DOORBELL_FRAME_MAGIC, 2, 1, 0, &[]);
    assert_eq!(
        WhiteboxDoorbellFrame::decode_bounded(&frame, WHITEBOX_MARKER_BODY_MAX_BYTES),
        Err(WhiteboxDoorbellFrameDecodeError::UnsupportedVersion {
            expected: WHITEBOX_DOORBELL_PROTOCOL_VERSION,
            actual: 2,
        })
    );
}

fn assert_doorbell_marker_kind_vocabulary() {
    assert_eq!(
        WhiteboxDoorbellMarkerKind::ALL.map(|kind| (kind.wire_value(), kind.semantic_label())),
        [
            (1, "guest_assertion_marker"),
            (2, "guest_lifecycle_marker"),
            (3, "guest_event_marker"),
            (4, "guest_coverage_marker"),
            (5, "app_random_request"),
            (6, "guest_measurement_begin"),
            (7, "guest_metric_sample"),
            (8, "guest_measurement_end"),
            (9, "guest_semantic_marker"),
        ],
    );
    assert_eq!(
        WhiteboxDoorbellMarkerKind::ALL.len(),
        WHITEBOX_DOORBELL_MARKER_KIND_COUNT,
    );
    for kind in WhiteboxDoorbellMarkerKind::ALL {
        assert_eq!(
            WhiteboxDoorbellMarkerKind::from_wire_value(kind.wire_value()),
            Some(kind),
        );
    }
    assert_eq!(WhiteboxDoorbellMarkerKind::from_wire_value(10), None);
    assert!(WhiteboxDoorbellMarkerKind::Assertion.is_observational());
    assert!(!WhiteboxDoorbellMarkerKind::RandomRequest.is_observational());

    assert_eq!(
        WhiteboxMeasurementValueKind::ALL.map(WhiteboxMeasurementValueKind::wire_value),
        [0, 1, 2, 3, 4, 5, 6],
    );
    assert_eq!(
        WhiteboxMeasurementValueKind::ALL.len(),
        WHITEBOX_MEASUREMENT_VALUE_KIND_COUNT,
    );
    for kind in WhiteboxMeasurementValueKind::ALL {
        assert_eq!(
            WhiteboxMeasurementValueKind::from_wire_value(kind.wire_value()),
            Some(kind),
        );
    }
    assert_eq!(WhiteboxMeasurementValueKind::from_wire_value(7), None);
}

#[test]
fn protocol_doorbell_marker_subvocabularies_are_closed_and_versioned() {
    assert_doorbell_marker_subvocabularies();
}

fn assert_doorbell_marker_subvocabularies() {
    assert_eq!(
        WhiteboxAssertionMarkerFlavor::ALL
            .map(|flavor| { (flavor.wire_value(), flavor.semantic_label()) }),
        [
            (0, "always"),
            (1, "sometimes"),
            (2, "reachable"),
            (3, "unreachable"),
        ],
    );
    assert_eq!(
        WhiteboxAssertionMarkerFlavor::ALL.len(),
        WHITEBOX_DOORBELL_ASSERTION_FLAVOR_COUNT,
    );
    for flavor in WhiteboxAssertionMarkerFlavor::ALL {
        assert_eq!(
            WhiteboxAssertionMarkerFlavor::from_wire_value(flavor.wire_value()),
            Some(flavor),
        );
    }
    assert_eq!(WhiteboxAssertionMarkerFlavor::from_wire_value(4), None);

    assert_eq!(
        WhiteboxLifecycleMarkerEvent::ALL
            .map(|event| { (event.wire_value(), event.semantic_label()) }),
        [(1, "setup_complete"), (2, "test_done")],
    );
    assert_eq!(
        WhiteboxLifecycleMarkerEvent::ALL.len(),
        WHITEBOX_DOORBELL_LIFECYCLE_EVENT_COUNT,
    );
    for event in WhiteboxLifecycleMarkerEvent::ALL {
        assert_eq!(
            WhiteboxLifecycleMarkerEvent::from_wire_value(event.wire_value()),
            Some(event),
        );
    }
    assert_eq!(WhiteboxLifecycleMarkerEvent::from_wire_value(3), None);
}

#[test]
fn measurement_marker_codec_rejects_noncanonical_and_oversized_values() {
    let invalid_identifier =
        WhiteboxDoorbellFrame::new(WHITEBOX_DOORBELL_KIND_METRIC_SAMPLE, &[0, 0])
            .unwrap_or_else(|error| panic!("invalid identifier frame should build: {error}"));
    assert!(matches!(
        decode_whitebox_marker_payload(&invalid_identifier),
        Err(WhiteboxMarkerPayloadDecodeError::InvalidMeasurementIdentifier { .. })
    ));

    let unknown_value = WhiteboxDoorbellFrame::new(
        WHITEBOX_DOORBELL_KIND_METRIC_SAMPLE,
        &[1, 0, b'm', 1, 0, b'i', 1, 0, b'x', 7],
    )
    .unwrap_or_else(|error| panic!("unknown value frame should build: {error}"));
    assert_eq!(
        decode_whitebox_marker_payload(&unknown_value),
        Err(WhiteboxMarkerPayloadDecodeError::InvalidMeasurementValueKind { tag: 7 })
    );

    let oversized_vector = WhiteboxMarkerPayload::MetricSample(WhiteboxMetricSampleBody {
        measurement: String::from("m"),
        instance: String::from("i"),
        metric: String::from("x"),
        value: WhiteboxMeasurementValue::UnsignedVector(vec![
            0;
            WHITEBOX_MEASUREMENT_VECTOR_MAX_ELEMENTS
                + 1
        ]),
    });
    assert!(matches!(
        encode_whitebox_marker_payload_body(&oversized_vector),
        Err(WhiteboxMarkerPayloadEncodeError::MeasurementVectorTooLong { .. })
    ));

    let duplicate_details = WhiteboxDoorbellFrame::new(
        WHITEBOX_DOORBELL_KIND_SEMANTIC_MARKER,
        &[
            1, 0, b'm', 1, 0, b'i', 2, 0, 1, 0, b'a', 3, 1, 1, 0, b'a', 3, 0,
        ],
    )
    .unwrap_or_else(|error| panic!("duplicate detail frame should build: {error}"));
    assert!(matches!(
        decode_whitebox_marker_payload(&duplicate_details),
        Err(WhiteboxMarkerPayloadDecodeError::NonCanonicalDetailOrder { .. })
    ));

    let oversized_body = WhiteboxMarkerPayload::SemanticMarker(WhiteboxSemanticMarkerBody {
        marker: String::from("m"),
        instance: String::from("i"),
        details: vec![
            WhiteboxSemanticMarkerDetail {
                key: String::from("a"),
                value: WhiteboxMeasurementValue::UnsignedVector(vec![
                    0;
                    WHITEBOX_MEASUREMENT_VECTOR_MAX_ELEMENTS
                ]),
            },
            WhiteboxSemanticMarkerDetail {
                key: String::from("b"),
                value: WhiteboxMeasurementValue::UnsignedVector(vec![
                    0;
                    WHITEBOX_MEASUREMENT_VECTOR_MAX_ELEMENTS
                ]),
            },
        ],
    });
    assert!(matches!(
        encode_whitebox_marker_payload_body(&oversized_body),
        Err(WhiteboxMarkerPayloadEncodeError::FramePayloadTooLarge {
            max_len: WHITEBOX_MARKER_BODY_MAX_BYTES,
            ..
        })
    ));

    let oversized_decode = WhiteboxDoorbellFrame::new(
        WHITEBOX_DOORBELL_KIND_SEMANTIC_MARKER,
        &vec![0; WHITEBOX_MARKER_BODY_MAX_BYTES + 1],
    )
    .unwrap_or_else(|error| {
        panic!("oversized marker body should reach the marker decoder: {error}")
    });
    assert!(matches!(
        decode_whitebox_marker_payload(&oversized_decode),
        Err(WhiteboxMarkerPayloadDecodeError::BodyTooLarge {
            max_len: WHITEBOX_MARKER_BODY_MAX_BYTES,
            ..
        })
    ));
}

#[test]
fn protocol_doorbell_decoder_fuzz_corpus_is_clean_and_bounded() {
    assert_doorbell_decoder_fuzz_corpus();
}

fn assert_doorbell_decoder_fuzz_corpus() {
    let cases = doorbell_fuzz_corpus();
    assert!(
        cases.len() >= 8,
        "doorbell fuzz corpus must cover malformed and adversarial frame shapes"
    );

    for case in cases {
        let first = assert_doorbell_decode_does_not_panic(case.name, &case.frame, 8);
        let second = WhiteboxDoorbellFrame::decode_bounded(&case.frame, 8);
        assert_eq!(first, second, "doorbell fuzz case `{}` drifted", case.name);
        if case.name != "well-formed-empty-assertion" {
            assert!(
                first.is_err(),
                "doorbell fuzz case `{}` must exercise a typed rejection",
                case.name
            );
        }
    }

    let unknown_kind =
        match WhiteboxDoorbellFrame::decode_bounded(&doorbell_frame_with_header(0xffff, &[]), 8) {
            Ok(frame) => frame,
            Err(error) => panic!("unknown-kind doorbell frame header should decode: {error}"),
        };
    assert_eq!(
        decode_whitebox_marker_payload(&unknown_kind),
        Err(WhiteboxMarkerPayloadDecodeError::UnknownKind { kind: 0xffff })
    );
}

fn assert_doorbell_decode_does_not_panic(
    name: &str,
    frame: &[u8],
    max_payload_len: usize,
) -> Result<WhiteboxDoorbellFrame, WhiteboxDoorbellFrameDecodeError> {
    match catch_unwind(AssertUnwindSafe(|| {
        WhiteboxDoorbellFrame::decode_bounded(frame, max_payload_len)
    })) {
        Ok(result) => result,
        Err(_) => panic!("doorbell decoder fuzz case `{name}` panicked for frame {frame:?}"),
    }
}

struct DoorbellFuzzCase {
    name: &'static str,
    frame: Vec<u8>,
}

fn doorbell_fuzz_corpus() -> Vec<DoorbellFuzzCase> {
    vec![
        DoorbellFuzzCase {
            name: "empty",
            frame: Vec::new(),
        },
        DoorbellFuzzCase {
            name: "truncated-header",
            frame: vec![0x43, 0x52, 0x42],
        },
        DoorbellFuzzCase {
            name: "bad-magic",
            frame: doorbell_frame_with_custom_header(
                0,
                WHITEBOX_DOORBELL_PROTOCOL_VERSION,
                1,
                0,
                &[],
            ),
        },
        DoorbellFuzzCase {
            name: "bad-version",
            frame: doorbell_frame_with_custom_header(
                WHITEBOX_DOORBELL_FRAME_MAGIC,
                WHITEBOX_DOORBELL_PROTOCOL_VERSION.wrapping_add(1),
                1,
                0,
                &[],
            ),
        },
        DoorbellFuzzCase {
            name: "declared-length-exceeds-bound",
            frame: doorbell_frame_with_custom_header(
                WHITEBOX_DOORBELL_FRAME_MAGIC,
                WHITEBOX_DOORBELL_PROTOCOL_VERSION,
                1,
                9,
                &[],
            ),
        },
        DoorbellFuzzCase {
            name: "declared-length-short",
            frame: doorbell_frame_with_custom_header(
                WHITEBOX_DOORBELL_FRAME_MAGIC,
                WHITEBOX_DOORBELL_PROTOCOL_VERSION,
                1,
                4,
                &[0xa5],
            ),
        },
        DoorbellFuzzCase {
            name: "declared-length-trailing",
            frame: doorbell_frame_with_custom_header(
                WHITEBOX_DOORBELL_FRAME_MAGIC,
                WHITEBOX_DOORBELL_PROTOCOL_VERSION,
                1,
                0,
                &[0xa5],
            ),
        },
        DoorbellFuzzCase {
            name: "well-formed-empty-assertion",
            frame: doorbell_frame_with_header(1, &[]),
        },
    ]
}

#[test]
fn protocol_codec_fuzz_regression_corpus_is_clean_and_deterministic() {
    assert_structure_aware_fuzz_corpus();
    assert_protocol_codec_fuzz_corpus();
}

fn assert_structure_aware_fuzz_corpus() {
    for case in regression_corpus() {
        let outcome = assert_clean_reject_or_deterministic_decode(case.frame);
        match case.name {
            "well-formed-host-frame-in-plugin-decoder"
            | "well-formed-plugin-frame-in-host-decoder" => {
                assert!(outcome.tag.is_ok());
            }
            _ => {
                assert!(
                    outcome.plugin.is_err() || outcome.host.is_err() || outcome.tag.is_err(),
                    "adversarial corpus case `{}` must exercise a typed rejection",
                    case.name
                );
            }
        }
    }
}

fn assert_protocol_codec_fuzz_corpus() {
    let names = regression_corpus()
        .iter()
        .map(|case| case.name)
        .collect::<BTreeSet<_>>();
    for required in [
        "empty",
        "truncated-length-one-byte",
        "oversize-length",
        "unknown-tag",
        "hello-short-payload",
        "setup-ack-truncated-payload",
        "well-formed-host-frame-in-plugin-decoder",
    ] {
        assert!(
            names.contains(required),
            "protocol fuzz corpus missing `{required}`"
        );
    }
}

fn assert_clean_reject_or_deterministic_decode(frame: &[u8]) -> ControlCodecFuzzOutcome {
    let first = match catch_unwind(AssertUnwindSafe(|| run_control_codec_fuzz_target(frame))) {
        Ok(outcome) => outcome,
        Err(_) => panic!("protocol codec fuzz target panicked for frame {frame:?}"),
    };
    let second = run_control_codec_fuzz_target(frame);
    assert_eq!(first, second);
    first
}

fn regression_corpus() -> &'static [ControlCodecFuzzCase] {
    &CODEC_FUZZ_REGRESSION_CORPUS
}

fn encode_vector(vector: ControlGoldenVector) -> Vec<u8> {
    match vector.message {
        ControlGoldenVectorMessage::Hello {
            proto_version,
            abi_version,
        } => control_encode_plugin_msg(&PluginMsg::Hello {
            proto_version,
            abi_version,
        }),
        ControlGoldenVectorMessage::SetupAck { status } => {
            control_encode_plugin_msg(&PluginMsg::SetupAck { status })
        }
        ControlGoldenVectorMessage::HelloAck {
            proto_version,
            abi_version,
            slot_index,
            node_count,
        } => control_encode_host_msg(&HostMsg::HelloAck {
            proto_version,
            abi_version,
            slot_index,
            node_count,
        }),
        ControlGoldenVectorMessage::SetupPayload { region_len } => {
            control_encode_host_msg(&HostMsg::Setup { region_len })
        }
        ControlGoldenVectorMessage::Quit => control_encode_host_msg(&HostMsg::Quit),
    }
}

fn decode_vector(vector: ControlGoldenVector) -> ControlGoldenVectorMessage {
    match vector.direction {
        ControlDirection::PluginToHost => match control_decode_plugin_msg(vector.frame) {
            Ok(PluginMsg::Hello {
                proto_version,
                abi_version,
            }) => ControlGoldenVectorMessage::Hello {
                proto_version,
                abi_version,
            },
            Ok(PluginMsg::SetupAck { status }) => ControlGoldenVectorMessage::SetupAck { status },
            Err(error) => panic!("plugin golden vector should decode: {error}"),
        },
        ControlDirection::HostToPlugin => match control_decode_host_msg(vector.frame) {
            Ok(HostMsg::HelloAck {
                proto_version,
                abi_version,
                slot_index,
                node_count,
            }) => ControlGoldenVectorMessage::HelloAck {
                proto_version,
                abi_version,
                slot_index,
                node_count,
            },
            Ok(HostMsg::Setup { region_len }) => {
                ControlGoldenVectorMessage::SetupPayload { region_len }
            }
            Ok(HostMsg::Quit) => ControlGoldenVectorMessage::Quit,
            Err(error) => panic!("host golden vector should decode: {error}"),
        },
    }
}

fn assert_vector_bytes(name: &str, expected: &[u8]) {
    let vector = vector_by_name(name);
    assert_eq!(vector.frame, expected);
}

fn vector_by_name(name: &str) -> ControlGoldenVector {
    for vector in GOLDEN_CONTROL_VECTORS {
        if vector.name == name {
            return vector;
        }
    }
    panic!("missing protocol golden vector {name}");
}

fn assert_doorbell_vector_bytes(name: &str, expected: &[u8]) {
    for vector in GOLDEN_WHITEBOX_DOORBELL_FRAME_VECTORS {
        if vector.name == name {
            assert_eq!(vector.frame, expected);
            return;
        }
    }
    panic!("missing doorbell frame golden vector {name}");
}

fn doorbell_frame_with_header(kind: u16, body: &[u8]) -> Vec<u8> {
    doorbell_frame_with_custom_header(
        WHITEBOX_DOORBELL_FRAME_MAGIC,
        WHITEBOX_DOORBELL_PROTOCOL_VERSION,
        kind,
        body.len() as u32,
        body,
    )
}

fn doorbell_frame_with_custom_header(
    magic: u32,
    version: u16,
    kind: u16,
    declared_len: u32,
    body: &[u8],
) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&magic.to_le_bytes());
    frame.extend_from_slice(&version.to_le_bytes());
    frame.extend_from_slice(&kind.to_le_bytes());
    frame.extend_from_slice(&declared_len.to_le_bytes());
    frame.extend_from_slice(body);
    frame
}

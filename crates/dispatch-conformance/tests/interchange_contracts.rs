//! Independent exact JSON and language-neutral framed-message vectors.

#![allow(clippy::expect_used)]

use std::io::Cursor;

use dispatch_model::{Quantity, Rational};
use dispatch_protocol::{
    WORKER_VERSION, framing,
    json::{self, JsonLimits},
    wire,
};

#[test]
fn quantities_round_trip_at_integer_boundaries_and_reject_other_representations() {
    for decimal in ["0", "1", "9007199254740993", "18446744073709551615"] {
        let input = format!("\"{decimal}\"");
        let decoded: Quantity =
            json::from_slice(input.as_bytes(), JsonLimits::default()).expect("canonical quantity");
        assert_eq!(
            json::to_vec(&decoded).expect("quantity export"),
            input.as_bytes()
        );
    }
    for input in [
        "0",
        "1",
        "9007199254740993",
        "1.0",
        "1e3",
        "null",
        "\"\"",
        "\"01\"",
        "\"+1\"",
        "\"-1\"",
        "\" 1\"",
        "\"1.0\"",
        "\"1e3\"",
        "\"18446744073709551616\"",
    ] {
        assert!(
            json::from_slice::<Quantity>(input.as_bytes(), JsonLimits::default()).is_err(),
            "accepted {input}"
        );
    }
}

#[test]
fn exact_rationals_reject_ambiguous_records() {
    let input = br#"{"numerator":"-9007199254740993","denominator":"7"}"#;
    let decoded: Rational =
        json::from_slice(input, JsonLimits::default()).expect("exact signed rational");
    assert_eq!(decoded.numerator().to_string(), "-9007199254740993");
    assert_eq!(decoded.denominator().to_string(), "7");

    for input in [
        r#"{"numerator":1,"denominator":"2"}"#,
        r#"{"numerator":"1","denominator":"0"}"#,
        r#"{"numerator":"1","denominator":"-2"}"#,
        r#"{"numerator":"1","denominator":"02"}"#,
        r#"{"numerator":"-0","denominator":"1"}"#,
        r#"{"numerator":"1","denominator":"2","extra":true}"#,
        r#"{"numerator":"1","numerator":"2","denominator":"3"}"#,
        r#"{"numerator":"1","\u006eumerator":"2","denominator":"3"}"#,
    ] {
        assert!(
            json::from_slice::<Rational>(input.as_bytes(), JsonLimits::default()).is_err(),
            "accepted {input}"
        );
    }
}

#[test]
fn json_limits_apply_before_typed_model_construction() {
    let base = JsonLimits::default();
    assert!(
        json::from_slice::<serde_json::Value>(
            b"[[]]",
            JsonLimits {
                max_nesting: 1,
                ..base
            }
        )
        .is_err()
    );
    assert!(
        json::from_slice::<serde_json::Value>(
            b"[0,1]",
            JsonLimits {
                max_values: 2,
                ..base
            }
        )
        .is_err()
    );
    assert!(
        json::from_slice::<serde_json::Value>(
            br#"{"long_key":"1"}"#,
            JsonLimits {
                max_string_bytes: 3,
                ..base
            }
        )
        .is_err()
    );
    assert!(
        json::from_slice::<serde_json::Value>(
            b"[0]",
            JsonLimits {
                max_decoded_bytes: 1,
                ..base
            }
        )
        .is_err()
    );
    assert!(
        json::from_slice::<serde_json::Value>(
            b"[0]",
            JsonLimits {
                max_bytes: 2,
                ..base
            }
        )
        .is_err()
    );
    assert!(json::from_slice::<serde_json::Value>(b"{}{}", base).is_err());
    assert!(
        json::from_slice::<dispatch_model::Problem>(br#"{"model_version":"1","unknown":0}"#, base)
            .is_err()
    );
}

#[test]
fn protobuf_hello_matches_an_independently_authored_golden_frame() {
    let envelope = wire::WorkerEnvelope {
        protocol_version: Some(WORKER_VERSION),
        session_generation: 1,
        worker_generation: 2,
        request_id: 3,
        body: Some(wire::worker_envelope::Body::Hello(wire::Hello::default())),
    };
    // Field tags and lengths are authored from the published wire format,
    // without deriving the expected bytes through the production encoder.
    let golden = hex::decode("0000000c0a0208011001180220035200").expect("literal frame");
    assert_eq!(
        framing::encode_frame(&envelope, 1024).expect("encoded hello"),
        golden
    );
    assert_eq!(
        framing::decode_frame(&golden, 1024).expect("decoded golden"),
        envelope
    );
}

#[test]
fn malformed_frames_reject_truncation_duplicates_unknowns_and_trailing_bytes() {
    let golden = hex::decode("0000000c0a0208011001180220035200").expect("literal frame");
    for removed in 1..golden.len() {
        assert!(framing::decode_frame(&golden[..removed], 1024).is_err());
    }
    let mut trailing = golden.clone();
    trailing.push(0);
    assert!(framing::decode_frame(&trailing, 1024).is_err());

    for extra in [&[0x10, 0x01][..], &[0xf8, 0x07, 0x01][..]] {
        let mut modified = golden.clone();
        modified.extend_from_slice(extra);
        let length = u32::try_from(modified.len() - 4).expect("small frame");
        modified[..4].copy_from_slice(&length.to_be_bytes());
        assert!(framing::decode_frame(&modified, 1024).is_err());
    }
    let mut oversized = Cursor::new(u32::MAX.to_be_bytes());
    assert!(framing::read_frame(&mut oversized, 1024).is_err());
    assert_eq!(oversized.position(), 4);
    assert!(framing::decode_frame(&[0, 0, 0, 0], 1024).is_err());
}

#[test]
fn canonical_model_commitment_matches_a_language_neutral_golden_vector() {
    let mut problem = dispatch_model::Problem {
        model_version: 1,
        ..Default::default()
    };
    problem.dimensions.insert(
        "d".into(),
        dispatch_model::Dimension {
            unit: "u".into(),
            quantum: Quantity::new(24),
        },
    );
    let validated = dispatch_model::validate(problem).expect("valid dimension-only model");
    // Thirteen local record keys, empty entry arrays, and one dimension record:
    // key 5 holds [["d", {1: "u", 2: 24}]]. The quantity uses CBOR uint8.
    let golden =
        hex::decode("ad01010280038004800581826164a201617502181806800780088009800a800b800c800d80")
            .expect("literal CBOR vector");
    assert_eq!(
        dispatch_protocol::canonical::model_bytes(&validated).expect("canonical model"),
        golden
    );
    let digest = dispatch_protocol::canonical::model_digest(&validated).expect("model commitment");
    assert_eq!(
        hex::encode(digest),
        "ac5ecc8014b49dc79bfa1ec94fde11b78d750e334bae503cee3f9df05f10e4e7"
    );
}

#[test]
fn model_identity_excludes_hints_but_request_identity_includes_effective_options() {
    let validated = dispatch_model::validate(dispatch_model::Problem {
        model_version: 1,
        ..Default::default()
    })
    .expect("valid empty model");
    let options = wire::SolveOptions {
        mode: wire::SearchMode::LocalSearch as i32,
        wall_time_millis: 1000,
        threads: 1,
        ..Default::default()
    };
    let no_hint = dispatch_protocol::canonical::request_digest(&validated, &options, None)
        .expect("request without hint");
    let empty_hint = dispatch_protocol::canonical::request_digest(
        &validated,
        &options,
        Some(&dispatch_model::Assignment::default()),
    )
    .expect("explicit empty hint");
    assert_ne!(no_hint, empty_hint);
    for changed in [
        wire::SolveOptions {
            wall_time_millis: 999,
            ..options.clone()
        },
        wire::SolveOptions {
            threads: 2,
            ..options.clone()
        },
        wire::SolveOptions {
            seed: Some(0),
            ..options.clone()
        },
    ] {
        assert_ne!(
            no_hint,
            dispatch_protocol::canonical::request_digest(&validated, &changed, None)
                .expect("changed effective policy")
        );
    }
    let other_backend = dispatch_protocol::canonical::request_digest_for_backend(
        &validated,
        "different",
        &options,
        None,
    )
    .expect("backend binding");
    assert_ne!(no_hint, other_backend);
}

#[test]
fn rational_objective_and_effective_request_have_portable_golden_commitments() {
    let mut problem = dispatch_model::Problem {
        model_version: 1,
        ..Default::default()
    };
    problem.objectives.push(dispatch_model::ObjectiveTier {
        id: "t".into(),
        terms: vec![dispatch_model::ObjectiveTerm {
            id: "x".into(),
            direction: dispatch_model::Direction::Minimize,
            weight: Rational::new(1.into(), 3.into()).expect("exact third"),
            normalizer: Rational::one(),
            metric: dispatch_model::Metric::AdmittedCount { items: Vec::new() },
        }],
    });
    let validated = dispatch_model::validate(problem).expect("portable rational objective model");
    let golden = hex::decode("ad0101028003800480058006800780088009800a800b800c800d81a20161740281a501617802686d696e696d697a6503826131613304826131613105a2016e61646d69747465645f636f756e740280").expect("literal CBOR objective record");
    assert_eq!(
        dispatch_protocol::canonical::model_bytes(&validated).expect("canonical objective"),
        golden
    );
    assert_eq!(
        hex::encode(dispatch_protocol::canonical::model_digest(&validated).expect("model digest")),
        "04912834757caecc987d81778c4e5bd2fba67f3bf0f30ec4bc2e8bfa7ca3a41b"
    );
    let options = wire::SolveOptions {
        mode: wire::SearchMode::LocalSearch as i32,
        wall_time_millis: 1000,
        threads: 1,
        ..Default::default()
    };
    assert_eq!(
        hex::encode(
            dispatch_protocol::canonical::request_digest(&validated, &options, None)
                .expect("request digest")
        ),
        "8979da65a667839006701143ed8824940f2305e4a91219e3faef38f427da4089"
    );
}

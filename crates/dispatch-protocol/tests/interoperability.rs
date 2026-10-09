//! Public golden octets and malformed transports exercise cross-language contracts.

#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;

use dispatch_model::{validate, Problem, Target};
use dispatch_protocol::{canonical, framing, json, wire, INITIAL_MAX_FRAME_BYTES};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Vectors {
    version: String,
    empty_model: Problem,
    empty_model_cbor_hex: String,
    empty_model_sha256_hex: String,
    hello_frame_hex: String,
    hello_session_generation: String,
    hello_worker_generation: String,
    hello_request_id: String,
}

fn vectors() -> Vectors {
    json::from_slice(
        include_bytes!("fixtures/vectors.json"),
        json::JsonLimits::default(),
    )
    .unwrap()
}

fn unhex(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0);
    hex.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let digits = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(digits, 16).unwrap()
        })
        .collect()
}

#[test]
fn published_model_vector_has_exact_cbor_and_domain_separated_digest() {
    let vectors = vectors();
    assert_eq!(vectors.version, "1");
    let problem = validate(vectors.empty_model).unwrap();

    assert_eq!(
        canonical::model_bytes(&problem).unwrap(),
        unhex(&vectors.empty_model_cbor_hex)
    );
    assert_eq!(
        canonical::model_digest(&problem).unwrap().as_slice(),
        unhex(&vectors.empty_model_sha256_hex)
    );
}

#[test]
fn published_protobuf_vector_reencodes_without_unknown_fields() {
    let vectors = vectors();
    let bytes = unhex(&vectors.hello_frame_hex);
    let message = framing::decode_frame(&bytes, INITIAL_MAX_FRAME_BYTES).unwrap();

    assert_eq!(
        message.session_generation.to_string(),
        vectors.hello_session_generation
    );
    assert_eq!(
        message.worker_generation.to_string(),
        vectors.hello_worker_generation
    );
    assert_eq!(message.request_id.to_string(), vectors.hello_request_id);
    assert!(matches!(
        message.body,
        Some(wire::worker_envelope::Body::Hello(_))
    ));
    assert_eq!(
        framing::encode_frame(&message, INITIAL_MAX_FRAME_BYTES).unwrap(),
        bytes
    );
}

#[test]
fn set_order_preserves_identity_while_observation_changes_do_not() {
    let mut original = vectors().empty_model;
    for id in ["a", "b"] {
        original.targets.insert(
            id.into(),
            Target {
                capacities: BTreeMap::new(),
                fixed_load: BTreeMap::new(),
            },
        );
    }
    original
        .domains
        .insert("pool".into(), vec!["a".into(), "b".into()]);
    let mut reordered = original.clone();
    reordered.domains.get_mut("pool").unwrap().reverse();
    let original_digest = canonical::model_digest(&validate(original).unwrap()).unwrap();

    assert_eq!(
        original_digest,
        canonical::model_digest(&validate(reordered.clone()).unwrap()).unwrap()
    );
    reordered
        .observation_basis
        .insert("inventory".into(), "next".into());
    assert_ne!(
        original_digest,
        canonical::model_digest(&validate(reordered).unwrap()).unwrap()
    );
}

#[test]
fn every_truncated_golden_frame_and_boundary_length_is_rejected() {
    let bytes = unhex(&vectors().hello_frame_hex);
    for end in 0..bytes.len() {
        assert!(
            framing::decode_frame(&bytes[..end], INITIAL_MAX_FRAME_BYTES).is_err(),
            "accepted truncation at {end}"
        );
    }
    for length in [0, INITIAL_MAX_FRAME_BYTES + 1, u32::MAX] {
        assert!(framing::decode_frame(&length.to_be_bytes(), INITIAL_MAX_FRAME_BYTES).is_err());
    }
}

#[test]
fn unknown_semantic_tags_and_mutated_lengths_cannot_be_dropped() {
    let mut bytes = unhex(&vectors().hello_frame_hex);
    bytes.extend_from_slice(&[0xf8, 0x07, 0x01]);
    let length = (bytes.len() - 4) as u32;
    bytes[..4].copy_from_slice(&length.to_be_bytes());
    assert!(framing::decode_frame(&bytes, INITIAL_MAX_FRAME_BYTES).is_err());

    let mut bytes = unhex(&vectors().hello_frame_hex);
    bytes[5] = 0x7f;
    assert!(framing::decode_frame(&bytes, INITIAL_MAX_FRAME_BYTES).is_err());
}

#[test]
fn deterministic_malformed_corpus_stays_within_frame_bounds() {
    let mut state = 17_u64;
    for size in 0..128_usize {
        for _ in 0..8 {
            let mut bytes = Vec::with_capacity(size + 4);
            bytes.extend_from_slice(&(size as u32).to_be_bytes());
            for _ in 0..size {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                bytes.push((state >> 32) as u8);
            }
            let _ = framing::decode_frame(&bytes, 128);
        }
    }
}

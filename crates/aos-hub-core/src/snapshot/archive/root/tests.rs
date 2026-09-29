//! External trust, canonical declarations, key-role custody and splice rejection.

use std::io::Cursor;

use rand::rngs::StdRng;
use rand::SeedableRng;
use serde_json::{json, Value};

use super::*;
use crate::auth::seal::{AesGcmSealer, SecretSealer};
use crate::snapshot::archive::{FreshStreamKey, StreamDecoder, StreamEncoder};

struct Fixture {
    signed: SignedDeclaredRoot,
    signer: ArchiveSigningKey,
    wrapping: ArchiveWrappingKeys,
    metadata_bytes: Vec<u8>,
    private_bytes: Vec<u8>,
}

fn signer() -> ArchiveSigningKey {
    ArchiveSigningKey::from_seed("operator-export-v1", [1; 32]).unwrap()
}

fn wrapping() -> ArchiveWrappingKeys {
    ArchiveWrappingKeys::new(
        ArchiveWrappingKey::from_bytes("metadata-wrap-v1", [2; 32]).unwrap(),
        ArchiveWrappingKey::from_bytes("private-wrap-v1", [3; 32]).unwrap(),
    )
    .unwrap()
}

fn trust(signer: &ArchiveSigningKey) -> ArchiveSignerTrust {
    ArchiveSignerTrust::new([(signer.id().to_owned(), signer.public_key())]).unwrap()
}

fn fresh(seed: u64) -> (FreshArchiveId, FreshStreamKey, FreshStreamKey) {
    // Deterministic fixture state is not a production entropy qualification.
    let mut rng = StdRng::seed_from_u64(seed);
    (
        FreshArchiveId::generate(&mut rng).unwrap(),
        FreshStreamKey::generate(&mut rng).unwrap(),
        FreshStreamKey::generate(&mut rng).unwrap(),
    )
}

fn fixture(seed: u64) -> Fixture {
    let signer = signer();
    let wrapping = wrapping();
    let (id, metadata, private) = fresh(seed);
    let prepared = prepare_archive_keys(&id, &signer, &wrapping, &metadata, &private, &[]).unwrap();
    let mut meta = StreamEncoder::new(
        Vec::new(),
        metadata,
        StreamContext::new(id.bytes(), StreamRole::Metadata),
        StreamLimits::default(),
    )
    .unwrap();
    meta.write_plaintext(b"CLASSIFIED-METADATA").unwrap();
    let (metadata_bytes, metadata_summary) = meta.finish().unwrap();
    let mut private = StreamEncoder::new(
        Vec::new(),
        private,
        StreamContext::new(id.bytes(), StreamRole::Private),
        StreamLimits::default(),
    )
    .unwrap();
    private.write_plaintext(b"PRIVATE-EXACT-ORIGINAL").unwrap();
    let (private_bytes, private_summary) = private.finish().unwrap();
    let signed =
        sign_declared_root(prepared, &signer, &metadata_summary, &private_summary).unwrap();
    Fixture {
        signed,
        signer,
        wrapping,
        metadata_bytes,
        private_bytes,
    }
}

fn wire(root: &SignedDeclaredRoot) -> Value {
    serde_json::from_slice(root.as_bytes()).unwrap()
}

fn resign(value: &mut Value, signer: &ArchiveSigningKey, domain: &str) -> Vec<u8> {
    let payload = canonical_bytes(&value["payload"]).unwrap();
    let digest = Sha256Digest::separated(domain, payload);
    let signature = signer.key.sign(digest.as_bytes());
    value["signature_base64url"] = Value::String(URL_SAFE_NO_PAD.encode(signature.to_bytes()));
    canonical_bytes(value).unwrap()
}

fn full_decode(
    root: &VerifiedDeclaredRoot,
    role: StreamRole,
    key: StreamDecryptionKey,
    bytes: &[u8],
) -> StreamSummary {
    let mut decoder = StreamDecoder::new(
        Cursor::new(bytes),
        key,
        root.stream_context(role),
        StreamLimits::default(),
    )
    .unwrap();
    while let Some(chunk) = decoder.next_chunk().unwrap() {
        assert!(!chunk.is_empty());
    }
    decoder.summary().unwrap().clone()
}

#[test]
fn pinned_root_unwraps_reader_keys_and_reconciles_actual_completed_decoders() {
    let f = fixture(1);
    let verified = verify_declared_root(f.signed.as_bytes(), &trust(&f.signer)).unwrap();
    assert_eq!(verified.signer_id(), f.signer.id());
    let keys = verified.unwrap_reader_keys(&f.wrapping, &[]).unwrap();
    let (metadata, private) = keys.into_role_keys();
    for (role, key, bytes) in [
        (StreamRole::Metadata, metadata, &f.metadata_bytes),
        (StreamRole::Private, private, &f.private_bytes),
    ] {
        let observed = full_decode(&verified, role, key, bytes);
        verified
            .reconcile_declared_summary(role, &observed)
            .unwrap();
    }
    let encoded = std::str::from_utf8(f.signed.as_bytes()).unwrap();
    assert!(!encoded.contains("PRIVATE-EXACT"));
    assert_eq!(wire(&f.signed)["payload"]["profile"], "framing_only");
    assert!(wire(&f.signed)["payload"]
        .get("whole_hub_complete")
        .is_none());
    assert!(wire(&f.signed)["payload"]
        .get("activation_authorized")
        .is_none());
}

#[test]
fn declared_authenticity_does_not_attest_actual_bytes_or_summary_provenance() {
    let f = fixture(2);
    let root = verify_declared_root(f.signed.as_bytes(), &trust(&f.signer)).unwrap();
    let keys = root.unwrap_reader_keys(&f.wrapping, &[]).unwrap();
    let (metadata, _) = keys.into_role_keys();
    let mut decoder = StreamDecoder::new(
        Cursor::new(&f.metadata_bytes[..f.metadata_bytes.len() - 1]),
        metadata,
        root.stream_context(StreamRole::Metadata),
        StreamLimits::default(),
    )
    .unwrap();
    decoder.next_chunk().unwrap();
    assert!(decoder.next_chunk().is_err());
    assert!(decoder.summary().is_none());
    let mut different = root.declared_summary(StreamRole::Metadata).clone();
    for changed in [
        &mut different.data_frames,
        &mut different.plaintext_bytes,
        &mut different.ciphertext_bytes,
    ] {
        *changed += 1;
    }
    assert!(root
        .reconcile_declared_summary(StreamRole::Metadata, &different)
        .is_err());
    let mut different = root.declared_summary(StreamRole::Metadata).clone();
    different.ciphertext_sha256[0] ^= 1;
    assert!(root
        .reconcile_declared_summary(StreamRole::Metadata, &different)
        .is_err());
    // This public typed value is a declaration, not a decoder-produced capability.
    root.reconcile_declared_summary(
        StreamRole::Metadata,
        root.declared_summary(StreamRole::Metadata),
    )
    .unwrap();
}

#[test]
fn archive_cannot_supply_its_own_trust_or_select_an_unpinned_signer() {
    let f = fixture(3);
    assert!(
        verify_declared_root(f.signed.as_bytes(), &ArchiveSignerTrust::new([]).unwrap()).is_err()
    );
    let other = ArchiveSigningKey::from_seed(f.signer.id(), [9; 32]).unwrap();
    assert!(verify_declared_root(f.signed.as_bytes(), &trust(&other)).is_err());
    let mut value = wire(&f.signed);
    value["public_key"] = json!(hex::encode(f.signer.public_key()));
    let bytes = canonical_bytes(&value).unwrap();
    assert!(verify_declared_root(&bytes, &trust(&f.signer)).is_err());
}

#[test]
fn signer_alias_and_cross_domain_signature_substitution_fail() {
    let f = fixture(4);
    let pins = ArchiveSignerTrust::new([
        (f.signer.id().into(), f.signer.public_key()),
        ("alias-v1".into(), f.signer.public_key()),
    ])
    .unwrap();
    let mut value = wire(&f.signed);
    value["payload"]["signer_key_id"] = json!("alias-v1");
    assert!(verify_declared_root(&canonical_bytes(&value).unwrap(), &pins).is_err());
    let mut value = wire(&f.signed);
    for domain in [
        "aos.hub.release-evidence-signature/v1",
        "aos.hub.snapshot-archive-signature/v2",
        "",
    ] {
        let bytes = resign(&mut value, &f.signer, domain);
        assert!(verify_declared_root(&bytes, &pins).is_err());
    }
}

#[test]
fn signature_payload_tampering_and_noncanonical_signature_encodings_fail() {
    let f = fixture(5);
    let mut value = wire(&f.signed);
    value["payload"]["streams"]["metadata"]["ciphertext_sha256"] = json!("0".repeat(64));
    assert!(verify_declared_root(&canonical_bytes(&value).unwrap(), &trust(&f.signer)).is_err());
    for signature in [
        "".to_owned(),
        "PRIVATE-BAD-SIGNATURE".into(),
        format!(
            "{}=",
            wire(&f.signed)["signature_base64url"].as_str().unwrap()
        ),
        "a".repeat(86),
    ] {
        let mut value = wire(&f.signed);
        value["signature_base64url"] = json!(signature);
        assert!(
            verify_declared_root(&canonical_bytes(&value).unwrap(), &trust(&f.signer)).is_err()
        );
    }
}

#[test]
fn root_size_is_checked_before_parse_and_noncanonical_forms_fail() {
    let f = fixture(6);
    let pins = trust(&f.signer);
    let error = verify_declared_root(&vec![b'P'; MAX_ROOT_BYTES + 1], &pins).unwrap_err();
    assert_eq!(error.to_string(), "snapshot root exceeds limits");
    let mut trailing = f.signed.as_bytes().to_vec();
    trailing.push(b'\n');
    assert!(verify_declared_root(&trailing, &pins).is_err());
    let pretty = serde_json::to_vec_pretty(&wire(&f.signed)).unwrap();
    assert!(verify_declared_root(&pretty, &pins).is_err());
    let duplicate = std::str::from_utf8(f.signed.as_bytes()).unwrap().replacen(
        "\"schema_version\":",
        &format!("\"schema_version\":\"{ROOT_SCHEMA}\",\"schema_version\":"),
        1,
    );
    assert!(verify_declared_root(duplicate.as_bytes(), &pins).is_err());
}

#[test]
fn unknown_members_versions_suites_scope_and_completion_flags_reject_even_signed() {
    let f = fixture(7);
    let original = wire(&f.signed);
    let modifications = [
        ("/schema_version", json!("aos.hub.snapshot-archive/v2")),
        ("/payload/profile", json!("whole_hub")),
        ("/payload/algorithm_suite", json!("aes-128-gcm")),
        ("/payload/streams/metadata/role", json!("private")),
        (
            "/payload/streams/private/filename",
            json!("../private.aosh"),
        ),
        ("/payload/streams/metadata/filename", json!("Metadata.aosh")),
    ];
    for (path, replacement) in modifications {
        let mut value = original.clone();
        *value.pointer_mut(path).unwrap() = replacement;
        let bytes = resign(&mut value, &f.signer, SIGNATURE_DOMAIN);
        assert!(
            verify_declared_root(&bytes, &trust(&f.signer)).is_err(),
            "{path}"
        );
    }
    for field in [
        "whole_hub_complete",
        "activation_authorized",
        "complete",
        "source_provenance",
        "PRIVATE-UNKNOWN",
    ] {
        let mut value = original.clone();
        value["payload"][field] = json!(true);
        let bytes = resign(&mut value, &f.signer, SIGNATURE_DOMAIN);
        let error = verify_declared_root(&bytes, &trust(&f.signer)).unwrap_err();
        assert!(!format!("{error:#}").contains("PRIVATE"));
    }
}

#[test]
fn canonical_decimal_hash_and_archive_identity_admission_is_strict() {
    let f = fixture(8);
    let original = wire(&f.signed);
    for count in [
        json!(1),
        json!("+1"),
        json!("01"),
        json!("-0"),
        json!("18446744073709551616"),
        json!(" 1"),
        json!("1.0"),
    ] {
        let mut value = original.clone();
        value["payload"]["streams"]["metadata"]["data_frames"] = count;
        let bytes = resign(&mut value, &f.signer, SIGNATURE_DOMAIN);
        assert!(verify_declared_root(&bytes, &trust(&f.signer)).is_err());
    }
    for (path, bad) in [
        ("/payload/archive_id", "A".repeat(32)),
        ("/payload/archive_id", "0".repeat(31)),
        (
            "/payload/streams/metadata/ciphertext_sha256",
            "A".repeat(64),
        ),
        (
            "/payload/streams/metadata/ciphertext_sha256",
            "g".repeat(64),
        ),
    ] {
        let mut value = original.clone();
        *value.pointer_mut(path).unwrap() = json!(bad);
        let bytes = resign(&mut value, &f.signer, SIGNATURE_DOMAIN);
        assert!(verify_declared_root(&bytes, &trust(&f.signer)).is_err());
    }
}

#[test]
fn impossible_declared_frame_arithmetic_and_overflow_are_rejected() {
    let empty = StreamSummary {
        data_frames: 0,
        plaintext_bytes: 0,
        ciphertext_bytes: 116,
        ciphertext_sha256: [0; 32],
    };
    validate_summary(&empty).unwrap();
    let variants = [
        StreamSummary {
            plaintext_bytes: 1,
            ..empty.clone()
        },
        StreamSummary {
            data_frames: 1,
            ..empty.clone()
        },
        StreamSummary {
            ciphertext_bytes: 115,
            ..empty.clone()
        },
        StreamSummary {
            data_frames: u64::MAX,
            ..empty.clone()
        },
        StreamSummary {
            plaintext_bytes: u64::MAX,
            ..empty.clone()
        },
        StreamSummary {
            data_frames: 1,
            plaintext_bytes: 256 * 1024 + 1,
            ciphertext_bytes: 116 + 32 + 256 * 1024 + 1,
            ..empty.clone()
        },
    ];
    for summary in variants {
        assert!(validate_summary(&summary).is_err());
    }
    let (id, metadata, private) = fresh(9);
    let signer = signer();
    let wrapping = wrapping();
    let prepared = prepare_archive_keys(&id, &signer, &wrapping, &metadata, &private, &[]).unwrap();
    let invalid = StreamSummary {
        ciphertext_bytes: 0,
        ..empty.clone()
    };
    assert!(sign_declared_root(prepared, &signer, &invalid, &empty).is_err());
}

#[test]
fn wrapping_material_ids_signing_keys_stream_keys_and_known_source_exclusions_are_distinct() {
    assert!(ArchiveWrappingKeys::new(
        ArchiveWrappingKey::from_bytes("same", [2; 32]).unwrap(),
        ArchiveWrappingKey::from_bytes("same", [3; 32]).unwrap()
    )
    .is_err());
    assert!(ArchiveWrappingKeys::new(
        ArchiveWrappingKey::from_bytes("m", [2; 32]).unwrap(),
        ArchiveWrappingKey::from_bytes("p", [2; 32]).unwrap()
    )
    .is_err());
    let (id, metadata, private) = fresh(10);
    let signer = signer();
    let wrapping = wrapping();
    for bytes in [
        [1; 32],
        [2; 32],
        [3; 32],
        metadata.with_private_key_bytes(|key| *key),
        private.with_private_key_bytes(|key| *key),
    ] {
        let excluded = [ExcludedArchiveKey::from_bytes(bytes)];
        assert!(
            prepare_archive_keys(&id, &signer, &wrapping, &metadata, &private, &excluded).is_err()
        );
    }
    let too_many = (0..33)
        .map(|_| ExcludedArchiveKey::from_bytes([99; 32]))
        .collect::<Vec<_>>();
    assert!(prepare_archive_keys(&id, &signer, &wrapping, &metadata, &private, &too_many).is_err());
    let bad = ArchiveWrappingKeys::new(
        ArchiveWrappingKey::from_bytes("m", [1; 32]).unwrap(),
        ArchiveWrappingKey::from_bytes("p", [3; 32]).unwrap(),
    )
    .unwrap();
    assert!(prepare_archive_keys(&id, &signer, &bad, &metadata, &private, &[]).is_err());
    let bad = ArchiveWrappingKeys::new(
        ArchiveWrappingKey::from_bytes("m", signer.public_key()).unwrap(),
        ArchiveWrappingKey::from_bytes("p", [3; 32]).unwrap(),
    )
    .unwrap();
    assert!(prepare_archive_keys(&id, &signer, &bad, &metadata, &private, &[]).is_err());
    let a = FreshStreamKey::generate(&mut StdRng::seed_from_u64(99)).unwrap();
    let b = FreshStreamKey::generate(&mut StdRng::seed_from_u64(99)).unwrap();
    assert!(prepare_archive_keys(&id, &signer, &wrapping, &a, &b, &[]).is_err());
}

#[test]
fn preparation_cannot_be_signed_by_a_different_seed_or_identity() {
    let (id, metadata, private) = fresh(11);
    let signer = signer();
    let wrapping = wrapping();
    let summary = StreamSummary {
        data_frames: 0,
        plaintext_bytes: 0,
        ciphertext_bytes: 116,
        ciphertext_sha256: [0; 32],
    };
    for other in [
        ArchiveSigningKey::from_seed(signer.id(), [9; 32]).unwrap(),
        ArchiveSigningKey::from_seed("different-id", [1; 32]).unwrap(),
    ] {
        let prepared =
            prepare_archive_keys(&id, &signer, &wrapping, &metadata, &private, &[]).unwrap();
        assert!(sign_declared_root(prepared, &other, &summary, &summary).is_err());
    }
}

#[test]
fn wrap_nonces_are_randomized_without_reusing_source_sealing_key_initialization() {
    let (id, metadata, private) = fresh(12);
    let signer = signer();
    let wrapping = wrapping();
    let first = prepare_archive_keys(&id, &signer, &wrapping, &metadata, &private, &[]).unwrap();
    let second = prepare_archive_keys(&id, &signer, &wrapping, &metadata, &private, &[]).unwrap();
    assert_ne!(first.metadata.sealed, second.metadata.sealed);
    assert_ne!(first.private.sealed, second.private.sealed);
}

#[test]
fn wrong_wrap_ids_material_and_signed_ciphertext_tampering_fail() {
    let f = fixture(13);
    let root = verify_declared_root(f.signed.as_bytes(), &trust(&f.signer)).unwrap();
    let wrong = ArchiveWrappingKeys::new(
        ArchiveWrappingKey::from_bytes("metadata-wrap-v1", [8; 32]).unwrap(),
        ArchiveWrappingKey::from_bytes("private-wrap-v1", [3; 32]).unwrap(),
    )
    .unwrap();
    assert!(root.unwrap_reader_keys(&wrong, &[]).is_err());
    let wrong = ArchiveWrappingKeys::new(
        ArchiveWrappingKey::from_bytes("other-meta", [2; 32]).unwrap(),
        ArchiveWrappingKey::from_bytes("private-wrap-v1", [3; 32]).unwrap(),
    )
    .unwrap();
    assert!(root.unwrap_reader_keys(&wrong, &[]).is_err());
    let mut value = wire(&f.signed);
    let encoded = value["payload"]["streams"]["metadata"]["wrapped_key"]["sealed"]
        .as_str()
        .unwrap();
    let mut bytes = URL_SAFE_NO_PAD.decode(encoded).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    value["payload"]["streams"]["metadata"]["wrapped_key"]["sealed"] =
        json!(URL_SAFE_NO_PAD.encode(bytes));
    let signed = resign(&mut value, &f.signer, SIGNATURE_DOMAIN);
    let root = verify_declared_root(&signed, &trust(&f.signer)).unwrap();
    assert!(root.unwrap_reader_keys(&f.wrapping, &[]).is_err());
}

#[test]
fn correctly_resigned_cross_archive_wrapped_context_is_still_rejected() {
    let f = fixture(14);
    let other = fixture(15);
    let mut value = wire(&f.signed);
    value["payload"]["streams"]["metadata"]["wrapped_key"] =
        wire(&other.signed)["payload"]["streams"]["metadata"]["wrapped_key"].clone();
    let signed = resign(&mut value, &f.signer, SIGNATURE_DOMAIN);
    let root = verify_declared_root(&signed, &trust(&f.signer)).unwrap();
    assert!(root.unwrap_reader_keys(&f.wrapping, &[]).is_err());
    let mut value = wire(&f.signed);
    value["payload"]["archive_id"] = json!("0".repeat(32));
    let signed = resign(&mut value, &f.signer, SIGNATURE_DOMAIN);
    let root = verify_declared_root(&signed, &trust(&f.signer)).unwrap();
    assert!(root.unwrap_reader_keys(&f.wrapping, &[]).is_err());
}

fn replace_inner(value: &mut Value, path: &str, key: [u8; 32], modify: impl FnOnce(&mut Value)) {
    let old = value.pointer(path).unwrap().as_str().unwrap();
    let sealer = AesGcmSealer::new(&key).unwrap();
    let plaintext = sealer.unseal(old).unwrap();
    let mut inner: Value = serde_json::from_str(&plaintext).unwrap();
    modify(&mut inner);
    let encoded = canonical_bytes(&inner).unwrap();
    let sealed = sealer.seal(std::str::from_utf8(&encoded).unwrap()).unwrap();
    *value.pointer_mut(path).unwrap() = json!(sealed);
}

#[test]
fn encrypted_inner_role_wrapping_identity_version_suite_and_key_shape_are_closed() {
    let f = fixture(16);
    let path = "/payload/streams/metadata/wrapped_key/sealed";
    for (field, change) in [
        ("role", json!("private")),
        ("wrapping_key_id", json!("other-id")),
        ("schema_version", json!("aos.hub.snapshot-stream-key/v2")),
        ("algorithm", json!("xor")),
        ("stream_key_base64url", json!("PRIVATE-INVALID-KEY")),
        ("extra", json!("PRIVATE-UNKNOWN")),
    ] {
        let mut value = wire(&f.signed);
        replace_inner(&mut value, path, [2; 32], |inner| inner[field] = change);
        let bytes = resign(&mut value, &f.signer, SIGNATURE_DOMAIN);
        let root = verify_declared_root(&bytes, &trust(&f.signer)).unwrap();
        let error = root.unwrap_reader_keys(&f.wrapping, &[]).unwrap_err();
        assert!(!format!("{error:#} {error:?}").contains("PRIVATE"));
    }
}

#[test]
fn metadata_and_private_keys_cannot_be_exchanged_or_overlap_after_unwrap() {
    let f = fixture(17);
    let root = verify_declared_root(f.signed.as_bytes(), &trust(&f.signer)).unwrap();
    let (meta, private) = root
        .unwrap_reader_keys(&f.wrapping, &[])
        .unwrap()
        .into_role_keys();
    let mut wrong = StreamDecoder::new(
        Cursor::new(&f.metadata_bytes),
        private,
        root.stream_context(StreamRole::Metadata),
        StreamLimits::default(),
    )
    .unwrap();
    assert!(wrong.next_chunk().is_err());
    let mut wrong = StreamDecoder::new(
        Cursor::new(&f.private_bytes),
        meta,
        root.stream_context(StreamRole::Private),
        StreamLimits::default(),
    )
    .unwrap();
    assert!(wrong.next_chunk().is_err());
    let mut value = wire(&f.signed);
    let meta_sealer = AesGcmSealer::new(&[2; 32]).unwrap();
    let private_sealer = AesGcmSealer::new(&[3; 32]).unwrap();
    let meta_inner: Value = serde_json::from_str(
        &meta_sealer
            .unseal(
                value["payload"]["streams"]["metadata"]["wrapped_key"]["sealed"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap(),
    )
    .unwrap();
    let mut private_inner: Value = serde_json::from_str(
        &private_sealer
            .unseal(
                value["payload"]["streams"]["private"]["wrapped_key"]["sealed"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap(),
    )
    .unwrap();
    private_inner["stream_key_base64url"] = meta_inner["stream_key_base64url"].clone();
    value["payload"]["streams"]["private"]["wrapped_key"]["sealed"] = json!(private_sealer
        .seal(std::str::from_utf8(&canonical_bytes(&private_inner).unwrap()).unwrap())
        .unwrap());
    let signed = resign(&mut value, &f.signer, SIGNATURE_DOMAIN);
    let root = verify_declared_root(&signed, &trust(&f.signer)).unwrap();
    assert!(root.unwrap_reader_keys(&f.wrapping, &[]).is_err());
}

#[test]
fn bounded_opaque_ids_external_trust_and_wrapped_encodings_reject_unsupported_inputs() {
    for id in [
        "",
        "provider://PRIVATE/secret/v1",
        "../PRIVATE",
        "PRIVATE space",
        "PRIVATE\n",
    ] {
        assert!(ArchiveSigningKey::from_seed(id, [1; 32]).is_err());
        assert!(ArchiveWrappingKey::from_bytes(id, [2; 32]).is_err());
    }
    // Dots are allowed inside opaque names; the fixed filenames never use IDs.
    assert!(ArchiveWrappingKey::from_bytes("wrap.key-v1", [2; 32]).is_ok());
    let signer = signer();
    assert!(ArchiveSignerTrust::new([
        (signer.id().into(), signer.public_key()),
        (signer.id().into(), signer.public_key())
    ])
    .is_err());
    assert!(ArchiveSignerTrust::new(
        (0..33).map(|index| (format!("key-{index}"), signer.public_key()))
    )
    .is_err());
    assert!(ArchiveSignerTrust::new([("weak".into(), [0; 32])]).is_err());
    let f = fixture(18);
    for bad in ["x".repeat(1025), "PRIVATE-WRAP=PAD".into(), "".into()] {
        let mut value = wire(&f.signed);
        value["payload"]["streams"]["metadata"]["wrapped_key"]["sealed"] = json!(bad);
        let bytes = resign(&mut value, &f.signer, SIGNATURE_DOMAIN);
        assert!(verify_declared_root(&bytes, &trust(&f.signer)).is_err());
    }
}

#[test]
fn private_wrapper_and_failure_debug_do_not_disclose_key_payloads() {
    let (id, meta, private) = fresh(19);
    let signer = signer();
    let wrapping = wrapping();
    let excluded = ExcludedArchiveKey::from_bytes([99; 32]);
    let prepared = prepare_archive_keys(&id, &signer, &wrapping, &meta, &private, &[]).unwrap();
    let debug = format!("{signer:?} {wrapping:?} {excluded:?} {prepared:?}");
    assert!(!debug.contains(&hex::encode([1; 32])));
    assert!(!debug.contains(&URL_SAFE_NO_PAD.encode([2; 32])));
    let f = fixture(20);
    let verified = verify_declared_root(f.signed.as_bytes(), &trust(&f.signer)).unwrap();
    let keys = verified.unwrap_reader_keys(&f.wrapping, &[]).unwrap();
    assert_eq!(format!("{keys:?}"), "UnwrappedReaderKeys { <redacted> }");
    let error =
        verify_declared_root(b"{\"PRIVATE-PARSER-DETAIL\":", &trust(&f.signer)).unwrap_err();
    assert!(!format!("{error:#} {error:?}").contains("PRIVATE"));
}

#[test]
fn archive_identity_generation_failure_is_value_free() {
    struct Refuse;
    impl rand::TryRngCore for Refuse {
        type Error = std::io::Error;
        fn try_next_u32(&mut self) -> std::result::Result<u32, Self::Error> {
            Err(std::io::Error::other("PRIVATE-RNG"))
        }
        fn try_next_u64(&mut self) -> std::result::Result<u64, Self::Error> {
            Err(std::io::Error::other("PRIVATE-RNG"))
        }
        fn try_fill_bytes(&mut self, _bytes: &mut [u8]) -> std::result::Result<(), Self::Error> {
            Err(std::io::Error::other("PRIVATE-RNG"))
        }
    }
    impl rand::TryCryptoRng for Refuse {}
    let error = FreshArchiveId::generate(&mut Refuse).unwrap_err();
    assert_eq!(
        error.to_string(),
        "snapshot archive identity generation failed"
    );
}

#[test]
fn metadata_only_custody_reads_metadata_and_cannot_unlock_private() {
    let f = fixture(21);
    let root = verify_declared_root(f.signed.as_bytes(), &trust(&f.signer)).unwrap();
    let metadata_custody = ArchiveWrappingKey::from_bytes("metadata-wrap-v1", [2; 32]).unwrap();
    let key = root
        .unwrap_reader_key(StreamRole::Metadata, &metadata_custody, &[])
        .unwrap();
    let observed = full_decode(&root, StreamRole::Metadata, key, &f.metadata_bytes);
    root.reconcile_declared_summary(StreamRole::Metadata, &observed)
        .unwrap();
    assert!(root
        .unwrap_reader_key(StreamRole::Private, &metadata_custody, &[])
        .is_err());
    let falsely_named = ArchiveWrappingKey::from_bytes("private-wrap-v1", [2; 32]).unwrap();
    assert!(root
        .unwrap_reader_key(StreamRole::Private, &falsely_named, &[])
        .is_err());
    let excluded = [ExcludedArchiveKey::from_bytes([2; 32])];
    assert!(root
        .unwrap_reader_key(StreamRole::Metadata, &metadata_custody, &excluded)
        .is_err());
}

#[test]
fn authenticated_inner_noncanonical_duplicate_and_oversized_plaintext_rejects() {
    let f = fixture(22);
    let sealer = AesGcmSealer::new(&[2; 32]).unwrap();
    let original = wire(&f.signed);
    let plaintext = sealer
        .unseal(
            original["payload"]["streams"]["metadata"]["wrapped_key"]["sealed"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
    let duplicate = plaintext.replacen(
        "\"schema_version\":",
        "\"schema_version\":\"aos.hub.snapshot-stream-key/v1\",\"schema_version\":",
        1,
    );
    let cases = [
        format!(" {plaintext}"),
        duplicate,
        format!("{}{}", " ".repeat(300), plaintext),
    ];
    for inner in cases {
        let mut value = original.clone();
        value["payload"]["streams"]["metadata"]["wrapped_key"]["sealed"] =
            json!(sealer.seal(&inner).unwrap());
        let bytes = resign(&mut value, &f.signer, SIGNATURE_DOMAIN);
        let root = verify_declared_root(&bytes, &trust(&f.signer)).unwrap();
        assert!(root.unwrap_reader_keys(&f.wrapping, &[]).is_err());
    }
}

//! Source identity, signature, field and encoded-budget tests for narinfo results.

use super::*;

fn source() -> String {
    "StorePath: /nix/store/0123456789abcdfghijklmnpqrsvwxyz-test\nURL: nar/test.nar\nNarHash: sha256:test\nNarSize: 9007199254740993\nFileSize: 12\nReferences: ref-one ref-two\nUnknownField: text retained only in storage\n".to_owned()
}

#[test]
fn original_digest_is_distinct_from_projection_and_lossless_counter() {
    let text = source();
    let projected = HybridNarinfoProjection::from_bytes(text.as_bytes()).unwrap();

    assert_eq!(
        projected.source_sha256,
        crate::hybrid_ingress::body_sha256(text.as_bytes())
    );
    assert_eq!(projected.nar_size, "9007199254740993");
    assert_eq!(
        projected.references,
        ["/nix/store/ref-one", "/nix/store/ref-two"]
    );
    let encoded = serde_json::to_vec(&projected).unwrap();
    assert!(!String::from_utf8(encoded.clone())
        .unwrap()
        .contains("UnknownField"));
    assert_ne!(
        projected.source_sha256,
        crate::hybrid_ingress::body_sha256(&encoded)
    );
    assert_eq!(
        serde_json::from_slice::<HybridNarinfoProjection>(&encoded).unwrap(),
        projected
    );
}

#[test]
fn projection_verifies_selected_original_nix_signature() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[47; 32]);
    let text = crate::nix_sign::sign_narinfo(&source(), "selected", &key).unwrap();
    let public =
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(key.verifying_key().to_bytes());
    let mut projected = HybridNarinfoProjection::from_bytes(text.as_bytes()).unwrap();

    projected.verify_selected_key("selected", &public).unwrap();
    assert!(projected
        .verify_selected_key("another-key", &public)
        .is_err());
    projected.references.reverse();
    assert!(projected.verify_selected_key("selected", &public).is_err());
}

#[test]
fn duplicate_fields_counters_and_paths_are_rejected() {
    for text in [
        format!("{}NarSize: 1\n", source()),
        source().replace("9007199254740993", "09007199254740993"),
        source().replace("9007199254740993", "-1"),
        source().replace("nar/test.nar", "nar/../private.nar"),
        source().replace("nar/test.nar", "https://untrusted.example/object.nar"),
    ] {
        assert!(HybridNarinfoProjection::from_bytes(text.as_bytes()).is_err());
    }
}

#[test]
fn unknown_and_duplicate_wire_fields_are_not_accepted() {
    let projected = HybridNarinfoProjection::from_bytes(source().as_bytes()).unwrap();
    let encoded = serde_json::to_string(&projected).unwrap();
    let unknown = encoded.replacen('{', "{\"raw_narinfo\":\"file bytes\",", 1);
    let duplicate = encoded.replacen('{', "{\"version\":1,", 1);

    assert!(serde_json::from_str::<HybridNarinfoProjection>(&unknown).is_err());
    assert!(serde_json::from_str::<HybridNarinfoProjection>(&duplicate).is_err());
}

#[test]
fn received_projection_count_and_aggregate_budget_are_bounded() {
    let mut projected = HybridNarinfoProjection::from_bytes(source().as_bytes()).unwrap();
    projected.references = vec!["/nix/store/test".to_owned(); MAX_REFERENCES + 1];
    assert!(projected.validate().is_err());
    projected.references = vec![format!("/{}", "a".repeat(MAX_FIELD_BYTES - 1)); MAX_REFERENCES];
    assert!(projected.validate().is_err());
}

#[test]
fn signing_delimiters_and_noncanonical_store_paths_are_rejected() {
    let mut projection = HybridNarinfoProjection::from_bytes(source().as_bytes()).unwrap();
    for path in [
        "/nix/store/name;other",
        "/nix/store/name,other",
        "/nix/store/name other",
        "/nix/store/../name",
        "/nix//store/name",
        "/nix/store/name/",
    ] {
        projection.store_path = path.to_owned();
        assert!(projection.validate().is_err(), "{path}");
    }
    let mut projection = HybridNarinfoProjection::from_bytes(source().as_bytes()).unwrap();
    projection.references = vec!["/nix/store/one,two".to_owned()];
    assert!(projection.validate().is_err());
    projection.references.clear();
    projection.nar_hash = "sha256:one;two".to_owned();
    assert!(projection.validate().is_err());
}

#[test]
fn parsed_store_hash_is_bound_to_the_exact_admitted_narinfo_path() {
    let projection = HybridNarinfoProjection::from_bytes(source().as_bytes()).unwrap();
    projection
        .validate_cache_path("0123456789abcdfghijklmnpqrsvwxyz.narinfo")
        .unwrap();
    for path in [
        "different.narinfo",
        "nested/0123456789abcdfghijklmnpqrsvwxyz.narinfo",
        "nar/payload.nar",
    ] {
        assert!(projection.validate_cache_path(path).is_err());
    }
}

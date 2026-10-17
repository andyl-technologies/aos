//! Tests live registration and negotiation refusals of an immutable source policy.
//!
//! Local registrars are modeled. The original Unix connection, installed policy
//! and revocation handle are owning values; no child or Capture right is issued.

#![allow(clippy::unwrap_used)]

use super::*;

fn frame(authority: &ConnectionAuthority) -> (Envelope, ReceivedBody) {
    let mut original = crate::envelope::tests::request();
    original.session_id = Nullable(Some(authority.session_id().clone()));
    original.incarnation_id = Nullable(Some(authority.incarnation_id().clone()));
    original.method = Method::Discover;
    original.body = serde_json::json!({"profile_ids":[],"extensions":{}})
        .as_object()
        .unwrap()
        .clone();
    original.extensions.clear();
    let body = ReceivedBody::Request(Box::new(
        crate::bodies::decode_request(original.method, &original.body).unwrap(),
    ));
    (original, body)
}

#[test]
fn native5_policy_current_checks_refuse_same_original_registration_after_revocation() {
    let (handshake, mut connection, _native, policy, _storage, _hello, _host) =
        endpoint_recovery_tests::retained_endpoint_fixture();
    let authority = connection.provider_authority().unwrap().clone();
    let codec = connection.retained_native5_codec_owner().unwrap().clone();
    let (original, body) = frame(&authority);
    policy.verify(&authority, &original, &body).unwrap();
    codec.verify(&authority, &original, &body).unwrap();
    connection.authenticate_native5_source_codec().unwrap();

    drop(handshake);

    for _ in 0..2 {
        assert!(policy.verify(&authority, &original, &body).is_err());
        assert!(codec.verify(&authority, &original, &body).is_err());
        assert!(connection.authenticate_native5_source_codec().is_err());
    }
}

#[test]
fn native5_policy_current_checks_keep_session_feature_and_body_extension_refusals() {
    let (_handshake, mut connection, _native, policy, _storage, _hello, _host) =
        endpoint_recovery_tests::retained_endpoint_fixture();
    let authority = connection.provider_authority().unwrap().clone();
    let codec = connection.retained_native5_codec_owner().unwrap().clone();
    let (original, body) = frame(&authority);
    codec.verify(&authority, &original, &body).unwrap();

    let (_foreign_handshake, foreign, _, _) = scope_named(true, Some("foreign-policy"), 0);
    assert!(policy.verify(&foreign, &original, &body).is_err());
    assert!(codec.verify(&foreign, &original, &body).is_err());
    let (_legacy_handshake, legacy, _, _) = scope(false);
    assert!(policy.verify(&legacy, &original, &body).is_err());
    assert!(codec.verify(&legacy, &original, &body).is_err());

    let (_overlimit_handshake, overlimit, _, _) = scope_named_with_limits(
        true,
        None,
        0,
        Some(Limits {
            frame_bytes: U64::new(65536),
            requests: U64::new(8),
            journal_entries: U64::new(64),
            nesting: U64::new(64),
            blob_chunk_bytes: U64::new(8192),
        }),
    );
    assert!(policy.verify(&overlimit, &original, &body).is_err());
    assert!(codec.verify(&overlimit, &original, &body).is_err());

    let mut changed = original.clone();
    changed
        .body
        .insert("extensions".into(), serde_json::json!({"unsupported":true}));
    assert!(policy.verify(&authority, &changed, &body).is_err());
    assert!(codec.verify(&authority, &changed, &body).is_err());
    let mut changed = original.clone();
    changed
        .extensions
        .insert("source-owned.packet-input/4".into(), serde_json::json!({}));
    assert!(policy.verify(&authority, &changed, &body).is_err());
    assert!(codec.verify(&authority, &changed, &body).is_err());
    codec.verify(&authority, &original, &body).unwrap();
    connection.authenticate_native5_source_codec().unwrap();
}

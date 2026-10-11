//! Cold selector recovery preserves the original incarnation and grants no turn.

use aos_hub_core::storage_authority::external_object::copy::session::{CopyAction, CopySession};

use super::*;

#[test]
fn cold_lookup_keeps_unknown_original_after_source_replacement() {
    let (object, config, original) = super::super::config::tests::fixture();
    let domain = config.domain(&object, &original).unwrap();
    let selector = CopyOriginalSelector::from_original(&original).unwrap();
    let request = Request {
        domain: DOMAIN.into(),
        nonce: "a".repeat(64),
        scope: domain.selector_scope(&object, &selector).unwrap(),
        selector,
    };
    assert_eq!(
        request.selector.copy_id().unwrap(),
        original.copy_id().unwrap()
    );
    let mut session = CopySession::initialize(original.clone()).unwrap();
    session
        .begin(&original, CopyAction::Create, "b".repeat(64))
        .unwrap();
    let archived = serde_json::to_vec(&session).unwrap();
    let cold: CopySession = serde_json::from_slice(&archived).unwrap();
    cold.validate(cold.original()).unwrap();
    let key = StorageWorkKey::new([7_u8; 32]).unwrap();
    let (body, signature) = sign_reply(
        &key,
        &request,
        Some(Retained {
            original: cold.original().clone(),
            progress: cold.progress().unwrap(),
        }),
    )
    .unwrap();
    let retained = verify_reply(&key, &request, &signature, &body)
        .unwrap()
        .unwrap();
    assert_eq!(retained.original, original);
    assert!(retained.progress.pending);

    let mut fresh = original.clone();
    fresh.source_object.provider_version = Some("new-source-version".into());
    assert_eq!(fresh.copy_id().unwrap(), original.copy_id().unwrap());
    assert!(cold.validate(&fresh).is_err());
    assert_ne!(retained.original.source_object, fresh.source_object);
    assert!(body.len() <= MAX_MESSAGE);
    assert!(
        !String::from_utf8(body.clone())
            .unwrap()
            .contains("source_state")
    );

    let mut changed = request.clone();
    changed.nonce = "c".repeat(64);
    assert!(verify_reply(&key, &changed, &signature, &body).is_err());
    changed = request.clone();
    changed.selector.destination.prefix.push_str("-changed");
    assert!(verify_reply(&key, &changed, &signature, &body).is_err());
    assert!(sign_reply(&key, &changed, Some(retained)).is_err());
    assert!(
        verify_reply(
            &StorageWorkKey::new([8_u8; 32]).unwrap(),
            &request,
            &signature,
            &body
        )
        .is_err()
    );

    let (body, signature) = sign_reply(&key, &request, None).unwrap();
    assert!(
        verify_reply(&key, &request, &signature, &body)
            .unwrap()
            .is_none()
    );
}

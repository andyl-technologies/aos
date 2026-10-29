//! Actual signed probe validation across receiver-clock admission boundaries.

use std::cell::Cell;

use aos_hub_db::direct_upload::*;
use aos_hub_db::storage_work::StorageWorkKey;

use super::*;
use crate::direct_guard::fixture;
use crate::direct_upload::acceptance_window::AcceptedProducerWindow;

const DEPLOYMENT: &str = "fixture-deployment";
const ORIGIN: &str = "https://executor.example";

fn capabilities() -> DirectStorageCapabilitiesRequest {
    DirectStorageCapabilitiesRequest {
        version: 2,
        deployment_id: DEPLOYMENT.into(),
        executor_public_origin: ORIGIN.into(),
        request_nonce: "ab".repeat(32),
        issued_at: WireInteger::new(100),
        expires_at: WireInteger::new(128),
        managed: true,
        external_selectors: Vec::new(),
    }
}

fn authority() -> DirectAuthorityLookup {
    let owner = fixture::reservation(DEPLOYMENT, "fixture/metadata");
    let evidence = DirectVerifiedStageEvidence {
        session_id: owner.admission.session_id.clone(),
        logical_fingerprint: owner.admission.logical_fingerprint.clone(),
        operation_id: owner.complete.operation_id.clone(),
        part_count: owner.admission.intent.part_count().unwrap(),
        sha256: owner.source.sha256.clone(),
        byte_size: owner.source.byte_size,
        placements: owner
            .complete
            .manifests
            .iter()
            .map(|manifest| DirectStagePlacementEvidence {
                placement: manifest.placement.clone(),
                manifest: manifest.clone(),
                verification_operation_id: "de".repeat(32),
                staging_incarnation: owner.source.incarnation.clone(),
            })
            .collect(),
        projection: None,
    };
    DirectAuthorityLookup {
        deployment_id: DEPLOYMENT.into(),
        request_nonce: "bc".repeat(32),
        issued_at: WireInteger::new(100),
        expires_at: WireInteger::new(128),
        operation: DirectAuthorityLookupOperation::Stage {
            admission: owner.admission,
            complete: owner.complete,
            evidence,
        },
    }
}

fn final_guard() -> DirectFinalGuardLookup {
    let owner = fixture::reservation(DEPLOYMENT, "fixture/metadata");
    let record = fixture::final_record(&owner);
    DirectFinalGuardLookup {
        admission: owner.admission,
        complete: owner.complete,
        expected: record,
        request_nonce: "cd".repeat(32),
        issued_at: WireInteger::new(100),
        expires_at: WireInteger::new(128),
    }
}

#[tokio::test]
async fn future_capability_probe_waits_for_actual_clock_without_changing_original() {
    let key = StorageWorkKey::new("metadata-fixture-authentication-key").unwrap();
    let original = capabilities();
    let signed = sign_direct_storage_capabilities_request(&key, &original).unwrap();
    let challenge =
        authenticate_direct_storage_capabilities_request(&key, &signed.signature, &signed.body)
            .unwrap();
    let clock = Cell::new(99);
    let waited = Cell::new(None);
    let (resume, ready) = tokio::sync::oneshot::channel();
    let mut checked = Box::pin(validate_when_current(
        challenge.issued_at.get(),
        || Ok(clock.get()),
        |now| challenge.validate(DEPLOYMENT, ORIGIN, now),
        |duration| {
            waited.set(Some(duration));
            async move { ready.await.unwrap() }
        },
    ));

    assert!(futures_util::poll!(&mut checked).is_pending());
    assert_eq!(waited.get(), Some(Duration::from_secs(1)));
    assert!(verify_direct_storage_capabilities_request(
        &key,
        &signed.signature,
        &signed.body,
        DEPLOYMENT,
        ORIGIN,
        clock.get(),
    )
    .is_err());

    clock.set(100);
    resume.send(()).unwrap();
    checked.await.unwrap();

    assert_eq!(challenge, original);
    verify_direct_storage_capabilities_request(
        &key,
        &signed.signature,
        &signed.body,
        DEPLOYMENT,
        ORIGIN,
        clock.get(),
    )
    .unwrap();
}

#[tokio::test]
async fn metadata_not_before_wait_is_bounded_and_keeps_strict_expiry() {
    let challenge = capabilities();
    let clock = Cell::new(98);
    let waited = Cell::new(None);
    validate_when_current(
        challenge.issued_at.get(),
        || Ok(clock.get()),
        |now| challenge.validate(DEPLOYMENT, ORIGIN, now),
        |duration| {
            waited.set(Some(duration));
            async { clock.set(100) }
        },
    )
    .await
    .unwrap();
    assert_eq!(waited.get(), Some(Duration::from_secs(2)));

    for observed in [0, 97, 128, u64::MAX] {
        assert!(validate_when_current(
            challenge.issued_at.get(),
            || Ok(observed),
            |now| challenge.validate(DEPLOYMENT, ORIGIN, now),
            |_| async { panic!("refused probes must not allocate a timer") },
        )
        .await
        .is_err());
    }
}

#[tokio::test]
async fn metadata_wait_rechecks_clock_rollback_and_original_acceptance() {
    let challenge = capabilities();
    for after_wait in [98, 99, 128, 129] {
        let clock = Cell::new(99);
        assert!(validate_when_current(
            challenge.issued_at.get(),
            || Ok(clock.get()),
            |now| challenge.validate(DEPLOYMENT, ORIGIN, now),
            |_| async { clock.set(after_wait) },
        )
        .await
        .is_err());
    }

    let acceptance = AcceptedProducerWindow::new(90, 101, 1).unwrap();
    let raw_clock = Cell::new(98);
    assert!(validate_when_current(
        challenge.issued_at.get(),
        || acceptance.latest_now(raw_clock.get()),
        |now| challenge.validate(DEPLOYMENT, ORIGIN, now),
        |_| async { raw_clock.set(100) },
    )
    .await
    .is_err());
    assert!(challenge.validate(DEPLOYMENT, ORIGIN, 101).is_ok());
}

#[tokio::test]
async fn malformed_metadata_and_foreign_audience_fail_before_waiting() {
    for change in 0..4 {
        let mut challenge = capabilities();
        match change {
            0 => challenge.version = 3,
            1 => challenge.deployment_id = "another-deployment".into(),
            2 => challenge.executor_public_origin = "https://another.example".into(),
            _ => challenge.expires_at = challenge.issued_at,
        }
        assert!(validate_when_current(
            challenge.issued_at.get(),
            || Ok(99),
            |now| challenge.validate(DEPLOYMENT, ORIGIN, now),
            |_| async { panic!("malformed or foreign probes must not wait") },
        )
        .await
        .is_err());
    }
}

#[tokio::test]
async fn authenticated_authority_and_guard_probes_keep_their_exact_originals() {
    let key = StorageWorkKey::new("metadata-fixture-authentication-key").unwrap();
    let original = authority();
    let signed = sign_direct_authority_lookup(&key, &original).unwrap();
    let challenge =
        authenticate_direct_authority_lookup(&key, &signed.signature, &signed.body).unwrap();
    let clock = Cell::new(99);
    validate_when_current(
        challenge.issued_at.get(),
        || Ok(clock.get()),
        |now| challenge.validate(DEPLOYMENT, now),
        |_| async { clock.set(100) },
    )
    .await
    .unwrap();
    assert_eq!(challenge, original);
    assert!(
        verify_direct_authority_lookup(&key, &signed.signature, &signed.body, DEPLOYMENT, 99)
            .is_err()
    );

    let original = final_guard();
    let signed = sign_direct_final_guard_lookup(&key, &original).unwrap();
    let challenge =
        authenticate_direct_final_guard_lookup(&key, &signed.signature, &signed.body).unwrap();
    clock.set(99);
    validate_when_current(
        challenge.issued_at.get(),
        || Ok(clock.get()),
        |now| challenge.validate(DEPLOYMENT, now),
        |_| async { clock.set(100) },
    )
    .await
    .unwrap();
    assert_eq!(challenge, original);
    assert!(verify_direct_final_guard_lookup(
        &key,
        &signed.signature,
        &signed.body,
        DEPLOYMENT,
        99
    )
    .is_err());
}

#[test]
fn metadata_authentication_rejects_changed_body_key_and_protocol_domain() {
    let key = StorageWorkKey::new("metadata-fixture-authentication-key").unwrap();
    let wrong = StorageWorkKey::new("another-metadata-authentication-key").unwrap();
    let capability = sign_direct_storage_capabilities_request(&key, &capabilities()).unwrap();
    let authority = sign_direct_authority_lookup(&key, &authority()).unwrap();
    let guard = sign_direct_final_guard_lookup(&key, &final_guard()).unwrap();

    assert!(authenticate_direct_storage_capabilities_request(
        &wrong,
        &capability.signature,
        &capability.body,
    )
    .is_err());
    assert!(
        authenticate_direct_authority_lookup(&wrong, &authority.signature, &authority.body)
            .is_err()
    );
    assert!(authenticate_direct_final_guard_lookup(&wrong, &guard.signature, &guard.body).is_err());

    let mut changed = capability.body.clone();
    changed.push(b' ');
    assert!(authenticate_direct_storage_capabilities_request(
        &key,
        &capability.signature,
        &changed
    )
    .is_err());
    assert!(
        authenticate_direct_authority_lookup(&key, &capability.signature, &capability.body)
            .is_err()
    );
    assert!(
        authenticate_direct_final_guard_lookup(&key, &authority.signature, &authority.body)
            .is_err()
    );
}

#[tokio::test]
async fn current_metadata_originals_do_not_wait_or_relax_validation() {
    let challenge = capabilities();
    for observed in [100, 127] {
        validate_when_current(
            challenge.issued_at.get(),
            || Ok(observed),
            |now| challenge.validate(DEPLOYMENT, ORIGIN, now),
            |_| async { panic!("current probes must not wait") },
        )
        .await
        .unwrap();
    }
}

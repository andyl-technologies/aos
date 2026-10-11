//! Checks atomic durable route ownership without claiming native qualification.

// crucible-lint: allow panic-shortcut -- Model assertions deliberately panic on changed original route custody.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crucible_cas::content_store::{DirectoryBlobBackend, DirectoryRefBackend};
use std::sync::Barrier;

const EXECUTION: &str = "82828282828282828282828282828282";

fn claims(path: &std::path::Path) -> OriginalClaims {
    OriginalClaims::new(
        Arc::new(DirectoryBlobBackend::new("claim-model", path.join("blobs"))),
        Arc::new(DirectoryRefBackend::new(path.join("refs"))),
    )
    .unwrap()
}

#[test]
fn competing_caller_threads_choose_one_original_route_before_effects() {
    let directory = tempfile::tempdir().unwrap();
    let claims = claims(directory.path());
    let barrier = Arc::new(Barrier::new(3));
    let jobs: Vec<_> = [Route::Capability, Route::Conditional]
        .into_iter()
        .map(|route| {
            let claims = claims.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                let result = claims.reserve(EXECUTION, route, b"original request bytes");
                (route, result)
            })
        })
        .collect();

    barrier.wait();
    let outcomes: Vec<_> = jobs.into_iter().map(|job| job.join().unwrap()).collect();
    assert_eq!(
        outcomes
            .iter()
            .filter(|(_, result)| matches!(result, Ok(Reservation::Original)))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|(_, result)| result.is_err())
            .count(),
        1
    );
    let winning_route = outcomes
        .iter()
        .find(|(_, result)| result.is_ok())
        .unwrap()
        .0;
    assert_eq!(
        claims
            .reserve(EXECUTION, winning_route, b"original request bytes")
            .unwrap(),
        Reservation::Retained
    );
}

#[test]
fn unresolved_claim_survives_restart_and_cannot_dispatch_changed_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let original = claims(directory.path());
    assert_eq!(
        original
            .reserve(EXECUTION, Route::Root, b"original Root request")
            .unwrap(),
        Reservation::Original
    );
    let roots = original.retention_roots().unwrap();
    assert_eq!(roots.len(), 3);
    assert!(roots.contains(&ContentId::for_bytes(
        ObjectKind::Trace,
        1,
        b"original Root request"
    )));
    drop(original);

    let restarted = claims(directory.path());
    assert_eq!(
        restarted
            .reserve(EXECUTION, Route::Root, b"original Root request")
            .unwrap(),
        Reservation::Retained
    );
    assert!(
        restarted
            .reserve(EXECUTION, Route::Root, b"changed Root request")
            .is_err()
    );
    assert!(
        restarted
            .reserve(EXECUTION, Route::Ordinary, b"original Root request")
            .is_err()
    );
    assert_eq!(restarted.retention_roots().unwrap(), roots);
}

#[test]
fn legacy_foreign_pending_record_cannot_become_another_route_claim() {
    let directory = tempfile::tempdir().unwrap();
    let claims = claims(directory.path());
    let bytes = b"model legacy record";
    let identity = ContentId::for_bytes(ObjectKind::Trace, 1, bytes);
    claims.put(identity, bytes).unwrap();
    let name = RefName::new(format!("node-conditional-preparations/{EXECUTION}")).unwrap();
    claims.refs.compare_exchange(&name, None, identity).unwrap();

    assert!(
        claims
            .reserve(EXECUTION, Route::Capability, b"new request")
            .is_err()
    );
    assert!(
        claims
            .refs
            .read_ref(&claim_ref(EXECUTION).unwrap())
            .unwrap()
            .is_none()
    );
    assert!(claims.retention_roots().unwrap().is_empty());
}

#[test]
fn missing_original_request_body_refuses_retained_claim_and_gc_inventory() {
    let directory = tempfile::tempdir().unwrap();
    let claims = claims(directory.path());
    let missing = ContentId::for_bytes(ObjectKind::Trace, 1, b"omitted bytes");
    let bytes = encode(&Claim {
        format: "crucible.original-node-preparation-claim".into(),
        version: 1,
        execution: EXECUTION.into(),
        route: Route::Ordinary,
        request: missing.encode(),
    })
    .unwrap();
    let identity = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
    claims.put(identity, &bytes).unwrap();
    claims
        .refs
        .compare_exchange(&claim_ref(EXECUTION).unwrap(), None, identity)
        .unwrap();

    assert!(
        claims
            .reserve(EXECUTION, Route::Ordinary, b"omitted bytes")
            .is_err()
    );
    assert!(claims.retention_roots().is_err());
}

#[test]
fn lifetime_credit_refuses_before_new_request_or_claim_publication() {
    let directory = tempfile::tempdir().unwrap();
    let claims = claims(directory.path());
    let bytes = encode(&Quota {
        format: "crucible.original-node-preparation-quota".into(),
        version: 1,
        consumed: MAXIMUM_RECORDS,
    })
    .unwrap();
    let identity = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
    claims.put(identity, &bytes).unwrap();
    claims
        .refs
        .compare_exchange(&quota_ref().unwrap(), None, identity)
        .unwrap();
    let original_roots = claims.retention_roots().unwrap();

    assert!(
        claims
            .reserve(EXECUTION, Route::Ordinary, b"not published")
            .is_err()
    );
    assert!(
        claims
            .refs
            .read_ref(&claim_ref(EXECUTION).unwrap())
            .unwrap()
            .is_none()
    );
    assert!(
        !claims
            .blobs
            .contains(ContentId::for_bytes(ObjectKind::Trace, 1, b"not published"))
            .unwrap()
    );
    assert_eq!(claims.retention_roots().unwrap(), original_roots);
}

#[test]
fn panic_after_common_cas_keeps_original_raw_custody_without_dispatch_permission() {
    let directory = tempfile::tempdir().unwrap();
    let claims = claims(directory.path());
    let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        assert_eq!(
            claims
                .reserve(EXECUTION, Route::Root, b"original Root request")
                .unwrap(),
            Reservation::Original
        );
        panic!("injected failure before the route admission record");
    }));
    assert!(failed.is_err());
    let roots = claims.retention_roots().unwrap();
    assert_eq!(roots.len(), 3);
    assert_eq!(
        claims
            .reserve(EXECUTION, Route::Root, b"original Root request")
            .unwrap(),
        Reservation::Retained
    );
    assert_eq!(claims.retention_roots().unwrap(), roots);
}

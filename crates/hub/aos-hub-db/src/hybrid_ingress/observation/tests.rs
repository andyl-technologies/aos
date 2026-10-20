//! Request-scope isolation, overflow and already-checked context observations.

use super::*;

#[tokio::test]
async fn checks_are_scoped_and_hash_only() {
    record_existing_check("permission_read", &"outside");
    let (reply, observed) = observe_handler(async {
        record_existing_check("permission_read", &("actor", "resource"));
        42
    })
    .await;

    assert_eq!(reply, 42);
    assert!(!observed.incomplete);
    assert_eq!(observed.checks.len(), 1);
    assert_eq!(
        observed.checks[0].checked_context_sha256,
        hex::encode(Sha256::digest(
            serde_json::to_vec(&("actor", "resource")).unwrap()
        ))
    );
    assert!(!serde_json::to_string(&observed)
        .unwrap()
        .contains("resource"));
}

#[tokio::test]
async fn concurrent_and_nested_handlers_do_not_borrow_each_others_checks() {
    let (left, right) = tokio::join!(
        observe_handler(async {
            record_existing_check("permission_read", &1);
            let (_, nested) = observe_handler(async {
                record_existing_check("permission_publish", &2);
            })
            .await;
            assert_eq!(nested.checks.len(), 1);
            assert_eq!(nested.checks[0].kind, "permission_publish");
        }),
        observe_handler(async {
            tokio::task::yield_now().await;
        })
    );

    assert_eq!(left.1.checks.len(), 1);
    assert!(right.1.checks.is_empty());
}

#[tokio::test]
async fn overflow_or_unknown_checks_cannot_produce_complete_context() {
    let (_, overflow) = observe_handler(async {
        for value in 0..=MAX_CHECKS {
            record_existing_check("permission_read", &value);
        }
    })
    .await;
    let (_, unknown) = observe_handler(async {
        record_existing_check("supplied_permission", &true);
    })
    .await;

    assert!(overflow.incomplete);
    assert_eq!(overflow.checks.len(), MAX_CHECKS);
    assert!(unknown.incomplete);
    assert!(unknown.checks.is_empty());
}

#[tokio::test]
async fn refused_context_and_failed_hash_never_become_accepted() {
    let (_, refused) = observe_handler(async {
        record_existing_outcome("browse_registry_read_policy", false, &("private", 7));
    })
    .await;
    let (_, oversized) = observe_handler(async {
        record_existing_check("permission_read", &"x".repeat(MAX_CONTEXT_BYTES));
    })
    .await;

    assert_eq!(refused.checks.len(), 1);
    assert!(!refused.checks[0].accepted);
    assert!(!refused.incomplete);
    assert!(oversized.incomplete);
    assert!(oversized.checks.is_empty());
}

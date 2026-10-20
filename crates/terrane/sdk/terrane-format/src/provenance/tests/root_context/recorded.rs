//! Checks historical policy execution against genuine signed Original scopes.

#![allow(
    clippy::unwrap_used,
    reason = "Fixture failures intentionally panic in tests."
)]

use super::*;
use crate::properties::{selected::Selection, semantics::RecordedContext};

#[test]
fn recorded_scope_verification_preserves_fixed_interpretations_and_original_authority() {
    let (root, bytes) = tree(
        vec![],
        Some(vec![
            Property {
                name: "domain",
                value: b"\x66public",
            },
            Property {
                name: "index-roots",
                value: b"\x81\x00",
            },
        ]),
    );
    let mut record = unsigned_commit();
    record.tree = root;
    let claims = [RequestRoot {
        path: b"/",
        domain: PUBLIC,
    }];
    let original = signed(record.clone(), &claims, "refs/heads/main", vec![]);
    let selection = Selection::Recorded(RecordedContext::new(1, 3, &["index-roots"]).unwrap());
    let mut history = VerifiedHistory::new(MIN_CHUNK);
    history.insert_tree(root, &[(root, bytes)]).unwrap();
    history
        .insert_commit_selected(original.clone(), selection.clone())
        .unwrap();

    let scope = verify_fixture_scope(&mut history, original.identity(), defaults()).unwrap();

    assert_eq!(scope.view(), original.identity());
    assert_eq!(scope.claims().len(), 1);
    assert_eq!(scope.claims()[0].path(), b"/");
    assert_eq!(
        history.view_selection(original.identity()).unwrap(),
        selection
    );
    let context = TrustContext::new(
        &history,
        original.identity(),
        Selector::preset(Preset::Any),
        PUBLIC,
        None,
    )
    .unwrap();
    assert_eq!(context.view_root(), root);
    assert_eq!(context.canonical_context()[1], 3);
    assert!(validate_canonical_context(context.canonical_context()).is_ok());
    assert_eq!(history.commit(&original.identity()).unwrap(), &original);

    // A genuine signature over a different claimed root does not authorize the
    // actual namespace root discovered by complete canonical evidence.
    let outside = [RequestRoot {
        path: b"/missing",
        domain: PUBLIC,
    }];
    let restricted = signed(record, &outside, "refs/heads/main", vec![]);
    history
        .insert_commit_selected(restricted.clone(), selection)
        .unwrap();
    assert!(verify_fixture_scope(&mut history, restricted.identity(), defaults()).is_err());
    assert!(
        history
            .require_verified_context(restricted.identity())
            .is_err()
    );
    assert!(
        TrustContext::new(
            &history,
            restricted.identity(),
            Selector::preset(Preset::Any),
            PUBLIC,
            None
        )
        .is_err()
    );
    assert_eq!(history.commit(&original.identity()).unwrap(), &original);
}

mod historical_execution;

#[path = "recorded_private.rs"]
mod private_cases;

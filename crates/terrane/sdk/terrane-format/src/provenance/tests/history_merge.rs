//! Exercises transactional unions of genuinely checked history contexts.

use super::*;
use crate::{auth::RequestRoot, properties::Defaults, refs::CommitContext, tree_format::Property};

fn defaults() -> Defaults<'static> {
    Defaults {
        store: "test",
        private_domain: "private:history-union",
        home: "west",
    }
}

fn completed(message: &str) -> (VerifiedHistory, VerifiedCommit) {
    completed_selected(message, crate::properties::selected::Selection::Legacy)
}

fn completed_selected(
    message: &str,
    selection: crate::properties::selected::Selection,
) -> (VerifiedHistory, VerifiedCommit) {
    let mut domain = Vec::new();
    crate::cbor::write_text(&mut domain, "public");
    let (root, bytes) = tree(
        vec![item(b"file", entry(b"content"))],
        Some(vec![Property {
            name: "domain",
            value: &domain,
        }]),
    );
    let mut commit = unsigned_commit();
    commit.tree = root;
    commit.message = message.to_string();
    let signed = with_request(|request| {
        let roots = [RequestRoot {
            path: b"/",
            domain: "public",
        }];
        let request = Request {
            roots: &roots,
            ..*request
        };
        commit.profile_pair.commit_context = Some(CommitContext::from_request(&request).unwrap());
        sign_authored(commit, &[9; 32], &issuer_keys(), &request, 4).unwrap()
    });
    let mut history = VerifiedHistory::new(MIN_CHUNK);
    history.insert_tree(root, &[(root, bytes)]).unwrap();
    history
        .insert_commit_selected(signed.clone(), selection)
        .unwrap();
    verify_fixture_scope(&mut history, signed.identity(), defaults()).unwrap();
    (history, signed)
}

fn assert_rejection_preserves(destination: &mut VerifiedHistory, source: &VerifiedHistory) {
    let before = alloc::format!("{destination:?}");
    let original_policies = destination.bootstrap_policies.clone();
    let original_scopes = destination.root_scopes.clone();

    assert!(destination.append_verified(source).is_err());

    assert_eq!(alloc::format!("{destination:?}"), before);
    assert_eq!(destination.bootstrap_policies, original_policies);
    assert_eq!(destination.root_scopes, original_scopes);
}

#[test]
fn prov_history_union_preserves_completed_scopes_and_is_idempotent() {
    let (left, first) = completed("first checked history");
    let (right, second) = completed("second checked history");
    let mut forward = left.clone();
    let mut reverse = right.clone();

    forward.append_verified(&right).unwrap();
    reverse.append_verified(&left).unwrap();

    for signed in [&first, &second] {
        assert_eq!(forward.commit(&signed.identity()), Some(signed));
        assert!(forward.require_verified_context(signed.identity()).is_ok());
        assert!(reverse.require_verified_context(signed.identity()).is_ok());
    }
    assert_eq!(forward.root_scopes, reverse.root_scopes);
    assert_eq!(forward.bootstrap_policies, reverse.bootstrap_policies);
    assert_eq!(forward.commits, reverse.commits);

    let before = alloc::format!("{forward:?}");
    forward.append_verified(&forward.clone()).unwrap();
    assert_eq!(alloc::format!("{forward:?}"), before);
}

#[test]
fn prov_history_union_rejects_unfinished_contexts_on_either_side() {
    let (completed, signed) = completed("completed scope");
    let mut unfinished = completed.clone();
    unfinished.root_scopes.remove(&signed.identity());
    assert!(
        unfinished
            .require_verified_context(signed.identity())
            .is_err()
    );

    assert_rejection_preserves(&mut completed.clone(), &unfinished);
    assert_rejection_preserves(&mut unfinished, &completed);
}

#[test]
fn prov_history_union_rejects_provisional_contexts_on_either_side() {
    let (completed, signed) = completed("completed scope");
    let mut provisional = completed.clone();
    provisional.provisional_scopes.insert(signed.identity());

    assert_rejection_preserves(&mut completed.clone(), &provisional);
    assert_rejection_preserves(&mut provisional, &completed);
}

#[test]
fn prov_history_union_rejects_different_original_verification_contexts() {
    let (original, signed) = completed("same immutable signed record");

    let mut keys = issuer_keys();
    keys[0].retirement = Some(150);
    let roots = [RequestRoot {
        path: b"/",
        domain: "public",
    }];
    let reverified =
        verify_history(signed.commit(), &keys, &roots, &[("refs/heads/main", 4)]).unwrap();
    assert_eq!(reverified.commit(), signed.commit());
    assert_eq!(reverified.identity(), signed.identity());
    assert_ne!(reverified, signed);
    let mut unchanged = original.clone();
    assert!(unchanged.insert_commit(reverified.clone()).is_err());
    assert_eq!(unchanged.commit(&signed.identity()), Some(&signed));

    // A distinct verified context requires an independently assembled history;
    // replacing an immutable context in the original is itself a refusal.
    let mut domain = Vec::new();
    crate::cbor::write_text(&mut domain, "public");
    let (root, bytes) = tree(
        vec![item(b"file", entry(b"content"))],
        Some(vec![Property {
            name: "domain",
            value: &domain,
        }]),
    );
    assert_eq!(root, signed.commit().tree);
    let mut shortened = VerifiedHistory::new(MIN_CHUNK);
    shortened.insert_tree(root, &[(root, bytes)]).unwrap();
    shortened.insert_commit(reverified).unwrap();
    verify_fixture_scope(&mut shortened, signed.identity(), defaults()).unwrap();
    assert!(
        shortened
            .require_verified_context(signed.identity())
            .is_ok()
    );

    assert_rejection_preserves(&mut original.clone(), &shortened);
    assert_rejection_preserves(&mut shortened, &original);
}

#[test]
fn prov_history_union_rejects_different_profile_limits() {
    let (history, _) = completed("completed scope");
    let mut incompatible = VerifiedHistory::new(MIN_CHUNK + 1);

    assert_rejection_preserves(&mut history.clone(), &incompatible);
    assert_rejection_preserves(&mut incompatible, &history);
}

#[test]
fn prov_history_union_rejects_conflicting_tree_interpretations() {
    let (root, bytes) = tree(vec![], None);
    let mut ordinary = VerifiedHistory::new(MIN_CHUNK);
    ordinary
        .insert_tree(root, &[(root, bytes.clone())])
        .unwrap();
    let mut index = VerifiedHistory::new(MIN_CHUNK);
    index
        .insert_index_tree(root, &[(root, bytes.clone())])
        .unwrap();
    let mut overlay = VerifiedHistory::new(MIN_CHUNK);
    overlay.insert_overlay_tree(root, &[(root, bytes)]).unwrap();

    for (left, right) in [
        (&ordinary, &index),
        (&ordinary, &overlay),
        (&index, &overlay),
    ] {
        assert_rejection_preserves(&mut left.clone(), right);
        assert_rejection_preserves(&mut right.clone(), left);
    }
}

#[test]
fn prov_history_union_rejects_conflicting_retained_bootstrap_associations() {
    let (original, signed) = completed("completed bootstrap");
    let mut other = original.clone();
    other.root_scopes.clear();
    other.bootstrap_policies.clear();
    let policy = OriginalBootstrapPolicy {
        authority: "another-original-physical-authority",
        ..fixture_bootstrap()
    };
    verify_root_context_with_bootstrap(
        &mut other,
        signed.identity(),
        defaults(),
        policy.authority,
        policy,
    )
    .unwrap();
    assert!(other.require_verified_context(signed.identity()).is_ok());

    assert_rejection_preserves(&mut original.clone(), &other);
    assert_rejection_preserves(&mut other, &original);
}

#[test]
fn prov_history_union_preserves_exact_historical_selection() {
    use crate::properties::{selected::Selection, semantics::RecordedContext};
    let selected = Selection::Recorded(RecordedContext::new(1, 3, &["index-roots"]).unwrap());
    let (mut destination, _) = completed("legacy receiver");
    let (source, signed) = completed_selected("historical sender", selected.clone());

    destination.append_verified(&source).unwrap();

    assert_eq!(
        destination.view_selection(signed.identity()).unwrap(),
        selected
    );
    let context = TrustContext::new(
        &destination,
        signed.identity(),
        Selector::preset(Preset::Any),
        "public",
        None,
    )
    .unwrap();
    assert_eq!(context.canonical_context()[1], 3);
    assert!(validate_canonical_context(context.canonical_context()).is_ok());
}

#[test]
fn prov_history_union_refuses_reinterpreting_one_view_and_preserves_receiver() {
    use crate::properties::{selected::Selection, semantics::RecordedContext};
    let (mut destination, _) = completed("same immutable view");
    let selected = Selection::Recorded(RecordedContext::new(1, 3, &[]).unwrap());
    let (source, _) = completed_selected("same immutable view", selected);

    assert_rejection_preserves(&mut destination, &source);
}

#[test]
fn prov_recorded_installation_requires_explicit_view_selection() {
    use crate::properties::{selected::Selection, semantics::RecordedContext};
    let (_, signed) = completed("independently verified record");
    let selected = Selection::Recorded(RecordedContext::new(1, 3, &[]).unwrap());
    let mut history = VerifiedHistory::new_selected(MIN_CHUNK, selected.clone());

    assert!(history.insert_commit(signed.clone()).is_err());
    assert!(history.commit(&signed.identity()).is_none());
    history
        .insert_commit_selected(signed.clone(), selected.clone())
        .unwrap();
    assert_eq!(history.view_selection(signed.identity()).unwrap(), selected);
}

#[test]
fn prov_recorded_current_revision_remains_distinct_when_registered_bytes_match() {
    use crate::properties::{selected::Selection, semantics::RecordedContext};
    let first = Selection::Recorded(RecordedContext::new(1, 2, &[]).unwrap());
    let second = Selection::Recorded(RecordedContext::new(1, 3, &[]).unwrap());
    let (left, view) = completed_selected("same signed historical interpretation", first);
    let (right, _) = completed_selected("same signed historical interpretation", second);
    let a = TrustContext::new(
        &left,
        view.identity(),
        Selector::preset(Preset::Any),
        "public",
        None,
    )
    .unwrap();
    let b = TrustContext::new(
        &right,
        view.identity(),
        Selector::preset(Preset::Any),
        "public",
        None,
    )
    .unwrap();

    assert_eq!(a.canonical_context(), b.canonical_context());
    assert_ne!(
        left.view_selection(view.identity()).unwrap(),
        right.view_selection(view.identity()).unwrap()
    );
    assert_rejection_preserves(&mut left.clone(), &right);
}

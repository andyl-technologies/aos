//! Checks addressed native work and fresh refusal after earlier successful admission.

#![allow(
    clippy::unwrap_used,
    reason = "genuine native fixture failures must fail tests"
)]

pub(in crate::guard) mod support;

use crate::ref_advance::tests::{fixture, request_file, request_file_acl, token};
use crate::store::{InvalidReason, RefStore, StoreErrorKind};
use std::error::Error;
use support::{archive_original, fork_request, observed, refresh_retained};
use terrane_format::auth::Verb;
use terrane_format::identity::IdentityKind;

const SOURCE: &str = "refs/heads/_/main";
const CHILD: &str = "refs/heads/_/child";
const PLAINTEXT: &[u8] = b"ordinary admission retains exact immutable witnesses";

#[tokio::test]
async fn fork_admission_uses_one_complete_source_tree_check_and_keeps_path_checks() {
    let coordinator = fixture().await;
    let mut session = coordinator.begin(SOURCE, &token(), "sdk").await.unwrap();
    let ancestor = coordinator
        .advance(
            &mut session,
            request_file(Vec::new(), b"earlier source tree"),
        )
        .await
        .unwrap();
    let head = coordinator
        .advance(&mut session, request_file(vec![ancestor.commit], PLAINTEXT))
        .await
        .unwrap();
    let request = fork_request(coordinator.guard(), head.commit).await;
    let source_tree = coordinator
        .guard()
        .verified_tree(head.commit)
        .await
        .unwrap()
        .evidence
        .root;
    let guard = observed(coordinator.guard());
    let native_reads = coordinator.store().observe_content_for_tests();
    native_reads.reset();

    let admitted = guard.admit_fork(SOURCE, CHILD, 1, request).await.unwrap();

    // Current authorization and complete immutable history use the retained
    // native bucket, bypassing this addressed Commit GET wrapper. Typed native
    // counters observe attempts by kind, not which identities were consumed;
    // the missing ancestor Original below independently checks ancestry closure.
    let physical_reads = native_reads.snapshot();
    assert!(physical_reads.commit_gets >= 2);
    assert!(physical_reads.node_gets > 0);
    assert_eq!(physical_reads.commit_puts, 0);
    assert_eq!(physical_reads.node_puts, 0);
    assert_eq!(guard.store().total_content_reads(IdentityKind::Commit), 0);
    assert_eq!(guard.store().reference_reads(SOURCE), 2);
    assert_eq!(admitted.commit.commit().tree, source_tree);
    assert_eq!(admitted.commit.commit().parents, [head.commit]);
    let source = admitted.source_authorization.as_ref().unwrap();
    assert_eq!(source.record, head);
    assert_eq!(source.reference, SOURCE);
    assert_eq!(source.verb, Verb::Fork);
    assert_eq!(source.paths, [b"/".to_vec()]);
    assert!(admitted.expected.is_none());
    assert!(admitted.uploads.is_empty());
    guard.store().assert_no_effects();
    assert!(coordinator.store().ref_get(CHILD).await.unwrap().is_none());

    // A prior success cannot replace the ancestor's protected Original evidence.
    let next = fork_request(coordinator.guard(), head.commit).await;
    let (original, archived) = archive_original(coordinator.guard(), ancestor.commit).await;
    guard.store().reset();
    let failure = match guard.admit_fork(SOURCE, CHILD, 1, next).await {
        Err(failure) => failure,
        Ok(_) => panic!("missing ancestor Original must refuse fork admission"),
    };
    tokio::fs::rename(&archived, &original).await.unwrap();
    assert!(matches!(
        failure.kind(),
        StoreErrorKind::Unavailable { retry_after: None }
    ));
    assert_eq!(
        failure
            .source()
            .and_then(|source| source.downcast_ref::<std::io::Error>())
            .unwrap()
            .kind(),
        std::io::ErrorKind::NotFound
    );
    guard.store().assert_no_effects();
    assert_eq!(
        coordinator.store().ref_get(SOURCE).await.unwrap(),
        Some(head)
    );
    assert!(coordinator.store().ref_get(CHILD).await.unwrap().is_none());
}

#[tokio::test]
async fn existing_commit_admission_checks_the_exact_parent_once_after_current_authorization() {
    let coordinator = fixture().await;
    let mut session = coordinator.begin(SOURCE, &token(), "sdk").await.unwrap();
    let head = coordinator
        .advance(&mut session, request_file(Vec::new(), PLAINTEXT))
        .await
        .unwrap();
    let root = coordinator
        .guard()
        .verified_tree(head.commit)
        .await
        .unwrap()
        .evidence
        .root;
    let guard = observed(coordinator.guard());
    let native_reads = coordinator.store().observe_content_for_tests();
    native_reads.reset();

    let request = request_file(vec![head.commit], PLAINTEXT);
    assert_eq!(request.commit.tree, root);
    let admitted = guard.admit(SOURCE, session.epoch(), request).await.unwrap();

    // The native factory bypasses the addressed wrapper. These real counters
    // establish work by kind, not an exact identity count or authorization order.
    let physical_reads = native_reads.snapshot();
    assert!(physical_reads.commit_gets > 0);
    assert!(physical_reads.node_gets > 0);
    assert_eq!(guard.store().total_content_reads(IdentityKind::Commit), 0);
    assert_eq!(physical_reads.commit_puts, 0);
    assert_eq!(physical_reads.node_puts, 0);
    assert_eq!(admitted.commit.commit().tree, root);
    assert_eq!(admitted.expected.as_ref(), Some(&head));
    assert_eq!(admitted.commit.commit().parents, [head.commit]);
    guard.store().assert_no_effects();
    assert_eq!(
        coordinator.store().ref_get(SOURCE).await.unwrap(),
        Some(head)
    );
}

#[tokio::test]
async fn fork_admission_rechecks_current_source_acl_after_an_earlier_success() {
    let coordinator = fixture().await;
    let mut session = coordinator.begin(SOURCE, &token(), "sdk").await.unwrap();
    let head = coordinator
        .advance(&mut session, request_file(Vec::new(), PLAINTEXT))
        .await
        .unwrap();
    let first = fork_request(coordinator.guard(), head.commit).await;
    let next = fork_request(coordinator.guard(), head.commit).await;
    let guard = observed(coordinator.guard());
    let admitted = guard.admit_fork(SOURCE, CHILD, 1, first).await.unwrap();
    assert_eq!(admitted.source_authorization.as_ref().unwrap().record, head);

    let revoked = coordinator
        .advance(
            &mut session,
            request_file_acl(vec![head.commit], PLAINTEXT, 0),
        )
        .await
        .unwrap();
    refresh_retained(coordinator.guard(), &guard);
    guard.store().reset();
    let native_reads = coordinator.store().observe_content_for_tests();
    native_reads.reset();
    assert_ne!(revoked.commit, head.commit);
    assert_eq!(
        coordinator.store().ref_get(SOURCE).await.unwrap(),
        Some(revoked.clone())
    );
    let result = guard.admit_fork(SOURCE, CHILD, 1, next).await;

    let Err(failure) = result else {
        panic!("old admission must not retain source authority")
    };
    assert!(
        matches!(failure.kind(), StoreErrorKind::Denied { verb: "fork", pattern } if pattern == SOURCE)
    );
    assert_eq!(guard.store().reference_reads(SOURCE), 1);
    // The genuine current reader must consume the new policy; the ordinary
    // immutable verifier is never reached after current Fork refusal.
    let physical_reads = native_reads.snapshot();
    assert!(physical_reads.commit_gets > 0);
    assert!(physical_reads.node_gets > 0);
    assert_eq!(physical_reads.commit_puts, 0);
    assert_eq!(physical_reads.node_puts, 0);
    assert_eq!(
        guard
            .store()
            .content_reads(IdentityKind::Commit, revoked.commit),
        0
    );
    assert_eq!(
        coordinator.store().ref_get(SOURCE).await.unwrap(),
        Some(revoked)
    );
    guard.store().assert_no_effects();
    assert!(coordinator.store().ref_get(CHILD).await.unwrap().is_none());
}

#[tokio::test]
async fn existing_commit_admission_rechecks_protected_original_association_across_calls() {
    let coordinator = fixture().await;
    let mut session = coordinator.begin(SOURCE, &token(), "sdk").await.unwrap();
    let head = coordinator
        .advance(&mut session, request_file(Vec::new(), PLAINTEXT))
        .await
        .unwrap();
    let guard = observed(coordinator.guard());
    guard
        .admit(
            SOURCE,
            session.epoch(),
            request_file(vec![head.commit], PLAINTEXT),
        )
        .await
        .unwrap();
    let context = coordinator.guard().original_commit(&head.commit).unwrap();
    let hex = head
        .commit
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let association = context
        .baseline()
        .authority()
        .control()
        .join(format!("commit-{hex}.cbor"));
    let archived = association.with_extension("removed");
    tokio::fs::rename(&association, &archived).await.unwrap();
    guard.store().reset();
    let native_reads = coordinator.store().observe_content_for_tests();
    native_reads.reset();

    let result = guard
        .admit(
            SOURCE,
            session.epoch(),
            request_file(vec![head.commit], PLAINTEXT),
        )
        .await;

    let Err(failure) = result else {
        panic!("retained in-memory context must not replace missing physical evidence")
    };
    // OriginalVerifier checks the real association's metadata before its bytes.
    // An absent file retains the native NotFound cause as an unavailable read.
    assert!(
        matches!(
            failure.kind(),
            StoreErrorKind::Unavailable { retry_after: None }
        ),
        "{failure:?}"
    );
    assert_eq!(
        failure
            .source()
            .and_then(|source| source.downcast_ref::<std::io::Error>())
            .unwrap()
            .kind(),
        std::io::ErrorKind::NotFound
    );
    // Native preparation rechecks configured Original pins before starting the
    // historical typed reader; missing evidence must refuse before Commit GETs.
    assert_eq!(native_reads.snapshot().commit_gets, 0);
    guard.store().assert_no_effects();
    assert_eq!(
        coordinator.store().ref_get(SOURCE).await.unwrap(),
        Some(head)
    );
    assert!(!association.exists());
}

/// Builds two independently governed children beneath a parent without Commit rights.
fn child_scope_request(
    parents: Vec<[u8; 32]>,
    child_bytes: &[u8],
    other_bytes: &[u8],
    descriptor: &'static [u8],
    parent_acl: &'static [u8],
    parent_domain: &'static [u8],
) -> crate::guard::CommitRequest {
    use terrane_format::tree_builder::Tree;
    use terrane_format::tree_format::{Attribute, Entry, EntryKind, LeafItem, Property, TreeUse};

    let mut request = request_file(parents.clone(), child_bytes);
    let child = request.commit.tree;
    let other = request_file(parents, other_bytes);
    let graft = |key: &[u8], root| LeafItem {
        key: key.to_vec(),
        entry: Entry {
            kind: EntryKind::Tree {
                root,
                props: Some(vec![Property {
                    name: "store",
                    value: b"\x65local",
                }]),
            },
            attrs: vec![Attribute {
                name: "note",
                value: descriptor,
            }],
            attrs_present: true,
            xattrs: Vec::new(),
            xattrs_present: false,
            provenance: None,
        },
    };
    let parent = Tree::build(
        vec![graft(b"child", child), graft(b"other", other.commit.tree)],
        Some(vec![
            Property {
                name: "acl",
                value: parent_acl,
            },
            Property {
                name: "domain",
                value: parent_domain,
            },
        ]),
        262144,
        TreeUse::Ordinary,
    )
    .unwrap();
    request.commit.tree = parent.root_identity();
    request.uploads.extend(other.uploads);
    request
        .uploads
        .extend(parent.nodes().map(|node| crate::guard::StagedUpload::Meta {
            kind: IdentityKind::Node,
            bytes: node.encoded().to_vec(),
        }));
    request
}

fn child_scope_token() -> (Vec<u8>, [u8; 32]) {
    use terrane_format::auth::{Attenuation, Grant, Token, Verbs};

    let terminal = [0x63; 32];
    let token = Token::decode(&token())
        .unwrap()
        .attenuate(
            Attenuation {
                not_after: None,
                not_before: None,
                grants: Some(vec![
                    Grant::new(format!("{SOURCE}:/child"), Verbs::new(5).unwrap()).unwrap(),
                ]),
                caveats: Vec::new(),
            },
            &crate::ref_advance::tests::secret(),
            terrane_format::auth::public_key_from_secret(&terminal),
        )
        .unwrap()
        .encode();
    (token, terminal)
}

const PARENT_ACL: &[u8] = b"\x81\x82\x66writer\x0b";
const PARENT_DOMAIN: &[u8] = b"\x66public";

#[tokio::test]
async fn native_child_only_commit_preserves_ancestor_descriptor_and_original_scope() {
    use terrane_format::auth::Verb;

    let native = fixture().await;
    let mut baseline = native.begin(SOURCE, &token(), "sdk").await.unwrap();
    let first = native
        .advance(
            &mut baseline,
            child_scope_request(
                Vec::new(),
                b"old child",
                b"stable other",
                b"\x61x",
                PARENT_ACL,
                PARENT_DOMAIN,
            ),
        )
        .await
        .unwrap();
    let (scoped, terminal) = child_scope_token();
    assert!(
        native
            .guard()
            .authorize(SOURCE, &token(), Verb::Commit, &[b"/".to_vec()], "sdk")
            .await
            .is_err()
    );
    assert!(
        native
            .guard()
            .authorize(SOURCE, &scoped, Verb::Commit, &[b"/".to_vec()], "sdk")
            .await
            .is_err()
    );
    let mut session = native
        .begin_scoped(SOURCE, &scoped, &[b"/child".to_vec()], "sdk")
        .await
        .unwrap();
    let mut request = child_scope_request(
        vec![first.commit],
        b"new child",
        b"stable other",
        b"\x61x",
        PARENT_ACL,
        PARENT_DOMAIN,
    );
    request.token = scoped.clone();
    request.terminal_secret = terminal;

    let second = native.advance(&mut session, request).await.unwrap();

    assert_eq!(second.seq, first.seq + 1);
    assert_eq!(
        native.store().ref_get(SOURCE).await.unwrap(),
        Some(second.clone())
    );
    let history = native
        .guard()
        .verified_history(second.commit)
        .await
        .unwrap();
    let verified = history.commit(&second.commit).unwrap();
    let context = verified
        .commit()
        .profile_pair
        .commit_context
        .as_ref()
        .unwrap();
    assert_eq!(context.roots().len(), 1);
    assert_eq!(context.roots()[0].path(), b"/child");
    assert_eq!(context.roots()[0].domain(), "public");
    assert_eq!(
        verified.commit().provenance.embedded_token.as_ref(),
        Some(&scoped)
    );
    let original = native.guard().original_commit(&second.commit).unwrap();
    native
        .guard()
        .revalidate_original_context(&original, crate::guard::HistoryObservation::default())
        .await
        .unwrap();
    let prior = native.guard().verified_tree(first.commit).await.unwrap();
    let after = native.guard().verified_tree(second.commit).await.unwrap();
    let before_tree = prior.evidence.tree(prior.evidence.root, 262144).unwrap();
    let after_tree = after.evidence.tree(after.evidence.root, 262144).unwrap();
    assert_eq!(before_tree.props(), after_tree.props());
    let mut prior_descriptor = before_tree.get(b"child").unwrap().clone();
    let mut next_descriptor = after_tree.get(b"child").unwrap().clone();
    if let terrane_format::tree_format::EntryKind::Tree { root, .. } = &mut prior_descriptor.kind {
        *root = [0; 32];
    }
    if let terrane_format::tree_format::EntryKind::Tree { root, .. } = &mut next_descriptor.kind {
        *root = [0; 32];
    }
    assert_eq!(prior_descriptor, next_descriptor);
    assert_eq!(before_tree.get(b"other"), after_tree.get(b"other"));
}

#[tokio::test]
async fn native_child_only_scope_refuses_descriptor_policy_domain_and_sibling_changes() {
    let native = fixture().await;
    let mut baseline = native.begin(SOURCE, &token(), "sdk").await.unwrap();
    let first = native
        .advance(
            &mut baseline,
            child_scope_request(
                Vec::new(),
                b"old child",
                b"stable other",
                b"\x61x",
                PARENT_ACL,
                PARENT_DOMAIN,
            ),
        )
        .await
        .unwrap();
    let (scoped, terminal) = child_scope_token();
    let guard = observed(native.guard());
    let cases = [
        (
            "descriptor",
            b"new child".as_slice(),
            b"stable other".as_slice(),
            b"\x61y".as_slice(),
            PARENT_ACL,
            PARENT_DOMAIN,
            StoreErrorKind::Denied {
                verb: "commit",
                pattern: SOURCE.into(),
            },
        ),
        (
            "root policy",
            b"new child".as_slice(),
            b"stable other".as_slice(),
            b"\x61x".as_slice(),
            b"\x81\x82\x66writer\x18\x1f".as_slice(),
            PARENT_DOMAIN,
            StoreErrorKind::Denied {
                verb: "admin",
                pattern: SOURCE.into(),
            },
        ),
        (
            "domain",
            b"new child".as_slice(),
            b"stable other".as_slice(),
            b"\x61x".as_slice(),
            PARENT_ACL,
            // The unchanged public children are more open than this private
            // parent. DOM-2 rejects canonical policy before current authority.
            b"\x6cprivate:test".as_slice(),
            StoreErrorKind::Invalid(InvalidReason::MalformedRequest),
        ),
        (
            "sibling",
            b"old child".as_slice(),
            b"changed other".as_slice(),
            b"\x61x".as_slice(),
            PARENT_ACL,
            PARENT_DOMAIN,
            StoreErrorKind::Denied {
                verb: "commit",
                pattern: SOURCE.into(),
            },
        ),
    ];
    for (case, child, other, descriptor, acl, domain, expected) in cases {
        let mut request =
            child_scope_request(vec![first.commit], child, other, descriptor, acl, domain);
        request.token = scoped.clone();
        request.terminal_secret = terminal;
        guard.store().reset();

        let failure = match guard.admit(SOURCE, first.writer_epoch + 1, request).await {
            Err(failure) => failure,
            Ok(_) => panic!("{case} must preserve canonical policy and affected authority checks"),
        };

        assert_eq!(failure.kind(), &expected, "{case}: {failure:?}");
        if case == "domain" {
            assert!(failure.source().is_none(), "{case}: {failure:?}");
        }
        guard.store().assert_no_effects();
        let before = {
            let holder = crate::bucket::held::SingleHeld::acquire(native.store())
                .await
                .unwrap();
            holder
                .destination()
                .observe_publication()
                .await
                .unwrap()
                .stamp()
        };
        let mut session = native
            .begin_scoped(SOURCE, &scoped, &[b"/child".to_vec()], "sdk")
            .await
            .unwrap();
        let mut request =
            child_scope_request(vec![first.commit], child, other, descriptor, acl, domain);
        request.token = scoped.clone();
        request.terminal_secret = terminal;
        let failure = native.advance(&mut session, request).await.unwrap_err();
        let crate::ref_advance::AdvanceError::Store(failure) = failure else {
            panic!("{case}: {failure:?}");
        };
        assert_eq!(failure.kind(), &expected, "{case}: {failure:?}");
        if case == "domain" {
            assert!(failure.source().is_none(), "{case}: {failure:?}");
        }
        let holder = crate::bucket::held::SingleHeld::acquire(native.store())
            .await
            .unwrap();
        assert_eq!(
            holder
                .destination()
                .observe_publication()
                .await
                .unwrap()
                .stamp(),
            before,
            "{case}"
        );
        drop(holder);
        assert_eq!(
            native.store().ref_get(SOURCE).await.unwrap(),
            Some(first.clone())
        );
    }
}

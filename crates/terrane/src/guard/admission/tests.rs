//! Checks addressed native work and fresh refusal after earlier successful admission.

#![allow(
    clippy::unwrap_used,
    reason = "genuine native fixture failures must fail tests"
)]

pub(in crate::guard) mod support;

use crate::ref_advance::tests::{fixture, request_file, request_file_acl, token};
use crate::store::{RefStore, StoreErrorKind};
use std::error::Error;
use support::{fork_request, observed, refresh_retained};
use terrane_core::identity::IdentityKind;

const SOURCE: &str = "refs/heads/_/main";
const CHILD: &str = "refs/heads/_/child";
const PLAINTEXT: &[u8] = b"ordinary admission retains exact immutable witnesses";

#[tokio::test]
async fn fork_admission_uses_one_complete_source_tree_check_and_keeps_path_checks() {
    let coordinator = fixture().await;
    let mut session = coordinator.begin(SOURCE, &token(), "sdk").await.unwrap();
    let head = coordinator
        .advance(&mut session, request_file(Vec::new(), PLAINTEXT))
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

    let admitted = guard.admit_fork(SOURCE, CHILD, 1, request).await.unwrap();

    // Root authorization, exact source verification and root-path authorization
    // each load the target and its complete history. The former standalone
    // history traversal added a seventh addressed commit read.
    assert_eq!(
        guard
            .store()
            .content_reads(IdentityKind::Commit, head.commit),
        6
    );
    assert_eq!(
        guard.store().content_reads(IdentityKind::Node, source_tree),
        7
    );
    assert_eq!(guard.store().reference_reads(SOURCE), 2);
    assert_eq!(admitted.commit.commit().tree, source_tree);
    assert_eq!(admitted.commit.commit().parents, [head.commit]);
    assert_eq!(admitted.source_authorization.as_ref().unwrap().record, head);
    assert!(admitted.uploads.is_empty());
    guard.store().assert_no_effects();
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

    let admitted = guard
        .admit(
            SOURCE,
            session.epoch(),
            request_file(vec![head.commit], PLAINTEXT),
        )
        .await
        .unwrap();

    // Independent current authorization and exact parent verification each
    // perform two addressed reads. The discarded standalone history added one.
    assert_eq!(
        guard
            .store()
            .content_reads(IdentityKind::Commit, head.commit),
        4
    );
    assert_eq!(guard.store().content_reads(IdentityKind::Node, root), 4);
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
    guard.admit_fork(SOURCE, CHILD, 1, first).await.unwrap();

    let revoked = coordinator
        .advance(
            &mut session,
            request_file_acl(vec![head.commit], PLAINTEXT, 0),
        )
        .await
        .unwrap();
    refresh_retained(coordinator.guard(), &guard);
    guard.store().reset();
    let result = guard.admit_fork(SOURCE, CHILD, 1, next).await;

    let Err(failure) = result else {
        panic!("old admission must not retain source authority")
    };
    assert!(
        matches!(failure.kind(), StoreErrorKind::Denied { verb: "fork", pattern } if pattern == SOURCE)
    );
    assert_eq!(guard.store().reference_reads(SOURCE), 1);
    assert!(
        guard
            .store()
            .content_reads(IdentityKind::Commit, revoked.commit)
            > 0
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
    assert!(
        guard
            .store()
            .content_reads(IdentityKind::Commit, head.commit)
            > 0
    );
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
    use terrane_core::tree_builder::Tree;
    use terrane_core::tree_format::{Attribute, Entry, EntryKind, LeafItem, Property, TreeUse};

    let mut request = request_file(parents.clone(), child_bytes);
    let child = request.commit.tree;
    let other = request_file(parents, other_bytes);
    let graft = |key: &[u8], root| LeafItem {
        key: key.to_vec(),
        entry: Entry {
            kind: EntryKind::Tree { root, props: None },
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
    use terrane_core::auth::{Attenuation, Grant, Token, Verbs};

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
            terrane_core::auth::public_key_from_secret(&terminal),
        )
        .unwrap()
        .encode();
    (token, terminal)
}

const PARENT_ACL: &[u8] = b"\x81\x82\x66writer\x0b";
const PARENT_DOMAIN: &[u8] = b"\x66public";

#[tokio::test]
async fn native_child_only_commit_preserves_ancestor_descriptor_and_original_scope() {
    use terrane_core::auth::Verb;

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
    if let terrane_core::tree_format::EntryKind::Tree { root, .. } = &mut prior_descriptor.kind {
        *root = [0; 32];
    }
    if let terrane_core::tree_format::EntryKind::Tree { root, .. } = &mut next_descriptor.kind {
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
            "commit",
        ),
        (
            "root policy",
            b"new child".as_slice(),
            b"stable other".as_slice(),
            b"\x61x".as_slice(),
            b"\x81\x82\x66writer\x18\x1f".as_slice(),
            PARENT_DOMAIN,
            "admin",
        ),
        (
            "domain",
            b"new child".as_slice(),
            b"stable other".as_slice(),
            b"\x61x".as_slice(),
            PARENT_ACL,
            b"\x6cprivate:test".as_slice(),
            "commit",
        ),
        (
            "sibling",
            b"old child".as_slice(),
            b"changed other".as_slice(),
            b"\x61x".as_slice(),
            PARENT_ACL,
            PARENT_DOMAIN,
            "commit",
        ),
    ];
    for (case, child, other, descriptor, acl, domain, verb) in cases {
        let mut request =
            child_scope_request(vec![first.commit], child, other, descriptor, acl, domain);
        request.token = scoped.clone();
        request.terminal_secret = terminal;
        guard.store().reset();

        let failure = match guard.admit(SOURCE, first.writer_epoch + 1, request).await {
            Err(failure) => failure,
            Ok(_) => panic!("{case} must require independently governed affected authority"),
        };

        assert!(
            matches!(failure.kind(), StoreErrorKind::Denied { verb: actual, pattern } if *actual == verb && pattern == SOURCE),
            "{case}: {failure:?}"
        );
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
        assert!(
            matches!(failure, crate::ref_advance::AdvanceError::Store(ref failure)
            if matches!(failure.kind(), StoreErrorKind::Denied { verb: actual, pattern } if *actual == verb && pattern == SOURCE)),
            "{case}: {failure:?}"
        );
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

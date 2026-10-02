//! Exercises immutable-root defaults and explicit ownership preservation.

#![allow(clippy::unwrap_used)]

use super::native_fixture::NativeFixture;
use super::tests::{Validator, config, fixture, raw_fixture, request, secret, token};
use super::{CommitRequest, CommitTiming, Coordinator, StagedUpload};
use crate::bucket::FileBucket;
use crate::guard::Guard;
use crate::store::{ContentStore, LocalFs, RefStore, TokioClock, TokioLocalFs};
use std::time::Duration;
use terrane_core::auth::Verb;
use terrane_core::identity::{IdentityKind, TERRANE_V1};
use terrane_core::tree_builder::Tree;
use terrane_core::tree_format::{Property, TreeUse};

type Bucket = FileBucket<TokioLocalFs, TokioClock, Validator>;

#[tokio::test]
async fn copied_fork_root_widening_requires_destination_bootstrap_admin() {
    let (coordinator, source_record) = bootstrap_fork_source(true).await;
    let source = "refs/heads/_/source";
    let destination = "refs/heads/_/destination";
    let mut candidate = request(Vec::new());
    candidate.uploads.clear();

    for (reference, verb) in [(source, Verb::Fork), (destination, Verb::Commit)] {
        coordinator
            .guard()
            .authorize(reference, &token(), verb, &[], "sdk")
            .await
            .unwrap();
    }
    assert!(
        coordinator
            .guard()
            .authorize(destination, &token(), Verb::Admin, &[], "sdk")
            .await
            .is_err()
    );

    let failure = coordinator
        .guard()
        .admit_fork(source, destination, 1, candidate)
        .await
        .err()
        .unwrap();
    assert!(matches!(
        failure.kind(),
        crate::store::StoreErrorKind::Denied { verb: "admin", .. }
    ));
    let mut publication = request(Vec::new());
    publication.uploads.clear();
    assert!(
        coordinator
            .fork(source, destination, publication)
            .await
            .is_err()
    );
    assert_eq!(
        coordinator.store().ref_get(destination).await.unwrap(),
        None
    );
    assert_eq!(
        coordinator.store().ref_get(source).await.unwrap(),
        Some(source_record)
    );

    tokio::fs::remove_dir_all(coordinator.store().root())
        .await
        .unwrap();
}

#[tokio::test]
async fn copied_fork_root_retaining_bootstrap_needs_only_destination_commit() {
    use terrane_core::auth::{Attenuation, Grant, Token, Verbs};

    let (coordinator, source_record) = bootstrap_fork_source(false).await;
    let destination = "refs/heads/_/destination";
    let mut candidate = request(Vec::new());
    candidate.uploads.clear();
    let terminal = [0x64; 32];
    candidate.token = Token::decode(&token())
        .unwrap()
        .attenuate(
            Attenuation {
                not_after: None,
                not_before: None,
                grants: Some(vec![
                    Grant::new(
                        "refs/heads/_/source".into(),
                        Verbs::new(Verb::Fork as u8).unwrap(),
                    )
                    .unwrap(),
                    Grant::new(destination.into(), Verbs::new(4).unwrap()).unwrap(),
                ]),
                caveats: Vec::new(),
            },
            &secret(),
            terrane_core::auth::public_key_from_secret(&terminal),
        )
        .unwrap()
        .encode();
    candidate.terminal_secret = terminal;

    assert!(
        coordinator
            .guard()
            .authorize(destination, &candidate.token, Verb::Admin, &[], "sdk")
            .await
            .is_err()
    );
    let copied = coordinator
        .fork("refs/heads/_/source", destination, candidate)
        .await
        .unwrap();
    assert_eq!(copied.seq, 1);
    assert_ne!(copied.commit, source_record.commit);

    tokio::fs::remove_dir_all(coordinator.store().root())
        .await
        .unwrap();
}

// The source ACL widens through its independently authorized operator. The
// destination remains governed by its original Commit/Fork writer bootstrap.
async fn bootstrap_fork_source(
    widen: bool,
) -> (NativeFixture<TokioLocalFs>, terrane_core::refs::RefRecord) {
    let original = raw_fixture().await;
    let mut policy = original.guard().config().clone();
    policy.initial_acl = vec![
        ("operator".into(), 31),
        ("writer".into(), Verb::Commit as u8 | Verb::Fork as u8),
    ];
    let coordinator = Coordinator::new(
        Guard::new(
            original.store().clone(),
            TokioClock,
            original.guard().keys().to_vec(),
            policy,
        ),
        CommitTiming::new(
            Duration::from_secs(30),
            Duration::from_secs(60),
            Duration::from_secs(10),
        )
        .unwrap(),
        TokioLocalFs,
    );
    let coordinator = NativeFixture::initialize(coordinator).await;
    let reference = "refs/heads/_/source";
    let mut session = coordinator.begin(reference, &token(), "sdk").await.unwrap();
    let first = coordinator
        .advance(
            &mut session,
            propose(&bootstrap_fork_tree(false), Vec::new()),
        )
        .await
        .unwrap();
    if !widen {
        return (coordinator, first);
    }

    let mut candidate = propose(&bootstrap_fork_tree(true), vec![first.commit]);
    candidate.token = bootstrap_operator_token();
    let mut operator = coordinator
        .begin(reference, &candidate.token, "sdk")
        .await
        .unwrap();
    let changed = coordinator.advance(&mut operator, candidate).await.unwrap();
    (coordinator, changed)
}

fn bootstrap_fork_tree(widen: bool) -> Tree<'static> {
    let acl: &[u8] = if widen {
        b"\x82\x82\x68operator\x18\x1f\x82\x66writer\x18\x1f"
    } else {
        b"\x82\x82\x68operator\x18\x1f\x82\x66writer\x06"
    };
    Tree::build(
        Vec::new(),
        Some(vec![
            Property {
                name: "acl",
                value: acl,
            },
            Property {
                name: "domain",
                value: b"\x66public",
            },
        ]),
        262144,
        TreeUse::Ordinary,
    )
    .unwrap()
}

fn bootstrap_operator_token() -> Vec<u8> {
    use terrane_core::auth::{Authority, Grant, PrincipalKind, Token, Verbs};

    Token::issue(
        Authority {
            issuer: "test".into(),
            key_id: "key".into(),
            subject: "operator".into(),
            kind: PrincipalKind::Human,
            groups: Vec::new(),
            not_after: u64::MAX,
            not_before: None,
            token_id: [2; 16],
            grants: vec![Grant::new("refs/**".into(), Verbs::new(31).unwrap()).unwrap()],
            workload: None,
        },
        &secret(),
        terrane_core::auth::public_key_from_secret(&secret()),
    )
    .unwrap()
    .encode()
}

#[tokio::test]
async fn initial_commit_grant_narrows_bootstrap_admin_without_extra_admin() {
    use terrane_core::auth::{Attenuation, Grant, Token, Verbs};

    let original = raw_fixture().await;
    let mut policy = original.guard().config().clone();
    policy.initial_acl = vec![("writer".into(), 16)];
    let coordinator = Coordinator::new(
        Guard::new(
            original.store().clone(),
            TokioClock,
            original.guard().keys().to_vec(),
            policy,
        ),
        CommitTiming::new(
            Duration::from_secs(30),
            Duration::from_secs(60),
            Duration::from_secs(10),
        )
        .unwrap(),
        TokioLocalFs,
    );
    let coordinator = NativeFixture::initialize(coordinator).await;
    let reference = "refs/heads/_/main";
    let terminal = [0x62; 32];
    let restricted = Token::decode(&token())
        .unwrap()
        .attenuate(
            Attenuation {
                not_after: None,
                not_before: None,
                grants: Some(vec![
                    Grant::new(reference.to_owned(), Verbs::new(4).unwrap()).unwrap(),
                ]),
                caveats: Vec::new(),
            },
            &secret(),
            terrane_core::auth::public_key_from_secret(&terminal),
        )
        .unwrap()
        .encode();
    let tree = Tree::build(
        Vec::new(),
        Some(vec![
            Property {
                name: "acl",
                value: b"\x81\x82\x66writer\x04",
            },
            Property {
                name: "domain",
                value: b"\x66public",
            },
        ]),
        262144,
        TreeUse::Ordinary,
    )
    .unwrap();
    let mut candidate = propose(&tree, Vec::new());
    candidate.token = restricted.clone();
    candidate.terminal_secret = terminal;
    let mut session = coordinator
        .begin(reference, &restricted, "sdk")
        .await
        .unwrap();

    assert!(
        coordinator
            .guard()
            .authorize(reference, &restricted, Verb::Admin, &[], "sdk")
            .await
            .is_err()
    );
    let record = coordinator.advance(&mut session, candidate).await.unwrap();
    assert_eq!(record.seq, 1);

    tokio::fs::remove_dir_all(coordinator.store().root())
        .await
        .unwrap();
}

#[tokio::test]
async fn introduced_child_delegation_uses_its_actual_ancestor_acl() {
    use terrane_core::auth::{Attenuation, Grant, Token, Verbs};
    use terrane_core::tree_format::{Entry, EntryKind, LeafItem};

    let coordinator = fixture().await;
    let reference = "refs/heads/_/main";
    let policy = vec![
        Property {
            name: "acl",
            value: b"\x82\x82\x66reader\x04\x82\x66writer\x04",
        },
        Property {
            name: "domain",
            value: b"\x66public",
        },
    ];
    let child = Tree::build(Vec::new(), Some(policy.clone()), 262144, TreeUse::Ordinary).unwrap();
    let mut first_session = coordinator.begin(reference, &token(), "sdk").await.unwrap();
    let first = coordinator
        .advance(&mut first_session, propose(&child, Vec::new()))
        .await
        .unwrap();
    let terminal = [0x63; 32];
    let restricted = Token::decode(&token())
        .unwrap()
        .attenuate(
            Attenuation {
                not_after: None,
                not_before: None,
                grants: Some(vec![
                    Grant::new(reference.to_owned(), Verbs::new(4).unwrap()).unwrap(),
                ]),
                caveats: Vec::new(),
            },
            &secret(),
            terrane_core::auth::public_key_from_secret(&terminal),
        )
        .unwrap()
        .encode();
    let parent = Tree::build(
        vec![LeafItem {
            key: b"mount".to_vec(),
            entry: Entry {
                kind: EntryKind::Tree {
                    root: child.root_identity(),
                    props: None,
                },
                attrs: Vec::new(),
                attrs_present: false,
                xattrs: Vec::new(),
                xattrs_present: false,
                provenance: None,
            },
        }],
        Some(policy),
        262144,
        TreeUse::Ordinary,
    )
    .unwrap();
    let mut candidate = propose(&parent, vec![first.commit]);
    candidate
        .uploads
        .extend(child.nodes().map(|node| StagedUpload::Meta {
            kind: IdentityKind::Node,
            bytes: node.encoded().to_vec(),
        }));
    candidate.token = restricted.clone();
    candidate.terminal_secret = terminal;
    let mut session = coordinator
        .begin(reference, &restricted, "sdk")
        .await
        .unwrap();

    assert!(
        coordinator
            .guard()
            .authorize(reference, &restricted, Verb::Admin, &[], "sdk")
            .await
            .is_err()
    );
    let second = coordinator.advance(&mut session, candidate).await.unwrap();
    assert_eq!(second.seq, first.seq + 1);

    tokio::fs::remove_dir_all(coordinator.store().root())
        .await
        .unwrap();
}

#[tokio::test]
async fn unsupported_effective_store_is_rejected_before_any_publication() {
    let coordinator = fixture().await;
    let reference = "refs/heads/_/main";
    let tree = Tree::build(
        Vec::new(),
        Some(vec![
            Property {
                name: "acl",
                value: b"\x81\x82\x66writer\x18\x1f",
            },
            Property {
                name: "domain",
                value: b"\x66public",
            },
            Property {
                name: "store",
                value: b"\x65other",
            },
        ]),
        262144,
        TreeUse::Ordinary,
    )
    .unwrap();
    let identity = TERRANE_V1
        .from_digest(IdentityKind::Node, &tree.root_identity())
        .unwrap();
    let mut session = coordinator.begin(reference, &token(), "sdk").await.unwrap();

    assert!(
        coordinator
            .advance(&mut session, propose(&tree, Vec::new()))
            .await
            .is_err()
    );
    assert!(
        coordinator
            .store()
            .ref_get(reference)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(coordinator.store().has(&[identity]).await.unwrap(), [false]);

    tokio::fs::remove_dir_all(coordinator.store().root())
        .await
        .unwrap();
}

async fn reroute(
    source: &Coordinator<Bucket, TokioClock, TokioLocalFs>,
    domain: &str,
) -> NativeFixture<TokioLocalFs> {
    let mut policy = source.guard().config().clone();
    policy.private_domain = "private:configured-bootstrap".into();
    policy.storage_domain = domain.into();
    let nonce = TokioLocalFs.random_bytes(16).await.unwrap();
    let suffix = nonce
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    // Different configured domain pins require distinct physical namespaces.
    let root = source
        .store()
        .root()
        .with_file_name(format!("terrane-domain-{suffix}"));
    let bucket = FileBucket::open(config(root).await, TokioLocalFs, TokioClock, Validator)
        .await
        .unwrap();
    let coordinator = Coordinator::new(
        Guard::new(bucket, TokioClock, source.guard().keys().to_vec(), policy),
        CommitTiming::new(
            Duration::from_secs(30),
            Duration::from_secs(60),
            Duration::from_secs(10),
        )
        .unwrap(),
        TokioLocalFs,
    );
    NativeFixture::initialize(coordinator).await
}

fn propose(tree: &Tree<'_>, parents: Vec<[u8; 32]>) -> CommitRequest {
    let mut candidate = request(parents);
    candidate.commit.tree = tree.root_identity();
    candidate.uploads = tree
        .nodes()
        .map(|node| StagedUpload::Meta {
            kind: IdentityKind::Node,
            bytes: node.encoded().to_vec(),
        })
        .collect();
    candidate
}

#[tokio::test]
async fn implicit_domain_uses_immutable_root_and_edits_preserve_explicit_owner() {
    let original = fixture().await;
    let initial = Tree::build(
        Vec::new(),
        Some(vec![Property {
            name: "acl",
            value: b"\x81\x82\x66writer\x18\x1f",
        }]),
        262144,
        TreeUse::Ordinary,
    )
    .unwrap();
    let identity = TERRANE_V1
        .from_digest(IdentityKind::Node, &initial.root_identity())
        .unwrap();
    let owner = crate::domain::private_default(&identity);
    let reference = "refs/heads/_/main";

    let wrong = reroute(&original, "private:configured-bootstrap").await;
    let mut rejected = wrong.begin(reference, &token(), "sdk").await.unwrap();
    assert!(
        wrong
            .advance(&mut rejected, propose(&initial, Vec::new()))
            .await
            .is_err()
    );
    assert_eq!(wrong.store().ref_get(reference).await.unwrap(), None);
    assert_eq!(wrong.store().has(&[identity]).await.unwrap(), vec![false]);

    let matching = reroute(&original, &owner).await;
    let mut session = matching.begin(reference, &token(), "sdk").await.unwrap();
    let first = matching
        .advance(&mut session, propose(&initial, Vec::new()))
        .await
        .unwrap();
    let access = matching
        .guard()
        .domain_access(reference, &token(), Verb::Read, b"/", "sdk")
        .await
        .unwrap();
    assert_eq!(access.binding().domain, owner);
    let verified = matching.guard().verified_tree(first.commit).await.unwrap();
    assert_eq!(
        verified
            .commit
            .commit()
            .profile_pair
            .commit_context
            .as_ref()
            .unwrap()
            .roots()[0]
            .domain(),
        owner
    );

    let unrelated = Tree::build(
        Vec::new(),
        Some(vec![
            Property {
                name: "acl",
                value: b"\x81\x82\x66writer\x18\x1f",
            },
            Property {
                name: "durability",
                value: b"\x65local",
            },
        ]),
        262144,
        TreeUse::Ordinary,
    )
    .unwrap();
    assert_ne!(unrelated.root_identity(), initial.root_identity());
    assert!(
        matching
            .advance(&mut session, propose(&unrelated, vec![first.commit]))
            .await
            .is_err()
    );
    assert_eq!(
        matching.store().ref_get(reference).await.unwrap(),
        Some(first.clone())
    );

    let mut encoded_domain = Vec::new();
    terrane_core::cbor::write_text(&mut encoded_domain, &owner);
    let preserved = Tree::build(
        Vec::new(),
        Some(vec![
            Property {
                name: "acl",
                value: b"\x81\x82\x66writer\x18\x1f",
            },
            Property {
                name: "domain",
                value: &encoded_domain,
            },
            Property {
                name: "durability",
                value: b"\x65local",
            },
        ]),
        262144,
        TreeUse::Ordinary,
    )
    .unwrap();
    let second = matching
        .advance(&mut session, propose(&preserved, vec![first.commit]))
        .await
        .unwrap();
    assert_eq!(second.seq, first.seq + 1);
    let bucket = FileBucket::open(
        config(matching.store().root().to_owned()).await,
        TokioLocalFs,
        TokioClock,
        Validator,
    )
    .await
    .unwrap();
    let reopened = Coordinator::new(
        Guard::new(
            bucket,
            TokioClock,
            matching.guard().keys().to_vec(),
            matching.guard().config().clone(),
        ),
        CommitTiming::new(
            Duration::from_secs(30),
            Duration::from_secs(60),
            Duration::from_secs(10),
        )
        .unwrap(),
        TokioLocalFs,
    );
    let reopened = NativeFixture::reopen(reopened).await;
    let access = reopened
        .guard()
        .domain_access(reference, &token(), Verb::Read, b"/", "sdk")
        .await
        .unwrap();
    assert_eq!(access.binding().domain, owner);
    assert_eq!(access.reference_record(), Some(&second));
}

#[tokio::test]
async fn initial_domain_caveats_use_physical_scope_and_actual_candidate_domain() {
    use terrane_core::auth::{Attenuation, Caveat, Token};

    let original = fixture().await;
    let coordinator = reroute(&original, "public").await;
    let reference = "refs/heads/_/main";
    let terminal_secret = [0x57; 32];
    let terminal_public = terrane_core::auth::public_key_from_secret(&terminal_secret);
    let scoped = |domain: &str| {
        Token::decode(&token())
            .unwrap()
            .attenuate(
                Attenuation {
                    not_after: None,
                    not_before: None,
                    grants: None,
                    caveats: vec![Caveat::Domain(domain.into())],
                },
                &secret(),
                terminal_public,
            )
            .unwrap()
            .encode()
    };
    let wrong = scoped("private:configured-bootstrap");
    assert!(coordinator.begin(reference, &wrong, "sdk").await.is_err());
    let public = scoped("public");
    let mut session = coordinator.begin(reference, &public, "sdk").await.unwrap();

    let implicit = Tree::build(
        Vec::new(),
        Some(vec![Property {
            name: "acl",
            value: b"\x81\x82\x66writer\x18\x1f",
        }]),
        262144,
        TreeUse::Ordinary,
    )
    .unwrap();
    let mut mismatch = propose(&implicit, Vec::new());
    mismatch.token = public.clone();
    mismatch.terminal_secret = terminal_secret;
    assert!(coordinator.advance(&mut session, mismatch).await.is_err());
    assert_eq!(coordinator.store().ref_get(reference).await.unwrap(), None);

    let mut explicit = request(Vec::new());
    explicit.token = public.clone();
    explicit.terminal_secret = terminal_secret;
    let published = coordinator.advance(&mut session, explicit).await.unwrap();
    assert_eq!(published.seq, 1);
    let authorized = coordinator
        .guard()
        .domain_access(reference, &public, Verb::Read, b"/", "sdk")
        .await
        .unwrap();
    assert_eq!(authorized.binding().domain, "public");
    assert_eq!(authorized.reference_record(), Some(&published));
}

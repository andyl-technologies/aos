//! Retains inert later property bytes through genuine historical collection.

use super::*;
use crate::guard::AuthoringNamespaceProfile;
use crate::store::RefStore;
use terrane_format::gc::RootReason;
use terrane_format::properties::selected::Selection;
use terrane_format::properties::semantics::RecordedContext;
use terrane_format::refs::{RefPolicy, Retention};

const REFERENCE: &str = "refs/heads/_/preserved";
const COUNT: &[u8] = b"\x82\x65count\x01";
const EMPTY_BINDING: &[u8] = b"\xa2\x65value\xa0\x67inherit\xf4";

/// Constructs ordinary root and graft bytes independently of their later meaning.
fn namespace<'a>(
    root_binding: Option<&'a [u8]>,
    child_binding: Option<&'a [u8]>,
    override_binding: Option<&'a [u8]>,
) -> (Tree<'a>, Tree<'a>) {
    let child = Tree::build(
        vec![LeafItem {
            key: b"file".to_vec(),
            entry: entry(b"preserved child data"),
        }],
        child_binding.map(|value| {
            vec![Property {
                name: "index-roots",
                value,
            }]
        }),
        262144,
        TreeUse::Ordinary,
    )
    .assert_success();
    let mut root_props = vec![
        Property {
            name: "acl",
            value: b"\x81\x82\x66writer\x18\x1f",
        },
        Property {
            name: "domain",
            value: b"\x66public",
        },
        Property {
            name: "reflog_retain",
            value: COUNT,
        },
    ];
    if let Some(value) = root_binding {
        root_props.push(Property {
            name: "index-roots",
            value,
        });
    }
    let graft = Entry {
        kind: EntryKind::Tree {
            root: child.root_identity(),
            props: override_binding.map(|value| {
                vec![Property {
                    name: "index-roots",
                    value,
                }]
            }),
        },
        attrs: Vec::new(),
        attrs_present: false,
        xattrs: Vec::new(),
        xattrs_present: false,
        provenance: None,
    };
    let root = Tree::build(
        vec![LeafItem {
            key: b"graft".to_vec(),
            entry: graft,
        }],
        Some(root_props),
        262144,
        TreeUse::Ordinary,
    )
    .assert_success();
    (root, child)
}

/// Supplies only actual ordinary namespace metadata and its declared data chunk.
async fn namespace_request(fixture: &Fixture, root: &Tree<'_>, child: &Tree<'_>) -> CommitRequest {
    let mut request = proposal(fixture, root, None, &[b"preserved child data"]).await;
    request
        .uploads
        .extend(child.nodes().map(|node| StagedUpload::Meta {
            kind: IdentityKind::Node,
            bytes: node.encoded().to_vec(),
        }));
    request
}

/// Checks preserved root and graft values under an independently selected old view.
///
/// # Panics
/// Panics if genuine native publication, current collection or any oracle fails.
pub(super) async fn recorded_preservation_keeps_inert_index_bindings() {
    // Initialize the protected current vocabulary as revision 3 before any
    // native Guard installation. Historical authoring inputs may vary without
    // replacing that current configuration or its genuine Original evidence.
    let mut fixture = Fixture::new_indexed().await;
    let current_snapshot = ConsumedResolver::new(fixture.guard(), &fixture.authority)
        .assert_success()
        .snapshot_bytes()
        .assert_success();
    fixture.authoring =
        Some(AuthoringNamespaceProfile::new(1, 3, &["index-roots"], 2).assert_success());
    let repository = production_repository(&fixture).await;
    assert_eq!(
        ConsumedResolver::new(repository.coordinator().guard(), &fixture.authority)
            .assert_success()
            .snapshot_bytes()
            .assert_success(),
        current_snapshot
    );
    let (root, child) = namespace(Some(b"\x00"), Some(b"\x00"), Some(b"\x00"));
    let mut request = namespace_request(&fixture, &root, &child).await;
    request.commit.parents.clear();
    let mut writer = repository
        .begin(REFERENCE, &token(&fixture), "sdk")
        .await
        .assert_success();
    let head = repository
        .commit_request(&mut writer, request)
        .await
        .assert_success();
    assert_eq!(head.commit, writer.record().assert_success().commit);
    let node_bytes = [root.clone(), child.clone()]
        .iter()
        .flat_map(|tree| tree.nodes())
        .map(|node| (node.identity(), node.encoded().to_vec()))
        .collect::<BTreeMap<_, _>>();
    let selections = crate::gc::runner::fixture::capture_view_selections(
        repository.coordinator().guard(),
        &[head.commit, fixture.head.commit],
    )
    .await;
    let (selected, _) = repository
        .coordinator()
        .guard()
        .selected_view_context_for_tests(head.commit, root.root_identity())
        .assert_success();
    assert_eq!(
        selected,
        Selection::Recorded(RecordedContext::new(1, 3, &["index-roots"]).assert_success())
    );
    drop(repository);

    // New authoring now uses revision 3 while protected current inputs stay
    // exact. Historical interpretation comes from independently captured rows.
    fixture.authoring = Some(AuthoringNamespaceProfile::new(3, 3, &[], 2).assert_success());
    let repository = production_repository_with_selections(&fixture, selections).await;
    let guard = repository.coordinator().guard();
    assert_eq!(
        ConsumedResolver::new(guard, &fixture.authority)
            .assert_success()
            .snapshot_bytes()
            .assert_success(),
        current_snapshot
    );
    assert_eq!(
        guard.semantic_selection(),
        Selection::Recorded(RecordedContext::new(3, 3, &[]).assert_success())
    );
    let (selected_after, _) = guard
        .selected_view_context_for_tests(head.commit, root.root_identity())
        .assert_success();
    assert_eq!(selected_after, selected);
    let verified = guard.verified_tree(head.commit).await.assert_success();
    for (hash, bytes) in &node_bytes {
        assert_eq!(verified.evidence.nodes.get(hash), Some(bytes));
    }
    let mut collection = Collection::start(
        guard,
        &fixture.authority,
        "collector".into(),
        1_000,
        1,
        windows(),
    )
    .await
    .assert_success();
    assert!(collection.roots().roots.iter().any(|row| {
        row.reference.as_str() == REFERENCE
            && row.commit == head.commit
            && row.reason == RootReason::ReflogCount
            && row.parent_cutoff == ParentCutoff::RootsOnly
    }));
    let holder = SingleHeld::acquire(guard.store()).await.assert_success();
    let held = holder.destination();
    let observed = held.observe_publication_unrepaired().await.assert_success();
    let adapted = crate::guard::collection_authority::historical_guard(
        guard,
        &held,
        &observed,
        &collection.session,
        collection.session.clock().assert_success(),
    )
    .assert_success();
    let consumed = ConsumedResolver::new(guard, &fixture.authority).assert_success();
    let observation = HistoryObservation::held(observed.identity()).tracked(&consumed);
    let roots = crate::selected_bridge::native_collection_roots::current(
        &adapted,
        &consumed,
        &held,
        &observed,
        &collection.session,
        (1, windows()),
    )
    .await
    .assert_success();
    let paths = arm_data_reads(&fixture, adapted.store()).await;
    let mut state = crate::gc::runner::roots::initial(roots.snapshot());
    let mut marks = BTreeSet::new();

    while !state.pending.is_empty() {
        expand(
            &adapted,
            &consumed,
            observation,
            &roots,
            &mut state,
            &mut marks,
        )
        .await
        .assert_success();
    }

    assert!(marks.contains(&digest(IdentityKind::Chunk, b"preserved child data")));
    for (node, path) in [
        (root.root_identity(), b"/".as_slice()),
        (child.root_identity(), b"/graft".as_slice()),
    ] {
        let context = ProofContext::new(head.commit, node, path.to_vec()).assert_success();
        assert!(state.expanded.contains(&ExpandedContext {
            commit: head.commit,
            parent_cutoff: ParentCutoff::RootsOnly,
            proof_context: Some(context.clone()),
        }));
        assert!(state.objects.iter().any(|object| object.kind == 2
            && object.hash == node
            && object.flags == ROOT
            && object.proof_context.as_ref() == Some(&context)));
        assert!(
            state
                .objects
                .iter()
                .filter(|object| object.proof_context.as_ref() == Some(&context))
                .all(|object| object.flags & INDEX == 0)
        );
    }
    let namespace_nodes = verified
        .evidence
        .nodes
        .keys()
        .copied()
        .chain(
            roots
                .history(&fixture.head.commit)
                .assert_success()
                .assert_success()
                .tree()
                .evidence
                .nodes
                .keys()
                .copied(),
        )
        .collect::<BTreeSet<_>>();
    for identity in adapted.store().identities().assert_success() {
        match identity.kind() {
            IdentityKind::Node => {
                assert!(namespace_nodes.contains(&identity.terrane_v1_digest().assert_success()))
            }
            IdentityKind::Commit => {}
            other => panic!("inert bindings introduced an auxiliary GET: {other:?}"),
        }
    }
    observed.revalidate().await.assert_success();
    prove_data_read_traps(&fixture, &paths).await;
    drop(roots);
    drop(adapted);
    drop(observed);
    drop(held);
    drop(holder);

    collection.mark_batch(512).await.assert_success();
    assert!(collection.state().pending.is_empty());
    let after = guard.verified_tree(head.commit).await.assert_success();
    for (hash, bytes) in &node_bytes {
        assert_eq!(after.evidence.nodes.get(hash), Some(bytes));
    }
    assert_eq!(
        guard
            .selected_view_context_for_tests(head.commit, root.root_identity())
            .assert_success()
            .0,
        selected
    );
    let original_ref = guard.store().ref_get(REFERENCE).await.assert_success();

    // Active semantics reject both malformed owner values and well-formed
    // structural bindings placed on graft overrides before publication.
    for (name, candidate) in [
        (
            "active malformed owner value",
            namespace(Some(b"\x00"), None, None),
        ),
        (
            "active graft binding placement",
            namespace(None, None, Some(EMPTY_BINDING)),
        ),
    ] {
        let mut request = namespace_request(&fixture, &candidate.0, &candidate.1).await;
        request.commit.parents = vec![head.commit];
        let mut writer = repository
            .begin(REFERENCE, &token(&fixture), "sdk")
            .await
            .assert_success();
        let failure = repository
            .commit_request(&mut writer, request)
            .await
            .assert_failure();
        let crate::repository::Error::Advance(crate::ref_advance::AdvanceError::Store(failure)) =
            failure
        else {
            panic!("{name}: expected an actual Store failure, observed {failure:?}");
        };
        assert_eq!(
            failure.kind(),
            &StoreErrorKind::Invalid(InvalidReason::MalformedRequest),
            "{name}"
        );
        assert_eq!(
            guard.store().ref_get(REFERENCE).await.assert_success(),
            original_ref,
            "{name}"
        );
    }
    assert_eq!(
        guard
            .selected_view_context_for_tests(head.commit, root.root_identity())
            .assert_success()
            .0,
        selected
    );
    fixture.fs.forbid_data_body_reads(&[]).assert_success();
    let active = namespace(None, None, None);
    let mut request = namespace_request(&fixture, &active.0, &active.1).await;
    request.commit.parents = vec![head.commit];
    let mut writer = repository
        .begin(REFERENCE, &token(&fixture), "sdk")
        .await
        .assert_success();
    let active_head = repository
        .commit_request(&mut writer, request)
        .await
        .assert_success();
    assert_eq!(
        guard
            .selected_view_context_for_tests(active_head.commit, active.0.root_identity())
            .assert_success()
            .0,
        Selection::Recorded(RecordedContext::new(3, 3, &[]).assert_success())
    );

    let restored = repository
        .coordinator()
        .rollback(&mut writer, head.commit, &token(&fixture), "sdk")
        .await
        .assert_success();
    assert_eq!(restored.commit, head.commit);

    let overridden = repository
        .coordinator()
        .set_policy(
            REFERENCE,
            Some(RefPolicy {
                retention: Some(Retention::Forever),
                ..RefPolicy::default()
            }),
            &token(&fixture),
            "sdk",
        )
        .await
        .assert_success();
    assert_eq!(overridden.commit, head.commit);
    let holder = SingleHeld::acquire(guard.store()).await.assert_success();
    let held = holder.destination();
    let observed = held.observe_publication_unrepaired().await.assert_success();
    let adapted = crate::guard::collection_authority::historical_guard(
        guard,
        &held,
        &observed,
        &collection.session,
        collection.session.clock().assert_success(),
    )
    .assert_success();
    let consumed = ConsumedResolver::new(guard, &fixture.authority).assert_success();
    let current = crate::selected_bridge::native_collection_roots::current(
        &adapted,
        &consumed,
        &held,
        &observed,
        &collection.session,
        (1, windows()),
    )
    .await
    .assert_success();
    assert!(current.snapshot().roots.iter().any(|row| {
        row.reference.as_str() == REFERENCE
            && row.commit == head.commit
            && row.parent_cutoff == ParentCutoff::Unbounded
    }));
    observed.revalidate().await.assert_success();
    drop(current);
    drop(adapted);
    drop(observed);
    drop(held);
    drop(holder);
    drop(collection);
    drop(repository);
    fixture.cleanup();
}

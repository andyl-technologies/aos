//! Checks actual signed historical completion and isolated immutable relationships.
//!
//! Native cases retain genuine Original controls. Literal cases independently
//! predict complete I/P/G bytes and finite failures without constructing authority.

use std::collections::BTreeSet;
use std::error::Error as _;

use crate::guard::{
    AuthoringNamespaceProfile, ConsumedResolver, HistoryObservation, StagedUpload, TreeEvidence,
};
use crate::indexing::{Error, ErrorKind};
use crate::store::{CorruptSubject, StoreErrorKind, StoreFailure};
use terrane_format::gc::publication::evidence::ViewInterpretationMode;
use terrane_format::identity::{IdentityKind, TERRANE_V1};

mod native;
mod wire;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Requires the fixture's expected present value and keeps failure as a panic.
trait Required {
    type Value;

    /// Returns the expected value.
    ///
    /// # Panics
    /// Panics when a fixture result is Err or an expected option is None.
    fn required(self) -> Self::Value;
}

impl<T, E: std::fmt::Debug> Required for Result<T, E> {
    type Value = T;

    fn required(self) -> T {
        match self {
            Ok(value) => value,
            Err(error) => panic!("historical fixture unexpectedly failed: {error:?}"),
        }
    }
}

impl<T> Required for Option<T> {
    type Value = T;

    fn required(self) -> T {
        match self {
            Some(value) => value,
            None => panic!("historical fixture omitted an expected value"),
        }
    }
}

/// Requires refusal without changing the original error or its source chain.
trait Rejected {
    type Failure;

    /// Returns the original expected failure for subsequent exact assertions.
    ///
    /// # Panics
    /// Panics when the validation unexpectedly succeeds.
    fn rejected(self) -> Self::Failure;
}

impl<T, E> Rejected for Result<T, E> {
    type Failure = E;

    fn rejected(self) -> E {
        match self {
            Err(error) => error,
            Ok(_) => panic!("historical validation unexpectedly succeeded"),
        }
    }
}

async fn check(
    graph: &wire::Graph,
    store: &native::Memory,
    required: bool,
) -> Result<(), StoreFailure> {
    let evidence = TreeEvidence::load_tree(store, graph.owner, &[], wire::MINIMUM).await?;
    super::verify(
        store,
        &evidence,
        &[],
        &native::profile(),
        if required {
            vec![(graph.owner, "uid".into())]
        } else {
            Vec::new()
        },
        wire::MINIMUM,
    )
    .await
}

fn index_error(failure: &StoreFailure) -> &Error {
    failure
        .source()
        .required()
        .downcast_ref::<Error>()
        .required()
}

#[tokio::test]
async fn historical_index_completion_validates_real_signed_owner_and_full_carriers() -> TestResult {
    let fixture = native::Fixture::new(
        wire::Graph::small(),
        AuthoringNamespaceProfile::new(1, 3, &["index-roots"], 1)?,
    )
    .await?;
    let guard = fixture.guard(2).await?;
    let before = native::selected(&fixture.repository).await?;

    let inputs = native::complete(&guard, &fixture.commit).await?;
    let contexts = inputs
        .view_interpretations
        .as_ref()
        .ok_or("completed context absent")?;
    assert_eq!(contexts.len(), 1);
    assert_eq!(contexts[0].view, fixture.commit.identity());
    assert_eq!(contexts[0].original_root, fixture.graph.owner);
    assert_eq!(contexts[0].mode, ViewInterpretationMode::Recorded);
    assert_eq!(contexts[0].registries.property_revision, 3);
    assert_eq!(contexts[0].registries.attribute_revision, 2);
    // The enclosing configured Guard snapshot remains its actual revision 1;
    // only this independently installed and executed view context records 2.
    assert_eq!(inputs.registries.attribute_revision, 1);
    assert_eq!(contexts[0].registries.tree_revision, 1);
    assert_eq!(contexts[0].registries.later_properties, ["future-name"]);
    assert_eq!(inputs.views[0].roots[0].path, b"/");

    let actual = guard.store().node_reads();
    let expected = BTreeSet::from([
        fixture.graph.owner,
        fixture.graph.primary,
        fixture.graph.gap,
        fixture.graph.present,
        fixture.graph.missing,
    ]);
    assert_eq!(
        actual.iter().map(|(id, _)| *id).collect::<BTreeSet<_>>(),
        expected
    );
    for (node, bytes) in actual {
        assert_eq!(bytes, fixture.graph.nodes[&node].len());
    }
    guard.store().assert_read_only();
    native::unchanged(&fixture, &before).await
}

#[tokio::test]
async fn historical_index_completion_preserves_repeated_occurrence_policy_contexts() -> TestResult {
    let fixture = native::Fixture::new(
        wire::Graph::repeated(),
        AuthoringNamespaceProfile::new(1, 3, &["index-roots"], 1)?,
    )
    .await?;
    let guard = fixture.guard(2).await?;
    let before = native::selected(&fixture.repository).await?;

    let inputs = native::complete(&guard, &fixture.commit).await?;
    let roots = &inputs.views[0].roots;
    assert_eq!(
        roots
            .iter()
            .map(|row| row.path.clone())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([b"/".to_vec(), b"/g".to_vec(), b"/h".to_vec()])
    );
    let g = roots.iter().find(|row| row.path == b"/g").required();
    let h = roots.iter().find(|row| row.path == b"/h").required();
    assert_eq!(Some(g.root), fixture.graph.child);
    assert_eq!(g.root, h.root);
    assert_eq!(g.layers.len(), 2);
    assert_eq!(h.layers.len(), 2);
    assert_eq!(g.layers[1].properties, h.layers[1].properties);
    assert_eq!(
        g.layers[1].overrides,
        wire::properties(vec![("index", wire::names(&["uid"]))])
    );
    assert_eq!(
        h.layers[1].overrides,
        wire::properties(vec![("index", wire::names(&[]))])
    );
    assert_eq!(inputs.view_interpretations.as_ref().required().len(), 1);
    let memory = native::Memory::new(fixture.graph.nodes.clone());
    let evidence =
        TreeEvidence::load_tree(&memory, fixture.graph.owner, &[], wire::MINIMUM).await?;
    let interpretation = guard.select_view(
        fixture.commit.identity(),
        fixture.graph.owner,
        HistoryObservation::default(),
    )?;
    for occurrence in evidence.occurrences(wire::MINIMUM)? {
        let layers = occurrence
            .layers
            .iter()
            .map(
                |(properties, overrides)| terrane_format::properties::RootLayer {
                    properties,
                    overrides,
                },
            )
            .collect::<Vec<_>>();
        let effective = interpretation.resolve(&layers, guard.defaults_for(&evidence))?;
        let expected: &[&str] = if occurrence.path == b"/h" {
            &[]
        } else {
            &["uid"]
        };
        assert_eq!(
            effective.get(terrane_format::properties::PropertyName::Index),
            Some(&terrane_format::properties::Value::Names(expected.to_vec()))
        );
    }
    guard.store().assert_read_only();
    native::unchanged(&fixture, &before).await
}

#[tokio::test]
async fn historical_index_completion_refuses_divergent_or_incomplete_relationships() -> TestResult {
    let baseline = wire::Graph::small();
    check(
        &baseline,
        &native::Memory::new(baseline.nodes.clone()),
        true,
    )
    .await?;

    for role in [
        baseline.primary,
        baseline.present,
        baseline.gap,
        baseline.missing,
    ] {
        let id = TERRANE_V1.from_digest(IdentityKind::Node, &role)?;
        for kind in [
            StoreErrorKind::Absent(id.clone()),
            StoreErrorKind::Unavailable { retry_after: None },
            StoreErrorKind::Corrupt(CorruptSubject::Identity(id.clone())),
        ] {
            let mut store = native::Memory::new(baseline.nodes.clone());
            store.failure = Some((role, kind.clone()));
            let failure = check(&baseline, &store, true).await.rejected();
            assert_eq!(failure.kind(), &kind);
            let original = index_error(&failure);
            assert_eq!(original.subject(), Some(role));
            assert!(original.source().required().source().is_some());
        }
        let mut wrong = native::Memory::new(baseline.nodes.clone());
        wrong.nodes.insert(role, wire::leaf(&[], None));
        let failure = check(&baseline, &wrong, true).await.rejected();
        assert_eq!(index_error(&failure).kind(), ErrorKind::Invalid);
        assert_eq!(index_error(&failure).subject(), Some(role));
    }

    // The changed route and primary are independently readdressed, so this is
    // a valid-carrier relationship failure rather than a digest mismatch.
    let mut divergent = baseline.clone();
    let present = wire::insert(
        &mut divergent.nodes,
        wire::leaf(&[(b"z".to_vec(), wire::terminal(divergent.object))], None),
    );
    let mut key = vec![1];
    key.extend_from_slice(&divergent.object);
    let primary = wire::insert(
        &mut divergent.nodes,
        wire::leaf(
            &[(key, wire::forward(divergent.object, present))],
            Some(wire::properties(vec![(
                "index-gaps",
                wire::wrapper(wire::text(&wire::hex(divergent.gap)), false),
            )])),
        ),
    );
    divergent.rebind(Some(primary), true);
    let failure = check(
        &divergent,
        &native::Memory::new(divergent.nodes.clone()),
        true,
    )
    .await
    .rejected();
    assert_eq!(index_error(&failure).kind(), ErrorKind::Invalid);
    Ok(())
}

#[tokio::test]
async fn historical_index_completion_keeps_missing_binding_and_conflict_incomplete() -> TestResult {
    let mut missing = wire::Graph::small();
    missing.rebind(None, true);
    let store = native::Memory::new(missing.nodes.clone());
    check(&missing, &store, true).await?;
    let absent = crate::indexing::load(
        &store,
        missing.owner,
        "uid",
        crate::indexing::SemanticRevisions {
            property: 3,
            attribute: 2,
            tree: 1,
        },
        wire::MINIMUM,
    )
    .await
    .rejected();
    assert!(matches!(absent, Error::MissingBinding(owner) if owner == missing.owner));
    assert!(
        store
            .reads
            .lock()
            .required()
            .iter()
            .all(|(node, _)| *node == missing.owner)
    );

    let fixture = native::Fixture::new(
        missing.clone(),
        AuthoringNamespaceProfile::new(1, 3, &["index-roots"], 1)?,
    )
    .await?;
    let guard = fixture.guard(2).await?;
    let before = native::selected(&fixture.repository).await?;
    let original = guard.original_commit(&fixture.commit.identity())?;
    let consumed = ConsumedResolver::new(&guard, original.baseline().authority())?;
    guard
        .verified_history_observed(
            fixture.commit.identity(),
            HistoryObservation::default().tracked(&consumed),
        )
        .await?;
    assert!(!consumed.finish()?.views.is_empty());
    guard.store().assert_read_only();
    native::unchanged(&fixture, &before).await?;

    let mut conflict = wire::Graph::small();
    let mut entry = vec![0xa2, 1, 6, 12, 0x82];
    entry.extend(wire::file(conflict.object, Some(1)));
    entry.extend(wire::file(conflict.object, Some(2)));
    conflict.rows[0].1 = entry;
    conflict.rebind(Some(conflict.primary), true);
    let failure = check(
        &conflict,
        &native::Memory::new(conflict.nodes.clone()),
        true,
    )
    .await
    .rejected();
    assert_eq!(failure.kind(), &StoreErrorKind::Unsupported);
    assert_eq!(index_error(&failure).kind(), ErrorKind::Incomplete);
    Ok(())
}

#[tokio::test]
async fn historical_index_completion_uses_independently_installed_attribute_profile() -> TestResult
{
    let fixture = native::Fixture::new(
        wire::Graph::small(),
        AuthoringNamespaceProfile::new(1, 3, &["index-roots"], 1)?,
    )
    .await?;
    let old = fixture.guard(1).await?;
    let active = fixture.guard(2).await?;
    let before = native::selected(&fixture.repository).await?;

    let failure = native::complete(&old, &fixture.commit).await.rejected();
    assert_eq!(failure.kind(), &StoreErrorKind::Unsupported);
    let complete = native::complete(&active, &fixture.commit).await?;
    assert_eq!(
        complete.view_interpretations.as_ref().required()[0]
            .registries
            .attribute_revision,
        2
    );
    let association = terrane_format::properties::semantics::associations::RecordedAssociation::new(
        fixture.commit.identity(),
        fixture.graph.owner,
        terrane_format::properties::semantics::RecordedContext::new(3, 3, &[])?,
    );
    assert!(crate::guard::RecordedNamespaceProfile::new(association, 3).is_err());
    old.store().assert_read_only();
    active.store().assert_read_only();
    native::unchanged(&fixture, &before).await?;

    // Attribute revision 1 retains this inert ordinary attribute; independently
    // installing revision 2 forbids its namespace placement even with Index [].
    let mut graph = wire::Graph::small();
    graph.rows[0].1 = wire::file_with_pointer(graph.object, graph.present);
    // Omit the owner binding to isolate namespace attribute semantics.
    graph.rebind(None, false);
    let inert = native::Fixture::new(
        graph,
        AuthoringNamespaceProfile::new(1, 3, &["index-roots"], 1)?,
    )
    .await?;
    let old = inert.guard(1).await?;
    let inputs = native::complete(&old, &inert.commit).await?;
    assert_eq!(
        inputs.view_interpretations.as_ref().required()[0]
            .registries
            .attribute_revision,
        1
    );
    let active = inert.guard(2).await?;
    let failure = native::complete(&active, &inert.commit).await.rejected();
    assert!(matches!(failure.kind(), StoreErrorKind::Invalid(_)));
    old.store().assert_read_only();
    active.store().assert_read_only();
    Ok(())
}

#[tokio::test]
async fn historical_index_completion_rechecks_full_profile_only_after_history_finish() -> TestResult
{
    let fixture = native::Fixture::new(
        wire::Graph::small(),
        AuthoringNamespaceProfile::new(1, 3, &["index-roots"], 1)?,
    )
    .await?;
    let guard = fixture.guard(2).await?;
    let original = guard.original_commit(&fixture.commit.identity())?;
    let consumed = ConsumedResolver::new(&guard, original.baseline().authority())?;
    let evidence =
        TreeEvidence::load_tree(guard.store(), fixture.graph.owner, &[], wire::MINIMUM).await?;
    let interpretation = guard.select_view(
        fixture.commit.identity(),
        fixture.graph.owner,
        HistoryObservation::default(),
    )?;
    let pending = super::super::PendingViewUse::prepare_interpreted(
        &guard,
        &fixture.commit,
        &evidence,
        &interpretation,
        &[],
    )
    .await?;
    assert!(consumed.finish()?.views.is_empty());

    let completed = native::complete(&guard, &fixture.commit).await?;
    let retained = &completed.view_interpretations.as_ref().required()[0];
    assert_eq!(pending.context(), retained);
    for field in 0..4 {
        let mut changed = retained.registries.clone();
        match field {
            0 => changed.tree_revision = 2,
            1 => changed.selector_revision = 2,
            2 => changed.chunk_revision = 2,
            _ => changed.identity_profile = "other-profile".into(),
        }
        assert!(
            crate::guard::consumed::view_interpretation::compare_selected_data(
                Some(retained),
                &interpretation,
                &fixture.commit,
                &changed
            )
            .is_err()
        );
    }
    let old = fixture.guard(1).await?;
    let selected = old.select_view(
        fixture.commit.identity(),
        fixture.graph.owner,
        HistoryObservation::default(),
    )?;
    let profile = super::super::profile_inputs(&old, &fixture.commit, &selected)?;
    assert!(
        crate::guard::consumed::view_interpretation::compare_selected_data(
            Some(retained),
            &selected,
            &fixture.commit,
            &profile
        )
        .is_err()
    );

    let consumed = ConsumedResolver::new(&guard, original.baseline().authority())?;
    let association = original.baseline().authority().control().join(format!(
        "commit-{}.cbor",
        wire::hex(fixture.commit.identity())
    ));
    std::fs::remove_file(association)?;
    assert!(
        guard
            .verified_history_observed(
                fixture.commit.identity(),
                HistoryObservation::default().tracked(&consumed)
            )
            .await
            .is_err()
    );
    assert!(
        consumed
            .observed_completed_view_contexts_for_tests()?
            .is_empty()
    );
    assert!(matches!(
        consumed.finish().rejected().kind(),
        StoreErrorKind::Invalid(crate::store::InvalidReason::MalformedRequest)
    ));
    guard.store().assert_read_only();
    Ok(())
}

#[tokio::test]
async fn historical_index_completion_loads_exact_staged_and_stored_nodes_read_only() -> TestResult {
    let graph = wire::Graph::small();
    let store = native::Memory::new(graph.nodes.clone());
    let evidence = TreeEvidence::load_tree(&store, graph.owner, &[], wire::MINIMUM).await?;
    assert_eq!(
        evidence.nodes.keys().copied().collect::<BTreeSet<_>>(),
        graph.namespace
    );
    assert_eq!(
        *store.reads.lock().required(),
        [(graph.owner, graph.nodes[&graph.owner].len())]
    );
    store.reads.lock().required().clear();

    super::verify(
        &store,
        &evidence,
        &[],
        &native::profile(),
        vec![(graph.owner, "uid".into())],
        wire::MINIMUM,
    )
    .await?;
    let reads = store.reads.lock().required().clone();
    let expected = BTreeSet::from([graph.primary, graph.gap, graph.present, graph.missing]);
    assert_eq!(
        reads.iter().map(|(node, _)| *node).collect::<BTreeSet<_>>(),
        expected
    );
    assert_eq!(reads.len(), expected.len());
    assert_eq!(
        reads.iter().map(|(_, size)| size).sum::<usize>(),
        expected
            .iter()
            .map(|id| graph.nodes[id].len())
            .sum::<usize>()
    );
    store.reads.lock().required().clear();

    let uploads = graph
        .nodes
        .values()
        .map(|bytes| StagedUpload::Meta {
            kind: IdentityKind::Node,
            bytes: bytes.clone(),
        })
        .collect::<Vec<_>>();
    super::verify(
        &store,
        &evidence,
        &uploads,
        &native::profile(),
        vec![(graph.owner, "uid".into())],
        wire::MINIMUM,
    )
    .await?;
    assert!(store.reads.lock().required().is_empty());
    let mut duplicate = uploads.clone();
    duplicate.push(uploads[0].clone());
    assert!(
        super::verify(
            &store,
            &evidence,
            &duplicate,
            &native::profile(),
            Vec::new(),
            wire::MINIMUM
        )
        .await
        .is_err()
    );
    assert!(store.reads.lock().required().is_empty());
    Ok(())
}

#[tokio::test]
async fn historical_index_completion_validates_structural_placement_without_requirements()
-> TestResult {
    let mut graph = wire::Graph::small();
    graph.rebind(None, false);
    check(&graph, &native::Memory::new(graph.nodes.clone()), false).await?;

    let mut misplaced = graph.clone();
    let owner = wire::leaf(
        &misplaced.rows,
        Some(wire::properties(vec![
            ("index", wire::names(&[])),
            (
                "index-gaps",
                wire::wrapper(wire::text(&wire::hex(misplaced.gap)), false),
            ),
        ])),
    );
    misplaced.owner = wire::insert(&mut misplaced.nodes, owner);
    let failure = check(
        &misplaced,
        &native::Memory::new(misplaced.nodes.clone()),
        false,
    )
    .await
    .rejected();
    assert_eq!(index_error(&failure).kind(), ErrorKind::Invalid);
    assert_eq!(index_error(&failure).subject(), Some(misplaced.owner));

    let mut inherited = graph.clone();
    let owner = wire::leaf(
        &inherited.rows,
        Some(wire::properties(vec![
            ("index", wire::names(&[])),
            (
                "index-roots",
                wire::wrapper(
                    wire::properties(vec![("uid", wire::text(&wire::hex(inherited.primary)))]),
                    true,
                ),
            ),
        ])),
    );
    inherited.owner = wire::insert(&mut inherited.nodes, owner);
    let failure = check(
        &inherited,
        &native::Memory::new(inherited.nodes.clone()),
        false,
    )
    .await
    .rejected();
    assert_eq!(index_error(&failure).kind(), ErrorKind::Invalid);
    let mut namespace_pointer = graph.clone();
    namespace_pointer.rows[0].1 = wire::file_with_pointer(graph.object, graph.present);
    namespace_pointer.rebind(None, false);
    let failure = check(
        &namespace_pointer,
        &native::Memory::new(namespace_pointer.nodes.clone()),
        false,
    )
    .await
    .rejected();
    assert_eq!(index_error(&failure).kind(), ErrorKind::Invalid);

    let mut override_binding = wire::Graph::repeated();
    let child = override_binding.child.required();
    override_binding.rows[0].1 = wire::graft(
        child,
        Some(wire::properties(vec![(
            "index-roots",
            wire::wrapper(
                wire::properties(vec![(
                    "uid",
                    wire::text(&wire::hex(override_binding.primary)),
                )]),
                false,
            ),
        )])),
    );
    override_binding.rebind(None, false);
    let failure = check(
        &override_binding,
        &native::Memory::new(override_binding.nodes.clone()),
        false,
    )
    .await
    .rejected();
    assert_eq!(index_error(&failure).kind(), ErrorKind::Invalid);
    Ok(())
}

//! Checks independently installed per-view interpretation through genuine native history and ACKs.
//!
//! Every association comes from trusted setup and an actual signed view/root.
//! Decoded lineage is inspected only after publication; it never configures a Guard.

#[path = "recorded_selection_tests/evaluators.rs"]
mod evaluators;
#[path = "recorded_selection_tests/graft.rs"]
mod graft;
#[path = "recorded_selection_tests/support.rs"]
mod support;
#[path = "recorded_selection_tests/table.rs"]
mod table;

use super::support as indexed;

use crate::bucket::held::SingleHeld;
use crate::guard::{ConsumedResolver, HistoryObservation, ViewSelection};
use crate::ref_advance::tests::{request, token};
use crate::store::{RefStore, StoreErrorKind, TokioClock};
use indexed::Native;
use support::{Location, completed, lineage, selected, signed_root};
use terrane_format::gc::publication::evidence::{
    CheckedLineage, LineageUsedInputs, ViewInterpretationMode,
};
use terrane_format::identity::{Digest, IdentityKind, TERRANE_V1};
use terrane_format::properties::selected::Selection;

type Result<T = ()> = core::result::Result<T, Box<dyn core::error::Error>>;
const REFERENCE: &str = "refs/heads/_/main";

// Fixed historical vocabulary is independent of the current compiled registry.
const LEGACY_NAMES: &[&str] = &[
    "acl",
    "baseline",
    "chunk",
    "classify",
    "compaction_threshold",
    "compression",
    "dedup",
    "degraded",
    "domain",
    "durability",
    "encryption",
    "gap_merge_bytes",
    "hashes",
    "home",
    "index",
    "merge",
    "on-release",
    "passthrough",
    "prefetch",
    "quota",
    "reassembly",
    "redundancy",
    "reflog_retain",
    "replicate",
    "retain",
    "span_max_bytes",
    "store",
    "strict-attrs",
    "trust",
    "warm",
    "whole_pack_threshold",
    "wipe",
    "writers",
];

struct Expected {
    view: Digest,
    root: Digest,
    mode: ViewInterpretationMode,
    property: u64,
    attribute: u64,
    later: Vec<String>,
}

impl Expected {
    fn legacy(view: Digest, root: Digest) -> Self {
        Self {
            view,
            root,
            mode: ViewInterpretationMode::Legacy,
            property: 1,
            attribute: 1,
            later: Vec::new(),
        }
    }

    fn recorded(view: Digest, root: Digest, property: u64, attribute: u64, later: &[&str]) -> Self {
        let mut later = later
            .iter()
            .map(|name| (*name).to_owned())
            .collect::<Vec<_>>();
        later.sort();
        Self {
            view,
            root,
            mode: ViewInterpretationMode::Recorded,
            property,
            attribute,
            later,
        }
    }
}

fn assert_contexts(used: &LineageUsedInputs, expected: &[Expected]) -> Result {
    assert!(used.check_supported_view_contexts()?);
    assert_eq!(used.views.len(), expected.len());
    let contexts = used
        .view_interpretations
        .as_ref()
        .ok_or("completed history omitted contexts")?;
    assert_eq!(contexts.len(), expected.len());
    assert!(contexts.windows(2).all(|pair| pair[0].view < pair[1].view));
    for expected in expected {
        let context = contexts
            .iter()
            .find(|context| context.view == expected.view)
            .ok_or("missing genuinely consumed view")?;
        assert_eq!(context.original_root, expected.root);
        assert_eq!(context.mode, expected.mode);
        let inputs = &context.registries;
        assert_eq!(inputs.property_revision, expected.property);
        assert_eq!(inputs.attribute_revision, expected.attribute);
        assert_eq!(inputs.selector_revision, 1);
        assert_eq!(inputs.tree_revision, 1);
        assert_eq!(inputs.chunk_revision, 1);
        assert_eq!(inputs.identity_profile, "terrane-v1");
        assert_eq!(inputs.later_properties, expected.later);
        let mut names = LEGACY_NAMES
            .iter()
            .map(|name| (*name).to_owned())
            .collect::<Vec<_>>();
        if expected.property >= 2 {
            names.push("index-roots".into());
        }
        if expected.property >= 3 {
            names.push("index-gaps".into());
        }
        names.sort();
        assert_eq!(inputs.behavioral_properties, names);
        let view = used
            .views
            .iter()
            .find(|view| view.view == expected.view)
            .ok_or("missing independently verified policies")?;
        let namespace = view
            .roots
            .iter()
            .find(|root| root.path == b"/")
            .ok_or("missing signed namespace occurrence")?;
        assert_eq!(namespace.root, expected.root);
    }
    Ok(())
}

#[tokio::test]
async fn native_recorded_selection_mixed_legacy_history_completes_before_indexed_ack() -> Result {
    let legacy = crate::guard::recorded_native_fixture::fixture(false).await?;
    let mut session = legacy.begin(REFERENCE, &token(), "sdk").await?;
    let first = legacy
        .commit_request(&mut session, request(Vec::new()))
        .await?;
    let first_root = signed_root(&legacy, first.commit).await?;
    let location = Location::capture(&legacy, first.commit).await?;
    drop(session);
    drop(legacy);

    let repository = location
        .reopen(
            3,
            2,
            &[],
            vec![ViewSelection::new(
                first.commit,
                first_root,
                Selection::Legacy,
                1,
            )?],
        )
        .await?;
    let mut session = repository.begin(REFERENCE, &token(), "sdk").await?;
    let proposal = indexed::indexed(vec![first.commit], true)?;
    let owner = proposal.owner;
    let second = repository
        .commit_request(&mut session, proposal.request)
        .await?;
    assert_eq!(
        repository.coordinator().store().ref_get(REFERENCE).await?,
        Some(second.clone())
    );
    let actual = lineage(&repository).await?;
    assert_eq!(actual.source, second);
    assert_eq!(actual.commit_id, second.commit);
    let expected = [
        Expected::legacy(first.commit, first_root),
        Expected::recorded(second.commit, owner, 3, 2, &[]),
    ];
    assert_contexts(&actual.used, &expected)?;
    let child = actual
        .used
        .views
        .iter()
        .find(|view| view.view == second.commit)
        .ok_or("missing indexed current view")?;
    assert_eq!(child.roots.len(), 3);
    assert_eq!(child.roots[0].path, b"/");
    assert_eq!(child.roots[1].path, b"/right");
    assert_eq!(child.roots[2].path, b"/left");
    assert_eq!(child.roots[1].root, child.roots[2].root);
    assert_contexts(&completed(&repository, second.commit).await?, &expected)?;
    Ok(())
}

#[tokio::test]
async fn native_recorded_selection_different_supported_revisions_complete_independently() -> Result
{
    let legacy = crate::guard::recorded_native_fixture::fixture(false).await?;
    let mut session = legacy.begin(REFERENCE, &token(), "sdk").await?;
    let first = legacy
        .commit_request(&mut session, request(Vec::new()))
        .await?;
    let first_root = signed_root(&legacy, first.commit).await?;
    let location = Location::capture(&legacy, first.commit).await?;
    drop(session);
    drop(legacy);

    let revision_two = location
        .reopen(
            2,
            1,
            &[],
            vec![ViewSelection::new(
                first.commit,
                first_root,
                Selection::Legacy,
                1,
            )?],
        )
        .await?;
    let mut session = revision_two.begin(REFERENCE, &token(), "sdk").await?;
    let second = revision_two
        .commit_request(&mut session, request(vec![first.commit]))
        .await?;
    let second_root = signed_root(&revision_two, second.commit).await?;
    drop(session);
    drop(revision_two);

    let repository = location
        .reopen(
            3,
            2,
            &[],
            vec![
                ViewSelection::new(first.commit, first_root, Selection::Legacy, 1)?,
                selected(second.commit, second_root, 2, 1, &[])?,
            ],
        )
        .await?;
    let mut session = repository.begin(REFERENCE, &token(), "sdk").await?;
    let proposal = indexed::indexed(vec![second.commit], false)?;
    let owner = proposal.owner;
    let third = repository
        .commit_request(&mut session, proposal.request)
        .await?;
    assert_eq!(
        repository.coordinator().store().ref_get(REFERENCE).await?,
        Some(third.clone())
    );
    let expected = [
        Expected::legacy(first.commit, first_root),
        Expected::recorded(second.commit, second_root, 2, 1, &[]),
        Expected::recorded(third.commit, owner, 3, 2, &[]),
    ];
    assert_contexts(&lineage(&repository).await?.used, &expected)?;
    assert_contexts(&completed(&repository, third.commit).await?, &expected)?;
    Ok(())
}

#[tokio::test]
async fn native_recorded_selection_trusted_later_bindings_remain_inert_per_historical_view()
-> Result {
    let legacy = crate::guard::recorded_native_fixture::fixture(false).await?;
    let mut session = legacy.begin(REFERENCE, &token(), "sdk").await?;
    let first = legacy
        .commit_request(&mut session, request(Vec::new()))
        .await?;
    let first_root = signed_root(&legacy, first.commit).await?;
    let location = Location::capture(&legacy, first.commit).await?;
    drop(session);
    drop(legacy);

    let later = ["index-gaps", "index-roots"];
    let revision_one = location
        .reopen(
            1,
            1,
            &later,
            vec![ViewSelection::new(
                first.commit,
                first_root,
                Selection::Legacy,
                1,
            )?],
        )
        .await?;
    let mut session = revision_one.begin(REFERENCE, &token(), "sdk").await?;
    let inert = support::inert_later_request(vec![first.commit])?;
    let inert_root = inert.commit.tree;
    let second = revision_one.commit_request(&mut session, inert).await?;
    drop(session);
    drop(revision_one);

    let repository = location
        .reopen(
            3,
            2,
            &[],
            vec![
                ViewSelection::new(first.commit, first_root, Selection::Legacy, 1)?,
                selected(second.commit, inert_root, 1, 1, &later)?,
            ],
        )
        .await?;
    let mut session = repository.begin(REFERENCE, &token(), "sdk").await?;
    let third = repository
        .commit_request(&mut session, request(vec![second.commit]))
        .await?;
    let third_root = signed_root(&repository, third.commit).await?;
    let expected = [
        Expected::legacy(first.commit, first_root),
        Expected::recorded(second.commit, inert_root, 1, 1, &later),
        Expected::recorded(third.commit, third_root, 3, 2, &[]),
    ];
    assert_contexts(&lineage(&repository).await?.used, &expected)?;
    assert_contexts(&completed(&repository, third.commit).await?, &expected)?;
    assert_eq!(
        repository.coordinator().store().ref_get(REFERENCE).await?,
        Some(third)
    );
    Ok(())
}

#[tokio::test]
async fn native_recorded_selection_missing_or_changed_used_association_promotes_nothing() -> Result
{
    let original = crate::guard::recorded_native_fixture::fixture(true).await?;
    let mut session = original.begin(REFERENCE, &token(), "sdk").await?;
    let first = original
        .commit_request(&mut session, request(Vec::new()))
        .await?;
    let first_root = signed_root(&original, first.commit).await?;
    let second = original
        .commit_request(&mut session, request(vec![first.commit]))
        .await?;
    let second_root = signed_root(&original, second.commit).await?;
    let before = lineage(&original).await?;
    let location = Location::capture(&original, second.commit).await?;
    drop(session);
    drop(original);

    for changed_root in [None, Some([9; 32])] {
        let mut selections = vec![selected(second.commit, second_root, 3, 2, &[])?];
        if let Some(root) = changed_root {
            assert_ne!(root, first_root);
            selections.push(selected(first.commit, root, 3, 2, &[])?);
        }
        let repository = location.reopen(3, 2, &[], selections).await?;
        let authority = repository
            .coordinator()
            .guard()
            .original_commit(&second.commit)?
            .baseline()
            .authority()
            .clone();
        {
            let holder = SingleHeld::acquire(repository.coordinator().store()).await?;
            let destination = holder.destination();
            let observed = destination.observe_publication().await?;
            let guard = repository
                .coordinator()
                .guard()
                .held_guard(holder.destination(), TokioClock)?;
            let consumed = ConsumedResolver::new(&guard, &authority)?;
            consumed.registration(&authority)?;
            let result = guard
                .verified_history_observed(
                    second.commit,
                    HistoryObservation::held(observed.identity()).tracked(&consumed),
                )
                .await;
            let failure = result
                .err()
                .ok_or("missing or changed independently installed association completed")?;
            if changed_root.is_some() {
                assert!(matches!(
                    failure.kind(),
                    StoreErrorKind::Invalid(crate::store::InvalidReason::MalformedRequest)
                ));
            } else {
                assert!(matches!(failure.kind(), StoreErrorKind::Unsupported));
            }
            assert!(
                consumed
                    .observed_completed_view_contexts_for_tests()?
                    .is_empty()
            );
            assert!(consumed.finish().is_err());
            assert_eq!(
                destination.selected_lineage(&observed, REFERENCE).await?,
                Some(before.encode()?)
            );
            observed.revalidate().await?;
        }
        assert_eq!(
            repository.coordinator().store().ref_get(REFERENCE).await?,
            Some(second.clone())
        );
    }
    Ok(())
}

#[tokio::test]
async fn native_recorded_selection_same_view_conflict_never_installs() -> Result {
    let repository = crate::guard::recorded_native_fixture::fixture(false).await?;
    let mut session = repository.begin(REFERENCE, &token(), "sdk").await?;
    let first = repository
        .commit_request(&mut session, request(Vec::new()))
        .await?;
    let root = signed_root(&repository, first.commit).await?;
    let location = Location::capture(&repository, first.commit).await?;
    let before = lineage(&repository).await?;
    let result = location
        .reopen(
            3,
            2,
            &[],
            vec![
                ViewSelection::new(first.commit, root, Selection::Legacy, 1)?,
                selected(first.commit, root, 1, 1, &[])?,
            ],
        )
        .await;
    let failure = result
        .err()
        .ok_or("conflicting actual view selections installed")?;
    let failure = failure
        .downcast_ref::<crate::store::StoreFailure>()
        .ok_or("conflicting selection lost its typed configuration failure")?;
    assert!(matches!(
        failure.kind(),
        StoreErrorKind::Invalid(crate::store::InvalidReason::MalformedRequest)
    ));
    assert_eq!(
        repository.coordinator().store().ref_get(REFERENCE).await?,
        Some(first)
    );
    assert_eq!(lineage(&repository).await?, before);
    Ok(())
}

#[tokio::test]
async fn native_recorded_selection_late_missing_original_promotes_no_completed_views() -> Result {
    use crate::store::{LocalFs, TokioLocalFs};
    use core::error::Error;

    let original = crate::guard::recorded_native_fixture::fixture(true).await?;
    let mut session = original.begin(REFERENCE, &token(), "sdk").await?;
    let first = original
        .commit_request(&mut session, request(Vec::new()))
        .await?;
    let first_root = signed_root(&original, first.commit).await?;
    let second = original
        .commit_request(&mut session, request(vec![first.commit]))
        .await?;
    let second_root = signed_root(&original, second.commit).await?;
    let before = lineage(&original).await?;
    let location = Location::capture(&original, second.commit).await?;
    drop(session);
    drop(original);
    let repository = location
        .reopen(
            3,
            2,
            &[],
            vec![
                selected(first.commit, first_root, 3, 2, &[])?,
                selected(second.commit, second_root, 3, 2, &[])?,
            ],
        )
        .await?;
    let authority = repository
        .coordinator()
        .guard()
        .original_commit(&second.commit)?
        .baseline()
        .authority()
        .clone();
    let association = location.association(second.commit);
    let saved = association.with_extension("saved");
    TokioLocalFs.rename(&association, &saved).await?;
    TokioLocalFs.sync_directory(location.control()).await?;
    {
        let holder = SingleHeld::acquire(repository.coordinator().store()).await?;
        let destination = holder.destination();
        let observed = destination.observe_publication().await?;
        let guard = repository
            .coordinator()
            .guard()
            .held_guard(holder.destination(), TokioClock)?;
        let consumed = ConsumedResolver::new(&guard, &authority)?;
        consumed.registration(&authority)?;
        let result = guard
            .verified_history_observed(
                second.commit,
                HistoryObservation::held(observed.identity()).tracked(&consumed),
            )
            .await;
        // Restore actual bytes and their incarnation before checking the failure.
        TokioLocalFs.rename(&saved, &association).await?;
        TokioLocalFs.sync_directory(location.control()).await?;
        let failure = result
            .err()
            .ok_or("absent late physical Original association completed")?;
        assert!(matches!(
            failure.kind(),
            StoreErrorKind::Unavailable { retry_after: None }
        ));
        assert_eq!(
            failure
                .source()
                .and_then(|source| source.downcast_ref::<std::io::Error>())
                .map(std::io::Error::kind),
            Some(std::io::ErrorKind::NotFound)
        );
        assert!(
            consumed
                .observed_completed_view_contexts_for_tests()?
                .is_empty()
        );
        assert!(matches!(
            consumed
                .finish()
                .err()
                .ok_or("failed history finalized pending contexts")?
                .kind(),
            StoreErrorKind::Invalid(crate::store::InvalidReason::MalformedRequest)
        ));
        assert_eq!(
            destination.selected_lineage(&observed, REFERENCE).await?,
            Some(before.encode()?)
        );
        observed.revalidate().await?;
    }
    assert_eq!(
        repository.coordinator().store().ref_get(REFERENCE).await?,
        Some(second.clone())
    );
    assert_contexts(
        &completed(&repository, second.commit).await?,
        &[
            Expected::recorded(first.commit, first_root, 3, 2, &[]),
            Expected::recorded(second.commit, second_root, 3, 2, &[]),
        ],
    )?;
    Ok(())
}

#[tokio::test]
async fn native_recorded_selection_mixed_history_never_grandfathers_missing_index_binding() -> Result
{
    let legacy = crate::guard::recorded_native_fixture::fixture(false).await?;
    let mut session = legacy.begin(REFERENCE, &token(), "sdk").await?;
    let first = legacy
        .commit_request(&mut session, request(Vec::new()))
        .await?;
    let first_root = signed_root(&legacy, first.commit).await?;
    let location = Location::capture(&legacy, first.commit).await?;
    drop(session);
    drop(legacy);
    let repository = location
        .reopen(
            3,
            2,
            &[],
            vec![ViewSelection::new(
                first.commit,
                first_root,
                Selection::Legacy,
                1,
            )?],
        )
        .await?;
    let mut session = repository.begin(REFERENCE, &token(), "sdk").await?;
    // Initial construction may create the binding. The negative case must
    // omit an already maintained Current binding in this actual mixed history.
    let maintained = indexed::indexed(vec![first.commit], false)?;
    let maintained_owner = maintained.owner;
    let maintained_primary = maintained.primary;
    let second = repository
        .commit_request(&mut session, maintained.request)
        .await?;
    assert_contexts(
        &completed(&repository, second.commit).await?,
        &[
            Expected::legacy(first.commit, first_root),
            Expected::recorded(second.commit, maintained_owner, 3, 2, &[]),
        ],
    )?;
    let before = lineage(&repository).await?;
    let proposal = indexed::missing_local_binding(vec![second.commit])?;
    let missing_owner = proposal.owner;
    let proposed_evidence = crate::guard::TreeEvidence::load_tree(
        repository.coordinator().store(),
        missing_owner,
        &proposal.request.uploads,
        262144,
    )
    .await?;
    let error = repository
        .commit_request(&mut session, proposal.request)
        .await
        .err()
        .ok_or("missing required current owner binding received ACK")?;
    let failure = match error {
        crate::repository::Error::Store(failure)
        | crate::repository::Error::Advance(crate::ref_advance::AdvanceError::Store(failure)) => {
            failure
        }
        other => {
            return Err(
                format!("unexpected failure instead of typed index cause: {other:?}").into(),
            );
        }
    };
    assert_eq!(
        failure.kind(),
        &StoreErrorKind::Invalid(crate::store::InvalidReason::MalformedRequest)
    );
    assert_eq!(
        repository
            .coordinator()
            .guard()
            .dropped_index_binding_for_tests(&failure),
        Some((missing_owner, "uid"))
    );
    assert_eq!(
        repository.coordinator().store().ref_get(REFERENCE).await?,
        Some(second)
    );
    assert_eq!(lineage(&repository).await?, before);

    let revisions = crate::indexing::SemanticRevisions {
        property: 3,
        attribute: 2,
        tree: 1,
    };
    let loaded = crate::indexing::load(
        repository.coordinator().store(),
        maintained_owner,
        "uid",
        revisions,
        262144,
    )
    .await?;
    assert_eq!(loaded.index_root(), maintained_primary);
    {
        let sources = loaded.sources()?;
        assert_eq!(
            loaded
                .prepare(&sources.trees)?
                .preparation()
                .verification
                .candidates,
            1
        );
    }

    // The unselected proposal still has an exact incomplete relationship. The
    // real preceding index and Legacy parent cannot supply its local binding.
    let proposed_inputs = repository
        .coordinator()
        .guard()
        .staged_index_inputs_for_tests(&proposed_evidence)?;
    let missing = crate::indexing::load(&proposed_inputs, missing_owner, "uid", revisions, 262144)
        .await
        .err()
        .ok_or("unbound mixed-history owner became a verified index")?;
    assert!(matches!(
        missing,
        crate::indexing::Error::MissingBinding(owner) if owner == missing_owner
    ));
    assert_eq!(missing.kind(), crate::indexing::ErrorKind::Incomplete);
    Ok(())
}

#[tokio::test]
async fn native_recorded_selection_attribute_producer_requires_actual_signed_readable_evidence()
-> Result {
    use crate::ref_advance::tests::{request_file, secret};
    use terrane_format::derived::{AttrRecord, AttributeValue};

    let legacy = crate::guard::recorded_native_fixture::fixture(false).await?;
    let mut session = legacy.begin(REFERENCE, &token(), "sdk").await?;
    let plaintext = b"source plaintext";
    let first = legacy
        .commit_request(&mut session, request_file(Vec::new(), plaintext))
        .await?;
    let producer = legacy
        .coordinator()
        .guard()
        .verified_tree(first.commit)
        .await?;
    let first_root = producer.commit.commit().tree;
    let location = Location::capture(&legacy, first.commit).await?;
    let object = TERRANE_V1
        .calculate(IdentityKind::Chunk, plaintext)?
        .terrane_v1_digest()?;
    let mut hashes = terrane_format::derived::PlaintextHashes::new(plaintext.len() as u64);
    hashes.update(plaintext)?;
    let mut record = AttrRecord::new(
        object,
        AttributeValue::Sha256(hashes.finish()?.sha256),
        first.commit,
    );
    record.sign(&producer.commit, &secret())?;
    drop(producer);
    drop(session);
    drop(legacy);

    let repository = location
        .reopen(
            3,
            2,
            &[],
            vec![ViewSelection::new(
                first.commit,
                first_root,
                Selection::Legacy,
                1,
            )?],
        )
        .await?;
    let before = lineage(&repository).await?;
    let mut session = repository.begin(REFERENCE, &token(), "sdk").await?;
    assert!(
        repository
            .commit_request(
                &mut session,
                support::hash_request(first.commit, object, plaintext)?
            )
            .await
            .is_err()
    );
    assert_eq!(
        repository.coordinator().store().ref_get(REFERENCE).await?,
        Some(first.clone())
    );
    assert_eq!(lineage(&repository).await?, before);

    let mut forged = record.clone();
    let signature = forged
        .signature
        .as_mut()
        .ok_or("real signed producer has no signature")?;
    signature[0] ^= 1;
    let mut invalid = support::hash_request(first.commit, object, plaintext)?;
    invalid
        .uploads
        .push(crate::ref_advance::StagedUpload::Meta {
            kind: IdentityKind::Attribute,
            bytes: forged.encode()?,
        });
    assert!(
        repository
            .commit_request(&mut session, invalid)
            .await
            .is_err()
    );
    assert_eq!(
        repository.coordinator().store().ref_get(REFERENCE).await?,
        Some(first.clone())
    );
    assert_eq!(lineage(&repository).await?, before);

    let mut valid = support::hash_request(first.commit, object, plaintext)?;
    let current_root = valid.commit.tree;
    valid.uploads.push(crate::ref_advance::StagedUpload::Meta {
        kind: IdentityKind::Attribute,
        bytes: record.encode()?,
    });
    let second = repository.commit_request(&mut session, valid).await?;
    assert_eq!(second.seq, first.seq + 1);
    assert_eq!(
        repository.coordinator().store().ref_get(REFERENCE).await?,
        Some(second.clone())
    );
    let expected = [
        Expected::legacy(first.commit, first_root),
        Expected::recorded(second.commit, current_root, 3, 2, &[]),
    ];
    assert_contexts(&lineage(&repository).await?.used, &expected)?;
    assert_contexts(&completed(&repository, second.commit).await?, &expected)?;
    Ok(())
}

#[tokio::test]
async fn native_recorded_selection_unrelated_real_view_does_not_enlarge_used_contexts() -> Result {
    let legacy = crate::guard::recorded_native_fixture::fixture(false).await?;
    let mut main = legacy.begin(REFERENCE, &token(), "sdk").await?;
    let first = legacy
        .commit_request(&mut main, request(Vec::new()))
        .await?;
    let first_root = signed_root(&legacy, first.commit).await?;
    let mut other = legacy
        .begin("refs/heads/_/unrelated", &token(), "sdk")
        .await?;
    let unrelated = legacy
        .commit_request(&mut other, request(Vec::new()))
        .await?;
    let unrelated_root = signed_root(&legacy, unrelated.commit).await?;
    assert_ne!(first.commit, unrelated.commit);
    let location = Location::capture(&legacy, first.commit).await?;
    drop(main);
    drop(other);
    drop(legacy);

    let repository = location
        .reopen(
            3,
            2,
            &[],
            vec![
                ViewSelection::new(first.commit, first_root, Selection::Legacy, 1)?,
                ViewSelection::new(unrelated.commit, unrelated_root, Selection::Legacy, 1)?,
            ],
        )
        .await?;
    let mut session = repository.begin(REFERENCE, &token(), "sdk").await?;
    let second = repository
        .commit_request(&mut session, request(vec![first.commit]))
        .await?;
    let second_root = signed_root(&repository, second.commit).await?;
    let expected = [
        Expected::legacy(first.commit, first_root),
        Expected::recorded(second.commit, second_root, 3, 2, &[]),
    ];
    let actual = lineage(&repository).await?;
    assert_contexts(&actual.used, &expected)?;
    assert!(
        !actual
            .used
            .views
            .iter()
            .any(|view| view.view == unrelated.commit)
    );
    assert_contexts(&completed(&repository, second.commit).await?, &expected)?;
    assert_eq!(
        repository
            .coordinator()
            .store()
            .ref_get("refs/heads/_/unrelated")
            .await?,
        Some(unrelated)
    );
    Ok(())
}

#[tokio::test]
async fn native_recorded_selection_unknown_registered_inputs_cannot_replace_real_view_configuration()
-> Result {
    use terrane_format::properties::semantics::RecordedContext;

    let repository = crate::guard::recorded_native_fixture::fixture(false).await?;
    let mut session = repository.begin(REFERENCE, &token(), "sdk").await?;
    let first = repository
        .commit_request(&mut session, request(Vec::new()))
        .await?;
    let root = signed_root(&repository, first.commit).await?;
    let before = lineage(&repository).await?;
    assert!(RecordedContext::new(4, 4, &[]).is_err());
    let unsupported = ViewSelection::new(
        first.commit,
        root,
        Selection::Recorded(RecordedContext::new(1, 3, &[])?),
        3,
    );
    let failure = unsupported
        .err()
        .ok_or("unknown attribute revision selected a real view")?;
    assert!(matches!(failure.kind(), StoreErrorKind::Unsupported));
    assert_eq!(
        repository.coordinator().store().ref_get(REFERENCE).await?,
        Some(first)
    );
    assert_eq!(lineage(&repository).await?, before);
    Ok(())
}

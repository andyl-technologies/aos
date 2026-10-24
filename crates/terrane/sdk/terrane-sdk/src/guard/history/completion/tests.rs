//! Checks native publication and successful-history context.
//!
//! These tests use the existing production Repository/Original fixture. No
//! fixture constructs completed view evidence or fills a publication receipt.
//! They exercise supported ordinary completion, not full ALG-32 qualification.

use std::error::Error as _;

use crate::bucket::held::SingleHeld;
use crate::guard::admission::tests::support::observed;
use crate::guard::recorded_properties::SelectedReadInterpretation;
use crate::guard::{ConsumedResolver, HistoryObservation};
use crate::ref_advance::tests::{fixture, request_file, token};
use crate::store::{RefStore, StoreErrorKind};
use terrane_format::{
    gc::publication::evidence::{CheckedLineage, ViewInterpretationMode},
    identity::IdentityKind,
    properties::semantics::RecordedContext,
    tree_builder::Tree,
    tree_format::{self, Attribute, NodeItems, Property, TreeUse},
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
const SOURCE: &str = "refs/heads/_/main";

#[tokio::test]
async fn actual_repository_publication_persists_complete_candidate_context() -> TestResult {
    let repository = fixture().await;
    let mut writer = repository.begin(SOURCE, &token(), "sdk").await?;
    let request = request_file(Vec::new(), b"genuine published candidate context");
    let original_root = request.commit.tree;

    let head = repository.advance(&mut writer, request).await?;
    let hold = SingleHeld::acquire_read_only(repository.store()).await?;
    let source = hold.source();
    let selected = source.observe_publication().await?;
    let read = source
        .selected_lineage_record(&selected, SOURCE)
        .await?
        .ok_or("actual published source has no selected lineage")?;
    let lineage = CheckedLineage::decode(read.bytes().ok_or("actual lineage read absent")?)?;
    let contexts = lineage
        .used
        .view_interpretations
        .as_ref()
        .ok_or("actual producer omitted key7")?;

    assert_eq!(lineage.source, head);
    assert_eq!(lineage.commit_id, head.commit);
    assert_eq!(contexts.len(), 1);
    let context = &contexts[0];
    assert_eq!(context.view, head.commit);
    assert_eq!(context.original_root, original_root);
    assert_eq!(context.mode, ViewInterpretationMode::Legacy);
    assert_eq!(context.registries.property_revision, 1);
    assert_eq!(context.registries.behavioral_properties.len(), 33);
    assert_eq!(context.registries.attribute_revision, 1);
    assert_eq!(context.registries.selector_revision, 1);
    assert_eq!(context.registries.tree_revision, 1);
    assert_eq!(context.registries.chunk_revision, 1);
    assert_eq!(context.registries.identity_profile, "terrane-v1");
    assert!(context.registries.later_properties.is_empty());
    Ok(())
}

#[tokio::test]
async fn completed_recorded_history_retains_actual_mode_fence_and_original_root() -> TestResult {
    let repository = crate::ref_advance::tests::recorded_fixture(
        RecordedContext::new(3, 3, &["future-name"])?,
        1,
    )
    .await?;
    let mut writer = repository.begin(SOURCE, &token(), "sdk").await?;
    let request = request_file(Vec::new(), b"complete independently selected history");
    let root = request.commit.tree;
    let head = repository.advance(&mut writer, request).await?;
    let guard = observed(repository.guard());
    let original = guard.original_commit(&head.commit)?;
    let consumed = ConsumedResolver::new(&guard, original.baseline().authority())?;

    guard
        .verified_history_observed(
            head.commit,
            HistoryObservation::default().tracked(&consumed),
        )
        .await?;
    let inputs = consumed.finish()?;
    let contexts = inputs
        .view_interpretations
        .as_ref()
        .ok_or("completed context absent")?;

    assert_eq!(inputs.views.len(), 1);
    assert_eq!(contexts.len(), 1);
    assert_eq!(contexts[0].view, head.commit);
    assert_eq!(contexts[0].original_root, root);
    assert_eq!(contexts[0].mode, ViewInterpretationMode::Recorded);
    assert_eq!(contexts[0].registries.property_revision, 3);
    assert_eq!(contexts[0].registries.later_properties, ["future-name"]);
    assert_eq!(contexts[0].registries.attribute_revision, 1);
    guard.store().assert_no_effects();
    Ok(())
}

#[tokio::test]
async fn missing_original_association_prevents_successful_history_context_recording() -> TestResult
{
    let repository = fixture().await;
    let mut writer = repository.begin(SOURCE, &token(), "sdk").await?;
    let head = repository
        .advance(
            &mut writer,
            request_file(Vec::new(), b"mandatory original evidence"),
        )
        .await?;
    let original = repository.guard().original_commit(&head.commit)?;
    let consumed = ConsumedResolver::new(repository.guard(), original.baseline().authority())?;
    let suffix = head
        .commit
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let path = original
        .baseline()
        .authority()
        .control()
        .join(format!("commit-{suffix}.cbor"));
    let saved = path.with_extension("saved");
    std::fs::rename(&path, &saved)?;

    let result = repository
        .guard()
        .verified_history_observed(
            head.commit,
            HistoryObservation::default().tracked(&consumed),
        )
        .await;
    std::fs::rename(&saved, &path)?;

    let failure = result.err().ok_or("missing Original completed history")?;
    assert_eq!(
        failure.kind(),
        &StoreErrorKind::Unavailable { retry_after: None }
    );
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
    let unfinished = consumed
        .finish()
        .err()
        .ok_or("failed Original finalized pending views")?;
    assert_eq!(
        unfinished.kind(),
        &StoreErrorKind::Invalid(crate::store::InvalidReason::MalformedRequest)
    );
    repository.guard().verified_history(head.commit).await?;
    Ok(())
}

#[tokio::test]
async fn actual_required_index_candidate_refuses_context_until_owning_validator_exists()
-> TestResult {
    let repository = fixture().await;
    let mut writer = repository.begin(SOURCE, &token(), "sdk").await?;
    let head = repository
        .advance(&mut writer, request_file(Vec::new(), b"source authority"))
        .await?;
    let original = repository.guard().original_commit(&head.commit)?;
    let consumed = ConsumedResolver::new(repository.guard(), original.baseline().authority())?;
    let mut request = request_file(Vec::new(), b"writer inline value");
    let (root, uploads) = {
        let bytes = request
            .uploads
            .iter()
            .find_map(|upload| match upload {
                crate::guard::StagedUpload::Meta {
                    kind: IdentityKind::Node,
                    bytes,
                } => Some(bytes),
                _ => None,
            })
            .ok_or("independent fixture root absent")?;
        let node = tree_format::decode_node_for(bytes, true, 262144, TreeUse::Ordinary)?;
        let NodeItems::Leaf(mut entries) = node.items else {
            return Err("fixture is not a leaf".into());
        };
        for item in &mut entries {
            item.entry.attrs = vec![Attribute {
                name: "tag.checked",
                value: b"\x61x",
            }];
        }
        drop(node.props);
        let tree = Tree::build(
            entries,
            Some(vec![
                Property {
                    name: "acl",
                    value: b"\x81\x82\x66writer\x18\x1f",
                },
                Property {
                    name: "index",
                    value: b"\x81\x6btag.checked",
                },
                Property {
                    name: "domain",
                    value: b"\x66public",
                },
            ]),
            262144,
            TreeUse::Ordinary,
        )?;
        let root = tree.root_identity();
        let uploads = tree
            .nodes()
            .map(|node| crate::guard::StagedUpload::Meta {
                kind: IdentityKind::Node,
                bytes: node.encoded().to_vec(),
            })
            .collect::<Vec<_>>();
        drop(tree);
        (root, uploads)
    };
    request.commit.tree = root;
    request.uploads.retain(|upload| {
        !matches!(
            upload,
            crate::guard::StagedUpload::Meta {
                kind: IdentityKind::Node,
                ..
            }
        )
    });
    request.uploads.extend(uploads);
    let destination = "refs/heads/_/required-index";
    let admitted = repository.guard().admit(destination, 1, request).await?;

    let result = HistoryObservation::default()
        .tracked(&consumed)
        .record_candidate(repository.guard(), &admitted)
        .await;

    let failure = result
        .err()
        .ok_or("required-index capture unexpectedly completed")?;
    assert_eq!(failure.kind(), &StoreErrorKind::Unsupported);
    assert!(consumed.finish()?.views.is_empty());
    assert!(repository.store().ref_get(destination).await?.is_none());
    Ok(())
}

#[tokio::test]
async fn policy_admission_cannot_relabel_actual_legacy_work_as_recorded_history() -> TestResult {
    let repository =
        crate::ref_advance::tests::recorded_fixture(RecordedContext::new(3, 3, &[])?, 1).await?;
    let mut writer = repository.begin(SOURCE, &token(), "sdk").await?;
    let request = request_file(Vec::new(), b"same-view distinct owning interpretation");
    let root = request.commit.tree;
    let head = repository.advance(&mut writer, request).await?;
    let guard = observed(repository.guard());
    let original = guard.original_commit(&head.commit)?;
    let consumed = ConsumedResolver::new(&guard, original.baseline().authority())?;
    let observation = HistoryObservation::default().tracked(&consumed);
    guard
        .verified_history_observed(head.commit, observation)
        .await?;
    let legacy = crate::guard::admission::tests::support::observed_with_legacy_selection(
        repository.guard(),
        head.commit,
        root,
    )?;
    let legacy_history = legacy.verified_history(head.commit).await?;
    assert_eq!(
        legacy_history.property_selection(head.commit)?,
        terrane_format::properties::selected::Selection::Legacy,
    );
    assert_eq!(
        legacy_history
            .commit(&head.commit)
            .ok_or("missing genuine Legacy view")?
            .commit()
            .tree,
        root,
    );
    assert_eq!(legacy.original_commit(&head.commit)?, original);
    let admitted = legacy.admit_policy(SOURCE, None, &token(), "sdk").await?;
    assert!(matches!(
        &admitted.admission_interpretation,
        SelectedReadInterpretation::Legacy
    ));

    assert!(
        observation
            .record_candidate(&guard, &admitted)
            .await
            .is_err()
    );

    let inputs = consumed.finish()?;
    let contexts = inputs
        .view_interpretations
        .as_ref()
        .ok_or("completed historical context absent")?;
    assert_eq!(contexts.len(), 1);
    assert_eq!(contexts[0].mode, ViewInterpretationMode::Recorded);
    assert_eq!(contexts[0].view, head.commit);
    assert_eq!(contexts[0].original_root, root);
    assert!(matches!(
        guard.select_view(head.commit, root, HistoryObservation::default())?,
        SelectedReadInterpretation::Recorded(_)
    ));
    assert_eq!(
        legacy.select_view(head.commit, root, HistoryObservation::default())?,
        SelectedReadInterpretation::Legacy,
    );
    legacy.store().assert_no_effects();
    guard.store().assert_no_effects();
    Ok(())
}

#[tokio::test]
async fn completed_revision_one_history_preserves_exact_registered_vocabulary() -> TestResult {
    let repository =
        crate::ref_advance::tests::recorded_fixture(RecordedContext::new(1, 3, &[])?, 1).await?;
    let mut writer = repository.begin(SOURCE, &token(), "sdk").await?;
    let request = request_file(Vec::new(), b"original historical revision one");
    let root = request.commit.tree;
    let head = repository.advance(&mut writer, request).await?;
    let guard = observed(repository.guard());
    let original = guard.original_commit(&head.commit)?;
    let consumed = ConsumedResolver::new(&guard, original.baseline().authority())?;

    guard
        .verified_history_observed(
            head.commit,
            HistoryObservation::default().tracked(&consumed),
        )
        .await?;
    let inputs = consumed.finish()?;
    let contexts = inputs
        .view_interpretations
        .as_ref()
        .ok_or("completed historical context absent")?;

    assert_eq!(contexts.len(), 1);
    assert_eq!(contexts[0].mode, ViewInterpretationMode::Recorded);
    assert_eq!(contexts[0].original_root, root);
    assert_eq!(contexts[0].registries.property_revision, 1);
    assert_eq!(contexts[0].registries.behavioral_properties.len(), 33);
    let names = &contexts[0].registries.behavioral_properties;
    assert!(names.iter().any(|name| name == "index"));
    assert!(!names.iter().any(|name| name == "index-roots"));
    assert!(!names.iter().any(|name| name == "index-gaps"));
    guard.store().assert_no_effects();
    Ok(())
}

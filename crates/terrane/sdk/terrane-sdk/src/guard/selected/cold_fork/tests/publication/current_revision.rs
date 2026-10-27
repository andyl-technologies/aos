//! Checks actual cold reuse across a newly justified current registration fence.
//!
//! The historical execution remains Recorded revision one. Every source is
//! genuinely authored and completed before a fresh operator configuration is
//! opened. The existing strict native calibration and ACK oracle owns the cold
//! interval; equal ordinary context bytes supply no authority.

use std::os::unix::fs::MetadataExt;
use std::sync::Arc;
use std::time::Duration;

use super::support::{
    ALL_VERBS, Fixture, SOURCE, Snapshot, TARGET, TestResult, assert_no_nodes, fork_request,
    rejected, request, store_failure,
};
use crate::bucket::{BucketBinding, FileBucket, FileBucketConfig, FileBucketPublicationConfig};
use crate::domain::DomainNamespace;
use crate::guard::{Guard, ViewSelection};
use crate::ref_advance::{CommitTiming, Coordinator};
use crate::repository::{MetadataValidator, Repository};
use crate::store::{Clock, LocalFs, RefStore, StoreErrorKind, TestClock, TokioClock, TokioLocalFs};
use terrane_format::identity::Digest;
use terrane_format::properties::selected::Selection;
use terrane_format::properties::semantics::RecordedContext;
use terrane_format::refs::Commit;

/// Reopens actual native controls with newly supplied operator inputs.
async fn reopen<C: Clock + BucketBinding + Clone + Sync + 'static>(
    fixture: &mut Fixture<C>,
    current_revision: u64,
    associations: Vec<ViewSelection>,
) -> TestResult {
    reopen_with_authoring(
        fixture,
        RecordedContext::new(1, current_revision, &[])?,
        1,
        associations,
    )
    .await
}

/// Reopens actual controls with independently selected authoring semantics.
///
/// # Errors
/// Preserves bucket, configuration and protected retention reopening failures.
async fn reopen_with_authoring<C: Clock + BucketBinding + Clone + Sync + 'static>(
    fixture: &mut Fixture<C>,
    authoring: RecordedContext,
    attribute_revision: u64,
    associations: Vec<ViewSelection>,
) -> TestResult {
    let current = fixture.repository.coordinator().guard();
    let config = current.config().clone();
    let keys = current.keys().to_vec();
    let root = fixture.bucket().root().to_owned();
    let owner = TokioLocalFs
        .symlink_metadata(&fixture.original)
        .await?
        .uid();
    let old_observer = fixture.bucket().observe_content_for_tests();
    let bucket = FileBucket::open(
        FileBucketConfig {
            root: root.clone(),
            publication_control: Some(FileBucketPublicationConfig {
                operator_uid: owner,
                control: None,
            }),
            chunk_profile_name: config.chunk_profile_name.clone(),
            chunk_profile: (*config.chunk_profile).clone(),
            locality: config.home.clone(),
        },
        fixture.fs.clone(),
        fixture.clock.clone(),
        MetadataValidator::new((*config.chunk_profile).clone()),
    )
    .await?;
    let guard = Guard::new(bucket, fixture.clock.clone(), keys, config)
        .with_recorded_authoring(authoring, attribute_revision)?
        .with_view_selections(associations)?;
    let coordinator = Coordinator::new(
        guard,
        CommitTiming::new(
            Duration::from_secs(30),
            Duration::from_secs(60),
            Duration::from_secs(10),
        )?,
        fixture.fs.clone(),
    );
    fixture.repository = Repository::reopen_native_retention(
        coordinator,
        &DomainNamespace {
            root,
            domain: "public".into(),
        },
        &fixture.original,
        owner,
    )
    .await?;
    let observer = fixture.bucket().observe_metadata_for_tests()?;
    assert!(Arc::ptr_eq(
        &observer,
        &fixture.bucket().observe_content_for_tests()
    ));
    assert!(!Arc::ptr_eq(&old_observer, &observer));
    Ok(())
}

/// Retains original roots from actual fully authenticated source history.
async fn completed_source<C: Clock + BucketBinding + Clone + Sync + 'static>(
    clock: C,
) -> TestResult<(Fixture<C>, Vec<(Digest, Digest)>)> {
    let mut fixture = Fixture::with_clock(clock).await?;
    assert!(fixture.bucket().ref_get(SOURCE).await?.is_none());
    reopen(&mut fixture, 2, Vec::new()).await?;
    let source = fixture.complete_source(ALL_VERBS).await?;
    let source_snapshot = Snapshot::capture(&fixture, SOURCE).await?;
    let signed = Commit::decode(&source_snapshot.commit)?;
    assert_eq!(signed.parents.len(), 1);
    let history = fixture
        .repository
        .coordinator()
        .guard()
        .verified_history(source.commit)
        .await?;
    let mut roots = Vec::new();
    for view in [signed.parents[0], source.commit] {
        let verified = history
            .commit(&view)
            .ok_or("actual fully verified source view")?;
        assert_eq!(verified.identity(), view);
        roots.push((view, verified.commit().tree));
    }
    let lineage = source_snapshot.lineage()?;
    let contexts = lineage
        .used
        .view_interpretations
        .as_ref()
        .ok_or("actual completed context")?;
    assert_eq!(contexts.len(), roots.len());
    for (view, root) in &roots {
        let (selection, registries) = fixture
            .repository
            .coordinator()
            .guard()
            .selected_view_context_for_tests(*view, *root)?;
        assert_eq!(registries.property_revision, 1);
        assert_eq!(registries.attribute_revision, 1);
        assert_eq!(
            selection,
            Selection::Recorded(RecordedContext::new(1, 2, &[])?)
        );
    }
    drop(history);
    Ok((fixture, roots))
}

fn associations(
    roots: &[(Digest, Digest)],
    semantics: Selection,
    attribute_revision: u64,
    substitute_root: bool,
) -> TestResult<Vec<ViewSelection>> {
    roots
        .iter()
        .map(|(view, root)| {
            Ok(ViewSelection::new(
                *view,
                if substitute_root { [91; 32] } else { *root },
                semantics.clone(),
                attribute_revision,
            )?)
        })
        .collect()
}

#[tokio::test]
async fn root_native_cold_fork_revalidates_new_current_registration_without_nodes() -> TestResult {
    let clock = TestClock::new(2_000_000_000);
    let (mut fixture, roots) = completed_source(clock.clone()).await?;
    let before = Snapshot::capture(&fixture, SOURCE).await?;
    // The actual selected complete Guard stays explicitly Legacy1/attribute1.
    // The per-view current registration fence is a separate operator input.
    let current_guard = terrane_format::gc::publication::evidence::GuardSnapshot::decode(
        before
            .guard_read
            .bytes()
            .ok_or("selected complete Guard bytes")?,
    )?;
    assert_eq!(current_guard.registries.property_revision, 1);
    assert_eq!(current_guard.registries.attribute_revision, 1);
    assert!(current_guard.registries.later_properties.is_empty());
    assert_eq!(current_guard.registries.behavioral_properties.len(), 33);
    assert!(
        current_guard
            .registries
            .behavioral_properties
            .iter()
            .all(|name| name != "index-roots" && name != "index-gaps")
    );

    let (previous_selection, previous_registries) = fixture
        .repository
        .coordinator()
        .guard()
        .selected_view_context_for_tests(roots[0].0, roots[0].1)?;
    let old_observer = fixture.bucket().observe_content_for_tests();
    fixture.fs.reset();

    reopen(
        &mut fixture,
        3,
        associations(
            &roots,
            Selection::Recorded(RecordedContext::new(1, 3, &[])?),
            1,
            false,
        )?,
    )
    .await?;

    // The active backend probe is a no-op when the independently retained wall
    // clock equals its selected timestamp, including every protected state field.
    let unchanged = Snapshot::capture(&fixture, SOURCE).await?;
    assert_eq!(unchanged.state, before.state);
    assert_eq!(unchanged.logical, before.logical);
    assert!(fixture.fs.mutations().is_empty());
    before.assert_source_unchanged(&fixture, SOURCE).await?;

    fixture.fs.reset();
    clock.set(2_000_000_001, 0);
    reopen(
        &mut fixture,
        3,
        associations(
            &roots,
            Selection::Recorded(RecordedContext::new(1, 3, &[])?),
            1,
            false,
        )?,
    )
    .await?;

    let (current_selection, current_registries) = fixture
        .repository
        .coordinator()
        .guard()
        .selected_view_context_for_tests(roots[0].0, roots[0].1)?;
    assert_ne!(previous_selection, current_selection);
    assert_eq!(
        current_selection,
        Selection::Recorded(RecordedContext::new(1, 3, &[])?)
    );
    assert_eq!(previous_registries, current_registries);
    let reopened = Snapshot::capture(&fixture, SOURCE).await?;
    // A genuine writable reopen probes this backend at the actual clock time.
    // Its only allowed pre-calibration mutation is the checked CAPABILITIES
    // timestamp successor; it does not install another Guard or alter a source.
    let previous_capabilities = before
        .logical
        .get("CAPABILITIES")
        .and_then(Option::as_deref)
        .ok_or("prior selected capabilities")?;
    let mut capabilities =
        terrane_format::bucket::BucketCapabilities::decode(previous_capabilities)?;
    capabilities.probed_at = fixture
        .clock
        .now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)?
        .as_secs();
    let current_capabilities = capabilities.encode()?;
    let mut expected_state = before.state.clone();
    if previous_capabilities != current_capabilities.as_slice() {
        expected_state.revision = expected_state
            .revision
            .checked_add(1)
            .ok_or("reopen revision overflow")?;
    }
    let mut expected_logical = before.logical.clone();
    expected_logical.insert("CAPABILITIES".into(), Some(current_capabilities.clone()));
    assert_eq!(reopened.state, expected_state);
    assert_eq!(reopened.logical, expected_logical);
    let mutations = fixture.fs.mutations();
    assert_eq!(mutations.len(), 1);
    let actual = &mutations[0];
    assert!(actual.acknowledged);
    assert_eq!(
        actual.transaction.proof,
        terrane_format::gc::publication::PublicationProof::Raw
    );
    assert_eq!(actual.transaction.old.as_ref(), Some(&before.state));
    assert_eq!(actual.transaction.new, expected_state);
    assert_eq!(
        actual.transaction.changes,
        vec![terrane_format::gc::publication::LogicalChange {
            key: "CAPABILITIES".into(),
            expected: Some(previous_capabilities.to_vec()),
            new: Some(current_capabilities),
        }]
    );
    assert_eq!(actual.transaction_bytes, actual.transaction.encode()?);
    assert_eq!(
        reopened.lineage_read.as_ref().and_then(|read| read.bytes()),
        before.lineage_read.as_ref().and_then(|read| read.bytes())
    );
    fixture.assert_full_context(&reopened.lineage()?)?;
    before.assert_source_unchanged(&fixture, SOURCE).await?;
    assert!(!Arc::ptr_eq(
        &old_observer,
        &fixture.bucket().observe_content_for_tests()
    ));

    // Real monotonic timer progression resumes before calibration and the cold
    // interval; the final native effect retains this same actual clock instance.
    clock.enable_timer();

    // This unchanged oracle positively calibrates both the real bucket and a
    // fresh reopen, then checks zero Node GET/PUT/validator decode through the
    // native Committed ACK, source immutability and fresh signed sole-parent fork.
    fixture.assert_cold(SOURCE, TARGET).await?;
    Ok(())
}

#[tokio::test]
async fn root_native_cold_fork_refuses_changed_historical_inputs_without_nodes() -> TestResult {
    for contrast in [
        "later",
        "revision-and-vocabulary",
        "mode",
        "root",
        "attribute-profile",
    ] {
        let (mut fixture, roots) = completed_source(TokioClock).await?;
        let before = Snapshot::capture(&fixture, SOURCE).await?;
        let semantics = match contrast {
            "later" => Selection::Recorded(RecordedContext::new(1, 3, &["future-note"])?),
            "revision-and-vocabulary" => Selection::Recorded(RecordedContext::new(2, 3, &[])?),
            "mode" => Selection::Legacy,
            _ => Selection::Recorded(RecordedContext::new(1, 3, &[])?),
        };
        let attribute_revision = if contrast == "attribute-profile" {
            2
        } else {
            1
        };
        reopen(
            &mut fixture,
            3,
            associations(&roots, semantics, attribute_revision, contrast == "root")?,
        )
        .await?;
        let signed = Commit::decode(&before.commit)?;
        fixture.calibrate(signed.tree).await?;
        let calibrated = Snapshot::capture(&fixture, SOURCE).await?;
        let observer = fixture.bucket().observe_content_for_tests();

        let error = rejected(
            fixture
                .repository
                .fork(SOURCE, TARGET, fork_request()?)
                .await,
        );

        assert_eq!(
            store_failure(&error).kind(),
            &StoreErrorKind::Invalid(crate::store::InvalidReason::MalformedRequest),
            "{contrast}"
        );
        assert_no_nodes(&observer.snapshot());
        assert_eq!(observer.snapshot().commit_puts, 0, "{contrast}");
        assert_eq!(fixture.fs.successful_ref_ack(TARGET), 0, "{contrast}");
        assert!(
            fixture.bucket().ref_get(TARGET).await?.is_none(),
            "{contrast}"
        );
        let after = Snapshot::capture(&fixture, SOURCE).await?;
        assert_eq!(after.state, calibrated.state, "{contrast}");
        assert_eq!(after.logical, calibrated.logical, "{contrast}");
        before.assert_source_unchanged(&fixture, SOURCE).await?;
        assert_no_nodes(&observer.snapshot());
    }
    Ok(())
}

#[tokio::test]
async fn root_native_cold_fork_preserves_inert_later_parent_after_current_revision_advance()
-> TestResult {
    use crate::ref_advance::StagedUpload;
    use terrane_format::identity::IdentityKind;
    use terrane_format::tree_builder::Tree;
    use terrane_format::tree_format::{Property, TreeUse};

    let mut fixture = Fixture::open().await?;
    let historical = RecordedContext::new(1, 3, &["index-gaps", "index-roots"])?;
    reopen_with_authoring(&mut fixture, historical.clone(), 1, Vec::new()).await?;
    let mut parent_request = request(Vec::new(), ALL_VERBS)?;
    let parent_root = {
        // These canonical empty arrays are preserve-only data under revision one.
        // Revision three rejects index-gaps on this namespace root if consulted.
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
                    name: "index-gaps",
                    value: b"\x80",
                },
                Property {
                    name: "index-roots",
                    value: b"\x80",
                },
            ]),
            262144,
            TreeUse::Ordinary,
        )?;
        parent_request.commit.tree = tree.root_identity();
        parent_request.uploads = tree
            .nodes()
            .map(|node| StagedUpload::Meta {
                kind: IdentityKind::Node,
                bytes: node.encoded().to_vec(),
            })
            .collect();
        tree.root_identity()
    };
    let parent = fixture.publish(SOURCE, parent_request).await?;
    let parent_selection = ViewSelection::new(
        parent.commit,
        parent_root,
        Selection::Recorded(historical.clone()),
        1,
    )?;
    let current = RecordedContext::new(3, 3, &[])?;
    reopen_with_authoring(
        &mut fixture,
        current.clone(),
        2,
        vec![parent_selection.clone()],
    )
    .await?;

    // Genuine admission removes the inert properties and completes P -> C under
    // the exact independently installed interpretation of each signed view.
    let child_request = request(vec![parent.commit], ALL_VERBS)?;
    let child_root = child_request.commit.tree;
    assert_ne!(parent_root, child_root);
    let child = fixture.publish(SOURCE, child_request).await?;
    let child_selection = ViewSelection::new(
        child.commit,
        child_root,
        Selection::Recorded(current.clone()),
        2,
    )?;
    reopen_with_authoring(
        &mut fixture,
        current,
        2,
        vec![parent_selection, child_selection],
    )
    .await?;

    let selected = Snapshot::capture(&fixture, SOURCE).await?;
    let signed = Commit::decode(&selected.commit)?;
    assert_eq!(signed.parents, vec![parent.commit]);
    assert_eq!(signed.tree, child_root);
    let lineage = selected.lineage()?;
    assert_eq!(lineage.source, child);
    fixture.assert_full_context(&lineage)?;
    let contexts = lineage
        .used
        .view_interpretations
        .as_ref()
        .ok_or("completed contexts")?;
    assert_eq!(contexts.len(), 2);
    for (view, root, revision, attribute, later) in [
        (
            parent.commit,
            parent_root,
            1,
            1,
            vec!["index-gaps".to_owned(), "index-roots".to_owned()],
        ),
        (child.commit, child_root, 3, 2, Vec::new()),
    ] {
        let context = contexts
            .iter()
            .find(|context| context.view == view)
            .ok_or("completed view")?;
        assert_eq!(context.original_root, root);
        assert_eq!(
            context.mode,
            terrane_format::gc::publication::evidence::ViewInterpretationMode::Recorded
        );
        assert_eq!(context.registries.property_revision, revision);
        assert_eq!(context.registries.attribute_revision, attribute);
        assert_eq!(context.registries.later_properties, later);
    }
    let history = fixture
        .repository
        .coordinator()
        .guard()
        .verified_history(child.commit)
        .await?;
    for (view, root) in [(parent.commit, parent_root), (child.commit, child_root)] {
        let verified = history.commit(&view).ok_or("fully verified actual view")?;
        assert_eq!(verified.identity(), view);
        assert_eq!(verified.commit().tree, root);
    }
    drop(history);

    fixture.assert_cold(SOURCE, TARGET).await?;
    Ok(())
}

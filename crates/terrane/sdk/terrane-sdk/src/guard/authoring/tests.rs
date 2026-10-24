//! Exercises actual authoring validation and signing with independently chosen inputs.
//!
//! The native observer delegates real reads and counts effects. The publication
//! child exercises selected ref publication and required-index completion through
//! the genuine Repository pipeline; the admission-only cases remain read-only.

mod publication;

use super::*;
use crate::guard::admission::tests::support::{ObservedGuard, observed_with_authoring};
use crate::guard::{CommitRequest, StagedUpload, TreeEvidence};
use crate::ref_advance::tests::{fixture, request_file};
use crate::store::{RefStore, StoreErrorKind};
use terrane_format::{
    identity::IdentityKind,
    tree_builder::Tree,
    tree_format::{Attribute, TreeUse},
};

const REFERENCE: &str = "refs/heads/_/main";
type TestResult = Result<(), Box<dyn std::error::Error>>;

async fn namespace_pointer_request(guard: &ObservedGuard) -> Result<CommitRequest, StoreFailure> {
    let mut request = request_file(Vec::new(), b"pre-sign namespace selection");
    let evidence = TreeEvidence::load_tree(
        guard.store(),
        request.commit.tree,
        &request.uploads,
        guard.config().min_chunk_size,
    )
    .await?;
    let original = evidence.tree(evidence.root, guard.config().min_chunk_size)?;
    let mut entries = original.iter().cloned().collect::<Vec<_>>();
    let Some(first) = entries.first_mut() else {
        return Err(invalid());
    };
    first.entry.attrs.push(Attribute {
        name: "index.occurrences",
        value: b"\x40",
    });
    first
        .entry
        .attrs
        .sort_by(|left, right| left.name.cmp(right.name));
    let tree = Tree::build(
        entries,
        original.props().map(<[_]>::to_vec),
        guard.config().min_chunk_size,
        TreeUse::Ordinary,
    )
    .map_err(|_| invalid())?;
    request.commit.tree = tree.root_identity();
    request.uploads.retain(|upload| {
        !matches!(
            upload,
            StagedUpload::Meta {
                kind: IdentityKind::Node,
                ..
            }
        )
    });
    request
        .uploads
        .extend(tree.nodes().map(|node| StagedUpload::Meta {
            kind: IdentityKind::Node,
            bytes: node.encoded().to_vec(),
        }));
    Ok(request)
}

#[tokio::test]
async fn authoring_attribute_two_is_selected_before_candidate_signing() -> TestResult {
    let native = fixture().await;
    let legacy_attributes = observed_with_authoring(
        native.guard(),
        AuthoringNamespaceProfile::new(3, 3, &[], 1)?,
    );
    let active_attributes = observed_with_authoring(
        native.guard(),
        AuthoringNamespaceProfile::new(3, 3, &[], 2)?,
    );
    let old_pointer = namespace_pointer_request(&legacy_attributes).await?;
    let same_pointer = namespace_pointer_request(&active_attributes).await?;
    assert_eq!(old_pointer.commit.tree, same_pointer.commit.tree);

    let old = legacy_attributes.admit(REFERENCE, 1, old_pointer).await?;
    let refused = active_attributes.admit(REFERENCE, 1, same_pointer).await;
    let Err(failure) = refused else {
        panic!("active namespace attributes must refuse a structural pointer before signing");
    };
    assert!(
        matches!(failure.kind(), StoreErrorKind::Denied { verb: "commit", pattern } if pattern == REFERENCE)
    );

    let admitted = active_attributes
        .admit(
            REFERENCE,
            1,
            request_file(Vec::new(), b"ordinary namespace"),
        )
        .await?;
    assert!(admitted.commit.commit().signature.is_some());
    assert_eq!(old.admission_profile.attribute_revision, 1);
    assert_eq!(admitted.admission_profile.attribute_revision, 2);
    assert_eq!(admitted.admission_profile.property_revision, 3);
    assert_eq!(
        admitted.admission_profile,
        active_attributes.configured_authoring_registries()?,
    );
    let SelectedReadInterpretation::Recorded(selected) = &admitted.admission_interpretation else {
        panic!("the actual authoring producer must retain its executed Recorded selection");
    };
    assert_eq!(selected.view(), admitted.commit.identity());
    assert_eq!(selected.original_root(), admitted.commit.commit().tree);
    assert_eq!(selected.revision(), 3);
    assert!(selected.later_registered().is_empty());
    legacy_attributes.store().assert_no_effects();
    active_attributes.store().assert_no_effects();
    assert!(native.store().ref_get(REFERENCE).await?.is_none());
    Ok(())
}

#[tokio::test]
async fn authoring_selection_survives_staging_and_next_begin() -> TestResult {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::time::Duration;

    use crate::bucket::{FileBucket, FileBucketConfig, FileBucketPublicationConfig};
    use crate::domain::DomainNamespace;
    use crate::ref_advance::{CommitTiming, Coordinator, tests::Validator};
    use crate::repository::Repository;
    use crate::store::{LocalFs, TokioClock, TokioLocalFs};

    let seed = fixture().await;
    let entropy = TokioLocalFs.random_bytes(16).await?;
    let suffix = entropy
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let root = std::env::temp_dir().join(format!("terrane-authoring-{suffix}"));
    let control = root.with_file_name(format!("terrane-authoring-{suffix}-operator"));
    TokioLocalFs.create_dir_new(&control).await?;
    TokioLocalFs
        .set_permissions_and_sync(&control, std::fs::Permissions::from_mode(0o700))
        .await?;
    let owner = TokioLocalFs.symlink_metadata(&control).await?.uid();
    let config = seed.guard().config().clone();
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
        TokioLocalFs,
        TokioClock,
        Validator,
    )
    .await?;
    let guard = Guard::new_with_authoring_namespace_profile(
        bucket,
        TokioClock,
        seed.guard().keys().to_vec(),
        config,
        AuthoringNamespaceProfile::new(3, 3, &[], 2)?,
    );
    let coordinator = Coordinator::new(
        guard,
        CommitTiming::new(
            Duration::from_secs(30),
            Duration::from_secs(60),
            Duration::from_secs(10),
        )?,
        TokioLocalFs,
    );
    let repository = Repository::initialize_native_retention(
        coordinator,
        &DomainNamespace {
            root,
            domain: "public".to_owned(),
        },
        &control,
        owner,
    )
    .await?;
    let token = crate::ref_advance::tests::token();
    let mut session = repository.begin(REFERENCE, &token, "sdk").await?;
    let first = repository
        .commit_request(
            &mut session,
            request_file(Vec::new(), b"first selected view"),
        )
        .await?;

    let guard = repository.coordinator().guard();
    let history = guard.verified_history(first.commit).await?;
    let record = history.commit(&first.commit).ok_or_else(invalid)?;
    let (interpretation, profile) =
        guard.selected_view_profile(record, crate::guard::HistoryObservation::default())?;
    assert!(matches!(
        interpretation,
        SelectedReadInterpretation::Recorded(_)
    ));
    assert_eq!(profile, guard.configured_authoring_registries()?);
    assert_eq!(profile.attribute_revision, 2);
    assert_eq!(guard.store().ref_get(REFERENCE).await?, Some(first.clone()));

    let mut next_session = repository.begin(REFERENCE, &token, "sdk").await?;
    assert_eq!(next_session.record(), Some(&first));
    let second = repository
        .commit_request(
            &mut next_session,
            request_file(vec![first.commit], b"second selected view"),
        )
        .await?;
    assert_eq!(second.seq, first.seq + 1);
    let history = guard.verified_history(second.commit).await?;
    for identity in [first.commit, second.commit] {
        let record = history.commit(&identity).ok_or_else(invalid)?;
        let (selected, actual) =
            guard.selected_view_profile(record, crate::guard::HistoryObservation::default())?;
        assert!(matches!(selected, SelectedReadInterpretation::Recorded(_)));
        assert_eq!(actual, profile);
    }
    Ok(())
}

#[tokio::test]
async fn selected_required_index_refuses_existing_guard_profile_replacement() -> TestResult {
    use std::os::unix::fs::MetadataExt;
    use std::time::Duration;

    use crate::bucket::held::SingleHeld;
    use crate::domain::DomainNamespace;
    use crate::ref_advance::{CommitTiming, Coordinator};
    use crate::repository::Repository;
    use crate::store::{LocalFs, TokioClock, TokioLocalFs};

    let native = fixture().await;
    let root = native.store().root().to_owned();
    let authority = native.guard().configured_original_authority()?;
    let owner = TokioLocalFs.symlink_metadata(&root).await?.uid();
    let before = {
        let namespace = SingleHeld::acquire(native.store()).await?;
        namespace
            .destination()
            .observe_publication()
            .await?
            .state()
            .guard
    };
    // Authoring inputs alone preserve the protected configured-current profile.
    // Select a different current profile to exercise actual replacement refusal.
    let replacement = Guard::new_active(
        native.store().clone(),
        TokioClock,
        native.guard().keys().to_vec(),
        native.guard().config().clone(),
    )
    .with_recorded_authoring(
        terrane_format::properties::semantics::RecordedContext::new(3, 3, &[])?,
        2,
    )?;
    assert_ne!(
        replacement.configured_current_registries()?,
        native.guard().configured_current_registries()?
    );

    let reopened = Repository::reopen_native_retention(
        Coordinator::new(
            replacement,
            CommitTiming::new(
                Duration::from_secs(30),
                Duration::from_secs(60),
                Duration::from_secs(10),
            )?,
            TokioLocalFs,
        ),
        &DomainNamespace {
            root,
            domain: "public".to_owned(),
        },
        authority.control(),
        owner,
    )
    .await;
    let Err(crate::repository::Error::Store(failure)) = reopened else {
        panic!("native reopen must refuse replacement of the protected Guard profile");
    };
    assert!(matches!(
        failure.kind(),
        StoreErrorKind::Denied { verb: "guard-install", pattern }
            if pattern == native.store().root().to_string_lossy().as_ref()
    ));
    assert!(native.store().ref_get(REFERENCE).await?.is_none());
    let after = {
        let namespace = SingleHeld::acquire(native.store()).await?;
        namespace
            .destination()
            .observe_publication()
            .await?
            .state()
            .guard
    };
    assert_eq!(after, before);
    Ok(())
}

#[tokio::test]
async fn selected_required_index_publishes_real_context_and_full_carriers() -> TestResult {
    publication::selected_required_index_publishes_real_context_and_full_carriers().await
}

#[tokio::test]
async fn selected_required_index_refuses_divergence_before_immutable_effects() -> TestResult {
    publication::selected_required_index_refuses_divergence_before_immutable_effects().await
}

#[tokio::test]
async fn selected_required_index_preserves_old_inert_historical_profiles() -> TestResult {
    publication::selected_required_index_preserves_old_inert_historical_profiles().await
}

#[tokio::test]
async fn selected_required_index_distinguishes_preserved_gaps_and_dropped_bindings() -> TestResult {
    publication::selected_required_index_distinguishes_preserved_gaps_and_dropped_bindings().await
}

#[tokio::test]
async fn selected_required_index_policy_and_rollback_retain_actual_view_selection() -> TestResult {
    publication::selected_required_index_policy_and_rollback_retain_actual_view_selection().await
}

#[tokio::test]
async fn selected_required_index_adapter_and_reopen_keep_installed_inputs() -> TestResult {
    publication::selected_required_index_adapter_and_reopen_keep_installed_inputs().await
}

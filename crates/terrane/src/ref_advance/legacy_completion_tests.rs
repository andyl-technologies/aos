//! Checks genuine unindexed Legacy completion through retained native publication.

use terrane_core::gc::publication::evidence::{CheckedLineage, ViewInterpretationMode};
use terrane_core::identity::IdentityKind;
use terrane_core::properties::PropertyName;
use terrane_core::tree_builder::Tree;
use terrane_core::tree_format::{Property, TreeUse};

use super::tests::{fixture, request, token};
use super::{AdvanceError, StagedUpload};
use crate::bucket::held::SingleHeld;
use crate::store::{RefStore, StoreErrorKind};

/// Preserves concrete test diagnostics without hiding typed producer failures.
type TestResult<T = ()> = Result<T, Box<dyn core::error::Error>>;

#[tokio::test]
async fn native_legacy_completion_retains_every_signed_parent_context() -> TestResult {
    let repository = fixture().await;
    let reference = "refs/heads/_/main";
    let capability = token();
    let mut session = repository.begin(reference, &capability, "sdk").await?;
    let first = repository
        .advance(&mut session, request(Vec::new()))
        .await?;
    let first_tree = repository.guard().verified_tree(first.commit).await?;
    let first_root = first_tree.commit.commit().tree;
    drop(first_tree);
    let second = repository
        .advance(&mut session, request(vec![first.commit]))
        .await?;
    let second_tree = repository.guard().verified_tree(second.commit).await?;
    let second_root = second_tree.commit.commit().tree;
    drop(second_tree);

    let holder = SingleHeld::acquire(repository.store()).await?;
    let destination = holder.destination();
    let observation = destination.observe_publication().await?;
    let bytes = destination
        .selected_lineage(&observation, reference)
        .await?;
    assert!(bytes.is_some());
    let lineage = CheckedLineage::decode(&bytes.ok_or("missing selected lineage")?)?;
    assert_eq!(lineage.source, second);
    assert_eq!(lineage.commit_id, second.commit);
    assert_eq!(lineage.controls, lineage.used.controls);
    assert!(lineage.used.check_supported_view_contexts()?);
    let contexts = lineage
        .used
        .view_interpretations
        .as_ref()
        .ok_or("missing view contexts")?;
    assert_eq!(contexts.len(), 2);
    assert_eq!(lineage.used.views.len(), 2);
    let mut names = PropertyName::ALL
        .iter()
        .map(|name| name.as_str().to_owned())
        .collect::<Vec<_>>();
    names.sort();
    for (identity, root) in [(first.commit, first_root), (second.commit, second_root)] {
        let context = contexts
            .iter()
            .find(|context| context.view == identity)
            .ok_or("missing actual view")?;
        assert_eq!(context.original_root, root);
        assert_eq!(context.mode, ViewInterpretationMode::Legacy);
        assert_eq!(context.registries.attribute_revision, 1);
        assert_eq!(context.registries.behavioral_properties, names);
        assert_eq!(context.registries, lineage.used.registries);
        let view = lineage
            .used
            .views
            .iter()
            .find(|view| view.view == identity)
            .ok_or("missing actual policies")?;
        assert_eq!(view.roots.len(), 1);
        assert_eq!(view.roots[0].root, root);
        assert_eq!(view.roots[0].path, b"/");
    }
    observation.revalidate().await?;
    Ok(())
}

#[tokio::test]
async fn native_legacy_completion_refuses_required_index_without_selected_ack() -> TestResult {
    let repository = fixture().await;
    let reference = "refs/heads/_/main";
    let capability = token();
    let mut session = repository.begin(reference, &capability, "sdk").await?;
    let first = repository
        .advance(&mut session, request(Vec::new()))
        .await?;
    let before = {
        let holder = SingleHeld::acquire(repository.store()).await?;
        let destination = holder.destination();
        let observation = destination.observe_publication().await?;
        (
            observation.state().clone(),
            destination
                .selected_lineage(&observation, reference)
                .await?,
        )
    };
    let tree = Tree::build(
        Vec::new(),
        Some(vec![
            Property {
                name: "acl",
                value: b"\x81\x82\x66writer\x18\x1f",
            },
            Property {
                name: "index",
                value: b"\x81\x63uid",
            },
            Property {
                name: "domain",
                value: b"\x66public",
            },
        ]),
        repository.guard().config().min_chunk_size,
        TreeUse::Ordinary,
    )?;
    let mut candidate = request(vec![first.commit]);
    candidate.commit.tree = tree.root_identity();
    candidate.uploads = tree
        .nodes()
        .map(|node| StagedUpload::Meta {
            kind: IdentityKind::Node,
            bytes: node.encoded().to_vec(),
        })
        .collect();
    drop(tree);
    let failure = repository.advance(&mut session, candidate).await;
    assert!(
        matches!(failure, Err(AdvanceError::Store(ref failure)) if matches!(failure.kind(), StoreErrorKind::Unsupported))
    );
    assert_eq!(repository.store().ref_get(reference).await?, Some(first));
    let holder = SingleHeld::acquire(repository.store()).await?;
    let destination = holder.destination();
    let observation = destination.observe_publication().await?;
    assert_eq!(observation.state().branches, before.0.branches);
    assert_eq!(observation.state().sources, before.0.sources);
    assert_eq!(observation.state().guard, before.0.guard);
    assert_eq!(
        observation.state().loss_generation,
        before.0.loss_generation
    );
    assert_eq!(
        destination
            .selected_lineage(&observation, reference)
            .await?,
        before.1
    );
    Ok(())
}

#[tokio::test]
async fn native_legacy_completion_checks_each_signed_requirement_field() -> TestResult {
    use crate::guard::{ConsumedResolver, HistoryObservation};
    use crate::store::TokioClock;

    let repository = fixture().await;
    let reference = "refs/heads/_/main";
    let mut session = repository.begin(reference, &token(), "sdk").await?;
    let first = repository
        .advance(&mut session, request(Vec::new()))
        .await?;
    let actual = repository.guard().verified_tree(first.commit).await?;
    let authority = repository
        .guard()
        .original_commit(&first.commit)?
        .baseline()
        .authority()
        .clone();
    let source = actual
        .commit
        .commit()
        .profile_pair
        .required_properties
        .as_deref()
        .ok_or("missing genuine requirements")?;
    let before = {
        let holder = SingleHeld::acquire(repository.store()).await?;
        let destination = holder.destination();
        let observed = destination.observe_publication().await?;
        destination.selected_lineage(&observed, reference).await?
    };

    for (name, value) in [
        ("index", b"\x81\x63uid".as_slice()),
        ("hashes", b"\x81\x66sha256".as_slice()),
        ("classify", b"\x81\x64text".as_slice()),
        ("strict-attrs", b"".as_slice()),
    ] {
        let mut candidate = actual.commit.commit().clone();
        candidate.profile_pair.required_properties =
            Some(replace_requirement(source, name, value)?);
        let signed = sign_actual_scope(&repository, candidate)?;
        let identity = put_signed(&repository, &signed).await?;
        let holder = SingleHeld::acquire(repository.store()).await?;
        let destination = holder.destination();
        let observed = destination.observe_publication().await?;
        let concrete = repository
            .guard()
            .held_guard(holder.destination(), TokioClock)?;
        let consumed = ConsumedResolver::new(&concrete, &authority)?;
        consumed.registration(&authority)?;
        let history = HistoryObservation::held(observed.identity()).tracked(&consumed);
        let result = concrete.verified_history_observed(identity, history).await;
        let failure = result
            .err()
            .ok_or("contradictory signed requirements unexpectedly completed")?;
        assert!(matches!(
            failure.kind(),
            StoreErrorKind::Invalid(crate::store::InvalidReason::MalformedRequest)
        ));

        // Signature-only verification succeeds, but contradiction is detected
        // before pending insertion or any absent Original could be the refusal.
        assert!(
            consumed
                .observed_completed_view_contexts_for_tests()?
                .is_empty()
        );
        let trace = consumed.finish()?;
        assert!(trace.views.is_empty());
        assert_eq!(trace.view_interpretations, Some(Vec::new()));
        assert_eq!(
            destination.selected_lineage(&observed, reference).await?,
            before
        );
        observed.revalidate().await?;
    }
    assert_eq!(repository.store().ref_get(reference).await?, Some(first));
    Ok(())
}

#[tokio::test]
async fn native_legacy_completion_refuses_historical_binding_with_empty_head_index() -> TestResult {
    use crate::guard::{ConsumedResolver, HistoryObservation};
    use crate::store::{ContentStore, ContentUpload, MetaUpload, TokioClock};

    let repository = fixture().await;
    let reference = "refs/heads/_/main";
    let mut session = repository.begin(reference, &token(), "sdk").await?;
    let first = repository
        .advance(&mut session, request(Vec::new()))
        .await?;
    let actual = repository.guard().verified_tree(first.commit).await?;
    let authority = repository
        .guard()
        .original_commit(&first.commit)?
        .baseline()
        .authority()
        .clone();
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
                name: "index-roots",
                value: b"\xa2\x65value\xa0\x67inherit\xf4",
            },
        ]),
        repository.guard().config().min_chunk_size,
        TreeUse::Ordinary,
    )?;
    let parent_root = tree.root_identity();
    let nodes = tree
        .nodes()
        .map(|node| node.encoded().to_vec())
        .collect::<Vec<_>>();
    drop(tree);
    for bytes in nodes {
        repository
            .store()
            .put(ContentUpload::Meta(MetaUpload::new(
                IdentityKind::Node,
                &bytes,
            )?))
            .await?;
    }
    let mut parent = actual.commit.commit().clone();
    parent.tree = parent_root;
    let parent = sign_actual_scope(&repository, parent)?;
    put_signed(&repository, &parent).await?;
    let mut head = actual.commit.commit().clone();
    head.parents = vec![parent.identity()];
    let head = sign_actual_scope(&repository, head)?;
    let identity = put_signed(&repository, &head).await?;
    assert_eq!(head.commit().tree, actual.commit.commit().tree);
    assert_eq!(
        head.commit().profile_pair.required_properties,
        actual.commit.commit().profile_pair.required_properties
    );

    let holder = SingleHeld::acquire(repository.store()).await?;
    let destination = holder.destination();
    let observed = destination.observe_publication().await?;
    let before = destination.selected_lineage(&observed, reference).await?;
    let concrete = repository
        .guard()
        .held_guard(holder.destination(), TokioClock)?;
    let consumed = ConsumedResolver::new(&concrete, &authority)?;
    consumed.registration(&authority)?;
    let history = HistoryObservation::held(observed.identity()).tracked(&consumed);
    let failure = concrete
        .verified_history_observed(identity, history)
        .await
        .err()
        .ok_or("historical binding unexpectedly completed")?;
    // Ordinary authoring resolution rejects an unregistered local binding
    // before completion preparation; the empty-index head cannot hide it.
    assert!(matches!(
        failure.kind(),
        StoreErrorKind::Invalid(crate::store::InvalidReason::MalformedRequest)
    ));
    assert!(
        consumed
            .observed_completed_view_contexts_for_tests()?
            .is_empty()
    );
    let pending = consumed
        .finish()
        .err()
        .ok_or("head preparation was unexpectedly completed")?;
    assert!(matches!(
        pending.kind(),
        StoreErrorKind::Invalid(crate::store::InvalidReason::MalformedRequest)
    ));
    assert_eq!(
        destination.selected_lineage(&observed, reference).await?,
        before
    );
    observed.revalidate().await?;
    drop(concrete);
    drop(observed);
    drop(destination);
    drop(holder);
    assert_eq!(repository.store().ref_get(reference).await?, Some(first));
    Ok(())
}

#[tokio::test]
async fn native_legacy_completion_late_original_failure_promotes_no_views() -> TestResult {
    use crate::guard::{ConsumedResolver, HistoryObservation};
    use crate::store::{LocalFs, TokioClock, TokioLocalFs};
    use core::error::Error;

    let repository = fixture().await;
    let reference = "refs/heads/_/main";
    let mut session = repository.begin(reference, &token(), "sdk").await?;
    let first = repository
        .advance(&mut session, request(Vec::new()))
        .await?;
    let second = repository
        .advance(&mut session, request(vec![first.commit]))
        .await?;
    let original = repository.guard().original_commit(&second.commit)?;
    let authority = original.baseline().authority().clone();
    let association = authority.control().join(format!(
        "commit-{}.cbor",
        second
            .commit
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    ));
    let saved = association.with_extension("saved");
    let before = {
        let holder = SingleHeld::acquire(repository.store()).await?;
        let destination = holder.destination();
        let observed = destination.observe_publication().await?;
        destination.selected_lineage(&observed, reference).await?
    };
    TokioLocalFs.rename(&association, &saved).await?;
    TokioLocalFs.sync_directory(authority.control()).await?;

    let holder = SingleHeld::acquire(repository.store()).await?;
    let destination = holder.destination();
    let observed = destination.observe_publication().await?;
    let concrete = repository
        .guard()
        .held_guard(holder.destination(), TokioClock)?;
    let consumed = ConsumedResolver::new(&concrete, &authority)?;
    consumed.registration(&authority)?;
    let history = HistoryObservation::held(observed.identity()).tracked(&consumed);
    let result = concrete
        .verified_history_observed(second.commit, history)
        .await;
    // Restore real bytes and their incarnation before asserting the outcome.
    // The first parent remained present and is independently checked first.
    TokioLocalFs.rename(&saved, &association).await?;
    TokioLocalFs.sync_directory(authority.control()).await?;
    let failure = result
        .err()
        .ok_or("missing actual Original association unexpectedly completed")?;
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
    let pending = consumed
        .finish()
        .err()
        .ok_or("failed history unexpectedly finalized pending views")?;
    assert!(matches!(
        pending.kind(),
        StoreErrorKind::Invalid(crate::store::InvalidReason::MalformedRequest)
    ));
    assert_eq!(
        destination.selected_lineage(&observed, reference).await?,
        before
    );
    observed.revalidate().await?;
    drop(concrete);
    drop(observed);
    drop(destination);
    drop(holder);
    assert_eq!(
        repository.store().ref_get(reference).await?,
        Some(second.clone())
    );
    // Restored physical association permits actual independent full verification.
    repository.guard().verified_history(second.commit).await?;
    Ok(())
}

fn replace_requirement(source: &[u8], replaced: &str, replacement: &[u8]) -> TestResult<Vec<u8>> {
    use terrane_core::cbor::{self, Decoder};
    let mut decoder = Decoder::new(source);
    assert_eq!(decoder.map(4)?, 4);
    let mut output = Vec::new();
    cbor::write_map(&mut output, 4);
    let mut changed = false;
    for _ in 0..4 {
        let name = decoder.text(32)?;
        let bytes = decoder.raw_value(65536)?;
        cbor::write_text(&mut output, name);
        if name == replaced {
            changed = true;
            if name == "strict-attrs" {
                assert!(bytes == [0xf4] || bytes == [0xf5]);
                output.push(if bytes == [0xf4] { 0xf5 } else { 0xf4 });
            } else {
                output.extend_from_slice(replacement);
            }
        } else {
            output.extend_from_slice(bytes);
        }
    }
    decoder.finish()?;
    assert!(changed);
    assert_ne!(source, output);
    Ok(output)
}

fn sign_actual_scope(
    repository: &super::native_fixture::NativeFixture<crate::store::TokioLocalFs>,
    mut commit: terrane_core::refs::Commit,
) -> TestResult<terrane_core::provenance::VerifiedCommit> {
    use terrane_core::auth::{Request, RequestRoot, Verb};
    let context = commit
        .profile_pair
        .commit_context
        .clone()
        .ok_or("missing actual signed scope")?;
    let roots = context
        .roots()
        .iter()
        .map(|root| RequestRoot {
            path: root.path(),
            domain: root.domain(),
        })
        .collect::<Vec<_>>();
    let epoch = commit.provenance.writer_epoch;
    let epochs = [(context.reference(), epoch)];
    let request = Request {
        reference: context.reference().as_bytes(),
        verb: Verb::Commit,
        roots: &roots,
        now: commit.timestamp,
        surface: context.surface(),
        locality: context.locality(),
        epochs: &epochs,
    };
    commit.signature = None;
    let signed = terrane_core::provenance::sign_authored(
        commit,
        &super::tests::secret(),
        repository.guard().keys(),
        &request,
        epoch,
    )?;
    let verified = terrane_core::provenance::verify_history(
        signed.commit(),
        repository.guard().keys(),
        &roots,
        &epochs,
    )?;
    assert_eq!(verified.identity(), signed.identity());
    Ok(signed)
}

async fn put_signed(
    repository: &super::native_fixture::NativeFixture<crate::store::TokioLocalFs>,
    signed: &terrane_core::provenance::VerifiedCommit,
) -> TestResult<[u8; 32]> {
    use crate::store::{ContentStore, ContentUpload, MetaUpload};
    let bytes = signed.commit().encode()?;
    let stored = repository
        .store()
        .put(ContentUpload::Meta(MetaUpload::new(
            IdentityKind::Commit,
            &bytes,
        )?))
        .await?;
    assert_eq!(stored.terrane_v1_digest()?, signed.identity());
    Ok(signed.identity())
}

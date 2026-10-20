//! Checks explicit active selection through genuine native signed-history publication.

#[path = "recorded_selection_tests.rs"]
mod recorded_selection_tests;
mod support;

use super::tests::{request, token};
use crate::bucket::held::SingleHeld;
use crate::store::{ContentStore, RefStore, StoreErrorKind, StoreFailure, TokioClock};
use support::{Native, fixture, indexed};
use terrane_format::gc::publication::evidence::{CheckedLineage, ViewInterpretationMode};
use terrane_format::identity::{Digest, IdentityKind, TERRANE_V1};

type Result<T = ()> = core::result::Result<T, Box<dyn core::error::Error>>;
const REFERENCE: &str = "refs/heads/_/main";

#[tokio::test]
async fn native_active_completion_direct_history_refuses_missing_required_auxiliary() -> Result {
    use crate::guard::StagedUpload;
    use crate::store::{ContentUpload, LocalFs, MetaUpload, TokioLocalFs};

    let repository = fixture(true).await?;
    let mut proposal = indexed(Vec::new(), false)?;
    let primary = proposal.primary;
    let owner = proposal.owner;
    // Genuine immutable offers isolate auxiliary storage before authoring. The
    // signed owner still binds the same complete independently built index.
    for (address, bytes) in &proposal.index_nodes {
        let identity = repository
            .coordinator()
            .store()
            .put(ContentUpload::Meta(MetaUpload::new(
                IdentityKind::Node,
                bytes,
            )?))
            .await?;
        assert_eq!(identity.terrane_v1_digest()?, *address);
    }
    let auxiliary = proposal
        .index_nodes
        .keys()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    let mut uploads = Vec::new();
    for upload in proposal.request.uploads {
        let omit = match &upload {
            StagedUpload::Meta {
                kind: IdentityKind::Node,
                bytes,
            } => auxiliary.contains(
                &TERRANE_V1
                    .calculate(IdentityKind::Node, bytes)?
                    .terrane_v1_digest()?,
            ),
            _ => false,
        };
        if !omit {
            uploads.push(upload);
        }
    }
    proposal.request.uploads = uploads;
    let mut session = repository.begin(REFERENCE, &token(), "sdk").await?;
    let first = repository
        .commit_request(&mut session, proposal.request)
        .await?;
    let second = repository
        .commit_request(&mut session, indexed(vec![first.commit], false)?.request)
        .await?;
    assert_ne!(first.commit, second.commit);

    let store = repository.coordinator().store();
    let mut primary_pack = None;
    for directory in TokioLocalFs
        .read_dir(&store.root().join("objects/pack"))
        .await?
    {
        for path in TokioLocalFs.read_dir(&directory).await? {
            if path
                .extension()
                .is_some_and(|extension| extension == "pack")
            {
                let bytes = TokioLocalFs.read_nofollow(&path).await?;
                let reader = crate::pack::PackReader::open(&bytes)?;
                if reader
                    .entries()
                    .iter()
                    .any(|entry| entry.hash() == &primary)
                {
                    assert!(
                        reader
                            .entries()
                            .iter()
                            .all(|entry| auxiliary.contains(entry.hash()))
                    );
                    assert!(primary_pack.replace(path).is_none());
                }
            }
        }
    }
    let primary_pack = primary_pack.ok_or("genuine auxiliary-only primary pack absent")?;
    let before = {
        let holder = SingleHeld::acquire(store).await?;
        let destination = holder.destination();
        let observed = destination.observe_publication().await?;
        let lineage = destination.selected_lineage(&observed, REFERENCE).await?;
        observed.revalidate().await?;
        lineage
    };
    let guard = repository.coordinator().guard();
    for tree_and_history in [false, true] {
        let baseline =
            direct_auxiliary_witness(&repository, first.commit, second.commit, tree_and_history)
                .await?;
        assert_eq!(baseline.commit().tree, owner);

        let saved = primary_pack.with_extension("required-auxiliary-saved");
        TokioLocalFs.rename(&primary_pack, &saved).await?;
        let refused =
            direct_auxiliary_witness(&repository, first.commit, second.commit, tree_and_history)
                .await;
        // Canonical signed namespace remains readable while the actual required
        // auxiliary recipe is absent; this is not shared-pack corruption.
        let canonical = crate::guard::TreeEvidence::load_commit(
            store,
            first.commit,
            guard.config().min_chunk_size,
        )
        .await;
        TokioLocalFs.rename(&saved, &primary_pack).await?;
        let canonical = canonical?;
        assert_eq!(canonical.root, owner);
        assert_eq!(canonical.commit.as_ref(), Some(baseline.commit()));
        assert!(
            refused.is_err(),
            "missing required auxiliary completed direct history"
        );
        let restored =
            direct_auxiliary_witness(&repository, first.commit, second.commit, tree_and_history)
                .await?;
        assert_eq!(restored, baseline);
        assert_eq!(store.ref_get(REFERENCE).await?, Some(second.clone()));
    }
    let holder = SingleHeld::acquire(store).await?;
    let destination = holder.destination();
    let observed = destination.observe_publication().await?;
    assert_eq!(
        destination.selected_lineage(&observed, REFERENCE).await?,
        before
    );
    observed.revalidate().await?;
    Ok(())
}

// Both tokenless APIs complete owning history. Tree intentionally exposes only
// its actual tree/commit witness, so no hidden completed-ledger count is claimed.
async fn direct_auxiliary_witness(
    repository: &Native,
    target: Digest,
    current: Digest,
    tree_and_history: bool,
) -> Result<terrane_format::provenance::VerifiedCommit> {
    let guard = repository.coordinator().guard();
    let observation = crate::guard::HistoryObservation::default();
    if tree_and_history {
        let tree = guard.verified_tree_observed(target, observation).await?;
        assert_eq!(tree.commit.identity(), target);
        assert_eq!(tree.evidence.root, tree.commit.commit().tree);
        Ok(tree.commit)
    } else {
        let history = guard.verified_history_observed(target, observation).await?;
        assert_eq!(history.commits().count(), 1);
        assert!(history.commit(&current).is_none());
        Ok(history
            .commit(&target)
            .ok_or("historical target absent")?
            .clone())
    }
}

#[tokio::test]
async fn native_active_completion_verifies_indexed_owner_before_selected_ack() -> Result {
    let repository = fixture(true).await?;
    let proposal = indexed(Vec::new(), false)?;
    let owner = proposal.owner;
    let primary = proposal.primary;
    let mut session = repository.begin(REFERENCE, &token(), "sdk").await?;
    let first = repository
        .commit_request(&mut session, proposal.request)
        .await?;
    let second = repository
        .commit_request(&mut session, indexed(vec![first.commit], false)?.request)
        .await?;
    assert_eq!(
        repository.coordinator().store().ref_get(REFERENCE).await?,
        Some(second.clone())
    );
    let holder = SingleHeld::acquire(repository.coordinator().store()).await?;
    let destination = holder.destination();
    let observed = destination.observe_publication().await?;
    let concrete = repository
        .coordinator()
        .guard()
        .held_guard(holder.destination(), TokioClock)?;
    let bytes = destination
        .selected_lineage(&observed, REFERENCE)
        .await?
        .ok_or("native ACK has no selected lineage")?;
    let lineage = CheckedLineage::decode(&bytes)?;
    assert!(lineage.used.check_supported_view_contexts()?);
    let contexts = lineage
        .used
        .view_interpretations
        .as_ref()
        .ok_or("missing genuine completed contexts")?;
    assert_eq!(contexts.len(), 2);
    for context in contexts {
        assert_eq!(context.mode, ViewInterpretationMode::Recorded);
        assert_eq!(
            (
                context.registries.property_revision,
                context.registries.attribute_revision,
                context.registries.tree_revision
            ),
            (3, 2, 1)
        );
        assert_eq!(context.registries.behavioral_properties.len(), 35);
        assert_eq!(context.original_root, owner);
        // Original verification must reuse the live namespace exclusion.
        let actual = concrete
            .verified_tree_observed(
                context.view,
                crate::guard::HistoryObservation::held(observed.identity()),
            )
            .await?;
        assert_eq!(actual.commit.commit().tree, context.original_root);
        assert!(
            lineage
                .used
                .views
                .iter()
                .any(|view| view.view == context.view)
        );
    }
    let loaded = crate::indexing::load(
        &destination,
        owner,
        "uid",
        crate::indexing::SemanticRevisions {
            property: 3,
            attribute: 2,
            tree: 1,
        },
        262144,
    )
    .await?;
    assert_eq!(loaded.index_root(), primary);
    {
        let sources = loaded.sources()?;
        let prepared = loaded.prepare(&sources.trees)?;
        assert_eq!(prepared.preparation().verification.candidates, 1);
    }
    observed.revalidate().await?;
    Ok(())
}

#[tokio::test]
async fn native_active_completion_checks_every_shared_graft_occurrence() -> Result {
    let repository = fixture(true).await?;
    let proposal = indexed(Vec::new(), true)?;
    let owner = proposal.owner;
    let mut session = repository.begin(REFERENCE, &token(), "sdk").await?;
    let record = repository
        .commit_request(&mut session, proposal.request)
        .await?;
    let holder = SingleHeld::acquire(repository.coordinator().store()).await?;
    let destination = holder.destination();
    let observed = destination.observe_publication().await?;
    let bytes = destination
        .selected_lineage(&observed, REFERENCE)
        .await?
        .ok_or("missing selected lineage")?;
    let lineage = CheckedLineage::decode(&bytes)?;
    assert_eq!(lineage.used.views.len(), 1);
    let view = &lineage.used.views[0];
    assert_eq!(view.view, record.commit);
    // The occurrence stack visits the right graft before the left graft.
    assert_eq!(
        view.roots
            .iter()
            .map(|root| root.path.as_slice())
            .collect::<Vec<_>>(),
        vec![b"/".as_slice(), b"/right".as_slice(), b"/left".as_slice()]
    );
    assert_eq!(view.roots[1].root, view.roots[2].root);
    let context = lineage
        .used
        .view_interpretations
        .as_ref()
        .ok_or("missing context")?;
    assert_eq!(context.len(), 1);
    assert_eq!(context[0].original_root, owner);
    assert_eq!(context[0].mode, ViewInterpretationMode::Recorded);
    assert_eq!(context[0].registries.attribute_revision, 2);
    observed.revalidate().await?;
    Ok(())
}

#[tokio::test]
async fn native_active_completion_missing_primary_never_selects_ref_or_lineage() -> Result {
    let repository = fixture(true).await?;
    let mut proposal = indexed(Vec::new(), false)?;
    let missing = TERRANE_V1.from_digest(IdentityKind::Node, &proposal.primary)?;
    let mut uploads = Vec::new();
    let mut removed = 0;
    for upload in proposal.request.uploads {
        let omit = match &upload {
            crate::guard::StagedUpload::Meta {
                kind: IdentityKind::Node,
                bytes,
            } => TERRANE_V1.calculate(IdentityKind::Node, bytes)? == missing,
            _ => false,
        };
        if omit {
            removed += 1;
        } else {
            uploads.push(upload);
        }
    }
    assert_eq!(removed, 1);
    proposal.request.uploads = uploads;
    let mut session = repository.begin(REFERENCE, &token(), "sdk").await?;
    let failure = store_failure(
        repository
            .commit_request(&mut session, proposal.request)
            .await
            .err()
            .ok_or("missing relationship acknowledged")?,
    );
    assert!(matches!(failure.kind(),StoreErrorKind::Absent(identity) if identity == &missing));
    assert_eq!(
        repository.coordinator().store().ref_get(REFERENCE).await?,
        None
    );
    let holder = SingleHeld::acquire(repository.coordinator().store()).await?;
    let destination = holder.destination();
    let observed = destination.observe_publication().await?;
    assert_eq!(
        destination.selected_lineage(&observed, REFERENCE).await?,
        None
    );
    observed.revalidate().await?;
    Ok(())
}

#[tokio::test]
async fn native_active_completion_legacy_one_never_coerces_indexed_view() -> Result {
    let repository = fixture(false).await?;
    let proposal = indexed(Vec::new(), false)?;
    let offered = proposal
        .request
        .uploads
        .iter()
        .map(|upload| match upload {
            crate::guard::StagedUpload::Meta { kind, bytes } => TERRANE_V1.calculate(*kind, bytes),
            crate::guard::StagedUpload::Chunk { identity, .. } => Ok(identity.clone()),
        })
        .collect::<core::result::Result<Vec<_>, _>>()?;
    {
        let owner_identity = TERRANE_V1.from_digest(IdentityKind::Node, &proposal.owner)?;
        let owner_bytes = proposal
            .request
            .uploads
            .iter()
            .find_map(|upload| match upload {
                crate::guard::StagedUpload::Meta {
                    kind: IdentityKind::Node,
                    bytes,
                } if TERRANE_V1
                    .calculate(IdentityKind::Node, bytes)
                    .ok()
                    .as_ref()
                    == Some(&owner_identity) =>
                {
                    Some(bytes)
                }
                _ => None,
            })
            .ok_or("indexed owner upload missing")?;
        let owner = terrane_format::tree_format::decode_node_for(
            owner_bytes,
            true,
            262144,
            terrane_format::tree_format::TreeUse::Ordinary,
        )?;
        let properties = owner.props.ok_or("indexed owner properties missing")?;
        let active_context =
            terrane_format::properties::semantics::RecordedContext::new(3, 3, &[])?;
        active_context.validate_map(&properties)?;
        assert_eq!(
            terrane_format::properties::semantics::RecordedContext::new(1, 1, &[])?
                .validate_map(&properties),
            Err(terrane_format::properties::Error::UnknownProperty)
        );
        let binding = properties
            .iter()
            .find(|property| property.name == "index-roots")
            .ok_or("indexed owner binding missing")?;
        assert_eq!(
            terrane_format::properties::semantics::RecordedContext::new(1, 1, &[])?
                .validate_map(core::slice::from_ref(binding)),
            Err(terrane_format::properties::Error::UnknownProperty)
        );
    }

    // The same complete canonical namespace and carriers genuinely publish
    // under Active selection; refusal below cannot be an unrelated bad upload.
    let active = fixture(true).await?;
    let mut active_request = request(Vec::new());
    active_request.commit = proposal.request.commit.clone();
    active_request.uploads = proposal.request.uploads.clone();
    let mut active_session = active.begin(REFERENCE, &token(), "sdk").await?;
    active
        .commit_request(&mut active_session, active_request)
        .await?;
    let loaded = crate::indexing::load(
        active.coordinator().store(),
        proposal.owner,
        "uid",
        crate::indexing::SemanticRevisions {
            property: 3,
            attribute: 2,
            tree: 1,
        },
        262144,
    )
    .await?;
    assert_eq!(loaded.index_root(), proposal.primary);
    let sources = loaded.sources()?;
    let prepared = loaded.prepare(&sources.trees)?;
    assert_eq!(prepared.preparation().verification.candidates, 1);

    assert_eq!(
        repository.coordinator().guard().semantic_selection(),
        terrane_format::properties::selected::Selection::Legacy
    );
    assert_eq!(
        repository.coordinator().store().has(&offered).await?,
        vec![false; offered.len()]
    );
    let mut session = repository.begin(REFERENCE, &token(), "sdk").await?;
    let failure = store_failure(
        repository
            .commit_request(&mut session, proposal.request)
            .await
            .err()
            .ok_or("Legacy constructor accepted active bindings")?,
    );
    // Fresh affected-root derivation rejects the unregistered Legacy binding
    // before current ACL authorization; it maps that invalid map to Invalid.
    assert!(
        matches!(
            failure.kind(),
            StoreErrorKind::Invalid(crate::store::InvalidReason::MalformedRequest)
        ),
        "Legacy indexed publication refusal: {failure:?}"
    );
    assert_eq!(
        repository.coordinator().store().ref_get(REFERENCE).await?,
        None
    );
    assert_eq!(
        repository.coordinator().store().has(&offered).await?,
        vec![false; offered.len()]
    );
    assert_eq!(
        repository.coordinator().guard().semantic_selection(),
        terrane_format::properties::selected::Selection::Legacy
    );
    {
        let holder = SingleHeld::acquire(repository.coordinator().store()).await?;
        let destination = holder.destination();
        let observed = destination.observe_publication().await?;
        assert_eq!(
            destination.selected_lineage(&observed, REFERENCE).await?,
            None
        );
        observed.revalidate().await?;
    }
    drop(session);
    let mut ordinary_session = repository.begin(REFERENCE, &token(), "sdk").await?;
    let ordinary = repository
        .commit_request(&mut ordinary_session, request(Vec::new()))
        .await?;
    let holder = SingleHeld::acquire(repository.coordinator().store()).await?;
    let destination = holder.destination();
    let observed = destination.observe_publication().await?;
    let lineage = CheckedLineage::decode(
        &destination
            .selected_lineage(&observed, REFERENCE)
            .await?
            .ok_or("missing ordinary lineage")?,
    )?;
    let contexts = lineage
        .used
        .view_interpretations
        .as_ref()
        .ok_or("missing explicit Legacy context")?;
    assert_eq!(contexts.len(), 1);
    assert_eq!(contexts[0].view, ordinary.commit);
    assert_eq!(contexts[0].mode, ViewInterpretationMode::Legacy);
    assert_eq!(
        (
            contexts[0].registries.property_revision,
            contexts[0].registries.attribute_revision
        ),
        (1, 1)
    );
    observed.revalidate().await?;
    Ok(())
}

#[tokio::test]
async fn native_active_completion_conflicting_same_view_selection_refuses() -> Result {
    let active = fixture(true).await?;
    let legacy = fixture(false).await?;
    let mut session = active.begin(REFERENCE, &token(), "sdk").await?;
    let record = active
        .commit_request(&mut session, request(Vec::new()))
        .await?;
    let guard = active.coordinator().guard();
    let mut history = guard.verified_history(record.commit).await?;
    let actual = guard.verified_tree(record.commit).await?;
    let different = legacy.coordinator().guard().semantic_selection();
    let (property_selection, _) =
        guard.selected_view_context_for_tests(record.commit, actual.evidence.root)?;
    assert_eq!(
        property_selection,
        terrane_format::properties::selected::Selection::Recorded(
            terrane_format::properties::semantics::RecordedContext::new(3, 3, &[])?,
        )
    );
    assert_ne!(property_selection, different);
    assert!(matches!(
        history.insert_commit_selected(actual.commit.clone(), different),
        Err(terrane_format::provenance::Rejected)
    ));
    assert_eq!(history.commit(&record.commit), Some(&actual.commit));
    history.insert_commit_selected(actual.commit.clone(), property_selection)?;
    assert_eq!(history.commit(&record.commit), Some(&actual.commit));
    assert_eq!(
        active.coordinator().store().ref_get(REFERENCE).await?,
        Some(record)
    );
    Ok(())
}

fn store_failure(error: crate::repository::Error) -> StoreFailure {
    match error {
        crate::repository::Error::Store(failure)
        | crate::repository::Error::Advance(super::AdvanceError::Store(failure)) => failure,
        error => panic!("expected exact native store failure, got {error:?}"),
    }
}

#[tokio::test]
async fn native_active_completion_checks_each_signed_requirement_field() -> Result {
    use crate::guard::{ConsumedResolver, Guard, HistoryObservation, ViewSelection};
    use crate::store::TokioClock;

    let repository = fixture(true).await?;
    let reference = "refs/heads/_/main";
    let mut session = repository.begin(reference, &token(), "sdk").await?;
    let first = repository
        .commit_request(&mut session, indexed(Vec::new(), false)?.request)
        .await?;
    let actual = repository
        .coordinator()
        .guard()
        .verified_tree(first.commit)
        .await?;
    let authority = repository
        .coordinator()
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
        let holder = SingleHeld::acquire(repository.coordinator().store()).await?;
        let destination = holder.destination();
        let observed = destination.observe_publication().await?;
        destination.selected_lineage(&observed, reference).await?
    };

    for (name, value) in [
        ("index", b"\x80".as_slice()),
        ("hashes", b"\x81\x66sha256".as_slice()),
        ("classify", b"\x81\x64text".as_slice()),
        ("strict-attrs", b"".as_slice()),
    ] {
        let mut candidate = actual.commit.commit().clone();
        candidate.profile_pair.required_properties =
            Some(replace_requirement(source, name, value)?);
        let signed = sign_actual_scope(&repository, candidate)?;
        let identity = put_signed(&repository, &signed).await?;
        // Each independently signed view needs its own operator-installed inputs.
        // This ordinary association supplies neither Original nor completion.
        let configured = Guard::new_active(
            repository.coordinator().store().clone(),
            TokioClock,
            repository.coordinator().guard().keys().to_vec(),
            repository.coordinator().guard().config().clone(),
        )
        .with_view_selections(vec![ViewSelection::new(
            identity,
            signed.commit().tree,
            terrane_format::properties::selected::Selection::Recorded(
                terrane_format::properties::semantics::RecordedContext::new(3, 3, &[])?,
            ),
            2,
        )?])?;
        configured.install_original_verifier(&authority).await?;
        let holder = SingleHeld::acquire(repository.coordinator().store()).await?;
        let destination = holder.destination();
        let observed = destination.observe_publication().await?;
        let concrete = configured.held_guard(holder.destination(), TokioClock)?;
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
    assert_eq!(
        repository.coordinator().store().ref_get(reference).await?,
        Some(first)
    );
    Ok(())
}

#[tokio::test]
async fn native_active_completion_late_original_failure_promotes_no_views() -> Result {
    use crate::guard::{ConsumedResolver, HistoryObservation};
    use crate::store::{LocalFs, TokioClock, TokioLocalFs};
    use core::error::Error;

    let repository = fixture(true).await?;
    let reference = "refs/heads/_/main";
    let mut session = repository.begin(reference, &token(), "sdk").await?;
    let first = repository
        .commit_request(&mut session, indexed(Vec::new(), false)?.request)
        .await?;
    let second = repository
        .commit_request(&mut session, indexed(vec![first.commit], false)?.request)
        .await?;
    let original = repository
        .coordinator()
        .guard()
        .original_commit(&second.commit)?;
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
        let holder = SingleHeld::acquire(repository.coordinator().store()).await?;
        let destination = holder.destination();
        let observed = destination.observe_publication().await?;
        destination.selected_lineage(&observed, reference).await?
    };
    TokioLocalFs.rename(&association, &saved).await?;
    TokioLocalFs.sync_directory(authority.control()).await?;

    let holder = SingleHeld::acquire(repository.coordinator().store()).await?;
    let destination = holder.destination();
    let observed = destination.observe_publication().await?;
    let concrete = repository
        .coordinator()
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
        repository.coordinator().store().ref_get(reference).await?,
        Some(second.clone())
    );
    // Restored physical association permits actual independent full verification.
    repository
        .coordinator()
        .guard()
        .verified_history(second.commit)
        .await?;
    Ok(())
}

fn replace_requirement(source: &[u8], replaced: &str, replacement: &[u8]) -> Result<Vec<u8>> {
    use terrane_format::cbor::{self, Decoder};
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
    repository: &Native,
    mut commit: terrane_format::refs::Commit,
) -> Result<terrane_format::provenance::VerifiedCommit> {
    use terrane_format::auth::{Request, RequestRoot, Verb};
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
    let signed = terrane_format::provenance::sign_authored(
        commit,
        &super::tests::secret(),
        repository.coordinator().guard().keys(),
        &request,
        epoch,
    )?;
    let verified = terrane_format::provenance::verify_history(
        signed.commit(),
        repository.coordinator().guard().keys(),
        &roots,
        &epochs,
    )?;
    assert_eq!(verified.identity(), signed.identity());
    Ok(signed)
}

async fn put_signed(
    repository: &Native,
    signed: &terrane_format::provenance::VerifiedCommit,
) -> Result<[u8; 32]> {
    use crate::store::{ContentStore, ContentUpload, MetaUpload};
    let bytes = signed.commit().encode()?;
    let stored = repository
        .coordinator()
        .store()
        .put(ContentUpload::Meta(MetaUpload::new(
            IdentityKind::Commit,
            &bytes,
        )?))
        .await?;
    assert_eq!(stored.terrane_v1_digest()?, signed.identity());
    Ok(signed.identity())
}

#[tokio::test]
async fn native_active_metadata_admits_index_roles_but_not_namespace_use() -> Result {
    use crate::store::{ContentUpload, ContentValidator, MetaUpload};
    use terrane_format::tree_format::{TreeUse, decode_node_for};

    let repository = fixture(true).await?;
    let validator = crate::repository::MetadataValidator::new(
        terrane_format::chunking::ChunkProfile::cdc_1m([0; 32]),
    );
    let data = support::mixed_role_index_data()?;
    // This is immutable format admission only. Actual owner binding and full
    // relationships remain the real history completion loader's obligation.
    {
        use terrane_format::indexing::carrier::{
            Role, SemanticContext, validate_node, validate_row,
        };
        use terrane_format::tree_format::NodeItems;
        let context = SemanticContext::new(3, 2, 1)?;
        let primary = decode_node_for(
            data.nodes.get(&data.root).ok_or("missing primary")?,
            true,
            262144,
            TreeUse::Index,
        )?;
        let gap = validate_node(context, Role::Primary, &primary, true)?
            .ok_or("missing actual gap binding")?
            .node();
        let NodeItems::Leaf(primary_rows) = primary.items else {
            return Err("small primary is not leaf".into());
        };
        assert_eq!(primary_rows.len(), 1);
        let present = validate_row(
            context,
            Role::Primary,
            &primary_rows[0].key,
            &primary_rows[0].entry,
        )?
        .route()
        .ok_or("missing present route")?;
        let gaps = decode_node_for(
            data.nodes.get(&gap).ok_or("missing gaps")?,
            true,
            262144,
            TreeUse::Index,
        )?;
        assert_eq!(validate_node(context, Role::Gap, &gaps, true)?, None);
        let NodeItems::Leaf(gap_rows) = gaps.items else {
            return Err("small gaps is not leaf".into());
        };
        assert_eq!(gap_rows.len(), 1);
        let missing = validate_row(context, Role::Gap, &gap_rows[0].key, &gap_rows[0].entry)?
            .route()
            .ok_or("missing missing-route")?;
        for (address, role, expected) in [
            (present, Role::PresentRoute, b"file-0".as_slice()),
            (missing, Role::MissingRoute, b"file-1".as_slice()),
        ] {
            let node = decode_node_for(
                data.nodes.get(&address).ok_or("missing actual route")?,
                true,
                262144,
                TreeUse::Index,
            )?;
            assert_eq!(validate_node(context, role, &node, true)?, None);
            let NodeItems::Leaf(rows) = node.items else {
                return Err("small route is not leaf".into());
            };
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].key, expected);
        }
        let roles = std::collections::BTreeSet::from([data.root, gap, present, missing]);
        assert_eq!(roles.len(), 4);
        assert_eq!(roles, data.nodes.keys().copied().collect());
    }
    for (address, bytes) in &data.nodes {
        let identity = TERRANE_V1.calculate(IdentityKind::Node, bytes)?;
        assert_eq!(identity.terrane_v1_digest()?, *address);
        let upload = MetaUpload::new(IdentityKind::Node, bytes)?;
        validator.validate_meta(&upload)?;
        let stored = repository
            .coordinator()
            .store()
            .put(ContentUpload::Meta(upload))
            .await?;
        assert_eq!(stored, identity);
        assert!(decode_node_for(bytes, true, 262144, TreeUse::Index).is_ok());
        assert!(decode_node_for(bytes, true, 262144, TreeUse::Ordinary).is_err());
    }
    let generic_index_bytes = {
        use terrane_format::tree_format::{Attribute, Entry, EntryKind, LeafItem};
        let tree = terrane_format::tree_builder::Tree::build(
            vec![LeafItem {
                key: b"file".to_vec(),
                entry: Entry {
                    kind: EntryKind::Index {
                        targets: vec![[9; 32]],
                    },
                    attrs: vec![Attribute {
                        name: "uid",
                        value: &[7],
                    }],
                    attrs_present: true,
                    xattrs: Vec::new(),
                    xattrs_present: false,
                    provenance: None,
                },
            }],
            None,
            262144,
            TreeUse::Index,
        )?;
        tree.nodes()
            .next()
            .ok_or("missing generic Index node")?
            .encoded()
            .to_vec()
    };
    // Generic retained Index metadata remains valid without an executable role.
    // Each explicitly selected carrier role independently rejects this shape.
    let generic_upload = MetaUpload::new(IdentityKind::Node, &generic_index_bytes)?;
    validator.validate_meta(&generic_upload)?;
    let stored = repository
        .coordinator()
        .store()
        .put(ContentUpload::Meta(generic_upload))
        .await?;
    assert_eq!(
        stored,
        TERRANE_V1.calculate(IdentityKind::Node, &generic_index_bytes)?,
    );
    let generic_node = decode_node_for(&generic_index_bytes, true, 262144, TreeUse::Index)?;
    assert!(decode_node_for(&generic_index_bytes, true, 262144, TreeUse::Ordinary).is_err());
    {
        use terrane_format::indexing::carrier::{Role, SemanticContext, validate_node};

        let context = SemanticContext::new(3, 2, 1)?;
        for role in [
            Role::Primary,
            Role::Gap,
            Role::PresentRoute,
            Role::MissingRoute,
        ] {
            assert_eq!(
                validate_node(context, role, &generic_node, true),
                Err(terrane_format::indexing::Error::Schema),
                "generic Index accepted under {role:?}",
            );
        }
    }
    let malformed = MetaUpload::new(IdentityKind::Node, &[0xff])?;
    let failure = validator
        .validate_meta(&malformed)
        .err()
        .ok_or("malformed Node accepted")?;
    assert!(matches!(
        failure.kind(),
        StoreErrorKind::Invalid(crate::store::InvalidReason::Upload { rule_id: "TREE-25" })
    ));
    assert_eq!(
        repository.coordinator().store().ref_get(REFERENCE).await?,
        None
    );
    Ok(())
}

#[tokio::test]
async fn native_active_completion_divergent_primary_never_promotes() -> Result {
    use core::error::Error;
    let repository = fixture(true).await?;
    let proposal = support::divergent_index()?;
    let mut session = repository.begin(REFERENCE, &token(), "sdk").await?;
    let failure = store_failure(
        repository
            .commit_request(&mut session, proposal.request)
            .await
            .err()
            .ok_or("divergent relationship acknowledged")?,
    );
    assert!(matches!(
        failure.kind(),
        StoreErrorKind::Invalid(crate::store::InvalidReason::MalformedRequest)
    ));
    assert!(matches!(
        failure
            .source()
            .and_then(|source| source.downcast_ref::<crate::indexing::Error>()),
        Some(crate::indexing::Error::Invalid {
            failure: terrane_format::indexing::evaluation::Error::Relationship,
            ..
        })
    ));
    assert_eq!(
        repository.coordinator().store().ref_get(REFERENCE).await?,
        None
    );
    let holder = SingleHeld::acquire(repository.coordinator().store()).await?;
    let destination = holder.destination();
    let observed = destination.observe_publication().await?;
    assert_eq!(
        destination.selected_lineage(&observed, REFERENCE).await?,
        None
    );
    observed.revalidate().await?;
    Ok(())
}

#[tokio::test]
async fn native_active_completion_dropped_required_owner_binding_refuses_publication() -> Result {
    let repository = fixture(true).await?;
    let first_proposal = indexed(Vec::new(), false)?;
    let first_owner = first_proposal.owner;
    let first_primary = first_proposal.primary;
    let mut session = repository.begin(REFERENCE, &token(), "sdk").await?;
    let first = repository
        .commit_request(&mut session, first_proposal.request)
        .await?;
    let before = {
        let holder = SingleHeld::acquire(repository.coordinator().store()).await?;
        let destination = holder.destination();
        let observed = destination.observe_publication().await?;
        let bytes = destination
            .selected_lineage(&observed, REFERENCE)
            .await?
            .ok_or("genuine first ACK has no lineage")?;
        observed.revalidate().await?;
        bytes
    };
    let proposal = support::missing_local_binding(vec![first.commit])?;
    let owner = proposal.owner;
    assert_ne!(owner, first_owner);
    let proposed_evidence = crate::guard::TreeEvidence::load_tree(
        repository.coordinator().store(),
        owner,
        &proposal.request.uploads,
        262144,
    )
    .await?;
    let failure = store_failure(
        repository
            .commit_request(&mut session, proposal.request)
            .await
            .err()
            .ok_or("missing local binding completed publication")?,
    );
    // Writer maintenance refuses dropping a valid required binding before
    // signed-history completion. Direct loading still reports the immutable
    // missing association as incomplete rather than verifying an index.
    assert_eq!(
        failure.kind(),
        &StoreErrorKind::Invalid(crate::store::InvalidReason::MalformedRequest),
        "unexpected dropped-binding failure: {failure:?}",
    );
    let cause = repository
        .coordinator()
        .guard()
        .dropped_index_binding_for_tests(&failure);
    assert!(
        cause.is_some(),
        "unexpected dropped-binding cause: {failure:?}",
    );
    let cause = cause.ok_or("typed dropped-binding cause lost")?;
    assert_eq!(cause, (owner, "uid"));
    assert_eq!(
        repository.coordinator().store().ref_get(REFERENCE).await?,
        Some(first)
    );

    let holder = SingleHeld::acquire(repository.coordinator().store()).await?;
    let destination = holder.destination();
    let observed = destination.observe_publication().await?;
    assert_eq!(
        destination.selected_lineage(&observed, REFERENCE).await?,
        Some(before)
    );
    // Actual prior binding remains valid. The extra genuine immutable closure
    // and another owner's pointer cannot supply the rejected new association.
    let revisions = crate::indexing::SemanticRevisions {
        property: 3,
        attribute: 2,
        tree: 1,
    };
    let loaded = crate::indexing::load(&destination, first_owner, "uid", revisions, 262144).await?;
    assert_eq!(loaded.index_root(), first_primary);
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
    assert_eq!(
        destination
            .has(&[TERRANE_V1.from_digest(IdentityKind::Node, &owner)?])
            .await?,
        vec![false],
    );
    // The rejected proposal remains ordinary immutable data. Check its exact
    // missing binding without publishing it or changing the selected bucket.
    let proposed_inputs = repository
        .coordinator()
        .guard()
        .staged_index_inputs_for_tests(&proposed_evidence)?;
    let failure = crate::indexing::load(&proposed_inputs, owner, "uid", revisions, 262144)
        .await
        .err()
        .ok_or("unbound owner became a verified index")?;
    assert!(matches!(failure,crate::indexing::Error::MissingBinding(subject) if subject == owner));
    assert_eq!(failure.kind(), crate::indexing::ErrorKind::Incomplete);
    observed.revalidate().await?;
    Ok(())
}

//! Checks cold publication and exact per-view interpretation comparisons.

use super::*;

#[path = "publication/guard_carry.rs"]
mod guard_carry;

#[path = "publication/requalification.rs"]
mod requalification;

#[path = "publication/older_lineage.rs"]
mod older_lineage;

#[tokio::test]
async fn repository_fork_publishes_fresh_signed_commit_without_node_io() -> TestResult {
    let fixture = Fixture::open().await?;
    let repository = &fixture.repository;
    let observer = repository.coordinator().store().observe_content_for_tests();
    observer.reset();

    let request = repository.source_request(&fixture.authority, metadata("Cold production fork"));
    let next = repository.fork(SOURCE, DESTINATION, request).await?;
    let measured = observer.snapshot();
    assert_eq!(measured.node_gets, 0);
    assert_eq!(measured.node_puts, 0);
    assert_eq!(measured.node_decodes, 0);
    assert_eq!(measured.commit_puts, 1);
    assert_ne!(next.commit, fixture.record.commit);
    assert_eq!(
        repository
            .coordinator()
            .store()
            .ref_get(DESTINATION)
            .await?,
        Some(next.clone())
    );
    assert_eq!(
        repository.coordinator().store().ref_get(SOURCE).await?,
        Some(fixture.record.clone())
    );

    let commit_identity = TERRANE_V1.from_digest(IdentityKind::Commit, &next.commit)?;
    let bytes = repository
        .coordinator()
        .store()
        .get(&commit_identity, None)
        .await?;
    let commit = terrane_format::refs::Commit::decode(&bytes)?;
    assert_eq!(commit.tree, fixture.root);
    assert_eq!(commit.parents, vec![fixture.record.commit]);
    assert!(commit.profile_pair.recipe.is_none());
    assert!(commit.profile_pair.entry_receipts.is_none());
    let context = commit
        .profile_pair
        .commit_context
        .as_ref()
        .ok_or("missing signed context")?;
    assert_eq!(context.reference(), DESTINATION);
    let roots = context
        .roots()
        .iter()
        .map(|root| terrane_format::auth::RequestRoot {
            path: root.path(),
            domain: root.domain(),
        })
        .collect::<Vec<_>>();
    let verified = terrane_format::provenance::verify_history(
        &commit,
        repository.coordinator().guard().keys(),
        &roots,
        &[(DESTINATION, next.writer_epoch)],
    )?;
    assert_eq!(verified.identity(), next.commit);
    assert_eq!(observer.snapshot().node_gets, 0);
    assert_eq!(observer.snapshot().node_decodes, 0);
    Ok(())
}

#[tokio::test]
async fn cold_reuse_refuses_absent_or_changed_per_view_interpretation_inputs() -> TestResult {
    let fixture = Fixture::open().await?;
    let concrete = fixture.repository.coordinator().guard();
    let authority = concrete
        .original_commit(&fixture.record.commit)?
        .baseline()
        .authority()
        .clone();
    let holder = SingleHeld::acquire(concrete.store()).await?;
    let guard = concrete.held_guard(holder.destination(), fixture.clock.clone())?;
    let observed = guard.store().observe_publication().await?;
    fixture.forbid_packs();
    let qualified = qualify_source(
        concrete,
        &authority,
        &guard,
        &observed,
        ColdForkRequest {
            source: SOURCE,
            token: fixture.authority.token(),
            surface: "sdk",
            started: Duration::ZERO,
            timing: timing()?,
        },
    )
    .await?;
    let lineage = &qualified.policies.lineage;
    let contexts = lineage
        .used
        .view_interpretations
        .as_ref()
        .ok_or("missing produced contexts")?;
    for context in contexts {
        let view = lineage
            .used
            .views
            .iter()
            .find(|view| view.view == context.view)
            .ok_or("missing used view")?;
        let mut absent = lineage.clone();
        absent.used.view_interpretations = None;
        assert!(
            matches!(super::super::super::compare_view_inputs(&guard, &absent, view),
            Err(ref failure) if matches!(failure.kind(), crate::store::StoreErrorKind::Unsupported))
        );
        for case in [
            "attribute",
            "mode",
            "root",
            "properties",
            "vocabulary",
            "later",
            "selector",
            "tree",
            "chunk",
            "identity",
        ] {
            let mut changed = lineage.clone();
            let row = changed
                .used
                .view_interpretations
                .as_mut()
                .ok_or("missing contexts")?
                .iter_mut()
                .find(|row| row.view == context.view)
                .ok_or("missing context")?;
            match case {
                "attribute" => {
                    row.registries.attribute_revision = if row.registries.attribute_revision == 1 {
                        2
                    } else {
                        1
                    }
                }
                "mode" => {
                    row.mode =
                        terrane_format::gc::publication::evidence::ViewInterpretationMode::Recorded
                }
                "root" => row.original_root = [91; 32],
                "properties" => row.registries.property_revision += 1,
                "vocabulary" => row.registries.behavioral_properties.clear(),
                "later" => row.registries.later_properties.push("future-policy".into()),
                "selector" => row.registries.selector_revision += 1,
                "tree" => row.registries.tree_revision += 1,
                "chunk" => row.registries.chunk_revision += 1,
                "identity" => row.registries.identity_profile = "unsupported".into(),
                _ => unreachable!("fixed cases"),
            }
            assert!(
                matches!(super::super::super::compare_view_inputs(&guard, &changed, view),
                    Err(ref failure) if matches!(failure.kind(), crate::store::StoreErrorKind::Invalid(_))),
                "{case}"
            );
        }
    }
    fixture.assert_no_content_io();
    Ok(())
}

#[tokio::test]
async fn final_cold_dispatch_refuses_source_original_lost_after_preparation() -> TestResult {
    let fixture = Fixture::open().await?;
    let digest: String = fixture
        .record
        .commit
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let original = fixture
        .location
        .authority
        .join(format!("commit-{digest}.cbor"));
    fixture.fs.lose_original_after_retention(original.clone())?;
    let observer = fixture
        .repository
        .coordinator()
        .store()
        .observe_content_for_tests();
    observer.reset();

    let request = fixture.repository.source_request(
        &fixture.authority,
        metadata("Lost original after cold preparation"),
    );
    assert!(
        fixture
            .repository
            .fork(SOURCE, DESTINATION, request)
            .await
            .is_err()
    );

    assert!(
        !original.exists(),
        "genuine candidate retention must trigger the loss"
    );
    assert!(
        fixture
            .repository
            .coordinator()
            .store()
            .ref_get(DESTINATION)
            .await?
            .is_none()
    );
    assert_eq!(
        fixture
            .repository
            .coordinator()
            .store()
            .ref_get(SOURCE)
            .await?,
        Some(fixture.record.clone())
    );
    let measured = observer.snapshot();
    assert_eq!(measured.node_gets, 0);
    assert_eq!(measured.node_puts, 0);
    assert_eq!(measured.node_decodes, 0);
    Ok(())
}

#[tokio::test]
async fn repository_raw_source_refuses_missing_native_context_without_node_io() -> TestResult {
    let fixture = Fixture::open().await?;
    let record = RefRecord {
        seq: 1,
        writer_epoch: 0,
        candidate_id: Some([19; 32]),
        ..fixture.record.clone()
    };
    let log = RefLogRecord {
        record: record.clone(),
        previous_commit: None,
        principal: "owner".into(),
        reason: RefLogReason::Commit,
        timestamp: 1000,
        expected_previous: Some(None),
        committed_previous: None,
    };
    let store = fixture.repository.coordinator().store();
    store.ref_log_append(DESTINATION, record.seq, &log).await?;
    assert_eq!(
        store.ref_cas(DESTINATION, None, &record).await?,
        RefCasOutcome::Applied
    );
    let observer = store.observe_content_for_tests();
    observer.reset();

    let target = "refs/heads/_/ordinary-fork";
    let request = fixture.repository.source_request(
        &fixture.authority,
        metadata("Ordinary source without selected lineage"),
    );
    fixture.fs.reset_acknowledged();
    let state_before = selected_fixture_state(&fixture.repository).await?;
    let (selected_before, bytes_before) =
        selected_fixture_lineage(&fixture.repository, &fixture.clock, SOURCE).await?;
    let failure = fixture
        .repository
        .fork(DESTINATION, target, request)
        .await
        .err()
        .ok_or("raw source without native context was accepted")?;
    assert!(matches!(
        failure,
        crate::repository::Error::Advance(crate::ref_advance::AdvanceError::Store(ref error))
            if matches!(error.kind(), crate::store::StoreErrorKind::Unsupported)
    ));
    assert!(store.ref_get(target).await?.is_none());
    assert_eq!(store.ref_get(DESTINATION).await?, Some(record));
    assert_eq!(store.ref_get(SOURCE).await?, Some(fixture.record.clone()));
    let (selected_after, bytes_after) =
        selected_fixture_lineage(&fixture.repository, &fixture.clock, SOURCE).await?;
    assert_eq!(selected_after, selected_before);
    assert_eq!(bytes_after, bytes_before);
    assert!(fixture.fs.acknowledged().is_empty());
    assert_eq!(
        selected_fixture_state(&fixture.repository).await?,
        state_before
    );
    let counts = observer.snapshot();
    assert_eq!(counts.node_gets, 0);
    assert_eq!(counts.node_puts, 0);
    assert_eq!(counts.node_decodes, 0);
    Ok(())
}

#[tokio::test]
async fn repository_selected_source_propagates_current_fork_denial_without_fallback() -> TestResult
{
    let mut fixture = Fixture::open().await?;
    fixture.revoke_fork().await?;
    let observer = fixture
        .repository
        .coordinator()
        .store()
        .observe_content_for_tests();
    observer.reset();

    let request = fixture
        .repository
        .source_request(&fixture.authority, metadata("Revoked current Fork"));
    let failure = fixture
        .repository
        .fork(SOURCE, DESTINATION, request)
        .await
        .err()
        .ok_or("revoked source was accepted")?;

    assert!(
        matches!(failure, crate::repository::Error::Advance(crate::ref_advance::AdvanceError::Store(ref error))
        if matches!(error.kind(), crate::store::StoreErrorKind::Denied { verb: "fork", .. }))
    );
    assert!(
        fixture
            .repository
            .coordinator()
            .store()
            .ref_get(DESTINATION)
            .await?
            .is_none()
    );
    let measured = observer.snapshot();
    assert_eq!(measured.node_gets, 0);
    assert_eq!(measured.node_puts, 0);
    assert_eq!(measured.node_decodes, 0);
    for (acl, admits) in [
        (vec![], false),
        (vec![("owner".into(), 4)], false),
        (vec![("owner".into(), 16)], true),
        (vec![("owner".into(), 4), ("owner".into(), 16)], true),
        (vec![("other".into(), 16)], false),
    ] {
        check_independently_retained_original_widening(acl, admits).await?;
    }
    Ok(())
}

// This fixture installs a real separately protected baseline before the existing
// preparation path checks it. Current configuration cannot stand in for it.
async fn check_independently_retained_original_widening(
    acl: Vec<(String, u8)>,
    admits: bool,
) -> TestResult {
    use std::os::unix::fs::PermissionsExt;
    use terrane_format::gc::publication::evidence::{AuthorityGrant, OriginalBootstrap};

    let fixture = Fixture::open().await?;
    let guard = fixture.repository.coordinator().guard();
    let signing = fixture
        .repository
        .source_request(&fixture.authority, metadata("Original bootstrap widening"));
    let restricted = Token::decode(fixture.authority.token())?
        .attenuate(
            Attenuation {
                grants: Some(vec![Grant::new("refs/**".into(), Verbs::new(6)?)?]),
                ..Attenuation::default()
            },
            &signing.terminal_secret,
            auth::public_key_from_secret(&[73; 32]),
        )?
        .encode();
    let mut session = fixture
        .repository
        .begin(DESTINATION, &restricted, "sdk")
        .await?;
    let authority = guard
        .original_commit(&fixture.record.commit)?
        .baseline()
        .authority()
        .clone();
    let baseline = OriginalBootstrap {
        original_id: *authority.id(),
        ref_name: DESTINATION.into(),
        epoch: session.epoch(),
        acl: acl
            .iter()
            .map(|(principal, verbs)| AuthorityGrant {
                principal: principal.clone(),
                verbs: *verbs,
            })
            .collect(),
    };
    let selector = format!(
        "bootstrap-{}-{}-{}.cbor",
        baseline
            .original_id
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
        blake3::hash(DESTINATION.as_bytes()).to_hex(),
        session.epoch()
    );
    let path = fixture.location.authority.join(selector);
    fixture.fs.write_new(&path, &baseline.encode()?).await?;
    fixture
        .fs
        .set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .await?;
    fixture.fs.sync_file(&path).await?;
    fixture
        .fs
        .sync_directory(&fixture.location.authority)
        .await?;
    guard
        .check_original_bootstrap(crate::guard::BootstrapView {
            id: authority.id(),
            reference: DESTINATION,
            epoch: session.epoch(),
            acl: &acl,
        })
        .await?;
    let observer = guard.store().observe_content_for_tests();
    observer.reset();
    let mut request = signing;
    request.token = restricted;
    request.terminal_secret = [73; 32];

    let result = fixture
        .repository
        .coordinator()
        .prepare_fork(&mut session, SOURCE, request)
        .await;

    if admits {
        let prepared = result?;
        assert_ne!(prepared.commit(), fixture.record.commit);
    } else {
        let failure = result
            .err()
            .ok_or("Original widening without historical Admin was accepted")?;
        assert!(
            matches!(failure, crate::ref_advance::AdvanceError::Store(ref error)
            if matches!(error.kind(), crate::store::StoreErrorKind::Denied { verb: "admin", .. }))
        );
    }
    assert!(guard.store().ref_get(DESTINATION).await?.is_none());
    let measured = observer.snapshot();
    assert_eq!(measured.node_gets, 0);
    assert_eq!(measured.node_puts, 0);
    assert_eq!(measured.node_decodes, 0);
    Ok(())
}

// Captures ordinary actual selected state under the same native observation API.
async fn selected_fixture_state(
    repository: &NativeRepository,
) -> TestResult<terrane_format::gc::publication::PublicationState> {
    let holder = SingleHeld::acquire_read_only(repository.coordinator().store()).await?;
    let held = holder.source();
    let observed = held.observe_publication().await?;
    let state = observed.state().clone();
    observed.revalidate().await?;
    Ok(state)
}

// Reads selected metadata through the real held backend. It grants no cold,
// history or collection authority and never touches a TreeNode body.
async fn selected_fixture_lineage(
    repository: &NativeRepository,
    clock: &TestClock,
    reference: &str,
) -> TestResult<(
    terrane_format::gc::publication::evidence::CheckedLineage,
    Vec<u8>,
)> {
    let holder = SingleHeld::acquire(repository.coordinator().store()).await?;
    let guard = repository
        .coordinator()
        .guard()
        .held_guard(holder.destination(), clock.clone())?;
    let observed = guard.store().observe_publication().await?;
    let selected = observed
        .state()
        .sources
        .iter()
        .find(|row| row.name == reference)
        .ok_or("missing genuinely selected source lineage")?;
    let bytes = guard
        .store()
        .selected_lineage(&observed, reference)
        .await?
        .ok_or("missing protected selected lineage")?;
    assert_eq!(*blake3::hash(&bytes).as_bytes(), selected.digest);
    let lineage = terrane_format::gc::publication::evidence::CheckedLineage::decode(&bytes)?;
    assert_eq!(lineage.source_name, reference);
    assert_eq!(
        guard.store().ref_get(reference).await?,
        Some(lineage.source.clone())
    );
    Ok((lineage, bytes))
}

#[tokio::test]
async fn repository_older_lineage_requalifies_before_separate_zero_node_fork() -> TestResult {
    let Fixture {
        repository,
        authority,
        fs,
        clock,
        location,
        _directory,
        ..
    } = Fixture::open().await?;
    let source_directory = location
        .bucket
        .parent()
        .ok_or("missing fixture parent")?
        .join("source");
    repository
        .coordinator()
        .guard()
        .historical_lineage_encoding_for_tests(Some(SOURCE))?;
    let mut session = repository.begin(SOURCE, authority.token(), "sdk").await?;
    let older_record = repository
        .commit_directory(
            &mut session,
            &source_directory,
            &authority,
            metadata("Historical optional lineage encoding"),
        )
        .await?;
    repository
        .coordinator()
        .guard()
        .historical_lineage_encoding_for_tests(None)?;
    let (older, older_bytes) = selected_fixture_lineage(&repository, &clock, SOURCE).await?;
    assert_eq!(older.source, older_record);
    assert!(older.used.view_interpretations.is_none());
    assert!(!older.used.views.is_empty());
    assert!(!older.controls.is_empty());
    let root = terrane_format::refs::Commit::decode(&older.commit_bytes)?.tree;
    drop(session);
    drop(repository);
    drop(authority);

    // Reopen installs its actual configured interpretation; absence in the
    // selected older record supplies neither configuration nor cold eligibility.
    let parent = location.bucket.parent().ok_or("missing parent")?;
    let owner_uid = fs.metadata(parent).await?.uid();
    let (repository, authority) = Repository::open_local(
        &location,
        &LocalAuthorityIdentity {
            issuer: "local".into(),
            key_id: "initial".into(),
            owner_uid,
        },
        policy()?,
        SOURCE,
        fs.clone(),
        clock.clone(),
    )
    .await?;
    assert_eq!(
        selected_fixture_lineage(&repository, &clock, SOURCE)
            .await?
            .1,
        older_bytes
    );
    // Reopening creates a new bucket and validator. Attach and calibrate that
    // actual decoder observer before measuring either subsequent operation.
    let store = repository.coordinator().store();
    let observer = store.observe_metadata_for_tests()?;
    observer.reset();
    let node = TERRANE_V1.from_digest(IdentityKind::Node, &root)?;
    let bytes = store.get(&node, None).await?;
    assert!(observer.snapshot().node_gets > 0);
    assert!(observer.snapshot().node_decodes > 0);
    store
        .put(crate::store::ContentUpload::Meta(
            crate::store::MetaUpload::new(IdentityKind::Node, &bytes)?,
        ))
        .await?;
    assert!(observer.snapshot().node_puts > 0);
    assert!(observer.snapshot().node_decodes > 0);
    observer.reset();
    fs.reset_acknowledged();
    let state_before = selected_fixture_state(&repository).await?;
    let warm_record = repository
        .requalify_fork_source(SOURCE, authority.token(), "sdk")
        .await?;
    let ordinary_counts = observer.snapshot();
    assert!(
        ordinary_counts.node_gets > 0,
        "owning history must read actual Nodes"
    );
    assert!(
        ordinary_counts.node_decodes > 0,
        "owning history must validate actual Nodes"
    );
    assert_eq!(ordinary_counts.commit_puts, 0);
    assert_eq!(ordinary_counts.node_puts, 0);
    assert_eq!(warm_record, older_record);
    assert_eq!(store.ref_get(SOURCE).await?, Some(older_record.clone()));
    let (warm, warm_bytes) = selected_fixture_lineage(&repository, &clock, SOURCE).await?;
    assert_eq!(warm.source, older_record);
    assert_eq!(warm.commit_bytes, older.commit_bytes);
    assert_ne!(warm_bytes, older_bytes);
    let acknowledgements = fs.acknowledged();
    assert_eq!(acknowledgements.len(), 1);
    let acknowledged = &acknowledgements[0];
    assert!(matches!(
        acknowledged.proof,
        terrane_format::gc::publication::PublicationProof::Candidate(_)
    ));
    assert!(acknowledged.changes.is_empty());
    let prior = acknowledged
        .old
        .as_ref()
        .ok_or("missing actual old publication state")?;
    assert_eq!(prior.branches, acknowledged.new.branches);
    assert_eq!(prior.loss_generation, acknowledged.new.loss_generation);
    assert_eq!(prior.binding, acknowledged.new.binding);
    assert_eq!(prior.guard, acknowledged.new.guard);
    assert_eq!(prior.burn_owners, acknowledged.new.burn_owners);
    assert_eq!(prior, &state_before);
    let mut expected_state = state_before.clone();
    expected_state.revision = expected_state
        .revision
        .checked_add(1)
        .ok_or("revision overflow")?;
    let replacement = expected_state
        .sources
        .iter_mut()
        .find(|row| row.name == SOURCE)
        .ok_or("missing acknowledged source row")?;
    replacement.digest = *blake3::hash(&warm_bytes).as_bytes();
    assert_eq!(acknowledged.new, expected_state);
    assert_eq!(selected_fixture_state(&repository).await?, expected_state);
    let warm_commit = terrane_format::refs::Commit::decode(&warm.commit_bytes)?;
    assert_eq!(warm_commit.tree, root);
    assert_eq!(
        warm_commit,
        terrane_format::refs::Commit::decode(&older.commit_bytes)?
    );
    let contexts = warm
        .used
        .view_interpretations
        .as_ref()
        .ok_or("missing fresh contexts")?;
    assert_eq!(contexts.len(), warm.used.views.len());
    for view in &warm.used.views {
        let context = contexts
            .iter()
            .find(|row| row.view == view.view)
            .ok_or("missing used context")?;
        let original_root = view.roots.first().ok_or("missing used root")?.root;
        repository
            .coordinator()
            .guard()
            .compare_cold_fork_view_inputs(Some(context), view.view, original_root)?;
    }

    // The full owning requalification and same-head native ACK finish before
    // the separate fork interval, which retains its exact zero-Node assertions.
    observer.reset();
    fs.reset_acknowledged();
    let cold_state_before = selected_fixture_state(&repository).await?;
    let source_controls = older_lineage::SourceControls::capture(
        &repository,
        &clock,
        &location.authority,
        &warm_record,
    )
    .await?;
    let cold_reference = "refs/heads/_/after-requalification";
    let request =
        repository.source_request(&authority, metadata("Cold fork after requalification"));
    let cold_record = repository.fork(SOURCE, cold_reference, request).await?;
    let cold_counts = observer.snapshot();
    assert_eq!(cold_counts.node_gets, 0);
    assert_eq!(cold_counts.node_puts, 0);
    assert_eq!(cold_counts.node_decodes, 0);
    assert_eq!(cold_counts.commit_puts, 1);
    assert_ne!(cold_record.commit, warm_record.commit);
    assert_eq!(
        repository
            .coordinator()
            .store()
            .ref_get(cold_reference)
            .await?,
        Some(cold_record.clone())
    );
    assert_eq!(
        repository.coordinator().store().ref_get(SOURCE).await?,
        Some(warm_record.clone())
    );
    let acknowledgements = fs.acknowledged();
    assert_eq!(acknowledgements.len(), 1);
    let acknowledged = &acknowledgements[0];
    assert!(matches!(
        acknowledged.proof,
        terrane_format::gc::publication::PublicationProof::Candidate(_)
    ));
    let prior = acknowledged.old.as_ref().ok_or("missing cold old state")?;
    // A real fresh Commit Raw/CAP admission precedes the Candidate seal. Its
    // physical binding may advance; the selected source and logical state do not.
    assert_eq!(prior.sources, cold_state_before.sources);
    assert_eq!(prior.branches, cold_state_before.branches);
    assert_eq!(prior.guard, cold_state_before.guard);
    assert_eq!(prior.loss_generation, cold_state_before.loss_generation);
    assert_eq!(prior.burn_owners, cold_state_before.burn_owners);
    let (cold, cold_bytes) = selected_fixture_lineage(&repository, &clock, cold_reference).await?;
    {
        use terrane_format::gc::publication::{
            CommittedSelection, HistoryEntry, LogicalChange, SelectedHistory, SourceLineage,
        };
        let predecessor =
            older_lineage::prior_fork_selection(&repository, &clock, acknowledged).await?;
        assert_eq!(acknowledged.old.as_ref(), Some(&predecessor.state));
        let prior_capabilities = predecessor
            .logical
            .get("CAPABILITIES")
            .and_then(Option::as_deref)
            .ok_or("actual preceding whole capabilities")?;
        let mut capabilities =
            terrane_format::bucket::BucketCapabilities::decode(prior_capabilities)?;
        assert_eq!(capabilities.encode()?.as_slice(), prior_capabilities);
        let names = capabilities
            .ref_names
            .as_mut()
            .ok_or("actual complete ref inventory")?;
        let position = names
            .binary_search_by(|name| name.as_bytes().cmp(cold_reference.as_bytes()))
            .err()
            .ok_or("cold destination unexpectedly inventoried")?;
        names.insert(position, cold_reference.into());
        let prior_history = predecessor
            .logical
            .get("publication/SELECTED-HISTORY")
            .and_then(Option::as_deref)
            .ok_or("actual preceding selected history")?;
        let history = SelectedHistory::decode(prior_history)?;
        assert_eq!(history.encode()?.as_slice(), prior_history);
        assert_eq!(history.origin, predecessor.state.binding);
        assert_eq!(history.branches, predecessor.state.branches);

        let mut expected_state = predecessor.state.clone();
        expected_state.revision = expected_state
            .revision
            .checked_add(1)
            .ok_or("revision overflow")?;
        let position = expected_state
            .branches
            .binary_search_by(|row| row.name.as_bytes().cmp(cold_reference.as_bytes()))
            .err()
            .ok_or("cold destination unexpectedly retained")?;
        expected_state.branches.insert(
            position,
            HistoryEntry {
                name: cold_reference.into(),
                selection: CommittedSelection::Selected(cold_record.clone().into()),
            },
        );
        let position = expected_state
            .sources
            .binary_search_by(|row| row.name.as_bytes().cmp(cold_reference.as_bytes()))
            .err()
            .ok_or("cold destination unexpectedly qualified")?;
        expected_state.sources.insert(
            position,
            SourceLineage {
                name: cold_reference.into(),
                digest: *blake3::hash(&cold_bytes).as_bytes(),
            },
        );
        let record_key = terrane_format::bucket::BucketKey::ref_record(cold_reference)?;
        assert!(
            predecessor
                .logical
                .get(record_key.as_str())
                .and_then(Option::as_deref)
                .is_none()
        );
        let mut expected_changes = vec![
            LogicalChange {
                key: record_key.as_str().into(),
                expected: None,
                new: Some(cold_record.encode()?),
            },
            LogicalChange {
                key: "CAPABILITIES".into(),
                expected: Some(prior_capabilities.to_vec()),
                new: Some(capabilities.encode()?),
            },
            LogicalChange {
                key: "publication/SELECTED-HISTORY".into(),
                expected: Some(prior_history.to_vec()),
                new: Some(
                    SelectedHistory {
                        origin: predecessor.state.binding.clone(),
                        branches: expected_state.branches.clone(),
                    }
                    .encode()?,
                ),
            },
        ];
        expected_changes.sort_by(|left, right| left.key.as_bytes().cmp(right.key.as_bytes()));
        assert_eq!(acknowledged.changes, expected_changes);
        assert_eq!(acknowledged.new, expected_state);
        assert_eq!(selected_fixture_state(&repository).await?, expected_state);
    }
    let record_change = acknowledged
        .changes
        .iter()
        .find(|change| change.key == format!("{cold_reference}:record"))
        .ok_or("missing actual cold ref change")?;
    assert!(record_change.expected.is_none());
    assert_eq!(
        record_change.new.as_deref(),
        Some(cold_record.encode()?.as_slice())
    );
    assert_eq!(acknowledged.new, selected_fixture_state(&repository).await?);
    source_controls.assert_unchanged(&repository).await?;
    assert_eq!(
        selected_fixture_lineage(&repository, &clock, SOURCE)
            .await?
            .1,
        warm_bytes
    );
    let cold_commit = terrane_format::refs::Commit::decode(&cold.commit_bytes)?;
    assert_eq!(cold_commit.tree, root);
    assert_eq!(cold_commit.parents, vec![warm_record.commit]);
    let signed = cold_commit
        .profile_pair
        .commit_context
        .as_ref()
        .ok_or("missing fresh signed context")?;
    assert_eq!(signed.reference(), cold_reference);
    let roots = signed
        .roots()
        .iter()
        .map(|row| terrane_format::auth::RequestRoot {
            path: row.path(),
            domain: row.domain(),
        })
        .collect::<Vec<_>>();
    let verified = terrane_format::provenance::verify_history(
        &cold_commit,
        repository.coordinator().guard().keys(),
        &roots,
        &[(cold_reference, cold_record.writer_epoch)],
    )?;
    assert_eq!(verified.identity(), cold_record.commit);
    assert_eq!(observer.snapshot().node_gets, 0);
    assert_eq!(observer.snapshot().node_puts, 0);
    assert_eq!(observer.snapshot().node_decodes, 0);
    Ok(())
}

#[tokio::test]
async fn repository_raw_source_requalifies_before_separate_zero_node_fork() -> TestResult {
    let fixture = Fixture::open().await?;
    let record = requalification::install_raw_alias(&fixture, DESTINATION).await?;
    let before =
        requalification::SourceSnapshot::capture(&fixture.repository, &fixture.clock, DESTINATION)
            .await?;
    assert_eq!(before.record, record);
    assert!(before.lineage.is_none());
    assert!(
        matches!(before.state.branches.iter().find(|row| row.name == DESTINATION).map(|row| &row.selection), Some(terrane_format::gc::publication::CommittedSelection::Selected(selected)) if selected.as_ref() == &record)
    );

    requalification::requalify_then_cold(
        &fixture.repository,
        &fixture.authority,
        &fixture.fs,
        &fixture.clock,
        DESTINATION,
        "refs/heads/_/ordinary-fork",
    )
    .await
}

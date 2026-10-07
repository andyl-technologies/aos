//! Checks genuine public native cold preparation through durable publication.
//!
//! Setup uses ordinary signed Node/history admission. Calibration and complete
//! source requalification finish before each independent measured fork interval.

#[path = "fs.rs"]
mod fs;
#[path = "support.rs"]
mod support;
use crate::store::{LocalFs, RefStore, StoreErrorKind};
#[cfg(feature = "send")]
use crate::{ref_advance::AdvanceError, store::Clock};
#[cfg(feature = "send")]
use std::error::Error;
use support::*;
use terrane_core::{
    auth::{Attenuation, Caveat, Grant, Token, Verb, Verbs},
    gc::publication::{CommittedSelection, SourceLineage},
    refs::Commit,
};

#[tokio::test]
async fn root_native_cold_fork_publishes_fresh_signed_namespace_without_nodes() -> TestResult {
    let fixture = Fixture::open().await?;
    fixture.complete_source(ALL_VERBS).await?;

    fixture.assert_cold(SOURCE, TARGET).await?;

    Ok(())
}

#[tokio::test]
async fn root_native_cold_fork_reuses_after_unrelated_ref_admission() -> TestResult {
    let fixture = Fixture::open().await?;
    fixture.complete_source(ALL_VERBS).await?;
    let before = Snapshot::capture(&fixture, SOURCE).await?;

    let unrelated = fixture
        .publish("refs/heads/_/unrelated", request(Vec::new(), ALL_VERBS)?)
        .await?;

    before.assert_source_unchanged(&fixture, SOURCE).await?;
    let after = Snapshot::capture(&fixture, SOURCE).await?;
    assert_eq!(after.state.guard, before.state.guard);
    assert_eq!(after.state.loss_generation, before.state.loss_generation);
    assert_eq!(after.state.binding, before.state.binding);
    assert_eq!(
        after.state.sources.iter().find(|row| row.name == SOURCE),
        before.state.sources.iter().find(|row| row.name == SOURCE)
    );
    assert_eq!(
        fixture.bucket().ref_get("refs/heads/_/unrelated").await?,
        Some(unrelated)
    );
    fixture.assert_cold(SOURCE, TARGET).await?;
    Ok(())
}

#[tokio::test]
async fn root_native_cold_fork_refuses_absent_context_before_node_io() -> TestResult {
    let fixture = Fixture::open().await?;
    let source = fixture.complete_source(ALL_VERBS).await?;
    let alias = "refs/heads/_/raw-alias";
    let record = raw_alias(&fixture, &source, alias).await?;
    let before = Snapshot::capture(&fixture, alias).await?;
    assert_eq!(before.record, record);
    assert!(before.lineage_read.is_none());
    assert!(
        matches!(before.state.branches.iter().find(|row| row.name == alias).map(|row| &row.selection), Some(CommittedSelection::Selected(selected)) if selected.as_ref() == &record)
    );
    eprintln!(
        "cold-raw-diagnostic stage=before-calibration state={:?} cap={:?} stamp={:?} pointer={:?} control={:?}",
        before.state,
        before.logical.get("CAPABILITIES"),
        before.selected_stamp,
        before.snapshot_pointer,
        before.control_identity
    );
    fixture.fs.enable_raw_diagnostic();
    fixture
        .calibrate(Commit::decode(&before.commit)?.tree)
        .await?;
    let calibrated = Snapshot::capture(&fixture, alias).await?;
    eprintln!(
        "cold-raw-diagnostic stage=after-calibration-before-fork state={:?} cap={:?} stamp={:?} pointer={:?} control={:?}",
        calibrated.state,
        calibrated.logical.get("CAPABILITIES"),
        calibrated.selected_stamp,
        calibrated.snapshot_pointer,
        calibrated.control_identity
    );
    fixture.fs.enable_raw_diagnostic();
    let observer = fixture.bucket().observe_content_for_tests();

    let error = rejected(
        fixture
            .repository
            .fork(alias, TARGET, fork_request()?)
            .await,
    );

    assert!(matches!(
        store_failure(&error).kind(),
        StoreErrorKind::Unsupported
    ));
    assert_no_nodes(&observer.snapshot());
    assert_eq!(fixture.fs.successful_ref_ack(TARGET), 0);
    assert!(fixture.bucket().ref_get(TARGET).await?.is_none());
    let after = Snapshot::capture(&fixture, alias).await?;
    fixture
        .fs
        .report_raw_diagnostics("after-fork-before-original-oracles");
    eprintln!(
        "cold-raw-diagnostic stage=after-fork state={:?} cap={:?} stamp={:?} pointer={:?} control={:?}",
        after.state,
        after.logical.get("CAPABILITIES"),
        after.selected_stamp,
        after.snapshot_pointer,
        after.control_identity
    );
    assert_eq!(after.state, before.state);
    assert_eq!(after.logical, before.logical);
    before.assert_source_unchanged(&fixture, alias).await?;
    Ok(())
}

#[tokio::test]
async fn root_native_cold_fork_after_separate_same_head_requalification() -> TestResult {
    let fixture = Fixture::open().await?;
    let source = fixture.complete_source(ALL_VERBS).await?;
    let alias = "refs/heads/_/requalify-alias";
    raw_alias(&fixture, &source, alias).await?;
    let before = Snapshot::capture(&fixture, alias).await?;
    fixture
        .calibrate(Commit::decode(&before.commit)?.tree)
        .await?;
    let observer = fixture.bucket().observe_content_for_tests();

    let returned = fixture
        .repository
        .requalify_fork_source(alias, &full_token()?, "sdk")
        .await?;

    assert_eq!(returned, before.record);
    let completed = observer.snapshot();
    assert!(
        completed.node_gets > 0,
        "separate full source history reads actual Nodes"
    );
    assert_eq!(completed.node_puts, 0);
    assert_eq!(completed.commit_puts, 0);
    // Calibration established validator attachment independently. Read-side Core
    // TreeEvidence decodes are not relabeled as MetadataValidator invocations.
    assert_eq!(fixture.fs.successful_requalification_ack(alias), 1);
    let mutation = fixture
        .fs
        .mutations()
        .into_iter()
        .find(|row| row.acknowledged && row.transaction.changes.is_empty())
        .ok_or("real requalification ACK")?;
    assert!(
        mutation
            .transaction
            .old
            .as_ref()
            .is_some_and(|old| old.branches == mutation.transaction.new.branches)
    );
    let after = Snapshot::capture(&fixture, alias).await?;
    assert_eq!(after.logical, before.logical);
    let lineage = after.lineage()?;
    fixture.assert_full_context(&lineage)?;
    assert_eq!(lineage.source, before.record);
    assert_eq!(lineage.commit_bytes, before.commit);
    let mut expected = before.state.clone();
    expected.revision += 1;
    expected.sources.retain(|row| row.name != alias);
    expected.sources.push(SourceLineage {
        name: alias.into(),
        digest: *blake3::hash(
            after
                .lineage_read
                .as_ref()
                .and_then(crate::bucket::publication::receipts::RecordRead::bytes)
                .ok_or("fresh actual lineage")?,
        )
        .as_bytes(),
    });
    expected
        .sources
        .sort_by(|left, right| left.name.as_bytes().cmp(right.name.as_bytes()));
    assert_eq!(after.state, expected);
    before.assert_source_unchanged(&fixture, alias).await?;

    // The genuinely completed source and native ACK are separate from this fork.
    fixture.assert_cold(alias, TARGET).await?;
    Ok(())
}

#[tokio::test]
async fn root_native_cold_fork_refuses_current_source_and_destination_rights() -> TestResult {
    for case in [
        "source-acl",
        "source-grant",
        "destination-grant",
        "destination-admin",
        "root",
        "domain",
        "surface",
        "time",
    ] {
        let fixture = Fixture::open().await?;
        if case == "destination-admin" {
            let first = fixture
                .publish(SOURCE, widened_request(Vec::new())?)
                .await?;
            fixture
                .publish(SOURCE, widened_request(vec![first.commit])?)
                .await?;
            let actual = Snapshot::capture(&fixture, SOURCE).await?;
            fixture.assert_full_context(&actual.lineage()?)?;
        } else {
            fixture
                .complete_source(if case == "source-acl" {
                    READ_COMMIT
                } else {
                    ALL_VERBS
                })
                .await?;
        }
        let before = Snapshot::capture(&fixture, SOURCE).await?;
        fixture
            .calibrate(Commit::decode(&before.commit)?.tree)
            .await?;
        let observer = fixture.bucket().observe_content_for_tests();
        let mut proposal = fork_request()?;
        let mut attenuation = Attenuation::default();
        match case {
            "source-grant" => {
                attenuation.grants = Some(vec![
                    Grant::new(SOURCE.into(), Verbs::new(READ_COMMIT)?)?,
                    Grant::new(TARGET.into(), Verbs::new(ALL_VERBS)?)?,
                ])
            }
            "destination-grant" => {
                attenuation.grants = Some(vec![
                    Grant::new(SOURCE.into(), Verbs::new(ALL_VERBS)?)?,
                    Grant::new(TARGET.into(), Verbs::new(Verb::Fork as u8)?)?,
                ])
            }
            "destination-admin" => {
                attenuation.grants = Some(vec![Grant::new(
                    "refs/**".into(),
                    Verbs::new(FORK_COMMIT)?,
                )?])
            }
            "root" => attenuation.caveats = vec![Caveat::Root("/missing".into())],
            "domain" => attenuation.caveats = vec![Caveat::Domain("private:other".into())],
            "surface" => attenuation.caveats = vec![Caveat::Surface("other".into())],
            "time" => attenuation.caveats = vec![Caveat::Before(0)],
            "source-acl" => {}
            _ => unreachable!("fixed current refusal cases"),
        }
        if case != "source-acl" {
            let next_secret = [73; 32];
            proposal.token = Token::decode(&proposal.token)?
                .attenuate(
                    attenuation,
                    &proposal.terminal_secret,
                    terrane_core::auth::public_key_from_secret(&next_secret),
                )?
                .encode();
            proposal.terminal_secret = next_secret;
        }

        let error = rejected(fixture.repository.fork(SOURCE, TARGET, proposal).await);

        let failure = store_failure(&error);
        match case {
            "source-acl" | "source-grant" => assert!(
                matches!(failure.kind(), StoreErrorKind::Denied { pattern, verb: "fork" } if pattern == SOURCE),
                "{case}: {error:?}"
            ),
            "destination-admin" => assert!(
                matches!(failure.kind(), StoreErrorKind::Denied { pattern, verb: "admin" } if pattern == TARGET),
                "{case}: {error:?}"
            ),
            _ => assert!(
                matches!(failure.kind(), StoreErrorKind::Denied { pattern, verb: "commit" } if pattern == TARGET),
                "{case}: {error:?}"
            ),
        }
        assert_no_nodes(&observer.snapshot());
        assert_eq!(fixture.fs.successful_ref_ack(TARGET), 0, "{case}");
        assert!(fixture.bucket().ref_get(TARGET).await?.is_none(), "{case}");
        let after = Snapshot::capture(&fixture, SOURCE).await?;
        assert_eq!(after.state, before.state, "{case}");
        assert_eq!(after.logical, before.logical, "{case}");
        before.assert_source_unchanged(&fixture, SOURCE).await?;
    }
    // Equal source/destination ACLs require actual Fork+Commit, without a new Admin bar.
    let fixture = Fixture::open().await?;
    fixture.complete_source(ALL_VERBS).await?;
    let before = Snapshot::capture(&fixture, SOURCE).await?;
    fixture
        .calibrate(Commit::decode(&before.commit)?.tree)
        .await?;
    let mut proposal = fork_request()?;
    proposal.token = token(vec![Grant::new(
        "refs/**".into(),
        Verbs::new(FORK_COMMIT)?,
    )?])?;
    let observer = fixture.bucket().observe_content_for_tests();
    fixture.repository.fork(SOURCE, TARGET, proposal).await?;
    assert_no_nodes(&observer.snapshot());
    assert_eq!(fixture.fs.successful_ref_ack(TARGET), 1);
    before.assert_source_unchanged(&fixture, SOURCE).await?;
    Ok(())
}

#[tokio::test]
async fn root_native_cold_fork_refuses_changed_original_and_selected_controls() -> TestResult {
    for case in [
        "source-original",
        "guard-incarnation",
        "lineage-incarnation",
    ] {
        let fixture = Fixture::open().await?;
        fixture.complete_source(ALL_VERBS).await?;
        let before = Snapshot::capture(&fixture, SOURCE).await?;
        fixture
            .calibrate(Commit::decode(&before.commit)?.tree)
            .await?;
        let observer = fixture.bucket().observe_content_for_tests();
        let path = match case {
            "source-original" => fixture
                .original
                .join(format!("commit-{}.cbor", hex(&before.record.commit))),
            "guard-incarnation" => before.guard_read.path().to_owned(),
            "lineage-incarnation" => before
                .lineage_read
                .as_ref()
                .ok_or("real selected lineage")?
                .path()
                .to_owned(),
            _ => unreachable!("fixed physical control cases"),
        };
        fixture.fs.arm(if case == "source-original" {
            fs::Hook::Remove(path.clone())
        } else {
            fs::Hook::Replace(path.clone())
        });

        let error = rejected(
            fixture
                .repository
                .fork(SOURCE, TARGET, fork_request()?)
                .await,
        );

        assert!(
            fixture.fs.reached() && fixture.fs.staging_reached(),
            "{case}: qualified cold staging never reached"
        );
        assert!(
            matches!(
                store_failure(&error).kind(),
                StoreErrorKind::Unavailable { .. }
            ),
            "{case}: {error:?}"
        );
        assert_no_nodes(&observer.snapshot());
        assert_eq!(fixture.fs.successful_ref_ack(TARGET), 0);
        assert!(fixture.bucket().ref_get(TARGET).await?.is_none());
        before
            .assert_head_and_history_unchanged(&fixture, SOURCE)
            .await?;
        let holder = crate::bucket::held::SingleHeld::acquire(fixture.bucket()).await?;
        let held = holder.destination();
        let observed = held.observe_publication().await?;
        assert_eq!(observed.state().branches, before.state.branches);
        assert_eq!(observed.state().sources, before.state.sources);
        assert_eq!(observed.state().guard, before.state.guard);
        assert_eq!(
            observed.state().loss_generation,
            before.state.loss_generation
        );
        if case == "source-original" {
            assert!(!path.exists());
        }
        // Physical damage is left as the real observed fault. No fixture repair
        // is passed off as the operation preserving or recreating authority.
    }
    Ok(())
}

#[tokio::test]
async fn root_native_cold_fork_rejects_profile_and_occurrence_contradictions() -> TestResult {
    let fixture = Fixture::open().await?;
    fixture.complete_source(ALL_VERBS).await?;
    let before = Snapshot::capture(&fixture, SOURCE).await?;
    let lineage = before.lineage()?;
    let commit = Commit::decode(&before.commit)?;
    fixture.calibrate(commit.tree).await?;
    let observer = fixture.bucket().observe_content_for_tests();
    let guard = fixture.repository.coordinator().guard();
    // Actual closed source is first successfully reused; the following cloned
    // tuples are comparison inputs only, never installed or qualifying evidence.
    fixture
        .repository
        .fork(SOURCE, TARGET, fork_request()?)
        .await?;
    assert_eq!(fixture.fs.successful_ref_ack(TARGET), 1);
    assert_no_nodes(&observer.snapshot());
    let distinct = lineage
        .used
        .views
        .iter()
        .map(|view| view.view)
        .collect::<std::collections::BTreeSet<_>>();
    for digest in distinct {
        let view = lineage
            .used
            .views
            .iter()
            .find(|view| view.view == digest)
            .ok_or("actual used view")?;
        for case in [
            "absent",
            "mode",
            "original-root",
            "attribute",
            "property",
            "vocabulary",
            "later",
            "selector",
            "tree",
            "chunk",
            "identity",
        ] {
            let mut changed = lineage.clone();
            if case == "absent" {
                changed.used.view_interpretations = None;
            } else {
                let context = changed
                    .used
                    .view_interpretations
                    .as_mut()
                    .and_then(|contexts| contexts.iter_mut().find(|context| context.view == digest))
                    .ok_or("actual context")?;
                match case {
                    "mode" => context.mode =
                        terrane_core::gc::publication::evidence::ViewInterpretationMode::Recorded,
                    "original-root" => context.original_root = [91; 32],
                    "attribute" => context.registries.attribute_revision += 1,
                    "property" => context.registries.property_revision += 1,
                    "vocabulary" => context.registries.behavioral_properties.clear(),
                    "later" => context.registries.later_properties.push("future".into()),
                    "selector" => context.registries.selector_revision += 1,
                    "tree" => context.registries.tree_revision += 1,
                    "chunk" => context.registries.chunk_revision += 1,
                    "identity" => context.registries.identity_profile = "unsupported".into(),
                    _ => unreachable!("fixed profile cases"),
                }
            }
            let error = rejected(super::super::compare_view_inputs(guard, &changed, view));
            assert!(
                if case == "absent" {
                    matches!(error.kind(), StoreErrorKind::Unsupported)
                } else {
                    matches!(error.kind(), StoreErrorKind::Invalid(_))
                },
                "{case}: {error:?}"
            );
        }
    }
    let original = super::super::check_views(&lineage, &commit)?;
    for case in ["path", "layer"] {
        let mut changed = lineage.clone();
        let mut repeated = changed.used.views[original].clone();
        let root = repeated.roots.first_mut().ok_or("actual root occurrence")?;
        if case == "path" {
            root.root = [81; 32];
        } else {
            root.layers[0].properties = vec![0xa0];
        }
        changed.used.views.push(repeated);
        assert!(
            matches!(
                rejected(super::super::check_views(&changed, &commit)).kind(),
                StoreErrorKind::Invalid(_)
            ),
            "{case}"
        );
    }
    assert_no_nodes(&observer.snapshot());
    before.assert_source_unchanged(&fixture, SOURCE).await?;

    // The actual public malformed-context refusal is separate from ordinary
    // tuple comparison. A damaged selected body never becomes a warm fallback.
    let read = before
        .lineage_read
        .as_ref()
        .ok_or("actual selected lineage")?;
    let mut bytes = read.bytes().ok_or("actual lineage bytes")?.to_vec();
    bytes[0] ^= 1;
    fixture.fs.remove_file(read.path()).await?;
    fixture.fs.write_new(read.path(), &bytes).await?;
    fixture
        .fs
        .set_permissions_and_sync(
            read.path(),
            read.metadata()
                .ok_or("actual lineage metadata")?
                .permissions(),
        )
        .await?;
    fixture.fs.reset();
    observer.reset();
    let error = rejected(
        fixture
            .repository
            .fork(SOURCE, "refs/heads/_/malformed", fork_request()?)
            .await,
    );
    assert!(matches!(
        store_failure(&error).kind(),
        StoreErrorKind::Corrupt(_)
    ));
    assert_eq!(fixture.fs.successful_ref_ack("refs/heads/_/malformed"), 0);
    assert_no_nodes(&observer.snapshot());
    before
        .assert_head_and_history_unchanged(&fixture, SOURCE)
        .await?;
    Ok(())
}

#[cfg(feature = "send")]
#[tokio::test]
async fn root_native_cold_fork_stops_on_sync_failure_and_expiry() -> TestResult {
    let fixture = Fixture::open().await?;
    fixture.complete_source(ALL_VERBS).await?;
    let before = Snapshot::capture(&fixture, SOURCE).await?;
    fixture
        .calibrate(Commit::decode(&before.commit)?.tree)
        .await?;
    fixture.fs.arm(fs::Hook::FinalSync);
    let observer = fixture.bucket().observe_content_for_tests();

    let error = rejected(
        fixture
            .repository
            .fork(SOURCE, TARGET, fork_request()?)
            .await,
    );

    assert!(fixture.fs.reached());
    assert!(matches!(
        &error,
        crate::repository::Error::Advance(AdvanceError::Indeterminate { .. })
    ));
    let failure = store_failure(&error);
    assert!(matches!(failure.kind(), StoreErrorKind::Unavailable { .. }));
    assert_eq!(
        failure
            .source()
            .ok_or("original actual sync failure")?
            .to_string(),
        "injected creation directory sync failure"
    );
    assert_eq!(fixture.fs.successful_ref_ack(TARGET), 0);
    assert_no_nodes(&observer.snapshot());
    before.assert_source_unchanged(&fixture, SOURCE).await?;
    let actual = fixture
        .fs
        .mutations()
        .into_iter()
        .find(|row| {
            row.transaction
                .changes
                .iter()
                .any(|change| change.key == format!("{TARGET}:record"))
        })
        .ok_or("real selected but unacknowledged final slot")?;
    assert!(!actual.acknowledged);
    // Selection may be visible before the failed sync. No rollback or durable
    // publication success is inferred from a diagnostic target reread.
    let _diagnostic_target = fixture.bucket().ref_get(TARGET).await?;

    let clock = crate::store::TestClock::new(2_000_000_000);
    let fixture = Fixture::with_clock(clock.clone()).await?;
    fixture.complete_source(ALL_VERBS).await?;
    let before = Snapshot::capture(&fixture, SOURCE).await?;
    fixture
        .calibrate(Commit::decode(&before.commit)?.tree)
        .await?;
    assert_eq!(
        clock.now(),
        std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(2_000_000_000)
    );
    assert_eq!(clock.monotonic(), std::time::Duration::ZERO);
    fixture.fs.arm(fs::Hook::Expire(clock.clone()));
    let observer = fixture.bucket().observe_content_for_tests();

    let error = rejected(
        fixture
            .repository
            .fork(SOURCE, TARGET, fork_request()?)
            .await,
    );

    assert!(fixture.fs.reached() && fixture.fs.staging_reached());
    assert_eq!(
        clock.now(),
        std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(2_000_000_031)
    );
    assert_eq!(clock.monotonic(), std::time::Duration::from_secs(31));
    let failure = store_failure(&error);
    assert!(matches!(failure.kind(), StoreErrorKind::Denied { .. }));
    // STORE-30 keeps the internal deadline cause private on a Denied surface.
    assert!(failure.source().is_none());
    assert_eq!(fixture.fs.successful_ref_ack(TARGET), 0);
    assert!(fixture.bucket().ref_get(TARGET).await?.is_none());
    assert_no_nodes(&observer.snapshot());
    before.assert_source_unchanged(&fixture, SOURCE).await?;
    let after = Snapshot::capture(&fixture, SOURCE).await?;
    assert_eq!(after.state.branches, before.state.branches);
    assert_eq!(after.state.sources, before.state.sources);
    assert_eq!(after.state.guard, before.state.guard);
    assert_eq!(after.state.loss_generation, before.state.loss_generation);
    Ok(())
}

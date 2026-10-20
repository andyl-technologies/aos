//! Regressions for real per-authorization held owner-history verification.
//!
//! The repository and protected controls come from the native production
//! factory. Observers count actual filesystem work and inject negative inputs;
//! neither fixture supplies a completed history or publication acknowledgment.

#![allow(
    clippy::unwrap_used,
    reason = "Fixture assertions intentionally panic."
)]

mod closing_cancellation;
mod configuration;
mod fs;
mod support;

use crate::bucket::held::SingleHeld;
use crate::guard::{ConsumedResolver, HistoryObservation};
use crate::ref_advance::tests::{request_file, request_file_acl, token};
use crate::store::{LocalFs, RefStore, TokioClock};
use fs::Fault;
use support::{Fixture, REFERENCE, TestResult};
use terrane_format::auth::Verb;
use terrane_format::gc::publication::evidence::ControlKind;

#[tokio::test]
async fn held_owner_history_preserves_original_purpose_and_baseline_selection() -> TestResult {
    let fixture = Fixture::open().await?;
    let original = fixture.guard().original_commit(&fixture.head.commit)?;
    // Plain bucket operations acquire namespace exclusion themselves; finish
    // those fixture reads before borrowing the tested exclusive holder.
    let admitted = fixture
        .guard()
        .admit_policy(REFERENCE, None, &token(), "sdk")
        .await?;
    let candidate = fixture.guard().capture_candidate_inputs(&admitted)?;
    let ancestor_root = fixture
        .guard()
        .verified_tree(fixture.base.commit)
        .await?
        .evidence
        .root;

    let holder = SingleHeld::acquire_read_only(fixture.guard().store()).await?;
    let source = holder.source();
    let identity = source.identity_proof();
    let guard = fixture.guard().held_guard(holder.source(), TokioClock)?;
    let consumed = ConsumedResolver::new(&guard, original.baseline().authority())?;
    let foreign = ConsumedResolver::new(&guard, original.baseline().authority())?;
    let other_identity = source.identity_proof();
    let copied_candidate = candidate.clone();
    let maintenance = crate::guard::index_maintenance::Purpose::for_source(fixture.head.commit);
    let copied_maintenance = maintenance;
    let baseline = HistoryObservation::held(&identity).tracked(&consumed);
    let staged = baseline.candidate(&candidate);
    let complete = staged
        .maintenance(&maintenance)
        .requested_target()
        .overlay_layer(fixture.head.commit, admitted.commit.commit().tree);

    let root = admitted.commit.commit().tree;
    let original_selection = guard.selected_view_inputs(fixture.head.commit, root, baseline)?;
    let staged_selection = guard.selected_view_inputs(fixture.head.commit, root, staged)?;
    assert_eq!(
        original_selection, staged_selection,
        "an admitted existing candidate must preserve the original exact selector inputs"
    );
    assert_eq!(original_selection, admitted.completion_inputs);
    assert_ne!(root, ancestor_root);
    assert!(
        guard
            .selected_view_inputs(fixture.head.commit, ancestor_root, staged)
            .is_err(),
        "a staged candidate cannot substitute another signed tree root"
    );

    for purpose in [baseline, staged, complete] {
        purpose.same_held_scope(purpose)?;
        for substituted in [
            HistoryObservation::default(),
            HistoryObservation::held(&identity),
            purpose.tracked(&foreign),
            HistoryObservation::held(&other_identity).tracked(&consumed),
        ] {
            assert!(purpose.same_held_scope(substituted).is_err());
            assert!(substituted.same_held_scope(purpose).is_err());
        }
    }
    for changed in [
        baseline.requested_target(),
        staged,
        baseline.maintenance(&maintenance),
        baseline.overlay_layer(fixture.head.commit, admitted.commit.commit().tree),
    ] {
        assert!(baseline.same_held_scope(changed).is_err());
        assert!(changed.same_held_scope(baseline).is_err());
    }
    assert!(
        staged
            .same_held_scope(staged.candidate(&copied_candidate))
            .is_err()
    );
    assert!(
        complete
            .same_held_scope(complete.maintenance(&copied_maintenance))
            .is_err()
    );
    assert!(
        complete
            .same_held_scope(
                complete.overlay_layer(fixture.base.commit, admitted.commit.commit().tree)
            )
            .is_err()
    );
    let selected = source.observe_publication_ordinary_retained().await?;
    let current =
        crate::guard::PendingCurrentReadCheck::capture(&guard, REFERENCE, &token(), Verb::Read)?;
    let purpose = super::HeldPurpose::capture(
        &source,
        &selected,
        REFERENCE,
        &fixture.head,
        baseline,
        current.clone(),
    )
    .await?;
    purpose.check(fixture.head.commit, baseline)?;
    assert!(purpose.check(fixture.base.commit, baseline).is_err());
    assert!(purpose.check(fixture.head.commit, staged).is_err());
    let mut changed = fixture.head.clone();
    changed.writer_epoch = changed
        .writer_epoch
        .checked_add(1)
        .ok_or("epoch overflow")?;
    assert!(
        super::HeldPurpose::capture(
            &source,
            &selected,
            REFERENCE,
            &changed,
            baseline,
            current.clone()
        )
        .await
        .is_err()
    );
    changed = fixture.head.clone();
    changed.seq = changed.seq.checked_add(1).ok_or("sequence overflow")?;
    assert!(
        super::HeldPurpose::capture(&source, &selected, REFERENCE, &changed, baseline, current)
            .await
            .is_err()
    );
    drop(purpose);
    drop(selected);
    assert!(
        consumed
            .observed_completed_view_contexts_for_tests()?
            .is_empty()
    );
    // The native first-hold path must independently retain genuine Original
    // controls when this held guard has no earlier receipt installed.
    let early = guard
        .authorize_observed(REFERENCE, &token(), Verb::Read, &[], "sdk", baseline)
        .await?;
    assert_eq!(early.record(), Some(&fixture.head));
    assert_eq!(consumed.finish()?.views.len(), 2);
    drop(guard);
    // The source adapter owns a namespace exclusion duplicate, so release it
    // before the next independent authorization reacquires that namespace.
    drop(source);
    drop(holder);

    // Binding checks confer no completion. The genuine enclosing authorization
    // must still walk both signed commits and preserve the Original baseline.
    let (authorized, ledger) = fixture.authorize().await?;
    assert_eq!(authorized.record(), Some(&fixture.head));
    assert_eq!(ledger.views.len(), 2);
    assert!(
        ledger
            .controls
            .iter()
            .any(|pin| pin.kind == ControlKind::Association)
    );
    configuration::check(&fixture).await?;
    Ok(())
}

#[tokio::test]
async fn held_owner_history_checks_each_authorization_with_scoped_pack_reads() -> TestResult {
    let fixture = Fixture::open().await?;
    let observation = fixture.guard().store().observe_content_for_tests();
    observation.reset();
    fixture.fs.reset();
    let (first, first_ledger) = fixture.authorize().await?;
    let first_reads = fixture.fs.paths();
    let first_native_reads = fixture.fs.native_paths();
    let first_content = observation.snapshot();
    observation.reset();
    fixture.fs.reset();
    let (second, second_ledger) = fixture.authorize().await?;
    let second_reads = fixture.fs.paths();
    let second_native_reads = fixture.fs.native_paths();
    let second_content = observation.snapshot();

    assert_eq!(first.record(), Some(&fixture.head));
    assert_eq!(second.record(), first.record());
    assert_eq!(first_ledger, second_ledger);
    assert_eq!(first_ledger.views.len(), 2);
    assert!(
        first_content.commit_gets >= 2,
        "both signed ancestors require real canonical Commit reads"
    );
    assert!(
        first_content.node_gets >= 2,
        "both signed trees require real canonical Node reads"
    );
    assert_eq!(
        first_content, second_content,
        "a second authorization cannot reuse completed first-call history"
    );
    assert!(!first_ledger.controls.is_empty());
    assert_eq!(
        first_reads, second_reads,
        "each call must execute a separate full walk and closing ledger"
    );
    assert_eq!(
        first_native_reads, second_native_reads,
        "each fresh walk must repeat its real native DATA reads"
    );
    let packs = first_native_reads
        .iter()
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "pack")
        })
        .collect::<Vec<_>>();
    assert!(
        !packs.is_empty(),
        "genuine history must read containing packs"
    );
    let unique = packs
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    for path in unique {
        let count = packs.iter().filter(|read| **read == path).count();
        assert!(
            count <= 2,
            "native pack DATA is shared inside one walk then independently closes: {} read {count} times",
            path.display()
        );
    }
    assert_eq!(
        fixture.guard().store().ref_get(REFERENCE).await?,
        Some(fixture.head.clone())
    );

    // A later real publication still obtains its normal final ACK and cannot
    // substitute either authorization's already completed history.
    let mut writer = fixture.repository.begin(REFERENCE, &token(), "sdk").await?;
    let next = fixture
        .repository
        .commit_request(
            &mut writer,
            request_file(
                vec![fixture.head.commit],
                b"unchanged publication ACK control",
            ),
        )
        .await?;
    assert_ne!(next.commit, fixture.head.commit);
    assert_eq!(
        fixture.guard().store().ref_get(REFERENCE).await?,
        Some(next)
    );
    Ok(())
}

#[tokio::test]
async fn held_owner_history_closes_all_physical_and_current_inputs() -> TestResult {
    for fault in [
        Fault::Unavailable,
        Fault::Corrupt,
        Fault::ReplaceLeaf,
        Fault::ReplaceParent,
    ] {
        let fixture = Fixture::open().await?;
        fixture.fs.reset();
        fixture.authorize().await?;
        let pack = fixture
            .fs
            .native_paths()
            .into_iter()
            .find(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "pack")
            })
            .ok_or("history pack absent")?;
        let original_body = if matches!(fault, Fault::Corrupt) {
            Some(crate::store::TokioLocalFs.read_nofollow(&pack).await?)
        } else {
            None
        };
        *fixture.fs.fault.lock().unwrap() = Some((pack.clone(), fault));
        assert!(
            fixture.authorize().await.is_err(),
            "changed physical input must refuse"
        );
        assert!(
            fixture.fs.fault.lock().unwrap().is_none(),
            "fault must hit a real read"
        );
        if let Some(mut expected) = original_body {
            *expected.last_mut().ok_or("actual fixture pack empty")? ^= 1;
            assert_eq!(
                crate::store::TokioLocalFs.read_nofollow(&pack).await?,
                expected,
                "corruption must change the actual whole pack before native capture"
            );
        }
        assert_eq!(
            fixture.guard().store().ref_get(REFERENCE).await?,
            Some(fixture.head.clone())
        );
    }

    let fixture = Fixture::open().await?;
    fixture.authorize().await?;
    let original = fixture.guard().original_commit(&fixture.base.commit)?;
    let association = crate::guard::publication_original_pins(&original)?
        .into_iter()
        .find(|pin| pin.kind == ControlKind::Association)
        .ok_or("ancestor Original association absent")?;
    let path = original
        .baseline()
        .authority()
        .control()
        .join(association.key);
    let archived = path.with_extension("held-history-archived");
    tokio::fs::rename(&path, &archived).await?;
    assert!(
        fixture.authorize().await.is_err(),
        "earlier success cannot replace ancestor Original authority"
    );
    tokio::fs::rename(&archived, &path).await?;
    fixture.authorize().await?;

    let mut writer = fixture.repository.begin(REFERENCE, &token(), "sdk").await?;
    let revoked = fixture
        .repository
        .commit_request(
            &mut writer,
            request_file_acl(vec![fixture.head.commit], b"fresh signed ACL refusal", 0),
        )
        .await?;
    let failure = fixture
        .authorize()
        .await
        .err()
        .ok_or("fresh ACL denial bypassed")?;
    assert!(
        failure
            .downcast_ref::<crate::store::StoreFailure>()
            .is_some_and(|error| matches!(
                error.kind(),
                crate::store::StoreErrorKind::Denied { .. }
            ))
    );
    assert_eq!(
        fixture.guard().store().ref_get(REFERENCE).await?,
        Some(revoked)
    );
    Ok(())
}

#[tokio::test]
async fn held_owner_history_cancellation_and_native_decline_preserve_failure() -> TestResult {
    let fixture = Fixture::open().await?;
    let (authorized, _) = fixture.authorize().await?;
    assert_eq!(authorized.record(), Some(&fixture.head));
    fixture.fs.reset();
    fixture.authorize().await?;
    let pack = fixture
        .fs
        .native_paths()
        .into_iter()
        .find(|path| {
            path.extension()
                .is_some_and(|extension| extension == "pack")
        })
        .ok_or("actual history pack absent")?;
    *fixture.fs.native_failure.lock().unwrap() = Some(pack.clone());
    assert!(
        fixture.authorize().await.is_err(),
        "configured native failure must propagate, never fall back"
    );
    *fixture.fs.native_failure.lock().unwrap() = None;
    fixture.authorize().await?;
    closing_cancellation::check(&fixture).await?;

    let holder = SingleHeld::acquire_read_only(fixture.guard().store()).await?;
    let held = holder.source();
    let identity = held.identity_proof();
    let mut guard = fixture.guard().held_guard(holder.source(), TokioClock)?;

    let observed = held.observe_publication_ordinary_retained().await?;
    let authority = fixture.guard().configured_original_authority()?;
    let mut exclusion = fixture
        .guard()
        .hold_original_registration(&authority, observed.identity())
        .await?;
    let retained = crate::guard::read::indexes::retention::capture(
        fixture.guard(),
        &authority,
        &mut exclusion,
        &held,
        &observed,
    )
    .await?;
    guard.retain_original_controls(retained.controls())?;
    let consumed = ConsumedResolver::new(&guard, &authority)?;
    let (entered, arrived) = tokio::sync::oneshot::channel();
    let (_release, released) = tokio::sync::oneshot::channel();
    *fixture.fs.pause.lock().unwrap() = Some(fs::ReadPause {
        target: pack,
        entered,
        released,
    });
    let capability = token();
    let history = HistoryObservation::held(&identity).tracked(&consumed);
    let mut pending =
        Box::pin(guard.authorize_observed(REFERENCE, &capability, Verb::Read, &[], "sdk", history));
    tokio::select! {
        arrived = tokio::time::timeout(std::time::Duration::from_secs(10), arrived) => { arrived??; }
        result = &mut pending => panic!("real paused authorization completed: {result:?}"),
    }
    drop(pending);
    assert!(
        consumed
            .observed_completed_view_contexts_for_tests()?
            .is_empty()
    );
    // Cancelling the consumer cannot release the caller's genuine namespace
    // and Original exclusions or invent a completed history for a later call.
    let coordination = fixture
        .guard()
        .store()
        .root()
        .join(terrane_format::bucket::BucketKey::parse("CAPABILITIES")?.lock_name());
    assert_eq!(
        crate::store::TokioLocalFs
            .try_lock_existing_exclusive(&coordination)
            .await
            .err()
            .ok_or("cancelled consumer released namespace exclusion")?
            .kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert_eq!(
        crate::store::TokioLocalFs
            .try_lock_existing_exclusive(&authority.control().join("retention.lock"))
            .await
            .err()
            .ok_or("cancelled consumer released Original exclusion")?
            .kind(),
        std::io::ErrorKind::WouldBlock
    );

    // An absent resolver declines native held dispatch and preserves generic
    // verification. Neither successful route grants a later malformed token.
    let generic = guard
        .authorize_observed(
            REFERENCE,
            &token(),
            Verb::Read,
            &[],
            "sdk",
            HistoryObservation::held(&identity),
        )
        .await?;
    assert_eq!(generic.record(), Some(&fixture.head));
    let mut expired =
        terrane_format::auth::verify(&token(), guard.keys(), guard.now(REFERENCE, Verb::Read)?)?
            .authority()
            .clone();
    expired.not_after = 1;
    let expired = terrane_format::auth::Token::issue(
        expired,
        &crate::ref_advance::tests::secret(),
        guard.keys()[0].public_key,
    )?
    .encode();
    assert!(
        guard
            .authorize_observed(
                REFERENCE,
                &expired,
                Verb::Read,
                &[],
                "sdk",
                HistoryObservation::held(&identity)
            )
            .await
            .is_err()
    );
    guard.keys[0].retirement = Some(guard.now(REFERENCE, Verb::Read)?);
    assert!(
        guard
            .authorize_observed(
                REFERENCE,
                &token(),
                Verb::Read,
                &[],
                "sdk",
                HistoryObservation::held(&identity)
            )
            .await
            .is_err(),
        "fresh issuer retirement must refuse after prior successful history"
    );
    guard.keys = fixture.guard().keys().to_vec();
    fixture.fs.reset();
    let refused = guard
        .authorize_observed(
            REFERENCE,
            b"invalid",
            Verb::Read,
            &[],
            "sdk",
            HistoryObservation::held(&identity),
        )
        .await;
    assert!(
        matches!(refused, Err(error) if matches!(error.kind(), crate::store::StoreErrorKind::Denied { .. }))
    );
    assert!(
        fixture.fs.paths().is_empty() && fixture.fs.native_paths().is_empty(),
        "authentication precedes physical history work"
    );
    Ok(())
}

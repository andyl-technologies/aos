//! Checks real current authorization against independent native input changes.
//!
//! Each fixture publishes through the ordinary production retention factory.
//! These tests construct no authorization snapshot or physical completion proof.

use super::*;
use crate::bucket::held::{CurrentNodeReads, SingleHeld};
use crate::guard::ConsumedResolver;
use crate::ref_advance::native_fixture::NativeFixture;
use crate::ref_advance::tests::{fixture, request_file, token};
use crate::store::{ContentStore, LocalFs, RefStore, TokioClock, TokioLocalFs};
use std::time::Duration;
use terrane_format::auth::Token;
use terrane_format::gc::publication::evidence::ControlKind;
use terrane_format::identity::{IdentityKind, TERRANE_V1};

type TestResult = Result<(), Box<dyn std::error::Error>>;
const REFERENCE: &str = "refs/heads/_/main";

async fn published() -> Result<(NativeFixture<TokioLocalFs>, RefRecord), Box<dyn std::error::Error>>
{
    let repository = fixture().await;
    let mut writer = repository.begin(REFERENCE, &token(), "sdk").await?;
    let head = repository
        .advance(
            &mut writer,
            request_file(Vec::new(), b"current authorization physical scope"),
        )
        .await?;
    Ok((repository, head))
}

#[tokio::test]
async fn native_current_history_rejects_invalid_token_before_content_reads() -> TestResult {
    let (repository, _) = published().await?;
    let observation = repository.store().observe_content_for_tests();
    observation.reset();

    let result = repository
        .guard()
        .authorize(REFERENCE, b"invalid token", Verb::Read, &[], "sdk")
        .await;

    assert!(
        matches!(result, Err(failure) if matches!(failure.kind(), crate::store::StoreErrorKind::Denied { .. }))
    );
    assert_eq!(observation.snapshot(), Default::default());
    Ok(())
}

#[tokio::test]
async fn native_current_history_walks_each_authorization_independently() -> TestResult {
    let (repository, head) = published().await?;
    let observation = repository.store().observe_content_for_tests();
    observation.reset();

    let first = repository
        .guard()
        .authorize(REFERENCE, &token(), Verb::Read, &[], "sdk")
        .await?;
    let first_counts = observation.snapshot();
    observation.reset();
    let second = repository
        .guard()
        .authorize(REFERENCE, &token(), Verb::Read, &[], "sdk")
        .await?;
    let second_counts = observation.snapshot();

    assert_eq!(first.record(), Some(&head));
    assert_eq!(second.record(), Some(&head));
    assert!(first_counts.commit_gets > 0);
    assert!(first_counts.node_gets > 0);
    assert_eq!(second_counts, first_counts);
    Ok(())
}

#[tokio::test]
async fn native_current_purpose_refuses_changed_whole_ref_epoch() -> TestResult {
    let (repository, head) = published().await?;
    let current =
        PendingCurrentReadCheck::for_guard(repository.guard(), REFERENCE, &token(), Verb::Read)?;
    let holder = SingleHeld::acquire_read_namespace(repository.store()).await?;
    let held = holder.source();
    let observed = held.observe_publication_ordinary_retained().await?;
    let identity = held.identity_proof();
    let authority = repository.guard().configured_original_authority()?;
    let consumed = ConsumedResolver::new(repository.guard(), &authority)?;
    let history = HistoryObservation::default().current_held_from_ordinary(&identity, &consumed)?;

    let purpose =
        CurrentPurpose::capture(&held, &observed, REFERENCE, &head, history, current.clone())
            .await?;
    purpose.check(head.commit, history)?;
    let mut changed = head.clone();
    changed.writer_epoch = changed
        .writer_epoch
        .checked_add(1)
        .ok_or("epoch overflow")?;
    let substituted =
        CurrentPurpose::capture(&held, &observed, REFERENCE, &changed, history, current).await;

    assert!(substituted.is_err());
    Ok(())
}

#[tokio::test]
async fn native_current_history_refuses_missing_actual_original_association() -> TestResult {
    let (repository, head) = published().await?;
    let authorized = repository
        .guard()
        .authorize(REFERENCE, &token(), Verb::Read, &[], "sdk")
        .await?;
    assert_eq!(authorized.record(), Some(&head));

    let context = repository.guard().original_commit(&head.commit)?;
    let pin = crate::guard::publication_original_pins(&context)?
        .into_iter()
        .find(|pin| pin.kind == ControlKind::Association)
        .ok_or("actual Original association pin absent")?;
    let path = context.baseline().authority().control().join(pin.key);
    TokioLocalFs.remove_file(&path).await?;
    let observation = repository.store().observe_content_for_tests();
    observation.reset();

    let result = repository
        .guard()
        .authorize(REFERENCE, &token(), Verb::Read, &[], "sdk")
        .await;

    assert!(result.is_err());
    assert_eq!(observation.snapshot(), Default::default());
    Ok(())
}

#[tokio::test]
async fn native_current_reader_refuses_cached_data_after_real_token_expiry() -> TestResult {
    let (repository, head) = published().await?;
    let commit = TERRANE_V1.from_digest(IdentityKind::Commit, &head.commit)?;
    let expected = repository.store().get(&commit, None).await?;
    let now = repository.guard().now(REFERENCE, Verb::Read)?;
    let expiry = now.checked_add(30).ok_or("expiry overflow")?;
    let mut authority = auth::verify(&token(), repository.guard().keys(), now)?
        .authority()
        .clone();
    authority.not_after = expiry;
    // The actual native fixture registers this RFC 8032 signing key.
    let secret = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];
    let capability =
        Token::issue(authority, &secret, repository.guard().keys()[0].public_key)?.encode();
    let current =
        PendingCurrentReadCheck::for_guard(repository.guard(), REFERENCE, &capability, Verb::Read)?;
    let holder = SingleHeld::acquire_read_namespace(repository.store()).await?;
    let held = holder.source();
    let observed = held.observe_publication_ordinary_retained().await?;
    let identity = held.identity_proof();
    let original = repository.guard().configured_original_authority()?;
    let consumed = ConsumedResolver::new(repository.guard(), &original)?;
    let history = HistoryObservation::default().current_held_from_ordinary(&identity, &consumed)?;
    let purpose =
        CurrentPurpose::capture(&held, &observed, REFERENCE, &head, history, current.clone())
            .await?;
    let reads = held.current_node_reads(&observed, &current).await?;

    purpose.check(head.commit, history)?;
    assert_eq!(reads.get(&commit, None).await?, expected);
    // This is one genuine current-reader invocation, not a race inside the
    // complete public authorize future. Its retained clock remains TokioClock.
    tokio::time::timeout(Duration::from_secs(35), async {
        while TokioClock
            .now()
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_secs()
            <= expiry
        {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Ok::<(), std::time::SystemTimeError>(())
    })
    .await??;
    let result = reads.get(&commit, None).await;

    assert!(matches!(result, Err(failure) if matches!(
        failure.kind(), crate::store::StoreErrorKind::Denied { .. }
    )));
    assert!(purpose.check(head.commit, history).is_err());
    assert!(reads.begin_closing().is_err());
    Ok(())
}

#[tokio::test]
async fn native_current_read_refuses_signed_acl_revocation() -> TestResult {
    let (repository, head) = published().await?;
    let authorized = repository
        .guard()
        .authorize(REFERENCE, &token(), Verb::Read, &[], "sdk")
        .await?;
    assert_eq!(authorized.record(), Some(&head));
    let mut writer = repository.begin(REFERENCE, &token(), "sdk").await?;
    let revoked = repository
        .advance(
            &mut writer,
            crate::ref_advance::tests::request_file_acl(
                vec![head.commit],
                b"signed revoked current policy",
                0,
            ),
        )
        .await?;
    assert_ne!(revoked.commit, head.commit);
    assert_eq!(
        repository.store().ref_get(REFERENCE).await?,
        Some(revoked.clone())
    );

    let result = repository
        .guard()
        .authorize(REFERENCE, &token(), Verb::Read, &[], "sdk")
        .await;

    assert!(matches!(result, Err(failure) if matches!(
        failure.kind(), crate::store::StoreErrorKind::Denied { .. }
    )));
    assert_eq!(repository.store().ref_get(REFERENCE).await?, Some(revoked));
    Ok(())
}

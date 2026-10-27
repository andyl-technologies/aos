//! Reads actual committed history without exposing raw backend or signing access.

#![cfg(all(feature = "tokio", unix))]

#[allow(
    dead_code,
    reason = "Other integration targets share this native fixture."
)]
#[path = "local_sdk/fixture.rs"]
mod fixture;

use fixture::{Fixture, MAIN, NEW, OLD, TestResult};
use terrane_format::auth::{Attenuation, Grant, Token, Verbs};
use terrane_sdk::{ref_advance::AdvanceError, repository::Error, store::StoreErrorKind};

fn attenuated(
    fixture: &Fixture,
    attenuation: Attenuation,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let secret: [u8; 32] = std::fs::read(fixture.location.authority.join("terminal.seed"))?
        .try_into()
        .map_err(|_| "invalid fixture terminal seed")?;
    Ok(Token::decode(fixture.authority.token())?
        .attenuate(
            attenuation,
            &secret,
            terrane_format::auth::public_key_from_secret(&secret),
        )?
        .encode())
}

#[tokio::test]
async fn committed_history_keeps_exact_order_provenance_and_reopened_head() -> TestResult {
    let fixture = Fixture::new().await?;
    let first = fixture.commit_bytes(OLD).await?;
    let second = fixture.commit_bytes(NEW).await?;
    let history = fixture
        .repository
        .ref_history(MAIN, 0, fixture.authority.token(), "sdk")
        .await?;
    let head = history.head().ok_or("missing actual head")?;

    assert_eq!(head.commit, second);
    assert_eq!(
        history.entries().last().map(|entry| &entry.record),
        Some(head)
    );
    assert_eq!(history.entries().len() as u64, head.seq);
    for (index, entry) in history.entries().iter().enumerate() {
        assert_eq!(entry.record.seq, index as u64 + 1);
        assert_eq!(entry.principal, "owner");
        assert!(entry.timestamp > 0);
        assert_eq!(entry.record.home, head.home);
    }
    let prior = &history.entries()[history.entries().len() - 2];
    assert_eq!(prior.record.commit, first);
    assert_eq!(
        history
            .entries()
            .last()
            .ok_or("missing history entry")?
            .previous_commit,
        Some(first)
    );

    let suffix = fixture
        .repository
        .ref_history(MAIN, head.seq, fixture.authority.token(), "sdk")
        .await?;
    assert_eq!(
        suffix.entries(),
        &history.entries()[history.entries().len() - 1..]
    );
    assert_eq!(suffix.head(), history.head());

    let reopened = fixture.reopen().await?;
    assert_eq!(
        reopened
            .repository
            .ref_history(MAIN, 1, reopened.authority.token(), "sdk")
            .await?,
        history
    );
    Ok(())
}

#[tokio::test]
async fn read_only_grants_can_read_history_but_other_branches_and_expiry_refuse() -> TestResult {
    let fixture = Fixture::new().await?;
    fixture.commit_bytes(OLD).await?;
    let read = attenuated(
        &fixture,
        Attenuation {
            grants: Some(vec![Grant::new(MAIN.into(), Verbs::new(1)?)?]),
            ..Attenuation::default()
        },
    )?;
    assert!(
        !fixture
            .repository
            .ref_history(MAIN, 1, &read, "sdk")
            .await?
            .entries()
            .is_empty()
    );

    for (reference, token) in [
        ("refs/heads/_/other", read),
        (
            MAIN,
            attenuated(
                &fixture,
                Attenuation {
                    not_after: Some(1),
                    ..Attenuation::default()
                },
            )?,
        ),
        (MAIN, b"invalid bearer".to_vec()),
    ] {
        assert!(
            matches!(fixture.repository.ref_history(reference, 1, &token, "sdk").await,
            Err(Error::Store(error)) if matches!(error.kind(), StoreErrorKind::Denied { .. }))
        );
    }
    Ok(())
}

#[tokio::test]
async fn absent_and_past_head_histories_are_empty_only_after_authorization() -> TestResult {
    let fixture = Fixture::new().await?;
    let absent = fixture
        .repository
        .ref_history("refs/heads/_/missing", 0, fixture.authority.token(), "sdk")
        .await?;
    assert!(absent.head().is_none());
    assert!(absent.entries().is_empty());

    let past = fixture
        .repository
        .ref_history(MAIN, u64::MAX, fixture.authority.token(), "sdk")
        .await?;
    assert!(past.head().is_some());
    assert!(past.entries().is_empty());
    assert!(
        fixture
            .repository
            .ref_history("refs/heads/_/missing", u64::MAX, b"invalid", "sdk")
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn malformed_and_nonbranch_names_cannot_open_history() -> TestResult {
    let fixture = Fixture::new().await?;
    for name in ["main", "refs/heads/../main", "refs/tags/release"] {
        assert!(matches!(
            fixture
                .repository
                .ref_history(name, 0, fixture.authority.token(), "sdk")
                .await,
            Err(Error::Advance(AdvanceError::InvalidRefClass))
        ));
    }
    Ok(())
}

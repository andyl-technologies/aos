//! Checks guarded point reads against genuine native refs and durable history.

#![cfg(all(feature = "tokio", unix))]

#[allow(
    dead_code,
    reason = "Other integration targets share this native fixture."
)]
#[path = "local_sdk/fixture.rs"]
mod fixture;

use fixture::{Fixture, MAIN, NEW, OLD, TestResult};
use terrane_format::auth::{self, Attenuation, Grant, Token, Verbs};
use terrane_sdk::{
    repository::Error,
    store::{Clock, StoreErrorKind, TokioClock},
};

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
async fn current_whole_head_matches_committed_history_and_survives_reopen() -> TestResult {
    let fixture = Fixture::new().await?;
    fixture.commit_bytes(OLD).await?;
    let previous = fixture
        .repository
        .ref_head(MAIN, fixture.authority.token(), "sdk")
        .await?
        .ok_or("missing initial head")?;
    let latest = fixture.commit_bytes(NEW).await?;
    let current = fixture
        .repository
        .ref_head(MAIN, fixture.authority.token(), "sdk")
        .await?
        .ok_or("missing current head")?;
    let history = fixture
        .repository
        .ref_history(MAIN, 0, fixture.authority.token(), "sdk")
        .await?;

    assert_eq!(current.commit, latest);
    assert_ne!(current, previous);
    assert_eq!(Some(&current), history.head());
    assert_eq!(
        Some(&current),
        history.entries().last().map(|entry| &entry.record)
    );

    let reopened = fixture.reopen().await?;
    assert_eq!(
        reopened
            .repository
            .ref_head(MAIN, reopened.authority.token(), "sdk")
            .await?,
        Some(current)
    );
    Ok(())
}

#[tokio::test]
async fn immutable_tag_point_read_preserves_its_complete_published_record() -> TestResult {
    let fixture = Fixture::new().await?;
    let commit = fixture.commit_bytes(OLD).await?;
    let name = "refs/tags/_/release";
    let published = fixture
        .repository
        .tag(MAIN, name, fixture.authority.token(), "sdk")
        .await?;

    assert_eq!(published.commit, commit);
    assert_eq!(
        fixture
            .repository
            .ref_head(name, fixture.authority.token(), "sdk")
            .await?,
        Some(published)
    );
    assert!(
        fixture
            .repository
            .ref_history(name, 0, fixture.authority.token(), "sdk")
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn authorized_absence_remains_distinct_from_invalid_credentials_and_scope_denial()
-> TestResult {
    let fixture = Fixture::new().await?;
    let absent = "refs/heads/_/missing";
    assert_eq!(
        fixture
            .repository
            .ref_head(absent, fixture.authority.token(), "sdk")
            .await?,
        None
    );
    let scoped = attenuated(
        &fixture,
        Attenuation {
            grants: Some(vec![Grant::new(MAIN.into(), Verbs::new(1)?)?]),
            ..Attenuation::default()
        },
    )?;

    for token in [b"invalid bearer".to_vec(), scoped] {
        assert!(
            matches!(fixture.repository.ref_head(absent, &token, "sdk").await,
            Err(Error::Store(error)) if matches!(error.kind(), StoreErrorKind::Denied { .. }))
        );
    }
    Ok(())
}

#[tokio::test]
async fn read_only_attenuation_permits_point_reads_but_expired_tokens_refuse() -> TestResult {
    let fixture = Fixture::new().await?;
    fixture.commit_bytes(OLD).await?;
    let scoped = attenuated(
        &fixture,
        Attenuation {
            grants: Some(vec![Grant::new(MAIN.into(), Verbs::new(1)?)?]),
            ..Attenuation::default()
        },
    )?;
    assert_eq!(
        fixture.repository.ref_head(MAIN, &scoped, "sdk").await?,
        fixture
            .repository
            .ref_head(MAIN, fixture.authority.token(), "sdk")
            .await?
    );
    let expired = attenuated(
        &fixture,
        Attenuation {
            not_after: Some(1),
            ..Attenuation::default()
        },
    )?;

    assert!(
        matches!(fixture.repository.ref_head(MAIN, &expired, "sdk").await,
        Err(Error::Store(error)) if matches!(error.kind(), StoreErrorKind::Denied { .. }))
    );
    Ok(())
}

#[tokio::test]
async fn genuine_issuer_signature_and_broad_grants_do_not_override_current_root_acl() -> TestResult
{
    let fixture = Fixture::new().await?;
    fixture.commit_bytes(OLD).await?;
    let now = TokioClock
        .now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let verified = auth::verify(
        fixture.authority.token(),
        &[fixture.authority.issuer_key().clone()],
        now,
    )?;
    let mut claims = verified.authority().clone();
    claims.subject = "outside-root-acl".into();
    claims.token_id = [94; 16];
    let issuer: [u8; 32] = std::fs::read(fixture.location.authority.join("issuer.seed"))?
        .try_into()
        .map_err(|_| "invalid fixture issuer seed")?;
    let foreign = Token::issue(claims, &issuer, auth::public_key_from_secret(&[95; 32]))?.encode();

    for name in [MAIN, "refs/heads/_/missing"] {
        assert!(
            matches!(fixture.repository.ref_head(name, &foreign, "sdk").await,
            Err(Error::Store(error)) if matches!(error.kind(), StoreErrorKind::Denied { .. }))
        );
    }
    Ok(())
}

#[tokio::test]
async fn malformed_names_refuse_and_lost_original_evidence_is_not_absence() -> TestResult {
    let fixture = Fixture::new().await?;
    let commit = fixture.commit_bytes(OLD).await?;
    for name in ["main", "refs/heads/../main", "refs/heads/_/main:/"] {
        assert!(
            fixture
                .repository
                .ref_head(name, fixture.authority.token(), "sdk")
                .await
                .is_err()
        );
    }
    let digest: String = commit.iter().map(|byte| format!("{byte:02x}")).collect();
    std::fs::remove_file(
        fixture
            .location
            .authority
            .join(format!("commit-{digest}.cbor")),
    )?;

    assert!(
        fixture
            .repository
            .ref_head(MAIN, fixture.authority.token(), "sdk")
            .await
            .is_err()
    );
    Ok(())
}

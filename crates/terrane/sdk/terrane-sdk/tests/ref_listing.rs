//! Exercises complete native inventories through guarded public SDK enumeration.

#![cfg(all(feature = "tokio", unix))]
#![allow(
    dead_code,
    reason = "Other integration targets share this native fixture."
)]

#[path = "local_sdk/fixture.rs"]
mod fixture;

use fixture::{Fixture, MAIN, TestResult, metadata};
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
        .map_err(|_| "invalid terminal fixture seed")?;
    Ok(Token::decode(fixture.authority.token())?
        .attenuate(attenuation, &secret, auth::public_key_from_secret(&secret))?
        .encode())
}

#[tokio::test]
async fn canonical_patterns_preserve_order_whole_heads_and_reopened_inventory() -> TestResult {
    let mut fixture = Fixture::new().await?;
    let fork = fixture
        .repository
        .fork(
            MAIN,
            "refs/heads/_/fork",
            fixture
                .repository
                .source_request(&fixture.authority, metadata("List genuine fork")),
        )
        .await?;
    let listed = fixture
        .repository
        .list_refs("refs/heads/*/*", fixture.authority.token(), "sdk")
        .await?;
    assert_eq!(
        listed.iter().map(|entry| entry.name()).collect::<Vec<_>>(),
        ["refs/heads/_/fork", MAIN]
    );
    assert_eq!(listed[0].record(), &fork);
    let history = fixture
        .repository
        .ref_history(MAIN, 1, fixture.authority.token(), "sdk")
        .await?;
    assert_eq!(Some(listed[1].record()), history.head());
    assert!(
        fixture
            .repository
            .list_refs("refs/heads/*", fixture.authority.token(), "sdk")
            .await?
            .is_empty()
    );

    fixture = fixture.reopen().await?;
    assert_eq!(
        fixture
            .repository
            .list_refs("refs/**", fixture.authority.token(), "sdk")
            .await?,
        listed
    );
    Ok(())
}

#[tokio::test]
async fn attenuation_filters_other_refs_and_grants_remain_intersected_with_actual_acl() -> TestResult
{
    let fixture = Fixture::new().await?;
    fixture
        .repository
        .fork(
            MAIN,
            "refs/heads/_/fork",
            fixture
                .repository
                .source_request(&fixture.authority, metadata("List separately scoped fork")),
        )
        .await?;
    let read = attenuated(
        &fixture,
        Attenuation {
            grants: Some(vec![Grant::new(MAIN.into(), Verbs::new(1)?)?]),
            ..Default::default()
        },
    )?;
    let listed = fixture
        .repository
        .list_refs("refs/**", &read, "sdk")
        .await?;
    assert_eq!(
        listed.iter().map(|entry| entry.name()).collect::<Vec<_>>(),
        [MAIN]
    );

    let now = TokioClock
        .now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)?
        .as_secs();
    let verified = auth::verify(
        fixture.authority.token(),
        &[fixture.authority.issuer_key().clone()],
        now,
    )?;
    let mut claims = verified.authority().clone();
    claims.subject = "outside-root-acl".into();
    claims.token_id = [82; 16];
    let issuer: [u8; 32] = std::fs::read(fixture.location.authority.join("issuer.seed"))?
        .try_into()
        .map_err(|_| "invalid issuer fixture seed")?;
    let foreign = Token::issue(claims, &issuer, auth::public_key_from_secret(&[83; 32]))?.encode();
    assert!(
        fixture
            .repository
            .list_refs("refs/**", &foreign, "sdk")
            .await?
            .is_empty()
    );
    Ok(())
}

#[tokio::test]
async fn empty_matches_still_refuse_invalid_and_expired_credentials() -> TestResult {
    let fixture = Fixture::new().await?;
    let expired = attenuated(
        &fixture,
        Attenuation {
            not_after: Some(1),
            ..Default::default()
        },
    )?;

    assert!(
        fixture
            .repository
            .list_refs("refs/tags/**", fixture.authority.token(), "sdk")
            .await?
            .is_empty()
    );
    for token in [b"invalid bearer".as_slice(), expired.as_slice()] {
        assert!(
            matches!(fixture.repository.list_refs("refs/tags/**", token, "sdk").await,
            Err(Error::Store(error)) if matches!(error.kind(), StoreErrorKind::Denied { .. }))
        );
    }
    Ok(())
}

#[tokio::test]
async fn malformed_patterns_and_root_suffixes_are_rejected() -> TestResult {
    let fixture = Fixture::new().await?;
    for pattern in [
        "",
        "heads/**",
        "refs//heads/**",
        "refs/heads/../**",
        "refs/**:/",
    ] {
        assert!(
            matches!(fixture.repository.list_refs(pattern, fixture.authority.token(), "sdk").await,
            Err(Error::Store(error)) if matches!(error.kind(), StoreErrorKind::Invalid(_)))
        );
    }
    Ok(())
}

#[tokio::test]
async fn an_unreadable_candidate_failure_exports_no_private_name_or_partial_result() -> TestResult {
    const HIDDEN: &str = "refs/heads/_/zz-private";
    let fixture = Fixture::new().await?;
    let fork = fixture
        .repository
        .fork(
            MAIN,
            HIDDEN,
            fixture.repository.source_request(
                &fixture.authority,
                metadata("List private candidate without disclosing faults"),
            ),
        )
        .await?;
    let read = attenuated(
        &fixture,
        Attenuation {
            grants: Some(vec![Grant::new(MAIN.into(), Verbs::new(1)?)?]),
            ..Default::default()
        },
    )?;
    assert_eq!(
        fixture
            .repository
            .list_refs("refs/**", &read, "sdk")
            .await?
            .iter()
            .map(|entry| entry.name())
            .collect::<Vec<_>>(),
        [MAIN]
    );

    // Remove this genuinely published fork's exact protected association. The
    // main ref sorts first, so its already gathered value must not escape when
    // later candidate verification fails before current Read can be decided.
    let digest: String = fork
        .commit
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let association = fixture
        .location
        .authority
        .join(format!("commit-{digest}.cbor"));
    assert!(!std::fs::read(&association)?.is_empty());
    std::fs::remove_file(association)?;

    let error = match fixture.repository.list_refs("refs/**", &read, "sdk").await {
        Err(Error::Store(error)) => error,
        other => return Err(format!("expected opaque inventory refusal, got {other:?}").into()),
    };
    assert!(matches!(error.kind(), StoreErrorKind::Unavailable { .. }));
    assert!(std::error::Error::source(&error).is_none());
    assert!(!error.to_string().contains(HIDDEN));
    Ok(())
}

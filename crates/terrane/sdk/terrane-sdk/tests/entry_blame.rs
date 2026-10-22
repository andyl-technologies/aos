//! Checks scoped graph audit through genuine repositories without content reads.

#![cfg(all(feature = "tokio", unix))]

#[allow(dead_code, reason = "Other targets share this repository fixture.")]
#[path = "local_sdk/fixture.rs"]
mod fixture;

use fixture::{Fixture, MAIN, OLD, TestResult};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use terrane_format::{
    auth::{self, Attenuation, Caveat, Grant, Token, Verbs},
    identity::{Identity, IdentityKind},
    surface::{View, ViewTarget},
};
use terrane_sdk::store::{
    ByteRange, Capabilities, CapabilityReport, ContentStore, ContentUpload, IdentityPrefix,
    StoreErrorKind, StoreFailure,
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
async fn blame_requires_only_selected_path_read_and_refuses_other_scopes() -> TestResult {
    let fixture = Fixture::new().await?;
    let commit = fixture.commit_bytes(OLD).await?;
    let view = View::parse(MAIN)?;
    let scoped = attenuated(
        &fixture,
        Attenuation {
            grants: Some(vec![Grant::new(MAIN.into(), Verbs::new(1)?)?]),
            caveats: vec![Caveat::Root("/file".into())],
            ..Default::default()
        },
    )?;

    let blame = fixture
        .repository
        .blame(&view, b"file", &scoped, "sdk")
        .await?;
    assert_eq!(blame.view_commit, commit);
    assert_eq!(blame.introduction.commit, commit);
    assert_eq!(blame.introduction.subject, "owner");
    assert!(blame.fold_chain.is_empty());
    let pinned = fixture
        .repository
        .blame(
            &View {
                target: ViewTarget::Commit(commit),
                subtree: Vec::new(),
                policy: None,
            },
            b"file",
            &scoped,
            "sdk",
        )
        .await?;
    assert_eq!(pinned, blame);

    let secret_path = fixture
        .repository
        .blame(&view, b"sibling", &scoped, "sdk")
        .await;
    assert!(
        matches!(secret_path, Err(terrane_sdk::repository::Error::Store(error))
        if matches!(error.kind(), StoreErrorKind::Denied { .. }))
    );
    for attenuation in [
        Attenuation {
            not_after: Some(1),
            ..Default::default()
        },
        Attenuation {
            caveats: vec![Caveat::Surface("other".into())],
            ..Default::default()
        },
        Attenuation {
            grants: Some(vec![Grant::new(
                "refs/heads/_/other".into(),
                Verbs::new(1)?,
            )?]),
            ..Default::default()
        },
        Attenuation {
            caveats: vec![Caveat::Root("/sibling".into())],
            ..Default::default()
        },
    ] {
        let token = attenuated(&fixture, attenuation)?;
        assert!(
            matches!(fixture.repository.blame(&view, b"file", &token, "sdk").await,
            Err(terrane_sdk::repository::Error::Store(error)) if matches!(error.kind(), StoreErrorKind::Denied { .. }))
        );
    }
    Ok(())
}

#[tokio::test]
async fn blame_uses_signed_metadata_without_requesting_object_bodies() -> TestResult {
    let fixture = Fixture::new().await?;
    let commit = fixture.commit_bytes(OLD).await?;
    let bodies = Arc::new(AtomicUsize::new(0));
    let repository = fixture
        .repository
        .with_read_driver(|original| MetadataOnly {
            original: original.clone(),
            bodies: Arc::clone(&bodies),
        });

    let blame = repository
        .blame(
            &View::parse(MAIN)?,
            b"file",
            fixture.authority.token(),
            "sdk",
        )
        .await?;

    assert_eq!(blame.introduction.commit, commit);
    assert_eq!(bodies.load(Ordering::Relaxed), 0);
    Ok(())
}

struct MetadataOnly<S> {
    original: S,
    bodies: Arc<AtomicUsize>,
}

impl<S: CapabilityReport> CapabilityReport for MetadataOnly<S> {
    fn capabilities(&self) -> &Capabilities {
        self.original.capabilities()
    }
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl<S: ContentStore + Sync> ContentStore for MetadataOnly<S> {
    async fn put(&self, _: ContentUpload<'_>) -> Result<Identity, StoreFailure> {
        panic!("metadata disclosure attempted a content write")
    }

    async fn get(
        &self,
        identity: &Identity,
        range: Option<ByteRange>,
    ) -> Result<Vec<u8>, StoreFailure> {
        if matches!(
            identity.kind(),
            IdentityKind::Chunk | IdentityKind::Manifest
        ) {
            self.bodies.fetch_add(1, Ordering::Relaxed);
            return Err(StoreFailure::new(StoreErrorKind::Unsupported));
        }
        self.original.get(identity, range).await
    }

    async fn has(&self, _: &[Identity]) -> Result<Vec<bool>, StoreFailure> {
        panic!("metadata disclosure attempted content presence reads")
    }

    async fn list(&self, _: &IdentityPrefix) -> Result<Vec<Identity>, StoreFailure> {
        panic!("metadata disclosure attempted advisory content enumeration")
    }
}

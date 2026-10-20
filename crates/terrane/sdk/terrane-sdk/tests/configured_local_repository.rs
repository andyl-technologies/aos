//! Exercises strict configured reopening and real authorized SDK startup.
#![cfg(all(feature = "tokio", feature = "surface-sdk", unix))]

#[allow(
    dead_code,
    reason = "The shared fixture supports other SDK integration targets."
)]
#[path = "local_sdk/fixture.rs"]
mod fixture;

use fixture::{Fixture, MAIN, OLD, TestResult};
use terrane_sdk::{
    config::{Config, local_repository::LocalOpenError},
    repository::Error,
    role::Role,
    store::{LocalFs, TokioClock, TokioLocalFs},
    surface::{ExposureState, PreparedExposures, TokenResolver},
};
use terrane_format::auth::{Attenuation, Grant, Token, Verbs};

struct ExplicitFileToken;

#[async_trait::async_trait]
impl TokenResolver for ExplicitFileToken {
    async fn resolve(&self, reference: &str) -> Result<Vec<u8>, Error> {
        let path = reference
            .strip_prefix("file:")
            .ok_or(Error::UnavailableOperation("test credential provider"))?;
        Ok(TokioLocalFs
            .read_nofollow(std::path::Path::new(path))
            .await?)
    }
}

fn configuration(fixture: &Fixture) -> String {
    format!(
        r#"store = "bucket(file://{})"
[[expose]]
id = "configured"
view = "{MAIN}"
surface = "sdk"
at = "{}"
token = "file:{}"
mode = {{ reader = "pinned" }}
[local_repository]
authority_directory = "{}"
issuer = "local"
key_id = "initial"
owner_uid = {}
store_name = "local"
domain = "private:owner"
default_private_domain = "private:owner"
current_reference = "{MAIN}"
policy_authority = "{MAIN}"
acl = [{{ principal = "owner", verbs = ["read", "fork", "commit", "tag", "admin"] }}]
[local_repository.timing]
maximum_ms = 30000
grace_ms = 60000
margin_ms = 10000
"#,
        fixture.location.bucket.display(),
        fixture.parent.join("configured").display(),
        fixture.parent.join("exposure.cbor").display(),
        fixture.location.authority.display(),
        fixture.owner
    )
}

async fn write_read_capability(fixture: &Fixture) -> TestResult {
    let secret: [u8; 32] = std::fs::read(fixture.location.authority.join("terminal.seed"))?
        .try_into()
        .map_err(|_| "wrong terminal seed length")?;
    let token = Token::decode(fixture.authority.token())?.attenuate(
        Attenuation {
            grants: Some(vec![Grant::new(MAIN.into(), Verbs::new(1)?)?]),
            ..Attenuation::default()
        },
        &secret,
        terrane_format::auth::public_key_from_secret(&secret),
    )?;
    std::fs::write(fixture.parent.join("exposure.cbor"), token.encode())?;
    Ok(())
}

#[tokio::test]
async fn configured_local_reopen_prepares_and_starts_actual_read_only_sdk() -> TestResult {
    let fixture = Fixture::new().await?;
    let commit = fixture.commit_bytes(OLD).await?;
    write_read_capability(&fixture).await?;
    let config = Config::parse(&configuration(&fixture))?;

    let repository = config
        .open_local_repository(Role::Serve, TokioLocalFs, TokioClock)
        .await?;
    assert_eq!(
        repository.chunk_profile(),
        fixture.repository.chunk_profile()
    );
    let prepared =
        PreparedExposures::prepare(&repository, config.exposures(), &ExplicitFileToken).await?;
    let handles = prepared.start(&repository).await?;

    assert_eq!(handles.len(), 1);
    assert_eq!(std::fs::read(fixture.parent.join("configured/file"))?, OLD);
    assert_eq!(handles[0].status().commit, commit);
    assert_eq!(handles[0].status().state, ExposureState::Serving);
    assert_eq!(handles[0].status().writer, None);
    handles[0].stop()?;
    Ok(())
}

#[tokio::test]
async fn configured_local_reopen_never_substitutes_instance_token_for_exposure() -> TestResult {
    let fixture = Fixture::new().await?;
    fixture.commit_bytes(OLD).await?;
    let config = Config::parse(&configuration(&fixture))?;
    let repository = config
        .open_local_repository(Role::Serve, TokioLocalFs, TokioClock)
        .await?;

    assert!(
        PreparedExposures::prepare(&repository, config.exposures(), &ExplicitFileToken)
            .await
            .is_err()
    );
    assert!(!fixture.parent.join("configured").exists());
    Ok(())
}

#[tokio::test]
async fn configured_local_reopen_rejects_unsupported_stores_and_nonserve_roles() -> TestResult {
    let fixture = Fixture::new().await?;
    let valid = configuration(&fixture);
    let store_line = valid.lines().next().ok_or("missing store")?;
    for expression in [
        "disk(/does-not-exist)",
        "bucket(s3://unsupported/prefix)",
        "guard(policy=explicit)(bucket(file:///does-not-exist))",
        "routed[bucket(file:///does-not-exist),disk(/also-absent)]",
    ] {
        let config = Config::parse(&valid.replace(store_line, &format!("store = '{expression}'")))?;
        assert!(
            matches!(
                config
                    .open_local_repository(Role::Serve, TokioLocalFs, TokioClock)
                    .await,
                Err(LocalOpenError::UnsupportedStore)
            ),
            "accepted {expression}"
        );
    }
    let missing = Config::parse("store = 'bucket(file:///does-not-exist)'")?;
    assert!(matches!(
        missing
            .open_local_repository(Role::Serve, TokioLocalFs, TokioClock)
            .await,
        Err(LocalOpenError::MissingConfiguration)
    ));
    let config = Config::parse(&valid)?;
    for role in [
        Role::Publish,
        Role::Realize,
        Role::FuseWorker,
        Role::Gc,
        Role::Job,
    ] {
        assert!(
            matches!(config.open_local_repository(role, TokioLocalFs, TokioClock).await,
            Err(LocalOpenError::WrongRole(rejected)) if rejected == role)
        );
    }
    assert!(!fixture.parent.join("configured").exists());
    Ok(())
}

#[tokio::test]
async fn configured_local_reopen_requires_original_trust_and_validated_timing() -> TestResult {
    let fixture = Fixture::new().await?;
    fixture.commit_bytes(OLD).await?;
    let valid = configuration(&fixture);
    for (from, to) in [
        ("issuer = \"local\"", "issuer = \"untrusted\""),
        ("key_id = \"initial\"", "key_id = \"wrong-key\""),
    ] {
        let config = Config::parse(&valid.replace(from, to))?;
        assert!(matches!(
            config
                .open_local_repository(Role::Serve, TokioLocalFs, TokioClock)
                .await,
            Err(LocalOpenError::Repository(_))
        ));
    }
    let wrong_authority = valid.replace(
        fixture.location.authority.to_string_lossy().as_ref(),
        fixture
            .parent
            .join("missing-authority")
            .to_string_lossy()
            .as_ref(),
    );
    let config = Config::parse(&wrong_authority)?;
    assert!(matches!(
        config
            .open_local_repository(Role::Serve, TokioLocalFs, TokioClock)
            .await,
        Err(LocalOpenError::Repository(_))
    ));
    let wrong_owner = valid.replace(
        &format!("owner_uid = {}", fixture.owner),
        &format!("owner_uid = {}", fixture.owner ^ 1),
    );
    let config = Config::parse(&wrong_owner)?;
    assert!(matches!(
        config
            .open_local_repository(Role::Serve, TokioLocalFs, TokioClock)
            .await,
        Err(LocalOpenError::Repository(_))
    ));

    for (from, to) in [
        ("maximum_ms = 30000", "maximum_ms = 50000"),
        ("margin_ms = 10000", "margin_ms = 0"),
        (
            "current_reference = \"refs/heads/_/main\"",
            "current_reference = \"refs/tags/_/main\"",
        ),
        ("issuer = \"local\"", "issuer = \"\""),
        ("key_id = \"initial\"", ""),
    ] {
        assert!(
            Config::parse(&valid.replace(from, to)).is_err(),
            "accepted {to:?}"
        );
    }
    assert!(!fixture.parent.join("configured").exists());
    Ok(())
}

#[tokio::test]
async fn configured_local_reopen_preserves_signed_current_acl_denial() -> TestResult {
    use terrane_sdk::{repository::PreparedTree, surface::View};
    use terrane_format::{
        cbor,
        tree_builder::Tree,
        tree_format::{Property, TreeUse},
    };

    let fixture = Fixture::new().await?;
    let previous = fixture.commit_bytes(OLD).await?;
    let mut acl = Vec::new();
    cbor::write_array(&mut acl, 1);
    cbor::write_array(&mut acl, 2);
    cbor::write_text(&mut acl, "owner");
    cbor::write_uint(&mut acl, 0);
    let tree = Tree::build(
        Vec::new(),
        Some(vec![
            Property {
                name: "acl",
                value: &acl,
            },
            Property {
                name: "domain",
                value: b"\x6dprivate:owner",
            },
            Property {
                name: "durability",
                value: b"\x65local",
            },
        ]),
        fixture.repository.chunk_profile().minimum() as u64,
        TreeUse::Ordinary,
    )?;
    let prepared = PreparedTree::from_tree(&tree)?;
    let mut session = fixture
        .repository
        .begin(MAIN, fixture.authority.token(), "sdk")
        .await?;
    let mut request = fixture.repository.source_request(
        &fixture.authority,
        fixture::metadata("Explicit current ACL denial"),
    );
    request.commit.tree = prepared.root();
    request.commit.parents = vec![previous];
    fixture
        .repository
        .commit(&mut session, prepared, request)
        .await?;
    assert!(
        fixture
            .repository
            .read_file(
                &View::parse(MAIN)?,
                b"file",
                fixture.authority.token(),
                "sdk"
            )
            .await
            .is_err()
    );

    let config = Config::parse(&configuration(&fixture))?;
    assert!(matches!(
        config
            .open_local_repository(Role::Serve, TokioLocalFs, TokioClock)
            .await,
        Err(LocalOpenError::Repository(_))
    ));
    assert!(!fixture.parent.join("configured").exists());
    Ok(())
}

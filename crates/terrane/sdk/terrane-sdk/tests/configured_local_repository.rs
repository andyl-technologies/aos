//! Exercises strict configured reopening and real authorized SDK startup.
#![cfg(all(feature = "tokio", feature = "surface-sdk", unix))]

#[allow(
    dead_code,
    reason = "The shared fixture supports other SDK integration targets."
)]
#[path = "local_sdk/fixture.rs"]
mod fixture;

use fixture::{Fixture, MAIN, OLD, TestResult};
use terrane_format::auth::{Attenuation, Grant, Token, Verbs};
use terrane_sdk::{
    config::{Config, local_repository::LocalOpenError},
    repository::Error,
    role::Role,
    store::{LocalFs, TokioClock, TokioLocalFs},
    surface::{ExposureState, PreparedExposures, TokenResolver},
};

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
    use terrane_format::{
        cbor,
        tree_builder::Tree,
        tree_format::{Property, TreeUse},
    };
    use terrane_sdk::{repository::PreparedTree, surface::View};

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

struct MissingCache {
    calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    capabilities: terrane_sdk::store::Capabilities,
}

impl MissingCache {
    fn new(calls: std::sync::Arc<std::sync::atomic::AtomicUsize>) -> Self {
        use terrane_sdk::store::{Capabilities, Durability, RangeCapability, RefCapability};
        Self {
            calls,
            capabilities: Capabilities {
                refs: RefCapability::None,
                ranges: RangeCapability::Ranges,
                presign: false,
                locality: Default::default(),
                durability: Durability::Local,
                sealed: false,
            },
        }
    }
}

impl terrane_sdk::store::CapabilityReport for MissingCache {
    fn capabilities(&self) -> &terrane_sdk::store::Capabilities {
        &self.capabilities
    }
}

#[async_trait::async_trait]
impl terrane_sdk::store::ContentStore for MissingCache {
    async fn put(
        &self,
        _: terrane_sdk::store::ContentUpload<'_>,
    ) -> Result<terrane_format::identity::Identity, terrane_sdk::store::StoreFailure> {
        panic!("read-only composition dispatched a cache write")
    }

    async fn get(
        &self,
        identity: &terrane_format::identity::Identity,
        _: Option<terrane_sdk::store::ByteRange>,
    ) -> Result<Vec<u8>, terrane_sdk::store::StoreFailure> {
        self.calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Err(terrane_sdk::store::StoreFailure::new(
            terrane_sdk::store::StoreErrorKind::Absent(identity.clone()),
        ))
    }

    async fn has(
        &self,
        _: &[terrane_format::identity::Identity],
    ) -> Result<Vec<bool>, terrane_sdk::store::StoreFailure> {
        panic!("composition bypassed verified content reads")
    }

    async fn list(
        &self,
        _: &terrane_sdk::store::IdentityPrefix,
    ) -> Result<Vec<terrane_format::identity::Identity>, terrane_sdk::store::StoreFailure> {
        panic!("composition used cache listing as original reachability")
    }
}

#[tokio::test]
async fn configured_read_cache_preserves_original_authority_and_refuses_writes() -> TestResult {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use terrane_sdk::surface::View;

    let fixture = Fixture::new().await?;
    let commit = fixture.commit_bytes(OLD).await?;
    write_read_capability(&fixture).await?;
    let config = Config::parse(&configuration(&fixture))?;
    let calls = Arc::new(AtomicUsize::new(0));
    let repository = config
        .open_local_repository(Role::Serve, TokioLocalFs, TokioClock)
        .await?
        .with_read_cache(MissingCache::new(Arc::clone(&calls)));
    let before = std::fs::read(fixture.location.bucket.join("publication/PORTABLE"))?;

    let listed = repository
        .list_refs("refs/**", fixture.authority.token(), "sdk")
        .await?;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].name(), MAIN);
    assert_eq!(listed[0].record().commit, commit);

    let contents = repository
        .read_file(
            &View::parse(MAIN)?,
            b"file",
            fixture.authority.token(),
            "sdk",
        )
        .await?;
    assert_eq!(contents, (commit, OLD.to_vec()));
    assert!(calls.load(Ordering::Relaxed) > 0);

    let mut session = repository
        .begin(MAIN, fixture.authority.token(), "sdk")
        .await?;
    assert!(
        repository
            .commit_directory(
                &mut session,
                &fixture.parent.join("source"),
                &fixture.authority,
                fixture::metadata("Refused cached repository write")
            )
            .await
            .is_err()
    );

    let prepared =
        PreparedExposures::prepare(&repository, config.exposures(), &ExplicitFileToken).await?;
    let handles = prepared.start(&repository).await?;
    assert_eq!(handles[0].status().commit, commit);
    assert_eq!(std::fs::read(fixture.parent.join("configured/file"))?, OLD);
    handles[0].stop()?;

    assert_eq!(
        std::fs::read(fixture.location.bucket.join("publication/PORTABLE"))?,
        before
    );
    Ok(())
}

struct OriginalDriver<S> {
    original: S,
    calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    unavailable: bool,
}

impl<S: terrane_sdk::store::CapabilityReport> terrane_sdk::store::CapabilityReport
    for OriginalDriver<S>
{
    fn capabilities(&self) -> &terrane_sdk::store::Capabilities {
        self.original.capabilities()
    }
}

#[async_trait::async_trait]
impl<S: terrane_sdk::store::ContentStore + Sync> terrane_sdk::store::ContentStore
    for OriginalDriver<S>
{
    async fn put(
        &self,
        _: terrane_sdk::store::ContentUpload<'_>,
    ) -> Result<terrane_format::identity::Identity, terrane_sdk::store::StoreFailure> {
        panic!("read-only driver composition dispatched a content write")
    }

    async fn get(
        &self,
        identity: &terrane_format::identity::Identity,
        range: Option<terrane_sdk::store::ByteRange>,
    ) -> Result<Vec<u8>, terrane_sdk::store::StoreFailure> {
        self.calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if self.unavailable {
            return Err(terrane_sdk::store::StoreFailure::new(
                terrane_sdk::store::StoreErrorKind::Unavailable { retry_after: None },
            ));
        }
        self.original.get(identity, range).await
    }

    async fn has(
        &self,
        identities: &[terrane_format::identity::Identity],
    ) -> Result<Vec<bool>, terrane_sdk::store::StoreFailure> {
        self.original.has(identities).await
    }

    async fn list(
        &self,
        prefix: &terrane_sdk::store::IdentityPrefix,
    ) -> Result<Vec<terrane_format::identity::Identity>, terrane_sdk::store::StoreFailure> {
        self.original.list(prefix).await
    }
}

#[tokio::test]
async fn configured_complete_content_driver_preserves_authority_and_is_not_bypassed() -> TestResult
{
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use terrane_sdk::surface::View;

    let fixture = Fixture::new().await?;
    let commit = fixture.commit_bytes(OLD).await?;
    write_read_capability(&fixture).await?;
    let config = Config::parse(&configuration(&fixture))?;
    let calls = Arc::new(AtomicUsize::new(0));
    let repository = config
        .open_local_repository(Role::Serve, TokioLocalFs, TokioClock)
        .await?
        .with_read_driver(|original| OriginalDriver {
            original: original.clone(),
            calls: Arc::clone(&calls),
            unavailable: false,
        });
    let before = std::fs::read(fixture.location.bucket.join("publication/PORTABLE"))?;

    let actual = repository
        .read_file(
            &View::parse(MAIN)?,
            b"file",
            fixture.authority.token(),
            "sdk",
        )
        .await?;
    assert_eq!(actual, (commit, OLD.to_vec()));
    assert!(calls.load(Ordering::Relaxed) > 0);
    let prepared =
        PreparedExposures::prepare(&repository, config.exposures(), &ExplicitFileToken).await?;
    let handles = prepared.start(&repository).await?;
    assert_eq!(handles[0].status().commit, commit);
    assert_eq!(std::fs::read(fixture.parent.join("configured/file"))?, OLD);
    handles[0].stop()?;
    assert_eq!(
        std::fs::read(fixture.location.bucket.join("publication/PORTABLE"))?,
        before
    );

    let calls = Arc::new(AtomicUsize::new(0));
    let refused = config
        .open_local_repository(Role::Serve, TokioLocalFs, TokioClock)
        .await?
        .with_read_driver(|original| OriginalDriver {
            original: original.clone(),
            calls: Arc::clone(&calls),
            unavailable: true,
        });
    let result = refused
        .read_file(
            &View::parse(MAIN)?,
            b"file",
            fixture.authority.token(),
            "sdk",
        )
        .await;
    assert!(matches!(result, Err(Error::Store(error))
                    if matches!(error.kind(), terrane_sdk::store::StoreErrorKind::Unavailable { .. })));
    assert!(calls.load(Ordering::Relaxed) > 0);
    Ok(())
}

struct ControlledPresentation {
    output: Option<Vec<u8>>,
    calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

#[async_trait::async_trait]
impl terrane_sdk::repository::ObjectPresentation for ControlledPresentation {
    async fn read(
        &self,
        _: &terrane_format::identity::Identity,
        _: usize,
    ) -> Result<Vec<u8>, terrane_sdk::store::StoreFailure> {
        self.calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.output.clone().ok_or_else(|| {
            terrane_sdk::store::StoreFailure::new(terrane_sdk::store::StoreErrorKind::Unavailable {
                retry_after: None,
            })
        })
    }
}

#[tokio::test]
async fn object_presentation_cannot_replace_verified_bytes_or_bypass_authorization() -> TestResult {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use terrane_sdk::surface::View;

    let fixture = Fixture::new().await?;
    let commit = fixture.commit_bytes(OLD).await?;
    let config = Config::parse(&configuration(&fixture))?;
    let view = View::parse(MAIN)?;
    for output in [
        Some(OLD.to_vec()),
        Some(b"substituted plaintext".to_vec()),
        None,
    ] {
        let succeeds = output.as_deref() == Some(OLD);
        let calls = Arc::new(AtomicUsize::new(0));
        let repository = config
            .open_local_repository(Role::Serve, TokioLocalFs, TokioClock)
            .await?
            .with_object_presentation(Arc::new(ControlledPresentation {
                output,
                calls: Arc::clone(&calls),
            }));

        assert!(
            repository
                .read_file(&view, b"file", b"invalid token", "sdk")
                .await
                .is_err()
        );
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        let result = repository
            .read_file(&view, b"file", fixture.authority.token(), "sdk")
            .await;

        assert_eq!(calls.load(Ordering::Relaxed), 1);
        if succeeds {
            assert_eq!(result?, (commit, OLD.to_vec()));
        } else {
            assert!(
                result.is_err(),
                "presentation failure or substitution was bypassed"
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn sdk_schema_preparation_never_calls_object_presentation() -> TestResult {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let fixture = Fixture::new().await?;
    fixture.commit_bytes(OLD).await?;
    write_read_capability(&fixture).await?;
    let config = Config::parse(&configuration(&fixture))?;
    let calls = Arc::new(AtomicUsize::new(0));
    let repository = config
        .open_local_repository(Role::Serve, TokioLocalFs, TokioClock)
        .await?
        .with_object_presentation(Arc::new(ControlledPresentation {
            output: Some(b"substituted plaintext".to_vec()),
            calls: Arc::clone(&calls),
        }));

    let prepared =
        PreparedExposures::prepare(&repository, config.exposures(), &ExplicitFileToken).await?;
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    assert!(prepared.start(&repository).await.is_err());

    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert!(!fixture.parent.join("configured").exists());
    Ok(())
}

#[tokio::test]
async fn explicit_seed_bootstrap_registers_original_profile_and_refuses_reseeding() -> TestResult {
    use std::time::Duration;
    use terrane_format::{
        auth::Authority,
        refs::{Locality, PrincipalKind},
    };
    use terrane_sdk::{
        ref_advance::CommitTiming,
        repository::{
            LocalAuthorityIdentity, LocalAuthorityParameters, LocalRepositoryLocation,
            LocalRepositoryPolicy, Repository,
        },
    };

    let fixture = Fixture::new().await?;
    let location = LocalRepositoryLocation {
        bucket: fixture.parent.join("explicit-seed-bucket"),
        authority: fixture.parent.join("explicit-seed-authority"),
    };
    let grants = vec![Grant::new("refs/**".into(), Verbs::new(31)?)?];
    let parameters = || LocalAuthorityParameters {
        owner_uid: fixture.owner,
        authority: Authority {
            issuer: "local".into(),
            key_id: "initial".into(),
            subject: "owner".into(),
            kind: PrincipalKind::Human,
            groups: Vec::new(),
            not_after: u64::MAX,
            not_before: None,
            token_id: [7; 16],
            grants: grants.clone(),
            workload: None,
        },
    };
    let policy = || -> Result<LocalRepositoryPolicy, Box<dyn std::error::Error>> {
        Ok(LocalRepositoryPolicy {
            store_name: "local".into(),
            domain: "private:owner".into(),
            default_private_domain: "private:owner".into(),
            acl: vec![("owner".into(), 31)],
            locality: Locality::default(),
            timing: CommitTiming::new(
                Duration::from_secs(30),
                Duration::from_secs(60),
                Duration::from_secs(10),
            )?,
            policy_authority: Some(MAIN.into()),
            bootstrap_properties: Vec::new(),
        })
    };
    let (repository, authority) = Repository::initialize_local_with_seed(
        &location,
        parameters(),
        policy()?,
        MAIN,
        [7; 32],
        TokioLocalFs,
        TokioClock,
    )
    .await?;
    assert_eq!(repository.chunk_profile().seed(), [7; 32]);
    let before = std::fs::read(location.bucket.join("publication/PORTABLE"))?;
    drop(repository);
    drop(authority);

    assert!(
        Repository::initialize_local_with_seed(
            &location,
            parameters(),
            policy()?,
            MAIN,
            [8; 32],
            TokioLocalFs,
            TokioClock
        )
        .await
        .is_err()
    );
    assert_eq!(
        std::fs::read(location.bucket.join("publication/PORTABLE"))?,
        before
    );
    let (reopened, _) = Repository::open_local(
        &location,
        &LocalAuthorityIdentity {
            owner_uid: fixture.owner,
            issuer: "local".into(),
            key_id: "initial".into(),
        },
        policy()?,
        MAIN,
        TokioLocalFs,
        TokioClock,
    )
    .await?;

    assert_eq!(reopened.chunk_profile().seed(), [7; 32]);
    Ok(())
}

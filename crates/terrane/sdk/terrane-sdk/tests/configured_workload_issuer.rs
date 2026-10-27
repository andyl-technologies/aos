//! Opens trusted static issuer configuration against actual native signing files.

#![cfg(all(feature = "tokio", unix))]

use std::{
    fs,
    num::NonZeroU64,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    time::UNIX_EPOCH,
};

use terrane_format::auth::{self, PrincipalKind, Token};
use terrane_sdk::{
    config::{Config, workload::IssuerOpenError},
    role::Role,
    store::{Clock, LocalFs, TokioClock, TokioLocalFs},
    workload::{MintError, WorkloadClaims},
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
const SEED: [u8; 32] = [31; 32];

struct Directory(PathBuf);

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn configuration(path: &Path, owner: u32) -> String {
    let public: String = auth::public_key_from_secret(&SEED)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!(
        r#"role = "serve"
store = "bucket(file:///not-opened)"
[static_workload_issuers.ci]
issuer = "ci"
key_id = "initial"
public_key = "{public}"
signing_key_file = "{}"
owner_uid = {owner}
maximum_lifetime_seconds = 300
lifetime_margin_seconds = 10
"#,
        path.display()
    )
}

#[test]
fn strict_issuer_policy_loads_without_accessing_its_signing_path() -> TestResult {
    let config = Config::parse(&configuration(
        Path::new("/does-not-exist/issuer.seed"),
        840,
    ))?;
    let issuer = config
        .static_workload_issuers()
        .get("ci")
        .ok_or("missing parsed issuer")?;
    assert_eq!(issuer.issuer, "ci");
    assert_eq!(issuer.maximum_lifetime_seconds, 300);
    assert_eq!(issuer.lifetime_margin_seconds, 10);
    assert_eq!(issuer.owner_uid, 840);
    assert_eq!(issuer.retirement, None);
    Ok(())
}

#[test]
fn invalid_and_ambiguous_whole_configuration_refuses_before_opening() -> TestResult {
    let valid = configuration(Path::new("/does-not-exist/issuer.seed"), 840);
    let public: String = auth::public_key_from_secret(&SEED)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    for (before, after) in [
        (public.as_str(), "00"),
        (public.as_str(), &public.to_uppercase()),
        ("/does-not-exist/issuer.seed", "relative.seed"),
        ("/does-not-exist/issuer.seed", "/keys/../issuer.seed"),
        ("/does-not-exist/issuer.seed", "/keys//issuer.seed"),
        ("/does-not-exist/issuer.seed", "/"),
        ("owner_uid = 840", "owner_uid = 4294967295"),
        (
            "maximum_lifetime_seconds = 300",
            "maximum_lifetime_seconds = 0",
        ),
        (
            "lifetime_margin_seconds = 10",
            "lifetime_margin_seconds = 301",
        ),
        ("issuer = \"ci\"", "issuer = \"\""),
        ("key_id = \"initial\"", "key_id = \"\""),
    ] {
        assert!(
            Config::parse(&valid.replace(before, after)).is_err(),
            "accepted {before} -> {after}"
        );
    }
    assert!(Config::parse(&(valid.clone() + "inline_seed = 'not-accepted'\n")).is_err());
    let duplicate = valid
        .split_once("[static_workload_issuers.ci]")
        .ok_or("missing fixture issuer table")?
        .1;
    assert!(
        Config::parse(&format!(
            "{valid}\n[static_workload_issuers.alias]{duplicate}"
        ))
        .is_err()
    );
    Ok(())
}

#[test]
fn role_and_name_checks_precede_private_signing_file_access() -> TestResult {
    let source = configuration(Path::new("/does-not-exist/issuer.seed"), 840);
    let config = Config::parse(&source)?;
    assert!(matches!(
        config.open_static_workload_issuer("missing", Role::Serve),
        Err(IssuerOpenError::MissingIssuer)
    ));
    for role in Role::ALL.into_iter().filter(|role| *role != Role::Serve) {
        assert!(matches!(
            config.open_static_workload_issuer("ci", role),
            Err(IssuerOpenError::Role(_))
        ));
        let configured =
            Config::parse(&source.replace("role = \"serve\"", &format!("role = \"{role}\"")))?;
        assert!(
            matches!(configured.open_static_workload_issuer("ci", role), Err(IssuerOpenError::WrongRole(actual)) if actual == role)
        );
    }
    assert!(matches!(
        config.open_static_workload_issuer("ci", Role::Serve),
        Err(IssuerOpenError::Issuer(MintError::Io(_)))
    ));
    Ok(())
}

#[tokio::test]
async fn configured_private_file_mints_bounded_ci_tokens_and_rejects_bad_authority() -> TestResult {
    let entropy = TokioLocalFs.random_bytes(16).await?;
    let suffix: String = entropy.iter().map(|byte| format!("{byte:02x}")).collect();
    let directory = std::env::temp_dir().join(format!("terrane-configured-issuer-{suffix}"));
    fs::create_dir(&directory)?;
    let cleanup = Directory(directory.clone());
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
    let key = directory.join("issuer.seed");
    fs::write(&key, SEED)?;
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600))?;
    let owner = fs::metadata(&key)?.uid();
    let source = configuration(&key, owner);
    let config = Config::parse(&source)?;
    let issuer = config.open_static_workload_issuer("ci", Role::Serve)?;
    let now = TokioClock.now().duration_since(UNIX_EPOCH)?.as_secs();
    let claims = WorkloadClaims::ci_change(
        "ci".into(),
        "run-123".into(),
        NonZeroU64::new(123).ok_or("zero change")?,
        now + 60,
    )?;
    let credential = issuer.mint(&TokioLocalFs, &TokioClock, claims).await?;
    let token = Token::decode(credential.token())?;
    let verified_at = TokioClock.now().duration_since(UNIX_EPOCH)?.as_secs();
    let verified = token.verify(&[issuer.policy().key().clone()], verified_at)?;

    assert_eq!(verified.authority().issuer, "ci");
    assert_eq!(verified.authority().kind, PrincipalKind::Workload);
    assert_eq!(verified.authority().workload.as_deref(), Some("run-123"));
    assert_eq!(verified.authority().not_after, now + 70);
    assert_eq!(verified.authority().grants.len(), 2);
    assert_eq!(fs::read(&key)?, SEED);

    let incorrect_owner = Config::parse(&source.replace(
        &format!("owner_uid = {owner}"),
        &format!("owner_uid = {}", owner ^ 1),
    ))?;
    assert!(matches!(
        incorrect_owner.open_static_workload_issuer("ci", Role::Serve),
        Err(IssuerOpenError::Issuer(MintError::Key))
    ));
    fs::write(&key, [32; 32])?;
    assert!(matches!(
        config.open_static_workload_issuer("ci", Role::Serve),
        Err(IssuerOpenError::Issuer(MintError::Key))
    ));
    fs::write(&key, SEED)?;
    fs::set_permissions(&key, fs::Permissions::from_mode(0o644))?;
    assert!(matches!(
        config.open_static_workload_issuer("ci", Role::Serve),
        Err(IssuerOpenError::Issuer(MintError::Key))
    ));

    drop(credential);
    drop(issuer);
    drop(cleanup);
    Ok(())
}

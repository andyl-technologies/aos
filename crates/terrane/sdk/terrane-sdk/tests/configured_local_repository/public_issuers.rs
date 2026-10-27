//! Exercises configured public trust and checked native key-file refusal.

use std::{
    os::unix::fs::{PermissionsExt, symlink},
    path::Path,
};

use terrane_format::{auth::IssuerKey, gc::Windows};
use terrane_sdk::{config::token::Tokens, role::Role};

use super::{Config, Fixture, LocalOpenError, OLD, TestResult, TokioClock, TokioLocalFs};

fn record(key: &IssuerKey) -> String {
    let public_key: String = key
        .public_key
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let retirement = key
        .retirement
        .map(|value| format!("retirement = {value}\n"))
        .unwrap_or_default();
    format!(
        "version = 1\nissuer = {:?}\nkey_id = {:?}\npublic_key = {public_key:?}\n{retirement}",
        key.issuer, key.key_id
    )
}

fn tokens(path: &Path) -> Tokens {
    Tokens {
        issuer_public_keys: vec![format!("file:{}", path.display())],
        host_token: Some("file:/missing-host-token".into()),
    }
}

fn configuration(fixture: &Fixture, keys: &[&Path]) -> Result<Config, Box<dyn std::error::Error>> {
    let source = super::configuration(fixture);
    let (_, local) = source
        .split_once("[local_repository]")
        .ok_or("missing local policy")?;
    let locators: Vec<_> = keys
        .iter()
        .map(|path| format!("file:{}", path.display()))
        .collect();
    Ok(Config::parse(&format!(
        "store = \"bucket(file://{})\"\n[tokens]\nissuer_public_keys = {locators:?}\nhost_token = \"file:/missing-host-token\"\n[local_repository]{local}",
        fixture.location.bucket.display()
    ))?)
}

#[tokio::test]
async fn configured_gc_reopens_public_keys_without_private_authority() -> TestResult {
    let fixture = Fixture::new().await?;
    let commit = fixture.commit_bytes(OLD).await?;
    let original = fixture.authority.issuer_key().clone();
    let path = fixture.parent.join("current.pub");
    std::fs::write(&path, record(&original))?;
    let config = configuration(&fixture, &[&path])?;

    for name in ["issuer.seed", "terminal.seed", "token.cbor"] {
        std::fs::remove_file(fixture.location.authority.join(name))?;
    }

    let reopened = config
        .open_local_maintenance(Role::Gc, TokioLocalFs, TokioClock)
        .await?;
    let collection = reopened
        .start_local_collection(
            "configured-maintenance".into(),
            1_000,
            1,
            Windows::new(30, 60, 60, 90)?,
        )
        .await?;

    assert!(
        collection
            .roots()
            .roots
            .iter()
            .any(|root| root.commit == commit)
    );
    assert_eq!(reopened.chunk_profile(), fixture.repository.chunk_profile());
    for name in ["issuer.seed", "terminal.seed", "token.cbor"] {
        assert!(!fixture.location.authority.join(name).exists());
    }
    assert!(!Path::new("/missing-host-token").exists());
    Ok(())
}

#[tokio::test]
async fn configured_gc_checks_role_and_store_before_public_key_io() -> TestResult {
    let fixture = Fixture::new().await?;
    let missing = fixture.parent.join("missing.pub");
    let config = configuration(&fixture, &[&missing])?;
    for role in Role::ALL.into_iter().filter(|role| *role != Role::Gc) {
        assert!(matches!(
            config.open_local_maintenance(role, TokioLocalFs, TokioClock).await,
            Err(LocalOpenError::WrongRole(actual)) if actual == role
        ));
    }

    let remote = Config::parse("store = \"bucket(s3://example/root)\"")?;
    assert!(matches!(
        remote
            .open_local_maintenance(Role::Gc, TokioLocalFs, TokioClock)
            .await,
        Err(LocalOpenError::UnsupportedStore)
    ));
    assert!(matches!(
        config
            .open_local_maintenance(Role::Gc, TokioLocalFs, TokioClock)
            .await,
        Err(LocalOpenError::IssuerKeys(_))
    ));
    assert!(!missing.exists());
    Ok(())
}

#[tokio::test]
async fn public_issuer_files_reject_unsafe_and_ambiguous_trust() -> TestResult {
    let fixture = Fixture::new().await?;
    let key = fixture.authority.issuer_key().clone();
    let path = fixture.parent.join("issuer.pub");
    let valid = record(&key);
    std::fs::write(&path, &valid)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
    let mut trusted = tokens(&path);
    let loaded = trusted.load_issuer_keys(fixture.owner)?;
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].public_key, key.public_key);
    assert_eq!(loaded[0].key_id, key.key_id);

    let mut rotation = key.clone();
    rotation.key_id = "retired-rotation".into();
    rotation.retirement = Some(0);
    let rotation_path = fixture.parent.join("rotation.pub");
    std::fs::write(&rotation_path, record(&rotation))?;
    trusted
        .issuer_public_keys
        .insert(0, format!("file:{}", rotation_path.display()));
    let loaded = trusted.load_issuer_keys(fixture.owner)?;
    assert_eq!(loaded.len(), 2);
    assert_eq!(loaded[0].key_id, rotation.key_id);
    assert_eq!(loaded[0].retirement, Some(0));
    assert_eq!(loaded[1].key_id, key.key_id);
    trusted.issuer_public_keys.remove(0);

    for invalid in [
        valid.replace("version = 1", "version = 2"),
        valid.replace("version = 1", "version = -1"),
        valid.replace("version = 1\n", ""),
        valid.replace("issuer = \"local\"", "issuer = \"\""),
        format!("{valid}signing_seed = \"private-marker\"\n"),
        format!("{valid}retirement = -1\n"),
        "x".repeat(16 * 1024 + 1),
    ] {
        std::fs::write(&path, invalid)?;
        let error = trusted
            .load_issuer_keys(fixture.owner)
            .err()
            .ok_or("invalid key accepted")?;
        assert!(!error.to_string().contains("private-marker"));
    }
    std::fs::write(&path, [0xff])?;
    assert!(trusted.load_issuer_keys(fixture.owner).is_err());
    std::fs::write(&path, &valid)?;

    trusted
        .issuer_public_keys
        .push(trusted.issuer_public_keys[0].clone());
    assert!(trusted.load_issuer_keys(fixture.owner).is_err());
    trusted.issuer_public_keys.pop();
    let alias = fixture.parent.join("alias.pub");
    std::fs::hard_link(&path, &alias)?;
    assert!(trusted.load_issuer_keys(fixture.owner).is_err());
    std::fs::remove_file(&alias)?;
    symlink(&path, &alias)?;
    assert!(tokens(&alias).load_issuer_keys(fixture.owner).is_err());
    std::fs::remove_file(&alias)?;
    let directory_alias = fixture.parent.join("alias-directory");
    symlink(&fixture.parent, &directory_alias)?;
    assert!(
        tokens(&directory_alias.join("issuer.pub"))
            .load_issuer_keys(fixture.owner)
            .is_err()
    );

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o664))?;
    assert!(trusted.load_issuer_keys(fixture.owner).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
    std::fs::set_permissions(&fixture.parent, std::fs::Permissions::from_mode(0o777))?;
    assert!(trusted.load_issuer_keys(fixture.owner).is_err());
    std::fs::set_permissions(&fixture.parent, std::fs::Permissions::from_mode(0o700))?;

    let fifo = fixture.parent.join("fifo.pub");
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        &fifo,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )?;
    assert!(tokens(&fifo).load_issuer_keys(fixture.owner).is_err());
    Ok(())
}

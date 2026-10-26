//! Checks configured read-only serving against actual writable native backing.

use std::{
    collections::BTreeMap,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

use terrane_sdk::{config::Config, role::Role};

use super::*;

#[derive(Debug, Eq, PartialEq)]
struct BackingEntry {
    device: u64,
    inode: u64,
    mode: u32,
    owner: u32,
    group: u32,
    links: u64,
    modified: (i64, i64),
    changed: (i64, i64),
    bytes: Vec<u8>,
}

fn observe(root: &Path) -> Result<BTreeMap<PathBuf, BackingEntry>, TestError> {
    fn visit(path: &Path, rows: &mut BTreeMap<PathBuf, BackingEntry>) -> TestResult {
        let metadata = std::fs::symlink_metadata(path)?;
        assert!(!metadata.file_type().is_symlink());
        let bytes = if metadata.is_file() {
            std::fs::read(path)?
        } else {
            assert!(metadata.is_dir());
            for entry in std::fs::read_dir(path)? {
                visit(&entry?.path(), rows)?;
            }
            Vec::new()
        };
        rows.insert(
            path.to_path_buf(),
            BackingEntry {
                device: metadata.dev(),
                inode: metadata.ino(),
                mode: metadata.mode(),
                owner: metadata.uid(),
                group: metadata.gid(),
                links: metadata.nlink(),
                // Reading may change atime. These timestamps also detect
                // identical-byte rewrites and transient probe entries.
                modified: (metadata.mtime(), metadata.mtime_nsec()),
                changed: (metadata.ctime(), metadata.ctime_nsec()),
                bytes,
            },
        );
        Ok(())
    }

    let mut rows = BTreeMap::new();
    visit(root, &mut rows)?;
    Ok(rows)
}

fn configuration(fixture: &Fixture) -> Result<Config, TestError> {
    // Bootstrap trust describes the existing repository. Serve's read-only
    // backend must refuse writes even with that original full owner policy.
    Ok(Config::parse(&format!(
        r#"role = "serve"
store = "bucket(file://{})"
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
        fixture.location.authority.display(),
        fixture.owner,
    ))?)
}

#[tokio::test]
async fn configured_native_serve_reads_preserve_backing_and_observe_publication() -> TestResult {
    let fixture = Fixture::new().await?;
    let first = fixture.commit_bytes(OLD).await?;
    let config = configuration(&fixture)?;
    let token = attenuated(
        &fixture,
        Attenuation {
            grants: Some(vec![Grant::new(MAIN.into(), Verbs::new(1)?)?]),
            caveats: vec![Caveat::Surface("sdk".into())],
            ..Default::default()
        },
    )?;
    let before = observe(&fixture.parent)?;

    let repository = Arc::new(
        config
            .open_local_repository(Role::Serve, TokioLocalFs, TokioClock)
            .await?,
    );
    // Even the independent writer's broad token cannot author through Serve.
    assert!(
        repository
            .begin(MAIN, fixture.authority.token(), "sdk")
            .await
            .is_err()
    );
    let service = LocalRefService::new(repository.clone(), limits()?).await?;
    let running = Running::start(Arc::new(service), &fixture, true).await?;
    let received = get_ref(
        &running.client,
        request(MAIN),
        options(&token)?,
        RefCodec::new(4 * 1024 * 1024)?,
    )
    .await?;
    let initial = received
        .value
        .ok_or("missing read-only native head")?
        .verify(&first, "cdc-1m")?;
    assert_eq!(
        Some(initial),
        fixture.repository.ref_head(MAIN, &token, "sdk").await?
    );
    assert_eq!(observe(&fixture.parent)?, before);

    let second = fixture.commit_bytes(NEW).await?;
    assert_ne!(first, second);
    let published = observe(&fixture.parent)?;
    let received = get_ref(
        &running.client,
        request(MAIN),
        options(&token)?,
        RefCodec::new(4 * 1024 * 1024)?,
    )
    .await?;
    let updated = received
        .value
        .ok_or("missing later read-only native head")?
        .verify(&second, "cdc-1m")?;
    assert_eq!(
        Some(updated),
        fixture.repository.ref_head(MAIN, &token, "sdk").await?
    );
    assert_eq!(
        repository
            .read_file(&fixture::fixed(second), b"file", &token, "sdk")
            .await?,
        (second, NEW.to_vec())
    );
    assert_eq!(
        repository
            .read_file(&fixture::fixed(first), b"file", &token, "sdk")
            .await?,
        (first, OLD.to_vec())
    );
    running.stop().await?;
    drop(repository);
    assert_eq!(observe(&fixture.parent)?, published);
    Ok(())
}

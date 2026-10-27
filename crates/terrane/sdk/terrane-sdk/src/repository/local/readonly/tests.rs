//! Checks effect-free native reopening against actual writable private backing.

use super::*;
use crate::store::{CapabilityReport, RefCapability, RefStore, TokioClock, TokioLocalFs};
use std::{collections::BTreeMap, os::unix::fs::PermissionsExt, path::Path, time::Duration};
use terrane_format::{
    auth::{Authority, Grant, Verbs},
    refs::RefRecord,
    surface::View,
};

type NativeRepository =
    Repository<FileBucket<TokioLocalFs, TokioClock, MetadataValidator>, TokioClock, TokioLocalFs>;
type Observation = BTreeMap<PathBuf, ObservedEntry>;

#[derive(Debug, Eq, PartialEq)]
struct ObservedEntry {
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

struct Fixture {
    parent: PathBuf,
    location: LocalRepositoryLocation,
    identity: LocalAuthorityIdentity,
    authority: LocalAuthority,
    session: WriterSession,
    head: RefRecord,
}

fn policy() -> LocalRepositoryPolicy {
    LocalRepositoryPolicy {
        store_name: "local".into(),
        domain: "private:owner".into(),
        default_private_domain: "private:owner".into(),
        acl: vec![("owner".into(), 31)],
        locality: Locality::default(),
        timing: CommitTiming::new(
            Duration::from_secs(30),
            Duration::from_secs(60),
            Duration::from_secs(10),
        )
        .unwrap(),
        policy_authority: None,
        bootstrap_properties: Vec::new(),
    }
}

async fn fixture() -> Fixture {
    let fs = TokioLocalFs;
    let entropy = fs.random_bytes(16).await.unwrap();
    let suffix: String = entropy.iter().map(|byte| format!("{byte:02x}")).collect();
    let parent = std::env::temp_dir().join(format!("terrane-native-ro-{suffix}"));
    fs.create_dir_new(&parent).await.unwrap();
    fs.set_permissions(&parent, std::fs::Permissions::from_mode(0o700))
        .await
        .unwrap();
    let owner_uid = fs.metadata(&parent).await.unwrap().uid();
    let location = LocalRepositoryLocation {
        bucket: parent.join("bucket"),
        authority: parent.join("authority"),
    };
    let identity = LocalAuthorityIdentity {
        issuer: "local".into(),
        key_id: "initial".into(),
        owner_uid,
    };
    let (repository, authority) = NativeRepository::initialize_local(
        &location,
        LocalAuthorityParameters {
            owner_uid,
            authority: Authority {
                issuer: identity.issuer.clone(),
                key_id: identity.key_id.clone(),
                subject: "owner".into(),
                kind: PrincipalKind::Human,
                groups: Vec::new(),
                not_after: u64::MAX,
                not_before: None,
                token_id: entropy.try_into().unwrap(),
                grants: vec![Grant::new("refs/**".into(), Verbs::new(31).unwrap()).unwrap()],
                workload: None,
            },
        },
        policy(),
        "refs/heads/_/main",
        fs,
        TokioClock,
    )
    .await
    .unwrap();
    let source = parent.join("source");
    fs.create_dir_new(&source).await.unwrap();
    fs.write_new(&source.join("file"), b"original native read-only payload")
        .await
        .unwrap();
    let mut session = repository
        .begin("refs/heads/_/main", authority.token(), "sdk")
        .await
        .unwrap();
    let head = repository
        .commit_directory(
            &mut session,
            &source,
            &authority,
            CommitMetadata {
                message: "Native read-only fixture".into(),
                process: "native-regression".into(),
                source: CommitSource::Built,
            },
        )
        .await
        .unwrap();
    drop(repository);
    Fixture {
        parent,
        location,
        identity,
        authority,
        session,
        head,
    }
}

fn observe(root: &Path) -> Observation {
    fn visit(path: &Path, rows: &mut Observation) {
        let metadata = std::fs::symlink_metadata(path).unwrap();
        assert!(!metadata.file_type().is_symlink());
        let bytes = if metadata.is_file() {
            std::fs::read(path).unwrap()
        } else {
            assert!(metadata.is_dir());
            for entry in std::fs::read_dir(path).unwrap() {
                visit(&entry.unwrap().path(), rows);
            }
            Vec::new()
        };
        rows.insert(
            path.to_path_buf(),
            ObservedEntry {
                device: metadata.dev(),
                inode: metadata.ino(),
                mode: metadata.mode(),
                owner: metadata.uid(),
                group: metadata.gid(),
                links: metadata.nlink(),
                // Reads may update atime. Retaining both other timestamps also
                // detects identical-byte rewrites and transient probe entries.
                modified: (metadata.mtime(), metadata.mtime_nsec()),
                changed: (metadata.ctime(), metadata.ctime_nsec()),
                bytes,
            },
        );
    }
    let mut rows = BTreeMap::new();
    visit(root, &mut rows);
    rows
}

async fn reopen(fixture: &Fixture) -> Result<(NativeRepository, LocalAuthority), Error> {
    NativeRepository::open_local_read_only(
        &fixture.location,
        &fixture.identity,
        policy(),
        "refs/heads/_/main",
        TokioLocalFs,
        TokioClock,
    )
    .await
}

#[tokio::test]
async fn native_read_only_reopen_keeps_writable_backing_and_denies_mutations() {
    let mut fixture = fixture().await;
    let projection = fixture.location.bucket.join("CAPABILITIES");
    std::fs::write(&projection, b"damaged untrusted projection").unwrap();
    assert!(std::fs::metadata(&projection).unwrap().permissions().mode() & 0o200 != 0);
    let before = observe(&fixture.parent);

    let (repository, authority) = reopen(&fixture).await.unwrap();
    assert!(repository.local_retention.is_none());
    assert!(repository.local_backend_root.is_none());
    assert_eq!(
        repository.coordinator.store().capabilities().refs,
        RefCapability::None
    );
    assert_eq!(
        repository
            .coordinator
            .store()
            .ref_get("refs/heads/_/main")
            .await
            .unwrap(),
        Some(fixture.head.clone())
    );
    let (commit, bytes) = repository
        .read_file(
            &View::parse("refs/heads/_/main").unwrap(),
            b"file",
            authority.token(),
            "sdk",
        )
        .await
        .unwrap();
    assert_eq!(commit, fixture.head.commit);
    assert_eq!(bytes, b"original native read-only payload");
    assert_eq!(observe(&fixture.parent), before);

    assert!(
        repository
            .coordinator
            .store()
            .ref_cas("refs/heads/_/main", Some(&fixture.head), &fixture.head)
            .await
            .is_err()
    );
    assert!(
        repository
            .begin("refs/heads/_/main", authority.token(), "sdk")
            .await
            .is_err()
    );
    assert!(
        repository
            .commit_directory(
                &mut fixture.session,
                &fixture.parent.join("source"),
                &fixture.authority,
                CommitMetadata {
                    message: "Must never publish".into(),
                    process: "native-regression".into(),
                    source: CommitSource::Built,
                },
            )
            .await
            .is_err()
    );
    assert!(
        repository
            .rotate_disclosure_key("refs/heads/_/main", authority.token(), "sdk")
            .await
            .is_err()
    );
    assert!(
        repository
            .requalify_fork_source("refs/heads/_/main", authority.token(), "sdk")
            .await
            .is_err()
    );
    assert_eq!(observe(&fixture.parent), before);

    drop(repository);
    std::fs::remove_dir_all(&fixture.parent).unwrap();
}

#[tokio::test]
async fn native_read_only_reopen_refuses_missing_registration_without_repair() {
    let fixture = fixture().await;
    std::fs::remove_file(fixture.location.authority.join("registration.cbor")).unwrap();
    let before = observe(&fixture.parent);

    assert!(reopen(&fixture).await.is_err());
    assert_eq!(observe(&fixture.parent), before);

    std::fs::remove_dir_all(&fixture.parent).unwrap();
}

#[tokio::test]
async fn native_read_only_reopen_refuses_missing_coordination_without_repair() {
    let fixture = fixture().await;
    std::fs::remove_file(fixture.location.authority.join("retention.lock")).unwrap();
    let before = observe(&fixture.parent);

    assert!(reopen(&fixture).await.is_err());
    assert_eq!(observe(&fixture.parent), before);

    std::fs::remove_dir_all(&fixture.parent).unwrap();
}

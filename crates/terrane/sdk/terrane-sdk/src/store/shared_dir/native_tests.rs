//! Exercises concrete host reads and scoped routing against ordinary disk files.
//!
//! Guard-issued test decisions isolate the routing contract. They do not stand
//! in for end-to-end current-authority verification by repository entry points.

mod residence_composition;

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use terrane_format::auth::Verb;
use terrane_format::chunking::ChunkProfile;
use terrane_format::identity::{Identity, IdentityKind, TERRANE_V1};

use super::{SharedDir, SharedDirRoutes};
use crate::domain::{DomainAccess, DomainBinding};
use crate::host::cache::{DomainHostLayout, HostReadLimits};
use crate::repository::MetadataValidator;
use crate::store::{
    ByteRange, CapabilityReport, ChunkPosition, ChunkUpload, ContentStore, ContentUpload,
    MetaUpload, RefCapability, StoreErrorKind, TokioLocalFs,
};

type Directory = SharedDir<TokioLocalFs, MetadataValidator>;

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
    profile: ChunkProfile,
}

impl Fixture {
    fn new() -> Self {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "terrane-shared-dir-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();

        Self {
            root,
            profile: ChunkProfile::cdc_1m([7; 32]),
        }
    }

    fn domain_root(&self, name: &str) -> PathBuf {
        let path = self.root.join(name);
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn layout(&self, root: PathBuf, domain: &str) -> DomainHostLayout {
        DomainHostLayout::new(root, binding(domain), self.profile.clone()).unwrap()
    }

    async fn open(&self, root: PathBuf, domain: &str) -> Directory {
        Directory::open_existing(
            self.layout(root, domain),
            TokioLocalFs,
            MetadataValidator::new(self.profile.clone()),
        )
        .await
        .unwrap()
    }

    fn chunk(&self, root: &Path, plaintext: &[u8]) -> (Identity, Vec<u8>, PathBuf) {
        let identity = TERRANE_V1
            .calculate(IdentityKind::Chunk, plaintext)
            .unwrap();
        let hash: String = identity
            .digest()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let shard = root.join("chunks").join(&hash[..2]);
        fs::create_dir_all(&shard).unwrap();
        let path = shard.join(format!("{hash}.0"));
        let mut encoded = vec![0];
        encoded.extend_from_slice(plaintext);
        fs::write(&path, &encoded).unwrap();

        (identity, encoded, path)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn binding(domain: &str) -> DomainBinding {
    DomainBinding {
        domain: domain.into(),
        reference: "refs/heads/main".into(),
        root: TERRANE_V1
            .calculate(IdentityKind::Node, b"bound root")
            .unwrap(),
        path: b"/".to_vec(),
    }
}

fn access(domain: &str, identities: &[Identity]) -> DomainAccess {
    DomainAccess::authorized(binding(domain), Verb::Read, "consumer".into(), [1; 16])
        .unwrap()
        .with_read_identities(identities.to_vec())
}

fn snapshot(root: &Path) -> BTreeMap<PathBuf, (u64, u64, u32, Vec<u8>)> {
    let mut entries = BTreeMap::new();
    let mut pending = vec![root.to_owned()];
    while let Some(path) = pending.pop() {
        let metadata = fs::symlink_metadata(&path).unwrap();
        let bytes = if metadata.is_file() {
            fs::read(&path).unwrap()
        } else {
            Vec::new()
        };
        entries.insert(
            path.strip_prefix(root).unwrap().to_owned(),
            (metadata.dev(), metadata.ino(), metadata.mode(), bytes),
        );
        if metadata.is_dir() {
            for entry in fs::read_dir(path).unwrap() {
                pending.push(entry.unwrap().path());
            }
        }
    }

    entries
}

#[tokio::test]
async fn existing_directory_reads_and_rejected_puts_leave_bytes_and_names_unchanged() {
    let fixture = Fixture::new();
    let root = fixture.domain_root("tenant-a");
    let (identity, encoded, _) = fixture.chunk(&root, b"existing host bytes");
    let absent = TERRANE_V1
        .calculate(IdentityKind::Chunk, b"absent")
        .unwrap();
    let before = snapshot(&fixture.root);

    let directory = fixture.open(root, "tenant:a").await;
    assert_eq!(directory.capabilities().refs, RefCapability::None);
    assert!(!directory.capabilities().presign);
    assert!(!directory.capabilities().sealed);
    assert_eq!(directory.get(&identity, None).await.unwrap(), encoded);
    assert_eq!(
        directory
            .has(&[identity.clone(), absent, identity.clone()])
            .await
            .unwrap(),
        [true, false, true]
    );
    let error = directory
        .put(ContentUpload::Chunk(ChunkUpload {
            encoded: &encoded,
            identity: &identity,
            declared_plaintext_len: encoded.len() - 1,
            position: ChunkPosition::Final,
            profile: &fixture.profile,
        }))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), &StoreErrorKind::ReadOnly);

    for bytes in [b"existing host bytes".as_slice(), b"new content".as_slice()] {
        let upload = MetaUpload::new(IdentityKind::Policy, bytes).unwrap();
        let error = directory
            .put(ContentUpload::Meta(upload))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), &StoreErrorKind::ReadOnly);
    }

    assert_eq!(snapshot(&fixture.root), before);
}

#[tokio::test]
async fn corrupt_existing_chunk_is_never_returned_or_repaired() {
    let fixture = Fixture::new();
    let root = fixture.domain_root("public");
    let (identity, _, path) = fixture.chunk(&root, b"original verified plaintext");
    let directory = fixture.open(root, "public").await;
    fs::write(path, b"\0changed plaintext").unwrap();
    let before = snapshot(&fixture.root);

    let error = directory.get(&identity, None).await.unwrap_err();
    assert!(matches!(error.kind(), StoreErrorKind::Corrupt(_)));
    assert!(directory.has(&[identity]).await.is_err());

    assert_eq!(snapshot(&fixture.root), before);
}

#[tokio::test]
async fn explicit_read_budget_returns_capacity_without_mutating_valid_content() {
    let fixture = Fixture::new();
    let root = fixture.domain_root("public");
    let (identity, _, _) = fixture.chunk(&root, b"valid content beyond a tiny read budget");
    let before = snapshot(&fixture.root);
    let directory = Directory::open_existing_with_limits(
        fixture.layout(root, "public"),
        TokioLocalFs,
        MetadataValidator::new(fixture.profile.clone()),
        HostReadLimits {
            max_allocation_bytes: 1,
        },
    )
    .await
    .unwrap();

    let error = directory.get(&identity, None).await.unwrap_err();

    assert_eq!(error.kind(), &StoreErrorKind::Capacity);
    assert_eq!(snapshot(&fixture.root), before);
}

#[tokio::test]
async fn domain_routes_never_probe_another_directory_or_unreachable_identity() {
    let fixture = Fixture::new();
    let first_root = fixture.domain_root("first");
    let second_root = fixture.domain_root("second");
    let (identity, encoded, _) = fixture.chunk(&first_root, b"tenant a only");
    let first = fixture.open(first_root, "tenant:a").await;
    let second = fixture.open(second_root, "tenant:b").await;
    let routes = SharedDirRoutes::new(vec![first, second]).unwrap();
    let readable = access("tenant:a", &[identity.clone()]);
    let other = access("tenant:b", &[identity.clone()]);

    assert_eq!(
        routes.get(&readable, &identity, None).await.unwrap(),
        encoded
    );
    assert_eq!(
        routes.has(&other, &[identity.clone()]).await.unwrap(),
        [false]
    );
    assert!(matches!(
        routes
            .get(&other, &identity, None)
            .await
            .unwrap_err()
            .kind(),
        StoreErrorKind::Absent(_)
    ));
    assert_eq!(
        routes
            .has(&access("tenant:a", &[]), &[identity.clone()])
            .await
            .unwrap(),
        [false]
    );

    let mut changed = readable.binding().clone();
    changed.domain = "tenant:unknown".into();
    let wrong_root = DomainAccess::authorized(changed, Verb::Read, "consumer".into(), [1; 16])
        .unwrap()
        .with_read_identities(vec![identity.clone()]);
    assert!(matches!(
        routes
            .get(&wrong_root, &identity, None)
            .await
            .unwrap_err()
            .kind(),
        StoreErrorKind::Denied { .. }
    ));
}

#[tokio::test]
async fn same_domain_snapshots_read_one_existing_inode_without_extending_reachability() {
    let fixture = Fixture::new();
    let root = fixture.domain_root("shared-tenant");
    let (identity, encoded, path) = fixture.chunk(&root, b"shared same-domain source");
    let before = snapshot(&fixture.root);
    let first_inode = fs::File::open(&path).unwrap().metadata().unwrap();
    let directory = fixture.open(root.clone(), "tenant:a").await;
    let routes = SharedDirRoutes::new(vec![directory]).unwrap();
    let first = access("tenant:a", &[identity.clone()]);
    let mut second_binding = binding("tenant:a");
    second_binding.reference = "refs/heads/another-consumer".into();
    second_binding.root = TERRANE_V1
        .calculate(IdentityKind::Node, b"another snapshot")
        .unwrap();
    second_binding.path = b"/another-root".to_vec();
    let second = DomainAccess::authorized(
        second_binding.clone(),
        Verb::Read,
        "another-consumer".into(),
        [2; 16],
    )
    .unwrap()
    .with_read_identities(vec![identity.clone()]);
    let unreachable = DomainAccess::authorized(
        second_binding,
        Verb::Read,
        "another-consumer".into(),
        [2; 16],
    )
    .unwrap();

    assert_eq!(routes.get(&first, &identity, None).await.unwrap(), encoded);
    assert_eq!(routes.get(&second, &identity, None).await.unwrap(), encoded);
    assert_eq!(
        routes.has(&unreachable, &[identity.clone()]).await.unwrap(),
        [false]
    );
    assert!(matches!(
        routes
            .get(&unreachable, &identity, None)
            .await
            .unwrap_err()
            .kind(),
        StoreErrorKind::Denied { .. }
    ));

    let second_inode = fs::File::open(path).unwrap().metadata().unwrap();
    assert_eq!(
        (first_inode.dev(), first_inode.ino()),
        (second_inode.dev(), second_inode.ino())
    );
    assert_eq!(snapshot(&fixture.root), before);
}

#[tokio::test]
async fn shared_private_open_refuses_before_touching_missing_root() {
    let fixture = Fixture::new();
    let missing = fixture.root.join("must-remain-absent");
    let layout = fixture.layout(missing.clone(), "private:consumer");

    let error = Directory::open_existing(
        layout,
        TokioLocalFs,
        MetadataValidator::new(fixture.profile.clone()),
    )
    .await
    .err()
    .unwrap();

    assert_eq!(error.kind(), &StoreErrorKind::Unsupported);
    assert!(!missing.exists());
}

#[tokio::test]
async fn exact_encoded_ranges_verify_the_complete_chunk_before_returning_bytes() {
    let fixture = Fixture::new();
    let root = fixture.domain_root("public");
    let (identity, encoded, path) = fixture.chunk(&root, b"whole chunk verification");
    let directory = fixture.open(root, "public").await;
    let range = ByteRange {
        start: 1,
        length: 5,
    };

    assert_eq!(
        directory.get(&identity, Some(range)).await.unwrap(),
        encoded[1..6]
    );
    let out_of_bounds = ByteRange {
        start: encoded.len() as u64,
        length: 1,
    };
    assert!(matches!(
        directory
            .get(&identity, Some(out_of_bounds))
            .await
            .unwrap_err()
            .kind(),
        StoreErrorKind::Invalid(crate::store::InvalidReason::Range(_))
    ));

    let mut corrupt = encoded;
    *corrupt.last_mut().unwrap() ^= 1;
    fs::write(path, corrupt).unwrap();

    assert!(matches!(
        directory
            .get(&identity, Some(range))
            .await
            .unwrap_err()
            .kind(),
        StoreErrorKind::Corrupt(_)
    ));
}

#[tokio::test]
async fn routes_refuse_two_domain_labels_for_the_same_directory() {
    let fixture = Fixture::new();
    let root = fixture.domain_root("one-directory");
    let first = fixture.open(root.clone(), "tenant:a").await;
    let second = fixture.open(root, "tenant:b").await;

    assert!(SharedDirRoutes::new(vec![first, second]).is_err());
}

#[tokio::test]
async fn directory_and_body_symlinks_cannot_cross_domain_boundaries() {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new();
    let first_root = fixture.domain_root("first");
    let second_root = fixture.domain_root("second");
    let (identity, _, target) = fixture.chunk(&first_root, b"other domain");
    let (_, _, link) = fixture.chunk(&second_root, b"other domain");
    fs::remove_file(&link).unwrap();
    symlink(target, &link).unwrap();
    let directory = fixture.open(second_root, "tenant:b").await;

    assert!(directory.get(&identity, None).await.is_err());
    assert!(directory.has(&[identity]).await.is_err());

    let root_link = fixture.root.join("root-link");
    symlink(first_root, &root_link).unwrap();
    assert!(
        Directory::open_existing(
            fixture.layout(root_link, "tenant:b"),
            TokioLocalFs,
            MetadataValidator::new(fixture.profile.clone()),
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn manifest_get_returns_canonical_metadata_instead_of_sealed_plaintext() {
    use crate::pack::{EntryKind, PackClass, PackId, PackWriter};
    use terrane_format::manifest::{ChunkRef, Manifest};

    let fixture = Fixture::new();
    let root = fixture.domain_root("public");
    let plaintext = vec![b'x'; fixture.profile.minimum() + 1];
    let (chunk, _, _) = fixture.chunk(&root, &plaintext);
    let manifest = Manifest {
        size: plaintext.len() as u64,
        chunks: vec![ChunkRef {
            digest: chunk.digest().try_into().unwrap(),
            length: plaintext.len() as u64,
        }],
        hashes: BTreeMap::from([(
            "blake3".into(),
            blake3::hash(&plaintext).as_bytes().to_vec(),
        )]),
        media_type: None,
    }
    .encode(&fixture.profile)
    .unwrap();
    let identity = TERRANE_V1
        .calculate(IdentityKind::Manifest, &manifest)
        .unwrap();
    let pack_id = PackId::generate(&TokioLocalFs).await.unwrap();
    let mut writer = PackWriter::new(pack_id, PackClass::Meta, false);
    writer.append_raw(EntryKind::Manifest, &manifest).unwrap();
    let pack = writer.seal().unwrap();
    let pack_path = root.join(pack_id.pack_key());
    fs::create_dir_all(pack_path.parent().unwrap()).unwrap();
    fs::write(pack_path, pack.bytes()).unwrap();
    fs::write(root.join(pack_id.index_key()), pack.index_object()).unwrap();
    let object_hash: String = identity
        .digest()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let sealed_path = root
        .join("sealed")
        .join(&object_hash[..2])
        .join(&object_hash);
    fs::create_dir_all(sealed_path.parent().unwrap()).unwrap();
    fs::write(sealed_path, plaintext).unwrap();
    let before = snapshot(&fixture.root);

    let directory = fixture.open(root, "public").await;
    assert_eq!(directory.get(&identity, None).await.unwrap(), manifest);
    assert_eq!(snapshot(&fixture.root), before);
}

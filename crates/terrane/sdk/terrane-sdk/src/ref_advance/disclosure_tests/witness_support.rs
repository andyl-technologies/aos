//! Constructs signed native proposals and reopens their genuine retained factory.

use super::*;
use crate::ref_advance::CommitRequest;
use crate::repository::local_authority::LocalAuthority;
use crate::repository::{MetadataValidator, Repository};
use crate::store::LocalFs;
use std::collections::BTreeMap;
use std::ops::Deref;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use terrane_format::identity::Digest;

type IndexCoordinator =
    Coordinator<FileBucket<TokioLocalFs, TokioClock, MetadataValidator>, TokioClock, TokioLocalFs>;

/// Retains the actual native repository with its production metadata validator.
pub(crate) struct IndexFixture {
    repository: Repository<
        FileBucket<TokioLocalFs, TokioClock, MetadataValidator>,
        TokioClock,
        TokioLocalFs,
    >,
}

impl Deref for IndexFixture {
    type Target = IndexCoordinator;

    fn deref(&self) -> &Self::Target {
        self.repository.coordinator()
    }
}

impl IndexFixture {
    /// Admits and retains the proposal through the genuine repository commit path.
    ///
    /// # Errors
    /// Preserves repository, coordinator and original typed storage failures.
    pub(crate) async fn advance(
        &self,
        session: &mut crate::ref_advance::WriterSession,
        proposal: CommitRequest,
    ) -> Result<terrane_format::refs::RefRecord, crate::repository::Error> {
        self.repository.commit_request(session, proposal).await
    }
}

/// Reopens the same protected native destination with the registered production schemas.
///
/// Shared fixture Validator only decodes Ordinary Nodes; production
/// MetadataValidator also recognizes Index Nodes, without authenticating them.
/// This changes no root, profile, issuer, registration or retained control.
///
/// # Panics
/// Panics if the real destination bucket or protected reopen factory refuses.
pub(crate) async fn production_metadata(
    destination: NativeFixture<TokioLocalFs>,
    authority: &LocalAuthority,
) -> IndexFixture {
    let root = destination.store().root().to_owned();
    let policy = destination.guard().config().clone();
    drop(destination);
    index_open(root, policy, authority).await
}

/// Reopens all retained Index fixture evidence using the same actual native factory.
///
/// # Panics
/// Panics if the original controls or physical destination binding no longer verify.
pub(crate) async fn reopen_index(
    destination: IndexFixture,
    authority: &LocalAuthority,
) -> IndexFixture {
    let root = destination.store().root().to_owned();
    let policy = destination.guard().config().clone();
    drop(destination);
    index_open(root, policy, authority).await
}

async fn index_open(
    root: PathBuf,
    policy: crate::guard::GuardConfig,
    authority: &LocalAuthority,
) -> IndexFixture {
    let validator = MetadataValidator::new(policy.chunk_profile.as_ref().clone());
    let bucket = FileBucket::open(
        config(root.clone()).await,
        TokioLocalFs,
        TokioClock,
        validator,
    )
    .await
    .unwrap();
    let owner = TokioLocalFs.metadata(&root).await.unwrap().uid();
    let namespace = crate::domain::DomainNamespace {
        root: root.clone(),
        domain: policy.storage_domain.clone(),
    };
    let coordinator = Coordinator::new(
        Guard::new(
            bucket,
            TokioClock,
            vec![authority.issuer_key().clone()],
            policy,
        ),
        CommitTiming::new(
            Duration::from_secs(30),
            Duration::from_secs(60),
            Duration::from_secs(10),
        )
        .unwrap(),
        TokioLocalFs,
    );
    let repository =
        Repository::reopen_native_retention(coordinator, &namespace, &control(&root), owner)
            .await
            .unwrap();
    IndexFixture { repository }
}

/// Extracts the original typed Store failure without inventing a mapped cause.
///
/// # Panics
/// Panics if the actual repository fails in a different phase than expected.
pub(super) fn storage_failure(error: crate::repository::Error) -> crate::store::StoreFailure {
    match error {
        crate::repository::Error::Store(error)
        | crate::repository::Error::Advance(crate::ref_advance::AdvanceError::Store(error)) => {
            error
        }
        error => panic!("expected precise native Store refusal, observed {error:?}"),
    }
}

/// Names the actual current policy reference used by these fixtures.
pub(super) const REFERENCE: &str = "refs/heads/_/main";

/// Uses the registered cdc-1m minimum without changing geometry.
pub(super) const MINIMUM: u64 = 262144;

/// Creates a plain file without copied attribute producer claims.
///
/// # Panics
/// Panics if the fixed v1 Chunk identity calculation refuses.
pub(super) fn file(plaintext: &[u8]) -> Entry<'static> {
    entry(EntryKind::File {
        mode: 0o644,
        size: plaintext.len() as u64,
        content: ContentRef::Inline(digest(IdentityKind::Chunk, plaintext)),
        link_id: None,
    })
}

/// Creates an entry with no attribute or provenance claims.
pub(super) fn entry(kind: EntryKind<'static>) -> Entry<'static> {
    Entry {
        kind,
        attrs: Vec::new(),
        attrs_present: false,
        xattrs: Vec::new(),
        xattrs_present: false,
        provenance: None,
    }
}

/// Calculates the offered immutable identity in the closed v1 profile.
///
/// # Panics
/// Panics if the selected fixture identity kind is unsupported.
pub(super) fn digest(kind: IdentityKind, bytes: &[u8]) -> Digest {
    TERRANE_V1
        .calculate(kind, bytes)
        .unwrap()
        .terrane_v1_digest()
        .unwrap()
}

/// Stages only the explicitly supplied reachable plaintexts and canonical tree.
///
/// # Panics
/// Panics if a fixture proposal or plaintext upload cannot be encoded.
pub(crate) fn proposal(
    authority: &LocalAuthority,
    parents: Vec<Digest>,
    tree: &Tree<'_>,
    plaintexts: &[&[u8]],
) -> CommitRequest {
    let mut staged = materialization::stage_tree(request(parents), tree);
    for plaintext in plaintexts {
        staged.uploads.extend(
            request_file(Vec::new(), plaintext)
                .uploads
                .into_iter()
                .filter(|upload| matches!(upload, StagedUpload::Chunk { .. })),
        );
    }
    let mut signed = authority.commit_request(staged.commit, "sdk".into());
    signed.uploads = staged.uploads;
    signed
}

/// Locates the actual fixture control sibling selected by the native factory.
///
/// # Panics
/// Panics if the supplied path has no final component.
pub(super) fn control(root: &std::path::Path) -> PathBuf {
    root.with_file_name(format!(
        "{}-original-control",
        root.file_name().unwrap().to_string_lossy()
    ))
}

/// Removes only the runtime source fixture and its original controls and credentials.
///
/// # Panics
/// Panics if deletion fails or an erased runtime fixture path remains.
pub(super) async fn erase_source(source: NativeFixture<TokioLocalFs>, credentials: PathBuf) {
    let root = source.store().root().to_owned();
    drop(source);
    erase_root(root, credentials).await;
}

/// Removes the genuine production-validator source and its physical signing controls.
///
/// # Panics
/// Panics if removal fails or an erased runtime source path remains.
pub(crate) async fn erase_index_source(source: IndexFixture, credentials: PathBuf) {
    let root = source.store().root().to_owned();
    drop(source);
    erase_root(root, credentials).await;
}

async fn erase_root(root: PathBuf, credentials: PathBuf) {
    for path in [control(&root), root, credentials] {
        tokio::fs::remove_dir_all(&path).await.unwrap();
        assert!(!path.exists());
    }
}

/// Reopens with actual destination controls and its independently configured issuer.
///
/// # Panics
/// Panics if bucket opening or protected native reopening refuses.
pub(super) async fn reopen(
    destination: NativeFixture<TokioLocalFs>,
    authority: &LocalAuthority,
) -> NativeFixture<TokioLocalFs> {
    let root = destination.store().root().to_owned();
    let policy = destination.guard().config().clone();
    drop(destination);
    let bucket = FileBucket::open(config(root).await, TokioLocalFs, TokioClock, Validator)
        .await
        .unwrap();
    NativeFixture::reopen(Coordinator::new(
        Guard::new(
            bucket,
            TokioClock,
            vec![authority.issuer_key().clone()],
            policy,
        ),
        CommitTiming::new(
            Duration::from_secs(30),
            Duration::from_secs(60),
            Duration::from_secs(10),
        )
        .unwrap(),
        TokioLocalFs,
    ))
    .await
}

/// Returns all offered immutable identities for exact before/after refusal checks.
///
/// # Panics
/// Panics if an offered fixture metadata identity cannot be calculated.
pub(super) fn offered(proposal: &CommitRequest) -> Vec<terrane_format::identity::Identity> {
    proposal
        .uploads
        .iter()
        .map(|upload| match upload {
            StagedUpload::Meta { kind, bytes } => TERRANE_V1.calculate(*kind, bytes).unwrap(),
            StagedUpload::Chunk { identity, .. } => identity.clone(),
        })
        .collect()
}

/// Records a complete persistent namespace entry independently of store membership.
#[derive(Debug, Eq, PartialEq)]
pub(super) struct PhysicalEntry {
    mode: u32,
    uid: u32,
    gid: u32,
    size: u64,
    modified: (i64, i64),
    changed: (i64, i64),
    bytes: Vec<u8>,
}

/// Snapshots every destination bucket/control entry, including unselected temporary files.
///
/// This is a before/after persistent-state oracle, not a syscall counter: a
/// transient create/remove entirely between observations is outside its scope.
/// Reads intentionally exclude atime, which inspection itself can update.
///
/// # Panics
/// Panics if the bucket root has no final component, a fixture entry cannot be
/// observed, or an entry has an unexpected special kind.
pub(super) async fn physical_snapshot(root: &std::path::Path) -> BTreeMap<PathBuf, PhysicalEntry> {
    let root = root.to_owned();
    snapshot_namespaces(vec![control(&root), root]).await
}

/// Snapshots only the original protected control namespace of the supplied bucket.
///
/// Includes every retained and temporary control entry, with the same physical
/// observations and transient-operation limits as [`physical_snapshot`].
///
/// # Panics
/// Panics if the bucket root has no final component, a control entry cannot be
/// observed, or an entry has an unexpected special kind.
pub(super) async fn control_snapshot(root: &std::path::Path) -> BTreeMap<PathBuf, PhysicalEntry> {
    snapshot_namespaces(vec![control(root)]).await
}

async fn snapshot_namespaces(mut pending: Vec<PathBuf>) -> BTreeMap<PathBuf, PhysicalEntry> {
    let mut entries = BTreeMap::new();
    while let Some(path) = pending.pop() {
        let metadata = tokio::fs::symlink_metadata(&path).await.unwrap();
        let bytes = if metadata.is_dir() {
            let mut directory = tokio::fs::read_dir(&path).await.unwrap();
            while let Some(child) = directory.next_entry().await.unwrap() {
                pending.push(child.path());
            }
            Vec::new()
        } else {
            assert!(
                metadata.is_file(),
                "unexpected fixture special entry: {path:?}"
            );
            tokio::fs::read(&path).await.unwrap()
        };
        entries.insert(
            path,
            PhysicalEntry {
                mode: metadata.mode(),
                uid: metadata.uid(),
                gid: metadata.gid(),
                size: metadata.size(),
                modified: (metadata.mtime(), metadata.mtime_nsec()),
                changed: (metadata.ctime(), metadata.ctime_nsec()),
                bytes,
            },
        );
    }
    entries
}

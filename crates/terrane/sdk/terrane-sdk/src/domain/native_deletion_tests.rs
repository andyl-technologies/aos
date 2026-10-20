//! Exercises actual signed route authority and native administrative destruction.
//!
//! Each fixture uses production local signing/retention, independently configured
//! physical namespaces and native filesystem oracles. No caller decisions,
//! collector witnesses or decoded records substitute for current authority.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "Isolated fixture setup and assertions intentionally panic."
)]

mod audit_intent;

use super::{
    ConfiguredDomainRoute, DomainAuditRoute, DomainDeletionAudit, DomainNamespace,
    DomainNamespaces, DomainReadRequest, DomainWriteRequest, RoutedDomainStore,
};
use crate::{
    bucket::{FileBucket, FileBucketConfig, FileBucketPublicationConfig},
    guard::{Guard, GuardConfig},
    ref_advance::{CommitTiming, Coordinator},
    repository::{
        CommitMetadata, LocalAuthority, LocalAuthorityIdentity, LocalAuthorityParameters,
        LocalRepositoryLocation, LocalRepositoryPolicy, MetadataValidator, Repository,
    },
    store::{
        ChunkPosition, ChunkUpload, ContentStore, ContentUpload, LocalFs, RefStore, TokioClock,
        TokioLocalFs,
    },
};
use std::{
    collections::BTreeSet,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};
use terrane_format::{
    auth::{Authority, Grant, Verbs},
    chunking::ChunkProfile,
    identity::{Identity, IdentityKind, TERRANE_V1},
    properties::Domain,
    refs::{CommitSource, Locality, PrincipalKind},
    tree_format::{ContentRef, EntryKind},
};

type NativeRepository =
    Repository<FileBucket<TokioLocalFs, TokioClock, MetadataValidator>, TokioClock, TokioLocalFs>;
const MAIN: &str = "refs/heads/_/main";
const TARGET: &str = "tenant:domain-deletion-fixture";
const AUDIT: &str = "private:domain-deletion-audit";
const NOTES: &str = "refs/notes/memos/_/domain-deletion";
const OPAQUE_NOTE: &[u8] = b"opaque advisory bytes, never a RefRecord";

struct Fixture {
    directory: PathBuf,
    target: NativeRepository,
    target_authority: LocalAuthority,
    audit: NativeRepository,
    audit_authority: LocalAuthority,
    audit_location: LocalRepositoryLocation,
    owner: u32,
    route: ConfiguredDomainRoute,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn timing() -> CommitTiming {
    CommitTiming::new(
        Duration::from_secs(30),
        Duration::from_secs(60),
        Duration::from_secs(10),
    )
    .unwrap()
}

fn authority(owner: u32, token_id: [u8; 16], mask: u8) -> LocalAuthorityParameters {
    LocalAuthorityParameters {
        owner_uid: owner,
        authority: Authority {
            issuer: "domain-fixture".into(),
            key_id: "initial".into(),
            subject: "owner".into(),
            kind: PrincipalKind::Human,
            groups: Vec::new(),
            not_after: u64::MAX,
            not_before: None,
            token_id,
            grants: vec![Grant::new("refs/**".into(), Verbs::new(mask).unwrap()).unwrap()],
            workload: None,
        },
    }
}

fn policy(domain: &str, reference: &str, audit: bool) -> LocalRepositoryPolicy {
    let bootstrap_properties = if audit {
        let mut forever = Vec::new();
        terrane_format::cbor::write_text(&mut forever, "forever");
        vec![("retain".into(), forever)]
    } else {
        Vec::new()
    };
    LocalRepositoryPolicy {
        store_name: "domain-fixture".into(),
        domain: domain.into(),
        default_private_domain: "private:domain-fixture-default".into(),
        acl: vec![("owner".into(), 31)],
        locality: Locality::default(),
        timing: timing(),
        policy_authority: Some(reference.into()),
        bootstrap_properties,
    }
}

fn metadata(message: &str) -> CommitMetadata {
    CommitMetadata {
        message: message.into(),
        process: "domain-deletion-fixture".into(),
        source: CommitSource::Built,
    }
}

impl Fixture {
    async fn new(mask: u8, empty: bool) -> Self {
        let entropy: [u8; 16] = TokioLocalFs
            .random_bytes(16)
            .await
            .unwrap()
            .try_into()
            .unwrap();
        let suffix: String = entropy.iter().map(|byte| format!("{byte:02x}")).collect();
        let directory = std::env::temp_dir().join(format!("terrane-domain-deletion-{suffix}"));
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let owner = std::fs::metadata(&directory).unwrap().uid();
        let target_location = LocalRepositoryLocation {
            bucket: directory.join("target"),
            authority: directory.join("target-authority"),
        };
        let audit_location = LocalRepositoryLocation {
            bucket: directory.join("audit"),
            authority: directory.join("audit-authority"),
        };
        let namespaces = DomainNamespaces::with_audit_routes(
            vec![
                DomainNamespace {
                    domain: TARGET.into(),
                    root: target_location.bucket.clone(),
                },
                DomainNamespace {
                    domain: AUDIT.into(),
                    root: audit_location.bucket.clone(),
                },
            ],
            vec![DomainAuditRoute {
                target_domain: TARGET.into(),
                audit_domain: AUDIT.into(),
            }],
        )
        .unwrap();
        let route = namespaces
            .audit_route(Domain::parse(TARGET).unwrap())
            .unwrap()
            .clone();
        let (target, target_authority) = if empty {
            empty_repository(&target_location, owner, entropy, mask).await
        } else {
            Repository::initialize_local(
                &target_location,
                authority(owner, entropy, mask),
                policy(TARGET, MAIN, false),
                MAIN,
                TokioLocalFs,
                TokioClock,
            )
            .await
            .unwrap()
        };
        let (audit, audit_authority) = Repository::initialize_local(
            &audit_location,
            authority(owner, entropy, 31),
            policy(AUDIT, route.control_ref(), true),
            route.control_ref(),
            TokioLocalFs,
            TokioClock,
        )
        .await
        .unwrap();
        audit
            .register_domain_route(&route, &audit_authority)
            .await
            .unwrap();
        Self {
            directory,
            target,
            target_authority,
            audit,
            audit_authority,
            audit_location,
            owner,
            route,
        }
    }

    async fn commit(&self, bytes: &[u8]) -> [u8; 32] {
        let source = self.directory.join("input");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(source.join("file"), bytes).unwrap();
        let mut session = self
            .target
            .begin(MAIN, self.target_authority.token(), "sdk")
            .await
            .unwrap();
        self.target
            .commit_directory(
                &mut session,
                &source,
                &self.target_authority,
                metadata("Publish independently known bytes"),
            )
            .await
            .unwrap()
            .commit
    }

    async fn orphan(&self, bytes: &[u8]) -> Identity {
        let id = TERRANE_V1.calculate(IdentityKind::Chunk, bytes).unwrap();
        let mut encoded = vec![0];
        encoded.extend_from_slice(bytes);
        self.target
            .coordinator()
            .guard()
            .store()
            .put(ContentUpload::Chunk(ChunkUpload {
                encoded: &encoded,
                identity: &id,
                declared_plaintext_len: bytes.len(),
                position: ChunkPosition::Final,
                profile: self.target.chunk_profile(),
            }))
            .await
            .unwrap();
        id
    }

    fn payloads(&self) -> Vec<PathBuf> {
        payloads(&self.route.target().root)
    }
}

async fn empty_repository(
    location: &LocalRepositoryLocation,
    owner: u32,
    token_id: [u8; 16],
    mask: u8,
) -> (NativeRepository, LocalAuthority) {
    let authority = LocalAuthority::initialize(
        &TokioLocalFs,
        &location.bucket,
        &location.authority,
        authority(owner, token_id, mask),
    )
    .await
    .unwrap();
    let seed = TokioLocalFs
        .random_bytes(32)
        .await
        .unwrap()
        .try_into()
        .unwrap();
    let profile = ChunkProfile::cdc_1m(seed);
    let bucket = FileBucket::open(
        FileBucketConfig {
            root: location.bucket.clone(),
            chunk_profile_name: "cdc-1m".into(),
            chunk_profile: profile.clone(),
            locality: Locality::default(),
            publication_control: Some(FileBucketPublicationConfig {
                operator_uid: owner,
                control: None,
            }),
        },
        TokioLocalFs,
        TokioClock,
        MetadataValidator::new(profile.clone()),
    )
    .await
    .unwrap();
    let guard = Guard::new(
        bucket,
        TokioClock,
        vec![authority.issuer_key().clone()],
        GuardConfig {
            store_name: "domain-fixture".into(),
            private_domain: "private:domain-fixture-default".into(),
            home: Locality::default(),
            initial_acl: vec![("owner".into(), 31)],
            min_chunk_size: profile.minimum() as u64,
            storage_domain: TARGET.into(),
            chunk_profile_name: "cdc-1m".into(),
            chunk_profile: Box::new(profile),
            policy_authority: Some(MAIN.into()),
        },
    );
    let repository = Repository::initialize_native_retention(
        Coordinator::new(guard, timing(), TokioLocalFs),
        &DomainNamespace {
            domain: TARGET.into(),
            root: location.bucket.clone(),
        },
        &location.authority,
        owner,
    )
    .await
    .unwrap();
    assert!(
        repository
            .coordinator()
            .guard()
            .store()
            .ref_names()
            .await
            .unwrap()
            .is_empty()
    );
    (repository, authority)
}

fn payloads(root: &Path) -> Vec<PathBuf> {
    let mut pending = vec![root.join("objects/pack"), root.join("objects/index")];
    let mut files = Vec::new();
    while let Some(path) = pending.pop() {
        if !path.exists() {
            continue;
        }
        if path.is_dir() {
            pending.extend(
                std::fs::read_dir(path)
                    .unwrap()
                    .map(|entry| entry.unwrap().path()),
            );
        } else {
            files.push(path);
        }
    }
    files.sort();
    files
}

async fn selection(fixture: &Fixture, commit: [u8; 32]) -> (ContentRef, u64) {
    let snapshot = fixture
        .target
        .coordinator()
        .guard()
        .read_snapshot(MAIN, fixture.target_authority.token(), b"/file", "sdk")
        .await
        .unwrap();
    assert_eq!(snapshot.commit.identity(), commit);
    let (location, _) = snapshot.history.locate(commit, b"file").unwrap();
    let entry = snapshot.history.entry(&location).unwrap();
    match &entry.kind {
        EntryKind::File { content, size, .. } => (*content, *size),
        _ => panic!("fixture file is not a file"),
    }
}

/// Publishes ordinary opaque Notes data under the actual selected namespace fence.
///
/// The complete inventory remains explicit, including after logical removal.
/// Neither these bytes nor this Raw transaction creates checked graph authority.
///
/// # Panics
/// Panics if genuine selected publication fails or its exact Notes/inventory bytes differ.
async fn publish_note(repository: &NativeRepository, value: Option<&[u8]>) {
    use crate::bucket::held::SingleHeld;
    use terrane_format::bucket::{BucketCapabilities, BucketKey};
    use terrane_format::gc::publication::LogicalChange;

    let bucket = repository.coordinator().guard().store();
    let holder = SingleHeld::acquire(bucket).await.unwrap();
    let held = holder.destination();
    let observed = held.observe_publication_retained().await.unwrap();
    let key = BucketKey::ref_record(NOTES).unwrap();
    let previous = observed.logical().get(key.as_str()).cloned().flatten();
    let mut changes = vec![LogicalChange {
        key: key.as_str().into(),
        expected: previous,
        new: value.map(<[u8]>::to_vec),
    }];

    let capabilities_bytes = observed
        .logical()
        .get("CAPABILITIES")
        .and_then(Option::as_ref)
        .unwrap();
    let mut capabilities = BucketCapabilities::decode(capabilities_bytes).unwrap();
    let names = capabilities.ref_names.as_mut().unwrap();
    if !names.iter().any(|name| name == NOTES) {
        names.push(NOTES.into());
        names.sort();
        changes.push(LogicalChange {
            key: "CAPABILITIES".into(),
            expected: Some(capabilities_bytes.clone()),
            new: Some(capabilities.encode().unwrap()),
        });
    }

    held.publish_raw(&observed, changes).await.unwrap();
    let selected = held.observe_publication_retained().await.unwrap();
    assert_eq!(
        selected.logical().get(key.as_str()).cloned().flatten(),
        value.map(<[u8]>::to_vec),
    );
    let selected_capabilities = BucketCapabilities::decode(
        selected
            .logical()
            .get("CAPABILITIES")
            .and_then(Option::as_ref)
            .unwrap(),
    )
    .unwrap();
    assert!(
        selected_capabilities
            .ref_names
            .unwrap()
            .contains(&NOTES.into())
    );
}

#[tokio::test]
async fn domain_deletion_native_accepts_opaque_notes_in_target_and_audit_inventory() {
    let fixture = Fixture::new(31, false).await;
    fixture
        .commit(b"actual content with opaque advisory names")
        .await;
    assert!(terrane_format::refs::RefRecord::decode(OPAQUE_NOTE).is_err());
    publish_note(&fixture.target, Some(OPAQUE_NOTE)).await;
    publish_note(&fixture.audit, Some(OPAQUE_NOTE)).await;
    let files = fixture.payloads();
    assert!(!files.is_empty());
    let audit = fixture
        .audit
        .domain_audit(&fixture.route, &fixture.audit_authority)
        .await
        .unwrap();
    assert!(!audit.domain_deleted(TARGET).await.unwrap());

    fixture
        .target
        .delete_domain(&fixture.route, &fixture.target_authority, &audit)
        .await
        .unwrap();

    assert!(fixture.payloads().is_empty());
    assert!(files.iter().all(|path| !path.exists()));
    assert!(audit.domain_deleted(TARGET).await.unwrap());
    assert!(
        RoutedDomainStore::new(&fixture.target, &audit)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn domain_deletion_native_fences_changed_or_absent_opaque_notes_after_intent() {
    for replacement in [Some(b"changed opaque advisory bytes".as_slice()), None] {
        let fixture = Fixture::new(31, false).await;
        fixture
            .commit(b"content survives changed advisory inventory")
            .await;
        publish_note(&fixture.target, Some(OPAQUE_NOTE)).await;
        let files = fixture.payloads();
        let before = files
            .iter()
            .map(|path| (path.clone(), std::fs::read(path).unwrap()))
            .collect::<Vec<_>>();
        assert!(!before.is_empty());
        let audit = fixture
            .audit
            .domain_audit(&fixture.route, &fixture.audit_authority)
            .await
            .unwrap();
        let (entered, resume) = fixture.target.pause_domain_deletion_after_intent().unwrap();
        let deletion =
            fixture
                .target
                .delete_domain(&fixture.route, &fixture.target_authority, &audit);
        let mutation = async {
            entered.await.unwrap();
            assert!(audit.domain_deleted(TARGET).await.unwrap());
            publish_note(&fixture.target, replacement).await;
            resume.send(()).unwrap();
        };

        let (result, ()) = tokio::join!(deletion, mutation);

        assert!(result.is_err());
        assert_eq!(fixture.payloads(), files);
        for (path, bytes) in before {
            assert_eq!(std::fs::read(path).unwrap(), bytes);
        }
        assert!(audit.domain_deleted(TARGET).await.unwrap());
        assert!(
            RoutedDomainStore::new(&fixture.target, &audit)
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn domain_deletion_native_erases_generations_and_disables_surviving_and_reopened_routes() {
    let fixture = Fixture::new(31, false).await;
    fixture.commit(b"first independent generation").await;
    let expected = b"second independent generation";
    let commit = fixture.commit(expected).await;
    let orphan = fixture
        .orphan(b"unreferenced but domain-owned native chunk")
        .await;
    let (content, size) = selection(&fixture, commit).await;
    let audit = fixture
        .audit
        .domain_audit(&fixture.route, &fixture.audit_authority)
        .await
        .unwrap();
    let route = RoutedDomainStore::new(&fixture.target, &audit)
        .await
        .unwrap();
    let request = DomainReadRequest {
        reference: MAIN,
        token: fixture.target_authority.token(),
        commit,
        path: b"/file",
        content,
        size,
        surface: "sdk",
    };
    assert_eq!(route.read_content(&request).await.unwrap(), expected);
    assert_eq!(route.has(&request, &[orphan]).await.unwrap(), vec![false]);
    let files = fixture.payloads();
    assert!(files.iter().any(|path| {
        path.extension()
            .is_some_and(|extension| extension == "pack")
    }));
    let generations: BTreeSet<_> = files
        .iter()
        .filter_map(|path| {
            path.strip_prefix(fixture.route.target().root.join("objects/index"))
                .ok()
                .and_then(|path| path.components().next())
                .map(|part| part.as_os_str().to_owned())
        })
        .collect();
    assert!(generations.len() >= 2);
    let audit_before = payloads(&fixture.route.audit().root);

    let completion = fixture
        .target
        .delete_domain(&fixture.route, &fixture.target_authority, &audit)
        .await
        .unwrap();
    assert!(fixture.payloads().is_empty());
    assert!(files.iter().all(|path| !path.exists()));
    assert!(audit_before.iter().all(|path| path.exists()));
    assert!(audit.domain_deleted(TARGET).await.unwrap());
    let audit_head = fixture
        .audit
        .coordinator()
        .guard()
        .store()
        .ref_get(fixture.route.control_ref())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(completion.terrane_v1_digest().unwrap(), audit_head.commit);
    assert!(route.read_content(&request).await.is_err());
    assert!(route.has(&request, &[]).await.is_err());
    let write = DomainWriteRequest {
        reference: MAIN,
        token: fixture.target_authority.token(),
        path: b"/",
        surface: "sdk",
    };
    let mut encoded = vec![0];
    encoded.extend_from_slice(b"refused fresh publication");
    let id = TERRANE_V1
        .calculate(IdentityKind::Chunk, &encoded[1..])
        .unwrap();
    assert!(
        route
            .put(
                &write,
                ContentUpload::Chunk(ChunkUpload {
                    encoded: &encoded,
                    identity: &id,
                    declared_plaintext_len: encoded.len() - 1,
                    position: ChunkPosition::Final,
                    profile: fixture.target.chunk_profile()
                })
            )
            .await
            .is_err()
    );
    assert!(fixture.payloads().is_empty());

    let (reopened_audit, reopened_authority) = Repository::open_local(
        &fixture.audit_location,
        &LocalAuthorityIdentity {
            issuer: "domain-fixture".into(),
            key_id: "initial".into(),
            owner_uid: fixture.owner,
        },
        policy(AUDIT, fixture.route.control_ref(), true),
        fixture.route.control_ref(),
        TokioLocalFs,
        TokioClock,
    )
    .await
    .unwrap();
    let reopened_route = reopened_audit
        .domain_audit(&fixture.route, &reopened_authority)
        .await
        .unwrap();
    assert!(reopened_route.domain_deleted(TARGET).await.unwrap());
    assert!(
        RoutedDomainStore::new(&fixture.target, &reopened_route)
            .await
            .is_err()
    );
    assert!(fixture.payloads().is_empty());
}

/// A real legacy inventory never acquires completeness from a native directory listing.
async fn unknown_legacy_inventory(fixture: &Fixture) {
    use crate::store::StoreErrorKind;
    use terrane_format::bucket::{BucketCapabilities, StoreProfile};

    let root = fixture.directory.join("legacy-unknown-inventory");
    TokioLocalFs.create_dir_new(&root).await.unwrap();
    let profile = ChunkProfile::cdc_1m([42; 32]);
    let capabilities = BucketCapabilities {
        layout_version: 1,
        create_if_absent: true,
        compare_and_swap: true,
        ranges: true,
        presign: false,
        multi_writer: false,
        probed_at: 0,
        profile: StoreProfile {
            identity: "terrane-v1".into(),
            algorithm: "blake3".into(),
            chunk: "cdc-1m".into(),
            seed: profile.seed(),
        },
        generation: None,
        ref_names: None,
        publication_protocol: None,
    }
    .encode()
    .unwrap();
    TokioLocalFs
        .write_new(&root.join("CAPABILITIES"), &capabilities)
        .await
        .unwrap();
    TokioLocalFs
        .sync_file(&root.join("CAPABILITIES"))
        .await
        .unwrap();
    TokioLocalFs.sync_directory(&root).await.unwrap();
    let bucket = FileBucket::open_legacy_read_only(
        FileBucketConfig {
            root: root.clone(),
            chunk_profile_name: "cdc-1m".into(),
            chunk_profile: profile.clone(),
            locality: Locality::default(),
            publication_control: None,
        },
        TokioLocalFs,
        TokioClock,
        MetadataValidator::new(profile),
    )
    .await
    .unwrap();
    let error = bucket.ref_names().await.unwrap_err();
    assert!(matches!(error.kind(), StoreErrorKind::Unsupported));
    assert_eq!(
        std::fs::read(root.join("CAPABILITIES")).unwrap(),
        capabilities
    );
    assert!(!root.join(".terrane-locks").exists());
}

#[tokio::test]
async fn domain_deletion_native_rejects_denied_roots_and_whole_inventory_races() {
    let denied = Fixture::new(15, false).await;
    denied
        .commit(b"protected source that cannot be administered")
        .await;
    let audit = denied
        .audit
        .domain_audit(&denied.route, &denied.audit_authority)
        .await
        .unwrap();
    let files = denied.payloads();
    unknown_legacy_inventory(&denied).await;
    assert!(!audit.domain_deleted(TARGET).await.unwrap());
    assert!(
        denied
            .target
            .delete_domain(&denied.route, &denied.target_authority, &audit)
            .await
            .is_err()
    );
    assert!(files.iter().all(|path| path.exists()));
    assert!(!audit.domain_deleted(TARGET).await.unwrap());

    let racing = Fixture::new(31, false).await;
    racing.commit(b"actual original inventory").await;
    let audit = racing
        .audit
        .domain_audit(&racing.route, &racing.audit_authority)
        .await
        .unwrap();
    let files = racing.payloads();
    let (entered, resume) = racing.target.pause_domain_deletion_after_intent().unwrap();
    let deletion = racing
        .target
        .delete_domain(&racing.route, &racing.target_authority, &audit);
    let mutation = async {
        entered.await.unwrap();
        assert!(audit.domain_deleted(TARGET).await.unwrap());
        let request = racing.target.source_request(
            &racing.target_authority,
            metadata("Independently authorize new root after recorded intent"),
        );
        racing
            .target
            .fork(MAIN, "refs/heads/_/later-root", request)
            .await
            .unwrap();
        resume.send(()).unwrap();
    };
    let (result, ()) = tokio::join!(deletion, mutation);
    assert!(result.is_err());
    assert!(files.iter().all(|path| path.exists()));
    assert!(
        racing
            .target
            .coordinator()
            .guard()
            .store()
            .ref_names()
            .await
            .unwrap()
            .contains(&"refs/heads/_/later-root".into())
    );
    assert!(audit.domain_deleted(TARGET).await.unwrap());
    assert!(
        RoutedDomainStore::new(&racing.target, &audit)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn domain_deletion_native_erases_empty_registered_namespace_and_retains_pending_on_parent_sync_failure()
 {
    let empty = Fixture::new(31, true).await;
    empty
        .orphan(b"unreferenced native empty-domain payload")
        .await;
    let files = empty.payloads();
    assert!(!files.is_empty());
    assert!(
        empty
            .target
            .coordinator()
            .guard()
            .store()
            .ref_names()
            .await
            .unwrap()
            .is_empty()
    );
    let audit = empty
        .audit
        .domain_audit(&empty.route, &empty.audit_authority)
        .await
        .unwrap();
    empty
        .target
        .delete_domain(&empty.route, &empty.target_authority, &audit)
        .await
        .unwrap();
    assert!(empty.payloads().is_empty());
    assert!(audit.domain_deleted(TARGET).await.unwrap());
    assert!(RoutedDomainStore::new(&empty.target, &audit).await.is_err());

    let interrupted = Fixture::new(31, true).await;
    interrupted
        .orphan(b"actual data before parent-sync failure")
        .await;
    let files = interrupted.payloads();
    let first = files.first().unwrap();
    crate::bucket::domain_deletion::fail_next_parent_sync(
        &interrupted.route.target().root,
        first.parent().unwrap(),
    )
    .unwrap();
    let audit = interrupted
        .audit
        .domain_audit(&interrupted.route, &interrupted.audit_authority)
        .await
        .unwrap();
    assert!(
        interrupted
            .target
            .delete_domain(&interrupted.route, &interrupted.target_authority, &audit)
            .await
            .is_err()
    );
    assert!(!first.exists());
    assert!(files.iter().skip(1).all(|path| path.exists()));
    assert!(audit.domain_deleted(TARGET).await.unwrap());
    assert!(
        RoutedDomainStore::new(&interrupted.target, &audit)
            .await
            .is_err()
    );
}

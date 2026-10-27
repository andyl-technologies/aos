//! Qualifies real reopened repositories while forbidding ordinary pack-body I/O.

#[path = "tests/fs.rs"]
mod fs;

#[path = "tests/publication.rs"]
mod publication;

use std::{
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::atomic::Ordering,
    time::Duration,
};

use terrane_format::{
    auth::{self, Attenuation, Authority, Caveat, Grant, Token, Verb, Verbs},
    cbor,
    identity::{IdentityKind, TERRANE_V1},
    refs::{CommitSource, Locality, PrincipalKind, RefLogReason, RefLogRecord, RefRecord},
    tree_builder::Tree,
    tree_format::{Entry, EntryKind, LeafItem, Property, TreeUse},
};

use super::{ColdForkRequest, qualify_source};
use crate::store::native_publication_effects::collection::test_fs::TestClock;
use crate::{
    bucket::{FileBucket, held::SingleHeld},
    ref_advance::CommitTiming,
    repository::{
        CommitMetadata, LocalAuthority, LocalAuthorityIdentity, LocalAuthorityParameters,
        LocalRepositoryLocation, LocalRepositoryPolicy, MetadataValidator, PreparedTree,
        Repository,
    },
    store::{Clock, ContentStore, LocalFs, RefCasOutcome, RefStore},
};
use fs::CountingFs;

const SOURCE: &str = "refs/heads/_/main";
const DESTINATION: &str = "refs/heads/_/fork";
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
type NativeRepository =
    Repository<FileBucket<CountingFs, TestClock, MetadataValidator>, TestClock, CountingFs>;

struct FixtureDirectory(PathBuf);

impl Drop for FixtureDirectory {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_dir_all(&self.0) {
            eprintln!("Failed to remove private cold-fork fixture: {error}");
        }
    }
}

struct Fixture {
    repository: NativeRepository,
    authority: LocalAuthority,
    record: RefRecord,
    root: [u8; 32],
    fs: CountingFs,
    clock: TestClock,
    location: LocalRepositoryLocation,
    _directory: FixtureDirectory,
}

fn timing() -> TestResult<CommitTiming> {
    Ok(CommitTiming::new(
        Duration::from_secs(30),
        Duration::from_secs(60),
        Duration::from_secs(10),
    )?)
}

fn policy() -> TestResult<LocalRepositoryPolicy> {
    Ok(LocalRepositoryPolicy {
        store_name: "local".into(),
        domain: "private:owner".into(),
        default_private_domain: "private:owner".into(),
        acl: vec![("owner".into(), 31)],
        locality: Locality::default(),
        timing: timing()?,
        policy_authority: None,
        bootstrap_properties: Vec::new(),
    })
}

fn metadata(message: &str) -> CommitMetadata {
    CommitMetadata {
        message: message.into(),
        process: "cold-fork-qualification".into(),
        source: CommitSource::Built,
    }
}

impl Fixture {
    async fn open() -> TestResult<Self> {
        let fs = CountingFs::default();
        let clock = TestClock::new(1000);
        let entropy = fs.random_bytes(16).await?;
        let suffix: String = entropy.iter().map(|byte| format!("{byte:02x}")).collect();
        let parent = std::env::temp_dir().join(format!("terrane-cold-fork-{suffix}"));
        fs.create_dir_new(&parent).await?;
        let directory = FixtureDirectory(parent.clone());
        let owner_uid = fs.metadata(&parent).await?.uid();
        let location = LocalRepositoryLocation {
            bucket: parent.join("bucket"),
            authority: parent.join("authority"),
        };
        let (repository, authority) = Repository::initialize_local(
            &location,
            LocalAuthorityParameters {
                owner_uid,
                authority: Authority {
                    issuer: "local".into(),
                    key_id: "initial".into(),
                    subject: "owner".into(),
                    kind: PrincipalKind::Human,
                    groups: Vec::new(),
                    not_after: 1010,
                    not_before: None,
                    token_id: entropy.try_into().map_err(|_| "invalid entropy")?,
                    grants: vec![Grant::new("refs/**".into(), Verbs::new(31)?)?],
                    workload: None,
                },
            },
            policy()?,
            SOURCE,
            fs.clone(),
            clock.clone(),
        )
        .await?;
        let directory_source = parent.join("source");
        fs.create_dir_new(&directory_source).await?;
        fs.write_new(&directory_source.join("file"), b"cold copied content")
            .await?;
        let mut session = repository.begin(SOURCE, authority.token(), "sdk").await?;
        let record = repository
            .commit_directory(
                &mut session,
                &directory_source,
                &authority,
                metadata("Import source"),
            )
            .await?;
        drop(repository);
        drop(authority);

        let (repository, authority) = Repository::open_local(
            &location,
            &LocalAuthorityIdentity {
                issuer: "local".into(),
                key_id: "initial".into(),
                owner_uid,
            },
            policy()?,
            SOURCE,
            fs.clone(),
            clock.clone(),
        )
        .await?;
        let root = repository
            .coordinator()
            .guard()
            .read_snapshot(SOURCE, authority.token(), b"/", "sdk")
            .await?
            .evidence
            .root;
        let store = repository.coordinator().store();
        let observer = store.observe_metadata_for_tests()?;
        observer.reset();
        let identity = TERRANE_V1.from_digest(IdentityKind::Node, &root)?;
        let bytes = store.get(&identity, None).await?;
        assert!(observer.snapshot().node_gets > 0);
        store
            .put(crate::store::ContentUpload::Meta(
                crate::store::MetaUpload::new(IdentityKind::Node, &bytes)?,
            ))
            .await?;
        assert!(observer.snapshot().node_puts > 0);
        assert!(observer.snapshot().node_decodes > 0);
        observer.reset();
        Ok(Self {
            repository,
            authority,
            record,
            root,
            fs,
            clock,
            location,
            _directory: directory,
        })
    }

    fn forbid_packs(&self) {
        self.repository
            .coordinator()
            .store()
            .observe_content_for_tests()
            .reset();
        self.fs.pack_io.store(0, Ordering::SeqCst);
        self.fs.effects.store(0, Ordering::SeqCst);
        self.fs.reject_packs.store(true, Ordering::SeqCst);
    }

    fn assert_no_content_io(&self) {
        let counts = self
            .repository
            .coordinator()
            .store()
            .observe_content_for_tests()
            .snapshot();
        assert_eq!(counts.node_gets, 0);
        assert_eq!(counts.node_puts, 0);
        assert_eq!(counts.node_decodes, 0);
        assert_eq!(self.fs.pack_io.load(Ordering::SeqCst), 0);
        assert_eq!(self.fs.effects.load(Ordering::SeqCst), 0);
    }

    async fn revoke_fork(&mut self) -> TestResult {
        let repository = &self.repository;
        let guard = repository.coordinator().guard();
        let minimum = repository.chunk_profile().minimum() as u64;
        let snapshot = guard
            .read_snapshot(SOURCE, self.authority.token(), b"/", "sdk")
            .await?;
        let prepared = {
            let tree = snapshot.evidence.tree(snapshot.evidence.root, minimum)?;
            let mut acl = Vec::new();
            cbor::write_array(&mut acl, 1);
            cbor::write_array(&mut acl, 2);
            cbor::write_text(&mut acl, "owner");
            // Admin implies Fork, so both grants must be removed. Read,
            // Commit and Tag remain available under the newly selected ACL.
            cbor::write_uint(&mut acl, 13);
            let mut properties = tree.props().ok_or("missing source ACL")?.to_vec();
            *properties
                .iter_mut()
                .find(|property| property.name == "acl")
                .ok_or("missing ACL property")? = Property {
                name: "acl",
                value: &acl,
            };
            let tree = Tree::build(
                tree.iter().cloned().collect(),
                Some(properties),
                minimum,
                TreeUse::Ordinary,
            )?;
            PreparedTree::from_tree(&tree)?
        };
        let mut session = repository
            .begin(SOURCE, self.authority.token(), "sdk")
            .await?;
        let mut request = repository.source_request(&self.authority, metadata("Revoke Fork"));
        request.commit.tree = prepared.root();
        request.commit.parents = vec![self.record.commit];
        self.record = repository.commit(&mut session, prepared, request).await?;
        Ok(())
    }

    async fn publish_repeated_roots(&mut self) -> TestResult {
        let repository = &self.repository;
        let guard = repository.coordinator().guard();
        let minimum = repository.chunk_profile().minimum() as u64;
        let snapshot = guard
            .read_snapshot(SOURCE, self.authority.token(), b"/", "sdk")
            .await?;
        let prepared = {
            let tree = snapshot.evidence.tree(snapshot.evidence.root, minimum)?;
            let properties = tree.props().ok_or("missing source policy")?.to_vec();
            let child = Tree::build(
                Vec::new(),
                Some(properties.clone()),
                minimum,
                TreeUse::Ordinary,
            )?;
            let mut entries = tree.iter().cloned().collect::<Vec<_>>();
            for name in [b"left".as_slice(), b"right".as_slice()] {
                entries.push(LeafItem {
                    key: name.to_vec(),
                    entry: Entry {
                        kind: EntryKind::Tree {
                            root: child.root_identity(),
                            props: None,
                        },
                        attrs: Vec::new(),
                        attrs_present: false,
                        xattrs: Vec::new(),
                        xattrs_present: false,
                        provenance: None,
                    },
                });
            }
            let tree = Tree::build(entries, Some(properties), minimum, TreeUse::Ordinary)?;
            let mut prepared = PreparedTree::from_tree(&tree)?;
            prepared
                .uploads
                .extend(PreparedTree::from_tree(&child)?.uploads);
            prepared
        };
        let mut session = repository
            .begin(SOURCE, self.authority.token(), "sdk")
            .await?;
        let mut request =
            repository.source_request(&self.authority, metadata("Graft repeated roots"));
        request.commit.tree = prepared.root();
        request.commit.parents = vec![self.record.commit];
        self.root = prepared.root();
        self.record = repository.commit(&mut session, prepared, request).await?;
        Ok(())
    }
}

#[tokio::test]
async fn reopened_selected_source_qualifies_without_node_or_pack_body_io() -> TestResult {
    let fixture = Fixture::open().await?;
    let concrete = fixture.repository.coordinator().guard();
    let node = TERRANE_V1.from_digest(IdentityKind::Node, &fixture.root)?;
    fixture.forbid_packs();
    assert!(concrete.store().get(&node, None).await.is_err());
    assert!(fixture.fs.pack_io.load(Ordering::SeqCst) > 0);
    fixture.forbid_packs();

    let authority = concrete
        .original_commit(&fixture.record.commit)?
        .baseline()
        .authority()
        .clone();
    let holder = SingleHeld::acquire(concrete.store()).await?;
    let guard = concrete.held_guard(holder.destination(), fixture.clock.clone())?;
    let observed = guard.store().observe_publication().await?;
    fixture.fs.effects.store(0, Ordering::SeqCst);
    // Native dispatch captures the concrete backend without a request clock.
    // Live timing and authorization belong to the independently held Guard.
    let captured = concrete.cold_fork_configuration_adapter();
    let mut qualified = qualify_source(
        &captured,
        &authority,
        &guard,
        &observed,
        ColdForkRequest {
            source: SOURCE,
            token: fixture.authority.token(),
            surface: "sdk",
            started: fixture.clock.monotonic(),
            timing: timing()?,
        },
    )
    .await?;

    assert_eq!(qualified.commit().identity(), fixture.record.commit);
    assert_eq!(qualified.commit().commit().tree, fixture.root);
    assert_eq!(qualified.authorization().record(), Some(&fixture.record));
    let destination = guard
        .authorize_cold_fork_destination(
            qualified.policies(),
            DESTINATION,
            1,
            fixture.authority.token(),
            "sdk",
        )
        .await?;
    assert!(destination.record().is_none());
    let signing = fixture
        .repository
        .source_request(&fixture.authority, metadata("Restrict grants"));
    let restricted = Token::decode(fixture.authority.token())?
        .attenuate(
            Attenuation {
                grants: Some(vec![Grant::new("refs/**".into(), Verbs::new(3)?)?]),
                ..Attenuation::default()
            },
            &signing.terminal_secret,
            auth::public_key_from_secret(&[73; 32]),
        )?
        .encode();
    guard
        .authorize_cold_fork_source(qualified.policies(), &restricted, "sdk")
        .await?;
    assert!(
        guard
            .authorize_cold_fork_destination(
                qualified.policies(),
                DESTINATION,
                1,
                &restricted,
                "sdk"
            )
            .await
            .is_err()
    );
    qualified.revalidate(&guard).await?;
    fixture.assert_no_content_io();
    Ok(())
}

#[tokio::test]
async fn qualified_source_rechecks_original_loss_and_live_expiry() -> TestResult {
    let fixture = Fixture::open().await?;
    let concrete = fixture.repository.coordinator().guard();
    let authority = concrete
        .original_commit(&fixture.record.commit)?
        .baseline()
        .authority()
        .clone();
    fixture.forbid_packs();
    let holder = SingleHeld::acquire(concrete.store()).await?;
    let guard = concrete.held_guard(holder.destination(), fixture.clock.clone())?;
    let observed = guard.store().observe_publication().await?;
    fixture.fs.effects.store(0, Ordering::SeqCst);
    let publication_timing = timing()?;
    let request = || ColdForkRequest {
        source: SOURCE,
        token: fixture.authority.token(),
        surface: "sdk",
        started: fixture.clock.monotonic(),
        timing: publication_timing,
    };
    let mut qualified = qualify_source(concrete, &authority, &guard, &observed, request()).await?;
    fixture.clock.set(1011, 0);
    assert!(qualified.revalidate(&guard).await.is_err());
    fixture.clock.set(1000, 31);
    assert!(matches!(
        qualified.revalidate(&guard).await,
        Err(crate::ref_advance::AdvanceError::Expired)
    ));
    fixture.clock.set(1000, 0);
    drop(qualified);

    let digest: String = fixture
        .record
        .commit
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    std::fs::remove_file(
        fixture
            .location
            .authority
            .join(format!("commit-{digest}.cbor")),
    )?;
    assert!(
        qualify_source(concrete, &authority, &guard, &observed, request())
            .await
            .is_err()
    );
    fixture.assert_no_content_io();
    Ok(())
}

#[tokio::test]
async fn newly_selected_source_acl_revocation_denies_cold_fork() -> TestResult {
    let mut fixture = Fixture::open().await?;
    fixture.revoke_fork().await?;
    let concrete = fixture.repository.coordinator().guard();
    concrete
        .authorize(SOURCE, fixture.authority.token(), Verb::Read, &[], "sdk")
        .await?;
    assert!(
        concrete
            .authorize(SOURCE, fixture.authority.token(), Verb::Fork, &[], "sdk")
            .await
            .is_err()
    );
    let authority = concrete
        .original_commit(&fixture.record.commit)?
        .baseline()
        .authority()
        .clone();
    fixture.forbid_packs();
    let holder = SingleHeld::acquire(concrete.store()).await?;
    let guard = concrete.held_guard(holder.destination(), fixture.clock.clone())?;
    let observed = guard.store().observe_publication().await?;
    fixture.fs.effects.store(0, Ordering::SeqCst);
    let failure = qualify_source(
        concrete,
        &authority,
        &guard,
        &observed,
        ColdForkRequest {
            source: SOURCE,
            token: fixture.authority.token(),
            surface: "sdk",
            started: fixture.clock.monotonic(),
            timing: timing()?,
        },
    )
    .await
    .err()
    .ok_or("revoked Fork was accepted")?;
    assert!(
        matches!(failure, crate::ref_advance::AdvanceError::Store(error) if matches!(error.kind(), crate::store::StoreErrorKind::Denied { verb: "fork", .. }))
    );
    fixture.assert_no_content_io();
    Ok(())
}

#[tokio::test]
async fn raw_alias_of_signed_source_has_no_cold_qualification() -> TestResult {
    let fixture = Fixture::open().await?;
    let concrete = fixture.repository.coordinator().guard();
    let record = RefRecord {
        seq: 1,
        writer_epoch: 0,
        candidate_id: Some([19; 32]),
        ..fixture.record.clone()
    };
    let log = RefLogRecord {
        record: record.clone(),
        previous_commit: None,
        principal: "owner".into(),
        reason: RefLogReason::Commit,
        timestamp: 1000,
        expected_previous: Some(None),
        committed_previous: None,
    };
    concrete
        .store()
        .ref_log_append(DESTINATION, record.seq, &log)
        .await?;
    assert_eq!(
        concrete.store().ref_cas(DESTINATION, None, &record).await?,
        RefCasOutcome::Applied
    );
    let authority = concrete
        .original_commit(&fixture.record.commit)?
        .baseline()
        .authority()
        .clone();
    fixture.forbid_packs();
    let holder = SingleHeld::acquire(concrete.store()).await?;
    let guard = concrete.held_guard(holder.destination(), fixture.clock.clone())?;
    let observed = guard.store().observe_publication().await?;
    fixture.fs.effects.store(0, Ordering::SeqCst);
    assert!(
        qualify_source(
            concrete,
            &authority,
            &guard,
            &observed,
            ColdForkRequest {
                source: DESTINATION,
                token: fixture.authority.token(),
                surface: "sdk",
                started: fixture.clock.monotonic(),
                timing: timing()?,
            }
        )
        .await
        .is_err()
    );
    fixture.assert_no_content_io();
    Ok(())
}

#[tokio::test]
async fn altered_protected_lineage_cannot_qualify_source_policies() -> TestResult {
    for target in ["guard", "lineage", "original"] {
        reject_replaced_qualified_record(target).await?;
    }

    let fixture = Fixture::open().await?;
    let concrete = fixture.repository.coordinator().guard();
    let authority = concrete
        .original_commit(&fixture.record.commit)?
        .baseline()
        .authority()
        .clone();
    fixture.forbid_packs();
    let holder = SingleHeld::acquire(concrete.store()).await?;
    let guard = concrete.held_guard(holder.destination(), fixture.clock.clone())?;
    let observed = guard.store().observe_publication().await?;
    let selected = observed
        .state()
        .sources
        .iter()
        .find(|source| source.name == SOURCE)
        .ok_or("missing selected lineage")?;
    let mut bytes = guard
        .store()
        .selected_lineage(&observed, SOURCE)
        .await?
        .ok_or("missing source evidence")?;
    let control = fixture.location.bucket.with_file_name(format!(
        ".terrane-control:{}",
        blake3::hash(fixture.location.bucket.as_os_str().as_encoded_bytes()).to_hex()
    ));
    let digest: String = selected
        .digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    bytes.push(0);
    std::fs::write(control.join("publication/lineage").join(digest), bytes)?;
    fixture.fs.effects.store(0, Ordering::SeqCst);

    assert!(
        qualify_source(
            concrete,
            &authority,
            &guard,
            &observed,
            ColdForkRequest {
                source: SOURCE,
                token: fixture.authority.token(),
                surface: "sdk",
                started: fixture.clock.monotonic(),
                timing: timing()?,
            }
        )
        .await
        .is_err()
    );
    fixture.assert_no_content_io();
    Ok(())
}

async fn reject_replaced_qualified_record(target: &str) -> TestResult {
    let fixture = Fixture::open().await?;
    let concrete = fixture.repository.coordinator().guard();
    let authority = concrete
        .original_commit(&fixture.record.commit)?
        .baseline()
        .authority()
        .clone();
    fixture.forbid_packs();
    let holder = SingleHeld::acquire(concrete.store()).await?;
    let guard = concrete.held_guard(holder.destination(), fixture.clock.clone())?;
    let observed = guard.store().observe_publication().await?;
    fixture.fs.effects.store(0, Ordering::SeqCst);
    let mut qualified = qualify_source(
        concrete,
        &authority,
        &guard,
        &observed,
        ColdForkRequest {
            source: SOURCE,
            token: fixture.authority.token(),
            surface: "sdk",
            started: fixture.clock.monotonic(),
            timing: timing()?,
        },
    )
    .await?;
    let path = match target {
        "guard" => qualified.guard_read.path(),
        "lineage" => qualified.lineage_read.path(),
        "original" => qualified
            .retained_controls
            .records()
            .iter()
            .find(|record| {
                record
                    .path()
                    .file_name()
                    .is_some_and(|name| name.as_encoded_bytes().starts_with(b"commit-"))
            })
            .ok_or("missing actual source original association")?
            .path(),
        _ => return Err("unknown replacement target".into()),
    };
    replace_same_bytes(path)?;

    assert!(
        qualified.revalidate(&guard).await.is_err(),
        "accepted replacement of {target}"
    );
    fixture.assert_no_content_io();
    Ok(())
}

fn replace_same_bytes(path: &Path) -> TestResult {
    use std::io::Write;

    let bytes = std::fs::read(path)?;
    let original = std::fs::symlink_metadata(path)?;
    let replacement = path.with_extension("cold-replacement");
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&replacement)?;
    file.set_permissions(original.permissions())?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    assert_ne!(original.ino(), file.metadata()?.ino());
    std::fs::rename(&replacement, path)?;
    std::fs::File::open(path.parent().ok_or("missing record parent")?)?.sync_all()?;
    assert_eq!(std::fs::read(path)?, bytes);
    Ok(())
}

#[tokio::test]
async fn repeated_root_occurrences_keep_independent_current_caveat_checks() -> TestResult {
    let mut fixture = Fixture::open().await?;
    fixture.publish_repeated_roots().await?;
    let concrete = fixture.repository.coordinator().guard();
    let authority = concrete
        .original_commit(&fixture.record.commit)?
        .baseline()
        .authority()
        .clone();
    fixture.forbid_packs();
    let holder = SingleHeld::acquire(concrete.store()).await?;
    let guard = concrete.held_guard(holder.destination(), fixture.clock.clone())?;
    let observed = guard.store().observe_publication().await?;
    fixture.fs.effects.store(0, Ordering::SeqCst);
    let qualified = qualify_source(
        concrete,
        &authority,
        &guard,
        &observed,
        ColdForkRequest {
            source: SOURCE,
            token: fixture.authority.token(),
            surface: "sdk",
            started: fixture.clock.monotonic(),
            timing: timing()?,
        },
    )
    .await?;
    let roots = &qualified.policies().source_view().roots;
    let left = roots
        .iter()
        .find(|root| root.path == b"/left")
        .ok_or("missing left occurrence")?;
    let right = roots
        .iter()
        .find(|root| root.path == b"/right")
        .ok_or("missing right occurrence")?;
    assert_eq!(left.root, right.root);
    assert_ne!(left.path, right.path);

    let signing = fixture
        .repository
        .source_request(&fixture.authority, metadata("Restrict roots"));
    let restricted = Token::decode(fixture.authority.token())?
        .attenuate(
            Attenuation {
                caveats: vec![Caveat::Root("/".into())],
                ..Attenuation::default()
            },
            &signing.terminal_secret,
            auth::public_key_from_secret(&[74; 32]),
        )?
        .encode();
    assert!(
        guard
            .authorize_cold_fork_source(qualified.policies(), &restricted, "sdk")
            .await
            .is_err()
    );
    fixture.assert_no_content_io();
    Ok(())
}

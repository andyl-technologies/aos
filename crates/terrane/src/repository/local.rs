//! Opens and initializes actual local bucket repositories with sibling authority.

mod recovery;

use std::{os::unix::fs::MetadataExt, path::PathBuf, time::SystemTime};

use terrane_core::{
    cbor,
    chunking::ChunkProfile,
    properties::Domain,
    refs::{Commit, CommitSource, Locality, PrincipalKind, ProfilePair, Provenance},
    tree_builder::Tree,
    tree_format::{Property, TreeUse},
};

use crate::{
    bucket::{BucketBinding, FileBucket, FileBucketConfig, FileBucketPublicationConfig},
    guard::{Guard, GuardConfig},
    ref_advance::{CommitTiming, Coordinator, WriterSession},
    store::{Clock, LocalFs},
};

impl<S, C, F> Repository<S, C, F>
where
    S: crate::store::Store + Sync,
    C: Clock + Sync,
    F: LocalFs + Sync,
{
    /// Creates signing input for a guarded fork, merge, or fold operation.
    ///
    /// The supplied metadata describes the new commit. Tree, parents, recipe,
    /// and source receipts are recomputed by the coordinator from authenticated
    /// source history; this request has no caller-provided uploads.
    pub fn source_request(
        &self,
        authority: &LocalAuthority,
        metadata: CommitMetadata,
    ) -> crate::guard::CommitRequest {
        authority.commit_request(
            proposal(
                [0; 32],
                Vec::new(),
                metadata,
                &self.coordinator.guard().config().chunk_profile_name,
            ),
            "sdk".to_owned(),
        )
    }

    /// Imports a directory while preserving the current root's registered policy.
    ///
    /// Filesystem reads use the coordinator's binding. The current signed root
    /// supplies ACL, retention, domain, trust, and other properties; publication
    /// still performs fresh admission and fences concurrent reference changes.
    ///
    /// # Errors
    /// Rejects absent or denied current authority, unsupported filesystem or
    /// attribute requirements, invalid entries, failed imports, stale sessions,
    /// and failed durable publication.
    pub async fn commit_directory(
        &self,
        session: &mut WriterSession,
        directory: &std::path::Path,
        authority: &LocalAuthority,
        metadata: CommitMetadata,
    ) -> Result<terrane_core::refs::RefRecord, Error> {
        let guard = self.coordinator.guard();
        let snapshot = guard
            .read_snapshot(session.reference(), authority.token(), b"/", "sdk")
            .await?;
        let properties = {
            let tree = snapshot.evidence.tree(
                snapshot.evidence.root,
                self.chunk_profile().minimum() as u64,
            )?;
            tree.props()
                .unwrap_or_default()
                .iter()
                .map(|property| (property.name.to_owned(), property.value.to_vec()))
                .collect::<Vec<_>>()
        };
        let borrowed = properties
            .iter()
            .map(|(name, value)| Property { name, value })
            .collect::<Vec<_>>();
        let prepared = super::import_directory(
            self.coordinator.fs(),
            directory,
            self.chunk_profile(),
            &borrowed,
        )
        .await?;
        let current = session.record().ok_or(Error::Absent)?;
        let commit = proposal(
            prepared.root(),
            vec![current.commit],
            metadata,
            &guard.config().chunk_profile_name,
        );
        self.commit(
            session,
            prepared,
            authority.commit_request(commit, "sdk".to_owned()),
        )
        .await
    }
}

use super::{
    Error, LocalAuthority, LocalAuthorityIdentity, LocalAuthorityParameters, MetadataValidator,
    PreparedTree, Repository,
};

/// Locates a bucket and its distinct sibling signing authority.
pub struct LocalRepositoryLocation {
    /// Final bucket leaf, created exclusively by the backend.
    pub bucket: PathBuf,
    /// Private sibling directory holding existing seed and token formats.
    pub authority: PathBuf,
}

impl LocalRepositoryLocation {
    /// Resolves a local `file:///absolute/path` bucket URL and sibling authority.
    ///
    /// Percent escapes preserve Unix path bytes. Hosts, queries, fragments,
    /// malformed escapes, and NUL bytes are rejected; initialization and reopen
    /// subsequently validate absolute paths and sibling ownership.
    ///
    /// # Errors
    /// Rejects nonlocal or malformed file URLs and invalid path bytes.
    pub fn from_file_url(bucket: &str, authority: PathBuf) -> Result<Self, Error> {
        use std::os::unix::ffi::OsStringExt;

        let path = bucket.strip_prefix("file://").ok_or(Error::PathEscape)?;
        if !path.starts_with('/') || path.contains(['?', '#', '\\']) {
            return Err(Error::PathEscape);
        }
        let mut decoded = Vec::new();
        let mut remaining = path.as_bytes();
        while let Some((&first, tail)) = remaining.split_first() {
            if first == b'%' {
                let digits = tail.get(..2).ok_or(Error::PathEscape)?;
                if !digits.iter().all(u8::is_ascii_hexdigit) {
                    return Err(Error::PathEscape);
                }
                let digits = std::str::from_utf8(digits).map_err(|_| Error::PathEscape)?;
                decoded.push(u8::from_str_radix(digits, 16).map_err(|_| Error::PathEscape)?);
                remaining = &tail[2..];
            } else {
                decoded.push(first);
                remaining = tail;
            }
        }
        if decoded.contains(&0) {
            return Err(Error::PathEscape);
        }
        Ok(Self {
            bucket: std::ffi::OsString::from_vec(decoded).into(),
            authority,
        })
    }
}

/// Supplies explicit trusted local policy without extending configuration files.
pub struct LocalRepositoryPolicy {
    /// Instance authority store name used by registered root properties.
    pub store_name: String,
    /// Canonical disclosure domain physically assigned to this bucket.
    pub domain: String,
    /// Private scope used to authorize an absent-head bootstrap.
    pub default_private_domain: String,
    /// Initial explicit root ACL and trusted bootstrap ACL.
    pub acl: Vec<(String, u8)>,
    /// Locality captured by the initial authority record.
    pub locality: Locality,
    /// Validated publication window relative to collection grace.
    pub timing: CommitTiming,
    /// Separate current policy ref for fixed-commit targets, when configured.
    pub policy_authority: Option<String>,
    /// Additional registered bootstrap properties, such as `retain = forever`.
    pub bootstrap_properties: Vec<(String, Vec<u8>)>,
}

/// Supplies caller-owned claims for one unsigned local commit proposal.
pub struct CommitMetadata {
    /// Human-readable commit message.
    pub message: String,
    /// Process descriptor asserted by the committer.
    pub process: String,
    /// Registered production source category.
    pub source: CommitSource,
}

impl<F, C> Repository<FileBucket<F, C, MetadataValidator>, C, F>
where
    F: LocalFs + BucketBinding + Clone + Sync + 'static,
    C: Clock + BucketBinding + Clone + Sync + 'static,
    FileBucket<F, C, MetadataValidator>: Sync,
{
    /// Creates local authority, opens a fresh bucket, and publishes its initial commit.
    ///
    /// Only the backend creates the bucket leaf and its authoritative empty
    /// inventory. A failure leaves private partial state for inspection and
    /// never overwrites or silently reinitializes that state.
    ///
    /// # Errors
    /// Rejects existing or unsafe paths, invalid policy, unavailable entropy,
    /// incompatible backend records, denied bootstrap authority, and failed
    /// durable publication, preserving indeterminate CAS outcomes.
    pub async fn initialize_local(
        location: &LocalRepositoryLocation,
        authority_parameters: LocalAuthorityParameters,
        policy: LocalRepositoryPolicy,
        reference: &str,
        fs: F,
        clock: C,
    ) -> Result<(Self, LocalAuthority), Error> {
        validate_policy(&policy)?;
        validate_local_reference(reference)?;
        match fs.symlink_metadata(&location.bucket).await {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
            Ok(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "local bucket already exists",
                )
                .into());
            }
        }
        let owner_uid = authority_parameters.owner_uid;
        let authority = LocalAuthority::initialize(
            &fs,
            &location.bucket,
            &location.authority,
            authority_parameters,
        )
        .await?;
        let seed = fs
            .random_bytes(32)
            .await?
            .try_into()
            .map_err(|_| Error::Denied)?;
        let profile = ChunkProfile::cdc_1m(seed);
        let tree = initial_tree(&policy, profile.minimum() as u64)?;
        let root = tree.root();
        let repository = open_repository(
            location,
            &authority,
            policy,
            profile,
            fs,
            clock,
            RetentionSetup::Initialize(owner_uid),
        )
        .await?;
        validate_bucket_owner(repository.coordinator.fs(), &location.bucket, owner_uid).await?;
        let mut session = repository
            .begin(reference, authority.token(), "sdk")
            .await?;
        let commit = proposal(
            root,
            Vec::new(),
            CommitMetadata {
                message: "Initialize local repository".to_owned(),
                process: "sdk".to_owned(),
                source: CommitSource::Built,
            },
            "cdc-1m",
        );
        repository
            .commit(
                &mut session,
                tree,
                authority.commit_request(commit, "sdk".to_owned()),
            )
            .await?;
        Ok((repository, authority))
    }

    /// Reopens durable local state and verifies its existing authorized head.
    ///
    /// The seed is read from the protected immutable registered genesis, then
    /// the actual backend verifies that exact profile. Mutable capability caches
    /// do not select reopening authority. Missing heads or incomplete
    /// initialization do not become fresh empty repositories.
    ///
    /// # Errors
    /// Rejects unsafe ownership or permissions, invalid credentials, malformed
    /// capability records, missing committed authority, incompatible policy,
    /// and backend or authentication failures.
    pub async fn open_local(
        location: &LocalRepositoryLocation,
        identity: &LocalAuthorityIdentity,
        policy: LocalRepositoryPolicy,
        reference: &str,
        fs: F,
        clock: C,
    ) -> Result<(Self, LocalAuthority), Error> {
        validate_policy(&policy)?;
        validate_local_reference(reference)?;
        let now = clock
            .now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| Error::Denied)?
            .as_secs();
        let authority =
            LocalAuthority::open(&fs, &location.bucket, &location.authority, identity, now).await?;
        validate_bucket_owner(&fs, &location.bucket, identity.owner_uid).await?;
        // Mutable payload caches cannot select the seed used to reopen the
        // protected publication chain. Read its immutable registered genesis.
        let registered = crate::bucket::publication::registered_profile(
            &fs,
            &location.bucket,
            &FileBucketPublicationConfig {
                operator_uid: identity.owner_uid,
                control: None,
            },
        )
        .await?;
        let profile = ChunkProfile::cdc_1m(registered.seed);
        let repository = open_repository(
            location,
            &authority,
            policy,
            profile,
            fs,
            clock,
            RetentionSetup::Reopen(identity.owner_uid),
        )
        .await?;
        repository
            .coordinator
            .guard()
            .read_snapshot(reference, authority.token(), b"/", "sdk")
            .await?;
        Ok((repository, authority))
    }
}

/// Separates explicit trusted setup from fail-closed existing-state loading.
enum RetentionSetup {
    Initialize(u32),
    Reopen(u32),
}

async fn open_repository<F, C>(
    location: &LocalRepositoryLocation,
    authority: &LocalAuthority,
    policy: LocalRepositoryPolicy,
    profile: ChunkProfile,
    fs: F,
    clock: C,
    setup: RetentionSetup,
) -> Result<Repository<FileBucket<F, C, MetadataValidator>, C, F>, Error>
where
    F: LocalFs + BucketBinding + Clone + Sync + 'static,
    C: Clock + BucketBinding + Clone + Sync + 'static,
    FileBucket<F, C, MetadataValidator>: Sync,
{
    let (owner_uid, initialize) = match setup {
        RetentionSetup::Initialize(owner_uid) => (owner_uid, true),
        RetentionSetup::Reopen(owner_uid) => (owner_uid, false),
    };
    let (coordinator, namespace) =
        open_local_parts(location, authority, policy, profile, fs, clock, owner_uid).await?;
    if initialize {
        Repository::initialize_native_retention(
            coordinator,
            &namespace,
            &location.authority,
            owner_uid,
        )
        .await
    } else {
        Repository::reopen_native_retention(coordinator, &namespace, &location.authority, owner_uid)
            .await
    }
}

/// Constructs the exact local bindings without choosing a repository factory.
async fn open_local_parts<F, C>(
    location: &LocalRepositoryLocation,
    authority: &LocalAuthority,
    policy: LocalRepositoryPolicy,
    profile: ChunkProfile,
    fs: F,
    clock: C,
    owner_uid: u32,
) -> Result<
    (
        Coordinator<FileBucket<F, C, MetadataValidator>, C, F>,
        crate::domain::DomainNamespace,
    ),
    Error,
>
where
    F: LocalFs + BucketBinding + Clone + Sync + 'static,
    C: Clock + BucketBinding + Clone + Sync + 'static,
    FileBucket<F, C, MetadataValidator>: Sync,
{
    let bucket = FileBucket::open(
        FileBucketConfig {
            publication_control: Some(FileBucketPublicationConfig {
                operator_uid: owner_uid,
                control: None,
            }),
            root: location.bucket.clone(),
            chunk_profile_name: "cdc-1m".to_owned(),
            chunk_profile: profile.clone(),
            locality: policy.locality.clone(),
        },
        fs.clone(),
        clock.clone(),
        MetadataValidator::new(profile.clone()),
    )
    .await?;
    let namespace = crate::domain::DomainNamespace {
        root: location.bucket.clone(),
        domain: policy.domain.clone(),
    };
    let guard = Guard::new(
        bucket,
        clock,
        vec![authority.issuer_key().clone()],
        GuardConfig {
            store_name: policy.store_name,
            private_domain: policy.default_private_domain,
            home: policy.locality,
            initial_acl: policy.acl,
            min_chunk_size: profile.minimum() as u64,
            storage_domain: policy.domain,
            chunk_profile_name: "cdc-1m".to_owned(),
            chunk_profile: Box::new(profile),
            policy_authority: policy.policy_authority,
        },
    );
    let coordinator = Coordinator::new(guard, policy.timing, fs);

    Ok((coordinator, namespace))
}

fn validate_local_reference(reference: &str) -> Result<(), Error> {
    let name = terrane_core::refs::RefName::parse(reference).map_err(|_| Error::Unrealizable)?;
    if name.class() != terrane_core::refs::RefClass::Heads {
        return Err(Error::Unrealizable);
    }
    terrane_core::bucket::BucketKey::parse(reference).map_err(|_| Error::Unrealizable)?;
    Ok(())
}

fn validate_policy(policy: &LocalRepositoryPolicy) -> Result<(), Error> {
    if policy.store_name.is_empty()
        || !matches!(
            Domain::parse(&policy.default_private_domain),
            Ok(Domain::Private(_))
        )
        || Domain::parse(&policy.domain).is_err()
    {
        return Err(Error::Denied);
    }
    Ok(())
}

fn initial_tree(policy: &LocalRepositoryPolicy, minimum: u64) -> Result<PreparedTree, Error> {
    let mut acl = Vec::new();
    cbor::write_array(&mut acl, policy.acl.len());
    for (principal, verbs) in &policy.acl {
        cbor::write_array(&mut acl, 2);
        cbor::write_text(&mut acl, principal);
        cbor::write_uint(&mut acl, u64::from(*verbs));
    }
    let mut domain = Vec::new();
    cbor::write_text(&mut domain, &policy.domain);
    let mut properties = policy.bootstrap_properties.clone();
    properties.extend([
        ("acl".to_owned(), acl),
        ("domain".to_owned(), domain),
        ("durability".to_owned(), b"\x65local".to_vec()),
    ]);
    let borrowed = properties
        .iter()
        .map(|(name, value)| Property { name, value })
        .collect();
    let tree = Tree::build(Vec::new(), Some(borrowed), minimum, TreeUse::Ordinary)?;
    Ok(PreparedTree::from_tree(&tree)?)
}

async fn validate_bucket_owner<F: LocalFs + Sync>(
    fs: &F,
    bucket: &std::path::Path,
    owner_uid: u32,
) -> Result<(), Error> {
    let metadata = fs.symlink_metadata(bucket).await?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != owner_uid
        || metadata.mode() & 0o7777 != 0o700
    {
        return Err(Error::Denied);
    }
    Ok(())
}

/// Builds an unsigned proposal whose authority fields are supplied by the guard.
pub(super) fn proposal(
    root: [u8; 32],
    parents: Vec<[u8; 32]>,
    metadata: CommitMetadata,
    profile: &str,
) -> Commit {
    Commit {
        tree: root,
        parents,
        provenance: Provenance {
            issuer: String::new(),
            token_id: [0; 16],
            subject: String::new(),
            kind: PrincipalKind::Human,
            workload_identity: None,
            process: metadata.process,
            observed_at: 0,
            writer_epoch: 0,
            source: metadata.source,
            embedded_token: None,
        },
        timestamp: 0,
        message: metadata.message,
        profile_pair: ProfilePair {
            tree_format: 1,
            chunk_profile: profile.to_owned(),
            recipe: None,
            conflicted: None,
            lease: None,
            required_properties: None,
            entry_receipts: None,
            commit_context: None,
        },
        packs: None,
        signature: None,
    }
}

#[cfg(all(test, feature = "tokio"))]
#[allow(
    clippy::unwrap_used,
    reason = "bootstrap regression requires valid fixtures"
)]
mod tests {
    use super::*;
    use crate::store::{ContentStore, RefStore, TokioClock, TokioLocalFs};
    use std::os::unix::fs::PermissionsExt;
    use std::time::Duration;
    use terrane_core::auth::{Authority, Grant, Verbs};

    #[test]
    fn local_file_urls_preserve_escaped_path_bytes_and_reject_nonlocal_state() {
        let location = LocalRepositoryLocation::from_file_url(
            "file:///tmp/my%20store/bucket",
            PathBuf::from("/tmp/my store/authority"),
        )
        .unwrap();
        assert_eq!(location.bucket, PathBuf::from("/tmp/my store/bucket"));
        for invalid in [
            "file://remote/bucket",
            "https://example/bucket",
            "file:///tmp/%00",
            "file:///tmp/%+1",
            "file:///tmp/%xz",
            "file:///tmp/%",
            "file:///tmp/bucket?query",
            "file:///tmp/bucket#fragment",
        ] {
            assert!(
                LocalRepositoryLocation::from_file_url(invalid, PathBuf::from("/tmp/authority"))
                    .is_err()
            );
        }
    }

    #[tokio::test]
    async fn local_bootstrap_private_tree_passes_actual_guard_admission() {
        let fs = TokioLocalFs;
        let entropy = fs.random_bytes(16).await.unwrap();
        let suffix: String = entropy.iter().map(|byte| format!("{byte:02x}")).collect();
        let parent = std::env::temp_dir().join(format!("terrane-sdk-bootstrap-{suffix}"));
        fs.create_dir_new(&parent).await.unwrap();
        let owner_uid = fs.metadata(&parent).await.unwrap().uid();
        let location = LocalRepositoryLocation {
            bucket: parent.join("bucket"),
            authority: parent.join("authority"),
        };
        let authority = LocalAuthority::initialize(
            &fs,
            &location.bucket,
            &location.authority,
            LocalAuthorityParameters {
                owner_uid,
                authority: Authority {
                    issuer: "local".into(),
                    key_id: "initial".into(),
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
        )
        .await
        .unwrap();
        let policy = || LocalRepositoryPolicy {
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
        };
        let profile = ChunkProfile::cdc_1m([42; 32]);
        let prepared = initial_tree(&policy(), profile.minimum() as u64).unwrap();
        let tree = prepared.tree().unwrap();
        let effective = terrane_core::properties::resolve(
            &[terrane_core::properties::RootLayer {
                properties: tree.props().unwrap(),
                overrides: &[],
            }],
            terrane_core::properties::Defaults {
                store: "local",
                private_domain: "private:owner",
                home: "local",
            },
        )
        .unwrap();
        assert_eq!(
            crate::guard::domain_label(&effective).unwrap(),
            "private:owner"
        );
        drop(tree);
        let repository = open_repository(
            &location,
            &authority,
            policy(),
            profile,
            fs,
            TokioClock,
            RetentionSetup::Initialize(owner_uid),
        )
        .await
        .unwrap();
        assert_eq!(
            repository
                .coordinator
                .store()
                .ref_get("refs/heads/_/main")
                .await
                .unwrap(),
            None
        );
        let now = TokioClock
            .now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let token =
            terrane_core::auth::verify(authority.token(), &[authority.issuer_key().clone()], now)
                .unwrap();
        token
            .authorize(&terrane_core::auth::Request {
                reference: b"refs/heads/_/main",
                verb: terrane_core::auth::Verb::Commit,
                roots: &[terrane_core::auth::RequestRoot {
                    path: b"/",
                    domain: "private:owner",
                }],
                now,
                surface: "sdk",
                locality: &Locality::default(),
                epochs: &[("refs/heads/_/main", 0)],
            })
            .unwrap();
        let mut session = repository
            .begin("refs/heads/_/main", authority.token(), "sdk")
            .await
            .unwrap();
        let commit = proposal(
            prepared.root(),
            Vec::new(),
            CommitMetadata {
                message: "Initialize local repository".into(),
                process: "sdk".into(),
                source: CommitSource::Built,
            },
            "cdc-1m",
        );
        repository.retain_baseline(&session).await.unwrap();
        let mut candidate_request = authority.commit_request(commit.clone(), "sdk".into());
        candidate_request.uploads.extend(prepared.uploads.clone());
        let candidate = repository
            .coordinator
            .prepare_advance(&mut session, candidate_request)
            .await
            .unwrap();
        let retention = repository.local_retention.as_ref().unwrap();
        let association = super::super::local_authority::retention::CommitAssociation {
            commit: candidate.commit(),
            id: *retention.authority.id(),
            reference: session.reference().to_owned(),
            epoch: session.epoch(),
        };
        let candidate_identity = terrane_core::identity::TERRANE_V1
            .from_digest(
                terrane_core::identity::IdentityKind::Commit,
                &candidate.commit(),
            )
            .unwrap();
        let root_identity = terrane_core::identity::TERRANE_V1
            .from_digest(terrane_core::identity::IdentityKind::Node, &prepared.root())
            .unwrap();

        assert!(
            repository
                .coordinator
                .guard()
                .check_original_commit(candidate.baseline(), association.view())
                .await
                .is_err()
        );
        assert_eq!(
            repository
                .coordinator
                .store()
                .has(&[candidate_identity.clone(), root_identity.clone()])
                .await
                .unwrap(),
            vec![false, false]
        );

        let context = retention
            .retain_candidate(repository.coordinator.guard(), &fs, &candidate)
            .await
            .unwrap();
        fs.set_permissions_and_sync(&location.authority, std::fs::Permissions::from_mode(0o755))
            .await
            .unwrap();
        assert!(
            repository
                .coordinator
                .publish_prepared(&mut session, candidate, context)
                .await
                .is_err()
        );
        assert_eq!(
            repository
                .coordinator
                .store()
                .has(&[candidate_identity, root_identity])
                .await
                .unwrap(),
            vec![false, false]
        );
        assert!(
            repository
                .coordinator
                .store()
                .ref_get(session.reference())
                .await
                .unwrap()
                .is_none()
        );
        fs.set_permissions_and_sync(&location.authority, std::fs::Permissions::from_mode(0o700))
            .await
            .unwrap();

        let published = repository
            .commit(
                &mut session,
                prepared,
                authority.commit_request(commit, "sdk".into()),
            )
            .await
            .unwrap();

        let retention = repository.local_retention.as_ref().unwrap();
        let association = super::super::local_authority::retention::CommitAssociation {
            commit: published.commit,
            id: *retention.authority.id(),
            reference: session.reference().to_owned(),
            epoch: session.epoch(),
        };
        let retained = super::super::local_authority::retention::read::<
            _,
            super::super::local_authority::retention::CommitAssociation,
        >(&fs, &location.authority, owner_uid, &association.selector())
        .await
        .unwrap();
        assert_eq!(retained.commit, published.commit);
        assert_eq!(retained.epoch, session.epoch());
        assert_eq!(
            repository
                .coordinator
                .store()
                .ref_get(session.reference())
                .await
                .unwrap(),
            Some(published.clone())
        );

        let next = repository
            .begin(session.reference(), authority.token(), "sdk")
            .await
            .unwrap();
        assert_eq!(next.record(), Some(&published));
        assert_eq!(next.epoch(), published.writer_epoch + 1);
        repository.retain_baseline(&next).await.unwrap();
        let old_baseline = super::super::local_authority::retention::BootstrapRecord {
            id: *retention.authority.id(),
            reference: session.reference().to_owned(),
            epoch: session.epoch(),
            acl: policy().acl,
        };
        let old_path = location.authority.join(old_baseline.selector().unwrap());
        fs.remove_file(&old_path).await.unwrap();

        // A genuine new epoch may retain its own policy; it cannot fill an
        // earlier history gap, even while the old checked context remains cached.
        repository.retain_baseline(&next).await.unwrap();
        assert_eq!(
            fs.symlink_metadata(&old_path).await.unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
        assert!(
            repository
                .coordinator
                .guard()
                .read_snapshot(session.reference(), authority.token(), b"/", "sdk")
                .await
                .is_err()
        );
        assert!(
            repository
                .begin(session.reference(), authority.token(), "sdk")
                .await
                .is_err()
        );
        drop(repository);

        let identity = LocalAuthorityIdentity {
            issuer: "local".into(),
            key_id: "initial".into(),
            owner_uid,
        };
        let mut changed_configuration = policy();
        changed_configuration.acl = vec![("owner".into(), 7)];
        assert!(
            Repository::open_local(
                &location,
                &identity,
                changed_configuration,
                session.reference(),
                fs,
                TokioClock,
            )
            .await
            .is_err()
        );
        assert_eq!(
            fs.symlink_metadata(&old_path).await.unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
    }
    #[tokio::test]
    async fn local_directory_edit_preserves_canonical_implicit_owner_on_reopen() {
        let fs = TokioLocalFs;
        let entropy = fs.random_bytes(16).await.unwrap();
        let suffix: String = entropy.iter().map(|byte| format!("{byte:02x}")).collect();
        let parent = std::env::temp_dir().join(format!("terrane-sdk-implicit-owner-{suffix}"));
        fs.create_dir_new(&parent).await.unwrap();
        let owner_uid = fs.metadata(&parent).await.unwrap().uid();
        let location = LocalRepositoryLocation {
            bucket: parent.join("bucket"),
            authority: parent.join("authority"),
        };
        let authority = LocalAuthority::initialize(
            &fs,
            &location.bucket,
            &location.authority,
            LocalAuthorityParameters {
                owner_uid,
                authority: Authority {
                    issuer: "local".into(),
                    key_id: "initial".into(),
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
        )
        .await
        .unwrap();
        let mut policy = LocalRepositoryPolicy {
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
        };
        let profile = ChunkProfile::cdc_1m([42; 32]);
        let mut prepared = initial_tree(&policy, profile.minimum() as u64).unwrap();
        prepared
            .properties
            .as_mut()
            .unwrap()
            .retain(|(name, _)| name != "domain");
        let raw_root = PreparedTree::from_tree(&prepared.tree().unwrap()).unwrap();
        let owner = crate::domain::private_default(
            &terrane_core::identity::TERRANE_V1
                .from_digest(terrane_core::identity::IdentityKind::Node, &raw_root.root())
                .unwrap(),
        );
        policy.domain = owner.clone();
        policy.default_private_domain = "private:bootstrap-scope".into();
        let repository = open_repository(
            &location,
            &authority,
            LocalRepositoryPolicy {
                store_name: policy.store_name.clone(),
                domain: policy.domain.clone(),
                default_private_domain: policy.default_private_domain.clone(),
                acl: policy.acl.clone(),
                locality: policy.locality.clone(),
                timing: policy.timing,
                policy_authority: policy.policy_authority.clone(),
                bootstrap_properties: policy.bootstrap_properties.clone(),
            },
            profile,
            fs,
            TokioClock,
            RetentionSetup::Initialize(owner_uid),
        )
        .await
        .unwrap();
        let reference = "refs/heads/_/main";
        let mut session = repository
            .begin(reference, authority.token(), "sdk")
            .await
            .unwrap();
        let request = authority.commit_request(
            proposal(
                raw_root.root(),
                Vec::new(),
                CommitMetadata {
                    message: "Publish implicit initial ownership".into(),
                    process: "sdk-regression".into(),
                    source: CommitSource::Built,
                },
                "cdc-1m",
            ),
            "sdk".into(),
        );
        let first = repository
            .commit(&mut session, raw_root, request)
            .await
            .unwrap();

        let source = parent.join("source");
        fs.create_dir_new(&source).await.unwrap();
        fs.write_new(&source.join("file"), b"preserved ownership")
            .await
            .unwrap();
        let second = repository
            .commit_directory(
                &mut session,
                &source,
                &authority,
                CommitMetadata {
                    message: "Edit under original private ownership".into(),
                    process: "sdk-regression".into(),
                    source: CommitSource::Built,
                },
            )
            .await
            .unwrap();
        assert_ne!(first.commit, second.commit);
        let snapshot = repository
            .coordinator
            .guard()
            .read_snapshot(reference, authority.token(), b"/", "sdk")
            .await
            .unwrap();
        let tree = snapshot
            .evidence
            .tree(
                snapshot.evidence.root,
                repository.chunk_profile().minimum() as u64,
            )
            .unwrap();
        let mut encoded_owner = Vec::new();
        cbor::write_text(&mut encoded_owner, &owner);
        assert_eq!(
            tree.props()
                .unwrap()
                .iter()
                .find(|property| property.name == "domain")
                .unwrap()
                .value,
            encoded_owner
        );
        drop(tree);
        drop(snapshot);
        let registered_profile = repository.chunk_profile().clone();
        drop(repository);
        drop(authority);

        // Reopening must select the protected genesis profile before the
        // backend repairs a damaged mutable capabilities projection.
        let capabilities = location.bucket.join("CAPABILITIES");
        fs.remove_file(&capabilities).await.unwrap();
        fs.write_new(&capabilities, b"damaged capability cache")
            .await
            .unwrap();

        let identity = LocalAuthorityIdentity {
            issuer: "local".into(),
            key_id: "initial".into(),
            owner_uid,
        };
        let (repository, authority) =
            Repository::open_local(&location, &identity, policy, reference, fs, TokioClock)
                .await
                .unwrap();
        assert_eq!(repository.chunk_profile(), &registered_profile);
        let (commit, bytes) = repository
            .read_file(
                &terrane_core::surface::View::parse(reference).unwrap(),
                b"file",
                authority.token(),
                "sdk",
            )
            .await
            .unwrap();
        assert_eq!(commit, second.commit);
        assert_eq!(bytes, b"preserved ownership");
    }
}

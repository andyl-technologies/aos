//! Builds genuine native histories, side records and finite metadata proposals.

use std::collections::BTreeSet;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::Duration;

use crate::bucket::{FileBucket, FileBucketConfig, FileBucketPublicationConfig};
use crate::derived::AttributeCatalog;
use crate::domain::DomainNamespace;
use crate::guard::{
    AuthoringNamespaceProfile, Guard, HistoryObservation, RecordedNamespaceProfile,
    RecordedNamespaceProfiles, StagedUpload, TreeEvidence, invalid,
};
use crate::ref_advance::{CommitRequest, CommitTiming, Coordinator, WriterSession};
use crate::repository::{CommitReport, MetadataValidator, PreparedTree, Repository};
use crate::store::{
    ByteRange, ContentStore, ContentUpload, LocalFs, MetaUpload, StoreFailure, TokioClock,
    TokioFileLock, TokioLocalFs,
};
use terrane_core::{
    cbor,
    derived::{AttrRecord, AttributeValue},
    identity::{Digest, Identity, IdentityKind, TERRANE_V1},
    properties::semantics::associations::RecordedAssociation,
    refs::RefRecord,
    tree_builder::Tree,
    tree_format::{Entry, EntryKind, LeafItem, Property, TreeUse},
};

/// Preserves actual factory, storage and assertion setup failures.
pub(crate) type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
/// Uses the actual native schema validator and filesystem executor.
pub(in crate::guard) type Bucket = FileBucket<Fs, TokioClock, MetadataValidator>;
/// Publishes through genuine native Original and selected controls.
pub(in crate::guard) type NativeRepository = Repository<Bucket, TokioClock, Fs>;
/// Names the ordinary authored fixture ref.
pub(in crate::guard) const REFERENCE: &str = "refs/heads/_/main";
/// Provides plaintext before the measured metadata-only operation.
pub(super) const BODY: &[u8] = b"hello";
/// Uses the independently published SHA-256 literal for `hello`.
pub(super) const SHA256: Digest = [
    0x2c, 0xf2, 0x4d, 0xba, 0x5f, 0xb0, 0xa3, 0x0e, 0x26, 0xe8, 0x3b, 0x2a, 0xc5, 0xb9, 0xe2, 0x9e,
    0x1b, 0x16, 0x1e, 0x5c, 0x1f, 0xa7, 0x42, 0x5e, 0x73, 0x04, 0x33, 0x62, 0x93, 0x8b, 0x98, 0x24,
];

/// Delegates every real operation, with one scoped missing-ack fault.
#[derive(Clone, Default)]
pub(in crate::guard) struct Fs {
    /// Arms a test-only swallowed final acknowledgment, without a receiver factory.
    pub(super) swallow_ack: Arc<AtomicBool>,
    /// Counts actual mutation acknowledgment effects encountered while armed.
    pub(super) ack_hits: Arc<AtomicUsize>,
}

/// Retains independently installed profile and exact actual factory locations.
pub(in crate::guard) struct Fixture {
    /// Real repository used for preparation and signed durable checkpoints.
    pub(in crate::guard) repository: NativeRepository,
    /// Actual forwarding executor and its scoped failure observer.
    pub(super) fs: Fs,
    /// Actual configured Original directory, never caller-supplied evidence.
    pub(in crate::guard) control: PathBuf,
    config: FileBucketConfig,
    authoring: AuthoringNamespaceProfile,
    owner: u32,
    timing: CommitTiming,
}

fn timing() -> Result<CommitTiming, crate::ref_advance::AdvanceError> {
    CommitTiming::new(
        Duration::from_secs(30),
        Duration::from_secs(60),
        Duration::from_secs(10),
    )
}

impl Fixture {
    /// Initializes genuine active namespace inputs before signing or installing Guard.
    ///
    /// # Errors
    /// Preserves real native entropy, profile, storage and retention failures.
    /// # Panics
    /// Propagates assertions in the genuine shared seed fixture.
    pub(in crate::guard) async fn new() -> TestResult<Self> {
        Self::new_with_timing(timing()?).await
    }

    /// Initializes a genuine bucket-capacity fixture with an explicit publication policy.
    ///
    /// The six growing-population witnesses measure canonical maintenance work,
    /// rather than the default fixture's thirty-second publication capacity.
    /// This policy validates the recommended six-hour commit window against a
    /// twenty-four-hour grace window; it does not configure a separate collector.
    ///
    /// # Errors
    /// Preserves timing validation, real native factory, profile and retention failures.
    /// # Panics
    /// Propagates assertions in the genuine shared seed fixture.
    pub(in crate::guard) async fn new_capacity() -> TestResult<Self> {
        let timing = CommitTiming::new(
            Duration::from_secs(6 * 60 * 60),
            Duration::from_secs(24 * 60 * 60),
            Duration::from_secs(10),
        )?;
        Self::new_with_timing(timing).await
    }

    // Select the complete publication policy before any native factory writes.
    async fn new_with_timing(timing: CommitTiming) -> TestResult<Self> {
        let seed = crate::ref_advance::tests::fixture().await;
        let fs = Fs::default();
        let entropy = fs.random_bytes(16).await?;
        let suffix = entropy
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let root = std::env::temp_dir().join(format!("terrane-backfill-{suffix}"));
        let control = root.with_file_name(format!("terrane-backfill-{suffix}-original"));
        fs.create_dir_new(&control).await?;
        fs.set_permissions_and_sync(&control, std::fs::Permissions::from_mode(0o700))
            .await?;
        let owner = fs.symlink_metadata(&control).await?.uid();
        let guard_config = seed.guard().config().clone();
        let config = FileBucketConfig {
            root: root.clone(),
            publication_control: Some(FileBucketPublicationConfig {
                operator_uid: owner,
                control: None,
            }),
            chunk_profile_name: guard_config.chunk_profile_name.clone(),
            chunk_profile: (*guard_config.chunk_profile).clone(),
            locality: guard_config.home.clone(),
        };
        let validator = MetadataValidator::new(config.chunk_profile.clone());
        let bucket = FileBucket::open(config.clone(), fs.clone(), TokioClock, validator).await?;
        let authoring = AuthoringNamespaceProfile::new(3, 3, &[], 2)?;
        let guard = Guard::new_active(
            bucket,
            TokioClock,
            seed.guard().keys().to_vec(),
            guard_config,
        )
        .with_recorded_authoring(
            authoring.clone().context().clone(),
            authoring.clone().registries().attribute_revision,
        )?;
        let repository = Repository::initialize_native_retention(
            Coordinator::new(guard, timing, fs.clone()),
            &DomainNamespace {
                root,
                domain: "public".into(),
            },
            &control,
            owner,
        )
        .await?;
        Ok(Self {
            repository,
            fs,
            control,
            config,
            authoring,
            owner,
            timing,
        })
    }

    /// Publishes an actual earlier file producer before requirements are installed.
    ///
    /// # Errors
    /// Preserves genuine body upload, admission and durable publication failures.
    /// # Panics
    /// Propagates the shared canonical unsigned fixture assertions.
    pub(super) async fn publish(&self, grafts: bool) -> TestResult<RefRecord> {
        self.publish_impl(grafts, false).await
    }

    /// Publishes two actual occurrences with one already canonical inline value.
    ///
    /// # Errors
    /// Preserves genuine upload, signed admission and publication failures.
    /// # Panics
    /// Propagates shared unsigned fixture assertions.
    pub(super) async fn partial(&self) -> TestResult<RefRecord> {
        self.publish_impl(false, true).await
    }

    async fn publish_impl(&self, grafts: bool, partial: bool) -> TestResult<RefRecord> {
        let mut request = crate::ref_advance::tests::request_file(Vec::new(), BODY);
        let tree = {
            let evidence = TreeEvidence::load_tree(
                self.repository.coordinator().guard().store(),
                request.commit.tree,
                &request.uploads,
                262144,
            )
            .await?;
            let source = evidence.tree(evidence.root, 262144)?;
            let inline = AttributeValue::Sha256(SHA256).encode()?;
            let mut items = source.iter().cloned().collect::<Vec<_>>();
            if partial {
                let mut second = items.first().cloned().ok_or_else(invalid)?;
                second.key = b"other".to_vec();
                items.push(second);
                let first = items.first_mut().ok_or_else(invalid)?;
                first
                    .entry
                    .attrs
                    .push(terrane_core::tree_format::Attribute {
                        name: "hash.sha256",
                        value: &inline,
                    });
                first
                    .entry
                    .attrs
                    .sort_by(|left, right| left.name.cmp(right.name));
            }
            if grafts {
                let child = Tree::build(items.clone(), None, 262144, TreeUse::Ordinary)?;
                for key in [b"a".as_slice(), b"b".as_slice()] {
                    items.push(LeafItem {
                        key: key.to_vec(),
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
                items.sort_by(|left, right| left.key.cmp(&right.key));

                request
                    .uploads
                    .extend(child.nodes().map(|node| StagedUpload::Meta {
                        kind: IdentityKind::Node,
                        bytes: node.encoded().to_vec(),
                    }));
            }
            let tree = Tree::build(
                items,
                source.props().map(<[_]>::to_vec),
                262144,
                TreeUse::Ordinary,
            )?;
            PreparedTree::from_tree(&tree)?
        };
        request.commit.tree = tree.root();
        request.uploads.retain(|upload| !matches!(upload, StagedUpload::Meta { kind: IdentityKind::Node, bytes } if TERRANE_V1.calculate(IdentityKind::Node, bytes).is_ok_and(|identity| identity.terrane_v1_digest().is_ok_and(|root| root == request.commit.tree))));
        let mut session = self
            .repository
            .begin(REFERENCE, &request.token, &request.surface)
            .await?;
        Ok(self.repository.commit(&mut session, tree, request).await?)
    }

    // Keeps ordinary signed-data construction separate from its one native
    // upload, so negative variants need not publish an intermediate record.
    async fn side_bytes(
        &self,
        producer: Digest,
        value: AttributeValue,
        valid: bool,
    ) -> TestResult<Vec<u8>> {
        let object = TERRANE_V1
            .calculate(IdentityKind::Chunk, BODY)?
            .terrane_v1_digest()?;
        let history = self
            .repository
            .coordinator()
            .guard()
            .verified_history(producer)
            .await?;
        let verified = history.commit(&producer).ok_or_else(invalid)?;
        let mut record = AttrRecord::new(object, value, producer);
        record.sign(
            verified,
            &crate::ref_advance::tests::request(Vec::new()).terminal_secret,
        )?;
        if !valid && let Some(signature) = &mut record.signature {
            signature[0] ^= 1;
        }
        Ok(record.encode()?)
    }

    /// Signs and publishes a real detached record through the native Attribute validator.
    ///
    /// # Errors
    /// Preserves genuine completed history, terminal signature and native upload failures.
    /// # Panics
    /// Propagates shared unsigned metadata fixture assertions.
    pub(super) async fn side(
        &self,
        producer: Digest,
        value: AttributeValue,
        valid: bool,
    ) -> TestResult<(Identity, Vec<u8>)> {
        let bytes = self.side_bytes(producer, value, valid).await?;
        let identity = self
            .repository
            .coordinator()
            .guard()
            .store()
            .put(ContentUpload::Meta(MetaUpload::new(
                IdentityKind::Attribute,
                &bytes,
            )?))
            .await?;
        Ok((identity, bytes))
    }

    /// Retains independently framed unsupported or dangling ordinary record data.
    ///
    /// # Errors
    /// Preserves actual prior producer verification, catalog, schema upload and
    /// exact stored-body read failures.
    /// # Panics
    /// Panics when the owned fixture already has Attribute records, or the
    /// final published catalog and body differ from the single prepared variant.
    /// Propagates the genuine unsigned key fixture assertions.
    pub(super) async fn side_variant(&self, producer: Digest, unavailable: bool) -> TestResult {
        let bucket = self.repository.coordinator().guard().store();
        assert!(bucket.attribute_identities().await?.is_empty());
        let bytes = self
            .side_bytes(producer, AttributeValue::Sha256(SHA256), false)
            .await?;
        let mut record = AttrRecord::decode(&bytes)?;
        if unavailable {
            record.producer = TERRANE_V1
                .calculate(IdentityKind::Commit, b"unpublished producer negative")?
                .terrane_v1_digest()?;
        } else {
            record.function.version = "unregistered-version".into();
        }
        let bytes = record.encode()?;
        let identity = bucket
            .put(ContentUpload::Meta(MetaUpload::new(
                IdentityKind::Attribute,
                &bytes,
            )?))
            .await?;
        assert_eq!(bucket.get(&identity, None).await?, bytes);
        assert_eq!(bucket.attribute_identities().await?, vec![identity]);
        Ok(())
    }

    /// Makes a metadata-only unsigned template from the actual current signed view.
    ///
    /// # Errors
    /// Preserves actual ref and signed commit/history failures.
    /// # Panics
    /// Propagates shared unsigned metadata fixture assertions.
    pub(super) async fn template(&self) -> TestResult<(WriterSession, CommitRequest)> {
        let token = crate::ref_advance::tests::token();
        let session = self.repository.begin(REFERENCE, &token, "sdk").await?;
        let current = session.record().ok_or_else(invalid)?;
        let history = self
            .repository
            .coordinator()
            .guard()
            .verified_history(current.commit)
            .await?;
        let commit = history.commit(&current.commit).ok_or_else(invalid)?;
        let mut request = crate::ref_advance::tests::request(vec![current.commit]);
        request.commit.tree = commit.commit().tree;
        request.uploads.clear();
        Ok((session, request))
    }

    /// Installs requirements or current policy using the actual unchanged file namespace.
    ///
    /// # Errors
    /// Preserves actual source history, canonical mutation, admission and publication failures.
    /// # Panics
    /// Propagates shared metadata-template assertions.
    pub(super) async fn policy(
        &self,
        indexes: &[&str],
        acl: Option<u64>,
        trust: Option<Vec<u8>>,
    ) -> TestResult<CommitReport> {
        let (mut session, mut request) = self.template().await?;
        let guard = self.repository.coordinator().guard();
        let evidence =
            TreeEvidence::load_tree(guard.store(), request.commit.tree, &[], 262144).await?;
        let prepared = {
            let source = evidence.tree(evidence.root, 262144)?;
            let mut names = Vec::new();
            cbor::write_array(&mut names, indexes.len());
            for name in indexes {
                cbor::write_text(&mut names, name);
            }
            let mut grant = vec![0x81, 0x82, 0x66];
            grant.extend_from_slice(b"writer");
            cbor::write_uint(&mut grant, acl.unwrap_or(31));
            let mut properties = source.props().unwrap_or_default().to_vec();
            properties.retain(|property| {
                property.name != "index"
                    && (acl.is_none() || property.name != "acl")
                    && (trust.is_none() || property.name != "trust")
            });
            properties.push(Property {
                name: "index",
                value: &names,
            });
            if acl.is_some() {
                properties.push(Property {
                    name: "acl",
                    value: &grant,
                });
            }
            if let Some(trust) = &trust {
                properties.push(Property {
                    name: "trust",
                    value: trust,
                });
            }
            let tree = Tree::build(
                source.iter().cloned().collect(),
                Some(properties),
                262144,
                TreeUse::Ordinary,
            )?;
            PreparedTree::from_tree(&tree)?
        };
        request.commit.tree = prepared.root();
        Ok(self
            .repository
            .commit_with_report(&mut session, prepared, request)
            .await?)
    }

    /// Installs a genuine bound gap index before the finite incremental backfill.
    ///
    /// # Errors
    /// Preserves exact source, canonical construction and normal signed publication failures.
    /// # Panics
    /// Propagates assertions in the shared unsigned template fixture.
    pub(super) async fn bound_requirement(&self) -> TestResult<CommitReport> {
        use std::collections::BTreeMap;
        use terrane_core::indexing::{
            IndexEvaluationRecipe, carrier::SemanticContext, completion, incremental, maintenance,
        };
        let (mut session, mut request) = self.template().await?;
        let guard = self.repository.coordinator().guard();
        let evidence =
            TreeEvidence::load_tree(guard.store(), request.commit.tree, &[], 262144).await?;
        let prepared = {
            let source = evidence.tree(evidence.root, 262144)?;
            let mut names = Vec::new();
            cbor::write_array(&mut names, 1);
            cbor::write_text(&mut names, "hash.sha256");
            let mut properties = source.props().unwrap_or_default().to_vec();
            properties.retain(|property| property.name != "index");
            properties.push(Property {
                name: "index",
                value: &names,
            });
            let source = Tree::build(
                source.iter().cloned().collect(),
                Some(properties),
                262144,
                TreeUse::Ordinary,
            )?;
            let owner = source.root_identity();
            let graph = BTreeMap::from([(owner, source)]);
            let context = SemanticContext::new(3, 2, 1)?;
            let arena = maintenance::ByteArena::new(usize::MAX)?;
            let recipe = IndexEvaluationRecipe::new(owner, "hash.sha256")?;
            let source = incremental::PreparedSource::new(&recipe, &graph, 262144, context)?;
            let (initialized, _) =
                maintenance::initialize(&recipe, &source, &arena, 262144, context)?;
            let (data, _) = initialized.materialize()?;
            let completed = completion::complete(
                owner,
                &graph,
                &[completion::Selection {
                    attribute: "hash.sha256",
                    data: &data,
                }],
                &arena,
                262144,
                context,
                completion::MemoPolicy::Omit,
            )?;
            let mut prepared = PreparedTree::from_tree(&completed.owner.tree)?;
            let existing = prepared
                .uploads
                .iter()
                .filter_map(|upload| match upload {
                    StagedUpload::Meta {
                        kind: IdentityKind::Node,
                        bytes,
                    } => Some(bytes.clone()),
                    _ => None,
                })
                .collect::<BTreeSet<_>>();
            prepared.uploads.extend(
                data.nodes
                    .into_values()
                    .filter(|bytes| !existing.contains(bytes))
                    .map(|bytes| StagedUpload::Meta {
                        kind: IdentityKind::Node,
                        bytes,
                    }),
            );
            prepared
        };
        request.commit.tree = prepared.root();
        Ok(self
            .repository
            .commit_with_report(&mut session, prepared, request)
            .await?)
    }

    /// Reopens independently retained historical profiles and actual native Original controls.
    ///
    /// # Errors
    /// Preserves genuine profile, native reopen and Original compatibility failures.
    /// # Panics
    /// Panics if completed factory context differs from the independently installed profile.
    pub(in crate::guard) async fn reopen(&self) -> TestResult<NativeRepository> {
        let old = self.repository.coordinator().guard();
        let mut views = std::collections::BTreeSet::new();
        views.extend(
            old.original_commits
                .read()
                .map_err(|_| invalid())?
                .keys()
                .copied(),
        );
        let inputs = self.authoring.registries();
        let context = self.authoring.context().clone();
        let mut profiles = Vec::new();
        for view in views {
            let (verified, _) = old
                .verified_tree_history_observed(view, HistoryObservation::default())
                .await?;
            let association =
                RecordedAssociation::new(view, verified.commit.commit().tree, context.clone());
            let (selected, actual) =
                old.selected_view_profile(&verified.commit, HistoryObservation::default())?;
            assert_eq!(&actual, inputs);
            match selected {
                crate::guard::recorded_properties::SelectedReadInterpretation::Recorded(actual) => {
                    assert_eq!(actual.as_ref(), &association)
                }
                crate::guard::recorded_properties::SelectedReadInterpretation::Legacy => {
                    return Err(StoreFailure::new(crate::store::StoreErrorKind::Unsupported).into());
                }
            }
            profiles.push(RecordedNamespaceProfile::new(
                association,
                inputs.attribute_revision,
            )?);
        }
        let bucket = FileBucket::open(
            self.config.clone(),
            self.fs.clone(),
            TokioClock,
            MetadataValidator::new(self.config.chunk_profile.clone()),
        )
        .await?;
        let guard = Guard::new_active(
            bucket,
            TokioClock,
            old.keys().to_vec(),
            old.config().clone(),
        )
        .with_recorded_authoring(
            self.authoring.clone().context().clone(),
            self.authoring.clone().registries().attribute_revision,
        )?
        .with_recorded_namespace_profiles(RecordedNamespaceProfiles::new(profiles)?)?;
        Ok(Repository::reopen_native_retention(
            Coordinator::new(guard, self.timing, self.fs.clone()),
            &DomainNamespace {
                root: self.config.root.clone(),
                domain: "public".into(),
            },
            &self.control,
            self.owner,
        )
        .await?)
    }
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl LocalFs for Fs {
    type Lock = TokioFileLock;

    fn retain_native_exclusion(
        &self,
        held: &Self::Lock,
    ) -> std::io::Result<crate::store::NativeExclusion> {
        TokioLocalFs.retain_native_exclusion(held)
    }

    async fn initialize_publication(
        &self,
        request: crate::store::NativePublicationInitialization,
    ) -> Result<crate::store::NativePublicationInitializationOutcome, crate::store::StoreFailure>
    {
        TokioLocalFs.initialize_publication(request).await
    }

    async fn execute_retained_effect(
        &self,
        effect: crate::store::NativeFsEffect,
    ) -> Result<(), crate::store::NativeEffectFailure> {
        if self.swallow_ack.load(Ordering::SeqCst)
            && matches!(
                effect.fault_probe(),
                crate::store::EffectFaultProbe::SealMutationPublication(_)
            )
        {
            self.ack_hits.fetch_add(1, Ordering::SeqCst);
            return Ok(());
        }
        TokioLocalFs.execute_retained_effect(effect).await
    }

    async fn random_bytes(&self, length: usize) -> std::io::Result<Vec<u8>> {
        TokioLocalFs.random_bytes(length).await
    }

    async fn lock_exclusive(&self, path: &Path) -> std::io::Result<Self::Lock> {
        TokioLocalFs.lock_exclusive(path).await
    }

    async fn lock_existing_exclusive(&self, path: &Path) -> std::io::Result<Self::Lock> {
        TokioLocalFs.lock_existing_exclusive(path).await
    }

    async fn try_lock_existing_shared(&self, path: &Path) -> std::io::Result<Self::Lock> {
        TokioLocalFs.try_lock_existing_shared(path).await
    }

    async fn try_lock_existing_exclusive(&self, path: &Path) -> std::io::Result<Self::Lock> {
        TokioLocalFs.try_lock_existing_exclusive(path).await
    }

    async fn read(&self, path: &Path) -> std::io::Result<Vec<u8>> {
        TokioLocalFs.read(path).await
    }

    async fn read_nofollow(&self, path: &Path) -> std::io::Result<Vec<u8>> {
        TokioLocalFs.read_nofollow(path).await
    }

    async fn read_ordinary_record(
        &self,
        read: crate::store::NativeOrdinaryRead,
    ) -> std::io::Result<Option<crate::store::NativeOrdinaryRecord>> {
        TokioLocalFs.read_ordinary_record(read).await
    }

    async fn read_payload_ranges(
        &self,
        read: crate::store::NativePayloadRangeRead,
    ) -> std::io::Result<Option<crate::store::NativePayloadRangeRecord>> {
        // Forward the same sealed read to the actual native binding. Declining
        // this capability would exercise fallback rather than this fixture's
        // ordinary retained read and physical closing path.
        TokioLocalFs.read_payload_ranges(read).await
    }

    async fn read_protected_record(
        &self,
        read: crate::store::NativeProtectedRead,
    ) -> Result<Option<crate::store::NativeProtectedRecord>, crate::store::StoreFailure> {
        TokioLocalFs.read_protected_record(read).await
    }

    async fn read_range(&self, path: &Path, range: ByteRange) -> std::io::Result<Vec<u8>> {
        TokioLocalFs.read_range(path, range).await
    }

    async fn write_new(&self, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
        TokioLocalFs.write_new(path, bytes).await?;
        Ok(())
    }

    async fn create_dir_all(&self, path: &Path) -> std::io::Result<()> {
        TokioLocalFs.create_dir_all(path).await
    }

    async fn create_dir_new(&self, path: &Path) -> std::io::Result<()> {
        TokioLocalFs.create_dir_new(path).await
    }

    async fn read_dir(&self, path: &Path) -> std::io::Result<Vec<PathBuf>> {
        TokioLocalFs.read_dir(path).await
    }

    async fn metadata(&self, path: &Path) -> std::io::Result<std::fs::Metadata> {
        TokioLocalFs.metadata(path).await
    }

    async fn symlink_metadata(&self, path: &Path) -> std::io::Result<std::fs::Metadata> {
        TokioLocalFs.symlink_metadata(path).await
    }

    async fn symlink_metadata_batch(
        &self,
        paths: &[PathBuf],
    ) -> std::io::Result<Vec<std::io::Result<std::fs::Metadata>>> {
        TokioLocalFs.symlink_metadata_batch(paths).await
    }

    async fn remove_file(&self, path: &Path) -> std::io::Result<()> {
        TokioLocalFs.remove_file(path).await
    }

    async fn remove_dir(&self, path: &Path) -> std::io::Result<()> {
        TokioLocalFs.remove_dir(path).await
    }

    async fn rename(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        TokioLocalFs.rename(from, to).await
    }

    async fn rename_no_replace(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        TokioLocalFs.rename_no_replace(from, to).await
    }

    async fn sync_file(&self, path: &Path) -> std::io::Result<()> {
        TokioLocalFs.sync_file(path).await
    }

    async fn sync_file_nofollow(
        &self,
        path: &Path,
        expected: &std::fs::Metadata,
    ) -> std::io::Result<std::fs::Metadata> {
        TokioLocalFs.sync_file_nofollow(path, expected).await
    }

    async fn sync_directory(&self, path: &Path) -> std::io::Result<()> {
        TokioLocalFs.sync_directory(path).await
    }

    async fn set_permissions(
        &self,
        path: &Path,
        permissions: std::fs::Permissions,
    ) -> std::io::Result<()> {
        TokioLocalFs.set_permissions(path, permissions).await
    }

    async fn set_permissions_and_sync(
        &self,
        path: &Path,
        permissions: std::fs::Permissions,
    ) -> std::io::Result<()> {
        TokioLocalFs
            .set_permissions_and_sync(path, permissions)
            .await
    }

    async fn read_link(&self, path: &Path) -> std::io::Result<PathBuf> {
        TokioLocalFs.read_link(path).await
    }

    async fn list_xattrs(&self, path: &Path) -> std::io::Result<Vec<std::ffi::OsString>> {
        TokioLocalFs.list_xattrs(path).await
    }

    async fn get_xattr(
        &self,
        path: &Path,
        name: &std::ffi::OsStr,
    ) -> std::io::Result<Option<Vec<u8>>> {
        TokioLocalFs.get_xattr(path, name).await
    }
}

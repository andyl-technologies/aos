//! Builds real signed source payloads and independently initialized local copies.
//!
//! Portable copy candidates are untrusted data. Destination registration,
//! Guard installation, collector leases and first ownership all use production
//! factories; no source Original association or native receipt is copied.

use super::fs::CopiedFs;
use super::indexed;
use crate::bucket::{FileBucket, FileBucketConfig, held::SingleHeld};
use crate::domain::DomainNamespace;
use crate::gc::runner::copied_retirement::CopiedRetirement;
use crate::gc::runner::fixture::Fixture;
use crate::guard::{Guard, OriginalAuthority};
use crate::pack::{EntryKind, PackClass, PackId, PackWriter};
use crate::ref_advance::{CommitTiming, Coordinator};
use crate::repository::{
    MetadataValidator, Repository,
    local_authority::retention::{self, RegistrationRecord},
};
use crate::store::{Clock, ContentStore, ContentUpload, LocalFs, MetaUpload, NativeEffectClock};
use std::collections::BTreeMap;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::Path;
use std::time::Duration;
use terrane_format::bucket::{
    BucketCapabilities, GenerationManifest, PackExclusion, PackInventoryEntry,
};
use terrane_format::gc::publication::{
    PermanentOwnerSelection, PortableCurrent, PortableSnapshot, ProjectionEntry, SelectedHistory,
};
use terrane_format::gc::retirement::{PermanentDeleteAuthorization, PermanentDeleteOperation};
use terrane_format::gc::{Tombstone, Windows};
use terrane_format::identity::{IdentityKind, TERRANE_V1};

/// Names the actual independently opened destination bucket.
pub(crate) type Bucket = FileBucket<CopiedFs, NativeEffectClock, MetadataValidator>;
/// Names its production repository and actual delegated native executor.
pub(crate) type NativeRepository = Repository<Bucket, NativeEffectClock, CopiedFs>;

/// Selects actual copied old-family residues without assigning them creator age.
#[derive(Clone, Copy)]
pub(crate) enum Residue {
    /// Only the copied old data pack is present.
    Pack,
    /// Only the copied old pack index is present.
    Index,
    /// Only an unrelated old Trash record is present.
    Trash,
    /// No copied old-family artifact is present.
    Absent,
    /// No old-family artifact or active source exclusion binding is present.
    AbsentWithoutExclusion,
}

/// Owns a real destination and retains independently signed source evidence.
pub(crate) struct CopiedFixture {
    /// Genuinely published source, whose Original is never destination permission.
    pub(crate) source: Fixture,
    /// Production destination repository with independently protected controls.
    pub(crate) repository: NativeRepository,
    /// Actual destination registration checked by the configured Guard.
    pub(crate) authority: OriginalAuthority,
    /// Burned copied pack named by the requested first-ownership operation.
    pub(crate) pack: PackId,
    /// Canonical old Trash bytes, retained solely as a collision/preservation input.
    pub(crate) old_trash: Vec<u8>,
    /// Exact independently configured destination, retained unchanged for reopening.
    config: FileBucketConfig,
    // Exact owning source Guard exports are ordinary configuration, not Original permission.
    selections: Vec<crate::guard::ViewSelection>,
}

/// Copies real temporary payload files without importing protected authority.
///
/// # Panics
/// Panics on inaccessible source entries, symlinks or failed temporary writes.
async fn copy_payload(source: &Path, target: &Path) {
    let mut directories = vec![(source.to_owned(), target.to_owned())];
    while let Some((source, target)) = directories.pop() {
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&target)
            .unwrap();
        let mut entries = tokio::fs::read_dir(source).await.unwrap();
        while let Some(entry) = entries.next_entry().await.unwrap() {
            let path = target.join(entry.file_name());
            let kind = entry.file_type().await.unwrap();
            assert!(!kind.is_symlink());
            if kind.is_dir() {
                directories.push((entry.path(), path));
            } else {
                assert!(kind.is_file());
                tokio::fs::copy(entry.path(), path).await.unwrap();
            }
        }
    }
}

/// Encodes an untrusted copy candidate from independently observed source data.
///
/// # Panics
/// Panics on malformed source history, unavailable entropy or failed writes.
async fn copy_checkpoint(
    root: &Path,
    logical: &BTreeMap<String, Option<Vec<u8>>>,
    fs: &impl LocalFs,
) {
    let origin =
        SelectedHistory::decode(logical["publication/SELECTED-HISTORY"].as_deref().unwrap())
            .unwrap()
            .origin;
    let bytes = PortableSnapshot {
        revision: 0,
        origin,
        predecessor: None,
        projection: logical
            .iter()
            .map(|(key, value)| ProjectionEntry {
                key: key.clone(),
                value: value.clone(),
            })
            .collect(),
    }
    .encode()
    .unwrap();
    let nonce = fs.random_bytes(32).await.unwrap();
    let suffix: String = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
    let pointer = PortableCurrent {
        key: format!("publication/snapshots/0:{suffix}"),
        digest: *blake3::hash(&bytes).as_bytes(),
    };
    tokio::fs::write(root.join(&pointer.key), bytes)
        .await
        .unwrap();
    tokio::fs::write(root.join("publication/PORTABLE"), pointer.encode().unwrap())
        .await
        .unwrap();
}

impl CopiedFixture {
    /// Publishes an actual signed source then initializes an independent copied destination.
    ///
    /// # Panics
    /// Panics when real source publication, canonical copied candidate construction,
    /// destination activation or independent protected Guard installation fails.
    pub(crate) async fn new(residue: Residue) -> Self {
        Self::with_old_body(residue, b"unreachable copied old body", (false, false))
            .await
            .0
    }

    /// Copies a burned old family containing the source's genuinely published chunk.
    ///
    /// # Panics
    /// Panics when real publication or independent copied destination setup fails.
    pub(crate) async fn with_live_old_fallback() -> Self {
        Self::with_old_body(Residue::Pack, b"published source", (false, false))
            .await
            .0
    }

    /// Adds an unrelated canonical copied retirement claim before native activation.
    ///
    /// The returned exclusion describes actual constructed pack/index inventory,
    /// not creator age, Original permission or a permanent deletion owner.
    ///
    /// # Panics
    /// Panics on real source admission, copied candidate setup or native activation.
    pub(crate) async fn new_with_unrelated_retirement(residue: Residue) -> (Self, PackExclusion) {
        let (fixture, exclusion, _) =
            Self::with_old_body(residue, b"unreachable copied old body", (true, false)).await;
        (fixture, exclusion.unwrap())
    }

    /// Copies a genuinely published indexed head and an unused canonical Memo.
    ///
    /// # Panics
    /// Panics on genuine indexed source publication or independent copied activation.
    pub(super) async fn with_indexed_memo() -> (Self, indexed::Observation) {
        let (fixture, _, observation) = Self::with_old_body(
            Residue::Absent,
            b"unreachable copied old body",
            (false, true),
        )
        .await;
        (fixture, observation.unwrap())
    }

    async fn with_old_body(
        residue: Residue,
        old_body: &[u8],
        options: (bool, bool),
    ) -> (Self, Option<PackExclusion>, Option<indexed::Observation>) {
        let (unrelated, with_indexed) = options;
        let (source, selections, observation) = if with_indexed {
            let setup = indexed::source().await;
            (setup.fixture, setup.selections, Some(setup.observation))
        } else {
            (Fixture::new().await, Vec::new(), None)
        };
        let old = PackId::generate(&source.fs).await.unwrap();
        let mut writer = PackWriter::new(old, PackClass::Data, false);
        writer.append_raw(EntryKind::Chunk, old_body).unwrap();
        let sealed = writer.seal().unwrap();
        let index = sealed.index_object();
        // The copied inventory retains a real canonical detached index alias,
        // even when the old family's physical pack and index are absent.
        source
            .guard()
            .store()
            .put(ContentUpload::Meta(
                MetaUpload::new(IdentityKind::Index, index).unwrap(),
            ))
            .await
            .unwrap();

        let inventory = PackInventoryEntry {
            pack_id: *old.as_bytes(),
            pack_hash: TERRANE_V1
                .calculate(IdentityKind::Pack, sealed.bytes())
                .unwrap()
                .terrane_v1_digest()
                .unwrap(),
            pack_size: sealed.bytes().len() as u64,
            index_hash: TERRANE_V1
                .calculate(IdentityKind::Index, index)
                .unwrap()
                .terrane_v1_digest()
                .unwrap(),
            index_size: index.len() as u64,
        };
        let extra = if unrelated {
            let pack = PackId::generate(&source.fs).await.unwrap();
            let mut writer = PackWriter::new(pack, PackClass::Data, false);
            writer
                .append_raw(EntryKind::Chunk, b"independent unrelated copied residue")
                .unwrap();
            let sealed = writer.seal().unwrap();
            let index = sealed.index_object();
            source
                .guard()
                .store()
                .put(ContentUpload::Meta(
                    MetaUpload::new(IdentityKind::Index, index).unwrap(),
                ))
                .await
                .unwrap();
            let inventory = PackInventoryEntry {
                pack_id: *pack.as_bytes(),
                pack_hash: TERRANE_V1
                    .calculate(IdentityKind::Pack, sealed.bytes())
                    .unwrap()
                    .terrane_v1_digest()
                    .unwrap(),
                pack_size: sealed.bytes().len() as u64,
                index_hash: TERRANE_V1
                    .calculate(IdentityKind::Index, index)
                    .unwrap()
                    .terrane_v1_digest()
                    .unwrap(),
                index_size: index.len() as u64,
            };
            Some((
                inventory,
                PackExclusion {
                    pack_id: *pack.as_bytes(),
                    cycle: 11,
                    epoch: 4,
                },
            ))
        } else {
            None
        };
        let mut logical = {
            let holder = SingleHeld::acquire(source.guard().store()).await.unwrap();
            let held = holder.destination();
            held.observe_publication_unrepaired()
                .await
                .unwrap()
                .logical()
                .clone()
        };
        let mut config = source.config.clone();
        config.root = source.parent.join("copied-bucket");
        config.publication_control.as_mut().unwrap().control =
            Some(source.parent.join("copied-publication"));
        copy_payload(&source.config.root, &config.root).await;
        logical.insert("gc/lease".into(), None);
        let capabilities =
            BucketCapabilities::decode(logical["CAPABILITIES"].as_deref().unwrap()).unwrap();
        let manifest_key = format!(
            "objects/index/{}/MANIFEST",
            capabilities.generation.unwrap()
        );
        let mut manifest =
            GenerationManifest::decode(logical[&manifest_key].as_deref().unwrap()).unwrap();
        let inventory_rows = manifest.inventory.as_mut().unwrap();
        inventory_rows.push(inventory);
        if let Some((inventory, _)) = &extra {
            inventory_rows.push(inventory.clone());
        }
        inventory_rows.sort_by_key(|row| row.pack_id);
        manifest.burns = Some(vec![*old.as_bytes()]);
        manifest.exclusions = Some(if matches!(residue, Residue::AbsentWithoutExclusion) {
            Vec::new()
        } else {
            vec![PackExclusion {
                pack_id: *old.as_bytes(),
                cycle: 7,
                epoch: 3,
            }]
        });
        if let Some((_, exclusion)) = &extra {
            let burns = manifest.burns.as_mut().unwrap();
            burns.push(exclusion.pack_id);
            burns.sort();
            let exclusions = manifest.exclusions.as_mut().unwrap();
            exclusions.push(exclusion.clone());
            exclusions.sort_by_key(|row| row.pack_id);
        }
        let manifest_bytes = manifest.encode().unwrap();
        logical.insert(manifest_key.clone(), Some(manifest_bytes.clone()));
        tokio::fs::write(config.root.join(&manifest_key), manifest_bytes)
            .await
            .unwrap();
        let old_trash = Tombstone {
            pack: *old.as_bytes(),
            cycle: 7,
            timestamp: 1,
            removed: 0,
            epoch: 3,
        }
        .encode();
        match residue {
            Residue::Pack => {
                let path = config.root.join(old.pack_key());
                tokio::fs::create_dir_all(path.parent().unwrap())
                    .await
                    .unwrap();
                tokio::fs::write(path, sealed.bytes()).await.unwrap();
            }
            Residue::Index => {
                let path = config.root.join(old.index_key());
                tokio::fs::create_dir_all(path.parent().unwrap())
                    .await
                    .unwrap();
                tokio::fs::write(path, index).await.unwrap();
            }
            Residue::Trash => {
                tokio::fs::create_dir_all(config.root.join("trash/7"))
                    .await
                    .unwrap();
                tokio::fs::write(config.root.join(format!("trash/7/{old}")), &old_trash)
                    .await
                    .unwrap();
            }
            Residue::Absent | Residue::AbsentWithoutExclusion => {}
        }
        copy_checkpoint(&config.root, &logical, &source.fs).await;
        let bucket = FileBucket::initialize_portable_copy(
            config.clone(),
            CopiedFs::new(source.fs.clone()),
            source.clock.retain_native_clock().unwrap(),
            MetadataValidator::new(config.chunk_profile.clone()),
        )
        .await
        .unwrap();
        let guard = crate::gc::runner::fixture::configured_guard(
            bucket,
            source.clock.retain_native_clock().unwrap(),
            source.guard().keys().to_vec(),
            source.guard().config().clone(),
            source.authoring.as_ref(),
        )
        .with_view_selections(selections.clone())
        .unwrap();
        let fs = guard.store().fs().clone();
        let coordinator = Coordinator::new(
            guard,
            CommitTiming::new(
                Duration::from_secs(30),
                Duration::from_secs(60),
                Duration::from_secs(10),
            )
            .unwrap(),
            fs,
        );
        let original = source.parent.join("copied-original");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&original)
            .unwrap();
        let owner = std::fs::symlink_metadata(&original).unwrap().uid();
        let namespace = DomainNamespace {
            root: config.root.clone(),
            domain: "public".into(),
        };
        let repository =
            Repository::initialize_native_retention(coordinator, &namespace, &original, owner)
                .await
                .unwrap();
        let registration: RegistrationRecord =
            retention::read(&source.fs, &original, owner, "registration.cbor")
                .await
                .unwrap();
        let authority = repository
            .coordinator()
            .guard()
            .bind_original_authority(&namespace, &original, registration.view())
            .await
            .unwrap();
        assert!(
            repository
                .coordinator()
                .guard()
                .original_commit(&source.head.commit)
                .is_err()
        );
        (
            Self {
                source,
                repository,
                authority,
                pack: old,
                old_trash,
                config,
                selections,
            },
            extra.map(|(_, exclusion)| exclusion),
            observation,
        )
    }

    /// Expires the genuine selected whole lease while advancing its retained clock.
    ///
    /// # Panics
    /// Panics on absent lease, mismatched physical bytes or exhausted fixture time.
    pub(crate) async fn expire_selected_lease(&self) {
        let holder = SingleHeld::acquire(self.guard().store()).await.unwrap();
        let held = holder.destination();
        let observed = held.observe_publication_unrepaired().await.unwrap();
        let bytes = observed.logical()["gc/lease"].as_deref().unwrap();
        assert_eq!(
            tokio::fs::read(held.root().join("gc/lease")).await.unwrap(),
            bytes
        );
        let lease = terrane_format::gc::GcLease::decode(bytes).unwrap();
        self.source.clock.set(
            lease.expiry.checked_add(1).unwrap(),
            self.source
                .clock
                .monotonic()
                .as_secs()
                .checked_add(1)
                .unwrap(),
        );
    }

    /// Reopens actual destination files with the same independently configured Guard.
    ///
    /// No native barrier object, elapsed claim or source Original is transferred.
    ///
    /// # Panics
    /// Panics on real open, bounded CAP probe, protected Guard or retention refusal.
    pub(crate) async fn reopen(self) -> Self {
        let prior = {
            let holder = SingleHeld::acquire(self.guard().store()).await.unwrap();
            let held = holder.destination();
            let observed = held.observe_publication_unrepaired().await.unwrap();
            observed.logical()["CAPABILITIES"].clone().unwrap()
        };
        let Self {
            source,
            repository,
            authority,
            pack,
            old_trash,
            config,
            selections,
        } = self;
        drop(authority);
        drop(repository);
        let start = source
            .clock
            .now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let bucket = FileBucket::open(
            config.clone(),
            CopiedFs::new(source.fs.clone()),
            source.clock.retain_native_clock().unwrap(),
            MetadataValidator::new(config.chunk_profile.clone()),
        )
        .await
        .unwrap();
        let end = source
            .clock
            .now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let probed = {
            let holder = SingleHeld::acquire(&bucket).await.unwrap();
            let held = holder.destination();
            let observed = held.observe_publication_unrepaired().await.unwrap();
            let bytes = observed.logical()["CAPABILITIES"].clone().unwrap();
            let after = BucketCapabilities::decode(&bytes).unwrap();
            assert!(start <= after.probed_at && after.probed_at <= end);
            let mut expected = BucketCapabilities::decode(&prior).unwrap();
            expected.probed_at = after.probed_at;
            assert_eq!(after, expected);
            bytes
        };
        let guard = crate::gc::runner::fixture::configured_guard(
            bucket,
            source.clock.retain_native_clock().unwrap(),
            source.guard().keys().to_vec(),
            source.guard().config().clone(),
            source.authoring.as_ref(),
        )
        .with_view_selections(selections.clone())
        .unwrap();
        let fs = guard.store().fs().clone();
        let coordinator = Coordinator::new(
            guard,
            CommitTiming::new(
                Duration::from_secs(30),
                Duration::from_secs(60),
                Duration::from_secs(10),
            )
            .unwrap(),
            fs,
        );
        let original = source.parent.join("copied-original");
        let owner = std::fs::symlink_metadata(&original).unwrap().uid();
        let namespace = DomainNamespace {
            root: config.root.clone(),
            domain: "public".into(),
        };
        let repository =
            Repository::reopen_native_retention(coordinator, &namespace, &original, owner)
                .await
                .unwrap();
        let registration: RegistrationRecord =
            retention::read(&source.fs, &original, owner, "registration.cbor")
                .await
                .unwrap();
        let authority = repository
            .coordinator()
            .guard()
            .bind_original_authority(&namespace, &original, registration.view())
            .await
            .unwrap();
        {
            let holder = SingleHeld::acquire(repository.coordinator().guard().store())
                .await
                .unwrap();
            let held = holder.destination();
            let observed = held.observe_publication_unrepaired().await.unwrap();
            assert_eq!(
                observed.logical()["CAPABILITIES"].as_deref(),
                Some(probed.as_slice())
            );
        }
        Self {
            source,
            repository,
            authority,
            pack,
            old_trash,
            config,
            selections,
        }
    }

    /// Borrows the independently installed destination Guard.
    pub(crate) fn guard(&self) -> &Guard<Bucket, NativeEffectClock> {
        self.repository.coordinator().guard()
    }

    /// Resolves one actual unburned DATA container from independent setup metadata.
    ///
    /// # Panics
    /// Panics when the signed fixture lacks a current eligible DATA placement.
    pub(crate) async fn live_data_path(&self) -> std::path::PathBuf {
        let holder = SingleHeld::acquire(self.guard().store()).await.unwrap();
        let held = holder.destination();
        let observed = held.observe_publication_unrepaired().await.unwrap();
        let capabilities =
            BucketCapabilities::decode(observed.logical()["CAPABILITIES"].as_deref().unwrap())
                .unwrap();
        let key = format!(
            "objects/index/{}/MANIFEST",
            capabilities.generation.unwrap()
        );
        let manifest =
            GenerationManifest::decode(observed.logical()[&key].as_deref().unwrap()).unwrap();
        let burns = manifest.burns.as_ref().unwrap();
        let exclusions = manifest.exclusions.as_ref().unwrap();
        for row in manifest.inventory.as_ref().unwrap() {
            if burns.binary_search(&row.pack_id).is_ok()
                || exclusions
                    .iter()
                    .any(|excluded| excluded.pack_id == row.pack_id)
            {
                continue;
            }
            let pack = PackId::from_random_bytes(row.pack_id);
            let bytes = tokio::fs::read(held.root().join(pack.index_key()))
                .await
                .unwrap();
            let index = crate::pack::PackIndexSnapshot::decode(&bytes, 1).unwrap();
            if index.header().class() == PackClass::Data {
                return held.root().join(pack.pack_key());
            }
        }
        panic!("actual live DATA container missing");
    }

    /// Calibrates an actual DATA-body read trap before reachability qualification.
    ///
    /// Setup reads classify real container bytes independently. The deliberate
    /// trapped read proves the counter endpoint, and subsequent delta must stay
    /// zero; native metadata-only descriptor checks do not read chunk bodies.
    ///
    /// # Panics
    /// Panics on invalid actual container bytes, missing live DATA or a trap that
    /// fails to observe and refuse a genuine filesystem read.
    pub(crate) async fn forbid_chunk_reads(&self) -> usize {
        let holder = SingleHeld::acquire(self.guard().store()).await.unwrap();
        let held = holder.destination();
        let observed = held.observe_publication_unrepaired().await.unwrap();
        let capabilities =
            BucketCapabilities::decode(observed.logical()["CAPABILITIES"].as_deref().unwrap())
                .unwrap();
        let key = format!(
            "objects/index/{}/MANIFEST",
            capabilities.generation.unwrap()
        );
        let manifest =
            GenerationManifest::decode(observed.logical()[&key].as_deref().unwrap()).unwrap();
        let mut paths = Vec::new();
        for inventory in manifest.inventory.unwrap() {
            let path = held
                .root()
                .join(PackId::from_random_bytes(inventory.pack_id).pack_key());
            let bytes = match tokio::fs::read(&path).await {
                Ok(bytes) => bytes,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => panic!("actual setup container read failed: {error}"),
            };
            if crate::pack::PackReader::open(&bytes)
                .unwrap()
                .header()
                .class()
                == PackClass::Data
            {
                paths.push(path);
            }
        }
        assert!(!paths.is_empty());
        self.source.fs.forbid_data_body_reads(&paths).unwrap();
        assert!(self.source.fs.read(&paths[0]).await.is_err());
        let before = self.source.fs.data_body_read_attempts();
        assert_eq!(before, 1);
        before
    }

    /// Runs the actual first-owner operation while preserving its typed refusal.
    ///
    /// # Errors
    /// Returns the exact production acquisition, qualification or native error.
    ///
    /// # Panics
    /// Panics if fixture observation state is poisoned or fixture diagnostics
    /// cannot write to standard error.
    pub(crate) async fn attempt(
        &self,
    ) -> Result<PermanentDeleteOperation, crate::gc::runner::CollectionError> {
        self.source.clock.enable_timer();
        let result = async {
            let mut runner = CopiedRetirement::start(
                self.guard(),
                &self.authority,
                "copied-first-owner".into(),
                90,
                Windows::new(30, 60, 60, 90).unwrap(),
            )
            .await?;
            runner
                .own_copied_pack(self.repository.coordinator(), *self.pack.as_bytes())
                .await
        }
        .await;
        self.guard().store().fs().close_unreached_pause();
        result
    }

    /// Reaches a genuine selected permanent owner through full native first ownership.
    ///
    /// # Panics
    /// Panics on any actual preparation, journal, wait, renewal or owner failure.
    pub(crate) async fn own(&self) -> PermanentDeleteOperation {
        self.own_with_holder("copied-first-owner").await
    }

    /// Acquires genuine first ownership under the independently named new holder.
    ///
    /// # Panics
    /// Panics on refused lease acquisition, native effects or the full wait oracle.
    pub(crate) async fn own_with_holder(&self, holder: &str) -> PermanentDeleteOperation {
        self.source.clock.enable_timer();
        let started = self.source.clock.monotonic();
        let mut runner = CopiedRetirement::start(
            self.guard(),
            &self.authority,
            holder.into(),
            90,
            Windows::new(30, 60, 60, 90).unwrap(),
        )
        .await
        .unwrap();
        let operation = runner
            .own_copied_pack(self.repository.coordinator(), *self.pack.as_bytes())
            .await
            .unwrap();
        assert!(
            self.source.clock.monotonic().checked_sub(started).unwrap() >= Duration::from_secs(60)
        );
        let PermanentDeleteAuthorization::Copied(authorization) = &operation.authorization else {
            panic!("copied owner expected")
        };
        assert!(authorization.lineage_fence.is_none());
        let holder = SingleHeld::acquire(self.guard().store()).await.unwrap();
        let held = holder.destination();
        let observed = held.observe_publication_unrepaired().await.unwrap();
        assert!(observed.state().sources.is_empty());
        assert!(
            observed
                .state()
                .burn_owners
                .as_ref()
                .unwrap()
                .iter()
                .any(|owner| owner.pack == *self.pack.as_bytes()
                    && matches!(owner.selection, PermanentOwnerSelection::Permanent(_)))
        );
        operation
    }

    /// Removes only this fixture's private temporary tree after all calls finish.
    ///
    /// # Panics
    /// Panics if the completed temporary fixture cannot be removed. Callers must
    /// first drop held adapters and await every actual native operation.
    pub(crate) fn cleanup(self) {
        let Self {
            source,
            repository,
            authority,
            ..
        } = self;
        drop(repository);
        drop(authority);
        source.cleanup();
    }
}

//! Builds genuine selected packs and observes bounded filesystem I/O.

use crate::bucket::FileBucket;
use crate::bucket::tests::{Validator, config, fixture};
use crate::pack::{EntryKind, NativeBodyDecoder, PackClass, PackId, PackIndexSnapshot, PackWriter};
use crate::store::{ByteRange, ChunkPosition, ContentStore, LocalFs, TokioClock, TokioLocalFs};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use terrane_format::identity::{Identity, IdentityKind, TERRANE_V1};

/// Carries actual fixture and store failures to the test runner.
pub(in crate::bucket::content) type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Serves real file-bucket operations through the observing filesystem wrapper.
pub(in crate::bucket::content) type CountedBucket = FileBucket<RangeFs, TokioClock, Validator>;

/// Selects actual binding capabilities and persisted layout for a fixture.
#[derive(Clone, Copy, Debug)]
pub(in crate::bucket::content) enum ReadProfile {
    /// Forwards sealed native hooks and ordinary filesystem operations.
    Native,
    /// Declines optional native hooks while retaining actual bounded scalar I/O.
    UnsupportedHooks,
    /// Refuses mutations and lock creation while permitting existing-only locks.
    ReadOnly,
    /// Reads layout one without permitting mutations or coordination.
    Legacy,
}

/// Observes real I/O and refuses whole-pack reads after fixture setup.
#[derive(Clone)]
pub(in crate::bucket::content) struct RangeFs {
    state: Arc<State>,
}

struct State {
    active: AtomicBool,
    packs: BTreeSet<PathBuf>,
    whole_reads: AtomicUsize,
    ranges: Mutex<Vec<(PathBuf, ByteRange)>>,
    closing_ranges: Mutex<Vec<(PathBuf, ByteRange)>>,
    replace_before_range: Mutex<Option<(PathBuf, bool)>>,
    profile: ReadProfile,
    effects: AtomicUsize,
    ordinary_range_reads: AtomicUsize,
    fail_native_read: AtomicBool,
    short_ordinary_read: AtomicBool,
    existing_locks: Mutex<Vec<ExistingLockRead>>,
}

#[derive(Clone)]
struct ExistingLockRead {
    path: PathBuf,
    metadata: std::fs::Metadata,
    bytes: Vec<u8>,
}

impl RangeFs {
    /// Configures observation of the actual selected pack paths.
    pub(in crate::bucket::content) fn new(packs: BTreeSet<PathBuf>, profile: ReadProfile) -> Self {
        Self {
            state: Arc::new(State {
                active: AtomicBool::new(false),
                packs,
                whole_reads: AtomicUsize::new(0),
                ranges: Mutex::new(Vec::new()),
                closing_ranges: Mutex::new(Vec::new()),
                replace_before_range: Mutex::new(None),
                profile,
                effects: AtomicUsize::new(0),
                ordinary_range_reads: AtomicUsize::new(0),
                fail_native_read: AtomicBool::new(false),
                short_ordinary_read: AtomicBool::new(false),
                existing_locks: Mutex::new(Vec::new()),
            }),
        }
    }

    /// Activates I/O traps after the bucket has reopened successfully.
    pub(in crate::bucket::content) fn arm(&self) {
        self.state.active.store(true, Ordering::SeqCst);
    }

    /// Returns the number of refused whole-pack read attempts.
    pub(in crate::bucket::content) fn whole_reads(&self) -> usize {
        self.state.whole_reads.load(Ordering::SeqCst)
    }

    /// Returns the number of filesystem mutation and synchronization attempts.
    pub(in crate::bucket::content) fn effects(&self) -> usize {
        self.state.effects.load(Ordering::SeqCst)
    }

    /// Returns scalar bounded-read attempts on selected pack paths.
    pub(in crate::bucket::content) fn ordinary_range_reads(&self) -> usize {
        self.state.ordinary_range_reads.load(Ordering::SeqCst)
    }

    /// Refuses the next sealed data read after actual native capture.
    pub(in crate::bucket::content) fn fail_native_read(&self) {
        self.state.fail_native_read.store(true, Ordering::SeqCst);
    }

    /// Truncates the next actual scalar range result to exercise short-read refusal.
    pub(in crate::bucket::content) fn short_ordinary_read(&self) {
        self.state.short_ordinary_read.store(true, Ordering::SeqCst);
    }

    fn check_coordination(&self, create: bool) -> std::io::Result<()> {
        if self.state.active.load(Ordering::SeqCst)
            && (matches!(self.state.profile, ReadProfile::Legacy)
                || (create && matches!(self.state.profile, ReadProfile::ReadOnly)))
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "read-only fixture refuses coordination",
            ));
        }
        Ok(())
    }

    async fn observe_existing_lock(
        &self,
        path: &Path,
    ) -> std::io::Result<Option<ExistingLockRead>> {
        if !self.state.active.load(Ordering::SeqCst) {
            return Ok(None);
        }
        Ok(Some(ExistingLockRead {
            path: path.to_owned(),
            metadata: TokioLocalFs.symlink_metadata(path).await?,
            bytes: TokioLocalFs.read_nofollow(path).await?,
        }))
    }

    fn retain_existing_lock(&self, read: Option<ExistingLockRead>) -> std::io::Result<()> {
        if let Some(read) = read {
            self.state
                .existing_locks
                .lock()
                .map_err(|_| std::io::Error::other("poisoned existing lock observations"))?
                .push(read);
        }
        Ok(())
    }

    /// Checks that successful existing-only lock opens preserve their real files.
    ///
    /// # Errors
    /// Propagates poisoned observation state or unavailable metadata and bytes.
    ///
    /// # Panics
    /// Panics if no existing lock was acquired or a lock's metadata or bytes changed.
    pub(in crate::bucket::content) async fn check_existing_lock_continuity(
        &self,
    ) -> std::io::Result<()> {
        use std::os::unix::fs::MetadataExt;

        let reads = self
            .state
            .existing_locks
            .lock()
            .map_err(|_| std::io::Error::other("poisoned existing lock observations"))?
            .clone();
        assert!(!reads.is_empty(), "no existing-only lock was acquired");
        let stamp = |metadata: &std::fs::Metadata| {
            (
                metadata.dev(),
                metadata.ino(),
                metadata.uid(),
                metadata.mode(),
                metadata.nlink(),
                metadata.len(),
                metadata.mtime(),
                metadata.mtime_nsec(),
                metadata.ctime(),
                metadata.ctime_nsec(),
            )
        };
        for read in reads {
            let after = TokioLocalFs.symlink_metadata(&read.path).await?;
            assert_eq!(stamp(&after), stamp(&read.metadata), "{:?}", read.path);
            assert_eq!(
                TokioLocalFs.read_nofollow(&read.path).await?,
                read.bytes,
                "{:?}",
                read.path
            );
        }
        Ok(())
    }

    fn check_effect(&self) -> std::io::Result<()> {
        if !self.state.active.load(Ordering::SeqCst) {
            return Ok(());
        }
        self.state.effects.fetch_add(1, Ordering::SeqCst);
        if matches!(
            self.state.profile,
            ReadProfile::ReadOnly | ReadProfile::Legacy
        ) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "read-only fixture refuses effects",
            ));
        }
        Ok(())
    }

    /// Copies observed scalar and sealed data range requests on selected packs.
    ///
    /// # Errors
    /// Returns an error if the observation mutex is poisoned.
    pub(in crate::bucket::content) fn ranges(&self) -> std::io::Result<Vec<(PathBuf, ByteRange)>> {
        self.state
            .ranges
            .lock()
            .map(|ranges| ranges.clone())
            .map_err(|_| std::io::Error::other("poisoned range observations"))
    }

    /// Copies genuine sealed closing replay intent without asserting completed I/O.
    ///
    /// # Errors
    /// Returns an error if the closing observation mutex is poisoned.
    pub(in crate::bucket::content) fn closing_ranges(
        &self,
    ) -> std::io::Result<Vec<(PathBuf, ByteRange)>> {
        self.state
            .closing_ranges
            .lock()
            .map(|ranges| ranges.clone())
            .map_err(|_| std::io::Error::other("poisoned closing range requests"))
    }

    /// Schedules a real same-byte leaf or ancestor replacement before pack range I/O.
    ///
    /// # Errors
    /// Returns an error if the replacement state mutex is poisoned.
    pub(in crate::bucket::content) fn replace_before_range(
        &self,
        path: PathBuf,
        directory: bool,
    ) -> std::io::Result<()> {
        *self
            .state
            .replace_before_range
            .lock()
            .map_err(|_| std::io::Error::other("poisoned replacement fixture"))? =
            Some((path, directory));
        Ok(())
    }

    fn check_whole_read(&self, path: &Path) -> std::io::Result<()> {
        if self.state.active.load(Ordering::SeqCst) && self.state.packs.contains(path) {
            self.state.whole_reads.fetch_add(1, Ordering::SeqCst);
            return Err(std::io::Error::other(
                "whole pack reads forbidden by fixture",
            ));
        }
        Ok(())
    }

    fn observe_range(&self, path: &Path, range: ByteRange) -> std::io::Result<()> {
        if !self.state.active.load(Ordering::SeqCst) || !self.state.packs.contains(path) {
            return Ok(());
        }

        self.state
            .ranges
            .lock()
            .map_err(|_| std::io::Error::other("poisoned range observations"))?
            .push((path.to_owned(), range));

        let replacement = self
            .state
            .replace_before_range
            .lock()
            .map_err(|_| std::io::Error::other("poisoned replacement fixture"))?
            .take();
        if let Some((path, directory)) = replacement {
            replace_physical_name(&path, directory)?;
        }
        Ok(())
    }

    fn observe_closing_range(&self, path: &Path, range: ByteRange) -> std::io::Result<()> {
        if self.state.active.load(Ordering::SeqCst) && self.state.packs.contains(path) {
            self.state
                .closing_ranges
                .lock()
                .map_err(|_| std::io::Error::other("poisoned closing range requests"))?
                .push((path.to_owned(), range));
        }
        Ok(())
    }
}

fn replace_physical_name(path: &Path, directory: bool) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let previous = path.with_extension("original-retained");
    if directory {
        std::fs::rename(path, &previous)?;
        std::fs::create_dir(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
        for entry in std::fs::read_dir(&previous)? {
            let entry = entry?;
            let destination = path.join(entry.file_name());
            std::fs::copy(entry.path(), &destination)?;
            std::fs::set_permissions(destination, std::fs::metadata(entry.path())?.permissions())?;
        }
    } else {
        let bytes = std::fs::read(path)?;
        let permissions = std::fs::metadata(path)?.permissions();
        std::fs::rename(path, &previous)?;
        std::fs::write(path, bytes)?;
        std::fs::set_permissions(path, permissions)?;
    }
    Ok(())
}

#[async_trait::async_trait]
impl LocalFs for RangeFs {
    type Lock = crate::store::TokioFileLock;

    async fn random_bytes(&self, length: usize) -> std::io::Result<Vec<u8>> {
        TokioLocalFs.random_bytes(length).await
    }

    async fn lock_exclusive(&self, path: &Path) -> std::io::Result<Self::Lock> {
        self.check_coordination(true)?;
        TokioLocalFs.lock_exclusive(path).await
    }

    async fn lock_existing_exclusive(&self, path: &Path) -> std::io::Result<Self::Lock> {
        self.check_coordination(false)?;
        let observed = self.observe_existing_lock(path).await?;
        let held = TokioLocalFs.lock_existing_exclusive(path).await?;
        self.retain_existing_lock(observed)?;
        Ok(held)
    }

    async fn try_lock_existing_shared(&self, path: &Path) -> std::io::Result<Self::Lock> {
        self.check_coordination(false)?;
        let observed = self.observe_existing_lock(path).await?;
        let held = TokioLocalFs.try_lock_existing_shared(path).await?;
        self.retain_existing_lock(observed)?;
        Ok(held)
    }

    async fn try_lock_existing_exclusive(&self, path: &Path) -> std::io::Result<Self::Lock> {
        self.check_coordination(false)?;
        let observed = self.observe_existing_lock(path).await?;
        let held = TokioLocalFs.try_lock_existing_exclusive(path).await?;
        self.retain_existing_lock(observed)?;
        Ok(held)
    }

    fn retain_native_exclusion(
        &self,
        held: &Self::Lock,
    ) -> std::io::Result<crate::store::NativeExclusion> {
        TokioLocalFs.retain_native_exclusion(held)
    }

    async fn execute_retained_effect(
        &self,
        effect: crate::store::NativeFsEffect,
    ) -> Result<(), crate::store::NativeEffectFailure> {
        self.check_effect()?;
        TokioLocalFs.execute_retained_effect(effect).await
    }

    async fn read(&self, path: &Path) -> std::io::Result<Vec<u8>> {
        self.check_whole_read(path)?;
        TokioLocalFs.read(path).await
    }

    async fn read_nofollow(&self, path: &Path) -> std::io::Result<Vec<u8>> {
        self.check_whole_read(path)?;
        TokioLocalFs.read_nofollow(path).await
    }

    async fn read_range(&self, path: &Path, range: ByteRange) -> std::io::Result<Vec<u8>> {
        if self.state.active.load(Ordering::SeqCst) && self.state.packs.contains(path) {
            self.state
                .ordinary_range_reads
                .fetch_add(1, Ordering::SeqCst);
        }
        self.observe_range(path, range)?;
        let mut bytes = TokioLocalFs.read_range(path, range).await?;
        if self.state.short_ordinary_read.swap(false, Ordering::SeqCst) {
            bytes.pop();
        }
        Ok(bytes)
    }

    async fn read_payload_ranges(
        &self,
        request: crate::store::NativePayloadRangeRead,
    ) -> std::io::Result<Option<crate::store::NativePayloadRangeRecord>> {
        if !matches!(self.state.profile, ReadProfile::Native) {
            return Ok(None);
        }
        if let Some((path, range)) = request.read_data_range() {
            self.observe_range(path, range)?;
            if self.state.fail_native_read.swap(false, Ordering::SeqCst) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "supported native reader failed after capture",
                ));
            }
        }
        if let Some(ranges) = request.closing_data_ranges_for_test() {
            for (path, range) in ranges {
                self.observe_closing_range(path, range)?;
            }
        }
        TokioLocalFs.read_payload_ranges(request).await
    }

    async fn read_ordinary_record(
        &self,
        request: crate::store::NativeOrdinaryRead,
    ) -> std::io::Result<Option<crate::store::NativeOrdinaryRecord>> {
        if !matches!(self.state.profile, ReadProfile::Native) {
            return Ok(None);
        }
        if let Some(path) = request.path_for_test() {
            self.check_whole_read(path)?;
        }
        TokioLocalFs.read_ordinary_record(request).await
    }

    async fn write_new(&self, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
        self.check_effect()?;
        TokioLocalFs.write_new(path, bytes).await
    }

    async fn create_dir_all(&self, path: &Path) -> std::io::Result<()> {
        self.check_effect()?;
        TokioLocalFs.create_dir_all(path).await
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

    async fn remove_file(&self, path: &Path) -> std::io::Result<()> {
        self.check_effect()?;
        TokioLocalFs.remove_file(path).await
    }

    async fn rename(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        self.check_effect()?;
        TokioLocalFs.rename(from, to).await
    }

    async fn rename_no_replace(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        self.check_effect()?;
        TokioLocalFs.rename_no_replace(from, to).await
    }

    async fn sync_file(&self, path: &Path) -> std::io::Result<()> {
        self.check_effect()?;
        TokioLocalFs.sync_file(path).await
    }

    async fn sync_directory(&self, path: &Path) -> std::io::Result<()> {
        self.check_effect()?;
        TokioLocalFs.sync_directory(path).await
    }
}

/// Retains a genuinely published selected pack and its observing bucket handle.
pub(in crate::bucket::content) struct Fixture {
    /// Serves public content requests through the actual filesystem wrapper.
    pub(in crate::bucket::content) bucket: CountedBucket,
    /// Shares I/O traps and observations with the bucket binding.
    pub(in crate::bucket::content) fs: RangeFs,
    /// Identifies the fixture's actual selected plaintext chunk.
    pub(in crate::bucket::content) identity: Identity,
    /// Contains the complete verified encoded chunk returned before traps activate.
    pub(in crate::bucket::content) encoded: Vec<u8>,
    /// Names the actual persisted pack containing the selected chunk.
    pub(in crate::bucket::content) pack_path: PathBuf,
    /// Names that pack's actual detached index.
    pub(in crate::bucket::content) index_path: PathBuf,
    /// Describes the actual detached index used to locate mutation offsets.
    pub(in crate::bucket::content) snapshot: PackIndexSnapshot,
}

impl Fixture {
    /// Publishes a raw selected member and a large unrelated member with native hooks.
    ///
    /// # Errors
    /// Propagates actual bucket reopening, persisted index and content-read failures.
    ///
    /// # Panics
    /// Panics if the shared native fixture or canonical publication setup fails.
    pub(in crate::bucket::content) async fn raw(
        plaintext: &[u8],
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Self::raw_with_profile(plaintext, ReadProfile::Native).await
    }

    /// Publishes genuine raw members and reopens with the requested binding profile.
    ///
    /// # Errors
    /// Propagates actual reopening, index, layout-conversion and content-read failures.
    ///
    /// # Panics
    /// Panics if the shared native fixture or canonical publication setup fails.
    pub(in crate::bucket::content) async fn raw_with_profile(
        plaintext: &[u8],
        profile: ReadProfile,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let plain = fixture().await;
        let unrelated = vec![b'x'; 512 * 1024];
        let id =
            crate::bucket::readmission_tests::publish_members(&plain, &[plaintext, &unrelated])
                .await;
        let fixture = Self::open(&plain, id, plaintext, profile).await?;
        Ok(fixture)
    }

    /// Publishes a real dictionary-dependent chunk and its independent dictionary.
    ///
    /// # Errors
    /// Propagates encoding, dictionary admission, native staging, publication and
    /// reopening failures; rejects an encoder result without a dictionary envelope.
    ///
    /// # Panics
    /// Panics if the shared native fixture creation fails or enabled phase
    /// diagnostics cannot write to standard error.
    pub(in crate::bucket::content) async fn dictionary(
        read_profile: ReadProfile,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let plain = fixture().await;
        let trace = crate::ref_advance::NativeTrace::new(plain.root(), "ranged-dictionary-fixture");
        trace.mark("dictionary-admission-start");
        let profile = &plain.inner.config.chunk_profile;
        let dictionary: Vec<_> = (0..16384)
            .map(|index| ((index * 17 + index / 19) % 251) as u8)
            .collect();
        let dictionary_identity = TERRANE_V1.calculate(IdentityKind::Chunk, &dictionary)?;
        let raw = crate::bucket::content_tests::raw(&dictionary);
        plain
            .put(crate::bucket::content_tests::upload(
                &raw,
                &dictionary_identity,
                dictionary.len(),
                profile,
                ChunkPosition::Final,
            ))
            .await?;
        trace.mark("dictionary-admission-returned");
        let plaintext = dictionary[..1024].repeat(16);
        let encoded =
            crate::codec::encode_chunk(&plaintext, profile.maximum(), 3, Some(&dictionary))?;
        if !matches!(
            terrane_format::codec::parse_envelope(&encoded)?.codec,
            terrane_format::codec::Codec::ZstdDictionary(_)
        ) {
            return Err("fixture did not produce an actual dictionary envelope".into());
        }

        trace.mark("namespace-acquisition-start");
        let holder = crate::bucket::held::SingleHeld::acquire(&plain).await?;
        trace.mark("namespace-acquisition-returned");
        let held = holder.destination();
        trace.mark("publication-observation-start");
        let observed = held.observe_publication().await?;
        trace.mark("publication-observation-returned");
        trace.mark("catalog-read-start");
        let catalog = plain.catalog().await?;
        trace.mark("catalog-read-returned");
        let id = PackId::generate(plain.fs()).await?;
        let mut writer = PackWriter::new(id, PackClass::Data, true);
        let dictionaries = BTreeMap::from([(dictionary_identity.terrane_v1_digest()?, dictionary)]);
        let decoder = NativeBodyDecoder::new(profile, &dictionaries);
        let hash = TERRANE_V1
            .calculate(IdentityKind::Chunk, &plaintext)?
            .terrane_v1_digest()?;
        writer.append_chunk(hash, &encoded, u32::try_from(plaintext.len())?, 0, &decoder)?;
        writer.append_raw(EntryKind::Chunk, &vec![b'y'; 32768])?;
        let sealed = writer.seal()?;
        let artifacts = crate::bucket::containers::admitted_artifacts(
            id,
            sealed.bytes(),
            sealed.index_object(),
        )?;
        trace.mark("container-staging-start");
        crate::store::native_publication_effects::stage_container(
            plain.fs(),
            &observed,
            &artifacts,
        )
        .await?;
        trace.mark("container-staging-returned");
        let generation = plain.next_generation(&catalog).await?;
        let snapshot = PackIndexSnapshot::decode(sealed.index_object(), generation)?;
        let inventory =
            crate::bucket::containers::inventory_entry(id, sealed.bytes(), sealed.index_object())?;
        trace.mark("catalog-publication-start");
        plain
            .publish_pack_catalog(&held, &observed, catalog, snapshot, inventory)
            .await?;
        trace.mark("catalog-publication-returned");
        drop(observed);
        drop(held);
        drop(holder);

        trace.mark("fixture-reopen-start");
        let reopened = Self::open(&plain, id, &plaintext, read_profile).await?;
        trace.mark("fixture-reopen-returned");
        Ok(reopened)
    }

    /// Reopens actual published artifacts before activating the requested I/O traps.
    ///
    /// # Errors
    /// Propagates actual index, catalog, content and reopening failures, or errors
    /// from explicitly converting the fixture to legacy layout one.
    ///
    /// # Panics
    /// Panics if the shared configuration cannot observe the actual operator or
    /// enabled phase diagnostics cannot write to standard error.
    pub(in crate::bucket::content) async fn open(
        plain: &crate::bucket::tests::Bucket,
        id: PackId,
        plaintext: &[u8],
        profile: ReadProfile,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let trace = crate::ref_advance::NativeTrace::new(plain.root(), "ranged-fixture-open");
        let pack_path = plain.root().join(id.pack_key());
        let index_path = plain.root().join(id.index_key());
        let index = TokioLocalFs.read_nofollow(&index_path).await?;
        let snapshot = PackIndexSnapshot::decode(&index, 1)?;
        let identity = TERRANE_V1.calculate(IdentityKind::Chunk, plaintext)?;
        trace.mark("pretrap-content-read-start");
        let encoded = plain.get(&identity, None).await?;
        trace.mark("pretrap-content-read-returned");
        trace.mark("pretrap-catalog-read-start");
        let packs = plain
            .catalog()
            .await?
            .inventory
            .ok_or("missing actual selected inventory")?
            .iter()
            .map(|entry| {
                plain
                    .root()
                    .join(PackId::from_random_bytes(entry.pack_id).pack_key())
            })
            .collect();
        trace.mark("pretrap-catalog-read-returned");
        let fs = RangeFs::new(packs, profile);
        let configuration = config(plain.root().to_owned());
        trace.mark("binding-reopen-start");
        let bucket = if matches!(profile, ReadProfile::Legacy) {
            let capability_path = plain.root().join("CAPABILITIES");
            let mut capabilities = terrane_format::bucket::BucketCapabilities::decode(
                &TokioLocalFs.read_nofollow(&capability_path).await?,
            )?;
            capabilities.layout_version = 1;
            capabilities.publication_protocol = None;
            capabilities.ref_names = None;
            tokio::fs::write(capability_path, capabilities.encode()?).await?;
            tokio::fs::remove_dir_all(crate::bucket::tests::control_path(plain.root())).await?;
            FileBucket::open_legacy_read_only(configuration, fs.clone(), TokioClock, Validator)
                .await?
        } else {
            FileBucket::open(configuration, fs.clone(), TokioClock, Validator).await?
        };
        trace.mark("binding-reopen-returned");
        fs.arm();

        Ok(Self {
            bucket,
            fs,
            identity,
            encoded,
            pack_path,
            index_path,
            snapshot,
        })
    }

    /// Locates the requested member in the fixture's actual detached index.
    ///
    /// # Errors
    /// Refuses an absent member or an offset that exceeds the address space.
    pub(in crate::bucket::content) fn body_offset(
        &self,
    ) -> Result<usize, Box<dyn std::error::Error>> {
        let entry = self
            .snapshot
            .entries()
            .iter()
            .find(|entry| entry.hash() == self.identity.digest())
            .ok_or("requested actual member absent")?;
        Ok(usize::try_from(entry.offset())?)
    }

    /// Removes the actual temporary bucket payload tree after its assertions.
    ///
    /// # Errors
    /// Propagates actual filesystem cleanup failures.
    pub(in crate::bucket::content) async fn remove(self) -> std::io::Result<()> {
        tokio::fs::remove_dir_all(self.bucket.root()).await
    }
}

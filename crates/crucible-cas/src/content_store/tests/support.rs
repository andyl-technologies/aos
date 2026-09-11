//! Shared content-store backends, sources, and path helpers.

use super::*;

#[derive(Default)]
pub(super) struct RecordingNamespaceAuthorizer {
    pub(super) allowed: AtomicBool,
    pub(super) calls: Mutex<Vec<(StoreNamespaceOperation, ContentId)>>,
}

impl RecordingNamespaceAuthorizer {
    pub(super) fn set_allowed(&self, allowed: bool) {
        self.allowed.store(allowed, Ordering::SeqCst);
    }

    pub(super) fn calls(&self) -> Vec<(StoreNamespaceOperation, ContentId)> {
        self.calls.lock().expect("namespace call lock").clone()
    }
}

impl StoreNamespaceAuthorizer for RecordingNamespaceAuthorizer {
    fn authorize(
        &self,
        operation: StoreNamespaceOperation,
        id: ContentId,
    ) -> Result<(), StoreError> {
        self.calls
            .lock()
            .expect("namespace call lock")
            .push((operation, id));
        if self.allowed.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(StoreError::Unauthorized)
        }
    }
}

pub(super) struct RecordingObjectProfiler {
    pub(super) allowed: AtomicBool,
    pub(super) calls: AtomicUsize,
    pub(super) returned_kind: Mutex<Option<ObjectKind>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RecordedPhysicalQuotaBinding {
    pub(super) root: PathBuf,
    pub(super) project_id: u32,
    pub(super) maximum_physical_bytes: u64,
    pub(super) maximum_inodes: u64,
}

#[derive(Default)]
pub(super) struct RecordingPhysicalQuotaGuard {
    pub(super) allowed: AtomicBool,
    pub(super) calls: AtomicUsize,
}

impl RecordingPhysicalQuotaGuard {
    pub(super) fn set_allowed(&self, allowed: bool) {
        self.allowed.store(allowed, Ordering::SeqCst);
    }
}

impl StorePhysicalQuotaGuard for RecordingPhysicalQuotaGuard {
    fn verify(&self) -> Result<(), StoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.allowed.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(StoreError::Quota)
        }
    }
}

pub(super) struct RecordingPhysicalQuotaBinder {
    pub(super) guard: Arc<RecordingPhysicalQuotaGuard>,
    pub(super) bindings: Mutex<Vec<RecordedPhysicalQuotaBinding>>,
}

impl RecordingPhysicalQuotaBinder {
    pub(super) fn new(allowed: bool) -> Self {
        let guard = Arc::new(RecordingPhysicalQuotaGuard::default());
        guard.set_allowed(allowed);
        Self {
            guard,
            bindings: Mutex::new(Vec::new()),
        }
    }

    pub(super) fn bindings(&self) -> Vec<RecordedPhysicalQuotaBinding> {
        self.bindings.lock().expect("quota binding lock").clone()
    }
}

impl StorePhysicalQuotaBinder for RecordingPhysicalQuotaBinder {
    fn bind(
        &self,
        root: &Path,
        project_id: u32,
        maximum_physical_bytes: u64,
        maximum_inodes: u64,
    ) -> Result<Arc<dyn StorePhysicalQuotaGuard>, StoreError> {
        self.bindings
            .lock()
            .expect("quota binding lock")
            .push(RecordedPhysicalQuotaBinding {
                root: root.to_owned(),
                project_id,
                maximum_physical_bytes,
                maximum_inodes,
            });
        self.guard.verify()?;
        Ok(self.guard.clone())
    }
}

impl RecordingObjectProfiler {
    pub(super) fn new(allowed: bool) -> Self {
        Self {
            allowed: AtomicBool::new(allowed),
            calls: AtomicUsize::new(0),
            returned_kind: Mutex::new(None),
        }
    }

    pub(super) fn set_allowed(&self, allowed: bool) {
        self.allowed.store(allowed, Ordering::SeqCst);
    }

    pub(super) fn set_returned_kind(&self, kind: Option<ObjectKind>) {
        *self.returned_kind.lock().expect("profile kind lock") = kind;
    }
}

impl StoreObjectProfiler for RecordingObjectProfiler {
    fn derive_profile(
        &self,
        id: ContentId,
        source: &BlobHandle,
    ) -> Result<ObjectProfile, StoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if !self.allowed.load(Ordering::SeqCst) {
            return Err(StoreError::Unauthorized);
        }
        let kind = self
            .returned_kind
            .lock()
            .expect("profile kind lock")
            .unwrap_or(id.kind());
        Ok(ObjectProfile::new(
            kind,
            source.logical_length(),
            SensitivityClass::Evidence,
            Reconstructibility::Canonical,
            RetentionRole::Evidence,
        ))
    }
}

pub(super) fn put_bytes(
    store: &dyn ImmutableBlobBackend,
    id: ContentId,
    bytes: &[u8],
) -> Result<PutReceipt, StoreError> {
    store.put_if_absent(id, &BlobHandle::from_bytes(bytes))
}

pub(super) fn read_bytes(
    store: &dyn ImmutableBlobBackend,
    id: ContentId,
    range: Option<ByteRange>,
) -> Result<Vec<u8>, StoreError> {
    store.read(id, range)?.read_all(TEST_READ_LIMIT)
}

pub(super) fn assert_bounded_ref_scan_contract(refs: &dyn MutableRefBackend) {
    let namespace = RefName::new("campaigns").expect("campaign namespace");
    let alpha = RefName::new("campaigns/alpha").expect("alpha ref");
    let zeta = RefName::new("campaigns/zeta").expect("zeta ref");
    let unrelated = RefName::new("other/ignored").expect("unrelated ref");
    let alpha_target = ContentId::for_bytes(ObjectKind::CampaignSnapshot, 1, b"alpha");
    let zeta_target = ContentId::for_bytes(ObjectKind::CampaignSnapshot, 1, b"zeta");
    let unrelated_target = ContentId::for_bytes(ObjectKind::CampaignSnapshot, 1, b"unrelated");
    refs.compare_exchange(&zeta, None, zeta_target)
        .expect("create zeta ref");
    refs.compare_exchange(&unrelated, None, unrelated_target)
        .expect("create unrelated ref");
    refs.compare_exchange(&alpha, None, alpha_target)
        .expect("create alpha ref");

    let first = refs
        .scan_refs(&namespace, None, 1)
        .expect("scan first campaign ref page");
    assert_eq!(first.entries().len(), 1);
    assert_eq!(first.entries()[0].name(), &alpha);
    assert_eq!(first.entries()[0].target(), alpha_target);
    assert_eq!(first.next_after(), Some(&alpha));
    assert!(first.visited() > 0);

    let second = refs
        .scan_refs(&namespace, Some(&alpha), 1)
        .expect("scan second campaign ref page");
    assert_eq!(second.entries().len(), 1);
    assert_eq!(second.entries()[0].name(), &zeta);
    assert_eq!(second.entries()[0].target(), zeta_target);
    assert_eq!(second.next_after(), None);

    assert!(matches!(
        refs.scan_refs(&namespace, Some(&unrelated), 1),
        Err(StoreError::InvalidComposition {
            reason: "authoritative ref scan cursor is outside its namespace"
        })
    ));
    assert!(matches!(
        refs.scan_refs(&namespace, None, 0),
        Err(StoreError::Quota)
    ));
}

pub(super) fn object_path(root: &Path, id: ContentId) -> PathBuf {
    let encoded = id.encode();
    let digest = encoded.rsplit_once('.').expect("digest separator").1;
    root.join(id.kind().as_str())
        .join(id.schema_version().to_string())
        .join(&digest[..2])
        .join(digest)
}

pub(super) fn node_id(value: &str) -> StoreNodeId {
    StoreNodeId::new(value).expect("valid store node ID")
}

pub(super) fn write_back_graph(
    root: &Path,
    maximum_pending_objects: u64,
    maximum_pending_bytes: u64,
) -> Result<StoreGraph, StoreError> {
    StoreGraph::build(write_back_graph_config(
        root,
        maximum_pending_objects,
        maximum_pending_bytes,
    ))
}

pub(super) fn write_back_graph_config(
    root: &Path,
    maximum_pending_objects: u64,
    maximum_pending_bytes: u64,
) -> StoreGraphConfig {
    let write_back = node_id("write-back");
    let staging = node_id("staging");
    let destination = node_id("destination");
    StoreGraphConfig {
        root: write_back.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::Finding]),
        nodes: BTreeMap::from([
            (
                write_back,
                StoreNodeSpec::WriteBack {
                    staging: staging.clone(),
                    destination: destination.clone(),
                    journal_root: root.join("journal"),
                    maximum_pending_objects,
                    maximum_pending_bytes,
                },
            ),
            (
                staging,
                StoreNodeSpec::Directory {
                    root: root.join("staging"),
                },
            ),
            (
                destination,
                StoreNodeSpec::Directory {
                    root: root.join("archive"),
                },
            ),
        ]),
    }
}

pub(super) fn filesystem_content_snapshot(root: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    fn visit(root: &Path, path: &Path, snapshot: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) {
        for entry in fs::read_dir(path).expect("read snapshot directory") {
            let entry = entry.expect("read snapshot entry");
            let entry_path = entry.path();
            let relative = entry_path
                .strip_prefix(root)
                .expect("snapshot entry under root")
                .to_path_buf();
            let file_type = entry.file_type().expect("snapshot entry type");
            if file_type.is_dir() {
                snapshot.insert(relative, None);
                visit(root, &entry_path, snapshot);
            } else if file_type.is_file() {
                snapshot.insert(
                    relative,
                    Some(fs::read(&entry_path).expect("read snapshot file")),
                );
            } else {
                panic!("unexpected snapshot entry: {}", entry_path.display());
            }
        }
    }

    let mut snapshot = BTreeMap::new();
    visit(root, root, &mut snapshot);
    snapshot
}

pub(super) fn pack_file_count(root: &Path) -> usize {
    fs::read_dir(root.join("packs"))
        .expect("read pack directory")
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.ends_with(".pack"))
        })
        .count()
}

pub(super) fn pack_staging_file_count(root: &Path) -> usize {
    fs::read_dir(root.join("packs"))
        .expect("read pack directory")
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with(".pack.tmp-")
        })
        .count()
}

pub(super) fn only_pack_path(root: &Path) -> PathBuf {
    let packs = fs::read_dir(root.join("packs"))
        .expect("read pack directory")
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.ends_with(".pack"))
        })
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    assert_eq!(packs.len(), 1);
    packs[0].clone()
}

pub(super) fn metrics_for<'a>(
    metrics: &'a [StoreNodeMetricsDescription],
    id: &StoreNodeId,
) -> &'a StoreNodeMetrics {
    &metrics
        .iter()
        .find(|entry| &entry.id == id)
        .expect("metrics node exists")
        .metrics
}

pub(super) fn assert_no_staging(root: &Path, id: ContentId) {
    let path = object_path(root, id);
    let directory = path.parent().expect("object directory");
    if !directory.exists() {
        return;
    }
    assert!(
        fs::read_dir(directory)
            .expect("read object directory")
            .all(|entry| !entry
                .expect("directory entry")
                .file_name()
                .to_string_lossy()
                .starts_with(".staging-"))
    );
}

pub(super) struct UnavailableReadBackend;

pub(super) struct CountingSource {
    pub(super) bytes: Arc<[u8]>,
    pub(super) opens: Arc<AtomicUsize>,
    pub(super) bytes_read: Arc<AtomicUsize>,
}

impl BlobSource for CountingSource {
    fn logical_length(&self) -> u64 {
        self.bytes.len() as u64
    }

    fn open(&self) -> Result<Box<dyn Read + Send>, StoreError> {
        self.opens.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(CountingReader {
            cursor: Cursor::new(self.bytes.clone()),
            bytes_read: self.bytes_read.clone(),
        }))
    }
}

pub(super) struct CountingReader {
    pub(super) cursor: Cursor<Arc<[u8]>>,
    pub(super) bytes_read: Arc<AtomicUsize>,
}

impl Read for CountingReader {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        let read = self.cursor.read(output)?;
        self.bytes_read.fetch_add(read, Ordering::SeqCst);
        Ok(read)
    }
}

pub(super) struct BlockingSource {
    pub(super) bytes: Arc<[u8]>,
    pub(super) opened: mpsc::Sender<()>,
    pub(super) release: Mutex<Option<mpsc::Receiver<()>>>,
}

impl BlobSource for BlockingSource {
    fn logical_length(&self) -> u64 {
        self.bytes.len() as u64
    }

    fn open(&self) -> Result<Box<dyn Read + Send>, StoreError> {
        let release = self
            .release
            .lock()
            .expect("blocking source release lock")
            .take()
            .expect("blocking source opens once");
        self.opened.send(()).expect("signal blocking source open");
        Ok(Box::new(BlockingReader {
            cursor: Cursor::new(Arc::clone(&self.bytes)),
            release: Some(release),
        }))
    }
}

pub(super) struct BlockingReader {
    pub(super) cursor: Cursor<Arc<[u8]>>,
    pub(super) release: Option<mpsc::Receiver<()>>,
}

impl Read for BlockingReader {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        if let Some(release) = self.release.take() {
            release
                .recv()
                .map_err(|_| std::io::Error::other("blocking source release dropped"))?;
        }
        self.cursor.read(output)
    }
}

pub(super) struct ChangingSource {
    pub(super) opens: AtomicUsize,
    pub(super) first: &'static [u8],
    pub(super) later: &'static [u8],
}

impl BlobSource for ChangingSource {
    fn logical_length(&self) -> u64 {
        self.first.len() as u64
    }

    fn open(&self) -> Result<Box<dyn Read + Send>, StoreError> {
        let bytes = if self.opens.fetch_add(1, Ordering::SeqCst) == 0 {
            self.first
        } else {
            self.later
        };
        Ok(Box::new(Cursor::new(bytes)))
    }
}

pub(super) struct FailingSource {
    pub(super) bytes: &'static [u8],
    pub(super) fail_after: usize,
}

impl BlobSource for FailingSource {
    fn logical_length(&self) -> u64 {
        self.bytes.len() as u64
    }

    fn open(&self) -> Result<Box<dyn Read + Send>, StoreError> {
        Ok(Box::new(FailingReader {
            bytes: self.bytes,
            fail_after: self.fail_after,
            position: 0,
        }))
    }
}

pub(super) struct FailingReader {
    pub(super) bytes: &'static [u8],
    pub(super) fail_after: usize,
    pub(super) position: usize,
}

impl Read for FailingReader {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        if self.position >= self.fail_after {
            return Err(std::io::Error::other("injected mid-stream failure"));
        }
        let end = self
            .bytes
            .len()
            .min(self.fail_after)
            .min(self.position.saturating_add(output.len()));
        let bytes = &self.bytes[self.position..end];
        output[..bytes.len()].copy_from_slice(bytes);
        self.position = end;
        Ok(bytes.len())
    }
}

pub(super) struct InterruptOnceSource {
    pub(super) bytes: &'static [u8],
}

impl BlobSource for InterruptOnceSource {
    fn logical_length(&self) -> u64 {
        self.bytes.len() as u64
    }

    fn open(&self) -> Result<Box<dyn Read + Send>, StoreError> {
        Ok(Box::new(InterruptOnceReader {
            cursor: Cursor::new(self.bytes),
            interrupted: false,
        }))
    }
}

pub(super) struct InterruptOnceReader {
    pub(super) cursor: Cursor<&'static [u8]>,
    pub(super) interrupted: bool,
}

impl Read for InterruptOnceReader {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        if !self.interrupted {
            self.interrupted = true;
            return Err(std::io::Error::from(std::io::ErrorKind::Interrupted));
        }
        self.cursor.read(output)
    }
}

pub(super) struct RepeatSource {
    pub(super) byte: u8,
    pub(super) logical_length: u64,
}

impl BlobSource for RepeatSource {
    fn logical_length(&self) -> u64 {
        self.logical_length
    }

    fn open(&self) -> Result<Box<dyn Read + Send>, StoreError> {
        Ok(Box::new(
            std::io::repeat(self.byte).take(self.logical_length),
        ))
    }
}

pub(super) struct MismatchedLengthSource {
    pub(super) declared: u64,
    pub(super) bytes: &'static [u8],
}

impl BlobSource for MismatchedLengthSource {
    fn logical_length(&self) -> u64 {
        self.declared
    }

    fn open(&self) -> Result<Box<dyn Read + Send>, StoreError> {
        Ok(Box::new(Cursor::new(self.bytes)))
    }
}

pub(super) struct FixedReadBackend {
    pub(super) source: BlobHandle,
}

impl ImmutableBlobBackend for FixedReadBackend {
    fn name(&self) -> &str {
        "fixed-read"
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities::default()
    }

    fn contains(&self, _id: ContentId) -> Result<bool, StoreError> {
        Ok(true)
    }

    fn read(&self, _id: ContentId, _range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        Ok(self.source.clone())
    }

    fn put_if_absent(
        &self,
        _id: ContentId,
        _source: &BlobHandle,
    ) -> Result<PutReceipt, StoreError> {
        Err(StoreError::Unsupported {
            capability: "fixed-read test put",
        })
    }
}

pub(super) struct DelayedMetricsBackend {
    pub(super) child: Arc<MemoryBlobBackend>,
    pub(super) delay: Duration,
}

impl ImmutableBlobBackend for DelayedMetricsBackend {
    fn name(&self) -> &str {
        "delayed-metrics"
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.child.capabilities()
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        thread::sleep(self.delay);
        self.child.contains(id)
    }

    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        thread::sleep(self.delay);
        let blob = self.child.read(id, range)?;
        let source = Arc::new(DelayedBlobSource {
            source: blob.clone(),
            delay: self.delay,
        });
        Ok(blob.with_observed_source(source))
    }

    fn put_if_absent(&self, id: ContentId, source: &BlobHandle) -> Result<PutReceipt, StoreError> {
        thread::sleep(self.delay);
        self.child.put_if_absent(id, source)
    }
}

pub(super) struct DelayedBlobSource {
    pub(super) source: BlobHandle,
    pub(super) delay: Duration,
}

impl BlobSource for DelayedBlobSource {
    fn logical_length(&self) -> u64 {
        self.source.logical_length()
    }

    fn open(&self) -> Result<Box<dyn Read + Send>, StoreError> {
        thread::sleep(self.delay);
        Ok(Box::new(DelayedBlobReader {
            reader: self.source.open()?,
            delay: self.delay,
        }))
    }
}

pub(super) struct DelayedBlobReader {
    pub(super) reader: Box<dyn Read + Send>,
    pub(super) delay: Duration,
}

impl Read for DelayedBlobReader {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        thread::sleep(self.delay);
        self.reader.read(output)
    }
}

impl ImmutableBlobBackend for UnavailableReadBackend {
    fn name(&self) -> &str {
        "unavailable"
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities::default()
    }

    fn contains(&self, _id: ContentId) -> Result<bool, StoreError> {
        Err(StoreError::Unavailable)
    }

    fn read(&self, _id: ContentId, _range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        Err(StoreError::Unavailable)
    }

    fn put_if_absent(
        &self,
        _id: ContentId,
        _source: &BlobHandle,
    ) -> Result<PutReceipt, StoreError> {
        Err(StoreError::Unavailable)
    }
}

pub(super) struct FailFirstPutBackend {
    pub(super) failed: AtomicBool,
    pub(super) inner: MemoryBlobBackend,
}

impl FailFirstPutBackend {
    pub(super) fn new() -> Self {
        Self {
            failed: AtomicBool::new(false),
            inner: MemoryBlobBackend::new("fail-first-inner", 1_024),
        }
    }
}

impl ImmutableBlobBackend for FailFirstPutBackend {
    fn name(&self) -> &str {
        "fail-first"
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.inner.capabilities()
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        self.inner.contains(id)
    }

    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        self.inner.read(id, range)
    }

    fn put_if_absent(&self, id: ContentId, source: &BlobHandle) -> Result<PutReceipt, StoreError> {
        if !self.failed.swap(true, Ordering::SeqCst) {
            return Err(StoreError::Unavailable);
        }
        self.inner.put_if_absent(id, source)
    }
}

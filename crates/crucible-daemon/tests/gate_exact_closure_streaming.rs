//! Production exact-closure streaming acceptance gate.
//!
//! This direct-capture section exercises the native production codec through
//! CAS preparation, loose and composed durable publication, and authenticated
//! lazy loading. Parent-relative v9 capture is composed into this gate
//! separately once its production host pipeline is available.

// crucible-lint: allow panic-shortcut -- gate assertions identify the violated invariant.
#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Read};
use std::path::Path;
use std::sync::{Arc, Mutex, mpsc};
use std::thread;

use crucible_api::build_streaming_production_checkpoint_codec_fixture;
use crucible_cas::content_store::{
    BackendCapabilities, BlobHandle, BlobInventoryRecord, BlobSource, ByteRange, ContentId,
    DirectoryBlobBackend, DurabilityRequirement, ImmutableBlobBackend, ObjectKind, PutReceipt,
    StoreError, StoreGraph, StoreGraphAdmin, StoreGraphConfig, StoreNodeId, StoreNodeSpec,
};
use crucible_daemon::ExactCheckpointStore;
use tempfile::TempDir;

const MAX_CHECKPOINT_BYTES: u64 = 512 * 1024 * 1024;
const MAX_CHECKPOINT_READ_BYTES: usize = 1024 * 1024;
const CAS_COPY_BUFFER_BYTES: usize = 64 * 1024;
const DIRECT_FRAGMENT_BYTES: usize = 8191;
const GRAPH_FRAGMENT_BYTES: usize = 65_521;
const FAIL_AFTER_BYTES: u64 = 96 * 1024;

#[test]
fn direct_production_closure_streams_across_durable_placements_and_failures() {
    let roots = GateRoots::new();
    let fixture = build_streaming_production_checkpoint_codec_fixture(roots.native_source.path())
        .expect("build authenticated multi-chunk production fixture");
    assert!(fixture.closure().objects().len() >= 7);
    assert!(fixture.overlay_bytes() > fixture.vmstate_bytes() * 4);

    let direct_leaf = Arc::new(DirectoryBlobBackend::new(
        "direct-loose",
        roots.direct_cas.path(),
    ));
    let direct_observer = Arc::new(ObservedBackend::new(
        "direct-observer",
        direct_leaf.clone(),
        DIRECT_FRAGMENT_BYTES,
        None,
    ));
    let direct_store = ExactCheckpointStore::new(direct_observer.clone(), MAX_CHECKPOINT_BYTES)
        .expect("admit observed direct store");
    let direct_prepared = direct_store
        .prepare_production_closure(fixture.closure().clone())
        .expect("prepare direct production closure");
    direct_observer.fail_next_large_put();

    direct_store
        .publish_production_closure(&direct_prepared)
        .expect_err("injected mid-object failure must stop publication");
    assert!(
        !direct_leaf
            .contains(direct_prepared.root().content_id())
            .expect("inspect failed direct root")
    );
    assert_eq!(direct_observer.snapshot().put.active, 0);
    assert_no_staging_files(roots.direct_cas.path());

    direct_observer.reset_streams();
    let direct_publication = direct_store
        .publish_production_closure(&direct_prepared)
        .expect("retry direct publication idempotently");
    let direct_inventory = inventory(direct_leaf.as_ref());
    assert_publication_streamed_once(
        direct_observer.snapshot().put,
        direct_inventory.logical_bytes,
        direct_inventory.objects.len(),
        DIRECT_FRAGMENT_BYTES,
    );
    assert_eq!(
        direct_publication.object_count() as usize,
        fixture.closure().objects().len()
    );
    assert!(direct_publication.index_count() >= 1);

    let (graph, graph_admin) = build_mirrored_graph(roots.graph_cas.path());
    let graph_observer = Arc::new(ObservedBackend::new(
        "graph-observer",
        Arc::new(graph),
        GRAPH_FRAGMENT_BYTES,
        None,
    ));
    let graph_store = ExactCheckpointStore::new(graph_observer.clone(), MAX_CHECKPOINT_BYTES)
        .expect("admit observed graph store");
    let graph_prepared = graph_store
        .prepare_production_closure(fixture.closure().clone())
        .expect("prepare graph production closure");
    assert_eq!(graph_prepared.root(), direct_prepared.root());

    let graph_publication = graph_store
        .publish_production_closure(&graph_prepared)
        .expect("publish production closure through graph");
    assert_eq!(graph_publication.root(), direct_publication.root());
    let graph_inventories = graph_inventories(&graph_admin);
    assert_eq!(graph_inventories.len(), 2);
    assert!(
        graph_inventories
            .iter()
            .all(|inventory| inventory.objects == direct_inventory.objects)
    );
    let graph_put = graph_observer.snapshot().put;
    assert_eq!(graph_put.active, 0);
    assert_eq!(graph_put.maximum_active, 1);
    assert_eq!(graph_put.maximum_request, CAS_COPY_BUFFER_BYTES);
    assert!(graph_put.maximum_returned <= GRAPH_FRAGMENT_BYTES);
    assert!(graph_put.maximum_returned > DIRECT_FRAGMENT_BYTES);
    // Routed admission authenticates once before the two durable leaf writes.
    assert_eq!(graph_put.opens, graph_put.calls * 3);
    assert_eq!(
        graph_put.opened_declared_bytes,
        direct_inventory.logical_bytes * 3
    );
    assert_eq!(graph_put.bytes, graph_put.opened_declared_bytes);

    direct_observer.reset_streams();
    let direct_loaded = direct_store
        .load_production_closure(direct_publication.root())
        .expect("load direct production closure lazily");
    assert_eq!(
        direct_loaded.production_identity(),
        fixture.closure().identity()
    );
    assert_eq!(direct_loaded.scenario(), fixture.closure().scenario());
    assert_eq!(
        direct_loaded.configuration(),
        fixture.closure().configuration()
    );
    assert_complete_bounded_reads(direct_observer.snapshot().read, DIRECT_FRAGMENT_BYTES);

    let (read_synchronization, read_controller) = ReadSynchronization::start();
    let synchronized_archive = Arc::new(ObservedBackend::new(
        "synchronized-archive",
        direct_leaf,
        CAS_COPY_BUFFER_BYTES,
        Some(Arc::clone(&read_synchronization)),
    ));
    let archive_store =
        ExactCheckpointStore::new(synchronized_archive.clone(), MAX_CHECKPOINT_BYTES)
            .expect("admit synchronized archive");
    let archived = archive_store
        .load_production_closure(direct_publication.root())
        .expect("load production closure from latency archive");
    assert_eq!(archived.root(), direct_loaded.root());
    assert_eq!(
        archived.production_identity(),
        direct_loaded.production_identity()
    );
    assert_eq!(archived.scenario(), direct_loaded.scenario());
    assert_eq!(archived.configuration(), direct_loaded.configuration());
    assert_eq!(
        archived
            .authenticated_restore_bytes()
            .expect("measure archive restore closure"),
        direct_loaded
            .authenticated_restore_bytes()
            .expect("measure direct restore closure")
    );
    let archive_read = synchronized_archive.snapshot().read;
    assert_complete_bounded_reads(archive_read, CAS_COPY_BUFFER_BYTES);
    assert!(archive_read.synchronized_reads > 0);

    drop(archived);
    drop(archive_store);
    drop(synchronized_archive);
    drop(read_synchronization);
    read_controller.join().expect("join read synchronization");
}

struct GateRoots {
    native_source: TempDir,
    direct_cas: TempDir,
    graph_cas: TempDir,
}

impl GateRoots {
    fn new() -> Self {
        Self {
            native_source: TempDir::new().expect("native fixture source"),
            direct_cas: TempDir::new().expect("direct CAS root"),
            graph_cas: TempDir::new().expect("graph CAS root"),
        }
    }
}

#[derive(Clone, Copy, Default)]
struct StreamSnapshot {
    calls: u64,
    opens: u64,
    active: u64,
    maximum_active: u64,
    opened_declared_bytes: u64,
    bytes: u64,
    maximum_request: usize,
    maximum_returned: usize,
    synchronized_reads: u64,
}

#[derive(Clone, Copy, Default)]
struct ObservationSnapshot {
    put: StreamSnapshot,
    read: StreamSnapshot,
}

#[derive(Default)]
struct ObservationState {
    put: StreamSnapshot,
    read: StreamSnapshot,
    fail_next_large_put: bool,
}

struct ReadSynchronization {
    requests: mpsc::SyncSender<mpsc::SyncSender<()>>,
}

impl ReadSynchronization {
    fn start() -> (Arc<Self>, thread::JoinHandle<()>) {
        let (requests, receiver) = mpsc::sync_channel::<mpsc::SyncSender<()>>(0);
        let controller = thread::spawn(move || {
            while let Ok(release) = receiver.recv() {
                release.send(()).expect("release synchronized read");
            }
        });
        (Arc::new(Self { requests }), controller)
    }

    fn rendezvous(&self) {
        let (release, released) = mpsc::sync_channel(0);
        self.requests.send(release).expect("synchronize read");
        released.recv().expect("observe synchronized read release");
    }
}

#[derive(Clone, Copy)]
enum Traffic {
    Put,
    Read,
}

struct ObservedBackend {
    name: String,
    inner: Arc<dyn ImmutableBlobBackend>,
    fragment_bytes: usize,
    read_synchronization: Option<Arc<ReadSynchronization>>,
    observations: Arc<Mutex<ObservationState>>,
}

impl ObservedBackend {
    fn new(
        name: impl Into<String>,
        inner: Arc<dyn ImmutableBlobBackend>,
        fragment_bytes: usize,
        read_synchronization: Option<Arc<ReadSynchronization>>,
    ) -> Self {
        Self {
            name: name.into(),
            inner,
            fragment_bytes,
            read_synchronization,
            observations: Arc::new(Mutex::new(ObservationState::default())),
        }
    }

    fn fail_next_large_put(&self) {
        self.observations
            .lock()
            .expect("lock observations")
            .fail_next_large_put = true;
    }

    fn reset_streams(&self) {
        let mut state = self.observations.lock().expect("lock observations");
        state.put = StreamSnapshot::default();
        state.read = StreamSnapshot::default();
    }

    fn snapshot(&self) -> ObservationSnapshot {
        let state = self.observations.lock().expect("lock observations");
        ObservationSnapshot {
            put: state.put,
            read: state.read,
        }
    }

    fn observed_source(
        &self,
        source: BlobHandle,
        traffic: Traffic,
        fail_after: Option<u64>,
    ) -> BlobHandle {
        BlobHandle::new(Arc::new(ObservedSource {
            source,
            traffic,
            fragment_bytes: self.fragment_bytes,
            read_synchronization: self.read_synchronization.clone(),
            fail_after,
            observations: Arc::clone(&self.observations),
        }))
    }
}

impl ImmutableBlobBackend for ObservedBackend {
    fn name(&self) -> &str {
        &self.name
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.inner.capabilities()
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        self.inner.contains(id)
    }

    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        let handle = self.inner.read(id, range)?;
        self.observations
            .lock()
            .expect("lock observations")
            .read
            .calls += 1;
        Ok(self.observed_source(handle, Traffic::Read, None))
    }

    fn put_if_absent(&self, id: ContentId, source: &BlobHandle) -> Result<PutReceipt, StoreError> {
        let fail_after = {
            let mut state = self.observations.lock().expect("lock observations");
            state.put.calls += 1;
            if source.logical_length() >= 4 * 1024 * 1024 && state.fail_next_large_put {
                state.fail_next_large_put = false;
                Some(FAIL_AFTER_BYTES)
            } else {
                None
            }
        };
        let source = self.observed_source(source.clone(), Traffic::Put, fail_after);
        self.inner.put_if_absent(id, &source)
    }
}

struct ObservedSource {
    source: BlobHandle,
    traffic: Traffic,
    fragment_bytes: usize,
    read_synchronization: Option<Arc<ReadSynchronization>>,
    fail_after: Option<u64>,
    observations: Arc<Mutex<ObservationState>>,
}

impl BlobSource for ObservedSource {
    fn logical_length(&self) -> u64 {
        self.source.logical_length()
    }

    fn open(&self) -> Result<Box<dyn Read + Send>, StoreError> {
        let reader = self.source.open()?;
        {
            let mut observations = self.observations.lock().expect("lock observations");
            let stats = traffic_stats(&mut observations, self.traffic);
            stats.opens += 1;
            stats.active += 1;
            stats.maximum_active = stats.maximum_active.max(stats.active);
            stats.opened_declared_bytes += self.source.logical_length();
        }
        Ok(Box::new(ObservedReader {
            reader,
            traffic: self.traffic,
            fragment_bytes: self.fragment_bytes,
            read_synchronization: self.read_synchronization.clone(),
            fail_after: self.fail_after,
            bytes: 0,
            observations: Arc::clone(&self.observations),
        }))
    }
}

struct ObservedReader {
    reader: Box<dyn Read + Send>,
    traffic: Traffic,
    fragment_bytes: usize,
    read_synchronization: Option<Arc<ReadSynchronization>>,
    fail_after: Option<u64>,
    bytes: u64,
    observations: Arc<Mutex<ObservationState>>,
}

impl Read for ObservedReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.fail_after.is_some_and(|limit| self.bytes >= limit) {
            return Err(io::Error::other("injected mid-object source failure"));
        }
        let mut limit = output.len().min(self.fragment_bytes.max(1));
        if let Some(fail_after) = self.fail_after {
            limit = limit.min(usize::try_from(fail_after - self.bytes).unwrap_or(usize::MAX));
        }
        if let Some(synchronization) = &self.read_synchronization
            && !output.is_empty()
        {
            synchronization.rendezvous();
        }
        let read = self.reader.read(&mut output[..limit])?;
        self.bytes = self.bytes.saturating_add(read as u64);

        let mut observations = self.observations.lock().expect("lock observations");
        let stats = traffic_stats(&mut observations, self.traffic);
        stats.maximum_request = stats.maximum_request.max(output.len());
        stats.maximum_returned = stats.maximum_returned.max(read);
        stats.bytes = stats.bytes.saturating_add(read as u64);
        if self.read_synchronization.is_some() && !output.is_empty() {
            stats.synchronized_reads += 1;
        }
        Ok(read)
    }
}

impl Drop for ObservedReader {
    fn drop(&mut self) {
        if let Ok(mut observations) = self.observations.lock() {
            let stats = traffic_stats(&mut observations, self.traffic);
            stats.active = stats.active.saturating_sub(1);
        }
    }
}

fn traffic_stats(state: &mut ObservationState, traffic: Traffic) -> &mut StreamSnapshot {
    match traffic {
        Traffic::Put => &mut state.put,
        Traffic::Read => &mut state.read,
    }
}

struct Inventory {
    objects: BTreeMap<ContentId, u64>,
    logical_bytes: u64,
}

fn inventory(admin: &dyn crucible_cas::content_store::BlobStoreAdmin) -> Inventory {
    let mut fence = admin
        .acquire_inventory_fence()
        .expect("acquire physical inventory fence");
    let mut objects = BTreeMap::new();
    let summary = fence
        .visit_inventory(&mut |record: BlobInventoryRecord| {
            assert!(
                objects
                    .insert(record.id(), record.logical_length())
                    .is_none(),
                "physical inventory repeated one logical ID"
            );
            Ok(())
        })
        .expect("complete physical inventory");
    assert_eq!(summary.objects() as usize, objects.len());
    Inventory {
        objects,
        logical_bytes: summary.logical_bytes(),
    }
}

fn graph_inventories(admin: &StoreGraphAdmin) -> Vec<Inventory> {
    admin
        .physical()
        .into_iter()
        .map(|physical| inventory(physical.admin()))
        .collect()
}

fn assert_publication_streamed_once(
    stats: StreamSnapshot,
    logical_bytes: u64,
    object_count: usize,
    fragment_bytes: usize,
) {
    assert_eq!(stats.active, 0);
    assert_eq!(stats.maximum_active, 1);
    assert_eq!(stats.calls as usize, object_count);
    assert_eq!(stats.opens, stats.calls);
    assert_eq!(stats.opened_declared_bytes, logical_bytes);
    assert_eq!(stats.bytes, logical_bytes);
    assert_eq!(stats.maximum_request, CAS_COPY_BUFFER_BYTES);
    assert!(stats.maximum_returned <= fragment_bytes);
}

fn assert_complete_bounded_reads(stats: StreamSnapshot, fragment_bytes: usize) {
    assert_eq!(stats.active, 0);
    assert_eq!(stats.maximum_active, 1);
    assert!(stats.calls > 0);
    assert_eq!(stats.bytes, stats.opened_declared_bytes);
    assert!(stats.maximum_request <= MAX_CHECKPOINT_READ_BYTES);
    assert!(stats.maximum_returned <= fragment_bytes);
}

fn build_mirrored_graph(root: &Path) -> (StoreGraph, StoreGraphAdmin) {
    let directory = node("directory");
    let packed = node("packed");
    let mirror = node("mirror");
    let routed = node("routed");
    let metrics = node("metrics");
    let durability = node("durability");
    let admitted = BTreeSet::from([
        ObjectKind::DeviceState,
        ObjectKind::ExactManifest,
        ObjectKind::Observation,
    ]);
    let config = StoreGraphConfig {
        root: durability.clone(),
        admitted_kinds: admitted.clone(),
        nodes: BTreeMap::from([
            (
                directory.clone(),
                StoreNodeSpec::Directory {
                    root: root.join("directory"),
                },
            ),
            (
                packed.clone(),
                StoreNodeSpec::Packed {
                    root: root.join("packed"),
                    target_pack_bytes: 8 * 1024 * 1024,
                },
            ),
            (
                mirror.clone(),
                StoreNodeSpec::WriteThrough {
                    children: vec![directory, packed],
                },
            ),
            (
                routed.clone(),
                StoreNodeSpec::Routed {
                    routes: admitted
                        .iter()
                        .copied()
                        .map(|kind| (kind, mirror.clone()))
                        .collect(),
                },
            ),
            (metrics.clone(), StoreNodeSpec::Metrics { child: routed }),
            (
                durability,
                StoreNodeSpec::DurabilityPolicy {
                    child: metrics,
                    requirements: admitted
                        .iter()
                        .copied()
                        .map(|kind| {
                            (
                                kind,
                                DurabilityRequirement::new(2, false)
                                    .expect("two durable placements"),
                            )
                        })
                        .collect(),
                },
            ),
        ]),
    };
    StoreGraph::build_with_admin(config).expect("admit mirrored exact-checkpoint graph")
}

fn node(value: &str) -> StoreNodeId {
    StoreNodeId::new(value).expect("valid store node ID")
}

fn assert_no_staging_files(root: &Path) {
    fn visit(path: &Path) {
        for entry in fs::read_dir(path).expect("walk CAS directory") {
            let entry = entry.expect("read CAS directory entry");
            let file_type = entry.file_type().expect("inspect CAS directory entry");
            assert!(
                !entry.file_name().to_string_lossy().starts_with(".staging-"),
                "failed put leaked a staging file"
            );
            if file_type.is_dir() {
                visit(&entry.path());
            }
        }
    }
    visit(root);
}

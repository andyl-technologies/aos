//! Bounded operational maintenance for one managed campaign store.
//!
//! The worker may flush durable write-back transfers and reclaim unfinished
//! S3 multipart uploads. It deliberately cannot inventory or delete committed
//! objects: destructive campaign GC additionally needs exact ref, pin,
//! assignment, and in-flight publication roots and remains an explicit
//! generation-bound plan/apply operation.

use std::collections::BTreeMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crucible_cas::content_store::{StoreError, StoreNodeId, StoreS3MultipartListCursor};

use super::{CampaignLocalRepositoryMaintenance, CampaignLoopbackServerShutdown};

const MINIMUM_MAINTENANCE_INTERVAL: Duration = Duration::from_millis(100);
const MAXIMUM_MAINTENANCE_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
const MAXIMUM_WRITE_BACK_TRANSFERS_PER_PASS: u32 = 65_536;
const MAXIMUM_S3_NODES_PER_PASS: u16 = 256;
const MAXIMUM_S3_UPLOADS_PER_NODE: u16 = 1_000;

/// Fixed bounds for one managed campaign-store maintenance worker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CampaignStoreMaintenanceConfig {
    interval: Duration,
    maximum_write_back_transfers_per_pass: u32,
    maximum_s3_nodes_per_pass: u16,
    maximum_s3_uploads_per_node: u16,
}

impl CampaignStoreMaintenanceConfig {
    /// Validates one fixed-cadence maintenance policy.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignStoreMaintenanceConfigError`] when the interval is
    /// outside 100 ms through 24 hours, the write-back limit is outside
    /// 1 through 65,536, the S3-node limit is outside 1 through 256, or the
    /// per-node upload limit is outside 1 through 1,000.
    pub fn new(
        interval: Duration,
        maximum_write_back_transfers_per_pass: u32,
        maximum_s3_nodes_per_pass: u16,
        maximum_s3_uploads_per_node: u16,
    ) -> Result<Self, CampaignStoreMaintenanceConfigError> {
        if !(MINIMUM_MAINTENANCE_INTERVAL..=MAXIMUM_MAINTENANCE_INTERVAL).contains(&interval) {
            return Err(CampaignStoreMaintenanceConfigError::Interval);
        }
        if maximum_write_back_transfers_per_pass == 0
            || maximum_write_back_transfers_per_pass > MAXIMUM_WRITE_BACK_TRANSFERS_PER_PASS
        {
            return Err(CampaignStoreMaintenanceConfigError::WriteBackTransfers);
        }
        if maximum_s3_nodes_per_pass == 0 || maximum_s3_nodes_per_pass > MAXIMUM_S3_NODES_PER_PASS {
            return Err(CampaignStoreMaintenanceConfigError::S3Nodes);
        }
        if maximum_s3_uploads_per_node == 0
            || maximum_s3_uploads_per_node > MAXIMUM_S3_UPLOADS_PER_NODE
        {
            return Err(CampaignStoreMaintenanceConfigError::S3Uploads);
        }
        Ok(Self {
            interval,
            maximum_write_back_transfers_per_pass,
            maximum_s3_nodes_per_pass,
            maximum_s3_uploads_per_node,
        })
    }

    /// Returns the fixed delay between completed maintenance passes.
    #[must_use]
    pub const fn interval(self) -> Duration {
        self.interval
    }

    /// Returns the global write-back completion limit for one pass.
    #[must_use]
    pub const fn maximum_write_back_transfers_per_pass(self) -> u32 {
        self.maximum_write_back_transfers_per_pass
    }

    /// Returns the round-robin S3-node limit for one pass.
    #[must_use]
    pub const fn maximum_s3_nodes_per_pass(self) -> u16 {
        self.maximum_s3_nodes_per_pass
    }

    /// Returns the unfinished-upload limit for each visited S3 node.
    #[must_use]
    pub const fn maximum_s3_uploads_per_node(self) -> u16 {
        self.maximum_s3_uploads_per_node
    }
}

/// Invalid campaign-store maintenance bound.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CampaignStoreMaintenanceConfigError {
    /// The fixed cadence was too short or too long.
    #[error("campaign-store maintenance interval is outside 100ms..=24h")]
    Interval,
    /// The write-back completion limit was zero or excessive.
    #[error("campaign-store write-back limit is outside 1..=65536")]
    WriteBackTransfers,
    /// The S3 node limit was zero or excessive.
    #[error("campaign-store S3 node limit is outside 1..=256")]
    S3Nodes,
    /// The per-node unfinished-upload limit was zero or excessive.
    #[error("campaign-store S3 upload limit is outside 1..=1000")]
    S3Uploads,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct CampaignStoreMaintenanceSnapshot {
    pub(super) passes: u64,
    pub(super) write_back_completed: u64,
    pub(super) write_back_pending: u64,
    pub(super) s3_nodes_visited: u64,
    pub(super) s3_uploads_aborted: u64,
}

struct CampaignStoreMaintenanceShared {
    closed: Mutex<bool>,
    changed: Condvar,
    snapshot: Mutex<CampaignStoreMaintenanceSnapshot>,
}

impl CampaignStoreMaintenanceShared {
    fn new() -> Self {
        Self {
            closed: Mutex::new(false),
            changed: Condvar::new(),
            snapshot: Mutex::new(CampaignStoreMaintenanceSnapshot::default()),
        }
    }

    fn close(&self) {
        match self.closed.lock() {
            Ok(mut closed) => {
                *closed = true;
                self.changed.notify_all();
            }
            Err(poisoned) => {
                *poisoned.into_inner() = true;
                self.changed.notify_all();
            }
        }
    }

    fn wait_for_pass(&self, interval: Duration) -> Result<bool, MaintenanceStateError> {
        let closed = self.closed.lock().map_err(|_| MaintenanceStateError)?;
        if *closed {
            return Ok(false);
        }
        let (closed, _timeout) = self
            .changed
            .wait_timeout(closed, interval)
            .map_err(|_| MaintenanceStateError)?;
        Ok(!*closed)
    }

    fn update_snapshot(
        &self,
        update: impl FnOnce(&mut CampaignStoreMaintenanceSnapshot),
    ) -> Result<(), MaintenanceStateError> {
        let mut snapshot = self.snapshot.lock().map_err(|_| MaintenanceStateError)?;
        update(&mut snapshot);
        Ok(())
    }

    #[cfg(test)]
    fn snapshot(&self) -> CampaignStoreMaintenanceSnapshot {
        self.snapshot
            .lock()
            .map(|snapshot| *snapshot)
            .unwrap_or_default()
    }
}

pub(super) struct CampaignStoreMaintenanceOwner {
    _authority: Arc<CampaignLocalRepositoryMaintenance>,
    shared: Option<Arc<CampaignStoreMaintenanceShared>>,
    worker: Option<JoinHandle<MaintenanceThreadExit>>,
}

impl CampaignStoreMaintenanceOwner {
    pub(super) fn retain(authority: CampaignLocalRepositoryMaintenance) -> Self {
        Self {
            _authority: Arc::new(authority),
            shared: None,
            worker: None,
        }
    }

    pub(super) fn start(
        authority: CampaignLocalRepositoryMaintenance,
        config: CampaignStoreMaintenanceConfig,
        shutdown: CampaignLoopbackServerShutdown,
    ) -> Result<Self, std::io::Error> {
        let authority = Arc::new(authority);
        let shared = Arc::new(CampaignStoreMaintenanceShared::new());
        let worker_authority = Arc::clone(&authority);
        let worker_shared = Arc::clone(&shared);
        let worker = thread::Builder::new()
            .name(String::from("crucible-campaign-store-maintenance"))
            .spawn(move || {
                let result = catch_unwind(AssertUnwindSafe(|| {
                    run_maintenance(worker_authority, worker_shared, config)
                }));
                match result {
                    Ok(Ok(())) => MaintenanceThreadExit::Closed,
                    Ok(Err(MaintenanceThreadFailure::Operation(failure))) => {
                        shutdown.shutdown();
                        MaintenanceThreadExit::Failed(failure)
                    }
                    Ok(Err(MaintenanceThreadFailure::State)) => {
                        shutdown.shutdown();
                        MaintenanceThreadExit::Panicked
                    }
                    Err(_) => {
                        shutdown.shutdown();
                        MaintenanceThreadExit::Panicked
                    }
                }
            })?;
        Ok(Self {
            _authority: authority,
            shared: Some(shared),
            worker: Some(worker),
        })
    }

    pub(super) fn close_and_join(&mut self) -> Result<(), MaintenanceJoinError> {
        if let Some(shared) = self.shared.as_ref() {
            shared.close();
        }
        let Some(worker) = self.worker.take() else {
            return Ok(());
        };
        match worker.join() {
            Ok(MaintenanceThreadExit::Closed) => Ok(()),
            Ok(MaintenanceThreadExit::Failed(failure)) => {
                Err(MaintenanceJoinError::Operation(failure))
            }
            Ok(MaintenanceThreadExit::Panicked) | Err(_) => Err(MaintenanceJoinError::Panicked),
        }
    }
}

impl Drop for CampaignStoreMaintenanceOwner {
    fn drop(&mut self) {
        let _ = self.close_and_join();
    }
}

#[derive(Debug)]
enum MaintenanceThreadExit {
    Closed,
    Failed(MaintenanceOperationFailure),
    Panicked,
}

#[derive(Debug)]
pub(super) enum MaintenanceJoinError {
    Operation(MaintenanceOperationFailure),
    Panicked,
}

#[derive(Debug)]
pub(super) struct MaintenanceOperationFailure {
    pub(super) operation: &'static str,
    pub(super) boundary: String,
    pub(super) source: StoreError,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MaintenanceStateError;

struct MaintenanceCursorState {
    next_node: usize,
    cursors: BTreeMap<StoreNodeId, StoreS3MultipartListCursor>,
}

impl MaintenanceCursorState {
    fn new() -> Self {
        Self {
            next_node: 0,
            cursors: BTreeMap::new(),
        }
    }
}

fn run_maintenance(
    authority: Arc<CampaignLocalRepositoryMaintenance>,
    shared: Arc<CampaignStoreMaintenanceShared>,
    config: CampaignStoreMaintenanceConfig,
) -> Result<(), MaintenanceThreadFailure> {
    let mut cursors = MaintenanceCursorState::new();
    while shared
        .wait_for_pass(config.interval())
        .map_err(|_| MaintenanceThreadFailure::State)?
    {
        run_maintenance_pass(&authority, &shared, config, &mut cursors)?;
    }
    Ok(())
}

#[derive(Debug)]
enum MaintenanceThreadFailure {
    Operation(MaintenanceOperationFailure),
    State,
}

impl From<MaintenanceOperationFailure> for MaintenanceThreadFailure {
    fn from(failure: MaintenanceOperationFailure) -> Self {
        Self::Operation(failure)
    }
}

fn run_maintenance_pass(
    authority: &CampaignLocalRepositoryMaintenance,
    shared: &CampaignStoreMaintenanceShared,
    config: CampaignStoreMaintenanceConfig,
    cursors: &mut MaintenanceCursorState,
) -> Result<(), MaintenanceThreadFailure> {
    let mut delta = CampaignStoreMaintenanceSnapshot {
        passes: 1,
        ..CampaignStoreMaintenanceSnapshot::default()
    };
    let summary = authority
        .store
        .flush_write_back(config.maximum_write_back_transfers_per_pass())
        .map_err(|source| MaintenanceOperationFailure {
            operation: "flush-write-back",
            boundary: String::from("store-graph"),
            source,
        })?;
    delta.write_back_completed = u64::from(summary.completed());
    let write_back_pending = summary.pending();

    let nodes = authority.graph.s3_multipart_cleanup();
    if !nodes.is_empty() {
        let count = nodes
            .len()
            .min(usize::from(config.maximum_s3_nodes_per_pass()));
        let start = cursors.next_node % nodes.len();
        for offset in 0..count {
            let node = nodes[(start + offset) % nodes.len()];
            let after = cursors.cursors.get(node.node());
            let page = node
                .admin()
                .cleanup_page(after, config.maximum_s3_uploads_per_node())
                .map_err(|source| MaintenanceOperationFailure {
                    operation: "cleanup-S3-multipart",
                    boundary: node.node().as_str().to_owned(),
                    source,
                })?;
            delta.s3_nodes_visited = delta.s3_nodes_visited.saturating_add(1);
            delta.s3_uploads_aborted = delta
                .s3_uploads_aborted
                .saturating_add(u64::from(page.aborted()));
            if let Some(next) = page.next() {
                cursors.cursors.insert(node.node().clone(), next.clone());
            } else {
                cursors.cursors.remove(node.node());
            }
        }
        cursors.next_node = (start + count) % nodes.len();
    }

    shared
        .update_snapshot(|snapshot| {
            snapshot.passes = snapshot.passes.saturating_add(delta.passes);
            snapshot.write_back_completed = snapshot
                .write_back_completed
                .saturating_add(delta.write_back_completed);
            snapshot.write_back_pending = write_back_pending;
            snapshot.s3_nodes_visited = snapshot
                .s3_nodes_visited
                .saturating_add(delta.s3_nodes_visited);
            snapshot.s3_uploads_aborted = snapshot
                .s3_uploads_aborted
                .saturating_add(delta.s3_uploads_aborted);
        })
        .map_err(|_| MaintenanceThreadFailure::State)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Arc;

    use crucible_cas::content_store::{
        BlobHandle, ContentId, DirectoryBlobBackend, DirectoryRefBackend, ImmutableBlobBackend,
        ObjectKind, RefStoreAdmin, StoreGraph, StoreGraphConfig, StoreNodeId, StoreNodeSpec,
    };

    use super::*;

    #[test]
    fn maintenance_configuration_enforces_every_closed_bound() {
        assert!(matches!(
            CampaignStoreMaintenanceConfig::new(Duration::from_millis(99), 1, 1, 1),
            Err(CampaignStoreMaintenanceConfigError::Interval)
        ));
        assert!(matches!(
            CampaignStoreMaintenanceConfig::new(Duration::from_millis(100), 0, 1, 1),
            Err(CampaignStoreMaintenanceConfigError::WriteBackTransfers)
        ));
        assert!(matches!(
            CampaignStoreMaintenanceConfig::new(Duration::from_millis(100), 1, 257, 1),
            Err(CampaignStoreMaintenanceConfigError::S3Nodes)
        ));
        assert!(matches!(
            CampaignStoreMaintenanceConfig::new(Duration::from_millis(100), 1, 1, 1_001),
            Err(CampaignStoreMaintenanceConfigError::S3Uploads)
        ));
        assert_eq!(
            CampaignStoreMaintenanceConfig::new(Duration::from_millis(100), 1, 1, 1)
                .expect("minimum maintenance configuration")
                .interval(),
            Duration::from_millis(100)
        );
    }

    #[test]
    fn maintenance_pass_obeys_the_global_write_back_limit() {
        let temp = tempfile::TempDir::new().expect("temporary maintenance store");
        let write_back = StoreNodeId::new("write-back").expect("write-back node");
        let staging = StoreNodeId::new("staging").expect("staging node");
        let destination = StoreNodeId::new("destination").expect("destination node");
        let destination_root = temp.path().join("destination");
        let (graph, admin) = StoreGraph::build_with_admin(StoreGraphConfig {
            root: write_back.clone(),
            admitted_kinds: BTreeSet::from([ObjectKind::Finding]),
            nodes: BTreeMap::from([
                (
                    write_back,
                    StoreNodeSpec::WriteBack {
                        staging: staging.clone(),
                        destination: destination.clone(),
                        journal_root: temp.path().join("journal"),
                        maximum_pending_objects: 8,
                        maximum_pending_bytes: 1_024,
                    },
                ),
                (
                    staging,
                    StoreNodeSpec::Directory {
                        root: temp.path().join("staging"),
                    },
                ),
                (
                    destination,
                    StoreNodeSpec::Directory {
                        root: destination_root.clone(),
                    },
                ),
            ]),
        })
        .expect("maintained write-back graph");
        let graph = Arc::new(graph);
        let refs: Arc<dyn RefStoreAdmin> =
            Arc::new(DirectoryRefBackend::new(temp.path().join("refs")));
        let authority = CampaignLocalRepositoryMaintenance {
            store: Arc::clone(&graph),
            graph: admin,
            refs,
        };
        let first_bytes = b"first pending maintenance object";
        let second_bytes = b"second pending maintenance object";
        let first = ContentId::for_bytes(ObjectKind::Finding, 1, first_bytes);
        let second = ContentId::for_bytes(ObjectKind::Finding, 1, second_bytes);
        graph
            .put_if_absent(first, &BlobHandle::from_bytes(first_bytes.to_vec()))
            .expect("stage first maintenance object");
        graph
            .put_if_absent(second, &BlobHandle::from_bytes(second_bytes.to_vec()))
            .expect("stage second maintenance object");

        let shared = CampaignStoreMaintenanceShared::new();
        let config = CampaignStoreMaintenanceConfig::new(Duration::from_millis(100), 1, 1, 1)
            .expect("bounded maintenance configuration");
        let mut cursors = MaintenanceCursorState::new();
        run_maintenance_pass(&authority, &shared, config, &mut cursors)
            .expect("first maintenance pass");
        let destination = DirectoryBlobBackend::new("destination-check", destination_root);
        let first_present = destination
            .contains(first)
            .expect("check first destination");
        let second_present = destination
            .contains(second)
            .expect("check second destination");
        assert_ne!(first_present, second_present);
        assert_eq!(
            shared.snapshot(),
            CampaignStoreMaintenanceSnapshot {
                passes: 1,
                write_back_completed: 1,
                write_back_pending: 1,
                ..CampaignStoreMaintenanceSnapshot::default()
            }
        );

        run_maintenance_pass(&authority, &shared, config, &mut cursors)
            .expect("second maintenance pass");
        assert!(
            destination
                .contains(first)
                .expect("recheck first destination")
        );
        assert!(
            destination
                .contains(second)
                .expect("recheck second destination")
        );
        assert_eq!(shared.snapshot().write_back_completed, 2);
        assert_eq!(shared.snapshot().write_back_pending, 0);
    }
}

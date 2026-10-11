//! Finite owning exact-state actor and independently retained GC inventory.

use std::{
    collections::BTreeSet,
    panic::{AssertUnwindSafe, catch_unwind},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError},
    },
    task::{Context, Waker},
    thread,
    time::Duration,
};

use crucible::node_state::{HostArchive, StateLimits};
use crucible_cas::content_store::{ContentId, ImmutableBlobBackend, MutableRefBackend};

use crate::node_observed_executor::{InstalledNodeCatalog, NodeObservationServiceConfig};

use super::{
    NodeControlError,
    host_state::{NodeHostStateOutcome, NodeHostStateRecord, NodeHostStateRequest},
    host_state_ledger::{HostStateLedger, StateReservation},
    refused,
};

#[path = "host_state_execution.rs"]
mod execution;

struct Work {
    request: NodeHostStateRequest,
    reservation: StateReservation,
}

/// Keeps exact-state request roots registered independently of submission handles.
///
/// A collector inventories this owner under its existing ref exclusion fence.
/// Persistent archive files belong to the private host realm, which exposes no
/// deletion operation. Borrower destruction never drops original native custody.
#[derive(Clone)]
pub struct NodeHostStateRetention {
    ledger: HostStateLedger,
    retired: Arc<AtomicBool>,
}

impl NodeHostStateRetention {
    /// Inventories every bounded original persistent operation and request root.
    ///
    /// # Errors
    /// Refuses corrupt state, missing original requests, unsupported editions,
    /// unavailable storage, and inventories exceeding installation capacity.
    pub fn retention_roots(&self) -> Result<BTreeSet<ContentId>, NodeControlError> {
        self.ledger.retention_roots()
    }

    /// Reports authentic complete native retirement after admission has stopped.
    #[must_use]
    pub fn is_retired(&self) -> bool {
        self.retired.load(Ordering::Acquire)
    }
}

pub(super) struct NodeHostStateService {
    commands: SyncSender<Work>,
    stopping: Arc<AtomicBool>,
    retention: NodeHostStateRetention,
}

impl NodeHostStateService {
    pub(super) fn start(
        configuration: NodeObservationServiceConfig,
        archive_directory: PathBuf,
        blobs: Arc<dyn ImmutableBlobBackend>,
        refs: Arc<dyn MutableRefBackend>,
    ) -> Result<Self, NodeControlError> {
        let ledger = HostStateLedger::new(Arc::clone(&blobs), Arc::clone(&refs))?;
        let (commands, receiver) = mpsc::sync_channel(configuration.maximum_pending_requests);
        let (ready, response) = mpsc::sync_channel(1);
        let stopping = Arc::new(AtomicBool::new(false));
        let retired = Arc::new(AtomicBool::new(false));
        let actor_stopping = Arc::clone(&stopping);
        let actor_retired = Arc::clone(&retired);
        let actor_ledger = ledger.clone();
        let mut fenced_results = Vec::new();
        // One active request, the bounded channel, and the daemon's single
        // serialized submission that may already be reserving when fenced.
        let result_capacity = configuration
            .maximum_pending_requests
            .checked_add(2)
            .ok_or_else(|| refused("host-state deferred result capacity overflows"))?;
        fenced_results
            .try_reserve_exact(result_capacity)
            .map_err(refused)?;

        thread::Builder::new()
            .name("crucible-node-host-state".into())
            .spawn(move || {
                // The native catalog and authenticated archive never leave their
                // original owner thread, including during failure reclamation.
                let limits = StateLimits {
                    maximum_content_bytes: 512 * 1024 * 1024,
                    maximum_total_content_bytes: 1024 * 1024 * 1024,
                    ..StateLimits::default()
                };
                let initialized = (|| {
                    let mut catalog = InstalledNodeCatalog::new(
                        configuration.device_executable,
                        configuration.expected_device,
                        configuration.socket_parent,
                        configuration.control_timeout,
                        configuration.maximum_worlds,
                    )
                    .map_err(refused)?;
                    catalog
                        .install_artifacts(configuration.installed_artifacts)
                        .map_err(refused)?;
                    let archive = HostArchive::open(archive_directory, limits).map_err(refused)?;
                    Ok::<_, NodeControlError>((catalog, archive))
                })();
                match initialized {
                    Ok((catalog, archive)) => {
                        let _ = ready.send(Ok(()));
                        run_actor(
                            catalog,
                            archive,
                            limits,
                            actor_ledger,
                            blobs,
                            refs,
                            receiver,
                            actor_stopping,
                            actor_retired,
                            fenced_results,
                        );
                    }
                    Err(error) => {
                        let _ = ready.send(Err(error));
                    }
                }
            })?;
        response
            .recv()
            .map_err(|_| refused("exact-state actor startup failed"))??;

        Ok(Self {
            commands,
            stopping,
            retention: NodeHostStateRetention { ledger, retired },
        })
    }

    pub(super) fn submit(
        &self,
        request: NodeHostStateRequest,
    ) -> Result<NodeHostStateRecord, NodeControlError> {
        request.validate()?;
        if super::host_state_ledger::is_status(&request) {
            return self.retention.ledger.state(request.execution());
        }
        if self.stopping.load(Ordering::Acquire) {
            return Err(refused("exact-state actor admission has stopped"));
        }
        let reservation = self.retention.ledger.reserve(&request)?;
        let original = reservation.record.clone();
        if !reservation.original_dispatch {
            return Ok(original);
        }
        match self.commands.try_send(Work {
            request,
            reservation,
        }) {
            Ok(()) => Ok(original),
            Err(TrySendError::Full(work) | TrySendError::Disconnected(work)) => self
                .retention
                .ledger
                .complete(&work.reservation, refused_outcome()),
        }
    }

    pub(super) fn retention_owner(&self) -> NodeHostStateRetention {
        self.retention.clone()
    }
}

impl Drop for NodeHostStateService {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Release);
    }
}

// crucible-lint: allow rust-allow -- the actor parameters make native and persistent ownership explicit.
#[allow(clippy::too_many_arguments)]
fn run_actor(
    mut catalog: InstalledNodeCatalog,
    archive: HostArchive,
    limits: StateLimits,
    ledger: HostStateLedger,
    blobs: Arc<dyn ImmutableBlobBackend>,
    refs: Arc<dyn MutableRefBackend>,
    receiver: Receiver<Work>,
    stopping: Arc<AtomicBool>,
    retired: Arc<AtomicBool>,
    mut fenced_results: Vec<(Work, NodeHostStateOutcome)>,
) {
    // Keep each original request and result outside every storage callback.
    // A failed publisher disables admission/publication while this same actor
    // continues polling the original native custody through reclamation.
    let mut publication_available = true;
    loop {
        let mut context = Context::from_waker(Waker::noop());
        let _ = catch_unwind(AssertUnwindSafe(|| {
            catalog.custody().clone().poll_reclamation(&mut context)
        }));
        if stopping.load(Ordering::Acquire) {
            while let Ok(work) = receiver.try_recv() {
                let outcome = refused_outcome();
                let published = publication_available
                    && matches!(
                        catch_unwind(AssertUnwindSafe(
                            || ledger.complete(&work.reservation, outcome.clone())
                        )),
                        Ok(Ok(_))
                    );
                if !published {
                    publication_available = false;
                    fenced_results.push((work, outcome));
                }
            }
            // Only original retained completions may be reconciled after the
            // fence. No native execution or replacement request is repeated.
            // Persistent backend failure keeps this finite owner alive rather
            // than discarding its result identity or unregistering GC roots.
            let mut next = 0;
            while next < fenced_results.len() {
                let (work, outcome) = &fenced_results[next];
                if matches!(
                    catch_unwind(AssertUnwindSafe(
                        || ledger.complete(&work.reservation, outcome.clone())
                    )),
                    Ok(Ok(_))
                ) {
                    fenced_results.swap_remove(next);
                } else {
                    next += 1;
                }
            }
            if catalog.custody().reserved_worlds() == 0 && fenced_results.is_empty() {
                retired.store(true, Ordering::Release);
                return;
            }
            thread::sleep(Duration::from_millis(10));
            continue;
        }
        let work = match receiver.recv_timeout(Duration::from_millis(10)) {
            Ok(work) => work,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => {
                stopping.store(true, Ordering::Release);
                continue;
            }
        };

        let outcome = catch_unwind(AssertUnwindSafe(|| {
            execution::execute(&work.request, &mut catalog, &archive, limits, &blobs, &refs)
        }));
        let outcome = match outcome {
            Ok(Ok(record)) => NodeHostStateOutcome::Completed {
                artifact: record.artifact().clone(),
                manifest: Box::new(record.manifest().clone()),
            },
            _ if matches!(work.request, NodeHostStateRequest::Terminal { .. }) => NodeHostStateOutcome::Unknown {
                reason: "original terminal operation requires reconciliation; replacement dispatch is refused".into(),
            },
            _ => refused_outcome(),
        };
        // Original native quarantine stays owned even if result publication fails.
        // Neither that failure nor a restarted actor may redispatch this nonce.
        if !matches!(
            catch_unwind(AssertUnwindSafe(
                || ledger.complete(&work.reservation, outcome.clone())
            )),
            Ok(Ok(_))
        ) {
            fenced_results.push((work, outcome));
            publication_available = false;
            stopping.store(true, Ordering::Release);
        }
    }
}

fn refused_outcome() -> NodeHostStateOutcome {
    NodeHostStateOutcome::Refused {
        reason: "exact host-state operation refused; original commitment remains retained".into(),
    }
}

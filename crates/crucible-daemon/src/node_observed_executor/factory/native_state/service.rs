//! Owns the installed native world actor through execution and authentic cleanup.
//!
//! Channels carry portable requests and durable records only. Actual native
//! peers, opaque grants, signed source descriptors and runtime queues remain on
//! their original thread. Callback unwind stops admission without discarding
//! those owners; the actor continues polling original cleanup obligations.

use std::{
    collections::BTreeSet,
    fs::File,
    os::unix::fs::MetadataExt,
    panic::{AssertUnwindSafe, catch_unwind},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError},
    },
    task::{Context, Poll, Waker},
    thread,
    time::Duration,
};

use crucible::node_state::NativeArchive;
use crucible_cas::content_store::{ContentId, ImmutableBlobBackend, MutableRefBackend};

use super::super::{NodeObservedError, refused};
use super::{
    control::{NativeWorldOutcome, NativeWorldRecord, NativeWorldRequest},
    execution::{archive_limits, execute},
    installed::InstalledMixedEngine,
    ledger::{NativeReservation, NativeWorldLedger},
};

/// Fixes the installed process-lifetime native capsule capacity before any spawn.
const INSTALLED_NATIVE_WORLD_CAPACITY: usize = 8;

struct Work {
    request: NativeWorldRequest,
    reservation: NativeReservation,
}

/// Retains durable request roots independently of service submission borrowers.
#[derive(Clone)]
pub struct NativeWorldRetention {
    ledger: NativeWorldLedger,
    retired: Arc<AtomicBool>,
}

impl NativeWorldRetention {
    /// Inventories every original durable request, operation and activation root.
    ///
    /// # Errors
    /// Refuses corrupt original bytes, missing commitment roots, unsupported
    /// records, unavailable storage or an inventory above the installed ceiling.
    pub fn retention_roots(&self) -> Result<BTreeSet<ContentId>, NodeObservedError> {
        self.ledger.retention_roots()
    }

    /// Reports authentic original native-group retirement after admission stops.
    #[must_use]
    pub fn is_retired(&self) -> bool {
        self.retired.load(Ordering::Acquire)
    }
}

/// Runs the installed isolated Clock and known-ELF gem5 preservation workflow.
///
/// Source installation fixes the implementation, guest, semantic grant and
/// per-ISA mechanical polling policy. The complete realm is private and retains
/// all signed artifacts. Its eight process-lifetime native slots keep original
/// journals even after kernel reclamation; exhausted custody refuses before a
/// new child can exist. This edition provides no deletion or journal-discard API.
pub struct NativeWorldService {
    commands: SyncSender<Work>,
    stopping: Arc<AtomicBool>,
    retention: NativeWorldRetention,
}

impl NativeWorldService {
    /// Starts one owning native actor under an independently installed profile.
    ///
    /// The caller holds exclusive ownership of the private realm and registers
    /// the returned retention owner before exposing operator admission. Startup
    /// performs installed-profile checks and archive authentication without
    /// allocating a native child.
    ///
    /// # Errors
    /// Refuses an unprivate realm, absent or changed source-installed profile,
    /// invalid queue ceiling, failed actor startup or nondurable reservation CAS.
    pub fn start(
        realm: PathBuf,
        maximum_pending_requests: usize,
        blobs: Arc<dyn ImmutableBlobBackend>,
        refs: Arc<dyn MutableRefBackend>,
    ) -> Result<Self, NodeObservedError> {
        if !(1..=64).contains(&maximum_pending_requests) {
            return Err(refused(
                "native-world request capacity must be between one and 64",
            ));
        }
        let ledger = NativeWorldLedger::new(blobs.clone(), refs.clone())?;
        let (commands, receiver) = mpsc::sync_channel(maximum_pending_requests);
        let (ready, response) = mpsc::sync_channel(1);
        let stopping = Arc::new(AtomicBool::new(false));
        let retired = Arc::new(AtomicBool::new(false));
        let actor_stopping = stopping.clone();
        let actor_retired = retired.clone();
        let actor_ledger = ledger.clone();

        thread::Builder::new()
            .name("crucible-native-world".into())
            .spawn(move || {
                let initialized = (|| {
                    let engine =
                        InstalledMixedEngine::new(realm.clone(), INSTALLED_NATIVE_WORLD_CAPACITY)?;
                    let lock = realm_lock(&realm)?;
                    let archive = NativeArchive::open(realm.join("archive"), archive_limits())
                        .map_err(|error| refused(&error.to_string()))?;
                    let state = ActorState::new(maximum_pending_requests)?;
                    Ok::<_, NodeObservedError>((engine, archive, lock, state))
                })();
                match initialized {
                    Ok((engine, archive, lock, state)) => {
                        let _ = ready.send(Ok(()));
                        let actor = Actor {
                            engine,
                            archive,
                            ledger: actor_ledger,
                            blobs,
                            refs,
                            stopping: actor_stopping,
                            _realm_lock: lock,
                        };
                        actor.run(receiver, state);
                        // `run` consumes the actor and returns only after the
                        // original groups and runtime custody are reclaimed.
                        // Its realm lock is therefore gone before reopening is
                        // advertised to another service borrower.
                        actor_retired.store(true, Ordering::Release);
                    }
                    Err(error) => {
                        let _ = ready.send(Err(error));
                    }
                }
            })
            .map_err(|error| refused(&error.to_string()))?;
        response
            .recv()
            .map_err(|_| refused("native-world actor startup failed"))??;

        Ok(Self {
            commands,
            stopping,
            retention: NativeWorldRetention { ledger, retired },
        })
    }

    /// Durably reserves one request and queues its unique original dispatch.
    ///
    /// Exact repeated requests and status reads return the original record. A
    /// reused nonce with different bytes refuses; an ambiguous old reservation
    /// never acquires new execution authority after daemon restart.
    ///
    /// # Errors
    /// Refuses invalid requests, changed nonce commitments, stopped admission,
    /// corrupt storage or unavailable unique durable reservation.
    pub fn submit(
        &self,
        request: NativeWorldRequest,
    ) -> Result<NativeWorldRecord, NodeObservedError> {
        request.validate()?;
        if matches!(request, NativeWorldRequest::Status { .. }) {
            return self.retention.ledger.state(request.execution());
        }
        if self.stopping.load(Ordering::Acquire) {
            return Err(refused("native-world actor admission has stopped"));
        }
        let reservation = self.retention.ledger.reserve(&request)?;
        let record = reservation.record.clone();
        if !reservation.original_dispatch {
            return Ok(record);
        }
        match self.commands.try_send(Work {
            request,
            reservation,
        }) {
            Ok(()) => Ok(record),
            Err(TrySendError::Full(work) | TrySendError::Disconnected(work)) => {
                self.retention.ledger.complete(&work.reservation, unknown())
            }
        }
    }

    /// Returns an independent original root owner for the collector exclusion fence.
    #[must_use]
    pub fn retention_owner(&self) -> NativeWorldRetention {
        self.retention.clone()
    }
}

impl Drop for NativeWorldService {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Release);
    }
}

struct Actor {
    engine: InstalledMixedEngine,
    archive: NativeArchive,
    ledger: NativeWorldLedger,
    blobs: Arc<dyn ImmutableBlobBackend>,
    refs: Arc<dyn MutableRefBackend>,
    stopping: Arc<AtomicBool>,
    _realm_lock: File,
}

impl Actor {
    fn run(self, receiver: Receiver<Work>, mut state: ActorState) {
        loop {
            // The complete queues, original work and its result, pending request
            // reservations and native namespaces stay outside the callback scope.
            // A storage or bookkeeping unwind therefore cannot destroy the actor
            // that must keep polling the original native reclamation obligations.
            let iteration =
                catch_unwind(AssertUnwindSafe(|| self.iteration(&receiver, &mut state)));
            match iteration {
                Ok(true) => return,
                Ok(false) => {}
                Err(_) => {
                    self.stopping.store(true, Ordering::Release);
                    state.publication_available = false;
                    if state.work.is_some() && state.outcome.is_none() {
                        state.outcome = Some(unknown());
                    }
                    thread::sleep(Duration::from_millis(10));
                }
            }
        }
    }

    fn iteration(&self, receiver: &Receiver<Work>, state: &mut ActorState) -> bool {
        let mut context = Context::from_waker(Waker::noop());
        let cleanup = self.engine.runtime.poll_reclamation(&mut context);
        if matches!(cleanup, Poll::Ready(Err(_))) {
            self.stopping.store(true, Ordering::Release);
        }
        if self.engine.runtime.reserved_worlds() == 0 {
            for retirement in &mut state.retirements {
                self.retire_namespace(retirement);
            }
        }
        if self.stopping.load(Ordering::Acquire) {
            self.drain(receiver, state);
            if self.engine.runtime.reserved_worlds() == 0
                && self.engine.native.all_groups_reclaimed()
            {
                return true;
            }
            thread::sleep(Duration::from_millis(10));
            return false;
        }
        if state.work.is_none() {
            state.work = match receiver.recv_timeout(Duration::from_millis(10)) {
                Ok(work) => Some(work),
                Err(RecvTimeoutError::Timeout) => return false,
                Err(RecvTimeoutError::Disconnected) => {
                    self.stopping.store(true, Ordering::Release);
                    return false;
                }
            };
        }
        if !state.dispatch_attempted {
            // This flag is retained before any native callback. An unwind after
            // an original BEGIN can never cause that work to be redispatched.
            state.dispatch_attempted = true;
            let outcome = if state.retirements.len() >= INSTALLED_NATIVE_WORLD_CAPACITY {
                unknown()
            } else if let Some(work) = state.work.as_ref() {
                match execute(
                    &work.request,
                    &self.engine,
                    &self.archive,
                    &self.blobs,
                    &self.refs,
                ) {
                    Ok(executed) => {
                        state.retirements.push(Retirement {
                            target: executed.target,
                            namespace: Some(executed.namespace),
                        });
                        executed.outcome
                    }
                    Err(_) => unknown(),
                }
            } else {
                self.stopping.store(true, Ordering::Release);
                unknown()
            };
            state.outcome = Some(outcome);
        }
        self.complete_active(state);
        false
    }

    fn complete_active(&self, state: &mut ActorState) {
        if !state.publication_available {
            return;
        }
        let (Some(work), Some(outcome)) = (state.work.as_ref(), state.outcome.as_ref()) else {
            return;
        };
        // Portable result bytes remain outside the fallible backend call, just
        // as opaque native custody remains in the independently owning queues.
        if self
            .ledger
            .complete(&work.reservation, outcome.clone())
            .is_err()
        {
            self.stopping.store(true, Ordering::Release);
            state.publication_available = false;
            return;
        }
        state.work = None;
        state.outcome = None;
        state.dispatch_attempted = false;
    }

    fn drain(&self, receiver: &Receiver<Work>, state: &mut ActorState) {
        // The bounded request inventory was reserved before admission. Receiving
        // into it preserves every original queued reservation across a backend
        // panic; unavailable publication leaves its durable Reserved root intact.
        while state.drained.len() < state.maximum_pending_requests {
            let Ok(work) = receiver.try_recv() else {
                break;
            };
            state.drained.push(work);
        }
        if state.work.is_some() && state.outcome.is_none() {
            state.outcome = Some(unknown());
        }
        self.complete_active(state);
        while state.publication_available && state.published_drained < state.drained.len() {
            let work = &state.drained[state.published_drained];
            if self.ledger.complete(&work.reservation, unknown()).is_err() {
                state.publication_available = false;
                break;
            }
            state.published_drained += 1;
        }
    }

    fn retire_namespace(&self, retirement: &mut Retirement) {
        if retirement.namespace.is_none()
            || !matches!(
                self.engine
                    .native
                    .original_group_reclaimed(&retirement.target),
                Ok(true)
            )
        {
            return;
        }
        if let Some(namespace) = retirement.namespace.as_ref()
            && std::fs::remove_dir_all(namespace).is_ok()
        {
            retirement.namespace = None;
        }
    }
}

/// Owns the bounded work inventory outside every effecting callback fence.
struct ActorState {
    retirements: Vec<Retirement>,
    work: Option<Work>,
    outcome: Option<NativeWorldOutcome>,
    dispatch_attempted: bool,
    drained: Vec<Work>,
    published_drained: usize,
    maximum_pending_requests: usize,
    publication_available: bool,
}

impl ActorState {
    fn new(maximum_pending_requests: usize) -> Result<Self, NodeObservedError> {
        let mut retirements = Vec::new();
        retirements
            .try_reserve_exact(INSTALLED_NATIVE_WORLD_CAPACITY)
            .map_err(|error| refused(&error.to_string()))?;
        let mut drained = Vec::new();
        drained
            .try_reserve_exact(maximum_pending_requests)
            .map_err(|error| refused(&error.to_string()))?;
        Ok(Self {
            retirements,
            work: None,
            outcome: None,
            dispatch_attempted: false,
            drained,
            published_drained: 0,
            maximum_pending_requests,
            publication_available: true,
        })
    }
}

struct Retirement {
    target: crucible::node_contract::ActivationRecord,
    namespace: Option<PathBuf>,
}

fn unknown() -> NativeWorldOutcome {
    NativeWorldOutcome::Unknown {
        reason: "original native-world operation is uncertain; original custody remains supervised"
            .into(),
    }
}

fn realm_lock(realm: &std::path::Path) -> Result<File, NodeObservedError> {
    let descriptor = rustix::fs::open(
        realm.join("native-world.lock"),
        rustix::fs::OFlags::RDWR
            | rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::from_bits_truncate(0o600),
    )
    .map_err(|error| refused(&error.to_string()))?;
    let lock = File::from(descriptor);
    let metadata = lock
        .metadata()
        .map_err(|error| refused(&error.to_string()))?;
    if !metadata.is_file()
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || metadata.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(refused(
            "native-world realm lock is not an owned private regular file",
        ));
    }
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive)
        .map_err(|error| refused(&error.to_string()))?;
    Ok(lock)
}

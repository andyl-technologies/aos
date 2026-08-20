//! Bounded authenticated listener for the local campaign service.
//!
//! This module owns only an already-bound Unix listener and a fixed worker
//! pool. Socket-path creation, permissions, and deployment policy loading stay
//! with the daemon bootstrap. Every accepted connection is authenticated once
//! through Linux peer credentials before the existing canonical service
//! protocol is allowed to dispatch repository work.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::net::Shutdown;
use std::os::unix::net::{UnixListener, UnixStream};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crucible_campaign::{CampaignPrincipalAuthorizer, CampaignRepository};

use crate::campaign_loopback::{
    DEFAULT_CAMPAIGN_REQUESTS_PER_CONNECTION, LoopbackCampaignServerError,
    LoopbackCampaignTimeouts, MAX_CAMPAIGN_REQUESTS_PER_CONNECTION,
    UnixPeerCampaignPrincipalResolver,
    serve_authenticated_repository_campaign_connection_with_limits,
};

const DEFAULT_CONNECTION_WORKERS: usize = 8;
const DEFAULT_PENDING_CONNECTIONS: usize = 32;
const DEFAULT_ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(10);
const MIN_ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(1);
const MAX_ACCEPT_POLL_INTERVAL: Duration = Duration::from_secs(1);
/// Maximum fixed worker count accepted by one local campaign listener.
pub const MAX_CAMPAIGN_LISTENER_WORKERS: usize = 256;
/// Maximum accepted sockets retained outside the fixed worker pool.
pub const MAX_CAMPAIGN_PENDING_CONNECTIONS: usize = 1_024;

/// Bounded operational configuration for one local campaign listener.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CampaignLoopbackServerConfig {
    connection_workers: usize,
    pending_connections: usize,
    maximum_requests_per_connection: usize,
    accept_poll_interval: Duration,
    exchange_timeouts: LoopbackCampaignTimeouts,
}

impl CampaignLoopbackServerConfig {
    /// Builds a bounded fixed-worker listener configuration.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignLoopbackServerConfigError`] when a worker, pending
    /// connection, or per-connection request count is zero or exceeds its
    /// fixed ceiling, or when the accept poll interval is outside one
    /// millisecond through one second.
    pub fn new(
        connection_workers: usize,
        pending_connections: usize,
        maximum_requests_per_connection: usize,
        accept_poll_interval: Duration,
        exchange_timeouts: LoopbackCampaignTimeouts,
    ) -> Result<Self, CampaignLoopbackServerConfigError> {
        if connection_workers == 0 || connection_workers > MAX_CAMPAIGN_LISTENER_WORKERS {
            return Err(CampaignLoopbackServerConfigError::InvalidWorkerCount);
        }
        if pending_connections == 0 || pending_connections > MAX_CAMPAIGN_PENDING_CONNECTIONS {
            return Err(CampaignLoopbackServerConfigError::InvalidPendingCount);
        }
        if maximum_requests_per_connection == 0
            || maximum_requests_per_connection > MAX_CAMPAIGN_REQUESTS_PER_CONNECTION
        {
            return Err(CampaignLoopbackServerConfigError::InvalidRequestCount);
        }
        if !(MIN_ACCEPT_POLL_INTERVAL..=MAX_ACCEPT_POLL_INTERVAL).contains(&accept_poll_interval) {
            return Err(CampaignLoopbackServerConfigError::InvalidPollInterval);
        }
        Ok(Self {
            connection_workers,
            pending_connections,
            maximum_requests_per_connection,
            accept_poll_interval,
            exchange_timeouts,
        })
    }

    /// Returns the fixed number of connection workers.
    #[must_use]
    pub const fn connection_workers(self) -> usize {
        self.connection_workers
    }

    /// Returns the maximum accepted sockets waiting for a worker.
    #[must_use]
    pub const fn pending_connections(self) -> usize {
        self.pending_connections
    }

    /// Returns the fairness ceiling for complete requests on one connection.
    #[must_use]
    pub const fn maximum_requests_per_connection(self) -> usize {
        self.maximum_requests_per_connection
    }

    /// Returns how often the nonblocking accept loop observes shutdown.
    #[must_use]
    pub const fn accept_poll_interval(self) -> Duration {
        self.accept_poll_interval
    }

    /// Returns the finite deadline profile for each canonical exchange.
    #[must_use]
    pub const fn exchange_timeouts(self) -> LoopbackCampaignTimeouts {
        self.exchange_timeouts
    }
}

impl Default for CampaignLoopbackServerConfig {
    fn default() -> Self {
        Self {
            connection_workers: DEFAULT_CONNECTION_WORKERS,
            pending_connections: DEFAULT_PENDING_CONNECTIONS,
            maximum_requests_per_connection: DEFAULT_CAMPAIGN_REQUESTS_PER_CONNECTION,
            accept_poll_interval: DEFAULT_ACCEPT_POLL_INTERVAL,
            exchange_timeouts: LoopbackCampaignTimeouts::default(),
        }
    }
}

/// Invalid bounded listener configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CampaignLoopbackServerConfigError {
    /// The fixed worker count was zero or exceeded its ceiling.
    #[error("campaign listener worker count is outside its fixed bound")]
    InvalidWorkerCount,
    /// The pending connection count was zero or exceeded its ceiling.
    #[error("campaign listener pending connection count is outside its fixed bound")]
    InvalidPendingCount,
    /// The per-connection request count was zero or exceeded its ceiling.
    #[error("campaign listener per-connection request count is outside its fixed bound")]
    InvalidRequestCount,
    /// The accept poll interval was too small or too large.
    #[error("campaign listener accept poll interval must be between 1ms and 1s")]
    InvalidPollInterval,
}

/// Sticky shutdown authority for one campaign listener incarnation.
#[derive(Clone)]
pub struct CampaignLoopbackServerShutdown {
    state: Arc<CampaignLoopbackServerState>,
}

impl CampaignLoopbackServerShutdown {
    /// Requests shutdown and interrupts every currently active connection.
    pub fn shutdown(&self) {
        self.state.shutdown();
    }

    /// Returns whether shutdown has been requested for this incarnation.
    #[must_use]
    pub fn is_shutdown(&self) -> bool {
        self.state.stopped.load(Ordering::Acquire)
    }

    /// Returns the current bounded number of worker-owned connections.
    #[must_use]
    pub fn active_connections(&self) -> usize {
        lock_recover(&self.state.active).len()
    }
}

/// Terminal listener counters collected outside campaign semantic state.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CampaignLoopbackServerReport {
    accepted_connections: u64,
    capacity_rejections: u64,
    completed_connections: u64,
    peer_rejections: u64,
    protocol_failures: u64,
}

impl CampaignLoopbackServerReport {
    /// Returns accepted kernel connections, including later rejections.
    #[must_use]
    pub const fn accepted_connections(self) -> u64 {
        self.accepted_connections
    }

    /// Returns connections closed because every worker and queue slot was busy.
    #[must_use]
    pub const fn capacity_rejections(self) -> u64 {
        self.capacity_rejections
    }

    /// Returns authenticated connections that ended cleanly.
    #[must_use]
    pub const fn completed_connections(self) -> u64 {
        self.completed_connections
    }

    /// Returns connections rejected while resolving authenticated peer policy.
    #[must_use]
    pub const fn peer_rejections(self) -> u64 {
        self.peer_rejections
    }

    /// Returns authenticated connections closed for protocol or I/O failure.
    #[must_use]
    pub const fn protocol_failures(self) -> u64 {
        self.protocol_failures
    }
}

/// Fixed-worker authenticated local campaign listener.
pub struct CampaignLoopbackServer<R: ?Sized, A: ?Sized> {
    listener: UnixListener,
    repository: Arc<CampaignRepository>,
    principal_resolver: Arc<R>,
    authorizer: Arc<A>,
    config: CampaignLoopbackServerConfig,
    state: Arc<CampaignLoopbackServerState>,
}

impl<R: ?Sized, A: ?Sized> CampaignLoopbackServer<R, A>
where
    R: UnixPeerCampaignPrincipalResolver + Send + Sync + 'static,
    A: CampaignPrincipalAuthorizer + Send + Sync + 'static,
{
    /// Wraps an already-bound listener and immutable deployment authorities.
    ///
    /// Socket path creation, ownership, permissions, and stale-file handling
    /// must be completed by the caller before this constructor is invoked.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignLoopbackListenerError::Io`] when the listener cannot
    /// be switched to bounded nonblocking acceptance.
    pub fn new(
        listener: UnixListener,
        repository: Arc<CampaignRepository>,
        principal_resolver: Arc<R>,
        authorizer: Arc<A>,
        config: CampaignLoopbackServerConfig,
    ) -> Result<Self, CampaignLoopbackListenerError> {
        listener.set_nonblocking(true)?;
        Ok(Self {
            listener,
            repository,
            principal_resolver,
            authorizer,
            config,
            state: Arc::new(CampaignLoopbackServerState::default()),
        })
    }

    /// Returns a cloneable sticky shutdown authority for this server.
    #[must_use]
    pub fn shutdown_handle(&self) -> CampaignLoopbackServerShutdown {
        CampaignLoopbackServerShutdown {
            state: Arc::clone(&self.state),
        }
    }

    /// Serves connections until sticky shutdown or a listener/worker failure.
    ///
    /// The fixed worker pool and bounded queue are allocated before the first
    /// accept. A full queue closes the newly accepted socket immediately.
    /// Shutdown closes every active stream, drops queued sockets, joins all
    /// workers, and only then returns the operational report.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignLoopbackListenerError::Io`] for listener failure or
    /// [`CampaignLoopbackListenerError::WorkerPanicked`] when a caught worker
    /// invariant panic forces fail-closed server shutdown.
    pub fn serve(self) -> Result<CampaignLoopbackServerReport, CampaignLoopbackListenerError> {
        let connections = Arc::new(ConnectionQueue::new(self.config.pending_connections));
        self.state.install_connections(Arc::clone(&connections));
        if self.state.stopped.load(Ordering::Acquire) {
            return Ok(self.state.report());
        }
        let mut workers: Vec<JoinHandle<Result<(), ()>>> =
            Vec::with_capacity(self.config.connection_workers);
        for slot in 0..self.config.connection_workers {
            let worker = match spawn_connection_worker(
                slot,
                Arc::clone(&connections),
                Arc::clone(&self.repository),
                Arc::clone(&self.principal_resolver),
                Arc::clone(&self.authorizer),
                self.config,
                Arc::clone(&self.state),
            ) {
                Ok(worker) => worker,
                Err(error) => {
                    self.state.shutdown();
                    connections.close();
                    for worker in workers {
                        let _ = worker.join();
                    }
                    return Err(error.into());
                }
            };
            workers.push(worker);
        }

        let mut accept_error = None;
        let mut worker_panicked = false;
        while !self.state.stopped.load(Ordering::Acquire) {
            if workers.iter().any(JoinHandle::is_finished) {
                worker_panicked = true;
                self.state.shutdown();
                break;
            }
            match self.listener.accept() {
                Ok((stream, _)) => {
                    increment(&self.state.accepted_connections);
                    if stream.set_nonblocking(false).is_err() {
                        increment(&self.state.protocol_failures);
                        let _ = stream.shutdown(Shutdown::Both);
                    } else {
                        enqueue_connection(&connections, stream, &self.state);
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(self.config.accept_poll_interval);
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => {
                    accept_error = Some(error);
                    self.state.shutdown();
                }
            }
        }

        connections.close();
        self.state.shutdown();
        for worker in workers {
            match worker.join() {
                Ok(Ok(())) => {}
                Ok(Err(())) | Err(_) => worker_panicked = true,
            }
        }

        if let Some(error) = accept_error {
            return Err(error.into());
        }
        if worker_panicked {
            return Err(CampaignLoopbackListenerError::WorkerPanicked);
        }
        Ok(self.state.report())
    }
}

/// Terminal failure of the bounded listener owner.
#[derive(Debug, thiserror::Error)]
pub enum CampaignLoopbackListenerError {
    /// Listener configuration or acceptance failed.
    #[error("campaign listener I/O failed")]
    Io(#[from] io::Error),
    /// A worker invariant panic forced fail-closed listener shutdown.
    #[error("campaign listener worker panicked")]
    WorkerPanicked,
}

#[derive(Default)]
struct CampaignLoopbackServerState {
    stopped: AtomicBool,
    connections: Mutex<Option<Arc<ConnectionQueue>>>,
    active: Mutex<BTreeMap<usize, UnixStream>>,
    accepted_connections: AtomicU64,
    capacity_rejections: AtomicU64,
    completed_connections: AtomicU64,
    peer_rejections: AtomicU64,
    protocol_failures: AtomicU64,
}

impl CampaignLoopbackServerState {
    fn shutdown(&self) {
        self.stopped.store(true, Ordering::Release);
        if let Some(connections) = lock_recover(&self.connections).as_ref() {
            connections.close();
        }
        let active = lock_recover(&self.active);
        for stream in active.values() {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }

    fn install_connections(&self, connections: Arc<ConnectionQueue>) {
        *lock_recover(&self.connections) = Some(Arc::clone(&connections));
        if self.stopped.load(Ordering::Acquire) {
            connections.close();
        }
    }

    fn report(&self) -> CampaignLoopbackServerReport {
        CampaignLoopbackServerReport {
            accepted_connections: self.accepted_connections.load(Ordering::Relaxed),
            capacity_rejections: self.capacity_rejections.load(Ordering::Relaxed),
            completed_connections: self.completed_connections.load(Ordering::Relaxed),
            peer_rejections: self.peer_rejections.load(Ordering::Relaxed),
            protocol_failures: self.protocol_failures.load(Ordering::Relaxed),
        }
    }
}

struct ActiveConnection {
    slot: usize,
    state: Arc<CampaignLoopbackServerState>,
}

impl ActiveConnection {
    fn install(
        slot: usize,
        stream: &UnixStream,
        state: Arc<CampaignLoopbackServerState>,
    ) -> io::Result<Self> {
        let retained = stream.try_clone()?;
        {
            let mut active = lock_recover(&state.active);
            match active.entry(slot) {
                Entry::Vacant(entry) => {
                    entry.insert(retained);
                }
                Entry::Occupied(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "campaign listener worker already owns a connection",
                    ));
                }
            }
        }
        if state.stopped.load(Ordering::Acquire) {
            let _ = stream.shutdown(Shutdown::Both);
        }
        Ok(Self { slot, state })
    }
}

impl Drop for ActiveConnection {
    fn drop(&mut self) {
        lock_recover(&self.state.active).remove(&self.slot);
    }
}

fn spawn_connection_worker<R, A>(
    slot: usize,
    connections: Arc<ConnectionQueue>,
    repository: Arc<CampaignRepository>,
    principal_resolver: Arc<R>,
    authorizer: Arc<A>,
    config: CampaignLoopbackServerConfig,
    state: Arc<CampaignLoopbackServerState>,
) -> io::Result<JoinHandle<Result<(), ()>>>
where
    R: UnixPeerCampaignPrincipalResolver + Send + Sync + 'static + ?Sized,
    A: CampaignPrincipalAuthorizer + Send + Sync + 'static + ?Sized,
{
    thread::Builder::new()
        .name(format!("crucible-campaign-{slot}"))
        .spawn(move || {
            let result = catch_unwind(AssertUnwindSafe(|| {
                connection_worker_loop(
                    slot,
                    &connections,
                    &repository,
                    principal_resolver.as_ref(),
                    authorizer.as_ref(),
                    config,
                    &state,
                );
            }));
            if result.is_err() {
                state.shutdown();
                return Err(());
            }
            Ok(())
        })
}

fn connection_worker_loop<R, A>(
    slot: usize,
    connections: &ConnectionQueue,
    repository: &CampaignRepository,
    principal_resolver: &R,
    authorizer: &A,
    config: CampaignLoopbackServerConfig,
    state: &Arc<CampaignLoopbackServerState>,
) where
    R: UnixPeerCampaignPrincipalResolver + ?Sized,
    A: CampaignPrincipalAuthorizer + ?Sized,
{
    while !state.stopped.load(Ordering::Acquire) {
        let mut stream = match connections.pop(config.accept_poll_interval) {
            Some(stream) => stream,
            None if state.stopped.load(Ordering::Acquire) || connections.is_closed() => return,
            None => continue,
        };
        let active = match ActiveConnection::install(slot, &stream, Arc::clone(state)) {
            Ok(active) => active,
            Err(_) => {
                increment(&state.protocol_failures);
                let _ = stream.shutdown(Shutdown::Both);
                continue;
            }
        };
        let result = serve_authenticated_repository_campaign_connection_with_limits(
            &mut stream,
            repository,
            principal_resolver,
            authorizer,
            config.exchange_timeouts,
            config.maximum_requests_per_connection,
        );
        drop(active);
        match result {
            Ok(()) if state.stopped.load(Ordering::Acquire) => {}
            Ok(()) => increment(&state.completed_connections),
            Err(LoopbackCampaignServerError::PeerAuthentication(_)) => {
                increment(&state.peer_rejections);
            }
            Err(LoopbackCampaignServerError::Protocol(_))
                if !state.stopped.load(Ordering::Acquire) =>
            {
                increment(&state.protocol_failures);
            }
            Err(LoopbackCampaignServerError::Protocol(_)) => {}
        }
    }
}

fn enqueue_connection(
    connections: &ConnectionQueue,
    stream: UnixStream,
    state: &CampaignLoopbackServerState,
) {
    match connections.try_push(stream) {
        Ok(()) => {}
        Err(ConnectionQueuePushError::Full(stream)) => {
            increment(&state.capacity_rejections);
            let _ = stream.shutdown(Shutdown::Both);
        }
        Err(ConnectionQueuePushError::Closed(stream)) => {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }
}

struct ConnectionQueue {
    capacity: usize,
    inner: Mutex<ConnectionQueueState>,
    ready: Condvar,
}

struct ConnectionQueueState {
    streams: VecDeque<UnixStream>,
    closed: bool,
}

enum ConnectionQueuePushError {
    Full(UnixStream),
    Closed(UnixStream),
}

impl ConnectionQueue {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            inner: Mutex::new(ConnectionQueueState {
                streams: VecDeque::with_capacity(capacity),
                closed: false,
            }),
            ready: Condvar::new(),
        }
    }

    fn try_push(&self, stream: UnixStream) -> Result<(), ConnectionQueuePushError> {
        let mut inner = lock_recover(&self.inner);
        if inner.closed {
            return Err(ConnectionQueuePushError::Closed(stream));
        }
        if inner.streams.len() >= self.capacity {
            return Err(ConnectionQueuePushError::Full(stream));
        }
        inner.streams.push_back(stream);
        self.ready.notify_one();
        Ok(())
    }

    fn pop(&self, timeout: Duration) -> Option<UnixStream> {
        let mut inner = lock_recover(&self.inner);
        if inner.streams.is_empty() && !inner.closed {
            inner = match self.ready.wait_timeout(inner, timeout) {
                Ok((inner, _)) => inner,
                Err(poisoned) => poisoned.into_inner().0,
            };
        }
        inner.streams.pop_front()
    }

    fn close(&self) {
        let mut inner = lock_recover(&self.inner);
        inner.closed = true;
        inner.streams.clear();
        self.ready.notify_all();
    }

    fn is_closed(&self) -> bool {
        lock_recover(&self.inner).closed
    }
}

fn increment(counter: &AtomicU64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_add(1))
    });
}

fn lock_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(test)]
mod tests;

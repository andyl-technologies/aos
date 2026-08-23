//! Bounded authenticated listener for the local executor component.
//!
//! This module owns a fixed connection-worker pool around one cloneable
//! executor service. Every accepted Unix connection is authenticated once
//! through Linux `SO_PEERCRED` before canonical component dispatch. The
//! semantic worker pool remains a separate owner: listener shutdown interrupts
//! socket work, while the containing daemon then shuts down and joins modeled
//! execution workers.

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

use crucible_campaign::{ExecutorCapabilityService, ExecutorControlService, ExecutorResumeService};

use crate::{
    DEFAULT_EXECUTOR_REQUESTS_PER_CONNECTION, LoopbackExecutorServerError,
    LoopbackExecutorTimeouts, MAX_EXECUTOR_REQUESTS_PER_CONNECTION,
    serve_loopback_executor_component_connection_with_limits,
};

const DEFAULT_CONNECTION_WORKERS: usize = 4;
const DEFAULT_PENDING_CONNECTIONS: usize = 16;
const DEFAULT_ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(10);
const MIN_ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(1);
const MAX_ACCEPT_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Maximum fixed worker count accepted by one local executor listener.
pub const MAX_EXECUTOR_LISTENER_WORKERS: usize = 256;
/// Maximum accepted executor sockets retained outside the fixed worker pool.
pub const MAX_EXECUTOR_PENDING_CONNECTIONS: usize = 1_024;

/// Exact effective identity admitted to one local executor endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct UnixPeerExecutorIdentity {
    user_id: u32,
    group_id: u32,
}

impl UnixPeerExecutorIdentity {
    /// Creates one exact effective user/group identity.
    #[must_use]
    pub const fn new(user_id: u32, group_id: u32) -> Self {
        Self { user_id, group_id }
    }

    /// Returns the required peer effective user ID.
    #[must_use]
    pub const fn user_id(self) -> u32 {
        self.user_id
    }

    /// Returns the required peer effective group ID.
    #[must_use]
    pub const fn group_id(self) -> u32 {
        self.group_id
    }
}

/// Bounded operational configuration for one local executor listener.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecutorLoopbackServerConfig {
    connection_workers: usize,
    pending_connections: usize,
    maximum_requests_per_connection: usize,
    accept_poll_interval: Duration,
    exchange_timeouts: LoopbackExecutorTimeouts,
}

impl ExecutorLoopbackServerConfig {
    /// Builds a bounded fixed-worker listener configuration.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorLoopbackServerConfigError`] when a worker, pending
    /// connection, or request count is zero or exceeds its fixed ceiling, or
    /// when the accept poll interval is outside one millisecond through one
    /// second.
    pub fn new(
        connection_workers: usize,
        pending_connections: usize,
        maximum_requests_per_connection: usize,
        accept_poll_interval: Duration,
        exchange_timeouts: LoopbackExecutorTimeouts,
    ) -> Result<Self, ExecutorLoopbackServerConfigError> {
        if connection_workers == 0 || connection_workers > MAX_EXECUTOR_LISTENER_WORKERS {
            return Err(ExecutorLoopbackServerConfigError::InvalidWorkerCount);
        }
        if pending_connections == 0 || pending_connections > MAX_EXECUTOR_PENDING_CONNECTIONS {
            return Err(ExecutorLoopbackServerConfigError::InvalidPendingCount);
        }
        if maximum_requests_per_connection == 0
            || maximum_requests_per_connection > MAX_EXECUTOR_REQUESTS_PER_CONNECTION
        {
            return Err(ExecutorLoopbackServerConfigError::InvalidRequestCount);
        }
        if !(MIN_ACCEPT_POLL_INTERVAL..=MAX_ACCEPT_POLL_INTERVAL).contains(&accept_poll_interval) {
            return Err(ExecutorLoopbackServerConfigError::InvalidPollInterval);
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
    pub const fn exchange_timeouts(self) -> LoopbackExecutorTimeouts {
        self.exchange_timeouts
    }
}

impl Default for ExecutorLoopbackServerConfig {
    fn default() -> Self {
        Self {
            connection_workers: DEFAULT_CONNECTION_WORKERS,
            pending_connections: DEFAULT_PENDING_CONNECTIONS,
            maximum_requests_per_connection: DEFAULT_EXECUTOR_REQUESTS_PER_CONNECTION,
            accept_poll_interval: DEFAULT_ACCEPT_POLL_INTERVAL,
            exchange_timeouts: LoopbackExecutorTimeouts::default(),
        }
    }
}

/// Invalid bounded executor-listener configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ExecutorLoopbackServerConfigError {
    /// The fixed worker count was zero or exceeded its ceiling.
    #[error("executor listener worker count is outside its fixed bound")]
    InvalidWorkerCount,
    /// The pending connection count was zero or exceeded its ceiling.
    #[error("executor listener pending connection count is outside its fixed bound")]
    InvalidPendingCount,
    /// The per-connection request count was zero or exceeded its ceiling.
    #[error("executor listener per-connection request count is outside its fixed bound")]
    InvalidRequestCount,
    /// The accept poll interval was too small or too large.
    #[error("executor listener accept poll interval must be between 1ms and 1s")]
    InvalidPollInterval,
}

/// Sticky shutdown authority for one executor-listener incarnation.
#[derive(Clone)]
pub struct ExecutorLoopbackServerShutdown {
    state: Arc<ExecutorLoopbackServerState>,
}

impl ExecutorLoopbackServerShutdown {
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

/// Terminal listener counters collected outside executor semantic state.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ExecutorLoopbackServerReport {
    accepted_connections: u64,
    capacity_rejections: u64,
    completed_connections: u64,
    peer_rejections: u64,
    protocol_failures: u64,
    service_failures: u64,
}

impl ExecutorLoopbackServerReport {
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

    /// Returns connections rejected by exact kernel peer identity.
    #[must_use]
    pub const fn peer_rejections(self) -> u64 {
        self.peer_rejections
    }

    /// Returns authenticated connections closed for protocol or I/O failure.
    #[must_use]
    pub const fn protocol_failures(self) -> u64 {
        self.protocol_failures
    }

    /// Returns connections closed because the executor service failed.
    #[must_use]
    pub const fn service_failures(self) -> u64 {
        self.service_failures
    }
}

/// Fixed-worker authenticated local executor listener.
pub struct ExecutorLoopbackServer<S> {
    listener: UnixListener,
    service: S,
    peer: UnixPeerExecutorIdentity,
    config: ExecutorLoopbackServerConfig,
    state: Arc<ExecutorLoopbackServerState>,
}

impl<S> ExecutorLoopbackServer<S>
where
    S: ExecutorCapabilityService
        + ExecutorControlService
        + ExecutorResumeService
        + Clone
        + Send
        + 'static,
{
    /// Wraps an already-bound listener and one immutable peer identity.
    ///
    /// Socket path creation, ownership, permissions, stale-file handling, and
    /// endpoint cleanup remain with the caller. The server authenticates the
    /// connected peer independently before dispatching protocol bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorLoopbackListenerError::Io`] when the listener cannot
    /// be switched to bounded nonblocking acceptance.
    pub fn new(
        listener: UnixListener,
        service: S,
        peer: UnixPeerExecutorIdentity,
        config: ExecutorLoopbackServerConfig,
    ) -> Result<Self, ExecutorLoopbackListenerError> {
        listener.set_nonblocking(true)?;
        Ok(Self {
            listener,
            service,
            peer,
            config,
            state: Arc::new(ExecutorLoopbackServerState::default()),
        })
    }

    /// Returns a cloneable sticky shutdown authority for this server.
    #[must_use]
    pub fn shutdown_handle(&self) -> ExecutorLoopbackServerShutdown {
        ExecutorLoopbackServerShutdown {
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
    /// Returns [`ExecutorLoopbackListenerError::Io`] for listener failure or
    /// [`ExecutorLoopbackListenerError::WorkerPanicked`] when a caught worker
    /// invariant panic forces fail-closed server shutdown.
    pub fn serve(self) -> Result<ExecutorLoopbackServerReport, ExecutorLoopbackListenerError> {
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
                self.service.clone(),
                self.peer,
                self.config,
                Arc::clone(&self.state),
            ) {
                Ok(worker) => worker,
                Err(source) => {
                    self.state.shutdown();
                    connections.close();
                    for worker in workers {
                        let _ = worker.join();
                    }
                    return Err(source.into());
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
            return Err(ExecutorLoopbackListenerError::WorkerPanicked);
        }
        Ok(self.state.report())
    }
}

/// Terminal failure of the bounded executor listener owner.
#[derive(Debug, thiserror::Error)]
pub enum ExecutorLoopbackListenerError {
    /// Listener configuration or acceptance failed.
    #[error("executor listener I/O failed")]
    Io(#[from] io::Error),
    /// A worker invariant panic forced fail-closed listener shutdown.
    #[error("executor listener worker panicked")]
    WorkerPanicked,
}

#[derive(Default)]
struct ExecutorLoopbackServerState {
    stopped: AtomicBool,
    connections: Mutex<Option<Arc<ConnectionQueue>>>,
    active: Mutex<BTreeMap<usize, UnixStream>>,
    accepted_connections: AtomicU64,
    capacity_rejections: AtomicU64,
    completed_connections: AtomicU64,
    peer_rejections: AtomicU64,
    protocol_failures: AtomicU64,
    service_failures: AtomicU64,
}

impl ExecutorLoopbackServerState {
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

    fn report(&self) -> ExecutorLoopbackServerReport {
        ExecutorLoopbackServerReport {
            accepted_connections: self.accepted_connections.load(Ordering::Relaxed),
            capacity_rejections: self.capacity_rejections.load(Ordering::Relaxed),
            completed_connections: self.completed_connections.load(Ordering::Relaxed),
            peer_rejections: self.peer_rejections.load(Ordering::Relaxed),
            protocol_failures: self.protocol_failures.load(Ordering::Relaxed),
            service_failures: self.service_failures.load(Ordering::Relaxed),
        }
    }
}

struct ActiveConnection {
    slot: usize,
    state: Arc<ExecutorLoopbackServerState>,
}

impl ActiveConnection {
    fn install(
        slot: usize,
        stream: &UnixStream,
        state: Arc<ExecutorLoopbackServerState>,
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
                        "executor listener worker already owns a connection",
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

fn spawn_connection_worker<S>(
    slot: usize,
    connections: Arc<ConnectionQueue>,
    service: S,
    peer: UnixPeerExecutorIdentity,
    config: ExecutorLoopbackServerConfig,
    state: Arc<ExecutorLoopbackServerState>,
) -> io::Result<JoinHandle<Result<(), ()>>>
where
    S: ExecutorCapabilityService + ExecutorControlService + ExecutorResumeService + Send + 'static,
{
    thread::Builder::new()
        .name(format!("crucible-executor-connection-{slot}"))
        .spawn(move || {
            let result = catch_unwind(AssertUnwindSafe(|| {
                connection_worker_loop(slot, &connections, service, peer, config, &state);
            }));
            if result.is_err() {
                state.shutdown();
                return Err(());
            }
            Ok(())
        })
}

fn connection_worker_loop<S>(
    slot: usize,
    connections: &ConnectionQueue,
    mut service: S,
    expected_peer: UnixPeerExecutorIdentity,
    config: ExecutorLoopbackServerConfig,
    state: &Arc<ExecutorLoopbackServerState>,
) where
    S: ExecutorCapabilityService + ExecutorControlService + ExecutorResumeService,
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
        let result = match authenticate_executor_peer(&stream, expected_peer) {
            Ok(()) => serve_loopback_executor_component_connection_with_limits(
                &mut stream,
                &mut service,
                config.exchange_timeouts,
                config.maximum_requests_per_connection,
            )
            .map_err(ConnectionFailure::Exchange),
            Err(()) => Err(ConnectionFailure::Peer),
        };
        drop(active);
        match result {
            Ok(()) if state.stopped.load(Ordering::Acquire) => {}
            Ok(()) => increment(&state.completed_connections),
            Err(ConnectionFailure::Peer) => increment(&state.peer_rejections),
            Err(ConnectionFailure::Exchange(LoopbackExecutorServerError::Protocol(_)))
                if !state.stopped.load(Ordering::Acquire) =>
            {
                increment(&state.protocol_failures);
            }
            Err(ConnectionFailure::Exchange(LoopbackExecutorServerError::Protocol(_))) => {}
            Err(ConnectionFailure::Exchange(LoopbackExecutorServerError::Service(_))) => {
                increment(&state.service_failures);
            }
        }
    }
}

enum ConnectionFailure<E> {
    Peer,
    Exchange(LoopbackExecutorServerError<E>),
}

fn authenticate_executor_peer(
    stream: &UnixStream,
    expected: UnixPeerExecutorIdentity,
) -> Result<(), ()> {
    let peer = rustix::net::sockopt::socket_peercred(stream).map_err(|_| ())?;
    if peer.uid.as_raw() != expected.user_id || peer.gid.as_raw() != expected.group_id {
        let _ = stream.shutdown(Shutdown::Both);
        return Err(());
    }
    Ok(())
}

fn enqueue_connection(
    connections: &ConnectionQueue,
    stream: UnixStream,
    state: &ExecutorLoopbackServerState,
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
        for stream in inner.streams.drain(..) {
            let _ = stream.shutdown(Shutdown::Both);
        }
        self.ready.notify_all();
    }

    fn is_closed(&self) -> bool {
        lock_recover(&self.inner).closed
    }
}

fn lock_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn increment(counter: &AtomicU64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_add(1))
    });
}

#[cfg(test)]
mod tests;

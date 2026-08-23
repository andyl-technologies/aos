//! Coupled ownership for one bounded local executor service.
//!
//! The executor listener and semantic worker pool have different concurrency
//! domains but one daemon lifecycle. This module binds those owners so listener
//! termination cancels and joins every modeled worker, while terminal worker
//! completion closes the listener. The concrete execution-model and QEMU
//! factory remain constructor inputs owned by [`LocalExecutorWorkerPool`].

use std::io;
use std::thread::{self, JoinHandle};

use crate::campaign_endpoint::LocalEndpointGuard;
use crate::{
    AssignmentLedger, AttemptAdmissionValidator, ExecutorLoopbackListenerError,
    ExecutorLoopbackServer, ExecutorLoopbackServerConfig, ExecutorLoopbackServerReport,
    ExecutorLoopbackServerShutdown, LocalExecutorPoolCompletion, LocalExecutorPoolReport,
    LocalExecutorPoolService, LocalExecutorPoolShutdown, LocalExecutorPoolShutdownError,
    LocalExecutorWorkerPool, ManagedExecutorLoopbackListener, UnixPeerExecutorIdentity,
};

/// Exclusive owner of one listener and its exact semantic worker pool.
///
/// Dropping an unserved owner is a synchronous fail-closed backstop: it closes
/// the listener, cancels and joins semantic workers, then releases the endpoint
/// namespace. Normal daemon control should call [`Self::serve`] and use
/// [`Self::shutdown_handle`] for explicit termination.
#[must_use = "the local executor service must be served or explicitly dropped"]
pub struct ExecutorLocalService<L, V>
where
    L: AssignmentLedger + Send + 'static,
    V: AttemptAdmissionValidator + Send + Sync + 'static,
{
    inner: Option<ExecutorLocalServiceInner<L, V>>,
    shutdown: ExecutorLocalServiceShutdown<L, V>,
}

struct ExecutorLocalServiceInner<L, V> {
    server: ExecutorLoopbackServer<LocalExecutorPoolService<L, V>>,
    pool: LocalExecutorWorkerPool<L, V>,
    endpoint_guard: LocalEndpointGuard,
}

impl<L, V> ExecutorLocalService<L, V>
where
    L: AssignmentLedger + Send + 'static,
    V: AttemptAdmissionValidator + Send + Sync + 'static,
{
    /// Couples a managed endpoint to the exact supplied semantic worker pool.
    ///
    /// The constructor obtains the listener service only from `pool`; callers
    /// cannot accidentally pair the endpoint with another supervisor
    /// incarnation. The managed endpoint guard remains held until listener and
    /// semantic workers have both joined.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorLoopbackListenerError::Io`] when the managed listener
    /// cannot enter bounded nonblocking acceptance.
    pub fn from_managed_listener(
        listener: ManagedExecutorLoopbackListener,
        pool: LocalExecutorWorkerPool<L, V>,
        peer: UnixPeerExecutorIdentity,
        config: ExecutorLoopbackServerConfig,
    ) -> Result<Self, ExecutorLoopbackListenerError> {
        let (listener, endpoint_guard) = listener.into_parts();
        let server = ExecutorLoopbackServer::new(listener, pool.service(), peer, config)?;
        let shutdown = ExecutorLocalServiceShutdown {
            listener: server.shutdown_handle(),
            pool: pool.shutdown_handle(),
        };
        Ok(Self {
            inner: Some(ExecutorLocalServiceInner {
                server,
                pool,
                endpoint_guard,
            }),
            shutdown,
        })
    }

    /// Returns one sticky authority that stops listener and semantic work.
    #[must_use]
    pub fn shutdown_handle(&self) -> ExecutorLocalServiceShutdown<L, V> {
        self.shutdown.clone()
    }

    /// Serves authenticated requests and joins every owned worker on exit.
    ///
    /// A fixed monitor closes the listener when the semantic pool terminates.
    /// Listener termination first requests pool cancellation and then joins all
    /// semantic workers. Pool failure takes precedence in the returned error so
    /// a poisoned executor is never reported as an ordinary listener stop.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorLocalServiceError`] for listener failure, semantic
    /// worker failure, or failure of the single lifecycle-monitor thread.
    pub fn serve(mut self) -> Result<ExecutorLocalServiceReport, ExecutorLocalServiceError> {
        let Some(ExecutorLocalServiceInner {
            server,
            pool,
            endpoint_guard,
        }) = self.inner.take()
        else {
            return Err(ExecutorLocalServiceError::OwnerUnavailable);
        };
        let monitor = spawn_pool_monitor(pool.completion_handle(), server.shutdown_handle());
        let monitor = match monitor {
            Ok(monitor) => monitor,
            Err(source) => {
                let pool_result = pool.shutdown_and_join();
                drop(server);
                drop(endpoint_guard);
                pool_result.map_err(ExecutorLocalServiceError::Pool)?;
                return Err(ExecutorLocalServiceError::MonitorSpawn { source });
            }
        };

        let listener_result = server.serve().map_err(ExecutorLocalServiceError::Listener);
        let pool_result = pool
            .shutdown_and_join()
            .map_err(ExecutorLocalServiceError::Pool);
        let monitor_result = monitor
            .join()
            .map_err(|_| ExecutorLocalServiceError::MonitorPanicked);

        let pool_report = pool_result?;
        monitor_result?;
        let listener_report = listener_result?;
        drop(endpoint_guard);
        Ok(ExecutorLocalServiceReport {
            listener: listener_report,
            pool: pool_report,
        })
    }
}

impl<L, V> Drop for ExecutorLocalService<L, V>
where
    L: AssignmentLedger + Send + 'static,
    V: AttemptAdmissionValidator + Send + Sync + 'static,
{
    fn drop(&mut self) {
        self.shutdown.shutdown();
        let Some(ExecutorLocalServiceInner {
            server,
            pool,
            endpoint_guard,
        }) = self.inner.take()
        else {
            return;
        };
        drop(server);
        let _ = pool.shutdown_and_join();
        drop(endpoint_guard);
    }
}

fn spawn_pool_monitor(
    completion: LocalExecutorPoolCompletion,
    listener: ExecutorLoopbackServerShutdown,
) -> io::Result<JoinHandle<()>> {
    thread::Builder::new()
        .name(String::from("crucible-executor-pool-monitor"))
        .spawn(move || {
            completion.wait();
            listener.shutdown();
        })
}

/// Cloneable sticky shutdown authority for one complete local executor service.
pub struct ExecutorLocalServiceShutdown<L, V> {
    listener: ExecutorLoopbackServerShutdown,
    pool: LocalExecutorPoolShutdown<L, V>,
}

impl<L, V> Clone for ExecutorLocalServiceShutdown<L, V> {
    fn clone(&self) -> Self {
        Self {
            listener: self.listener.clone(),
            pool: self.pool.clone(),
        }
    }
}

impl<L, V> ExecutorLocalServiceShutdown<L, V> {
    /// Prevents new work, cancels active attempts, and interrupts socket work.
    pub fn shutdown(&self) {
        self.pool.shutdown();
        self.listener.shutdown();
    }

    /// Returns whether both owned concurrency domains received shutdown.
    #[must_use]
    pub fn is_shutdown(&self) -> bool {
        self.pool.is_shutdown() && self.listener.is_shutdown()
    }
}

/// Final operational reports from one complete local executor incarnation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecutorLocalServiceReport {
    listener: ExecutorLoopbackServerReport,
    pool: LocalExecutorPoolReport,
}

impl ExecutorLocalServiceReport {
    /// Returns bounded listener and connection counters.
    #[must_use]
    pub const fn listener(self) -> ExecutorLoopbackServerReport {
        self.listener
    }

    /// Returns bounded semantic worker and supervisor counters.
    #[must_use]
    pub const fn pool(self) -> LocalExecutorPoolReport {
        self.pool
    }
}

/// Terminal failure from a coupled local executor service.
#[derive(Debug, thiserror::Error)]
pub enum ExecutorLocalServiceError {
    /// The service's linear listener/pool owner was already consumed.
    #[error("local executor lifecycle owner is unavailable")]
    OwnerUnavailable,
    /// The single pool-completion monitor could not be created.
    #[error("local executor lifecycle monitor could not be created")]
    MonitorSpawn {
        /// Underlying operating-system thread creation failure.
        source: io::Error,
    },
    /// The pool-completion monitor escaped through an invariant panic.
    #[error("local executor lifecycle monitor panicked")]
    MonitorPanicked,
    /// The authenticated listener failed while accepting or serving requests.
    #[error(transparent)]
    Listener(#[from] ExecutorLoopbackListenerError),
    /// A semantic worker or its supervisor failed during terminal join.
    #[error(transparent)]
    Pool(#[from] LocalExecutorPoolShutdownError),
}

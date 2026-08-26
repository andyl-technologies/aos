//! Coupled serving lifecycle for the campaign listener, runtimes, and executor.

use std::io;
use std::thread::{self, JoinHandle};

use super::*;

type RuntimeMonitor = JoinHandle<()>;
type RuntimeMonitorSpawnResult = Result<Vec<RuntimeMonitor>, (io::Error, Vec<RuntimeMonitor>)>;

impl CampaignLocalService {
    /// Returns a cloneable sticky shutdown authority.
    #[must_use]
    pub fn shutdown_handle(&self) -> CampaignLoopbackServerShutdown {
        self.server.shutdown_handle()
    }

    /// Serves authenticated campaign requests until sticky shutdown.
    ///
    /// Any attached runtime or packaged-executor termination stops the shared
    /// listener. Listener shutdown then cancels and joins every runtime and the
    /// executor before repository ownership is released.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignLocalServiceError::Listener`] when listener acceptance
    /// or a worker invariant fails, or the corresponding runtime, executor, or
    /// monitor error when a coupled owner fails. Repository and endpoint
    /// ownership remain held until all workers have stopped.
    pub fn serve(self) -> Result<CampaignLoopbackServerReport, CampaignLocalServiceError> {
        let Self {
            server,
            runtimes,
            executor,
            _state: state,
        } = self;
        let runtime_monitors = match spawn_runtime_monitors(&server, &runtimes) {
            Ok(monitors) => monitors,
            Err((source, monitors)) => {
                let runtime_result = shutdown_runtimes(runtimes);
                let executor_result = shutdown_executor(executor);
                let monitor_result = join_runtime_monitors(monitors);
                drop(state);
                executor_result?;
                runtime_result?;
                monitor_result?;
                return Err(CampaignLocalServiceError::RuntimeMonitorSpawn { source });
            }
        };
        let executor_monitor = match spawn_executor_monitor(&server, executor.as_ref()) {
            Ok(monitor) => monitor,
            Err(source) => {
                let runtime_result = shutdown_runtimes(runtimes);
                let executor_result = shutdown_executor(executor);
                let monitor_result = join_runtime_monitors(runtime_monitors);
                drop(state);
                executor_result?;
                runtime_result?;
                monitor_result?;
                return Err(CampaignLocalServiceError::PackagedExecutorMonitorSpawn { source });
            }
        };

        let result = server.serve().map_err(CampaignLocalServiceError::Listener);
        let runtime_result = shutdown_runtimes(runtimes);
        let executor_result = shutdown_executor(executor);
        let runtime_monitor_result = join_runtime_monitors(runtime_monitors);
        let executor_monitor_result = join_executor_monitor(executor_monitor);
        drop(state);

        executor_monitor_result?;
        runtime_monitor_result?;
        executor_result?;
        runtime_result?;
        result
    }
}

fn spawn_runtime_monitors(
    server: &CampaignLoopbackServer<UnixPeerCampaignPolicy, CampaignLocalAuthorizer>,
    runtimes: &[AttachedCanonicalCampaignRuntime],
) -> RuntimeMonitorSpawnResult {
    let mut monitors = Vec::with_capacity(runtimes.len());
    for (index, runtime) in runtimes.iter().enumerate() {
        let completion = runtime.completion_handle();
        let shutdown = server.shutdown_handle();
        let name = format!("crucible-campaign-runtime-monitor-{index:03}");
        match thread::Builder::new().name(name).spawn(move || {
            completion.wait();
            shutdown.shutdown();
        }) {
            Ok(monitor) => monitors.push(monitor),
            Err(source) => return Err((source, monitors)),
        }
    }
    Ok(monitors)
}

fn spawn_executor_monitor(
    server: &CampaignLoopbackServer<UnixPeerCampaignPolicy, CampaignLocalAuthorizer>,
    executor: Option<&AttachedPackagedQemuExecutor>,
) -> Result<Option<JoinHandle<()>>, io::Error> {
    executor
        .map(|executor| {
            let completion = executor.completion_handle();
            let shutdown = server.shutdown_handle();
            thread::Builder::new()
                .name(String::from("crucible-packaged-executor-monitor"))
                .spawn(move || {
                    completion.wait();
                    shutdown.shutdown();
                })
        })
        .transpose()
}

fn shutdown_runtimes(
    runtimes: Vec<AttachedCanonicalCampaignRuntime>,
) -> Result<(), CampaignLocalServiceError> {
    let mut first_error = None;
    for runtime in runtimes {
        if let Err(source) = runtime.shutdown_and_join()
            && first_error.is_none()
        {
            first_error = Some(CampaignLocalServiceError::Runtime(source));
        }
    }
    first_error.map_or(Ok(()), Err)
}

fn shutdown_executor(
    executor: Option<AttachedPackagedQemuExecutor>,
) -> Result<(), CampaignLocalServiceError> {
    executor
        .map(AttachedPackagedQemuExecutor::shutdown_and_join)
        .transpose()
        .map(|_| ())
        .map_err(CampaignLocalServiceError::PackagedExecutorJoin)
}

fn join_runtime_monitors(monitors: Vec<RuntimeMonitor>) -> Result<(), CampaignLocalServiceError> {
    let mut panicked = false;
    for monitor in monitors {
        panicked |= monitor.join().is_err();
    }
    if panicked {
        Err(CampaignLocalServiceError::RuntimeMonitorPanicked)
    } else {
        Ok(())
    }
}

fn join_executor_monitor(monitor: Option<JoinHandle<()>>) -> Result<(), CampaignLocalServiceError> {
    if monitor.is_some_and(|monitor| monitor.join().is_err()) {
        Err(CampaignLocalServiceError::PackagedExecutorMonitorPanicked)
    } else {
        Ok(())
    }
}

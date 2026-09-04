//! Coupled serving lifecycle for the campaign listener, runtimes, and executor.

use std::io;
use std::thread::{self, JoinHandle};

use super::*;

impl CampaignLocalService {
    /// Returns a cloneable sticky shutdown authority.
    #[must_use]
    pub fn shutdown_handle(&self) -> CampaignLoopbackServerShutdown {
        self.server.shutdown_handle()
    }

    /// Serves authenticated campaign requests until sticky shutdown.
    ///
    /// Any attached runtime or packaged-executor termination stops the shared
    /// listener. Listener shutdown then cancels and joins runtimes and waits
    /// for executor cleanup. If semantic workers remain after its bounded wait,
    /// they retain the repository and executor endpoint and return a pending
    /// cleanup error instead of claiming a completed shutdown.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignLocalServiceError::Listener`] when listener acceptance
    /// or a worker invariant fails, or the corresponding runtime, executor, or
    /// monitor error when a coupled owner fails. Unfinished executor workers
    /// retain repository and executor endpoint ownership.
    pub fn serve(self) -> Result<CampaignLoopbackServerReport, CampaignLocalServiceError> {
        let Self {
            server,
            executor,
            mut maintenance,
            runtime_registry,
        } = self;
        let executor_monitor = match spawn_executor_monitor(&server, executor.as_ref()) {
            Ok(monitor) => monitor,
            Err(source) => {
                let maintenance_result = shutdown_maintenance(&mut maintenance);
                let runtime_result = runtime_registry.close_and_join();
                let executor_result = shutdown_executor(executor);
                maintenance_result?;
                executor_result?;
                runtime_result?;
                return Err(CampaignLocalServiceError::PackagedExecutorMonitorSpawn { source });
            }
        };

        let result = server.serve().map_err(CampaignLocalServiceError::Listener);
        let maintenance_result = shutdown_maintenance(&mut maintenance);
        let runtime_result = runtime_registry.close_and_join();
        let executor_result = shutdown_executor(executor);
        let executor_monitor_result = join_executor_monitor(executor_monitor);

        executor_monitor_result?;
        maintenance_result?;
        executor_result?;
        runtime_result?;
        result
    }
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

fn shutdown_maintenance(
    maintenance: &mut Option<CampaignStoreMaintenanceOwner>,
) -> Result<(), CampaignLocalServiceError> {
    maintenance
        .as_mut()
        .map(CampaignStoreMaintenanceOwner::close_and_join)
        .transpose()
        .map_err(|error| match error {
            maintenance::MaintenanceJoinError::Operation(failure) => {
                CampaignLocalServiceError::StoreMaintenanceFailed {
                    operation: failure.operation,
                    boundary: failure.boundary,
                    source: failure.source,
                }
            }
            maintenance::MaintenanceJoinError::Panicked => {
                CampaignLocalServiceError::StoreMaintenancePanicked
            }
        })
        .map(|_| ())
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

fn join_executor_monitor(monitor: Option<JoinHandle<()>>) -> Result<(), CampaignLocalServiceError> {
    if monitor.is_some_and(|monitor| monitor.join().is_err()) {
        Err(CampaignLocalServiceError::PackagedExecutorMonitorPanicked)
    } else {
        Ok(())
    }
}

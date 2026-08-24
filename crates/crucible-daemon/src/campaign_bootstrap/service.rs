//! Coupled serving lifecycle for the campaign listener, runtime, and executor.

use std::thread;

use super::*;

impl CampaignLocalService {
    /// Returns a cloneable sticky shutdown authority.
    #[must_use]
    pub fn shutdown_handle(&self) -> CampaignLoopbackServerShutdown {
        self.server.shutdown_handle()
    }

    /// Serves authenticated campaign requests until sticky shutdown.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignLocalServiceError::Listener`] when listener acceptance
    /// or a worker invariant fails. Repository and endpoint ownership remain
    /// held until all workers have stopped.
    pub fn serve(self) -> Result<CampaignLoopbackServerReport, CampaignLocalServiceError> {
        let Self {
            server,
            runtime,
            executor,
            _state: state,
        } = self;
        let runtime_monitor = runtime
            .as_ref()
            .map(|runtime| {
                let completion = runtime.completion_handle();
                let shutdown = server.shutdown_handle();
                thread::Builder::new()
                    .name(String::from("crucible-campaign-runtime-monitor"))
                    .spawn(move || {
                        completion.wait();
                        shutdown.shutdown();
                    })
            })
            .transpose();
        let runtime_monitor = match runtime_monitor {
            Ok(monitor) => monitor,
            Err(source) => {
                let runtime_result = runtime
                    .map(AttachedCanonicalCampaignRuntime::shutdown_and_join)
                    .transpose()
                    .map_err(CampaignLocalServiceError::Runtime);
                let executor_result = executor
                    .map(AttachedPackagedQemuExecutor::shutdown_and_join)
                    .transpose()
                    .map_err(CampaignLocalServiceError::PackagedExecutorJoin);
                drop(state);
                executor_result?;
                runtime_result?;
                return Err(CampaignLocalServiceError::RuntimeMonitorSpawn { source });
            }
        };
        let executor_monitor = executor
            .as_ref()
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
            .transpose();
        let executor_monitor = match executor_monitor {
            Ok(monitor) => monitor,
            Err(source) => {
                let runtime_result = runtime
                    .map(AttachedCanonicalCampaignRuntime::shutdown_and_join)
                    .transpose()
                    .map_err(CampaignLocalServiceError::Runtime);
                let executor_result = executor
                    .map(AttachedPackagedQemuExecutor::shutdown_and_join)
                    .transpose()
                    .map_err(CampaignLocalServiceError::PackagedExecutorJoin);
                if let Some(monitor) = runtime_monitor {
                    monitor
                        .join()
                        .map_err(|_| CampaignLocalServiceError::RuntimeMonitorPanicked)?;
                }
                drop(state);
                executor_result?;
                runtime_result?;
                return Err(CampaignLocalServiceError::PackagedExecutorMonitorSpawn { source });
            }
        };
        let result = server.serve().map_err(CampaignLocalServiceError::Listener);
        let runtime_result = runtime
            .map(AttachedCanonicalCampaignRuntime::shutdown_and_join)
            .transpose()
            .map(|_| ())
            .map_err(CampaignLocalServiceError::Runtime);
        let executor_result = executor
            .map(AttachedPackagedQemuExecutor::shutdown_and_join)
            .transpose()
            .map(|_| ())
            .map_err(CampaignLocalServiceError::PackagedExecutorJoin);
        if let Some(monitor) = runtime_monitor {
            monitor
                .join()
                .map_err(|_| CampaignLocalServiceError::RuntimeMonitorPanicked)?;
        }
        if let Some(monitor) = executor_monitor {
            monitor
                .join()
                .map_err(|_| CampaignLocalServiceError::PackagedExecutorMonitorPanicked)?;
        }
        drop(state);
        match (result, runtime_result, executor_result) {
            (_, _, Err(error)) => Err(error),
            (_, Err(error), Ok(())) => Err(error),
            (Err(error), Ok(()), Ok(())) => Err(error),
            (Ok(report), Ok(()), Ok(())) => Ok(report),
        }
    }
}

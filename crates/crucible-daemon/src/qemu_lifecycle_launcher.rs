//! Attempt-owned guarded launcher for the production VM lifecycle.
//!
//! This adapter is the daemon-side owner of the API lifecycle's linear QEMU
//! generations. It admits and pins fresh generation directories, runs image
//! tools under the attempt contract, streams repository checkpoints, and lends
//! the sealed process contract only after preparation. Any unreaped QEMU or
//! helper child is transferred into the aggregate guard before an error returns.

use std::collections::BTreeMap;
#[cfg(target_os = "linux")]
use std::sync::{Arc, Mutex};

use crucible_api::{
    LifecycleApiError, ProductionVmExactNodeRestoreAdmission, ProductionVmNodeGeneration,
    ProductionVmNodeLaunch, ProductionVmNodeLaunchRequest, ProductionVmNodeLauncher,
    ProductionVmNodeLease,
};
use crucible_qemu::{
    QemuLiveNodeIdentity, QemuNode, QemuPreparedRunDirectory, QemuProductionFreshLaunchAdmission,
    launch_qemu_production_fresh_node,
};

use crate::{
    QemuAttemptGenerationLease, QemuAttemptGenerationResourceOwner, QemuAttemptProcessResourceGuard,
};

/// Guarded production lifecycle launcher for one admitted QEMU attempt.
#[must_use = "finish the lifecycle launcher or transfer its aggregate owner to quarantine"]
pub(crate) struct QemuAttemptProductionVmNodeLauncher<G>
where
    G: QemuAttemptProcessResourceGuard,
{
    owner: QemuAttemptGenerationResourceOwner<G>,
    run_directories: Arc<Mutex<BTreeMap<ProductionVmNodeGeneration, QemuPreparedRunDirectory>>>,
}

impl<G> QemuAttemptProductionVmNodeLauncher<G>
where
    G: QemuAttemptProcessResourceGuard,
{
    /// Wraps one attempt-wide resource owner as a lifecycle generation launcher.
    pub(crate) fn new(owner: QemuAttemptGenerationResourceOwner<G>) -> Self {
        Self {
            owner,
            run_directories: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    #[cfg(target_os = "linux")]
    fn launch_exact_generation(
        &mut self,
        request: ProductionVmNodeLaunchRequest<'_>,
        admission: ProductionVmExactNodeRestoreAdmission,
        lease: QemuAttemptGenerationLease,
        run_directories: &mut BTreeMap<ProductionVmNodeGeneration, QemuPreparedRunDirectory>,
    ) -> Result<ProductionVmNodeLaunch, LifecycleApiError> {
        if let Err(error) = self.owner.check_operational_boundary() {
            return Err(abort_unspawned_generation(lease, error));
        }
        let run_directory = match self
            .owner
            .prepare_generation_run_directory(request.launch().resource_requirements())
        {
            Ok(run_directory) => run_directory,
            Err(error) => return Err(abort_unspawned_generation(lease, error)),
        };
        let process_contract = match self.owner.child_process_contract() {
            Ok(contract) => contract,
            Err(error) => return Err(abort_unspawned_generation(lease, error)),
        };
        let atomic = match admission.into_atomic_restore(request, run_directory, process_contract) {
            Ok(atomic) => atomic,
            Err(error) => return Err(abort_unspawned_generation(lease, error)),
        };
        let (node, run_directory) = match atomic.launch() {
            Ok(launched) => launched,
            Err(mut error) => {
                let message = launch_error_chain(&error);
                if let Some(child) = error.take_unreaped_child() {
                    self.owner.retain_failed_launch_child(child);
                    drop(lease);
                    self.owner.quarantine();
                    return Err(launcher_message(format!(
                        "atomic exact restore for `{}` failed and transferred an unreaped child to quarantine: {message}",
                        request.node_name(),
                    )));
                }
                return Err(abort_unspawned_generation(
                    lease,
                    launcher_message(format!(
                        "atomic exact restore for `{}` failed after synchronous cleanup: {message}",
                        request.node_name(),
                    )),
                ));
            }
        };
        self.record_launched_generation(request, lease, run_directory, node, run_directories)
    }

    fn launch_fresh_generation(
        &mut self,
        request: ProductionVmNodeLaunchRequest<'_>,
        qemu_executable: &std::path::Path,
        root_image: &std::path::Path,
        lease: QemuAttemptGenerationLease,
        run_directories: &mut BTreeMap<ProductionVmNodeGeneration, QemuPreparedRunDirectory>,
    ) -> Result<ProductionVmNodeLaunch, LifecycleApiError> {
        if request.launch().qemu_executable() != qemu_executable
            || request.launch().root_image() != Some(root_image)
        {
            return Err(abort_unspawned_generation(
                lease,
                launcher_message(
                    "fresh image-tool inputs do not match the exact QEMU launch profile",
                ),
            ));
        }
        if let Err(error) = self.owner.check_operational_boundary() {
            return Err(abort_unspawned_generation(lease, error));
        }
        let mut run_directory = match self
            .owner
            .prepare_generation_run_directory(request.launch().resource_requirements())
        {
            Ok(run_directory) => run_directory,
            Err(error) => return Err(abort_unspawned_generation(lease, error)),
        };
        let preparation = {
            let process_contract = match self.owner.child_process_contract() {
                Ok(contract) => contract,
                Err(error) => return Err(abort_unspawned_generation(lease, error)),
            };
            run_directory.prepare_fresh_artifacts_guarded(
                qemu_executable,
                Some(root_image),
                process_contract,
            )
        };
        if let Err(mut error) = preparation {
            let message = launch_error_chain(&error);
            if let Some(child) = error.take_unreaped_child() {
                self.owner.retain_failed_launch_child(child);
                drop(lease);
                self.owner.quarantine();
                return Err(launcher_message(format!(
                    "prepare fresh QEMU node `{}` failed and transferred an unreaped image-tool child to quarantine: {message}",
                    request.node_name(),
                )));
            }
            return Err(abort_unspawned_generation(
                lease,
                launcher_message(format!(
                    "prepare fresh QEMU node `{}` failed after synchronous helper cleanup: {message}",
                    request.node_name(),
                )),
            ));
        }
        if let Err(error) = self.owner.check_operational_boundary() {
            return Err(abort_unspawned_generation(lease, error));
        }

        let launch = request
            .launch()
            .clone()
            .with_run_directory(run_directory.path());
        let identity = QemuLiveNodeIdentity::new(
            request.node_name(),
            request.router_name(),
            request.crash_detector(),
        );
        let launched = {
            let process_contract = match self.owner.child_process_contract() {
                Ok(contract) => contract,
                Err(error) => return Err(abort_unspawned_generation(lease, error)),
            };
            QemuProductionFreshLaunchAdmission::admit(
                &launch,
                &run_directory,
                process_contract,
                identity,
            )
            .and_then(|admission| launch_qemu_production_fresh_node(&launch, admission))
        };
        let node = match launched {
            Ok(node) => node,
            Err(mut error) => {
                let message = launch_error_chain(&error);
                if let Some(child) = error.take_unreaped_child() {
                    self.owner.retain_failed_launch_child(child);
                    drop(lease);
                    self.owner.quarantine();
                    return Err(launcher_message(format!(
                        "launch guarded fresh QEMU node `{}` failed and transferred an unreaped child to quarantine: {message}",
                        request.node_name(),
                    )));
                }
                return Err(abort_unspawned_generation(
                    lease,
                    launcher_message(format!(
                        "launch guarded fresh QEMU node `{}` failed after synchronous cleanup: {message}",
                        request.node_name(),
                    )),
                ));
            }
        };

        self.record_launched_generation(request, lease, run_directory, node, run_directories)
    }

    fn record_launched_generation(
        &self,
        request: ProductionVmNodeLaunchRequest<'_>,
        lease: QemuAttemptGenerationLease,
        run_directory: QemuPreparedRunDirectory,
        node: QemuNode,
        run_directories: &mut BTreeMap<ProductionVmNodeGeneration, QemuPreparedRunDirectory>,
    ) -> Result<ProductionVmNodeLaunch, LifecycleApiError> {
        let generation = lease.identity().clone();
        let run_directory_path = run_directory.path().to_path_buf();
        let prior = run_directories.insert(generation, run_directory);
        debug_assert!(prior.is_none());
        let lease = QemuLifecycleGenerationLease {
            inner: lease,
            run_directories: Arc::clone(&self.run_directories),
            directory_released: false,
        };

        ProductionVmNodeLaunch::new_in_run_directory(request, run_directory_path, node, lease)
    }
}

impl<G> ProductionVmNodeLauncher for QemuAttemptProductionVmNodeLauncher<G>
where
    G: QemuAttemptProcessResourceGuard + Send,
{
    fn begin_execution_quantum(&mut self) -> Result<(), LifecycleApiError> {
        self.owner.charge_execution_quantum()
    }

    fn check_operational_boundary(&mut self) -> Result<(), LifecycleApiError> {
        self.owner.check_operational_boundary()
    }

    fn launch_fresh(
        &mut self,
        request: ProductionVmNodeLaunchRequest<'_>,
        qemu_executable: &std::path::Path,
        root_image: &std::path::Path,
    ) -> Result<ProductionVmNodeLaunch, LifecycleApiError> {
        let identity =
            ProductionVmNodeGeneration::new(request.node().clone(), request.generation())?;
        let lease = self.owner.register_generation(identity.clone())?;
        let run_directories = Arc::clone(&self.run_directories);
        let mut run_directories = match run_directories.lock() {
            Ok(run_directories) => run_directories,
            Err(_) => {
                return Err(abort_unspawned_generation(
                    lease,
                    launcher_message("QEMU generation run-directory registry is poisoned"),
                ));
            }
        };
        if run_directories.contains_key(&identity) {
            return Err(abort_unspawned_generation(
                lease,
                launcher_message("QEMU generation already retains a run-directory authority"),
            ));
        }

        self.launch_fresh_generation(
            request,
            qemu_executable,
            root_image,
            lease,
            &mut run_directories,
        )
    }

    fn launch_restored(
        &mut self,
        request: ProductionVmNodeLaunchRequest<'_>,
        admission: ProductionVmExactNodeRestoreAdmission,
    ) -> Result<ProductionVmNodeLaunch, LifecycleApiError> {
        let identity =
            ProductionVmNodeGeneration::new(request.node().clone(), request.generation())?;
        let lease = self.owner.register_generation(identity.clone())?;
        let run_directories = Arc::clone(&self.run_directories);
        let mut run_directories = match run_directories.lock() {
            Ok(run_directories) => run_directories,
            Err(_) => {
                return Err(abort_unspawned_generation(
                    lease,
                    launcher_message("QEMU generation run-directory registry is poisoned"),
                ));
            }
        };
        if run_directories.contains_key(&identity) {
            return Err(abort_unspawned_generation(
                lease,
                launcher_message("QEMU generation already retains a run-directory authority"),
            ));
        }

        #[cfg(target_os = "linux")]
        {
            self.launch_exact_generation(request, admission, lease, &mut run_directories)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (admission, run_directories);
            Err(abort_unspawned_generation(
                lease,
                launcher_message("exact restore requires descriptor-backed v9 state on Linux"),
            ))
        }
    }

    fn replay_candidate(&self) -> Result<Box<dyn ProductionVmNodeLauncher>, LifecycleApiError> {
        Err(launcher_message(
            "attempt resource contract does not admit an independent debugger replay world",
        ))
    }

    fn finish(&mut self) -> Result<(), LifecycleApiError> {
        self.owner.finish()
    }
}

struct QemuLifecycleGenerationLease {
    inner: QemuAttemptGenerationLease,
    run_directories: Arc<Mutex<BTreeMap<ProductionVmNodeGeneration, QemuPreparedRunDirectory>>>,
    directory_released: bool,
}

impl ProductionVmNodeLease for QemuLifecycleGenerationLease {
    fn identity(&self) -> &ProductionVmNodeGeneration {
        self.inner.identity()
    }

    fn open_checkpoint_root_overlay(&self) -> Result<std::fs::File, LifecycleApiError> {
        let run_directories = self
            .run_directories
            .lock()
            .map_err(|_| launcher_message("QEMU generation run-directory registry is poisoned"))?;
        let directory = run_directories.get(self.inner.identity()).ok_or_else(|| {
            launcher_message("QEMU generation lost its retained run-directory authority")
        })?;
        directory
            .open_root_overlay_for_checkpoint()
            .map_err(|error| launcher_message(format!("open pinned checkpoint overlay: {error}")))
    }

    fn finish(&mut self) -> Result<(), LifecycleApiError> {
        if !self.directory_released {
            let mut run_directories = self.run_directories.lock().map_err(|_| {
                launcher_message("QEMU generation run-directory registry is poisoned")
            })?;
            if run_directories.remove(self.inner.identity()).is_none() {
                return Err(launcher_message(
                    "QEMU generation lost its retained run-directory authority",
                ));
            }
            self.directory_released = true;
        }
        self.inner.finish()
    }
}

fn abort_unspawned_generation(
    lease: QemuAttemptGenerationLease,
    primary: LifecycleApiError,
) -> LifecycleApiError {
    match lease.abort_without_process() {
        Ok(()) => primary,
        Err(abort) => launcher_message(format!(
            "{primary}; aborting the no-process generation also failed: {abort}"
        )),
    }
}

fn launcher_message(message: impl Into<String>) -> LifecycleApiError {
    LifecycleApiError::LoopFactory {
        message: message.into(),
    }
}

/// Preserves typed causes when crossing the lifecycle's string-only boundary.
/// Bounds also contain unexpectedly recursive or verbose backend errors.
// crucible-lint: allow erased-error -- diagnostic formatting follows Error::source without replacing the typed launch error.
fn launch_error_chain(error: &(dyn std::error::Error + 'static)) -> String {
    let mut message = String::new();
    let mut current = Some(error);
    for _ in 0..12 {
        let Some(error) = current else { break };
        if !message.is_empty() {
            message.push_str("; caused by: ");
        }
        message.extend(error.to_string().chars().take(1024));
        current = error.source();
    }
    if current.is_some() {
        message.push_str("; further causes omitted");
    }
    message
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rendered_launch_error(
        operation: &'static str,
        error: impl std::error::Error + 'static,
    ) -> String {
        launcher_message(format!("{operation}: {}", launch_error_chain(&error))).to_string()
    }

    #[test]
    fn launch_failure_preserves_rejected_asset_detail() {
        let error = crucible_qemu::QemuLiveNodeStepGateError::LaunchCommand {
            source: crucible_qemu::QemuLaunchCommandError::InvalidStorePath {
                field: "root_image",
                path: "/tmp/root.raw".to_owned(),
            },
        };
        let message = rendered_launch_error("launch fresh node", error);
        assert!(message.contains("build QEMU launch command failed"));
        assert!(message.contains("root_image must be an AOS store path, got `/tmp/root.raw`"));
    }

    #[test]
    fn launch_failure_bounds_recursive_and_verbose_causes() {
        // A manually implemented source exercises errors outside our derives.
        #[derive(Debug)]
        struct Recursive;
        impl std::fmt::Display for Recursive {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "recursive backend")
            }
        }
        impl std::error::Error for Recursive {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(self)
            }
        }
        let message = launch_error_chain(&Recursive);
        assert_eq!(message.matches("recursive backend").count(), 12);
        assert!(message.ends_with("further causes omitted"));
        assert_eq!(
            launch_error_chain(&std::io::Error::other("x".repeat(2048))).len(),
            1024
        );
    }
}

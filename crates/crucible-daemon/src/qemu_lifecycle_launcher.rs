//! Attempt-owned guarded launcher for the production VM lifecycle.
//!
//! This adapter is the daemon-side owner of the API lifecycle's linear QEMU
//! generations. It admits and pins fresh generation directories, runs image
//! tools under the attempt contract, streams repository checkpoints, reflinks
//! local replacements from retained prior-generation descriptors, and lends
//! the sealed process contract only after preparation. Any unreaped QEMU or
//! helper child is transferred into the aggregate guard before an error
//! returns.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use crucible_api::{
    LifecycleApiError, ProductionVmNodeGeneration, ProductionVmNodeLaunch,
    ProductionVmNodeLaunchKind, ProductionVmNodeLaunchRequest, ProductionVmNodeLauncher,
    ProductionVmNodeLease, ProductionVmNodePreparationKind,
};
use crucible_qemu::{
    QemuGuardedExactNodeLaunch, QemuGuardedFreshNodeLaunch, QemuLiveNodeIdentity, QemuNode,
    QemuPreparedRunDirectory, QemuVmStateBinding, launch_qemu_live_node_exact_snapshot_guarded,
    launch_qemu_live_node_exact_snapshot_paused_guarded, launch_qemu_live_node_guarded,
};

use crate::{
    QemuAttemptGenerationLease, QemuAttemptGenerationResourceOwner, QemuAttemptProcessResourceGuard,
};

/// Guarded production lifecycle launcher for one admitted QEMU attempt.
#[must_use = "finish the lifecycle launcher or transfer its aggregate owner to quarantine"]
pub struct QemuAttemptProductionVmNodeLauncher<G>
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
    pub fn new(owner: QemuAttemptGenerationResourceOwner<G>) -> Self {
        Self {
            owner,
            run_directories: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    fn launch_exact(
        &mut self,
        request: ProductionVmNodeLaunchRequest<'_>,
        exact: ExactLifecycleLaunch<'_>,
        lease: QemuAttemptGenerationLease,
        run_directories: &mut BTreeMap<ProductionVmNodeGeneration, QemuPreparedRunDirectory>,
    ) -> Result<ProductionVmNodeLaunch, LifecycleApiError> {
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
        let binding = QemuVmStateBinding::from_exact_checkpoint_root_digest(exact.root.bytes);

        let materialization = (|| {
            let mut destination = run_directory
                .begin_exact_root_overlay_materialization(binding, exact.root_overlay.length())
                .map_err(|error| {
                    launcher_error("begin exact root-overlay materialization", error)
                })?;
            exact.root_overlay.stream_into(&mut destination)?;
            destination.finish().map_err(|error| {
                launcher_error("finish exact root-overlay materialization", error)
            })?;

            self.owner.check_operational_boundary()?;
            let mut destination = run_directory
                .begin_exact_vmstate_materialization(binding, exact.vmstate.length())
                .map_err(|error| launcher_error("begin exact VMState materialization", error))?;
            exact.vmstate.stream_into(&mut destination)?;
            destination
                .finish()
                .map_err(|error| launcher_error("finish exact VMState materialization", error))?;
            self.owner.check_operational_boundary()
        })();
        if let Err(error) = materialization {
            return Err(abort_unspawned_generation(lease, error));
        }

        self.launch_prepared_exact(
            request,
            ExactLaunchTarget {
                snapshot: exact.snapshot,
                paused: exact.paused,
            },
            lease,
            run_directory,
            binding,
            run_directories,
        )
    }

    fn launch_fresh(
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
            launch_qemu_live_node_guarded(
                &launch,
                QemuGuardedFreshNodeLaunch::new(&run_directory, process_contract, identity),
            )
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

    fn launch_replacement(
        &mut self,
        request: ProductionVmNodeLaunchRequest<'_>,
        exact: ExactLaunchTarget<'_>,
        source_run_directory: &std::path::Path,
        lease: QemuAttemptGenerationLease,
        run_directories: &mut BTreeMap<ProductionVmNodeGeneration, QemuPreparedRunDirectory>,
    ) -> Result<ProductionVmNodeLaunch, LifecycleApiError> {
        let source_identity = run_directories.iter().find_map(|(identity, directory)| {
            (identity.node() == request.node()
                && directory.path() == source_run_directory
                && identity.generation().checked_add(1) == Some(request.generation()))
            .then(|| identity.clone())
        });
        let Some(source_identity) = source_identity else {
            return Err(abort_unspawned_generation(
                lease,
                launcher_message(format!(
                    "replacement source {} is not the retained prior generation for `{}` generation {}",
                    source_run_directory.display(),
                    request.node_name(),
                    request.generation(),
                )),
            ));
        };
        if let Err(error) = self.owner.check_operational_boundary() {
            return Err(abort_unspawned_generation(lease, error));
        }
        let mut destination = match self
            .owner
            .prepare_generation_run_directory(request.launch().resource_requirements())
        {
            Ok(run_directory) => run_directory,
            Err(error) => return Err(abort_unspawned_generation(lease, error)),
        };
        let binding = QemuVmStateBinding::from_replacement_snapshot_digest(
            exact.snapshot.checkpoint().id.bytes,
        );
        let Some(source) = run_directories.get(&source_identity) else {
            return Err(abort_unspawned_generation(
                lease,
                launcher_message("replacement source generation disappeared before cloning"),
            ));
        };
        if let Err(error) = destination.clone_replacement_artifacts_from(source, binding) {
            return Err(abort_unspawned_generation(
                lease,
                launcher_error("clone pinned replacement artifacts", error),
            ));
        }
        if let Err(error) = self.owner.check_operational_boundary() {
            return Err(abort_unspawned_generation(lease, error));
        }

        self.launch_prepared_exact(request, exact, lease, destination, binding, run_directories)
    }

    fn launch_prepared_exact(
        &mut self,
        request: ProductionVmNodeLaunchRequest<'_>,
        exact: ExactLaunchTarget<'_>,
        lease: QemuAttemptGenerationLease,
        run_directory: QemuPreparedRunDirectory,
        binding: QemuVmStateBinding,
        run_directories: &mut BTreeMap<ProductionVmNodeGeneration, QemuPreparedRunDirectory>,
    ) -> Result<ProductionVmNodeLaunch, LifecycleApiError> {
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
            let guarded = QemuGuardedExactNodeLaunch::new(
                &run_directory,
                process_contract,
                binding,
                identity,
                exact.snapshot,
            );
            if exact.paused {
                launch_qemu_live_node_exact_snapshot_paused_guarded(&launch, guarded)
            } else {
                launch_qemu_live_node_exact_snapshot_guarded(&launch, guarded)
            }
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
                        "launch guarded exact QEMU node `{}` failed and transferred an unreaped child to quarantine: {message}",
                        request.node_name()
                    )));
                }
                return Err(abort_unspawned_generation(
                    lease,
                    launcher_message(format!(
                        "launch guarded exact QEMU node `{}` failed after synchronous cleanup: {message}",
                        request.node_name()
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

    fn launch(
        &mut self,
        request: ProductionVmNodeLaunchRequest<'_>,
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

        match (request.preparation(), request.kind()) {
            (
                ProductionVmNodePreparationKind::Fresh {
                    qemu_executable,
                    root_image,
                },
                ProductionVmNodeLaunchKind::Fresh,
            ) => self.launch_fresh(
                request,
                qemu_executable,
                root_image,
                lease,
                &mut run_directories,
            ),
            (
                ProductionVmNodePreparationKind::Exact {
                    root,
                    root_overlay,
                    vmstate,
                },
                ProductionVmNodeLaunchKind::Exact { snapshot, paused },
            ) => self.launch_exact(
                request,
                ExactLifecycleLaunch {
                    root,
                    root_overlay,
                    vmstate,
                    snapshot,
                    paused,
                },
                lease,
                &mut run_directories,
            ),
            (
                ProductionVmNodePreparationKind::Replacement {
                    source_run_directory,
                },
                ProductionVmNodeLaunchKind::Exact { snapshot, paused },
            ) => self.launch_replacement(
                request,
                ExactLaunchTarget { snapshot, paused },
                source_run_directory,
                lease,
                &mut run_directories,
            ),
            _ => Err(abort_unspawned_generation(
                lease,
                launcher_message(
                    "guarded attempt launcher currently requires exact-checkpoint preparation",
                ),
            )),
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

#[derive(Clone, Copy)]
struct ExactLifecycleLaunch<'a> {
    root: crucible::ContentHash,
    root_overlay: crucible_api::ProductionVmNodeCheckpointArtifact<'a>,
    vmstate: crucible_api::ProductionVmNodeCheckpointArtifact<'a>,
    snapshot: &'a crucible_qemu::QemuVmSnapshot,
    paused: bool,
}

#[derive(Clone, Copy)]
struct ExactLaunchTarget<'a> {
    snapshot: &'a crucible_qemu::QemuVmSnapshot,
    paused: bool,
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

fn launcher_error(
    operation: &'static str,
    error: impl std::error::Error + 'static,
) -> LifecycleApiError {
    launcher_message(format!("{operation}: {}", launch_error_chain(&error)))
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

    #[test]
    fn launch_failure_preserves_rejected_asset_detail() {
        let error = crucible_qemu::QemuLiveNodeStepGateError::LaunchCommand {
            source: crucible_qemu::QemuLaunchCommandError::InvalidStorePath {
                field: "root_image",
                path: "/tmp/root.raw".to_owned(),
            },
        };
        let message = launcher_error("launch fresh node", error).to_string();
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

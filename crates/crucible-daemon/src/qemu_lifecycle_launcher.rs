//! Attempt-owned guarded launcher for the production VM lifecycle.
//!
//! This adapter is the daemon-side owner of the API lifecycle's linear QEMU
//! generations. It admits and pins a fresh generation directory, streams both
//! artifacts of an exact checkpoint under the attempt-wide writable quota,
//! lends the sealed process contract only after materialization, and transfers
//! any unreaped child into the aggregate guard before returning an error.

use crucible_api::{
    LifecycleApiError, ProductionVmNodeGeneration, ProductionVmNodeLaunch,
    ProductionVmNodeLaunchKind, ProductionVmNodeLaunchRequest, ProductionVmNodeLauncher,
    ProductionVmNodePreparationKind,
};
use crucible_qemu::{
    QemuGuardedExactNodeLaunch, QemuLiveNodeIdentity, QemuVmStateBinding,
    launch_qemu_live_node_exact_snapshot_guarded,
    launch_qemu_live_node_exact_snapshot_paused_guarded,
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
}

impl<G> QemuAttemptProductionVmNodeLauncher<G>
where
    G: QemuAttemptProcessResourceGuard,
{
    /// Wraps one attempt-wide resource owner as a lifecycle generation launcher.
    pub const fn new(owner: QemuAttemptGenerationResourceOwner<G>) -> Self {
        Self { owner }
    }

    fn launch_exact(
        &mut self,
        request: ProductionVmNodeLaunchRequest<'_>,
        exact: ExactLifecycleLaunch<'_>,
        lease: QemuAttemptGenerationLease,
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
                let message = error.to_string();
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

        ProductionVmNodeLaunch::new_in_run_directory(request, run_directory.path(), node, lease)
    }
}

impl<G> ProductionVmNodeLauncher for QemuAttemptProductionVmNodeLauncher<G>
where
    G: QemuAttemptProcessResourceGuard + Send,
{
    fn launch(
        &mut self,
        request: ProductionVmNodeLaunchRequest<'_>,
    ) -> Result<ProductionVmNodeLaunch, LifecycleApiError> {
        let identity =
            ProductionVmNodeGeneration::new(request.node().clone(), request.generation())?;
        let lease = self.owner.register_generation(identity)?;

        match (request.preparation(), request.kind()) {
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

#[derive(Clone, Copy)]
struct ExactLifecycleLaunch<'a> {
    root: crucible::ContentHash,
    root_overlay: crucible_api::ProductionVmNodeCheckpointArtifact<'a>,
    vmstate: crucible_api::ProductionVmNodeCheckpointArtifact<'a>,
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

fn launcher_error(operation: &'static str, error: impl std::fmt::Display) -> LifecycleApiError {
    launcher_message(format!("{operation}: {error}"))
}

fn launcher_message(message: impl Into<String>) -> LifecycleApiError {
    LifecycleApiError::LoopFactory {
        message: message.into(),
    }
}

//! Shares exact keyed Source launch and failed-child custody across consumers.

use super::*;

impl<G, F> QemuAttemptProductionVmNodeLauncher<G, F>
where
    G: QemuAttemptProcessResourceGuard,
{
    pub(super) fn launch_fresh_generation(
        &mut self,
        request: ProductionVmNodeLaunchRequest<'_>,
        qemu_executable: &std::path::Path,
        root_image: &std::path::Path,
        lease: QemuAttemptGenerationLease,
        run_directories: &mut BTreeMap<ProductionVmNodeGeneration, QemuPreparedRunDirectory>,
    ) -> Result<ProductionVmNodeLaunch, LifecycleApiError> {
        let fresh = self.prepare_fresh_generation(
            request.launch(),
            request.node(),
            QemuLiveNodeIdentity::new(
                request.node_name(),
                request.router_name(),
                request.crash_detector(),
            ),
            qemu_executable,
            Some(root_image),
            None,
            lease,
        )?;
        self.record_launched_generation(
            request,
            fresh.lease,
            fresh.directory,
            fresh.node,
            fresh.contract,
            run_directories,
        )
    }

    /// Shares the actual keyed launch, first/post checks, and child retention.
    /// The optional image is checked against the authored profile before tools.
    pub(super) fn prepare_fresh_generation(
        &mut self,
        profile: &crucible_qemu_host::QemuLiveNodeStepGateConfig,
        node_id: &crucible_engine::NodeId,
        identity: QemuLiveNodeIdentity<'_>,
        qemu_executable: &std::path::Path,
        root_image: Option<&std::path::Path>,
        observation: Option<(
            crucible_qemu_host::ram_control::RamControlRegistration,
            crucible_host_resources::host_supervision::HostOperationSupervisor,
        )>,
        lease: QemuAttemptGenerationLease,
    ) -> Result<PreparedFreshGeneration, LifecycleApiError> {
        if profile.qemu_executable() != qemu_executable || profile.root_image() != root_image {
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
            .prepare_generation_run_directory_for_node(node_id, profile.resource_requirements())
        {
            Ok(run_directory) => run_directory,
            Err(error) => return Err(abort_unspawned_generation(lease, error)),
        };
        let preparation = {
            let process_contract = match self.owner.child_process_contract_for_node(node_id) {
                Ok(contract) => contract,
                Err(error) => return Err(abort_unspawned_generation(lease, error)),
            };
            run_directory.prepare_fresh_artifacts_guarded(
                qemu_executable,
                root_image,
                process_contract,
            )
        };
        if let Err(mut error) = preparation {
            let message = launch_error_chain(&error);
            if let Some(child) = error.take_unreaped_child() {
                self.owner
                    .retain_failed_launch_child_for_node(node_id, child);
                drop(lease);
                self.owner.quarantine();
                return Err(launcher_message(format!(
                    "prepare fresh QEMU node `{}` failed and transferred an unreaped image-tool child to quarantine: {message}",
                    node_id.name,
                )));
            }
            return Err(abort_unspawned_generation(
                lease,
                launcher_message(format!(
                    "prepare fresh QEMU node `{}` failed after synchronous helper cleanup: {message}",
                    node_id.name,
                )),
            ));
        }
        if let Err(error) = self.owner.check_operational_boundary() {
            return Err(abort_unspawned_generation(lease, error));
        }

        let launch = profile.clone().with_run_directory(run_directory.path());
        let launch = match observation {
            Some((registration, original)) => launch
                .with_ram_control_registration(registration)
                .with_host_operation_supervisor(original),
            None => launch,
        };
        let (launched, retained_contract) = {
            let process_contract = match self.owner.child_process_contract_for_node(node_id) {
                Ok(contract) => contract,
                Err(error) => return Err(abort_unspawned_generation(lease, error)),
            };
            let retained_contract = match process_contract.try_clone_for_attempt_generation() {
                Ok(contract) => contract,
                Err(error) => {
                    return Err(abort_unspawned_generation(
                        lease,
                        launcher_message(format!("retain fresh generation contract: {error}")),
                    ));
                }
            };
            let launched = QemuProductionFreshLaunchAdmission::admit(
                &launch,
                &run_directory,
                process_contract,
                identity,
            )
            .and_then(|admission| {
                self.owner
                    .launch_fresh_node_for_node(node_id, &launch, admission)
            });
            (launched, retained_contract)
        };
        let node = match launched {
            Ok(node) => node,
            Err(mut error) => {
                #[cfg(feature = "private-measurement-domain")]
                if let crucible_qemu_host::QemuLiveNodeStepGateError::OriginalNativeLaunch { source } =
                    error
                {
                    // The original slot already owns this exact prepaid Arc,
                    // including any node created before the independent postcut.
                    // No ordinary error formatting or second shared allocation
                    // may replace that first cause or release its native credit.
                    self.owner.quarantine_original_launch();
                    drop(lease);
                    return Err(LifecycleApiError::BackendConstruction {
                        source: crucible_control_api::LifecycleBackendConstructionError::from_shared(
                            source,
                        ),
                    });
                }
                let message = launch_error_chain(&error);
                if let Some(child) = error.take_unreaped_child() {
                    self.owner
                        .retain_failed_launch_child_for_node(node_id, child);
                    drop(lease);
                    self.owner.quarantine();
                    return Err(launcher_message(format!(
                        "launch guarded fresh QEMU node `{}` failed and transferred an unreaped child to quarantine: {message}",
                        node_id.name,
                    )));
                }
                return Err(abort_unspawned_generation(
                    lease,
                    launcher_message(format!(
                        "launch guarded fresh QEMU node `{}` failed after synchronous cleanup: {message}",
                        node_id.name,
                    )),
                ));
            }
        };

        Ok(PreparedFreshGeneration {
            lease,
            directory: run_directory,
            node,
            contract: retained_contract,
        })
    }
}

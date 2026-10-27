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
        if self.retained_launch.is_some() {
            return Err(abort_unspawned_generation(
                lease,
                LifecycleApiError::CleanupRetained,
            ));
        }
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
        // Refuse missing custody before creating directory-owned descriptors.
        let receiver = {
            let process_contract = match self.owner.child_process_contract_for_node(node_id) {
                Ok(contract) => contract,
                Err(error) => return Err(abort_unspawned_generation(lease, error)),
            };
            let receiver = process_contract.issued_helper_receiver();
            match receiver {
                Some(receiver) => receiver,
                None => {
                    return Err(abort_unspawned_generation(
                        lease,
                        launcher_message("fresh preparation has no current issued helper receiver"),
                    ));
                }
            }
        };
        let run_directory = match self
            .owner
            .prepare_generation_run_directory_for_node(node_id, profile.resource_requirements())
        {
            Ok(run_directory) => run_directory,
            Err(error) => return Err(abort_unspawned_generation(lease, error)),
        };
        self.retained_launch = Some(RetainedLaunch::Preparation(RetainedFreshPreparation::new(
            lease,
            run_directory,
            receiver,
        )));

        // Borrow disjoint fields: the Main-contained slot owns both resources
        // before the helper can publish a child, refuse a post or unwind.
        let preparation = {
            let process_contract = self.owner.child_process_contract_for_node(node_id)?;
            let Some(RetainedLaunch::Preparation(preparation)) = self.retained_launch.as_mut()
            else {
                return Err(LifecycleApiError::CleanupRetained);
            };
            preparation
                .directory_mut()?
                .prepare_fresh_artifacts_guarded(qemu_executable, root_image, process_contract)
        };
        if let Err(error) = preparation {
            if let Some(source) = error.retained_receiver() {
                return Err(LifecycleApiError::BackendConstruction {
                    source: crucible_control_api::LifecycleBackendConstructionError::from_operational(
                        source.backend_cause(),
                    ),
                });
            }
            return Err(launcher_message(format!(
                "prepare fresh QEMU node `{}` failed before issued helper birth: {error}",
                node_id.name,
            )));
        }
        self.owner.check_operational_boundary()?;

        let Some(RetainedLaunch::Preparation(preparation)) = self.retained_launch.as_ref() else {
            return Err(LifecycleApiError::CleanupRetained);
        };
        let launch = profile
            .clone()
            .with_run_directory(preparation.directory()?.path());
        let launch = match observation {
            Some((registration, original)) => launch
                .with_ram_control_registration(registration)
                .with_host_operation_supervisor(original),
            None => launch,
        };
        let launched = {
            let process_contract = self.owner.child_process_contract_for_node(node_id)?;
            let retained_contract = process_contract
                .try_clone_for_attempt_generation()
                .map_err(|error| {
                    launcher_message(format!("retain fresh generation contract: {error}"))
                })?;
            let Some(RetainedLaunch::Preparation(preparation)) = self.retained_launch.as_mut()
            else {
                return Err(LifecycleApiError::CleanupRetained);
            };
            preparation.retain_contract(retained_contract)?;
            let (directory, native, node_slot) = preparation.native_inputs()?;
            match QemuProductionFreshLaunchAdmission::admit(
                &launch,
                directory,
                process_contract,
                identity,
            ) {
                Ok(admission) => {
                    // The same Main phase owns every input before native entry;
                    // unwind must not rewind the local generation fence.
                    *native = retained_node::NativeLaunchProgress::Entered;
                    let launched = self
                        .owner
                        .launch_fresh_node_for_node(node_id, &launch, admission);
                    // This records the actual call's return before inspecting
                    // either body or typed failure. Entry alone proves neither.
                    *native = retained_node::NativeLaunchProgress::Returned;
                    match launched {
                        Ok(node) => {
                            // Save the actual body before interpreting success.
                            *node_slot = retained_node::FreshPreparationBody::Node(node);
                            Ok(())
                        }
                        Err(error) => Err(error),
                    }
                }
                Err(error) => Err(error),
            }
        };
        if let Err(mut error) = launched {
            let Some(RetainedLaunch::Preparation(preparation)) = self.retained_launch.as_mut()
            else {
                return Err(LifecycleApiError::BackendConstruction {
                    source: crucible_control_api::LifecycleBackendConstructionError::new(error),
                });
            };
            #[cfg(target_os = "linux")]
            if let crucible_qemu_host::QemuLiveNodeStepGateError::OriginalNativeLaunch { source } =
                error
            {
                // Only the same issued controller can close this phase. A
                // foreign report retains its own body and closes no local debt.
                preparation.record_native_failure(&source);
                self.owner.quarantine_original_launch();
                return Err(LifecycleApiError::BackendConstruction {
                    source: crucible_control_api::LifecycleBackendConstructionError::from_operational(
                        source.backend_cause(),
                    ),
                });
            }
            let has_retained_owner = error.has_retained_owner();
            preparation.mark_unexpected_launch_failure();
            if has_retained_owner {
                return Err(LifecycleApiError::BackendConstruction {
                    source: crucible_control_api::LifecycleBackendConstructionError::new(error),
                });
            }
            let message = launch_error_chain(&error);
            return Err(launcher_message(format!(
                "launch guarded fresh QEMU node `{}` refused: {message}",
                node_id.name,
            )));
        }

        // Native success and its independent post are complete. The validated
        // final cut only moves the same owners; it runs no user code or IO.
        match self.retained_launch.take() {
            Some(RetainedLaunch::Preparation(preparation)) => match preparation.into_prepared() {
                Ok(prepared) => Ok(prepared),
                Err(preparation) => {
                    self.retained_launch = Some(RetainedLaunch::Preparation(preparation));
                    Err(LifecycleApiError::CleanupRetained)
                }
            },
            other => {
                self.retained_launch = other;
                Err(LifecycleApiError::CleanupRetained)
            }
        }
    }
}

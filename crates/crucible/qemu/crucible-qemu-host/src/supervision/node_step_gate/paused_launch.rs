//! Owns the authenticated stopped child before the first guest instruction.
//!
//! Ordinary node construction consumes this same stage to prime the guest and
//! publish its ready owner. The stage retains the actual selected sender and
//! process binding through the child; it creates no replacement launch account.
//! Abandoning it follows the child's real reap or uncertain-retention path.

use super::*;

/// Retains the already-spawned, QMP-authenticated `-S` child and launch owners.
///
/// The boot-barrier quantum is prepared, but QMP has not acknowledged `cont`.
/// Construction is private to the genuine launch body; raw descriptors, a PID
/// or copied resource values cannot create this owner.
pub struct PausedLiveNodeLaunch<'a> {
    // The child closes before its setup, channels and final cleanup alias.
    pub(super) child: crate::QemuNodeChild,
    pub(super) setup: crate::QemuHostPluginSetup,
    pub(super) qmp: crate::QemuQmpVmStateControlChannel<std::os::unix::net::UnixStream>,
    pub(super) runtime: QemuLiveHostIoRuntime,
    pub(super) block_servicer: Option<QemuLiveBlockIoServicer>,
    pub(super) ninep_servicer: Option<QemuLive9pIoServicer>,
    pub(super) accelerator_servicer: Option<QemuLiveAcceleratorServicer>,
    pub(super) prepared_priming: PreparedGuestPrime,
    pub(super) debug_guest_activation_stream: Option<std::os::unix::net::UnixStream>,
    pub(super) console_spool: Option<QemuConsoleObservationSpool>,
    pub(super) ram_controller: Option<crate::ram_control::RamControlClient>,
    pub(super) admitted_registration: Option<crate::ram_control::RamControlRegistration>,
    pub(super) operation_supervisor:
        crucible_host_resources::host_supervision::HostOperationSupervisor,
    #[cfg(target_os = "linux")]
    pub(super) original_native_binding:
        Option<crate::linux_attempt_host::OriginalNativeNodeBinding>,
    #[cfg(target_os = "linux")]
    pub(super) checkpoint_cancellation: std::os::fd::OwnedFd,
    pub(super) config: &'a QemuLiveNodeStepGateConfig,
    pub(super) identity: QemuLiveNodeIdentity<'a>,
    pub(super) restore: Option<QemuNodeRestorePlan<'a>>,
    pub(super) resume_restored: bool,
    pub(super) restoring_checkpoint: bool,
    pub(super) boot_backpressure_payload: Option<&'a [u8]>,
    pub(super) launch_cleanup: Option<crate::launch_cleanup::LaunchCleanup>,
}

impl PausedLiveNodeLaunch<'_> {
    /// Returns the actual child PID for host CPU accounting.
    #[cfg(feature = "private-measurement-domain")]
    #[must_use]
    pub fn process_id(&self) -> u32 {
        self.child.process_id()
    }

    /// Borrows the authenticated QMP channel while all launch owners stay held.
    ///
    /// Fixed measurement callers start their interval before `cont` and use
    /// the existing machine commands. Borrowing grants no process, descriptor
    /// or resource ownership, and does not prime or publish a scheduler node.
    #[cfg(feature = "private-measurement-domain")]
    pub fn qmp_mut(
        &mut self,
    ) -> &mut crate::QemuQmpVmStateControlChannel<std::os::unix::net::UnixStream> {
        &mut self.qmp
    }

    /// Reaps the actual child under its same original Cleanup.
    ///
    /// # Errors
    /// Refuses a different operation owner/class, cancellation or expiry, and
    /// retains an unreaped child and cleanup authority on physical refusal.
    #[cfg(feature = "private-measurement-domain")]
    pub fn shutdown(
        self,
        cleanup: &crucible_host_resources::host_supervision::HostOperationGuard,
    ) -> Result<(), QemuLiveNodeStepGateError> {
        let mut child = self.child;
        let result = (|| {
            cleanup.verify_operation_class(
                crucible_host_resources::host_supervision::HostOperationClass::Cleanup,
            )?;
            if !cleanup.shares_outer_cap(&self.operation_supervisor) {
                return Err(QemuLiveNodeStepGateError::HostSupervision(
                    crucible_host_resources::host_supervision::HostSupervisionError::Unavailable,
                ));
            }
            loop {
                cleanup.wait_slice()?;
                let observed = child.kill_and_poll_reap();
                let original_after = cleanup.wait_slice().err();
                match observed {
                    Ok(true) => {
                        if let Some(after) = original_after {
                            return Err(QemuLiveNodeStepGateError::HostSupervision(after));
                        }
                        return Ok(());
                    }
                    Ok(false) => {
                        if let Some(after) = original_after {
                            return Err(QemuLiveNodeStepGateError::HostSupervision(after));
                        }
                        cleanup.wait_for_change()?;
                    }
                    Err(physical) => {
                        return Err(QemuLiveNodeStepGateError::FailedCleanup {
                            primary: Box::new(match original_after {
                                Some(after) => QemuLiveNodeStepGateError::HostSupervision(after),
                                None => QemuLiveNodeStepGateError::ExactSnapshotInvariant {
                                    reason: String::from("reap stopped live launch"),
                                },
                            }),
                            cleanup: physical,
                            unreaped_child: None,
                        });
                    }
                }
            }
        })();
        result.map_err(|error| {
            if let QemuLiveNodeStepGateError::FailedCleanup {
                primary, cleanup, ..
            } = error
            {
                QemuLiveNodeStepGateError::FailedCleanup {
                    primary,
                    cleanup,
                    unreaped_child: Some(Box::new(child)),
                }
            } else {
                QemuLiveNodeStepGateError::FailedCleanup {
                    primary: Box::new(error),
                    cleanup: crate::QemuShutdownTargetError::new(
                        "retain stopped live launch",
                        "same original Cleanup could not attest child closure",
                    ),
                    unreaped_child: Some(Box::new(child)),
                }
            }
        })
    }

    /// Contains a late refusal using only the same generation's saved Cleanup.
    #[cfg(feature = "private-measurement-domain")]
    pub(crate) fn reap_refused(
        self,
        primary: QemuLiveNodeStepGateError,
        cleanup: Result<
            std::sync::Arc<crucible_host_resources::host_supervision::HostOperationGuard>,
            crate::OriginalActorAccountError,
        >,
    ) -> QemuLiveNodeStepGateError {
        let cleanup = match cleanup {
            Ok(cleanup) => cleanup,
            Err(source) => {
                return QemuLiveNodeStepGateError::FailedCleanup {
                    primary: Box::new(primary),
                    cleanup: crate::QemuShutdownTargetError::new(
                        "retain stopped live launch",
                        source.to_string(),
                    ),
                    unreaped_child: Some(Box::new(self.child)),
                };
            }
        };
        match self.shutdown(&cleanup) {
            Ok(()) => primary,
            Err(QemuLiveNodeStepGateError::FailedCleanup {
                primary: cleanup_refusal,
                cleanup,
                unreaped_child,
            }) => QemuLiveNodeStepGateError::FailedCleanup {
                primary: Box::new(primary),
                cleanup: crate::QemuShutdownTargetError::new(
                    "contain stopped live launch",
                    format!("{cleanup_refusal}; physical cleanup: {cleanup}"),
                ),
                unreaped_child,
            },
            Err(refusal) => QemuLiveNodeStepGateError::FailedCleanup {
                primary: Box::new(primary),
                cleanup: crate::QemuShutdownTargetError::new(
                    "contain stopped live launch",
                    refusal.to_string(),
                ),
                unreaped_child: None,
            },
        }
    }

    /// Starts the admitted guest and completes the existing node bring-up.
    pub(super) fn prime_and_build(self) -> Result<QemuNode, QemuLiveNodeStepGateError> {
        let Self {
            child,
            setup,
            mut qmp,
            mut runtime,
            mut block_servicer,
            mut ninep_servicer,
            accelerator_servicer,
            prepared_priming,
            debug_guest_activation_stream,
            console_spool,
            mut ram_controller,
            admitted_registration,
            operation_supervisor,
            #[cfg(target_os = "linux")]
            original_native_binding,
            #[cfg(target_os = "linux")]
            checkpoint_cancellation,
            config,
            identity,
            restore,
            resume_restored,
            restoring_checkpoint,
            boot_backpressure_payload,
            launch_cleanup,
        } = self;

        macro_rules! launch_try {
            ($result:expr) => {
                match $result {
                    Ok(value) => value,
                    Err(primary) => return Err(reap_failed_live_node_child(child, primary)),
                }
            };
        }

        launch_try!(
            qmp.resume_guest_acknowledged()
                .map_err(|source| QemuLiveNodeStepGateError::QmpStart { source })
        );
        let mut priming = launch_try!(complete_guest_prime(
            &setup,
            &operation_supervisor,
            prepared_priming,
            block_servicer.as_mut(),
            ninep_servicer.as_mut(),
            boot_backpressure_payload,
        ));
        // Ready precedes boot release and the final plugin worker registration.
        // Actual guest priming follows plugin initialization return and worker
        // readiness. The matched native consumer must use this exported basis.
        launch_try!(
            child
                .complete_original_plugin_startup()
                .map_err(QemuLiveNodeStepGateError::HostSupervision)
        );

        if !restoring_checkpoint
            && let Some(capture) = config.boot_network_backpressure_capture.as_ref()
            && capture.capture_icount > 1
        {
            let initial_network = launch_try!(priming.retained_network.take().ok_or_else(|| {
                QemuLiveNodeStepGateError::ExactSnapshotInvariant {
                    reason: String::from(
                        "boot backpressure continuation lost its icount-1 transport state",
                    ),
                }
            }));
            priming = launch_try!(continue_boot_network_backpressure_capture(
                &setup,
                &operation_supervisor,
                identity,
                config.coverage,
                BootNetworkBackpressureContinuation {
                    block: block_servicer.as_mut(),
                    ninep: ninep_servicer.as_mut(),
                    payload: capture.payload.as_slice(),
                    capture_icount: capture.capture_icount,
                    initial_network,
                    emitted_frames: priming.emitted_frames,
                    observable_events: priming.observable_events,
                },
            ));
        }
        runtime = launch_try!(finish_guest_prime_runtime(
            runtime,
            block_servicer,
            ninep_servicer,
            accelerator_servicer,
            config.shmem_block.as_ref().map(|block| block.latency),
            config.completion_timeout,
        ));
        let qmp = if config.whitebox == QemuLaunchPluginSwitch::On {
            let activation_stream = launch_try!(debug_guest_activation_stream.ok_or_else(|| {
                QemuLiveNodeStepGateError::prime(
                    "configure debug guest activation stream",
                    QemuNodeChannelError::new(
                        "configure debug guest activation stream",
                        "white-box launch omitted its activation stream",
                    ),
                )
            }));
            qmp.with_predeclared_debug_guest_endpoint()
                .with_debug_guest_activation_stream(activation_stream)
        } else {
            qmp
        };

        let shmem_config = QemuQuantumShmemConfig::new(node_id(identity.node), GATE_SLOT)
            .with_router(node_id(identity.router), SLOT_NET_ROUTER as u32)
            .with_coverage(basic_block_coverage_config(config.coverage));
        let factory_runtime = QemuNodeFactoryRuntime::new(
            shmem_config,
            GateSendAuthorizer,
            gate_shutdown_policy(),
            gate_async_policy(
                config.completion_timeout,
                config.unbounded_advance_completion,
            ),
            QemuCrashDetector::new(identity.crash_detector),
            runtime,
        );
        #[cfg(target_os = "linux")]
        let factory_runtime = match original_native_binding {
            Some(binding) => factory_runtime.with_original_binding(binding),
            None => factory_runtime,
        };
        let mut node = match restore {
            Some(restore) if resume_restored => build_qemu_node_from_restored_checkpoint(
                child,
                setup,
                qmp,
                restore,
                factory_runtime,
            ),
            Some(restore) => build_qemu_node_from_restored_checkpoint_paused(
                child,
                setup,
                qmp,
                restore,
                factory_runtime,
            ),
            None => build_qemu_node_from_completed_setup(child, setup, qmp, factory_runtime),
        }
        .map_err(|source| QemuLiveNodeStepGateError::NodeFactory { source })?;

        macro_rules! node_try {
            ($result:expr) => {
                match $result {
                    Ok(value) => value,
                    Err(primary) => return Err(reap_failed_live_node(node, primary)),
                }
            };
        }

        if let Some(gdbstub) = &config.gdbstub {
            node = node.with_gdbstub(gdbstub.clone());
        }
        if let Some(console_spool) = console_spool {
            node = node.with_console_observation(node_id(identity.node), console_spool);
        }
        if !restoring_checkpoint {
            node_try!(
                node.retain_priming_network_outputs(priming.emitted_frames)
                    .map_err(|source| {
                        QemuLiveNodeStepGateError::node_op("retain priming network outputs", source)
                    })
            );
        }
        #[cfg(target_os = "linux")]
        node.install_checkpoint_cancellation(checkpoint_cancellation);
        if let Some(network) = &priming.retained_network {
            node_try!(
                node.restore_network_transport_for_gate(network)
                    .map_err(|source| {
                        QemuLiveNodeStepGateError::node_op(
                            "bind retained priming network continuation",
                            source,
                        )
                    })
            );
        }
        let ready_boundary = node_try!(node.synchronize_observed_time().map_err(|source| {
            QemuLiveNodeStepGateError::node_op("synchronize primed icount", source)
        }));
        if !restoring_checkpoint {
            node = node.with_priming_observable_events(priming.observable_events, ready_boundary);
        }
        if let Some(registration) = &admitted_registration {
            node_try!(
                registration
                    .registrar
                    .register(
                        registration.target,
                        registration.initial_policy,
                        registration.resources,
                        operation_supervisor.clone(),
                        ram_controller.take(),
                    )
                    .map_err(|source| QemuLiveNodeStepGateError::ExactSnapshotInvariant {
                        reason: format!("register ready RAM owner: {source}"),
                    })
            );
            if let Some(cleanup) = &launch_cleanup {
                node_try!(cleanup.published().map_err(|source| {
                    QemuLiveNodeStepGateError::ExactSnapshotInvariant {
                        reason: format!("publish RAM cleanup responsibility: {source}"),
                    }
                }));
            }
        }
        Ok(node)
    }
}

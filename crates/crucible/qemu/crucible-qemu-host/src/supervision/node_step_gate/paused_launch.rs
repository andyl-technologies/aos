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
    pub(super) child: crate::node::IssuedLaunchOwner,
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

    /// Retains a late refusal in the same issued Source receiver.
    #[cfg(feature = "private-measurement-domain")]
    pub(crate) fn reap_refused(
        self,
        primary: QemuLiveNodeStepGateError,
    ) -> QemuLiveNodeStepGateError {
        reap_failed_live_node_child(self.child, primary)
    }

    /// Starts the admitted guest and completes the existing node bring-up.
    pub(super) fn prime_and_build(self) -> Result<QemuNode, QemuLiveNodeStepGateError> {
        let Self {
            mut child,
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
                .child_mut()
                .map_err(|first| QemuLiveNodeStepGateError::node_op(
                    "borrow issued startup completion",
                    first
                ))?
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
        match restore {
            Some(restore) if resume_restored => build_qemu_node_from_restored_checkpoint(
                &mut child,
                setup,
                qmp,
                restore,
                factory_runtime,
            ),
            Some(restore) => build_qemu_node_from_restored_checkpoint_paused(
                &mut child,
                setup,
                qmp,
                restore,
                factory_runtime,
            ),
            None => build_qemu_node_from_completed_setup(&mut child, setup, qmp, factory_runtime),
        }
        .map_err(|source| QemuLiveNodeStepGateError::NodeFactory { source })?;
        let node = child.node_mut().map_err(|first| {
            QemuLiveNodeStepGateError::node_op("borrow assembled issued Node", first)
        })?;

        macro_rules! node_try {
            ($result:expr) => {
                match $result {
                    Ok(value) => value,
                    Err(primary) => return Err(reap_failed_live_node_child(child, primary)),
                }
            };
        }

        if let Some(gdbstub) = &config.gdbstub {
            node.set_gdbstub(gdbstub.clone());
        }
        if let Some(console_spool) = console_spool {
            node.set_console_observation(node_id(identity.node), console_spool);
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
            node.set_priming_observable_events(priming.observable_events, ready_boundary);
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
        child.into_node().map_err(
            |_retained| QemuLiveNodeStepGateError::ExactSnapshotInvariant {
                reason: String::from("issued Node was not assembled before handoff"),
            },
        )
    }
}

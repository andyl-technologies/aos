//! Scripted QMP control used by the QEMU node tests.

use super::*;

impl QemuQmpMachineControlChannel for ScriptedQmpMachineControl {
    fn prepare_hot_fork_template_barriers(
        &mut self,
        _block_snapshot_bindings: &[crate::QmpHotForkBlockSnapshotBinding],
    ) -> Result<crate::QmpHotForkTemplateState, QemuNodeChannelError> {
        *self.hot_fork_aborted.lock().unwrap() = false;
        Ok(crate::QmpHotForkTemplateState::one_draining_without_resources(exact_hot_fork_request()))
    }

    fn abort_hot_fork_template(
        &mut self,
    ) -> Result<crate::QmpHotForkTemplateState, QemuNodeChannelError> {
        *self.hot_fork_aborted.lock().unwrap() = true;
        Ok(crate::QmpHotForkTemplateState::one_aborted(
            exact_hot_fork_request(),
        ))
    }

    fn stop_for_checkpoint(&mut self) -> Result<(), QemuNodeChannelError> {
        self.log.lock().unwrap().push(ChannelCall::QmpStop);
        if self.fail_stop {
            return Err(QemuNodeChannelError::new(
                "stop_for_checkpoint",
                "injected QMP stop failure",
            ));
        }
        Ok(())
    }

    fn resume_after_checkpoint(&mut self) -> Result<(), QemuNodeChannelError> {
        self.log.lock().unwrap().push(ChannelCall::QmpContinue);
        Ok(())
    }

    fn query_hot_fork_readiness(
        &mut self,
    ) -> Result<crate::QmpHotForkReadiness, QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpHotForkReadiness);
        crate::QmpHotForkReadiness::from_acknowledged_proofs(7).ok_or_else(|| {
            QemuNodeChannelError::new(
                "query_hot_fork_readiness",
                "scripted readiness bitmap is invalid",
            )
        })
    }

    fn query_hot_fork_thread_inventory(
        &mut self,
    ) -> Result<crate::QmpHotForkThreadInventory, QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpHotForkThreadInventory);
        Ok(crate::QmpHotForkThreadInventory::one_coordinator(
            self.process_id,
        ))
    }

    fn query_hot_fork_rcu_inventory(
        &mut self,
    ) -> Result<crate::QmpHotForkRcuInventory, QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpHotForkRcuInventory);
        Ok(crate::QmpHotForkRcuInventory::from_reader_ids(&[
            self.process_id
        ]))
    }

    fn query_hot_fork_aio_inventory(
        &mut self,
    ) -> Result<crate::QmpHotForkAioInventory, QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpHotForkAioInventory);
        Ok(crate::QmpHotForkAioInventory::one_idle(1, self.process_id))
    }

    fn query_hot_fork_aio_handler_inventory(
        &mut self,
    ) -> Result<crate::QmpHotForkAioHandlerInventory, QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpHotForkAioHandlerInventory);
        Ok(crate::QmpHotForkAioHandlerInventory::one_read(1, 1, 0))
    }

    fn query_hot_fork_block_backend_inventory(
        &mut self,
    ) -> Result<crate::QmpHotForkBlockBackendInventory, QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpHotForkBlockBackendInventory);
        Ok(crate::QmpHotForkBlockBackendInventory::one_hidden(1, 1))
    }

    fn query_hot_fork_plugin_resource_inventory(
        &mut self,
    ) -> Result<crate::QmpHotForkPluginResourceInventory, QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpHotForkPluginResourceInventory);
        self.plugin_resources.clone().ok_or_else(|| {
            QemuNodeChannelError::new(
                "query_hot_fork_plugin_resource_inventory",
                "scripted plugin-resource inventory is unavailable",
            )
        })
    }

    fn query_hot_fork_plugin_barrier(
        &mut self,
    ) -> Result<crate::QmpHotForkPluginBarrierState, QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpHotForkPluginBarrier);
        let barrier = self
            .plugin_barriers
            .as_ref()
            .ok_or_else(|| {
                QemuNodeChannelError::new(
                    "query_hot_fork_plugin_barrier",
                    "scripted plugin barrier is unavailable",
                )
            })?
            .lock()
            .unwrap()
            .pop_front()
            .ok_or_else(|| {
                QemuNodeChannelError::new(
                    "query_hot_fork_plugin_barrier",
                    "scripted plugin barrier sequence is exhausted",
                )
            })?;
        *self.last_plugin_barrier.lock().unwrap() = Some(barrier);
        Ok(barrier)
    }

    fn install_hot_fork_private_ring_descriptor(
        &mut self,
        name: &crate::QmpDescriptorName,
        _descriptor: std::os::fd::BorrowedFd<'_>,
        identity: crucible_shmem::SetupRegionBackingIdentity,
    ) -> Result<(), QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpHotForkInstallDescriptor(
                name.as_str().to_owned(),
                identity,
            ));
        if self.fail_descriptor_install {
            return Err(QemuNodeChannelError::new(
                "install hot-fork private ring descriptor",
                "injected descriptor transfer failure",
            ));
        }
        *self.private_ring_state.lock().unwrap() = Some((name.clone(), identity, 1));
        Ok(())
    }

    fn close_hot_fork_private_ring_descriptor(
        &mut self,
        name: &crate::QmpDescriptorName,
        identity: crucible_shmem::SetupRegionBackingIdentity,
    ) -> Result<(), QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpHotForkCloseDescriptor(
                name.as_str().to_owned(),
                identity,
            ));
        if self.fail_descriptor_close {
            return Err(QemuNodeChannelError::new(
                "close hot-fork private ring descriptor",
                "injected descriptor close failure",
            ));
        }
        *self.private_ring_state.lock().unwrap() = None;
        Ok(())
    }

    fn query_hot_fork_private_rings(
        &mut self,
    ) -> Result<crate::QmpHotForkPrivateRingState, QemuNodeChannelError> {
        let state = self.private_ring_state.lock().unwrap();
        let (name, identity, generation) = state.as_ref().ok_or_else(|| {
            QemuNodeChannelError::new(
                "query hot-fork private rings",
                "scripted private-ring stage is absent",
            )
        })?;
        Ok(crate::QmpHotForkPrivateRingState::one_template_staged(
            *generation,
            1,
            name.clone(),
            identity.device(),
            identity.inode(),
            identity.length(),
        ))
    }

    fn install_hot_fork_plugin_endpoints(
        &mut self,
        control_name: &crate::QmpDescriptorName,
        _control: std::os::fd::BorrowedFd<'_>,
        wake_name: &crate::QmpDescriptorName,
        _wake: std::os::fd::BorrowedFd<'_>,
        identity: crate::QmpHotForkPluginEndpointIdentity,
        private_ring_generation: u64,
    ) -> Result<crate::QmpHotForkPluginEndpointState, QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpHotForkInstallPluginEndpoints {
                control_name: control_name.as_str().to_owned(),
                wake_name: wake_name.as_str().to_owned(),
                identity,
                private_ring_generation,
            });
        if self.fail_endpoint_install {
            return Err(QemuNodeChannelError::new(
                "install hot-fork plugin endpoints",
                "injected endpoint transfer failure",
            ));
        }
        let plugin_barrier = self.last_plugin_barrier.lock().unwrap().ok_or_else(|| {
            QemuNodeChannelError::new(
                "install hot-fork plugin endpoints",
                "scripted plugin barrier was not queried before endpoint staging",
            )
        })?;
        let endpoint_barrier = if self.mismatch_endpoint_disposition {
            crate::QmpHotForkPluginBarrierState::one_quiescent(
                plugin_barrier.generation() + 1,
                plugin_barrier.ring_count(),
            )
        } else {
            plugin_barrier
        };
        let mut diagnostics = self.diagnostic_state.lock().unwrap();
        let Some((_name, _socket_cookie, _template_generation, bound)) = diagnostics.as_mut()
        else {
            return Err(QemuNodeChannelError::new(
                "install hot-fork plugin endpoints",
                "scripted diagnostics stage is absent",
            ));
        };
        *bound = true;
        let mut child_qmp = self.child_qmp_state.lock().unwrap();
        let Some((_name, _socket_cookie, _template_generation, bound)) = child_qmp.as_mut() else {
            return Err(QemuNodeChannelError::new(
                "install hot-fork plugin endpoints",
                "scripted child QMP stage is absent",
            ));
        };
        *bound = true;
        let mut child_console = self.child_console_state.lock().unwrap();
        let Some((_name, _socket_cookie, _template_generation, bound)) = child_console.as_mut()
        else {
            return Err(QemuNodeChannelError::new(
                "install hot-fork plugin endpoints",
                "scripted child console stage is absent",
            ));
        };
        *bound = true;
        Ok(crate::QmpHotForkPluginEndpointState::one_template_staged(
            1,
            1,
            control_name.clone(),
            wake_name.clone(),
            identity,
            private_ring_generation,
            endpoint_barrier,
        ))
    }

    fn close_hot_fork_plugin_endpoints(
        &mut self,
        control_name: &crate::QmpDescriptorName,
        wake_name: &crate::QmpDescriptorName,
        identity: crate::QmpHotForkPluginEndpointIdentity,
    ) -> Result<(), QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpHotForkClosePluginEndpoints {
                control_name: control_name.as_str().to_owned(),
                wake_name: wake_name.as_str().to_owned(),
                identity,
            });
        if self.fail_descriptor_close {
            return Err(QemuNodeChannelError::new(
                "close hot-fork plugin endpoints",
                "injected endpoint close failure",
            ));
        }
        if let Some((_name, _socket_cookie, _template_generation, bound)) =
            self.diagnostic_state.lock().unwrap().as_mut()
        {
            *bound = false;
        }
        if let Some((_name, _socket_cookie, _template_generation, bound)) =
            self.child_qmp_state.lock().unwrap().as_mut()
        {
            *bound = false;
        }
        if let Some((_name, _socket_cookie, _template_generation, bound)) =
            self.child_console_state.lock().unwrap().as_mut()
        {
            *bound = false;
        }
        Ok(())
    }

    fn install_hot_fork_child_diagnostics(
        &mut self,
        name: &crate::QmpDescriptorName,
        descriptor: std::os::fd::BorrowedFd<'_>,
        socket_cookie: u64,
        template_generation: u64,
    ) -> Result<crate::QmpHotForkChildDiagnosticState, QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpHotForkInstallDiagnostics {
                name: name.as_str().to_owned(),
                socket_cookie,
                template_generation,
            });
        if self.fail_descriptor_install {
            return Err(QemuNodeChannelError::new(
                "install hot-fork child diagnostics",
                "injected descriptor transfer failure",
            ));
        }
        let mut diagnostic_writer = std::os::unix::net::UnixStream::from(
            descriptor.try_clone_to_owned().map_err(|source| {
                QemuNodeChannelError::new(
                    "install hot-fork child diagnostics",
                    format!("clone scripted child diagnostics endpoint failed: {source}"),
                )
            })?,
        );
        diagnostic_writer
            .write_all(b"scripted child diagnostics")
            .map_err(|source| {
                QemuNodeChannelError::new(
                    "install hot-fork child diagnostics",
                    format!("write scripted child diagnostics failed: {source}"),
                )
            })?;
        let state = crate::QmpHotForkChildDiagnosticState::one_template_staged(
            1,
            template_generation,
            name.clone(),
            socket_cookie,
            32,
            false,
        );
        *self.diagnostic_state.lock().unwrap() =
            Some((name.clone(), socket_cookie, template_generation, false));
        Ok(state)
    }

    fn close_hot_fork_child_diagnostics(
        &mut self,
        name: &crate::QmpDescriptorName,
        socket_cookie: u64,
    ) -> Result<(), QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpHotForkCloseDiagnostics {
                name: name.as_str().to_owned(),
                socket_cookie,
            });
        if self.fail_descriptor_close {
            return Err(QemuNodeChannelError::new(
                "close hot-fork child diagnostics",
                "injected descriptor close failure",
            ));
        }
        *self.diagnostic_state.lock().unwrap() = None;
        Ok(())
    }

    fn query_hot_fork_child_diagnostics(
        &mut self,
    ) -> Result<crate::QmpHotForkChildDiagnosticState, QemuNodeChannelError> {
        let state = self.diagnostic_state.lock().unwrap();
        let (name, socket_cookie, template_generation, bound) =
            state.as_ref().ok_or_else(|| {
                QemuNodeChannelError::new(
                    "query hot-fork child diagnostics",
                    "scripted diagnostics stage is absent",
                )
            })?;
        Ok(crate::QmpHotForkChildDiagnosticState::one_template_staged(
            1,
            *template_generation,
            name.clone(),
            *socket_cookie,
            32,
            *bound,
        ))
    }

    fn install_hot_fork_child_qmp(
        &mut self,
        name: &crate::QmpDescriptorName,
        descriptor: std::os::fd::BorrowedFd<'_>,
        socket_cookie: u64,
        template_generation: u64,
    ) -> Result<crate::QmpHotForkChildQmpState, QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpHotForkInstallChildQmp {
                name: name.as_str().to_owned(),
                socket_cookie,
                template_generation,
            });
        if self.fail_descriptor_install {
            return Err(QemuNodeChannelError::new(
                "install hot-fork child QMP",
                "injected descriptor transfer failure",
            ));
        }
        let state = crate::QmpHotForkChildQmpState::one_template_staged(
            1,
            template_generation,
            7,
            name.clone(),
            socket_cookie,
            33,
            false,
            true,
        );
        *self.child_qmp_state.lock().unwrap() =
            Some((name.clone(), socket_cookie, template_generation, false));
        if self.serve_child_qmp {
            serve_scripted_hot_fork_child_qmp(
                descriptor,
                name,
                socket_cookie,
                template_generation,
            )?;
        }
        Ok(state)
    }

    fn close_hot_fork_child_qmp(
        &mut self,
        name: &crate::QmpDescriptorName,
        socket_cookie: u64,
    ) -> Result<(), QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpHotForkCloseChildQmp {
                name: name.as_str().to_owned(),
                socket_cookie,
            });
        if self.fail_descriptor_close {
            return Err(QemuNodeChannelError::new(
                "close hot-fork child QMP",
                "injected descriptor close failure",
            ));
        }
        *self.child_qmp_state.lock().unwrap() = None;
        Ok(())
    }

    fn query_hot_fork_child_qmp(
        &mut self,
    ) -> Result<crate::QmpHotForkChildQmpState, QemuNodeChannelError> {
        let state = self.child_qmp_state.lock().unwrap();
        let (name, socket_cookie, template_generation, bound) =
            state.as_ref().ok_or_else(|| {
                QemuNodeChannelError::new(
                    "query hot-fork child QMP",
                    "scripted child QMP stage is absent",
                )
            })?;
        Ok(crate::QmpHotForkChildQmpState::one_template_staged(
            1,
            *template_generation,
            7,
            name.clone(),
            *socket_cookie,
            33,
            *bound,
            true,
        ))
    }

    fn install_hot_fork_child_console(
        &mut self,
        name: &crate::QmpDescriptorName,
        _descriptor: std::os::fd::BorrowedFd<'_>,
        socket_cookie: u64,
        template_generation: u64,
    ) -> Result<crate::QmpHotForkChildConsoleState, QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpHotForkInstallChildConsole {
                name: name.as_str().to_owned(),
                socket_cookie,
                template_generation,
            });
        if self.fail_descriptor_install {
            return Err(QemuNodeChannelError::new(
                "install hot-fork child console",
                "injected descriptor transfer failure",
            ));
        }
        let state = crate::QmpHotForkChildConsoleState::one_template_staged(
            1,
            template_generation,
            name.clone(),
            socket_cookie,
            34,
            false,
        );
        *self.child_console_state.lock().unwrap() =
            Some((name.clone(), socket_cookie, template_generation, false));
        Ok(state)
    }

    fn close_hot_fork_child_console(
        &mut self,
        name: &crate::QmpDescriptorName,
        socket_cookie: u64,
    ) -> Result<(), QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpHotForkCloseChildConsole {
                name: name.as_str().to_owned(),
                socket_cookie,
            });
        if self.fail_descriptor_close {
            return Err(QemuNodeChannelError::new(
                "close hot-fork child console",
                "injected descriptor close failure",
            ));
        }
        if self.child_qmp_state.lock().unwrap().is_none() {
            return Err(QemuNodeChannelError::new(
                "close hot-fork child console",
                "scripted predecessor child QMP stage was already released",
            ));
        }
        *self.child_console_state.lock().unwrap() = None;
        Ok(())
    }

    fn query_hot_fork_child_console(
        &mut self,
    ) -> Result<crate::QmpHotForkChildConsoleState, QemuNodeChannelError> {
        let state = self.child_console_state.lock().unwrap();
        let (name, socket_cookie, template_generation, bound) =
            state.as_ref().ok_or_else(|| {
                QemuNodeChannelError::new(
                    "query hot-fork child console",
                    "scripted child console stage is absent",
                )
            })?;
        Ok(crate::QmpHotForkChildConsoleState::one_template_staged(
            1,
            *template_generation,
            name.clone(),
            *socket_cookie,
            34,
            *bound,
        ))
    }

    fn query_hot_fork_template(
        &mut self,
    ) -> Result<crate::QmpHotForkTemplateState, QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpHotForkTemplate);
        let mut template_query_count = self.template_query_count.lock().unwrap();
        *template_query_count += 1;
        let request = if self
            .request_basis_mismatch_after_queries
            .is_some_and(|threshold| *template_query_count > threshold)
        {
            crate::QmpHotForkRequest::for_test(1, 2, 1, 1, 1, 7, 1, 15, 8, 9, 10, 11, 12, 13, 0)
        } else {
            exact_hot_fork_request()
        };
        let resources_are_sealed = self
            .child_console_state
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|(_name, _cookie, _generation, bound)| *bound);
        Ok(if *self.hot_fork_aborted.lock().unwrap() {
            crate::QmpHotForkTemplateState::one_aborted(request)
        } else if resources_are_sealed {
            crate::QmpHotForkTemplateState::one_prepared(request)
        } else {
            crate::QmpHotForkTemplateState::one_draining_without_resources(request)
        })
    }

    fn query_hot_fork_child_process_contract(
        &mut self,
    ) -> Result<crate::QmpHotForkChildProcessContractState, QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpHotForkChildProcessContract);
        if let Some((names, identity, generation, template_generation)) =
            self.process_contract_state.lock().unwrap().as_ref()
        {
            return Ok(
                crate::QmpHotForkChildProcessContractState::one_template_staged(
                    *generation,
                    *template_generation,
                    names,
                    *identity,
                ),
            );
        }
        let identity = crate::QmpHotForkChildProcessContractIdentity::new(1, 2, 9, 3, 4)
            .map_err(QemuNodeChannelError::from)?;
        Ok(
            crate::QmpHotForkChildProcessContractState::one_template_staged(
                13,
                1,
                &test_hot_fork_contract_names()?,
                identity,
            ),
        )
    }

    fn install_hot_fork_child_process_contract(
        &mut self,
        names: &crate::QmpHotForkChildProcessContractNames,
        _cgroup: std::os::fd::BorrowedFd<'_>,
        _cgroup_procs: std::os::fd::BorrowedFd<'_>,
        _cancellation: std::os::fd::BorrowedFd<'_>,
        identity: crate::QmpHotForkChildProcessContractIdentity,
        template_generation: u64,
    ) -> Result<crate::QmpHotForkChildProcessContractState, QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpHotForkInstallProcessContract);
        let generation = 13;
        *self.process_contract_state.lock().unwrap() =
            Some((names.clone(), identity, generation, template_generation));
        Ok(
            crate::QmpHotForkChildProcessContractState::one_template_staged(
                generation,
                template_generation,
                names,
                identity,
            ),
        )
    }

    fn release_hot_fork_child_process_contract(
        &mut self,
        names: &crate::QmpHotForkChildProcessContractNames,
        identity: crate::QmpHotForkChildProcessContractIdentity,
    ) -> Result<crate::QmpHotForkChildProcessContractState, QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpHotForkReleaseProcessContract);
        let retained = self.process_contract_state.lock().unwrap().take();
        let Some((retained_names, retained_identity, generation, _)) = retained else {
            return Err(QemuNodeChannelError::new(
                "release hot-fork child process contract",
                "scripted process contract is absent",
            ));
        };
        if retained_names != *names || retained_identity != identity {
            return Err(QemuNodeChannelError::new(
                "release hot-fork child process contract",
                "scripted process contract basis changed",
            ));
        }
        Ok(crate::QmpHotForkChildProcessContractState::one_released(
            generation,
        ))
    }

    fn query_hot_fork_child_files(
        &mut self,
    ) -> Result<crate::QmpHotForkChildFilesState, QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpHotForkChildFiles);
        if let Some((files, maximum_bytes, generation, template_generation)) =
            self.child_files_state.lock().unwrap().as_ref()
        {
            return Ok(crate::QmpHotForkChildFilesState::one_template_staged(
                *generation,
                *template_generation,
                *maximum_bytes,
                files.clone(),
            ));
        }
        Ok(crate::QmpHotForkChildFilesState::one_released(0))
    }

    fn install_hot_fork_child_files(
        &mut self,
        files: &[crate::QmpHotForkChildFile],
        descriptors: &[std::os::fd::BorrowedFd<'_>],
        maximum_bytes: u64,
        template_generation: u64,
    ) -> Result<crate::QmpHotForkChildFilesState, QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpHotForkInstallChildFiles);
        if files.len() != descriptors.len() {
            return Err(QemuNodeChannelError::new(
                "install hot-fork child files",
                "scripted child file plan received mismatched descriptors",
            ));
        }
        let generation = 17;
        *self.child_files_state.lock().unwrap() = Some((
            files.to_vec(),
            maximum_bytes,
            generation,
            template_generation,
        ));
        Ok(crate::QmpHotForkChildFilesState::one_template_staged(
            generation,
            template_generation,
            maximum_bytes,
            files.to_vec(),
        ))
    }

    fn release_hot_fork_child_files(
        &mut self,
        generation: u64,
    ) -> Result<crate::QmpHotForkChildFilesState, QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpHotForkReleaseChildFiles);
        let retained = self.child_files_state.lock().unwrap().take();
        let Some((_files, _maximum_bytes, retained_generation, _template)) = retained else {
            return Err(QemuNodeChannelError::new(
                "release hot-fork child files",
                "scripted child file plan is absent",
            ));
        };
        if retained_generation != generation {
            return Err(QemuNodeChannelError::new(
                "release hot-fork child files",
                "scripted child file plan generation changed",
            ));
        }
        Ok(crate::QmpHotForkChildFilesState::one_released(generation))
    }

    fn hot_fork(
        &mut self,
        request: crate::QmpHotForkRequest,
    ) -> Result<crate::QmpHotForkState, crate::QemuHotForkCommandError> {
        self.log.lock().unwrap().push(ChannelCall::QmpHotFork);
        match self.hot_fork_script {
            HotForkScript::Forked => Ok(crate::QmpHotForkState::for_test(
                request,
                crate::QmpHotForkOutcome::Forked,
                321,
            )),
            HotForkScript::Rejected => Err(crate::QemuHotForkCommandError::Rejected {
                source: QemuNodeChannelError::new(
                    "fork retained hot-fork template",
                    "injected pre-fork rejection",
                ),
            }),
            HotForkScript::ParentDispositionFailed => Ok(crate::QmpHotForkState::for_test(
                request,
                crate::QmpHotForkOutcome::ParentDispositionFailed,
                321,
            )),
        }
    }

    fn query_hot_fork_bottom_half_inventory(
        &mut self,
    ) -> Result<crate::QmpHotForkBottomHalfInventory, QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpHotForkBottomHalfInventory);
        Ok(crate::QmpHotForkBottomHalfInventory::one_idle(1, 1))
    }

    fn query_hot_fork_mutex_inventory(
        &mut self,
    ) -> Result<crate::QmpHotForkMutexInventory, QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpHotForkMutexInventory);
        Ok(crate::QmpHotForkMutexInventory::one_owned(
            1,
            self.process_id,
        ))
    }

    fn query_hot_fork_timer_inventory(
        &mut self,
    ) -> Result<crate::QmpHotForkTimerInventory, QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpHotForkTimerInventory);
        Ok(crate::QmpHotForkTimerInventory::empty())
    }

    fn query_hot_fork_monitor_inventory(
        &mut self,
    ) -> Result<crate::QmpHotForkMonitorInventory, QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpHotForkMonitorInventory);
        Ok(crate::QmpHotForkMonitorInventory::one_supported())
    }

    fn complete_terminal_lifecycle_exit(
        &mut self,
        action: ContentHash,
        evidence: ContentHash,
        process_generation: u64,
    ) -> Result<(), QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpTerminalLifecycle {
                action,
                evidence,
                process_generation,
            });
        Ok(())
    }

    fn save_checkpoint_vmstate(
        &mut self,
        checkpoint: &Checkpoint,
    ) -> Result<(), QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpExactSave(checkpoint.id));
        if self.timeout_snapshot {
            return Err(QemuNodeChannelError::bounded_await_timeout(
                "save_checkpoint_vmstate",
                "QMP command timed out",
                Duration::from_millis(2),
            ));
        }
        if self.fail_snapshot {
            return Err(QemuNodeChannelError::new(
                "save_checkpoint_vmstate",
                "QMP error",
            ));
        }
        Ok(())
    }

    fn delete_checkpoint_vmstate(
        &mut self,
        checkpoint: &Checkpoint,
    ) -> Result<(), QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpExactDelete(checkpoint.id));
        Ok(())
    }

    fn quit(&mut self) -> Result<(), QemuNodeChannelError> {
        self.log.lock().unwrap().push(ChannelCall::QmpQuit);
        Ok(())
    }

    fn retire_process_scoped_endpoints_after_reap(&mut self) {
        if self.track_process_endpoint_retirement {
            self.log
                .lock()
                .unwrap()
                .push(ChannelCall::QmpRetireProcessScopedEndpoints);
        }
    }

    fn activate_debug_guest(&mut self) -> Result<(), QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpActivateDebugGuest);
        Ok(())
    }
}

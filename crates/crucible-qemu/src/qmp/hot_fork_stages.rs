//! Child resource staging surface of the typed QMP client.
//!
//! Each branch-private child resource (private rings, plugin endpoints,
//! the diagnostics stream, the child QMP endpoint, the child console, the
//! child process contract, and the child-file plan) is staged against the
//! retained template, queried, and released through the same three-verb
//! surface; QEMU consumes a staged resource only inside the fork.
use super::*;

impl<S> QmpClient<S>
where
    S: QmpTimeoutStream,
{
    /// Makes QEMU retain an independently duplicated private-ring descriptor.
    ///
    /// The descriptor must already have been imported under `name` through
    /// [`Self::install_descriptor`]. QEMU authenticates the duplicate against
    /// the exact backing identity and requires `F_SEAL_SHRINK`. This stage does
    /// not complete the eventual child disposition or acknowledge either
    /// corresponding hot-fork readiness proof.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the exchange fails, QEMU rejects the exact
    /// descriptor basis, or its response violates the closed stage contract.
    /// Every error poisons the client because retained descriptor ownership may
    /// then be ambiguous.
    pub fn stage_hot_fork_private_rings(
        &mut self,
        name: &QmpDescriptorName,
        identity: SetupRegionBackingIdentity,
    ) -> Result<QmpHotForkPrivateRingState, QmpError> {
        let result = self
            .send_command_return(QmpCommand::HotForkPrivateRings {
                action: HotForkPrivateRingAction::Stage,
                name: Some(name),
                identity: Some(identity),
            })
            .and_then(|response| parse_hot_fork_private_ring_state(&response.value))
            .and_then(|state| {
                let exact_basis = state.staged()
                    && state.descriptor_name() == Some(name)
                    && state.device() == identity.device()
                    && state.inode() == identity.inode()
                    && state.length() == identity.length()
                    && state.shrink_sealed();
                if exact_basis {
                    Ok(state)
                } else {
                    Err(QmpError::MalformedTypedResponse {
                        command: QmpCommandKind::HotForkPrivateRings,
                        response: format!(
                            "private-ring stage did not retain {name:?}/{identity:?}"
                        ),
                    })
                }
            });
        self.poison_after_descriptor_mutation_error(result)
    }

    /// Reads QEMU's exact retained private-ring descriptor state.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the query fails or QEMU returns a state outside
    /// the closed version-3 contract.
    pub fn query_hot_fork_private_rings(&mut self) -> Result<QmpHotForkPrivateRingState, QmpError> {
        let response = self.send_command_return(QmpCommand::HotForkPrivateRings {
            action: HotForkPrivateRingAction::Query,
            name: None,
            identity: None,
        })?;
        parse_hot_fork_private_ring_state(&response.value)
    }

    /// Releases QEMU's exact independently retained private-ring descriptor.
    ///
    /// This does not close the standard monitor-owned `getfd` name; callers
    /// release that second ownership layer with [`Self::close_descriptor`] only
    /// after this command confirms the QEMU-owned duplicate is absent.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the exchange fails, QEMU rejects the exact
    /// descriptor basis, or the response still reports a staged descriptor.
    /// Every error poisons the client because retained descriptor ownership may
    /// then be ambiguous.
    pub fn release_hot_fork_private_rings(
        &mut self,
        name: &QmpDescriptorName,
        identity: SetupRegionBackingIdentity,
    ) -> Result<QmpHotForkPrivateRingState, QmpError> {
        let result = self
            .send_command_return(QmpCommand::HotForkPrivateRings {
                action: HotForkPrivateRingAction::Release,
                name: Some(name),
                identity: Some(identity),
            })
            .and_then(|response| parse_hot_fork_private_ring_state(&response.value))
            .and_then(|state| {
                if state.staged() || state.generation() == 0 {
                    Err(QmpError::MalformedTypedResponse {
                        command: QmpCommandKind::HotForkPrivateRings,
                        response: String::from(
                            "private-ring release did not report a positive absent generation",
                        ),
                    })
                } else {
                    Ok(state)
                }
            });
        self.poison_after_descriptor_mutation_error(result)
    }

    /// Makes QEMU retain independently duplicated plugin control/wake endpoints.
    ///
    /// Both descriptors must already have been imported through
    /// [`Self::install_descriptor`]. QEMU authenticates the control socket by
    /// Linux `SO_COOKIE`, the wake eventfd by `/proc/self/fdinfo`, and requires
    /// both fresh endpoints to be empty. This does not install either endpoint
    /// in a fork child or acknowledge a hot-fork readiness proof.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the exchange fails, QEMU rejects the exact
    /// endpoint basis, or its response violates the closed stage contract.
    /// Every error poisons the client because retained ownership may be
    /// ambiguous.
    pub fn stage_hot_fork_plugin_endpoints(
        &mut self,
        control_name: &QmpDescriptorName,
        wake_name: &QmpDescriptorName,
        identity: QmpHotForkPluginEndpointIdentity,
        private_ring_generation: u64,
    ) -> Result<QmpHotForkPluginEndpointState, QmpError> {
        let result = self
            .send_command_return(QmpCommand::HotForkPluginEndpoints {
                action: HotForkPluginEndpointAction::Stage,
                control_name: Some(control_name),
                wake_name: Some(wake_name),
                identity: Some(identity),
            })
            .and_then(|response| parse_hot_fork_plugin_endpoint_state(&response.value))
            .and_then(|state| {
                let exact_basis = state.staged()
                    && state.control_name() == Some(control_name)
                    && state.wake_name() == Some(wake_name)
                    && state.identity() == Some(identity)
                    && state.private_ring_generation() == private_ring_generation;
                if exact_basis {
                    Ok(state)
                } else {
                    Err(QmpError::MalformedTypedResponse {
                        command: QmpCommandKind::HotForkPluginEndpoints,
                        response: format!(
                            "plugin endpoint stage did not retain {control_name:?}/{wake_name:?}/{identity:?}"
                        ),
                    })
                }
            });
        self.poison_after_descriptor_mutation_error(result)
    }

    /// Reads QEMU's exact retained branch-private plugin endpoint state.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the query fails or QEMU returns a state outside
    /// the closed version-1 contract.
    pub fn query_hot_fork_plugin_endpoints(
        &mut self,
    ) -> Result<QmpHotForkPluginEndpointState, QmpError> {
        let response = self.send_command_return(QmpCommand::HotForkPluginEndpoints {
            action: HotForkPluginEndpointAction::Query,
            control_name: None,
            wake_name: None,
            identity: None,
        })?;
        parse_hot_fork_plugin_endpoint_state(&response.value)
    }

    /// Releases QEMU's exact independently retained plugin endpoint pair.
    ///
    /// Standard monitor-owned `getfd` names remain until callers close them
    /// after this command confirms both QEMU-owned duplicates are absent.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the exchange fails, QEMU rejects the exact
    /// endpoint basis, or the response still reports staged endpoints. Every
    /// error poisons the client because retained ownership may be ambiguous.
    pub fn release_hot_fork_plugin_endpoints(
        &mut self,
        control_name: &QmpDescriptorName,
        wake_name: &QmpDescriptorName,
        identity: QmpHotForkPluginEndpointIdentity,
    ) -> Result<QmpHotForkPluginEndpointState, QmpError> {
        let result = self
            .send_command_return(QmpCommand::HotForkPluginEndpoints {
                action: HotForkPluginEndpointAction::Release,
                control_name: Some(control_name),
                wake_name: Some(wake_name),
                identity: Some(identity),
            })
            .and_then(|response| parse_hot_fork_plugin_endpoint_state(&response.value))
            .and_then(|state| {
                if state.staged() || state.generation() == 0 {
                    Err(QmpError::MalformedTypedResponse {
                        command: QmpCommandKind::HotForkPluginEndpoints,
                        response: String::from(
                            "plugin endpoint release did not report a positive absent generation",
                        ),
                    })
                } else {
                    Ok(state)
                }
            });
        self.poison_after_descriptor_mutation_error(result)
    }

    /// Makes QEMU retain one branch-private child diagnostics stream.
    ///
    /// The stream must already be imported with [`Self::install_descriptor`].
    /// QEMU authenticates its Linux `SO_COOKIE`, requires a connected empty
    /// AF_UNIX stream, and makes the retained description nonblocking. The
    /// template-bound contribution replaces only the fork child's inherited
    /// stderr slot after complete resource-plan composition.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the exchange fails, QEMU rejects the exact
    /// stream or template basis, or its response violates the closed schema.
    /// Every error poisons the client because retained ownership may then be
    /// ambiguous.
    pub fn stage_hot_fork_child_diagnostics(
        &mut self,
        name: &QmpDescriptorName,
        socket_cookie: u64,
        template_generation: u64,
    ) -> Result<QmpHotForkChildDiagnosticState, QmpError> {
        let result = self
            .send_command_return(QmpCommand::HotForkChildDiagnostics {
                action: HotForkChildDiagnosticAction::Stage,
                name: Some(name),
                socket_cookie: Some(socket_cookie),
            })
            .and_then(|response| parse_hot_fork_child_diagnostic_state(&response.value))
            .and_then(|state| {
                let exact_basis = state.staged()
                    && state.descriptor_name() == Some(name)
                    && state.socket_cookie() == Some(socket_cookie)
                    && state.template_generation() == template_generation
                    && state.target_descriptor()
                        == Some(QMP_HOT_FORK_CHILD_DIAGNOSTICS_TARGET_FD)
                    && !state.replacement_plan_bound();
                if exact_basis {
                    Ok(state)
                } else {
                    Err(QmpError::MalformedTypedResponse {
                        command: QmpCommandKind::HotForkChildDiagnostics,
                        response: format!(
                            "child diagnostics stage did not retain {name:?}/{socket_cookie}/{template_generation}"
                        ),
                    })
                }
            });
        self.poison_after_descriptor_mutation_error(result)
    }

    /// Reads QEMU's exact retained branch-private child diagnostics state.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the query fails or the response violates the
    /// closed version-1 contract.
    pub fn query_hot_fork_child_diagnostics(
        &mut self,
    ) -> Result<QmpHotForkChildDiagnosticState, QmpError> {
        let response = self.send_command_return(QmpCommand::HotForkChildDiagnostics {
            action: HotForkChildDiagnosticAction::Query,
            name: None,
            socket_cookie: None,
        })?;
        parse_hot_fork_child_diagnostic_state(&response.value)
    }

    /// Releases QEMU's exact independently retained diagnostics stream.
    ///
    /// The standard monitor-owned descriptor name remains until the caller
    /// closes it after this command confirms the QEMU-owned duplicate is gone.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the exchange fails, the exact basis no longer
    /// matches, or the response still reports a retained stream. Every error
    /// poisons the client because descriptor ownership may be ambiguous.
    pub fn release_hot_fork_child_diagnostics(
        &mut self,
        name: &QmpDescriptorName,
        socket_cookie: u64,
    ) -> Result<QmpHotForkChildDiagnosticState, QmpError> {
        let result = self
            .send_command_return(QmpCommand::HotForkChildDiagnostics {
                action: HotForkChildDiagnosticAction::Release,
                name: Some(name),
                socket_cookie: Some(socket_cookie),
            })
            .and_then(|response| parse_hot_fork_child_diagnostic_state(&response.value))
            .and_then(|state| {
                if state.staged() || state.generation() == 0 {
                    Err(QmpError::MalformedTypedResponse {
                        command: QmpCommandKind::HotForkChildDiagnostics,
                        response: String::from(
                            "child diagnostics release did not report a positive absent generation",
                        ),
                    })
                } else {
                    Ok(state)
                }
            });
        self.poison_after_descriptor_mutation_error(result)
    }

    /// Makes QEMU retain one branch-private child QMP stream.
    ///
    /// The stream must already be imported with [`Self::install_descriptor`].
    /// QEMU authenticates its Linux `SO_COOKIE`, requires a connected empty
    /// AF_UNIX stream, and makes the retained description nonblocking. The
    /// template-bound contribution retains the descriptor through child
    /// closure but does not attach it to a monitor.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the exchange fails, QEMU rejects the exact
    /// stream or template basis, or its response violates the closed schema.
    /// Every error poisons the client because retained ownership may then be
    /// ambiguous.
    pub fn stage_hot_fork_child_qmp(
        &mut self,
        name: &QmpDescriptorName,
        socket_cookie: u64,
        template_generation: u64,
    ) -> Result<QmpHotForkChildQmpState, QmpError> {
        let result = self
            .send_command_return(QmpCommand::HotForkChildQmp {
                action: HotForkChildQmpAction::Stage,
                name: Some(name),
                socket_cookie: Some(socket_cookie),
            })
            .and_then(|response| parse_hot_fork_child_qmp_state(&response.value))
            .and_then(|state| {
                let exact_basis = state.staged()
                    && state.descriptor_name() == Some(name)
                    && state.socket_cookie() == Some(socket_cookie)
                    && state.template_generation() == template_generation
                    && state.retained_descriptor().is_some()
                    && !state.resource_plan_bound();
                if exact_basis {
                    Ok(state)
                } else {
                    Err(QmpError::MalformedTypedResponse {
                        command: QmpCommandKind::HotForkChildQmp,
                        response: format!(
                            "child QMP stage did not retain {name:?}/{socket_cookie}/{template_generation}"
                        ),
                    })
                }
            });
        self.poison_after_descriptor_mutation_error(result)
    }

    /// Reads QEMU's exact retained branch-private child QMP state.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the query fails or the response violates the
    /// closed version-2 contract.
    pub fn query_hot_fork_child_qmp(&mut self) -> Result<QmpHotForkChildQmpState, QmpError> {
        let response = self.send_command_return(QmpCommand::HotForkChildQmp {
            action: HotForkChildQmpAction::Query,
            name: None,
            socket_cookie: None,
        })?;
        parse_hot_fork_child_qmp_state(&response.value)
    }

    /// Releases QEMU's exact independently retained child QMP stream.
    ///
    /// The standard monitor-owned descriptor name remains until the caller
    /// closes it after this command confirms the QEMU-owned duplicate is gone.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the exchange fails, the exact basis no longer
    /// matches, or the response still reports a retained stream. Every error
    /// poisons the client because descriptor ownership may be ambiguous.
    pub fn release_hot_fork_child_qmp(
        &mut self,
        name: &QmpDescriptorName,
        socket_cookie: u64,
    ) -> Result<QmpHotForkChildQmpState, QmpError> {
        let result = self
            .send_command_return(QmpCommand::HotForkChildQmp {
                action: HotForkChildQmpAction::Release,
                name: Some(name),
                socket_cookie: Some(socket_cookie),
            })
            .and_then(|response| parse_hot_fork_child_qmp_state(&response.value))
            .and_then(|state| {
                if state.staged() || state.generation() == 0 {
                    Err(QmpError::MalformedTypedResponse {
                        command: QmpCommandKind::HotForkChildQmp,
                        response: String::from(
                            "child QMP release did not report a positive absent generation",
                        ),
                    })
                } else {
                    Ok(state)
                }
            });
        self.poison_after_descriptor_mutation_error(result)
    }

    /// Makes QEMU retain one branch-private child console stream.
    ///
    /// The stream must already be imported with [`Self::install_descriptor`].
    /// QEMU authenticates its Linux `SO_COOKIE` and binds it to the exact
    /// connected `crucible-console` source chardev at the retained template.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the exchange fails, QEMU rejects the exact
    /// stream or source-console basis, or its response violates the closed
    /// schema. Every error poisons the client because retained ownership may
    /// then be ambiguous.
    pub fn stage_hot_fork_child_console(
        &mut self,
        name: &QmpDescriptorName,
        socket_cookie: u64,
        template_generation: u64,
    ) -> Result<QmpHotForkChildConsoleState, QmpError> {
        let result = self
            .send_command_return(QmpCommand::HotForkChildConsole {
                action: HotForkChildConsoleAction::Stage,
                name: Some(name),
                socket_cookie: Some(socket_cookie),
            })
            .and_then(|response| parse_hot_fork_child_console_state(&response.value))
            .and_then(|state| {
                let exact_basis = state.staged()
                    && state.descriptor_name() == Some(name)
                    && state.socket_cookie() == Some(socket_cookie)
                    && state.template_generation() == template_generation
                    && state.retained_descriptor().is_some()
                    && !state.resource_plan_bound();
                if exact_basis {
                    Ok(state)
                } else {
                    Err(QmpError::MalformedTypedResponse {
                        command: QmpCommandKind::HotForkChildConsole,
                        response: format!(
                            "child console stage did not retain {name:?}/{socket_cookie}/{template_generation}"
                        ),
                    })
                }
            });
        self.poison_after_descriptor_mutation_error(result)
    }

    /// Reads QEMU's exact retained branch-private child-console state.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the query fails or the response violates the
    /// closed version-1 contract.
    pub fn query_hot_fork_child_console(
        &mut self,
    ) -> Result<QmpHotForkChildConsoleState, QmpError> {
        let response = self.send_command_return(QmpCommand::HotForkChildConsole {
            action: HotForkChildConsoleAction::Query,
            name: None,
            socket_cookie: None,
        })?;
        parse_hot_fork_child_console_state(&response.value)
    }

    /// Releases QEMU's exact independently retained child console stream.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the exchange fails, the exact basis no longer
    /// matches, or QEMU still reports a retained stream. Every error poisons
    /// the client because descriptor ownership may be ambiguous.
    pub fn release_hot_fork_child_console(
        &mut self,
        name: &QmpDescriptorName,
        socket_cookie: u64,
    ) -> Result<QmpHotForkChildConsoleState, QmpError> {
        let result = self
            .send_command_return(QmpCommand::HotForkChildConsole {
                action: HotForkChildConsoleAction::Release,
                name: Some(name),
                socket_cookie: Some(socket_cookie),
            })
            .and_then(|response| parse_hot_fork_child_console_state(&response.value))
            .and_then(|state| {
                if state.staged() || state.generation() == 0 {
                    Err(QmpError::MalformedTypedResponse {
                        command: QmpCommandKind::HotForkChildConsole,
                        response: String::from(
                            "child console release did not report a positive absent generation",
                        ),
                    })
                } else {
                    Ok(state)
                }
            });
        self.poison_after_descriptor_mutation_error(result)
    }

    /// Confirms that launch predeclared the fixed guest-introspection channel.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError::DebugGuestEndpointNotPredeclared`] when the launch
    /// omitted the endpoint. Runtime QMP mutation is never attempted.
    pub const fn confirm_predeclared_debug_guest_endpoint(&self) -> Result<(), QmpError> {
        if self.predeclared_debug_guest_endpoint {
            Ok(())
        } else {
            Err(QmpError::DebugGuestEndpointNotPredeclared)
        }
    }

    /// Stages one exact target-attempt process contract for a future hot fork.
    ///
    /// All three descriptors must already be imported with
    /// [`Self::install_descriptor`]. QEMU independently authenticates the
    /// cgroup-v2 directory, its writable `cgroup.procs`, the nonblocking
    /// cancellation eventfd, and the resource ceiling before retaining
    /// duplicates.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the descriptor basis is rejected, the exchange
    /// fails, or the returned state does not match the exact staged contract.
    pub fn stage_hot_fork_child_process_contract(
        &mut self,
        names: &QmpHotForkChildProcessContractNames,
        identity: QmpHotForkChildProcessContractIdentity,
    ) -> Result<QmpHotForkChildProcessContractState, QmpError> {
        let response = self.send_command_return(QmpCommand::HotForkChildProcessContract {
            action: HotForkChildProcessContractAction::Stage,
            cgroup_name: Some(names.cgroup()),
            cgroup_procs_name: Some(names.cgroup_procs()),
            cancellation_name: Some(names.cancellation()),
            identity: Some(identity),
        })?;
        let state = parse_hot_fork_child_process_contract_state(&response.value)?;
        if !state.staged()
            || state.consumed()
            || !state.names_match(names)
            || state.identity() != Some(identity)
        {
            return Err(QmpError::MalformedTypedResponse {
                command: QmpCommandKind::HotForkChildProcessContract,
                response: response.value.to_string(),
            });
        }
        Ok(state)
    }

    /// Observes the staged one-shot child process contract.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the exchange fails or QEMU returns a malformed
    /// contract state.
    pub fn query_hot_fork_child_process_contract(
        &mut self,
    ) -> Result<QmpHotForkChildProcessContractState, QmpError> {
        let response = self.send_command_return(QmpCommand::HotForkChildProcessContract {
            action: HotForkChildProcessContractAction::Query,
            cgroup_name: None,
            cgroup_procs_name: None,
            cancellation_name: None,
            identity: None,
        })?;
        parse_hot_fork_child_process_contract_state(&response.value)
    }

    /// Releases the exact retained child process contract.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the basis differs, a fork is active, the
    /// exchange fails, or the released-state postcondition is malformed.
    pub fn release_hot_fork_child_process_contract(
        &mut self,
        names: &QmpHotForkChildProcessContractNames,
        identity: QmpHotForkChildProcessContractIdentity,
    ) -> Result<QmpHotForkChildProcessContractState, QmpError> {
        let response = self.send_command_return(QmpCommand::HotForkChildProcessContract {
            action: HotForkChildProcessContractAction::Release,
            cgroup_name: Some(names.cgroup()),
            cgroup_procs_name: Some(names.cgroup_procs()),
            cancellation_name: Some(names.cancellation()),
            identity: Some(identity),
        })?;
        let state = parse_hot_fork_child_process_contract_state(&response.value)?;
        if state.staged() || state.consumed() {
            return Err(QmpError::MalformedTypedResponse {
                command: QmpCommandKind::HotForkChildProcessContract,
                response: response.value.to_string(),
            });
        }
        Ok(state)
    }

    /// Stages the one-shot child-private native file plan for a future hot fork.
    ///
    /// Every destination descriptor must already be imported with
    /// [`Self::install_descriptor`] under its file's name. QEMU independently
    /// authenticates each destination before retaining duplicates.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the list or budget is unbounded, QEMU rejects
    /// the plan, the exchange fails, or the returned state does not echo the
    /// exact staged list.
    pub fn stage_hot_fork_child_files(
        &mut self,
        files: &[QmpHotForkChildFile],
        maximum_bytes: u64,
    ) -> Result<QmpHotForkChildFilesState, QmpError> {
        if files.is_empty()
            || files.len() > QMP_HOT_FORK_CHILD_FILES_MAX
            || maximum_bytes == 0
            || maximum_bytes == u64::MAX
        {
            return Err(QmpError::InvalidHotForkChildFiles);
        }
        let response = self.send_command_return(QmpCommand::HotForkChildFiles {
            action: HotForkChildFilesAction::Stage,
            files: Some(files),
            maximum_bytes: Some(maximum_bytes),
            expected_generation: None,
        })?;
        let state = parse_hot_fork_child_files_state(&response.value)?;
        if !state.staged()
            || state.consumed()
            || state.maximum_bytes() != maximum_bytes
            || state.files() != files
        {
            return Err(QmpError::MalformedTypedResponse {
                command: QmpCommandKind::HotForkChildFiles,
                response: response.value.to_string(),
            });
        }
        Ok(state)
    }

    /// Observes the staged one-shot child-private file plan.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the exchange fails or QEMU returns a malformed
    /// plan state.
    pub fn query_hot_fork_child_files(&mut self) -> Result<QmpHotForkChildFilesState, QmpError> {
        let response = self.send_command_return(QmpCommand::HotForkChildFiles {
            action: HotForkChildFilesAction::Query,
            files: None,
            maximum_bytes: None,
            expected_generation: None,
        })?;
        parse_hot_fork_child_files_state(&response.value)
    }

    /// Releases the exact retained child-private file plan.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the generation differs, a fork is active, the
    /// exchange fails, or the released-state postcondition is malformed.
    pub fn release_hot_fork_child_files(
        &mut self,
        generation: u64,
    ) -> Result<QmpHotForkChildFilesState, QmpError> {
        if generation == 0 {
            return Err(QmpError::InvalidHotForkChildFiles);
        }
        let response = self.send_command_return(QmpCommand::HotForkChildFiles {
            action: HotForkChildFilesAction::Release,
            files: None,
            maximum_bytes: None,
            expected_generation: Some(generation),
        })?;
        let state = parse_hot_fork_child_files_state(&response.value)?;
        if state.staged() || state.consumed() || state.generation() != generation {
            return Err(QmpError::MalformedTypedResponse {
                command: QmpCommandKind::HotForkChildFiles,
                response: response.value.to_string(),
            });
        }
        Ok(state)
    }
}

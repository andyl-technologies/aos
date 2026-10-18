//! QEMU-node staging and teardown for hot-fork diagnostics.

use super::*;

impl QemuNode {
    /// Stages a fresh branch-private diagnostics stream in the retained template.
    ///
    /// The operation requires one acknowledged private-ring stage and must
    /// precede plugin endpoint staging, which seals the complete child resource
    /// plan. The host retains one nonblocking stream endpoint while QEMU owns an
    /// authenticated duplicate of the child endpoint. No fork occurs here.
    ///
    /// # Errors
    ///
    /// Returns [`QemuHotForkChildDiagnosticStageError::Rejected`] before
    /// transfer when the node or template basis is invalid. Once transfer
    /// begins, every failure quarantines the node and returns
    /// [`QemuHotForkChildDiagnosticStageError::TransferUncertain`].
    pub fn stage_hot_fork_child_diagnostics(
        &mut self,
    ) -> Result<QemuHotForkChildDiagnosticStageProof, QemuHotForkChildDiagnosticStageError> {
        if self.lifecycle_state != crate::QemuNodeLifecycleState::Running {
            return Err(diagnostic_rejected(
                "diagnostic staging requires a running node",
            ));
        }
        if self.hot_fork_child_diagnostic_stage.is_some() {
            return Err(diagnostic_rejected(
                "node already retains a child diagnostics stage",
            ));
        }
        if self.hot_fork_child_qmp_stage.is_some() {
            return Err(diagnostic_rejected(
                "child diagnostics must precede child QMP staging",
            ));
        }
        if self.hot_fork_plugin_endpoint_stage.is_some() {
            return Err(diagnostic_rejected(
                "child diagnostics must precede plugin endpoint staging",
            ));
        }
        let (ring_name, ring_identity) = match self.hot_fork_private_ring_stage.as_ref() {
            Some(QemuHotForkPrivateRingStage::Installed(ring)) => {
                (ring.descriptor_name().clone(), ring.backing_identity())
            }
            Some(QemuHotForkPrivateRingStage::TransferUncertain(_)) => {
                return Err(diagnostic_rejected(
                    "private-ring descriptor ownership is uncertain",
                ));
            }
            None => {
                return Err(diagnostic_rejected(
                    "child diagnostics require an installed private-ring descriptor",
                ));
            }
        };
        let qemu_ring = self
            .channels
            .qmp_machine_control
            .query_hot_fork_private_rings()
            .map_err(diagnostic_rejected_source)?;
        let ring_basis_matches = qemu_ring.staged()
            && qemu_ring.descriptor_name() == Some(&ring_name)
            && qemu_ring.device() == ring_identity.device()
            && qemu_ring.inode() == ring_identity.inode()
            && qemu_ring.length() == ring_identity.length()
            && qemu_ring.shrink_sealed()
            && qemu_ring.source_mapping_bound()
            && qemu_ring.generation() != 0;
        if !ring_basis_matches {
            return Err(diagnostic_rejected(
                "QEMU private-ring stage no longer matches the node-owned mapping",
            ));
        }
        let template_generation = qemu_ring.template_generation();
        if template_generation == 0 {
            return Err(diagnostic_rejected(
                "child diagnostics require a template-bound private ring",
            ));
        }

        let mut endpoint = create_diagnostic_pair(template_generation).map_err(|source| {
            diagnostic_rejected_source(QemuNodeChannelError::new(
                "prepare hot-fork child diagnostics",
                source.to_string(),
            ))
        })?;
        let transfer = self
            .channels
            .qmp_machine_control
            .install_hot_fork_child_diagnostics(
                &endpoint.descriptor_name,
                endpoint.child.as_fd(),
                endpoint.socket_cookie,
                template_generation,
            );
        let qemu_state = match transfer {
            Ok(state) => state,
            Err(source) => {
                self.lifecycle_state = crate::QemuNodeLifecycleState::Quarantined;
                self.hot_fork_child_diagnostic_stage =
                    Some(QemuHotForkChildDiagnosticStage::TransferUncertain(endpoint));
                return Err(QemuHotForkChildDiagnosticStageError::TransferUncertain { source });
            }
        };
        let exact = qemu_state.staged()
            && qemu_state.descriptor_name() == Some(&endpoint.descriptor_name)
            && qemu_state.socket_cookie() == Some(endpoint.socket_cookie)
            && qemu_state.template_generation() == template_generation
            && qemu_state.target_descriptor()
                == Some(crate::QMP_HOT_FORK_CHILD_DIAGNOSTICS_TARGET_FD)
            && !qemu_state.replacement_plan_bound();
        if !exact {
            let source = QemuNodeChannelError::new(
                "install hot-fork child diagnostics",
                "QEMU did not retain the exact unsealed diagnostics contribution",
            );
            self.lifecycle_state = crate::QemuNodeLifecycleState::Quarantined;
            self.hot_fork_child_diagnostic_stage =
                Some(QemuHotForkChildDiagnosticStage::TransferUncertain(endpoint));
            return Err(QemuHotForkChildDiagnosticStageError::TransferUncertain { source });
        }
        endpoint.replacement_plan_bound = false;
        let proof = endpoint.proof(QemuHotForkChildDiagnosticStageState::Installed);
        self.hot_fork_child_diagnostic_stage =
            Some(QemuHotForkChildDiagnosticStage::Installed(endpoint));
        Ok(proof)
    }

    /// Returns evidence for the child diagnostics stream retained by this node.
    #[must_use]
    pub fn hot_fork_child_diagnostic_stage(&self) -> Option<QemuHotForkChildDiagnosticStageProof> {
        self.hot_fork_child_diagnostic_stage
            .as_ref()
            .map(QemuHotForkChildDiagnosticStage::proof)
    }

    pub(in crate::node) fn take_hot_fork_child_diagnostic_consumer(
        &mut self,
    ) -> Result<QemuHotForkChildDiagnosticConsumer, QemuNodeChannelError> {
        match self.hot_fork_child_diagnostic_stage.as_mut() {
            Some(QemuHotForkChildDiagnosticStage::Installed(endpoint))
                if endpoint.replacement_plan_bound =>
            {
                endpoint.take_consumer()
            }
            Some(QemuHotForkChildDiagnosticStage::Installed(_)) => Err(QemuNodeChannelError::new(
                "take hot-fork child diagnostics consumer",
                "diagnostics contribution is not bound to the sealed child plan",
            )),
            Some(QemuHotForkChildDiagnosticStage::TransferUncertain(_)) => {
                Err(QemuNodeChannelError::new(
                    "take hot-fork child diagnostics consumer",
                    "diagnostic transfer ownership is uncertain",
                ))
            }
            None => Err(QemuNodeChannelError::new(
                "take hot-fork child diagnostics consumer",
                "node retains no child diagnostics stage",
            )),
        }
    }

    /// Returns the child diagnostics retained by this node so far.
    ///
    /// This reads in every lifecycle state: a failed fork quarantines the node,
    /// and the child's last words on its diagnostics stream are the evidence a
    /// failure report needs. Available bytes are drained first; the node state
    /// is otherwise untouched.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when no acknowledged diagnostics stage
    /// exists, its consumer was transferred to a child owner, or reading the
    /// stream fails.
    pub(crate) fn retained_hot_fork_child_diagnostics(
        &mut self,
    ) -> Result<Vec<u8>, QemuNodeChannelError> {
        let consumer = match self.hot_fork_child_diagnostic_stage.as_mut() {
            Some(QemuHotForkChildDiagnosticStage::Installed(endpoint)) => {
                endpoint.consumer.as_mut()
            }
            Some(QemuHotForkChildDiagnosticStage::TransferUncertain(_)) | None => None,
        };
        let Some(consumer) = consumer else {
            return Err(QemuNodeChannelError::new(
                "read retained hot-fork child diagnostics",
                "node retains no child diagnostics consumer",
            ));
        };
        consumer.drain_available()?;
        Ok(consumer.retained().to_vec())
    }

    /// Releases one acknowledged diagnostics stage in exact ownership order.
    ///
    /// Plugin endpoints and their sealed plan must be released first. QEMU
    /// closes its retained duplicate, then the monitor name, before the node
    /// shuts down the node-owned child writer and drains the host consumer to
    /// EOF before returning the complete bounded capture.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the stage is absent or uncertain,
    /// plugin resources remain retained, or either exact close fails.
    pub fn release_hot_fork_child_diagnostics(
        &mut self,
    ) -> Result<QemuHotForkChildDiagnosticCapture, QemuNodeChannelError> {
        let mut consumer = match self.hot_fork_child_diagnostic_stage.as_mut() {
            Some(QemuHotForkChildDiagnosticStage::Installed(endpoint)) => {
                endpoint.take_consumer()?
            }
            Some(QemuHotForkChildDiagnosticStage::TransferUncertain(_)) => {
                return Err(QemuNodeChannelError::new(
                    "release hot-fork child diagnostics",
                    "diagnostic transfer ownership is uncertain",
                ));
            }
            None => {
                return Err(QemuNodeChannelError::new(
                    "release hot-fork child diagnostics",
                    "node retains no child diagnostics stage",
                ));
            }
        };
        let result = self.release_hot_fork_child_diagnostics_with_consumer(&mut consumer);
        if result.is_err()
            && let Some(QemuHotForkChildDiagnosticStage::Installed(endpoint)) =
                self.hot_fork_child_diagnostic_stage.as_mut()
            && endpoint.consumer.is_none()
            && !consumer.captured
        {
            endpoint.consumer = Some(consumer);
        }
        result
    }

    /// Releases one acknowledged diagnostics stage with its child-owned consumer.
    ///
    /// A successful fork transfers the only host reader to its linear child
    /// owner. After plugin and child-QMP teardown, that owner returns the exact
    /// consumer here. The source closes QEMU's writer and its retained writer,
    /// drains the external reader through EOF, and consumes the stage.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when source release ordering is invalid,
    /// the supplied consumer does not match the retained generation, an exact
    /// close fails, or EOF and the bounded complete capture cannot be proven.
    pub fn release_hot_fork_child_diagnostics_with_consumer(
        &mut self,
        consumer: &mut QemuHotForkChildDiagnosticConsumer,
    ) -> Result<QemuHotForkChildDiagnosticCapture, QemuNodeChannelError> {
        if self.lifecycle_state != crate::QemuNodeLifecycleState::Running {
            return Err(QemuNodeChannelError::new(
                "release hot-fork child diagnostics",
                "diagnostic release requires a running node",
            ));
        }
        if self.hot_fork_plugin_endpoint_stage.is_some() {
            return Err(QemuNodeChannelError::new(
                "release hot-fork child diagnostics",
                "plugin endpoints must release their sealed plan first",
            ));
        }
        if self.hot_fork_child_qmp_stage.is_some() {
            return Err(QemuNodeChannelError::new(
                "release hot-fork child diagnostics",
                "child QMP must release its retained template contribution first",
            ));
        }
        let (name, socket_cookie) = match self.hot_fork_child_diagnostic_stage.as_ref() {
            Some(QemuHotForkChildDiagnosticStage::Installed(endpoint)) => {
                if endpoint.consumer.is_some() || !consumer.matches_pair(endpoint) {
                    return Err(QemuNodeChannelError::new(
                        "release hot-fork child diagnostics",
                        "child-owned diagnostics consumer does not match the retained stage",
                    ));
                }
                (endpoint.descriptor_name.clone(), endpoint.socket_cookie)
            }
            Some(QemuHotForkChildDiagnosticStage::TransferUncertain(_)) => {
                return Err(QemuNodeChannelError::new(
                    "release hot-fork child diagnostics",
                    "diagnostic transfer ownership is uncertain",
                ));
            }
            None => {
                return Err(QemuNodeChannelError::new(
                    "release hot-fork child diagnostics",
                    "node retains no child diagnostics stage",
                ));
            }
        };
        if let Err(source) = self
            .channels
            .qmp_machine_control
            .close_hot_fork_child_diagnostics(&name, socket_cookie)
        {
            self.lifecycle_state = crate::QemuNodeLifecycleState::Quarantined;
            return Err(source);
        }
        let final_drain = match self.hot_fork_child_diagnostic_stage.as_mut() {
            Some(QemuHotForkChildDiagnosticStage::Installed(endpoint)) => endpoint
                .child
                .shutdown(Shutdown::Write)
                .map_err(|source| {
                    QemuNodeChannelError::new(
                        "release hot-fork child diagnostics",
                        format!("shut down retained child writer failed: {source}"),
                    )
                })
                .and_then(|()| consumer.drain_available()),
            Some(QemuHotForkChildDiagnosticStage::TransferUncertain(_)) | None => {
                Err(QemuNodeChannelError::new(
                    "release hot-fork child diagnostics",
                    "diagnostic stage changed after acknowledged close",
                ))
            }
        };
        let final_drain = match final_drain {
            Ok(drain) => drain,
            Err(source) => {
                self.lifecycle_state = crate::QemuNodeLifecycleState::Quarantined;
                return Err(source);
            }
        };
        if !final_drain.eof() {
            self.lifecycle_state = crate::QemuNodeLifecycleState::Quarantined;
            return Err(QemuNodeChannelError::new(
                "release hot-fork child diagnostics",
                "diagnostic writer remained live after acknowledged close",
            ));
        }
        match self.hot_fork_child_diagnostic_stage.take() {
            Some(QemuHotForkChildDiagnosticStage::Installed(_endpoint)) => {
                Ok(consumer.take_capture())
            }
            Some(QemuHotForkChildDiagnosticStage::TransferUncertain(_)) | None => {
                Err(QemuNodeChannelError::new(
                    "release hot-fork child diagnostics",
                    "diagnostic stage changed after acknowledged close",
                ))
            }
        }
    }

    pub(in crate::node) fn detach_hot_fork_child_diagnostics_with_consumer(
        &mut self,
        consumer: &mut QemuHotForkChildDiagnosticConsumer,
    ) -> Result<(), QemuNodeChannelError> {
        if self.lifecycle_state != crate::QemuNodeLifecycleState::Running {
            return Err(QemuNodeChannelError::new(
                "detach hot-fork child diagnostics",
                "diagnostic detachment requires a running source node",
            ));
        }
        if self.hot_fork_plugin_endpoint_stage.is_some() || self.hot_fork_child_qmp_stage.is_some()
        {
            return Err(QemuNodeChannelError::new(
                "detach hot-fork child diagnostics",
                "plugin endpoints and child QMP must release before diagnostics detachment",
            ));
        }
        let (name, socket_cookie, template_generation) =
            match self.hot_fork_child_diagnostic_stage.as_ref() {
                Some(QemuHotForkChildDiagnosticStage::Installed(endpoint)) => {
                    if endpoint.consumer.is_some() || !consumer.matches_pair(endpoint) {
                        return Err(QemuNodeChannelError::new(
                            "detach hot-fork child diagnostics",
                            "child-owned diagnostics consumer does not match the retained stage",
                        ));
                    }
                    (
                        endpoint.descriptor_name.clone(),
                        endpoint.socket_cookie,
                        endpoint.template_generation,
                    )
                }
                Some(QemuHotForkChildDiagnosticStage::TransferUncertain(_)) => {
                    return Err(QemuNodeChannelError::new(
                        "detach hot-fork child diagnostics",
                        "diagnostic transfer ownership is uncertain",
                    ));
                }
                None => {
                    return Err(QemuNodeChannelError::new(
                        "detach hot-fork child diagnostics",
                        "source node retains no child diagnostics stage",
                    ));
                }
            };
        if let Err(source) = self
            .channels
            .qmp_machine_control
            .close_hot_fork_child_diagnostics(&name, socket_cookie)
        {
            self.lifecycle_state = crate::QemuNodeLifecycleState::Quarantined;
            return Err(source);
        }
        if let Err(source) =
            consumer.mark_writer_detached(&name, socket_cookie, template_generation)
        {
            self.lifecycle_state = crate::QemuNodeLifecycleState::Quarantined;
            return Err(source);
        }
        match self.hot_fork_child_diagnostic_stage.take() {
            Some(QemuHotForkChildDiagnosticStage::Installed(_endpoint)) => Ok(()),
            Some(QemuHotForkChildDiagnosticStage::TransferUncertain(_)) | None => {
                self.lifecycle_state = crate::QemuNodeLifecycleState::Quarantined;
                Err(QemuNodeChannelError::new(
                    "detach hot-fork child diagnostics",
                    "diagnostic stage changed after acknowledged close",
                ))
            }
        }
    }
}

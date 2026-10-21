//! Binds actual restore artifact custody through complete physical destruction.

use super::Companion;

pub(super) const CONTRACT: Companion = Companion {
    path: "crates/crucible/qemu/crucible-qemu-host/src/linux_attempt_host/original_node/exact_artifacts.rs",
    required: &[(
        r##"pub(super) struct ExactArtifactCell<T> {
    state: Mutex<ArtifactState<T>>,
}

enum ArtifactState<T> {
    Vacant,
    Held(T),
    Issued,
    Closing,
    Uncertain(Option<T>),
}

impl<T> Default for ExactArtifactCell<T> {
    fn default() -> Self {
        Self {
            state: Mutex::new(ArtifactState::Vacant),
        }
    }
}

impl<T> ExactArtifactCell<T> {
    /// Reserves the existing cell while the launch still owns its artifacts.
    pub(super) fn reserve_transfer(&self) -> bool {
        let Ok(mut state) = self.state.try_lock() else {
            return false;
        };
        if !matches!(*state, ArtifactState::Vacant) {
            return false;
        }
        *state = ArtifactState::Issued;
        true
    }

    /// Transfers the actual artifacts to their next successful external owner.
    pub(super) fn finish_transfer(&self) -> bool {
        let Ok(mut state) = self.state.try_lock() else {
            return false;
        };
        if !matches!(*state, ArtifactState::Issued) {
            return false;
        }
        *state = ArtifactState::Vacant;
        true
    }

    /// Receives the unique actual artifacts without creating another owner.
    ///
    /// # Errors
    /// Returns a duplicate delivery to its sender and quarantines the cell.
    pub(super) fn retain(&self, artifacts: T) -> Result<(), T> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if matches!(*state, ArtifactState::Vacant | ArtifactState::Issued) {
            *state = ArtifactState::Held(artifacts);
            return Ok(());
        }

        // A duplicate violates the unique launch reservation. Keep the first
        // body and permanently prevent closure; losing a handle cannot certify
        // physical return. The extra body remains in terminal containment.
        let previous = std::mem::replace(&mut *state, ArtifactState::Closing);
        *state = match previous {
            ArtifactState::Held(first) => ArtifactState::Uncertain(Some(first)),
            ArtifactState::Uncertain(first) => ArtifactState::Uncertain(first),
            ArtifactState::Closing | ArtifactState::Vacant | ArtifactState::Issued => {
                ArtifactState::Uncertain(None)
            }
        };
        drop(state);
        Err(artifacts)
    }

    /// Destroys actual artifacts outside the mutex and latches only completion.
    pub(super) fn close(&self) -> bool {
        let artifacts = {
            let Ok(mut state) = self.state.try_lock() else {
                return false;
            };
            match &*state {
                ArtifactState::Vacant => return true,
                ArtifactState::Issued | ArtifactState::Closing | ArtifactState::Uncertain(_) => {
                    return false;
                }
                ArtifactState::Held(_) => {}
            }
            match std::mem::replace(&mut *state, ArtifactState::Closing) {
                ArtifactState::Held(artifacts) => artifacts,
                _ => return false,
            }
        };

        drop(artifacts);

        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        if !matches!(*state, ArtifactState::Closing) {
            return false;
        }
        *state = ArtifactState::Vacant;
        true
    }

    /// Reports only a vacant cell after successful handoff or destruction.
    pub(super) fn returned(&self) -> bool {
        self.state
            .try_lock()
            .is_ok_and(|state| matches!(*state, ArtifactState::Vacant))
    }
}

impl<T> Drop for ExactArtifactCell<T> {
    fn drop(&mut self) {
        let state = self
            .state
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match std::mem::replace(state, ArtifactState::Closing) {
            ArtifactState::Held(artifacts) | ArtifactState::Uncertain(Some(artifacts)) => {
                std::mem::forget(artifacts);
            }
            _ => {}
        }
    }
}"##,
        1,
    )],
};

pub(super) const HANDOFF: Companion = Companion {
    path: "crates/crucible/qemu/crucible-qemu-host/src/supervision/exact_restore/artifacts.rs",
    required: &[(
        r##"pub(crate) struct QemuExactRestoreArtifacts {
    /// Owns sealed input descriptors while admission and launch borrow them.
    pub(super) ram_inputs: Option<crate::spawn::SealedAtomicExactRestoreInputs>,
    /// Holds the move-only relation before materialization and after restore.
    pub(super) target: Option<crucible_engine::exact_checkpoint::ExactCheckpointVerifiedNode>,
    /// Drops last so final directory custody outlives every sealed input.
    pub(super) run_directory: QemuPreparedRunDirectory,
}

pub(super) struct IssuedExactRestoreArtifacts {
    receiver: crate::RetainedNativeFreshLaunchError,
    artifacts: Option<QemuExactRestoreArtifacts>,
}

impl IssuedExactRestoreArtifacts {
    /// Reserves the installed binding's existing cell before preparation effects.
    ///
    /// # Errors
    /// Retains artifacts on a missing or already occupied actual recipient.
    pub(super) fn new(
        binding: &crate::linux_attempt_host::OriginalNativeNodeBinding,
        run_directory: QemuPreparedRunDirectory,
        target: crucible_engine::exact_checkpoint::ExactCheckpointVerifiedNode,
    ) -> Result<Self, QemuLiveNodeStepGateError> {
        let artifacts = QemuExactRestoreArtifacts {
            run_directory,
            target: Some(target),
            ram_inputs: None,
        };
        let Ok(receiver) = binding
            .source_helper_lender()
            .and_then(|lender| lender.controller())
        else {
            // Preparation must never invent a physical recipient.
            std::mem::forget(artifacts);
            return Err(QemuLiveNodeStepGateError::ExactSnapshotInvariant {
                reason: String::from("issued exact launch lost its artifact recipient"),
            });
        };
        if !receiver.reserve_exact_artifact_transfer() {
            receiver.retain_exact_artifacts(artifacts);
            receiver.record_returned_cleanup_failure(
                QemuLiveNodeStepGateError::ExactSnapshotInvariant {
                    reason: String::from("issued exact artifact recipient was already occupied"),
                },
            );
            return Err(QemuLiveNodeStepGateError::OriginalNativeLaunch { source: receiver });
        }
        Ok(Self {
            receiver,
            artifacts: Some(artifacts),
        })
    }

    /// Borrows the actual prepared body without moving its return guard.
    ///
    /// # Errors
    /// Refuses an artifact body that has already left this guard.
    pub(super) fn preparation(
        &mut self,
    ) -> Result<&mut QemuExactRestoreArtifacts, QemuLiveNodeStepGateError> {
        self.artifacts
            .as_mut()
            .ok_or_else(|| QemuLiveNodeStepGateError::ExactSnapshotInvariant {
                reason: String::from("exact preparation lost its retained artifact body"),
            })
    }

    /// Hands the same assembled Node and actual files to their next owner.
    ///
    /// # Errors
    /// Retains both components on foreign custody or an incomplete handoff.
    pub(super) fn into_parts(
        mut self,
        mut owner: crate::node::IssuedLaunchOwner,
    ) -> Result<
        (
            QemuNode,
            QemuPreparedRunDirectory,
            crucible_engine::exact_checkpoint::ExactCheckpointVerifiedNode,
        ),
        QemuLiveNodeStepGateError,
    > {
        let same_receiver = owner
            .retained_receiver()
            .is_some_and(|receiver| receiver.same_owner(&self.receiver));
        if !same_receiver || owner.node_mut().is_err() {
            drop(self);
            return Err(owner.retain_cleanup_failure(
                QemuLiveNodeStepGateError::ExactSnapshotInvariant {
                    reason: String::from("exact handoff requires the same assembled issued Node"),
                },
            ));
        }
        let Some(mut artifacts) = self.artifacts.take() else {
            drop(self);
            return Err(owner.retain_cleanup_failure(
                QemuLiveNodeStepGateError::ExactSnapshotInvariant {
                    reason: String::from("issued exact artifacts were already transferred"),
                },
            ));
        };
        let Some(target) = artifacts.target.take() else {
            self.artifacts = Some(artifacts);
            drop(self);
            return Err(owner.retain_cleanup_failure(
                QemuLiveNodeStepGateError::ExactSnapshotInvariant {
                    reason: String::from(
                        "exact preparation did not return its authenticated target",
                    ),
                },
            ));
        };
        if !self.receiver.finish_exact_artifact_transfer() {
            artifacts.target = Some(target);
            self.artifacts = Some(artifacts);
            drop(self);
            return Err(owner.retain_cleanup_failure(
                QemuLiveNodeStepGateError::ExactSnapshotInvariant {
                    reason: String::from("issued exact artifact transfer lost its original cell"),
                },
            ));
        }

        // The child remains borrowed until this final pure phase conversion.
        // No callback or fallible effect separates the two actual handoffs.
        match owner.into_node() {
            Ok(node) => Ok((node, artifacts.run_directory, target)),
            Err(owner) => {
                artifacts.target = Some(target);
                self.artifacts = Some(artifacts);
                drop(self);
                Err(owner.retain_cleanup_failure(
                    QemuLiveNodeStepGateError::ExactSnapshotInvariant {
                        reason: String::from("issued exact Node changed during pure handoff"),
                    },
                ))
            }
        }
    }

    /// Returns actual files before publishing the existing receiver's failure.
    pub(super) fn retain_failure(
        self,
        primary: QemuLiveNodeStepGateError,
    ) -> QemuLiveNodeStepGateError {
        let receiver = self.receiver.clone();
        drop(self);
        receiver.record_returned_cleanup_failure(primary);
        QemuLiveNodeStepGateError::OriginalNativeLaunch { source: receiver }
    }
}

impl QemuExactRestoreArtifacts {
    /// Returns the authenticated target after the completed restore consumed inputs.
    ///
    /// # Errors
    /// Refuses completion without the same retained sealed restore inputs.
    pub(super) fn complete_preparation(&mut self) -> Result<(), QemuLiveNodeStepGateError> {
        let inputs = self.ram_inputs.take().ok_or_else(|| {
            QemuLiveNodeStepGateError::ExactSnapshotInvariant {
                reason: String::from("exact preparation lost its sealed RAM inputs"),
            }
        })?;
        self.target = Some(inputs.into_target());
        Ok(())
    }
}

impl Drop for IssuedExactRestoreArtifacts {
    fn drop(&mut self) {
        if let Some(artifacts) = self.artifacts.take() {
            self.receiver.retain_exact_artifacts(artifacts);
        }
    }
}"##,
        1,
    )],
};

pub(super) const LAUNCH: Companion = Companion {
    path: "crates/crucible/qemu/crucible-qemu-host/src/supervision/exact_restore.rs",
    required: &[
        (
            r##"pub struct QemuProductionExactRestoreLaunch {
    // Field order returns the process before its artifacts; the occupied
    // artifact cell prevents an interim process return from certifying closure.
    node: crate::node::IssuedLaunchOwner,
    artifacts: IssuedExactRestoreArtifacts,
}

impl QemuProductionExactRestoreLaunch {
    /// Retains a restored node at its authenticated paused boundary for replay comparison.
    ///
    /// The exact probe fingerprints the restored checkpoint before any guest
    /// instruction may execute. Production resume uses `into_running_parts`
    /// only after admitting that checkpoint as the live continuation.
    pub(crate) fn into_paused_parts(
        self,
    ) -> Result<
        (
            QemuNode,
            QemuPreparedRunDirectory,
            crucible_engine::exact_checkpoint::ExactCheckpointVerifiedNode,
        ),
        QemuLiveNodeStepGateError,
    > {
        self.artifacts.into_parts(self.node)
    }

    /// Resumes a fully restored node under its retained exact relation.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveNodeStepGateError`] when QMP does not acknowledge the
    /// running transition or the failed node cannot be synchronously reaped.
    pub fn into_running_node_and_run_directory(
        self,
    ) -> Result<(QemuNode, QemuPreparedRunDirectory), QemuLiveNodeStepGateError> {
        self.into_running_parts()
            .map(|(node, run_directory, _target)| (node, run_directory))
    }

    /// Consumes a lifecycle launch while dropping its replay-only root proof.
    ///
    /// # Errors
    /// Retains an unexpected unassembled body in its original receiver.
    pub fn into_node_and_run_directory(
        self,
    ) -> Result<(QemuNode, QemuPreparedRunDirectory), QemuLiveNodeStepGateError> {
        self.into_paused_parts()
            .map(|(node, run_directory, _target)| (node, run_directory))
    }

    pub(crate) fn into_running_parts(
        self,
    ) -> Result<
        (
            QemuNode,
            QemuPreparedRunDirectory,
            crucible_engine::exact_checkpoint::ExactCheckpointVerifiedNode,
        ),
        QemuLiveNodeStepGateError,
    > {
        match resume_restored_exact_node(self.node) {
            Ok(owner) => self.artifacts.into_parts(owner),
            Err(error) => Err(self.artifacts.retain_failure(error)),
        }
    }
}"##,
            1,
        ),
        (
            r#"pub(crate) fn launch_in_issuer(
        self,
        issuer: &crate::InstalledNodeLaunchIssuer,
    ) -> Result<QemuProductionExactRestoreLaunch, QemuLiveNodeStepGateError> {
        let Self {
            config,
            run_directory,
            process_contract,
            snapshot,
            snapshot_object,
            node,
            router,
            crash_detector,
            target,
            source,
        } = self;
        issuer.with_issued_node_launch(
            &config,
            &process_contract,
            |binding, workspace, issued_contract| {
                let envelope = issued_contract.configured_process_envelope().ok_or(
                    QemuLiveNodeStepGateError::OriginalNativeAccount {
                        source: crate::OriginalActorAccountError::Unavailable,
                    },
                )?;
                if !envelope.matches_contract(&process_contract) {
                    return Err(QemuLiveNodeStepGateError::OriginalNativeAccount {
                        source: crate::OriginalActorAccountError::Unavailable,
                    });
                }
                let mut artifacts =
                    IssuedExactRestoreArtifacts::new(&binding, run_directory, target)?;
                let prepared = artifacts.preparation()?;
                prepared
                    .run_directory
                    .prepare_vmstate_container_guarded(config.qemu_executable(), &process_contract)
                    .map_err(
                        |source| QemuLiveNodeStepGateError::ExactVmstatePreparation { source },
                    )?;
                let cancellation = process_contract
                    .try_clone_cancellation_event()
                    .map_err(|source| QemuLiveNodeStepGateError::Spawn { source })?;
                let ram_inputs = prepared
                    .run_directory
                    .materialize_production_exact_checkpoint(
                        &process_contract,
                        &mut prepared.target,
                        source,
                        cancellation.as_fd(),
                    )
                    .map_err(|source| QemuLiveNodeStepGateError::Spawn { source })?;
                prepared.ram_inputs = Some(ram_inputs);
                let ram_inputs = prepared.ram_inputs.as_ref().ok_or_else(|| {
                    QemuLiveNodeStepGateError::ExactSnapshotInvariant {
                        reason: String::from("exact preparation lost its retained sealed inputs"),
                    }
                })?;
                let identity = QemuLiveNodeIdentity::new(&node.name, &router, &crash_detector);
                let admission = AtomicExactRestoreAdmission::admit(
                    &mut prepared.run_directory,
                    &process_contract,
                    identity,
                    &snapshot,
                    snapshot_object,
                    ram_inputs,
                    cancellation.as_fd(),
                )?;
                let node =
                    launch_atomic_exact_restore(&config, admission, false, binding, workspace)?;
                prepared.complete_preparation()?;
                Ok(QemuProductionExactRestoreLaunch { node, artifacts })
            },
            |launch, refusal, after| refusal.retain_exact_launch(launch, after),
        )
    }"#,
            1,
        ),
    ],
};

//! Keeps exact restore files on the existing issued launch return route.
//!
//! The receiver's fixed cell stays occupied while this guard holds actual files.
//! Returning a process cannot race ahead of that separate artifact handoff.

use super::*;

/// Retains actual preparation files and the authenticated relation through launch.
pub(crate) struct QemuExactRestoreArtifacts {
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
}

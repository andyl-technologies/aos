//! Keeps exact restore files on the existing issued launch return route.
//!
//! The receiver's fixed cell stays occupied while this guard holds actual files.
//! Returning a process cannot race ahead of that separate artifact handoff.

use super::*;

/// Retains the actual pinned files and authenticated relation after launch.
pub(crate) struct QemuExactRestoreArtifacts {
    run_directory: QemuPreparedRunDirectory,
    target: crucible_engine::exact_checkpoint::ExactCheckpointVerifiedNode,
}

pub(super) struct IssuedExactRestoreArtifacts {
    receiver: crate::RetainedNativeFreshLaunchError,
    artifacts: Option<QemuExactRestoreArtifacts>,
}

impl IssuedExactRestoreArtifacts {
    /// Reserves this actual issued owner's existing artifact return cell.
    ///
    /// # Errors
    /// Retains artifacts on a missing or already occupied actual recipient.
    pub(super) fn new(
        owner: &crate::node::IssuedLaunchOwner,
        run_directory: QemuPreparedRunDirectory,
        target: crucible_engine::exact_checkpoint::ExactCheckpointVerifiedNode,
    ) -> Result<Self, QemuLiveNodeStepGateError> {
        let artifacts = QemuExactRestoreArtifacts {
            run_directory,
            target,
        };
        let Some(receiver) = owner.retained_receiver() else {
            // No physical recipient can be invented after child birth.
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
        let Some(artifacts) = self.artifacts.take() else {
            drop(self);
            return Err(owner.retain_cleanup_failure(
                QemuLiveNodeStepGateError::ExactSnapshotInvariant {
                    reason: String::from("issued exact artifacts were already transferred"),
                },
            ));
        };
        if !self.receiver.finish_exact_artifact_transfer() {
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
            Ok(node) => Ok((node, artifacts.run_directory, artifacts.target)),
            Err(owner) => {
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

impl Drop for IssuedExactRestoreArtifacts {
    fn drop(&mut self) {
        if let Some(artifacts) = self.artifacts.take() {
            self.receiver.retain_exact_artifacts(artifacts);
        }
    }
}

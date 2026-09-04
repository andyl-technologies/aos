//! Target-attempt process containment staged for one hot-fork child.

use std::os::fd::{AsFd as _, AsRawFd as _};

use super::*;

/// Exact source-QEMU proof for one staged target process contract.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuHotForkChildProcessContractStageProof {
    generation: u64,
    template_generation: u64,
    identity: crate::QmpHotForkChildProcessContractIdentity,
    consumed: bool,
}

impl QemuHotForkChildProcessContractStageProof {
    /// Returns the source-QEMU process-contract generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the exact template generation bound by QEMU.
    #[must_use]
    pub const fn template_generation(&self) -> u64 {
        self.template_generation
    }

    /// Returns the exact kernel-object identity and file-size ceiling.
    #[must_use]
    pub const fn identity(&self) -> crate::QmpHotForkChildProcessContractIdentity {
        self.identity
    }

    /// Returns whether this one-shot contract has created a child.
    #[must_use]
    pub const fn consumed(&self) -> bool {
        self.consumed
    }
}

#[derive(Debug)]
pub(super) struct QemuHotForkChildProcessContractStage {
    cgroup_name: crate::QmpDescriptorName,
    cancellation_name: crate::QmpDescriptorName,
    proof: QemuHotForkChildProcessContractStageProof,
}

impl QemuHotForkChildProcessContractStage {
    pub(super) fn proof(&self) -> QemuHotForkChildProcessContractStageProof {
        self.proof.clone()
    }

    pub(super) fn mark_consumed(&mut self) {
        self.proof.consumed = true;
    }

    pub(super) fn matches_state(&self, state: &crate::QmpHotForkChildProcessContractState) -> bool {
        state.staged()
            && !state.consumed()
            && state.generation() == self.proof.generation
            && state.template_generation() == self.proof.template_generation
            && state.cgroup_name() == Some(&self.cgroup_name)
            && state.cancellation_name() == Some(&self.cancellation_name)
            && state.identity() == Some(self.proof.identity)
            && !self.proof.consumed
    }
}

impl QemuNode {
    #[cfg(test)]
    pub(super) fn install_test_hot_fork_child_process_contract_stage(
        &mut self,
        generation: u64,
        template_generation: u64,
    ) -> Result<(), QemuNodeChannelError> {
        let identity = crate::QmpHotForkChildProcessContractIdentity::new(1, 2, 3, 4)
            .map_err(QemuNodeChannelError::from)?;
        self.hot_fork_child_process_contract_stage = Some(QemuHotForkChildProcessContractStage {
            cgroup_name: crate::QmpDescriptorName::new("test-hot-fork-cgroup")
                .map_err(QemuNodeChannelError::from)?,
            cancellation_name: crate::QmpDescriptorName::new("test-hot-fork-cancellation")
                .map_err(QemuNodeChannelError::from)?,
            proof: QemuHotForkChildProcessContractStageProof {
                generation,
                template_generation,
                identity,
                consumed: false,
            },
        });
        Ok(())
    }

    /// Stages the target attempt's cgroup and sticky cancellation descriptors.
    ///
    /// QEMU authenticates both imported descriptors, retains independent
    /// duplicates, and binds the resulting one-shot generation to the current
    /// retained template. The later fork uses `clone3(CLONE_INTO_CGROUP)`, so
    /// the child is charged to the target cgroup from its first instruction.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when no production cgroup directory is
    /// present, descriptor identity cannot be read, another contract remains
    /// staged, or QMP cannot complete and authenticate the transfer. Ambiguous
    /// transfer failures quarantine this source node.
    pub fn stage_hot_fork_child_process_contract(
        &mut self,
        contract: &crate::QemuChildProcessContract,
        template_generation: u64,
    ) -> Result<QemuHotForkChildProcessContractStageProof, QemuNodeChannelError> {
        if self.lifecycle_state != QemuNodeLifecycleState::Running {
            return Err(QemuNodeChannelError::new(
                "stage hot-fork child process contract",
                "process contract staging requires a running source node",
            ));
        }
        if self.hot_fork_child_process_contract_stage.is_some() {
            return Err(QemuNodeChannelError::new(
                "stage hot-fork child process contract",
                "one child process contract is already staged",
            ));
        }
        if template_generation == 0 {
            return Err(QemuNodeChannelError::new(
                "stage hot-fork child process contract",
                "template generation must be nonzero",
            ));
        }

        let (cgroup, cancellation) =
            contract
                .duplicate_hot_fork_descriptors()
                .map_err(|source| {
                    QemuNodeChannelError::new(
                        "stage hot-fork child process contract",
                        source.to_string(),
                    )
                })?;
        let status = rustix::fs::fstat(&cgroup).map_err(|source| {
            QemuNodeChannelError::new("stage hot-fork child process contract", source.to_string())
        })?;
        if rustix::fs::FileType::from_raw_mode(status.st_mode) != rustix::fs::FileType::Directory {
            return Err(QemuNodeChannelError::new(
                "stage hot-fork child process contract",
                "target cgroup descriptor is not a directory",
            ));
        }
        let cgroup_device = status.st_dev;
        let cgroup_inode = status.st_ino;
        let cancellation_eventfd_id = super::hot_fork_plugin_endpoints::eventfd_id(
            cancellation.as_raw_fd(),
        )
        .map_err(|source| {
            QemuNodeChannelError::new("stage hot-fork child process contract", source.to_string())
        })?;
        let identity = crate::QmpHotForkChildProcessContractIdentity::new(
            cgroup_device,
            cgroup_inode,
            cancellation_eventfd_id,
            contract.maximum_writable_bytes(),
        )
        .map_err(QemuNodeChannelError::from)?;
        let cgroup_name =
            crate::QmpDescriptorName::new(format!("crucible-hfork-cgroup-v1-{cgroup_inode:016x}"))
                .map_err(QemuNodeChannelError::from)?;
        let cancellation_name = crate::QmpDescriptorName::new(format!(
            "crucible-hfork-cancel-v1-{cancellation_eventfd_id:016x}"
        ))
        .map_err(QemuNodeChannelError::from)?;

        let state = self
            .channels
            .qmp_machine_control
            .install_hot_fork_child_process_contract(
                &cgroup_name,
                cgroup.as_fd(),
                &cancellation_name,
                cancellation.as_fd(),
                identity,
                template_generation,
            )
            .inspect_err(|_source| {
                self.lifecycle_state = QemuNodeLifecycleState::Quarantined;
            })?;
        let proof = QemuHotForkChildProcessContractStageProof {
            generation: state.generation(),
            template_generation: state.template_generation(),
            identity,
            consumed: false,
        };
        self.hot_fork_child_process_contract_stage = Some(QemuHotForkChildProcessContractStage {
            cgroup_name,
            cancellation_name,
            proof: proof.clone(),
        });
        Ok(proof)
    }

    /// Returns the locally retained process-contract stage proof.
    #[must_use]
    pub fn hot_fork_child_process_contract_stage(
        &self,
    ) -> Option<QemuHotForkChildProcessContractStageProof> {
        self.hot_fork_child_process_contract_stage
            .as_ref()
            .map(QemuHotForkChildProcessContractStage::proof)
    }

    /// Releases the exact QEMU-owned process contract after its fork outcome.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when no stage exists or QEMU cannot
    /// release the exact retained descriptor basis.
    pub fn release_hot_fork_child_process_contract(
        &mut self,
    ) -> Result<crate::QmpHotForkChildProcessContractState, QemuNodeChannelError> {
        let stage = self
            .hot_fork_child_process_contract_stage
            .as_ref()
            .ok_or_else(|| {
                QemuNodeChannelError::new(
                    "release hot-fork child process contract",
                    "source node retains no child process contract",
                )
            })?;
        let state = self
            .channels
            .qmp_machine_control
            .release_hot_fork_child_process_contract(
                &stage.cgroup_name,
                &stage.cancellation_name,
                stage.proof.identity,
            )?;
        self.hot_fork_child_process_contract_stage = None;
        Ok(state)
    }
}

//! Child-private native file destinations staged for one hot-fork child.
//!
//! The caller owns one empty regular file per originally writable native root
//! of the retained template. This module names each file for standard QMP
//! `getfd`, binds it to its root, and has QEMU retain authenticated
//! duplicates as a one-shot plan. The later fork copies the frozen bytes into
//! those files and the child adopts them; the parent never writes them.

use std::os::fd::BorrowedFd;

use super::*;

/// One caller-owned empty destination for a retained source root.
#[derive(Clone, Copy, Debug)]
pub struct QemuHotForkChildFileDestination<'a> {
    root: &'a crate::QmpHotForkChildFileRoot,
    file: BorrowedFd<'a>,
}

impl<'a> QemuHotForkChildFileDestination<'a> {
    /// Pairs one retained root with the empty file its child copy will occupy.
    #[must_use]
    pub const fn new(root: &'a crate::QmpHotForkChildFileRoot, file: BorrowedFd<'a>) -> Self {
        Self { root, file }
    }
}

/// Exact source-QEMU proof for one staged child-private file plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuHotForkChildFilesStageProof {
    generation: u64,
    template_generation: u64,
    maximum_bytes: u64,
    file_count: usize,
    consumed: bool,
}

impl QemuHotForkChildFilesStageProof {
    /// Returns the source-QEMU plan generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the exact template generation bound by QEMU.
    #[must_use]
    pub const fn template_generation(&self) -> u64 {
        self.template_generation
    }

    /// Returns the aggregate source-byte budget QEMU retained.
    #[must_use]
    pub const fn maximum_bytes(&self) -> u64 {
        self.maximum_bytes
    }

    /// Returns the number of staged destinations.
    #[must_use]
    pub const fn file_count(&self) -> usize {
        self.file_count
    }

    /// Returns whether this one-shot plan has created a child.
    #[must_use]
    pub const fn consumed(&self) -> bool {
        self.consumed
    }
}

#[derive(Debug)]
pub(super) struct QemuHotForkChildFilesStage {
    files: Vec<crate::QmpHotForkChildFile>,
    proof: QemuHotForkChildFilesStageProof,
}

impl QemuHotForkChildFilesStage {
    pub(super) fn proof(&self) -> QemuHotForkChildFilesStageProof {
        self.proof.clone()
    }

    pub(super) fn mark_consumed(&mut self) {
        self.proof.consumed = true;
    }

    pub(super) fn generation(&self) -> u64 {
        self.proof.generation
    }

    pub(super) fn files(&self) -> &[crate::QmpHotForkChildFile] {
        &self.files
    }

    pub(super) fn matches_state(&self, state: &crate::QmpHotForkChildFilesState) -> bool {
        state.staged()
            && !state.consumed()
            && state.generation() == self.proof.generation
            && state.template_generation() == self.proof.template_generation
            && state.maximum_bytes() == self.proof.maximum_bytes
            && state.files() == self.files.as_slice()
            && !self.proof.consumed
    }
}

impl QemuNode {
    /// Stages one empty destination per originally writable native root.
    ///
    /// Each file must be an empty regular file the caller keeps open. QEMU
    /// duplicates and authenticates every descriptor, binds the plan to the
    /// current retained template, and reports the exact staged list back. The
    /// plan is consumed by exactly one fork; the caller must not reuse the
    /// destinations for another child.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the node is not running, a plan is
    /// already staged, the list is empty or exceeds QEMU's bound, a destination
    /// is not an empty regular file, or QMP cannot complete and authenticate
    /// the transfer. Ambiguous transfer failures quarantine this source node.
    pub fn stage_hot_fork_child_files(
        &mut self,
        destinations: &[QemuHotForkChildFileDestination<'_>],
        maximum_bytes: u64,
        template_generation: u64,
    ) -> Result<QemuHotForkChildFilesStageProof, QemuNodeChannelError> {
        const OPERATION: &str = "stage hot-fork child files";

        if self.lifecycle_state != QemuNodeLifecycleState::Running {
            return Err(QemuNodeChannelError::new(
                OPERATION,
                "child file staging requires a running source node",
            ));
        }
        if self.hot_fork_child_files_stage.is_some() {
            return Err(QemuNodeChannelError::new(
                OPERATION,
                "one child file plan is already staged",
            ));
        }
        if template_generation == 0 {
            return Err(QemuNodeChannelError::new(
                OPERATION,
                "template generation must be nonzero",
            ));
        }
        if destinations.is_empty()
            || destinations.len() > crate::qmp::QMP_HOT_FORK_CHILD_FILES_MAX
            || maximum_bytes == 0
            || maximum_bytes == u64::MAX
        {
            return Err(QemuNodeChannelError::new(
                OPERATION,
                "child file plan requires a bounded destination list and byte budget",
            ));
        }

        let mut files = Vec::with_capacity(destinations.len());
        let mut descriptors = Vec::with_capacity(destinations.len());
        for (index, destination) in destinations.iter().enumerate() {
            let status = rustix::fs::fstat(destination.file)
                .map_err(|source| QemuNodeChannelError::new(OPERATION, source.to_string()))?;
            let regular = rustix::fs::FileType::from_raw_mode(status.st_mode)
                == rustix::fs::FileType::RegularFile;
            if !regular || status.st_size != 0 || status.st_nlink != 1 {
                return Err(QemuNodeChannelError::new(
                    OPERATION,
                    "child file destination must be an empty, singly linked regular file",
                ));
            }
            let name = crate::QmpDescriptorName::new(format!(
                "crucible-hfork-file-v1-{index:04x}-{:016x}",
                status.st_ino
            ))
            .map_err(QemuNodeChannelError::from)?;
            let file = crate::QmpHotForkChildFile::new(
                destination.root.clone(),
                name,
                status.st_dev,
                status.st_ino,
            )
            .map_err(QemuNodeChannelError::from)?;
            if files.iter().any(|prior: &crate::QmpHotForkChildFile| {
                prior.root() == file.root()
                    || (prior.device() == file.device() && prior.inode() == file.inode())
            }) {
                return Err(QemuNodeChannelError::new(
                    OPERATION,
                    "child file destinations must name distinct roots and files",
                ));
            }
            files.push(file);
            descriptors.push(destination.file);
        }

        let state = self
            .channels
            .qmp_machine_control
            .install_hot_fork_child_files(&files, &descriptors, maximum_bytes, template_generation)
            .inspect_err(|_source| {
                self.lifecycle_state = QemuNodeLifecycleState::Quarantined;
            })?;
        let proof = QemuHotForkChildFilesStageProof {
            generation: state.generation(),
            template_generation: state.template_generation(),
            maximum_bytes,
            file_count: files.len(),
            consumed: false,
        };
        self.hot_fork_child_files_stage = Some(QemuHotForkChildFilesStage {
            files,
            proof: proof.clone(),
        });
        Ok(proof)
    }

    /// Returns the locally retained child-file plan proof.
    #[must_use]
    pub fn hot_fork_child_files_stage(&self) -> Option<QemuHotForkChildFilesStageProof> {
        self.hot_fork_child_files_stage
            .as_ref()
            .map(QemuHotForkChildFilesStage::proof)
    }

    /// Releases the exact QEMU-owned child-file plan after its fork outcome.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when no stage exists, a fork operation
    /// is active, or QEMU cannot release the exact retained generation.
    pub fn release_hot_fork_child_files(
        &mut self,
    ) -> Result<crate::QmpHotForkChildFilesState, QemuNodeChannelError> {
        let stage = self.hot_fork_child_files_stage.as_ref().ok_or_else(|| {
            QemuNodeChannelError::new(
                "release hot-fork child files",
                "source node retains no child file plan",
            )
        })?;
        let state = self
            .channels
            .qmp_machine_control
            .release_hot_fork_child_files(stage.proof.generation)?;
        self.hot_fork_child_files_stage = None;
        Ok(state)
    }
}

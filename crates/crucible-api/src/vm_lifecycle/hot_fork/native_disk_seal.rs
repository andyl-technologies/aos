//! Native disk-seal adapter for the production lifecycle transaction.
//!
//! This concrete adapter retains the typed socket receipt and original request,
//! binds them to the live process and generation lease, and passes authenticated
//! identities to the independent file-custody owner. It owns no emulator code.

use super::disk_basis::{NativeDiskSealIdentity, PinnedHotForkDiskFiles};
use super::*;
use crucible_qemu::{
    QmpHotForkBlockSealRequest, QmpHotForkBlockSealState, QmpHotForkBlockSnapshotBinding,
};
use std::fs::File;
use std::path::Path;

/// Native seal request and independently authenticated open file custody.
pub(super) struct ProductionVmHotForkDiskCustody {
    request: QmpHotForkBlockSealRequest,
    files: PinnedHotForkDiskFiles,
}

impl ProductionVmHotForkDiskCustody {
    fn capture(
        receipt: &QmpHotForkBlockSealState,
        request: &QmpHotForkBlockSealRequest,
        snapshot: (File, &Path),
        boot: (File, &Path),
        expected_boot: ContentHash,
        vmstate: (File, &Path),
        detached: (File, &Path),
    ) -> Result<Self, SchedulerError> {
        if !receipt.seals(std::slice::from_ref(request))
            || request.candidate().file_path() != snapshot.1
        {
            return Err(hot_fork_boundary_error(
                "native block seal differs from the retained current root",
            ));
        }
        let seal = NativeDiskSealIdentity {
            source_pid: receipt.qemu_pid(),
            generation: receipt.receipt_generation(),
            backend_id: request.candidate().backend_id(),
            snapshot_identity: request.candidate().file_identity(),
        };
        let files = PinnedHotForkDiskFiles::capture(
            seal,
            snapshot,
            boot,
            expected_boot,
            vmstate,
            detached,
        )?;
        Ok(Self {
            request: request.clone(),
            files,
        })
    }

    /// Returns the independently authenticated continuation disk basis.
    pub(super) fn basis(&self) -> &ProductionVmHotForkDiskBasis {
        self.files.basis()
    }

    /// Rechecks retained file contents and original inode custody.
    ///
    /// # Errors
    ///
    /// Returns an error when a file cannot be inspected or authenticated.
    pub(super) fn current(&self) -> Result<bool, SchedulerError> {
        self.files.current()
    }

    fn native_current(&self, state: &QmpHotForkBlockSealState) -> bool {
        state.qemu_pid() == self.basis().source_pid
            && state.receipt_generation() == self.basis().seal_generation
            && state.seals(std::slice::from_ref(&self.request))
    }

    /// Rechecks the original source's retained native seal through its backend.
    ///
    /// # Errors
    ///
    /// Returns an error when the original backend cannot query its native seal.
    pub(super) fn native_current_for_node(
        &self,
        lifecycle: &mut ProductionVmLifecycleLoop,
        node: &NodeId,
    ) -> Result<bool, SchedulerError> {
        let state = lifecycle
            .inner
            .backend_mut()
            .query_hot_fork_disk_seal(node)
            .map_err(|error| {
                hot_fork_boundary_error(format!(
                    "recheck prepared source `{}` native disk seal: {error}",
                    node.name
                ))
            })?;
        Ok(self.native_current(&state))
    }

    fn snapshot_binding(&self) -> Result<QmpHotForkBlockSnapshotBinding, SchedulerError> {
        QmpHotForkBlockSnapshotBinding::new(
            self.request.candidate().backend_id(),
            self.request.candidate().backend_name(),
            self.request.overlay_node_name(),
            self.request.candidate().root_node_name(),
            blake3::Hash::from_bytes(self.basis().snapshot_content.bytes),
        )
        .map_err(|error| {
            hot_fork_boundary_error(format!("bind sealed current root to template: {error}",))
        })
    }
}

impl ProductionVmLifecycleLoop {
    /// Seals current root contents while retaining the exact stopped source.
    ///
    /// # Errors
    ///
    /// Returns an error when the source process, graph inventory, native hold,
    /// guarded overlay helper, or independently authenticated files differ.
    pub(super) fn prepare_sealed_hot_fork_disk(
        &mut self,
        node: &NodeId,
    ) -> Result<
        Option<(
            ProductionVmHotForkDiskCustody,
            crucible_qemu::QmpHotForkBlockSnapshotBinding,
        )>,
        SchedulerError,
    > {
        #[cfg(any(test, feature = "test-support"))]
        if self
            .node_leases
            .get(node)
            .is_some_and(|lease| lease.scripted_vmstate_only_hot_fork())
        {
            return Ok(None);
        }
        let launch = self.launch_configs.get(node).ok_or_else(|| {
            hot_fork_boundary_error(format!(
                "hot-fork node `{}` has no launch profile",
                node.name
            ))
        })?;
        if launch.root_image().is_none() {
            return Ok(None);
        }
        let root_path = launch
            .run_directory()
            .join(crucible_qemu::DEFAULT_ROOT_OVERLAY_FILE_NAME);
        let vmstate_path = launch
            .run_directory()
            .join(crucible_qemu::DEFAULT_VMSTATE_FILE_NAME);
        let boot_path = launch
            .root_image()
            .ok_or_else(|| {
                hot_fork_boundary_error("rooted hot-fork launch lost its authored boot image")
            })?
            .to_owned();
        let expected_boot = *self.immutable_root_images.get(node).ok_or_else(|| {
            hot_fork_boundary_error("rooted hot-fork node lost its authored boot-image hash")
        })?;

        let process = self
            .inner
            .backend()
            .process_identity(node)
            .map_err(|error| {
                hot_fork_boundary_error(format!("read hot-fork source process: {error}"))
            })?;
        let first = self
            .inner
            .backend_mut()
            .begin_hot_fork_disk_seal(node)
            .map_err(|error| {
                hot_fork_boundary_error(format!("pause and inventory hot-fork disk: {error}"))
            })?;
        if first.qemu_pid() != i64::from(process.process_id) || first.candidates().len() != 1 {
            return Err(hot_fork_boundary_error(
                "native disk inventory does not cover exactly the current root backend",
            ));
        }
        let candidate = first.candidates()[0].clone();
        if candidate.backend_name() != crucible_qemu::ROOT_DRIVE_ID
            || candidate.root_node_name() != crucible_qemu::ROOT_OVERLAY_NODE_NAME
            || candidate.file_path() != root_path
        {
            return Err(hot_fork_boundary_error(
                "native writable root differs from the pinned launch disk",
            ));
        }

        let overlay_node = format!("hf-root-{:x}", first.graph_mutation_generation());
        let request =
            crucible_qemu::QmpHotForkBlockSealRequest::new(candidate.clone(), overlay_node)
                .map_err(|error| {
                    hot_fork_boundary_error(format!(
                        "construct exact hot-fork root request: {error}",
                    ))
                })?;
        let lease = self.node_leases.get_mut(node).ok_or_else(|| {
            hot_fork_boundary_error("hot-fork source lost its original generation lease")
        })?;
        let (detached, detached_path) = lease
            .prepare_hot_fork_detached_root_overlay(
                first.graph_mutation_generation(),
                candidate.virtual_size(),
            )
            .map_err(|error| {
                hot_fork_boundary_error(format!(
                    "create guarded detached hot-fork overlay: {error}",
                ))
            })?;
        self.inner
            .backend_mut()
            .add_hot_fork_detached_root_overlay(node, &request, &detached_path)
            .map_err(|error| {
                hot_fork_boundary_error(format!("register detached hot-fork overlay: {error}",))
            })?;
        let held = self
            .inner
            .backend_mut()
            .hold_hot_fork_disk_seal_barrier(node)
            .map_err(|error| {
                hot_fork_boundary_error(format!("hold native block-drain barrier: {error}",))
            })?;
        if !held.held() {
            return Err(hot_fork_boundary_error(
                "native block-drain barrier did not retain its hold",
            ));
        }

        let mut current = None;
        for poll in 0..MAXIMUM_HOT_FORK_ROLLBACK_POLLS_PER_NODE {
            let state = self
                .inner
                .backend_mut()
                .query_hot_fork_disk_seal(node)
                .map_err(|error| {
                    hot_fork_boundary_error(
                        format!("query held hot-fork block inventory: {error}",),
                    )
                })?;
            if state.barrier_held() && state.barrier_quiescent() {
                current = Some(state);
                break;
            }
            if poll + 1 < MAXIMUM_HOT_FORK_ROLLBACK_POLLS_PER_NODE {
                std::thread::sleep(HOT_FORK_ROLLBACK_POLL_INTERVAL);
            }
        }
        let current = current.ok_or_else(|| {
            hot_fork_boundary_error(
                "native block-drain barrier did not become quiescent within the bounded wait",
            )
        })?;
        if current.qemu_pid() != first.qemu_pid() || current.candidates() != first.candidates() {
            return Err(hot_fork_boundary_error(
                "writable-root inventory changed before native sealing",
            ));
        }
        let sealed = self
            .inner
            .backend_mut()
            .seal_hot_fork_disk_roots(node, &current, std::slice::from_ref(&request))
            .map_err(|error| {
                hot_fork_boundary_error(
                    format!("install read-only current disk snapshot: {error}",),
                )
            })?;

        let lease = self.node_leases.get(node).ok_or_else(|| {
            hot_fork_boundary_error("sealed hot-fork source lost its original generation lease")
        })?;
        let snapshot = lease.open_checkpoint_root_overlay().map_err(|error| {
            hot_fork_boundary_error(format!("open pinned sealed current root: {error}"))
        })?;
        let vmstate = lease.open_hot_fork_vmstate().map_err(|error| {
            hot_fork_boundary_error(format!("open pinned parentless VMState: {error}"))
        })?;
        let boot = std::fs::File::open(&boot_path).map_err(|error| {
            hot_fork_boundary_error(format!("open authored boot-image backing: {error}"))
        })?;
        let custody = ProductionVmHotForkDiskCustody::capture(
            &sealed,
            &request,
            (snapshot, &root_path),
            (boot, &boot_path),
            expected_boot,
            (vmstate, &vmstate_path),
            (detached, &detached_path),
        )?;
        let latest = self
            .inner
            .backend_mut()
            .query_hot_fork_disk_seal(node)
            .map_err(|error| {
                hot_fork_boundary_error(format!("recheck retained native disk seal: {error}",))
            })?;
        if !custody.native_current(&latest)
            || !custody.current()?
            || self.inner.backend().process_identity(node).ok() != Some(process)
        {
            return Err(hot_fork_boundary_error(
                "sealed disk basis changed before template preparation",
            ));
        }
        let binding = custody.snapshot_binding()?;
        Ok(Some((custody, binding)))
    }
}

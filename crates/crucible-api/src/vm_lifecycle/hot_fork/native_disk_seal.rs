//! Native disk-seal adapter for the production lifecycle transaction.
//!
//! This concrete adapter retains the typed socket receipt and original request,
//! binds them to the live process and generation lease, and passes authenticated
//! identities to the independent file-custody owner. It owns no emulator code.

use super::disk_basis::{NativeDiskSealIdentity, PinnedHotForkDiskFiles};
use super::*;
use crucible_qemu::{
    QmpHotForkBlockSealRequest, QmpHotForkBlockSealState, QmpHotForkBlockSnapshotBinding,
    QmpHotForkSourceGraphReceipt,
};
use std::fs::File;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// Native seal request and independently authenticated open file custody.
pub(super) struct ProductionVmHotForkDiskCustody {
    source_process: QemuProcessIdentity,
    source_generation: ProductionVmNodeGeneration,
    request: QmpHotForkBlockSealRequest,
    files: PinnedHotForkDiskFiles,
}

impl ProductionVmHotForkDiskCustody {
    fn capture(
        source: (QemuProcessIdentity, ProductionVmNodeGeneration),
        seal: (&QmpHotForkBlockSealState, &QmpHotForkBlockSealRequest),
        snapshot: (File, &Path),
        boot: (File, &Path),
        expected_boot: ContentHash,
        vmstate: (File, &Path),
        detached: (File, &Path),
    ) -> Result<Self, SchedulerError> {
        let (source_process, source_generation) = source;
        let (receipt, request) = seal;
        if receipt.qemu_pid() != i64::from(source_process.process_id)
            || !receipt.seals(std::slice::from_ref(request))
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
            source_process,
            source_generation,
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

    fn source_identity_current(
        &self,
        process: Option<&QemuProcessIdentity>,
        generation: Option<&ProductionVmNodeGeneration>,
    ) -> bool {
        process == Some(&self.source_process) && generation == Some(&self.source_generation)
    }

    /// Authenticates the complete frozen native graph before child-file planning.
    ///
    /// # Errors
    ///
    /// Returns an error when original process or lease identity, graph roots or edges,
    /// or independently retained regular-file contents differ.
    pub(super) fn authenticate_source_graph(
        &self,
        lifecycle: &mut ProductionVmLifecycleLoop,
        node: &NodeId,
        template_generation: u64,
    ) -> Result<(), SchedulerError> {
        if !self.source_identity_current(
            lifecycle
                .inner
                .backend()
                .process_identity(node)
                .ok()
                .as_ref(),
            lifecycle
                .node_leases
                .get(node)
                .map(|lease| lease.identity()),
        ) {
            return Err(hot_fork_boundary_error(
                "original graph source process or lease is no longer current",
            ));
        }
        let graph = lifecycle
            .inner
            .backend_mut()
            .query_hot_fork_source_graph(
                node,
                i64::from(self.source_process.process_id),
                template_generation,
            )
            .map_err(|error| {
                hot_fork_boundary_error(format!(
                    "authenticate original frozen source graph: {error}"
                ))
            })?;
        self.authenticate_graph_receipt(&graph)?;
        if !self.source_identity_current(
            lifecycle
                .inner
                .backend()
                .process_identity(node)
                .ok()
                .as_ref(),
            lifecycle
                .node_leases
                .get(node)
                .map(|lease| lease.identity()),
        ) {
            return Err(hot_fork_boundary_error(
                "original graph source process or lease changed during authentication",
            ));
        }
        Ok(())
    }

    fn authenticate_graph_receipt(
        &self,
        graph: &QmpHotForkSourceGraphReceipt,
    ) -> Result<(), SchedulerError> {
        authenticate_graph_edges(
            graph,
            self.basis(),
            self.request.overlay_node_name(),
            self.request.candidate().root_node_name(),
        )?;
        // Format nodes and every incoming edge remain in the closed receipt;
        // file identity, writable disposition and full bytes are checked from
        // the host's independently admitted descriptions rather than paths.
        let files = graph
            .members
            .iter()
            .filter(|member| member.file_backed)
            .map(|member| {
                (
                    (member.file_device, member.file_inode),
                    member.file_size,
                    member.file_sha256.as_str(),
                    member.originally_writable_file,
                )
            })
            .collect::<Vec<_>>();
        self.files.authenticate_graph_files(&files)?;
        Ok(())
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
    /// Reacquires a recovered source by physically sealing its current overlay.
    ///
    /// The old receipt retired only after native restore and barrier release.
    /// Original process, generation, immutable ancestors and the current open
    /// overlay remain owned throughout a fresh native seal and new PREPARE.
    ///
    /// # Errors
    ///
    /// Returns an error when original ownership changed or native retirement,
    /// fresh sealing, or independent ancestor authentication cannot be proven.
    pub(super) fn reacquire_sealed_hot_fork_disk(
        &mut self,
        node: &NodeId,
        prior: &ProductionVmHotForkDiskCustody,
    ) -> Result<
        (
            ProductionVmHotForkDiskCustody,
            QmpHotForkBlockSnapshotBinding,
        ),
        SchedulerError,
    > {
        if self
            .node_leases
            .get(node)
            .is_none_or(|lease| lease.identity() != &prior.source_generation)
            || self.inner.backend().process_identity(node).ok().as_ref()
                != Some(&prior.source_process)
            || !prior.current()?
        {
            return Err(hot_fork_boundary_error(
                "recovered source lost its original process, generation or disk custody",
            ));
        }
        self.prepare_sealed_hot_fork_disk_with_prior(node, Some(prior))?
            .ok_or_else(|| {
                hot_fork_boundary_error("recovered rooted source lost its physical disk authority")
            })
    }

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
        self.prepare_sealed_hot_fork_disk_with_prior(node, None)
    }

    fn prepare_sealed_hot_fork_disk_with_prior(
        &mut self,
        node: &NodeId,
        prior: Option<&ProductionVmHotForkDiskCustody>,
    ) -> Result<
        Option<(
            ProductionVmHotForkDiskCustody,
            QmpHotForkBlockSnapshotBinding,
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
        let root_path = prior.map_or_else(
            || {
                launch
                    .run_directory()
                    .join(crucible_qemu::DEFAULT_ROOT_OVERLAY_FILE_NAME)
            },
            |custody| custody.basis().detached_path.clone(),
        );
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
        let original_root = match prior {
            Some(custody) => custody.files.open_current_overlay()?,
            None => self
                .node_leases
                .get(node)
                .ok_or_else(|| {
                    hot_fork_boundary_error("source lost its original generation lease")
                })?
                .open_checkpoint_root_overlay()
                .map_err(|error| {
                    hot_fork_boundary_error(format!("open original generation root: {error}"))
                })?,
        };
        let original_identity = original_root.metadata().map_err(|error| {
            hot_fork_boundary_error(format!("inspect original launch root: {error}"))
        })?;
        if candidate.backend_name() != crucible_qemu::ROOT_DRIVE_ID
            || prior.is_some_and(|custody| {
                candidate.root_node_name() != custody.request.overlay_node_name()
                    || candidate.backend_id() != custody.basis().backend_id
                    || first.receipt_generation() != 0
            })
            || !original_identity.is_file()
            || candidate.file_identity() != (original_identity.dev(), original_identity.ino())
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
        let detached_name = lease
            .authenticate_hot_fork_overlay_name(process.process_id, &detached, &detached_path)
            .map_err(|error| {
                hot_fork_boundary_error(format!("bind detached overlay to original cwd: {error}"))
            })?;
        self.inner
            .backend_mut()
            .add_hot_fork_detached_root_overlay(node, &request, &detached_name)
            .map_err(|error| {
                hot_fork_boundary_error(format!("register detached hot-fork overlay: {error}",))
            })?;
        self.node_leases
            .get(node)
            .ok_or_else(|| hot_fork_boundary_error("source lost its original generation lease"))?
            .authenticate_hot_fork_overlay_name(process.process_id, &detached, &detached_path)
            .map_err(|error| {
                hot_fork_boundary_error(format!("recheck detached overlay binding: {error}"))
            })?;
        if self.inner.backend().process_identity(node).ok() != Some(process.clone()) {
            return Err(hot_fork_boundary_error(
                "source process changed during detached overlay admission",
            ));
        }
        // Sealing changes the block graph, so its writer barrier must remain
        // unheld. The native transaction drains and flushes the stopped source,
        // revalidates these generations, and retains its own barrier only after
        // the fresh overlays and read-only snapshots are installed.
        let current = self
            .inner
            .backend_mut()
            .query_hot_fork_disk_seal(node)
            .map_err(|error| {
                hot_fork_boundary_error(format!(
                    "refresh stopped hot-fork block inventory: {error}"
                ))
            })?;
        if current.qemu_pid() != first.qemu_pid()
            || current.candidates() != first.candidates()
            || current.barrier_held()
            || current.receipt_generation() != 0
        {
            return Err(hot_fork_boundary_error(
                "stopped writable-root inventory changed or already retains a native seal",
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
        let snapshot = original_root;
        let vmstate = lease.open_hot_fork_vmstate().map_err(|error| {
            hot_fork_boundary_error(format!("open pinned parentless VMState: {error}"))
        })?;
        let boot = std::fs::File::open(&boot_path).map_err(|error| {
            hot_fork_boundary_error(format!("open authored boot-image backing: {error}"))
        })?;
        let mut custody = ProductionVmHotForkDiskCustody::capture(
            (process.clone(), lease.identity().clone()),
            (&sealed, &request),
            (snapshot, &root_path),
            (boot, &boot_path),
            expected_boot,
            (vmstate, &vmstate_path),
            (detached, &detached_path),
        )?;
        if let Some(prior) = prior {
            custody.files.retain_prior_backings(&prior.files)?;
        } else if let Some(backings) = self.hot_fork_backing_files.get(node) {
            custody.files.retain_adopted_backings(backings)?;
        }
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

pub(super) fn authenticate_graph_edges(
    graph: &QmpHotForkSourceGraphReceipt,
    basis: &ProductionVmHotForkDiskBasis,
    overlay_node: &str,
    snapshot_node: &str,
) -> Result<(), SchedulerError> {
    let malformed = || {
        hot_fork_boundary_error(
            "complete native graph differs from admitted disk roots or backing edges",
        )
    };
    let roots = graph
        .members
        .iter()
        .filter(|member| member.parent_index == -1)
        .collect::<Vec<_>>();
    if roots.len() != 2 {
        return Err(malformed());
    }
    let root = roots
        .iter()
        .find(|member| member.backend_id == basis.backend_id)
        .ok_or_else(malformed)?;
    let vmstate = roots
        .iter()
        .find(|member| {
            member.backend_id == 0
                && member.root_node_name == crucible_qemu::DEFAULT_VMSTATE_NODE_NAME
        })
        .ok_or_else(malformed)?;
    if root.backend_name != crucible_qemu::ROOT_DRIVE_ID
        || root.node_name != overlay_node
        || root.driver_name != "qcow2"
        || vmstate.driver_name != "qcow2"
    {
        return Err(malformed());
    }

    let mut expected = vec![basis.detached_identity, basis.snapshot_identity];
    expected.extend(basis.backing_files.iter().map(|file| file.identity));
    expected.push(basis.boot_identity);
    authenticate_linear_root(graph, root.root_index, &expected, Some(snapshot_node))?;
    authenticate_linear_root(graph, vmstate.root_index, &[basis.vmstate_identity], None)?;
    Ok(())
}

fn authenticate_linear_root(
    graph: &QmpHotForkSourceGraphReceipt,
    root_index: u64,
    expected_files: &[(u64, u64)],
    snapshot_node: Option<&str>,
) -> Result<(), SchedulerError> {
    let malformed = || {
        hot_fork_boundary_error("native disk edge no longer binds its independently admitted inode")
    };
    let members = graph
        .members
        .iter()
        .filter(|member| member.root_index == root_index)
        .collect::<Vec<_>>();
    if members.len() != expected_files.len() * 2 {
        return Err(malformed());
    }
    let mut format = *members.first().ok_or_else(malformed)?;
    for (index, identity) in expected_files.iter().enumerate() {
        if format.file_backed
            || !matches!(format.driver_name.as_str(), "qcow2" | "raw")
            || (index == 1 && snapshot_node.is_some_and(|name| format.node_name != name))
        {
            return Err(malformed());
        }
        let children = members
            .iter()
            .copied()
            .filter(|member| member.parent_index == format.node_index as i64)
            .collect::<Vec<_>>();
        let file = children
            .iter()
            .find(|member| member.edge_name == "file")
            .ok_or_else(malformed)?;
        if !file.file_backed
            || file.driver_name != "file"
            || (file.file_device, file.file_inode) != *identity
            || file.originally_writable_file != (index == 0)
            || children
                .iter()
                .any(|member| !matches!(member.edge_name.as_str(), "file" | "backing"))
        {
            return Err(malformed());
        }
        if index + 1 == expected_files.len() {
            if children.len() != 1 {
                return Err(malformed());
            }
        } else {
            if format.driver_name != "qcow2" || children.len() != 2 {
                return Err(malformed());
            }
            format = children
                .iter()
                .find(|member| member.edge_name == "backing")
                .copied()
                .ok_or_else(malformed)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn graph_for_basis(
        basis: &ProductionVmHotForkDiskBasis,
    ) -> Result<QmpHotForkSourceGraphReceipt, serde_json::Error> {
        let members = [
            (0, 0, -1, "overlay", "", "qcow2", 0),
            (0, 1, 0, "", "file", "file", 14),
            (0, 2, 0, "snapshot", "backing", "qcow2", 0),
            (0, 3, 2, "", "file", "file", 11),
            (0, 4, 2, "boot", "backing", "raw", 0),
            (0, 5, 4, "", "file", "file", 12),
            (1, 0, -1, "vmstate", "", "qcow2", 0),
            (1, 1, 0, "", "file", "file", 13),
        ]
        .into_iter()
        .map(|(root, node, parent, name, edge, driver, inode)| {
            let identity = match inode {
                11 => basis.snapshot_identity,
                12 => basis.boot_identity,
                13 => basis.vmstate_identity,
                14 => basis.detached_identity,
                _ => (0, 0),
            };
            json!({
                "root-index": root,
                "node-index": node,
                "parent-index": parent,
                "backend-id": if root == 0 { basis.backend_id } else { 0 },
                "backend-name": if root == 0 { crucible_qemu::ROOT_DRIVE_ID } else { "" },
                "root-node-name": if root == 0 { "overlay" } else { "vmstate" },
                "node-name": name,
                "edge-name": edge,
                "driver-name": driver,
                "file-backed": inode != 0,
                "originally-writable-file": inode == 13 || inode == 14,
                "file-path": "",
                "file-device": identity.0,
                "file-inode": identity.1,
                "file-size": 0,
                "file-sha256": if inode == 0 { String::new() } else { "0".repeat(64) },
            })
        })
        .collect::<Vec<_>>();
        serde_json::from_value(json!({
            "schema-version": 1, "qemu-pid": 451, "template-generation": 7,
            "runstate-generation": 1, "vmstop-generation": 1, "vmstop-request-generation": 1,
            "barrier-generation": 1, "graph-barrier-generation": 1, "graph-mutation-generation": 1,
            "snapshot-generation": 1, "backend-generation": 1, "root-count": 2, "node-count": 8, "members": members,
        }))
    }

    #[test]
    fn graph_edges_bind_both_writable_roots_and_each_readonly_backing()
    -> Result<(), Box<dyn std::error::Error>> {
        let basis = ProductionVmHotForkDiskBasis {
            source_pid: 451,
            seal_generation: 1,
            backend_id: 2,
            snapshot_path: "snapshot".into(),
            snapshot_identity: (1, 11),
            snapshot_content: ContentHash::from_bytes(b"snapshot"),
            boot_path: "boot".into(),
            boot_identity: (1, 12),
            boot_content: ContentHash::from_bytes(b"boot"),
            vmstate_path: "vmstate".into(),
            vmstate_identity: (1, 13),
            vmstate_content: ContentHash::from_bytes(b"vmstate"),
            detached_path: "overlay".into(),
            detached_identity: (1, 14),
            detached_content: ContentHash::from_bytes(b"overlay"),
            backing_files: Vec::new(),
        };
        let graph = graph_for_basis(&basis)?;
        authenticate_graph_edges(&graph, &basis, "overlay", "snapshot")?;
        let mut swapped = graph.clone();
        swapped.members[1].file_inode = 13;
        swapped.members[7].file_inode = 14;
        assert!(authenticate_graph_edges(&swapped, &basis, "overlay", "snapshot").is_err());
        let mut wrong_edge = graph.clone();
        wrong_edge.members[2].edge_name = "foreign".into();
        assert!(authenticate_graph_edges(&wrong_edge, &basis, "overlay", "snapshot").is_err());
        let mut swapped_backings = graph.clone();
        swapped_backings.members[3].file_inode = 12;
        swapped_backings.members[5].file_inode = 11;
        assert!(
            authenticate_graph_edges(&swapped_backings, &basis, "overlay", "snapshot").is_err()
        );
        let mut omitted = graph.clone();
        omitted.members.remove(5);
        assert!(authenticate_graph_edges(&omitted, &basis, "overlay", "snapshot").is_err());
        Ok(())
    }

    #[test]
    fn frozen_graph_retains_original_custody_without_a_writable_seal()
    -> Result<(), Box<dyn std::error::Error>> {
        use sha2::{Digest, Sha256};

        let directory = tempfile::tempdir()?;
        let paths =
            ["snapshot", "boot", "vmstate", "overlay"].map(|name| directory.path().join(name));
        let bytes = [b"snapshot".as_slice(), b"boot", b"vmstate", b"overlay"];
        for (path, contents) in paths.iter().zip(bytes) {
            std::fs::write(path, contents)?;
        }
        let snapshot = File::open(&paths[0])?;
        let metadata = snapshot.metadata()?;
        let candidate: crucible_qemu::QmpHotForkBlockSealCandidate =
            serde_json::from_value(json!({
                "backend-id": 2,
                "backend-name": crucible_qemu::ROOT_DRIVE_ID,
                "root-node-name": "snapshot",
                "file-path": paths[0],
                "file-device": metadata.dev(),
                "file-inode": metadata.ino(),
                "virtual-size": 4096,
            }))?;
        let request = QmpHotForkBlockSealRequest::new(candidate, "overlay")?;
        let sealed: QmpHotForkBlockSealState = serde_json::from_value(json!({
            "schema-version": 1,
            "qemu-pid": 451,
            "receipt-generation": 1,
            "backend-generation": 1,
            "graph-mutation-generation": 1,
            "barrier-held": true,
            "barrier-generation": 1,
            "barrier-quiescent": true,
            "candidates": [],
            "sealed-roots": [{
                "backend-id": 2,
                "backend-name": crucible_qemu::ROOT_DRIVE_ID,
                "overlay-node-name": "overlay",
                "snapshot-node-name": "snapshot",
                "snapshot-file-path": paths[0],
                "snapshot-file-device": metadata.dev(),
                "snapshot-file-inode": metadata.ino(),
                "virtual-size": 4096,
                "overlay-empty": true,
                "snapshot-read-only": true,
            }],
        }))?;
        let process = QemuProcessIdentity {
            process_id: 451,
            start_time_ticks: 37,
            executable: "qemu-system-test".into(),
        };
        let node = NodeId {
            name: "router-a".into(),
        };
        let generation = ProductionVmNodeGeneration::new(node.clone(), 1)?;
        let custody = ProductionVmHotForkDiskCustody::capture(
            (process.clone(), generation.clone()),
            (&sealed, &request),
            (snapshot, &paths[0]),
            (File::open(&paths[1])?, &paths[1]),
            ContentHash::from_bytes(bytes[1]),
            (File::open(&paths[2])?, &paths[2]),
            (File::open(&paths[3])?, &paths[3]),
        )?;
        let mut graph = graph_for_basis(custody.basis())?;
        for (index, path) in [1, 3, 5, 7]
            .into_iter()
            .zip([&paths[3], &paths[0], &paths[1], &paths[2]])
        {
            let contents = std::fs::read(path)?;
            graph.members[index].file_size = contents.len() as u64;
            graph.members[index].file_sha256 = Sha256::digest(&contents)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
        }

        // Freezing retires the writable disposition, while the original seal,
        // stopped template graph and independently pinned inodes remain owned.
        let readonly: QmpHotForkBlockSealState = serde_json::from_value(json!({
            "schema-version": 1,
            "qemu-pid": 451,
            "receipt-generation": 0,
            "backend-generation": 2,
            "graph-mutation-generation": 2,
            "barrier-held": true,
            "barrier-generation": 1,
            "barrier-quiescent": true,
            "candidates": [],
            "sealed-roots": [],
        }))?;
        assert!(custody.native_current(&sealed));
        assert!(!custody.native_current(&readonly));
        assert!(custody.source_identity_current(Some(&process), Some(&generation)));
        assert!(custody.current()?);
        custody.authenticate_graph_receipt(&graph)?;

        let mut stale_process = process.clone();
        stale_process.start_time_ticks += 1;
        let stale_generation = ProductionVmNodeGeneration::new(node, 2)?;
        assert!(!custody.source_identity_current(Some(&stale_process), Some(&generation)));
        assert!(!custody.source_identity_current(Some(&process), Some(&stale_generation)));
        assert!(!custody.source_identity_current(None, Some(&generation)));
        assert!(!custody.source_identity_current(Some(&process), None));

        let mut changed_edge = graph.clone();
        changed_edge.members[2].edge_name = "foreign".into();
        assert!(custody.authenticate_graph_receipt(&changed_edge).is_err());
        let mut changed_digest = graph.clone();
        changed_digest.members[3].file_sha256 = "0".repeat(64);
        assert!(custody.authenticate_graph_receipt(&changed_digest).is_err());
        std::fs::write(&paths[0], b"tampered!")?;
        assert!(!custody.current()?);
        assert!(custody.authenticate_graph_receipt(&graph).is_err());
        Ok(())
    }
}

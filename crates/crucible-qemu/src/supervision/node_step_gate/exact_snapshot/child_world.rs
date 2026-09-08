//! Live hot-fork child world: several sources forked into children that are
//! alive together, each executing a quantum its oracles must reproduce.
//!
//! Each source runs under its own delegated cgroup subroot, in its own
//! project-quota namespace, and under its own run root, since one attempt
//! host locks the cgroup root it is opened on. The flight captures every
//! source first, then forks every
//! child before any of them executes, proves all the children are alive at
//! once, and only then executes and compares each child in turn through the
//! single-source phases. The sources do not exchange traffic; this is the
//! coexistence half of a whole-world fork, not the atomic transaction the
//! daemon's world assembly owns.

use std::fs;
use std::os::unix::fs::DirBuilderExt as _;
use std::path::Path;

use super::child_execution::{
    InstalledChild, QemuLiveHotForkChildExecutionReport, capture_source, execute_and_compare,
    fork_and_install_child,
};
use super::child_files::{FIRST_PROJECT_ID, PROJECT_ID_COUNT, SourcePlacement, invariant};
use super::*;

/// Records a world of children forked from independent sources.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuLiveHotForkChildWorldReport {
    /// Sources captured and forked.
    pub node_count: u32,
    /// Children found alive at the same time after every fork.
    pub children_alive_together: u32,
    /// Each child's execution comparison, in source order.
    pub nodes: Vec<QemuLiveHotForkChildExecutionReport>,
}

/// Forks `node_count` independent sources into children that are alive
/// together, then executes and compares each child.
///
/// # Errors
///
/// Returns [`QemuLiveNodeStepGateError`] when `node_count` is zero, the
/// configuration carries a disk or mediated block device, any source's
/// capture, fork, installation, execution, restore, comparison, or cleanup
/// fails, or a forked child is not alive once every fork has completed.
pub fn run_qemu_live_hot_fork_child_world_gate(
    config: &QemuLiveNodeStepGateConfig,
    cgroup_root: &Path,
    run_root: &Path,
    node_count: u32,
) -> Result<QemuLiveHotForkChildWorldReport, QemuLiveNodeStepGateError> {
    if node_count == 0 {
        return Err(invariant("a child world needs at least one source"));
    }

    // Every source stands captured with its template retained before any
    // child exists.
    let mut captured = Vec::with_capacity(node_count as usize);
    for index in 0..node_count {
        let namespace = format!("hot-fork-world-{index}");
        // The attempt host authenticates an exact-owner private directory.
        let node_root = run_root.join(format!("node-{index}"));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&node_root)
            .map_err(|source| QemuLiveNodeStepGateError::PrepareRunDirectory {
                path: node_root.clone(),
                source,
            })?;
        let placement = SourcePlacement {
            namespace: &namespace,
            first_project_id: FIRST_PROJECT_ID
                .saturating_add(index.saturating_mul(PROJECT_ID_COUNT)),
            run_root: &node_root,
        };
        let node_cgroup = delegate_cgroup_subroot(cgroup_root, index)?;
        captured.push((
            capture_source(config, &node_cgroup, placement)?,
            node_cgroup,
        ));
    }

    // Every child is forked and installed before any executes.
    let mut installed: Vec<InstalledChild> = Vec::with_capacity(captured.len());
    for (source, node_cgroup) in captured {
        installed.push(fork_and_install_child(source, config, &node_cgroup)?);
    }
    let children_alive_together = installed
        .iter()
        .filter(|child| process_is_alive(child.child_process_id()))
        .count();
    let children_alive_together = u32::try_from(children_alive_together)
        .map_err(|_error| invariant("child count overflowed"))?;
    if children_alive_together != node_count {
        return Err(invariant(&format!(
            "only {children_alive_together} of {node_count} forked children were alive together"
        )));
    }

    let mut nodes = Vec::with_capacity(installed.len());
    for child in installed {
        nodes.push(execute_and_compare(child, config)?);
    }

    Ok(QemuLiveHotForkChildWorldReport {
        node_count,
        children_alive_together,
        nodes,
    })
}

/// Creates a delegated cgroup subroot for one source with the controllers
/// the attempt host enforces enabled for its children.
fn delegate_cgroup_subroot(
    cgroup_root: &Path,
    index: u32,
) -> Result<std::path::PathBuf, QemuLiveNodeStepGateError> {
    let subroot = cgroup_root.join(format!("world-{index}"));
    fs::create_dir(&subroot).map_err(|source| QemuLiveNodeStepGateError::PrepareRunDirectory {
        path: subroot.clone(),
        source,
    })?;
    let control = subroot.join("cgroup.subtree_control");
    fs::write(&control, "+cpu +memory +pids").map_err(|source| {
        QemuLiveNodeStepGateError::PrepareRunDirectory {
            path: control,
            source,
        }
    })?;
    Ok(subroot)
}

/// Whether the process still exists and is not a zombie.
fn process_is_alive(process_id: u32) -> bool {
    fs::read_to_string(format!("/proc/{process_id}/status"))
        .map(|status| {
            status
                .lines()
                .find_map(|line| line.strip_prefix("State:"))
                .is_some_and(|state| !state.trim_start().starts_with('Z'))
        })
        .unwrap_or(false)
}

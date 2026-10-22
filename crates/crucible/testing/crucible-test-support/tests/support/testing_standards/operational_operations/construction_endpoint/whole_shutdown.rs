//! Binds whole-node destruction to the same private lifecycle lease set.
//!
//! The digest corroborates generation identity; actual phase and value return
//! remain mandatory. Every production map-changing route invalidates the phase.

use super::super::Companion;

pub(super) const DAEMON: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/vm_lifecycle/quantum_loop/whole_shutdown.rs",
    required: &[(
        r#"use super::*;
impl ProductionVmLifecycleLoop {
    fn whole_shutdown_binding(&self) -> ContentHash {
        let mut hash = blake3::Hasher::new();
        hash.update(b"crucible.whole-node-shutdown-generations.v1\0");
        for (node, generation) in &self.node_generations {
            hash.update(&node.name.len().to_be_bytes());
            hash.update(node.name.as_bytes());
            hash.update(&generation.to_be_bytes());
        }
        ContentHash::from_bytes(hash.finalize().as_bytes())
    }
    pub(in crate::vm_lifecycle) fn prepare_whole_node_shutdown(
        &mut self,
    ) -> Result<ContentHash, SchedulerError> {
        for (node, lease) in &self.node_leases {
            let generation = self.node_generations.get(node).ok_or_else(|| {
                SchedulerError::BoundaryViolation {
                    message: format!("whole shutdown node `{}` has no generation", node.name),
                }
            })?;
            if lease.identity().node() != node || lease.identity().generation() != *generation {
                return Err(SchedulerError::BoundaryViolation {
                    message: format!("whole shutdown node `{}` has a foreign lease", node.name),
                });
            }
        }
        let binding = self.whole_shutdown_binding();
        self.inner.backend_mut()
            .prepare_whole_shutdown(binding, self.node_leases.keys())?;
        Ok(binding)
    }
    pub(in crate::vm_lifecycle) fn finish_whole_node_leases(
        &mut self,
        binding: ContentHash,
    ) -> Result<(), SchedulerError> {
        if binding != self.whole_shutdown_binding() {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("whole shutdown generation binding changed"),
            });
        }
        if self.node_leases.is_empty() { return Ok(()); }
        self.inner.backend().verify_whole_shutdown_return(binding)?;
        let nodes = self.node_leases.keys().cloned().collect::<Vec<_>>();
        let result = finish_reaped_node_lease_map(&self.node_generations, &mut self.node_leases, &nodes);
        if result.is_err() { self.node_lease_cleanup_failed = true; }
        result
    }
}"#,
        1,
    )],
};

pub(super) const HOST: Companion = Companion {
    path: "crates/crucible/qemu/crucible-qemu-host/src/node_set/whole_shutdown.rs",
    required: &[(
        r#"use super::*;
use crucible_engine::ContentHash;
#[derive(Debug)]
pub(super) enum WholeShutdown {
    Unarmed,
    Armed(ContentHash),
    Destructing,
    Returned(ContentHash),
    Invalidated,
}
impl QemuNodeSet {
    pub fn prepare_whole_shutdown<'a>(
        &mut self,
        binding: ContentHash,
        leased_nodes: impl IntoIterator<Item = &'a NodeId>,
    ) -> Result<(), BackendError> {
        match &self.whole_shutdown {
            WholeShutdown::Armed(saved) | WholeShutdown::Returned(saved) if *saved == binding => {
                return Ok(());
            }
            WholeShutdown::Unarmed => {}
            _ => return Err(whole_shutdown_error()),
        }
        for node in leased_nodes {
            if !self.nodes.contains_key(node) {
                return Err(BackendError::Rejected {
                    message: format!("whole shutdown has no authoritative node `{}`", node.name),
                });
            }
        }
        if !self.nodes.is_empty() {
            self.whole_shutdown = WholeShutdown::Armed(binding);
        }
        Ok(())
    }
    pub fn verify_whole_shutdown_return(&self, binding: ContentHash) -> Result<(), BackendError> {
        match &self.whole_shutdown {
            WholeShutdown::Returned(saved) if *saved == binding => Ok(()),
            _ => Err(whole_shutdown_error()),
        }
    }
    pub(super) fn invalidate_whole_shutdown(&mut self) {
        if matches!(self.whole_shutdown, WholeShutdown::Armed(_) | WholeShutdown::Returned(_)) {
            self.whole_shutdown = WholeShutdown::Invalidated;
        }
    }
    fn validate_whole_shutdown_cleanup(&self) -> Result<(), BackendError> {
        self.check_whole_shutdown_entry()?;
        match &self.whole_shutdown {
            WholeShutdown::Armed(_)
                if self.nodes.values().any(|node| !node.cleanup_physically_returned()) =>
            { Err(whole_shutdown_error()) }
            _ => Ok(()),
        }
    }
    pub(super) fn check_whole_shutdown_entry(&self) -> Result<(), BackendError> {
        if matches!(self.whole_shutdown, WholeShutdown::Destructing) {
            Err(whole_shutdown_error())
        } else { Ok(()) }
    }
    pub(super) fn clear_nodes_after_shutdown(&mut self) -> Result<(), BackendError> {
        self.validate_whole_shutdown_cleanup()?;
        let prior = std::mem::replace(&mut self.whole_shutdown, WholeShutdown::Destructing);
        self.nodes.clear();
        self.whole_shutdown = match prior {
            WholeShutdown::Armed(binding) => WholeShutdown::Returned(binding),
            prior => prior,
        };
        Ok(())
    }
}
fn whole_shutdown_error() -> BackendError {
    BackendError::Rejected {
        message: String::from("whole-node shutdown custody is absent, changed or not returned"),
    }
}
#[cfg(all(test, target_os = "linux"))]
#[path = "whole_shutdown/tests.rs"]
mod tests;"#,
        1,
    )],
};

pub(super) const HOST_CALLERS: Companion = Companion {
    path: "crates/crucible/qemu/crucible-qemu-host/src/node_set.rs",
    required: &[
        (
            r#"nodes: BTreeMap<NodeId, QemuNode>, whole_shutdown: whole_shutdown::WholeShutdown,"#,
            1,
        ),
        (
            r#"pub fn insert(&mut self, node: NodeId, backend: QemuNode) -> Option<QemuNode> {
    self.invalidate_whole_shutdown();
    self.permanently_closed.retain(|closed| closed != &node);
    self.parked_campaign_markers.remove(&node);
    self.nodes.insert(node, backend)
}"#,
            1,
        ),
        (
            r#"pub fn take(&mut self, node: &NodeId) -> Option<QemuNode> {
    self.invalidate_whole_shutdown();
    self.parked_campaign_markers.remove(node);
    self.nodes.remove(node)
}"#,
            1,
        ),
        (
            r#"let mut owned = Vec::with_capacity(operations.len());
self.invalidate_whole_shutdown();
for (node, data) in operations {
    let backend = self.nodes.remove(&node)"#,
            1,
        ),
        (
            r#"pub fn release_reaped_nodes(&mut self) -> Result<(), BackendError> {
    self.check_whole_shutdown_entry()?;
    if let Some((node, _backend)) = self.nodes.iter().find(|(_node, backend)| !backend.child_reaped()) {
        return Err(BackendError::Rejected {
            message: format!("cannot release modeled node `{}` before terminal reap", node.name),
        });
    }
    let mut first = None;
    for backend in self.nodes.values_mut() {
        if let Err(error) = SimulationBackend::shutdown(backend) && first.is_none() {
            first = Some(error);
        }
    }
    if let Some(first) = first { return Err(first); }
    self.clear_nodes_after_shutdown()?;
    Ok(())
}"#,
            1,
        ),
        (
            r#"fn shutdown(&mut self) -> Result<(), BackendError> {
    self.check_whole_shutdown_entry()?;
    let mut first_error = None;
    for (id, node) in &mut self.nodes {
        if self.permanently_closed.contains(id) { continue; }
        if let Err(error) = SimulationBackend::shutdown(node) && first_error.is_none() {
            first_error = Some(error);
        }
    }
    if let Some(error) = first_error { return Err(error); }
    self.clear_nodes_after_shutdown()?;
    Ok(())
}"#,
            1,
        ),
    ],
};

pub(super) const HOST_LIFECYCLE: Companion = Companion {
    path: "crates/crucible/qemu/crucible-qemu-host/src/node_set/lifecycle.rs",
    required: &[
        (
            r#"pub fn quarantine_terminal_lifecycle_work(
    &mut self,
    decisions: &[QemuNodeLifecycleDecision],
    boot_requests: &[NodeId],
) -> Result<(), BackendError> {
    self.invalidate_whole_shutdown();"#,
            1,
        ),
        (
            r#"pub fn quarantine_terminal_lifecycle_intents(
    &mut self,
    intents: &[QemuNodeLifecycleIntent],
) -> Result<(), BackendError> {
    self.invalidate_whole_shutdown();"#,
            1,
        ),
        (
            r#"pub fn commit_terminal_replacements(
    &mut self,
    mut plan: QemuNodeTerminalReplacementPlan,
    replacements: &mut Vec<Option<QemuNode>>,
) -> Result<Vec<(NodeId, QemuNode)>, BackendError> {
    if plan.nodes.len() != replacements.len()
        || !plan.nodes.iter().all(|node| {
            self.nodes.get(node).is_some_and(QemuNode::cleanup_physically_returned)
        })
    {
        return Err(BackendError::Rejected {
            message: String::from("terminal commit differs from the validated whole-node return",),
        });
    }
    self.invalidate_whole_shutdown();
    for (node, replacement) in plan.nodes.into_iter().zip(replacements.drain(..)) {
        match replacement {
            Some(replacement) => {
                let current = self.nodes.get_mut(&node)
                    .map(|current| std::mem::replace(current, replacement));
                debug_assert!(current.is_some());
                self.permanently_closed.retain(|closed| closed != &node);
                if let Some(current) = current { plan.retired.push((node, current)); }
            }
            None => {
                let current = self.nodes.remove_entry(&node);
                debug_assert!(current.is_some());
                if let Some(current) = current { plan.retired.push(current); }
                self.permanently_closed.push(node);
            }
        }
    }
    Ok(plan.retired)
}"#,
            1,
        ),
    ],
};

pub(super) const HOST_CONCURRENT: Companion = Companion {
    path: "crates/crucible/qemu/crucible-qemu-host/src/node_set/concurrent.rs",
    required: &[
        (
            r#"self.invalidate_whole_shutdown();
fingerprint_selected_nodes(&mut self.nodes, &selected, maximum_workers, |backend, node| backend.fingerprint(node),)"#,
            1,
        ),
        (
            r#"self.invalidate_whole_shutdown();
self.arm_concurrent_fault_event_staging(&runs)?;"#,
            1,
        ),
    ],
};

pub(super) const HOST_INITIALIZATION: Companion = Companion {
    path: "crates/crucible/qemu/crucible-qemu-host/src/node_set/collection.rs",
    required: &[(
        r#"pub const fn new() -> Self {
    Self {
        nodes: BTreeMap::new(),
        whole_shutdown: super::whole_shutdown::WholeShutdown::Unarmed,"#,
        1,
    )],
};

pub(super) const DAEMON_COMMIT: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/vm_lifecycle/quantum_loop.rs",
    required: &[(
        r#"let retired = self.inner.backend_mut()
    .commit_terminal_replacements(plan, replacement_values)?;
self.failed_host_io = committed_failed_host_io;
self.node_lease_cleanup_failed = true;
while let Some((node, lease)) = replacement_leases.pop_first() {
    let previous = self.node_leases.insert(node, lease);
    debug_assert!(previous.is_none());
}"#,
        1,
    )],
};

pub(super) const LEASE_RETURN: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/vm_lifecycle.rs",
    required: &[(
        r#"fn finish_reaped_node_lease_map(
    node_generations: &BTreeMap<NodeId, u64>,
    node_leases: &mut BTreeMap<NodeId, Box<dyn ProductionVmNodeLease>>,
    nodes: &[NodeId],
) -> Result<(), SchedulerError> {
    let mut first_error = None;
    for node in nodes {
        let Some(generation) = node_generations.get(node).copied() else {
            if first_error.is_none() {
                first_error = Some(format!("reaped QEMU node `{}` has no authenticated generation", node.name));
            }
            continue;
        };
        let Some(lease) = node_leases.get_mut(node) else {
            if first_error.is_none() {
                first_error = Some(format!("reaped QEMU node `{}` has no generation lease", node.name));
            }
            continue;
        };
        if lease.identity().node() != node || lease.identity().generation() != generation {
            if first_error.is_none() {
                first_error = Some(format!("reaped QEMU node `{}` has a mismatched generation lease", node.name));
            }
            continue;
        }
        if let Err(error) = lease.finish() {
            if first_error.is_none() {
                first_error = Some(format!("finish reaped QEMU node `{}` generation {generation}: {error}", node.name));
            }
            continue;
        }
        node_leases.remove(node);
    }
    first_error.map_or(Ok(()), |message| {
        Err(SchedulerError::BoundaryViolation { message })
    })
}"#,
        1,
    )],
};

pub(super) const NODE_RETURN: Companion = Companion {
    path: "crates/crucible/qemu/crucible-qemu-host/src/node/host_policy.rs",
    required: &[(
        r#"pub fn cleanup_physically_returned(&self) -> bool {
    self.child.reaped() && self.child_shutdown.physically_returned()
}"#,
        1,
    )],
};

pub(super) const NODE_COMPLETION: Companion = Companion {
    path: "crates/crucible/qemu/crucible-qemu-host/src/node/shutdown_continuation.rs",
    required: &[(
        r#"fn complete(&mut self) {
    if self.completion_attempted { return; }
    self.completion_attempted = true;
    self.history_pending = true;
    if let Some(CleanupOriginal::Owned { original: guard, .. }) = &self.guard {
        let (effect, result) = guard.complete_observed();
        self.completion_effect = effect;
        self.completion_failure = result.err();
    }
    self.completion_returned = true;
    self.guard = None;
}
pub(super) fn physically_returned(&self) -> bool {
    self.completion_returned
}
pub(super) fn finish_ram(
    &mut self,
    close: impl FnOnce(
        Option<crate::ram_control::RamCleanupOriginal<'_>>,
        &mut super::ram_cleanup::RamCleanup,
    ) -> bool,
) -> Result<(), QemuNodeError> {
    let returned = close(self.guard.as_ref().map(CleanupOriginal::view), &mut self.ram,);
    self.history_pending |= self.ram.take_unreported();
    if returned { self.complete(); }
    if self.failed() && (!returned || self.history_pending) {
        self.history_pending = false;
        self.health()?;
    }
    if returned { Ok(()) } else { Err(QemuNodeError::RamCleanupPending) }
}"#,
        1,
    )],
};

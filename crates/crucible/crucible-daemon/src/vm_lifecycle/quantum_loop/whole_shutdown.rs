//! Binds final lease return to this lifecycle's actual whole-node teardown.
//!
//! The generation digest corroborates the private map retained by this same
//! lifecycle. It is not a receipt: the containing NodeSet must independently
//! retain its own armed-to-returned transition after every node value closes.

use super::*;

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

    /// Validates every retained lease before arming this same backend owner.
    ///
    /// # Errors
    /// Refuses missing or foreign generations, absent nodes or changed custody.
    pub(in crate::vm_lifecycle) fn prepare_whole_node_shutdown(
        &mut self,
    ) -> Result<ContentHash, SchedulerError> {
        // Initial leases move once from construction's Partial into this fresh
        // Loop. Its sole production expansion is commit_terminal_replacements:
        // the backend commit invalidates this phase BEFORE the lease insert.
        // Successful return only removes rows. Thus the same private lease set
        // cannot grow while Armed/Returned; the generation digest alone would
        // not prove membership for a newly inserted, never-installed lease.
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
        self.inner
            .backend_mut()
            .prepare_whole_shutdown(binding, self.node_leases.keys())?;
        Ok(binding)
    }

    /// Returns existing leases only after the actual whole-set destruction cut.
    ///
    /// # Errors
    /// Refuses pending or invalidated teardown, changed generations or a lease
    /// return failure. Failed leases remain in their same owning map slots.
    pub(in crate::vm_lifecycle) fn finish_whole_node_leases(
        &mut self,
        binding: ContentHash,
    ) -> Result<(), SchedulerError> {
        if binding != self.whole_shutdown_binding() {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("whole shutdown generation binding changed"),
            });
        }
        if self.node_leases.is_empty() {
            return Ok(());
        }
        self.inner.backend().verify_whole_shutdown_return(binding)?;
        let nodes = self.node_leases.keys().cloned().collect::<Vec<_>>();
        let result =
            finish_reaped_node_lease_map(&self.node_generations, &mut self.node_leases, &nodes);
        if result.is_err() {
            self.node_lease_cleanup_failed = true;
        }
        result
    }
}

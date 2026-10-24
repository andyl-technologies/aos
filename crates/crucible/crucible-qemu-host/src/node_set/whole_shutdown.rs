//! Retains whole-set physical return across later scheduler and lease failures.
//!
//! The binding identifies the enclosing lifecycle's generation map; it issues
//! no authority. Only this same node set's actual cleanup and value destruction
//! can advance an armed phase to returned. Map mutation permanently invalidates
//! an outstanding phase rather than letting another generation inherit it.

use super::*;
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
    /// Arms physical teardown for the enclosing lifecycle's existing leases.
    ///
    /// The caller validates every lease's exact generation before this call.
    /// A binding alone never substitutes for actual installed node ownership.
    ///
    /// # Errors
    /// Refuses absent leased nodes, a changed binding or invalidated custody.
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
        // An ordinary empty backend may shut down, but cannot mint a return
        // disposition for an owner that never installed a physical node.
        if !self.nodes.is_empty() {
            self.whole_shutdown = WholeShutdown::Armed(binding);
        }
        Ok(())
    }

    /// Checks this same body's completed whole-set physical teardown.
    ///
    /// # Errors
    /// Refuses missing, pending, invalidated or differently bound teardown.
    pub fn verify_whole_shutdown_return(&self, binding: ContentHash) -> Result<(), BackendError> {
        match &self.whole_shutdown {
            WholeShutdown::Returned(saved) if *saved == binding => Ok(()),
            _ => Err(whole_shutdown_error()),
        }
    }

    pub(super) fn invalidate_whole_shutdown(&mut self) {
        if matches!(
            self.whole_shutdown,
            WholeShutdown::Armed(_) | WholeShutdown::Returned(_)
        ) {
            self.whole_shutdown = WholeShutdown::Invalidated;
        }
    }

    fn validate_whole_shutdown_cleanup(&self) -> Result<(), BackendError> {
        self.check_whole_shutdown_entry()?;
        match &self.whole_shutdown {
            WholeShutdown::Armed(_)
                if self
                    .nodes
                    .values()
                    .any(|node| !node.cleanup_physically_returned()) =>
            {
                Err(whole_shutdown_error())
            }
            _ => Ok(()),
        }
    }

    pub(super) fn check_whole_shutdown_entry(&self) -> Result<(), BackendError> {
        if matches!(self.whole_shutdown, WholeShutdown::Destructing) {
            Err(whole_shutdown_error())
        } else {
            Ok(())
        }
    }

    pub(super) fn clear_nodes_after_shutdown(&mut self) -> Result<(), BackendError> {
        self.validate_whole_shutdown_cleanup()?;
        // Value destruction can unwind after the map has become empty. Only
        // this same invocation's normal return may publish physical closure.
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
mod tests;

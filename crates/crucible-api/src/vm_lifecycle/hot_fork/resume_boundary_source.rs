//! Preparation of an attempt-launched world as a retained source at its stop boundary.
//!
//! A genesis source is launched with no start-specific replay inputs. A world
//! launched for one attempt instead carries that attempt's replay plans and
//! host deadline in its configuration, and every child forked from a source
//! inherits that configuration. Before such a world becomes a source, the
//! caller supplies the configuration an exact resume at the same boundary
//! would use; this module checks that only replay inputs and host bounds
//! differ, detaches attempt bindings, and then runs ordinary preparation.

use super::*;

impl ProductionVmLifecycleLoop {
    /// Prepares this attempt-launched world as a source with a resume configuration.
    ///
    /// `config` replaces the configuration children inherit. It must match
    /// the current launch basis (executables, guest assets, recovery root,
    /// scheduler bounds, and shared stores) and schedule no branch boundary.
    /// A `config` that names no trace segment store adopts the one this world
    /// launched with, because its runtime keeps sealing segments there.
    /// The launcher's attempt bindings are released before preparation, so a
    /// later attempt cancellation cannot reach the retained processes.
    ///
    /// # Errors
    ///
    /// Returns [`ProductionVmHotForkSourceWorldPreparationFailure`] retaining
    /// the lifecycle when the configuration changes the launch basis or names
    /// a branch boundary, when attempt bindings cannot be released, or when
    /// ordinary source preparation fails. The original configuration is
    /// restored on every failure that returns the lifecycle.
    pub fn prepare_hot_fork_source_world_with_config(
        mut self,
        config: ProductionVmLifecycleConfig,
    ) -> Result<ProductionVmHotForkSourceWorld, ProductionVmHotForkSourceWorldPreparationFailure>
    {
        // A resume configuration derived from the trusted base names no
        // attempt store; the retained world's segments already live in its own.
        let config = match (
            &config.fault_trace_segments,
            &self.config.fault_trace_segments,
        ) {
            (None, Some(segments)) => config.with_fault_trace_segments(Arc::clone(segments)),
            _ => config,
        };
        let mismatches = self.config.launch_basis_mismatches(&config);
        if !mismatches.is_empty() {
            return Err(ProductionVmHotForkSourceWorldPreparationFailure::new(
                self,
                format!(
                    "retained-source configuration changes the launch basis: {}",
                    mismatches.join(",")
                ),
                Vec::new(),
            ));
        }
        if config.has_pending_branch_boundary() {
            return Err(ProductionVmHotForkSourceWorldPreparationFailure::new(
                self,
                "retained-source configuration schedules a branch boundary",
                Vec::new(),
            ));
        }
        if let Err(error) = self.node_launcher.release_execution_bindings() {
            return Err(ProductionVmHotForkSourceWorldPreparationFailure::new(
                self,
                format!("release attempt bindings: {error}"),
                Vec::new(),
            ));
        }

        let original = std::mem::replace(&mut self.config, config);
        self.prepare_hot_fork_source_world().map_err(|mut failure| {
            if let Some(lifecycle) = failure.lifecycle.as_mut() {
                lifecycle.config = original;
            }
            failure
        })
    }
}

#[cfg(test)]
mod tests;

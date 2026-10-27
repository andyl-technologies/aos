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
    /// launched with, because its runtime keeps sealing segments there. The
    /// network adapter's selected campaign plan is rebound to the one `config`
    /// installs, which may drop only branches this world has not reached.
    /// The launcher's attempt bindings are released before preparation, so a
    /// later attempt cancellation cannot reach the retained processes.
    ///
    /// # Errors
    ///
    /// Returns [`ProductionVmHotForkSourceWorldPreparationFailure`] retaining
    /// the lifecycle when the configuration changes the launch basis, names
    /// a branch boundary, or drops a network fault branch this world already
    /// crossed, when attempt bindings cannot be released, or when ordinary
    /// source preparation fails. The original configuration and network plan
    /// are restored on every failure that returns the lifecycle.
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
        let network_replay = match resume_network_replay(&config) {
            Ok(replay) => replay,
            Err(error) => {
                return Err(ProductionVmHotForkSourceWorldPreparationFailure::new(
                    self,
                    format!("admit resume network fault replay: {error}"),
                    Vec::new(),
                ));
            }
        };
        // Children restore the checkpoint taken during preparation, so the
        // network adapter must name the resume plan before anything is sealed.
        let boundary = self.inner.loop_impl().configuration().clone();
        let (_, network) = self.inner.backend_and_network_output_interceptor_mut();
        let original_network_replay =
            match network.rebind_campaign_replay(network_replay, &boundary) {
                Ok(original) => original,
                Err(error) => {
                    return Err(ProductionVmHotForkSourceWorldPreparationFailure::new(
                        self,
                        format!("rebind network fault replay: {error}"),
                        Vec::new(),
                    ));
                }
            };
        if let Err(error) = self.node_launcher.release_execution_bindings() {
            self.restore_network_replay(original_network_replay);
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
                lifecycle.restore_network_replay(original_network_replay);
            }
            failure
        })
    }

    fn restore_network_replay(
        &mut self,
        replay: Option<crucible_engine::NetworkFaultCampaignReplayPlan>,
    ) {
        let (_, network) = self.inner.backend_and_network_output_interceptor_mut();
        network.restore_campaign_replay(replay);
    }
}

/// Returns the network fault plan an exact resume with `config` installs.
fn resume_network_replay(
    config: &ProductionVmLifecycleConfig,
) -> Result<
    Option<crucible_engine::NetworkFaultCampaignReplayPlan>,
    crucible_engine::NetworkFaultSelectableError,
> {
    let Some(replay) = config
        .signal_fault_replay
        .as_ref()
        .filter(|replay| !replay.network_branches().is_empty())
    else {
        return Ok(None);
    };
    crucible_engine::NetworkFaultCampaignReplayPlan::new(
        replay.target().clone(),
        replay.network_branches().to_vec(),
    )
    .map(Some)
}

#[cfg(test)]
mod tests;

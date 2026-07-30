//! Production World-to-scheduler scenario construction.

use super::*;

impl SchedulerLivenessScenario {
    /// Builds a runnable scheduler scenario from every VM in a logical world.
    ///
    /// `initial_ticks` is the scheduler-visible boundary at which each live
    /// backend was admitted. Production QEMU construction uses this to account
    /// for the bounded boot-barrier priming quantum before the first scheduled
    /// run.
    #[must_use]
    pub fn from_runnable_world(
        material: &str,
        shift: Shift,
        quantum_budget: u64,
        time_limit: SimInstant,
        initial_ticks: u64,
        world: &World,
    ) -> Self {
        let nodes = world
            .vm_nodes()
            .iter()
            .map(|node| SchedulerScenarioNode {
                id: SchedulerNodeId {
                    node: node.id.clone(),
                    kind: SchedulingNodeKind::Vm,
                },
                counter: NodeCounter {
                    ticks: initial_ticks,
                },
                activity: SchedulerNodeActivity::Runnable,
                network_lookahead: NetworkLookahead::Infinite,
                exact_local_event: ExactLocalEvent::NoArmedTimer,
            })
            .collect();
        let mut scenario = Self::from_canonical_material(
            material,
            shift,
            quantum_budget,
            time_limit,
            nodes,
            Vec::new(),
        );
        for node in world.vm_nodes() {
            scenario = scenario.with_ready_point_counter(
                SchedulerNodeId {
                    node: node.id.clone(),
                    kind: SchedulingNodeKind::Vm,
                },
                NodeCounter {
                    ticks: initial_ticks,
                },
            );
        }
        scenario.with_world(world)
    }

    /// Binds this runtime scheduler scenario to an existing scenario identity.
    ///
    /// Lifecycle-created sessions construct their frontier from the submitted
    /// [`ScenarioDef`]. A production backend scheduler must use that same
    /// definition rather than inventing a scheduler-fixture identity from its
    /// runtime parameters.
    #[must_use]
    pub fn with_scenario_def(mut self, scenario: ScenarioDef) -> Self {
        self.configuration = Configuration::genesis(scenario.clone());
        self.bound_scenario_def = Some(scenario);
        self
    }
}

//! Aggregate memory accounting for selected-origin campaign decoding.

use super::*;

pub(super) const MAX_SELECTED_ORIGIN_DECODE_BYTES: u64 = 256 * 1024 * 1024;
const SCENARIO_DECODE_EXPANSION: u64 = 256;
const CONFIGURATION_DECODE_PREFLIGHT_EXPANSION: u64 = 256;
const SELECTION_RESOLUTION_EXPANSION: u64 = 256;
const RETAINED_ALLOCATION_OVERHEAD: u64 = 64;

pub(super) struct SelectedOriginDecodeBudget {
    maximum: u64,
    retained: u64,
}

impl SelectedOriginDecodeBudget {
    pub(super) fn new(
        input: &AttemptExecutionInput,
        base: &ResolvedAttemptStart,
        origins: &ResolvedAttemptOrigins,
        maximum: u64,
    ) -> Result<Self, CrucibleArtifactError> {
        let mut budget = Self {
            maximum,
            retained: 0,
        };
        let scenario_bytes = u64::try_from(input.scenario().payload().len())
            .map_err(|_| selected_origin_memory_error())?;
        let decoded_scenario_bytes = scenario_bytes
            .checked_mul(SCENARIO_DECODE_EXPANSION)
            .and_then(|bytes| bytes.checked_mul(3))
            .ok_or_else(selected_origin_memory_error)?;
        budget.charge(
            scenario_bytes
                .checked_add(decoded_scenario_bytes)
                .ok_or_else(selected_origin_memory_error)?,
        )?;

        budget.charge_encoded_configuration(base_configuration_artifact(base)?)?;
        for origin in origins.iter() {
            budget.charge_encoded_configuration(origin.reached())?;
            budget.charge(origin.source_stop_bytes())?;
        }
        let origin_slots = u64::try_from(origins.len())
            .ok()
            .and_then(|count| {
                count.checked_mul(std::mem::size_of::<CrucibleAttemptOrigin>() as u64)
            })
            .ok_or_else(selected_origin_memory_error)?;
        budget.charge(origin_slots)?;
        Ok(budget)
    }

    fn charge_encoded_configuration(
        &mut self,
        artifact: &crucible_campaign::ConfigurationArtifact,
    ) -> Result<(), CrucibleArtifactError> {
        let bytes =
            u64::try_from(artifact.payload().len()).map_err(|_| selected_origin_memory_error())?;
        self.charge(bytes)
    }

    fn preflight_configuration(
        &self,
        artifact: &crucible_campaign::ConfigurationArtifact,
    ) -> Result<(), CrucibleArtifactError> {
        let bytes = u64::try_from(artifact.payload().len())
            .ok()
            .and_then(|bytes| bytes.checked_mul(CONFIGURATION_DECODE_PREFLIGHT_EXPANSION))
            .ok_or_else(selected_origin_memory_error)?;
        self.retained
            .checked_add(bytes)
            .filter(|total| *total <= self.maximum)
            .map(|_| ())
            .ok_or_else(selected_origin_memory_error)
    }

    fn charge_decoded_configuration(
        &mut self,
        configuration: &Configuration,
        campaign_branch_count: usize,
    ) -> Result<(), CrucibleArtifactError> {
        let schedule_bytes = decoded_configuration_logical_bytes(configuration)
            .ok_or_else(selected_origin_memory_error)?;
        let branches =
            u64::try_from(campaign_branch_count).map_err(|_| selected_origin_memory_error())?;
        // Each retained branch owns parent, selected, and decision-prefix
        // schedules. The terminal replay plan and final pending observation can
        // each clone that graph, so charge their exact worst-case multiplicity.
        let configuration_instances = branches
            .checked_mul(12)
            .and_then(|instances| instances.checked_add(6))
            .ok_or_else(selected_origin_memory_error)?;
        let configuration_bytes = schedule_bytes
            .checked_mul(configuration_instances)
            .ok_or_else(selected_origin_memory_error)?;
        let branch_bytes = branches
            .checked_mul(4)
            .and_then(|count| {
                count.checked_mul(std::mem::size_of::<crucible::SignalFaultCampaignBranch>() as u64)
            })
            .ok_or_else(selected_origin_memory_error)?;
        self.charge(
            configuration_bytes
                .checked_add(branch_bytes)
                .ok_or_else(selected_origin_memory_error)?,
        )
    }

    fn selection_resolution_canonical_limit(&self) -> Result<usize, CrucibleArtifactError> {
        let remaining = self
            .maximum
            .checked_sub(self.retained)
            .ok_or_else(selected_origin_memory_error)?;
        usize::try_from(remaining / SELECTION_RESOLUTION_EXPANSION)
            .map_err(|_| selected_origin_memory_error())
    }

    pub(super) fn charge_branch_start(
        &mut self,
        selected: &Configuration,
    ) -> Result<(), CrucibleArtifactError> {
        let bytes = decoded_configuration_logical_bytes(selected)
            .and_then(|bytes| bytes.checked_mul(2))
            .ok_or_else(selected_origin_memory_error)?;
        self.charge(bytes)
    }

    fn charge(&mut self, bytes: u64) -> Result<(), CrucibleArtifactError> {
        self.retained = self
            .retained
            .checked_add(bytes)
            .filter(|total| *total <= self.maximum)
            .ok_or_else(selected_origin_memory_error)?;
        Ok(())
    }
}

fn selected_origin_memory_error() -> CrucibleArtifactError {
    CrucibleArtifactError::ResourceLimit {
        resource: "selected-origin-decoded-resident-bytes",
    }
}

fn base_configuration_artifact(
    base: &ResolvedAttemptStart,
) -> Result<&crucible_campaign::ConfigurationArtifact, CrucibleArtifactError> {
    match base {
        ResolvedAttemptStart::Discover { configuration } => Ok(configuration),
        ResolvedAttemptStart::Branch { parent, .. } => Ok(parent),
        ResolvedAttemptStart::AfterAttempt { .. } => Err(CrucibleArtifactError::Campaign(
            crucible_campaign::CampaignCodecError::InvalidValue {
                reason: "attempt continuation has nested base",
            },
        )),
    }
}

pub(super) fn decode_selected_origin_configuration(
    store: &CampaignExecutorStore,
    scenario: &ScenarioDefForm,
    scenario_artifact: &crucible_campaign::ScenarioArtifact,
    artifact: &crucible_campaign::ConfigurationArtifact,
    budget: &mut SelectedOriginDecodeBudget,
) -> Result<(Configuration, SignalFaultCampaignReplayPlan), CrucibleArtifactError> {
    budget.preflight_configuration(artifact)?;
    let mut guard = |configuration: &Configuration, campaign_branch_count: usize| {
        budget.charge_decoded_configuration(configuration, campaign_branch_count)?;
        budget.selection_resolution_canonical_limit()
    };
    crate::crucible_artifact::decode_crucible_configuration_artifact_with_signal_fault_replay_guarded(
        scenario,
        scenario_artifact,
        artifact,
        store,
        Some(&mut guard),
    )
}

fn decoded_configuration_logical_bytes(configuration: &Configuration) -> Option<u64> {
    let mut bytes = u64::try_from(std::mem::size_of::<Configuration>()).ok()?;
    bytes = bytes.checked_add(
        u64::try_from(configuration.schedule.len())
            .ok()?
            .checked_mul(std::mem::size_of::<Decision>() as u64)?,
    )?;
    bytes = bytes.checked_add(RETAINED_ALLOCATION_OVERHEAD)?;

    for decision in configuration.schedule.decisions() {
        let variable = match decision {
            Decision::DeliveryOrder(decision) => {
                let mut retained = u64::try_from(decision.order.len())
                    .ok()?
                    .checked_mul(std::mem::size_of::<crucible::EventKey>() as u64)?;
                retained = retained.checked_add(RETAINED_ALLOCATION_OVERHEAD)?;
                for event in &decision.order {
                    retained = retained
                        .checked_add(u64::try_from(event.consumer.node.name.len()).ok()?)?
                        .checked_add(u64::try_from(event.producer.node.name.len()).ok()?)?
                        .checked_add(RETAINED_ALLOCATION_OVERHEAD.checked_mul(2)?)?;
                }
                retained
            }
            Decision::RngDraw(decision) => {
                u64::try_from(decision.stream.domain.len() + decision.stream.name.len())
                    .ok()?
                    .checked_add(RETAINED_ALLOCATION_OVERHEAD.checked_mul(2)?)?
            }
            Decision::Override(decision) => {
                u64::try_from(decision.point.key.len() + decision.choice.name.len())
                    .ok()?
                    .checked_add(RETAINED_ALLOCATION_OVERHEAD.checked_mul(2)?)?
            }
            Decision::Preemption(decision) => u64::try_from(decision.node.name.len())
                .ok()?
                .checked_add(RETAINED_ALLOCATION_OVERHEAD)?,
            Decision::Selection(decision) => u64::try_from(decision.canonical_bytes().len())
                .ok()?
                .checked_add(RETAINED_ALLOCATION_OVERHEAD)?,
        };
        bytes = bytes.checked_add(variable)?;
    }
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use crucible::{Decision, DeliveryOrderDecision, Schedule, VirtualTime};

    use super::*;

    #[test]
    fn many_branch_prefixes_exhaust_the_aggregate_decode_budget() -> Result<(), String> {
        let fixture = crucible::happy_path_scenario().map_err(|error| error.to_string())?;
        let decisions = (0..256).map(|tick| {
            Decision::DeliveryOrder(DeliveryOrderDecision {
                at: VirtualTime { ticks: tick },
                order: Vec::new(),
            })
        });
        let configuration = Configuration {
            def: fixture.scenario.scenario_def(),
            schedule: Schedule::from_decisions(decisions),
        };
        let mut budget = SelectedOriginDecodeBudget {
            maximum: 256 * 1024,
            retained: 0,
        };

        let error = match budget.charge_decoded_configuration(&configuration, 256) {
            Err(error) => error,
            Ok(()) => return Err(String::from("retained branch prefixes fit the budget")),
        };

        assert!(matches!(
            error,
            CrucibleArtifactError::ResourceLimit {
                resource: "selected-origin-decoded-resident-bytes"
            }
        ));
        assert_eq!(budget.retained, 0);
        Ok(())
    }

    #[test]
    fn repeated_origin_plans_exhaust_one_aggregate_budget() -> Result<(), String> {
        let fixture = crucible::happy_path_scenario().map_err(|error| error.to_string())?;
        let configuration = Configuration {
            def: fixture.scenario.scenario_def(),
            schedule: Schedule::from_decisions([Decision::DeliveryOrder(DeliveryOrderDecision {
                at: VirtualTime { ticks: 1 },
                order: Vec::new(),
            })]),
        };
        let one_plan_bytes = decoded_configuration_logical_bytes(&configuration)
            .ok_or_else(|| String::from("logical configuration byte count overflowed"))?
            .checked_mul(6)
            .ok_or_else(|| String::from("empty replay-plan multiplicity overflowed"))?;
        let mut budget = SelectedOriginDecodeBudget {
            maximum: one_plan_bytes
                .checked_mul(2)
                .and_then(|bytes| bytes.checked_sub(1))
                .ok_or_else(|| String::from("test budget overflowed"))?,
            retained: 0,
        };

        budget
            .charge_decoded_configuration(&configuration, 0)
            .map_err(|error| error.to_string())?;
        let retained_after_one = budget.retained;
        let error = match budget.charge_decoded_configuration(&configuration, 0) {
            Err(error) => error,
            Ok(()) => return Err(String::from("repeated origins fit the aggregate budget")),
        };

        assert!(matches!(
            error,
            CrucibleArtifactError::ResourceLimit {
                resource: "selected-origin-decoded-resident-bytes"
            }
        ));
        assert_eq!(retained_after_one, one_plan_bytes);
        assert_eq!(budget.retained, retained_after_one);
        Ok(())
    }
}

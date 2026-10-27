//! Aggregate memory accounting for selected-origin campaign decoding.

use super::*;

pub(super) const MAX_SELECTED_ORIGIN_DECODE_BYTES: u64 = 256 * 1024 * 1024;
const SCENARIO_DECODE_EXPANSION: u64 = 256;
const CONFIGURATION_DECODE_PREFLIGHT_EXPANSION: u64 = 256;
const SELECTION_RESOLUTION_EXPANSION: u64 = 256;
const RETAINED_ALLOCATION_OVERHEAD: u64 = 64;
// Worst-case resident copies of the decoded configuration: the replay plan
// target and the final pending observation, each possibly cloned.
const CONFIGURATION_INSTANCES: u64 = 6;
// Worst-case resident copies of one campaign branch across those holders.
const BRANCH_INSTANCES: u64 = 4;

pub(super) struct SelectedOriginDecodeBudget {
    maximum: u64,
    retained: u64,
}

impl SelectedOriginDecodeBudget {
    pub(super) fn new(
        input: &AttemptExecutionInput,
        base: &ResolvedAttemptStart,
        origins: &AttemptOriginChain,
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

        // The base and terminal origin stay resident. Intermediate origins are
        // reloaded and dropped one at a time, so only the largest is charged.
        budget.charge_encoded_configuration(base_configuration_artifact(base)?)?;
        let terminal = origins.last();
        budget.charge_encoded_configuration(terminal.reached())?;
        budget.charge(terminal.source_stop_bytes())?;
        budget.charge(origins.peak_intermediate_encoded_bytes())?;
        let origin_slots = u64::try_from(origins.len())
            .ok()
            .and_then(|count| count.checked_mul(std::mem::size_of::<OriginLink>() as u64))
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
        // The terminal replay plan and final pending observation can each
        // clone the decoded configuration, so charge its exact worst-case
        // multiplicity. Branches name prefixes of that one configuration and
        // own only their struct and their one or two branch decisions, so the
        // branch charge is linear in the schedule, not schedule times branches.
        let configuration_bytes = schedule_bytes
            .checked_mul(CONFIGURATION_INSTANCES)
            .ok_or_else(selected_origin_memory_error)?;
        let branch_decision_bytes = campaign_branch_decision_bytes(configuration)
            .ok_or_else(selected_origin_memory_error)?;
        let branch_bytes = branches
            .checked_mul(std::mem::size_of::<crucible_engine::SignalFaultCampaignBranch>() as u64)
            .and_then(|bytes| bytes.checked_add(branch_decision_bytes))
            .and_then(|bytes| bytes.checked_mul(BRANCH_INSTANCES))
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

    /// Returns the current charge, to release a transient decode back to it.
    pub(super) const fn mark(&self) -> u64 {
        self.retained
    }

    /// Releases every charge made since `mark`.
    ///
    /// Decoding an intermediate origin is charged in full, so the peak check
    /// covers it; once the origin is retained only as a terminal prefix, its
    /// decoded configuration is dropped and its charge is released.
    pub(super) fn release_to(&mut self, mark: u64) {
        self.retained = self.retained.min(mark);
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

    for decision in configuration.schedule.decision_history() {
        bytes = bytes.checked_add(decision_heap_bytes(decision)?)?;
    }
    Some(bytes)
}

/// Returns the bytes owned by every campaign branch's copied decisions.
///
/// A branch copies its selection decision and, for a signal-fault candidate,
/// the override that follows it. Each campaign-branch selection is charged
/// both, whichever adapter it names.
fn campaign_branch_decision_bytes(configuration: &Configuration) -> Option<u64> {
    let history = configuration.schedule.decision_history();
    let mut bytes = 0_u64;
    for (index, decision) in history.iter().enumerate() {
        let Decision::Selection(selection) = decision else {
            continue;
        };
        if !selection.is_campaign_branch() {
            continue;
        }
        for copied in history.iter_from(index).take(2) {
            bytes = bytes
                .checked_add(std::mem::size_of::<Decision>() as u64)?
                .checked_add(decision_heap_bytes(copied)?)?;
        }
    }
    Some(bytes)
}

/// Returns the heap bytes one decoded decision retains beyond its inline size.
fn decision_heap_bytes(decision: &Decision) -> Option<u64> {
    let variable = match decision {
        Decision::DeliveryOrder(decision) => {
            let mut retained = u64::try_from(decision.order.len())
                .ok()?
                .checked_mul(std::mem::size_of::<crucible_engine::EventKey>() as u64)?;
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
    Some(variable)
}

#[cfg(test)]
mod tests {
    use crucible_engine::{Decision, DeliveryOrderDecision, Schedule, VirtualTime};

    use super::*;

    #[test]
    fn branch_charge_grows_with_branch_count_not_schedule_times_branches() -> Result<(), String> {
        let fixture = crucible_engine::happy_path_scenario().map_err(|error| error.to_string())?;
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
        let charge = |branches| {
            let mut budget = SelectedOriginDecodeBudget {
                maximum: u64::MAX,
                retained: 0,
            };
            budget
                .charge_decoded_configuration(&configuration, branches)
                .map(|()| budget.retained)
                .map_err(|error| error.to_string())
        };

        let unbranched = charge(0)?;
        let branched = charge(256)?;
        let per_branch =
            BRANCH_INSTANCES * std::mem::size_of::<crucible_engine::SignalFaultCampaignBranch>() as u64;

        assert_eq!(branched - unbranched, 256 * per_branch);
        assert!(branched < unbranched * 256);
        Ok(())
    }

    #[test]
    fn repeated_origin_plans_exhaust_one_aggregate_budget() -> Result<(), String> {
        let fixture = crucible_engine::happy_path_scenario().map_err(|error| error.to_string())?;
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

    #[test]
    fn a_deep_prefix_chain_decodes_within_its_peak_budget() -> Result<(), Box<dyn std::error::Error>>
    {
        const DEPTH: u64 = 64;
        const STEP: u64 = 64;

        let scenario = crucible_engine::happy_path_scenario()?.scenario;
        let scenario_artifact = crate::encode_crucible_scenario_artifact(&scenario)?;
        let store = CampaignExecutorStore::new(std::sync::Arc::new(
            crucible_campaign::CampaignRepository::new(
                std::sync::Arc::new(crucible_store::content_store::MemoryBlobBackend::new(
                    "origin-decode",
                    1024 * 1024,
                )),
                std::sync::Arc::new(crucible_store::content_store::MemoryRefBackend::new()),
            ),
        ));
        let path = BranchPath::new(Vec::new())?.id()?;
        let configuration = |index: u64| Configuration {
            def: scenario.scenario_def(),
            schedule: Schedule::from_decisions((0..STEP * (index + 1)).map(|tick| {
                Decision::DeliveryOrder(DeliveryOrderDecision {
                    at: VirtualTime { ticks: tick },
                    order: Vec::new(),
                })
            })),
        };
        let origin = |index: u64| -> Result<ResolvedAttemptOrigin, Box<dyn std::error::Error>> {
            let reached = crate::encode_crucible_configuration_artifact(
                &scenario_artifact,
                &configuration(index).schedule,
            )?;
            let attempt = Attempt::new(
                AttemptStart::Discover {
                    configuration: reached.id()?,
                },
                path,
                crucible_campaign::StopCondition::ExecutionQuanta(index + 1),
            )?;
            Ok(ResolvedAttemptOrigin::from_test_parts(attempt, reached))
        };
        let charge = |index: u64| -> Result<u64, String> {
            decoded_configuration_logical_bytes(&configuration(index))
                .and_then(|bytes| bytes.checked_mul(CONFIGURATION_INSTANCES))
                .ok_or_else(|| String::from("configuration charge overflowed"))
        };

        let terminal = origin(DEPTH)?;
        let intermediates = (0..DEPTH).map(origin).collect::<Result<Vec<_>, _>>()?;
        let terminal_charge = charge(DEPTH)?;
        let preflight = u64::try_from(terminal.reached().payload().len())?
            * CONFIGURATION_DECODE_PREFLIGHT_EXPANSION;
        // Room for the terminal, the decode preflight, and one transient
        // intermediate, which the chain's summed decodes exceed.
        let maximum = terminal_charge * 2 + preflight;
        let summed = (0..DEPTH).map(charge).sum::<Result<u64, _>>()?;
        assert!(terminal_charge + summed > maximum);
        let mut budget = SelectedOriginDecodeBudget {
            maximum,
            retained: 0,
        };

        let decoded = decode_origin_ancestry(
            &store,
            &scenario,
            &scenario_artifact,
            &terminal,
            &mut budget,
            |visit| intermediates.iter().try_for_each(visit),
        )?;
        let reached = decoded
            .iter()
            .map(|origin| origin.map(|origin| origin.reached().clone()))
            .collect::<Result<Vec<_>, _>>()?;

        assert_eq!(reached, (0..=DEPTH).map(configuration).collect::<Vec<_>>());
        assert_eq!(budget.retained, terminal_charge);
        Ok(())
    }

    #[test]
    fn released_intermediate_decodes_charge_only_their_peak() -> Result<(), String> {
        let fixture = crucible_engine::happy_path_scenario().map_err(|error| error.to_string())?;
        let configuration = Configuration {
            def: fixture.scenario.scenario_def(),
            schedule: Schedule::from_decisions([Decision::DeliveryOrder(DeliveryOrderDecision {
                at: VirtualTime { ticks: 1 },
                order: Vec::new(),
            })]),
        };
        let one_plan_bytes = decoded_configuration_logical_bytes(&configuration)
            .ok_or_else(|| String::from("logical configuration byte count overflowed"))?
            .checked_mul(CONFIGURATION_INSTANCES)
            .ok_or_else(|| String::from("replay-plan multiplicity overflowed"))?;
        // Room for the resident terminal and one transient intermediate.
        let mut budget = SelectedOriginDecodeBudget {
            maximum: one_plan_bytes
                .checked_mul(2)
                .ok_or_else(|| String::from("test budget overflowed"))?,
            retained: 0,
        };
        budget
            .charge_decoded_configuration(&configuration, 0)
            .map_err(|error| error.to_string())?;

        for _ in 0..64 {
            let before = budget.mark();
            budget
                .charge_decoded_configuration(&configuration, 0)
                .map_err(|error| error.to_string())?;
            budget.release_to(before);
        }
        budget
            .charge_decoded_configuration(&configuration, 0)
            .map_err(|error| error.to_string())?;
        let unreleased = budget.charge_decoded_configuration(&configuration, 0);

        assert_eq!(budget.retained, one_plan_bytes * 2);
        assert!(matches!(
            unreleased,
            Err(CrucibleArtifactError::ResourceLimit {
                resource: "selected-origin-decoded-resident-bytes"
            })
        ));
        Ok(())
    }
}

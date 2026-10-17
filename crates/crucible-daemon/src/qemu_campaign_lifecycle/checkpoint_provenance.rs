//! Choice records carried from an in-attempt stop to its exact checkpoint.
//!
//! A sticky checkpoint request stops the attempt at a capture-ready boundary
//! before the raw exact root exists. The discoveries made so far travel with
//! the stop and are bound into the captured checkpoint's choice closure only
//! after the capture is proven to name the same scenario and configuration.

use super::*;

/// In-attempt choices retained until the raw exact root owns their records.
#[derive(Debug)]
pub struct QemuCheckpointChoiceProvenance {
    configuration: Configuration,
    discoveries: BTreeMap<ChoiceOpportunityId, ChoiceDiscovery>,
}

impl QemuCheckpointChoiceProvenance {
    pub(crate) fn new(
        configuration: Configuration,
        discoveries: BTreeMap<ChoiceOpportunityId, ChoiceDiscovery>,
    ) -> Self {
        Self {
            configuration,
            discoveries,
        }
    }

    pub(crate) fn configuration_id(&self) -> ConfigurationId {
        ConfigurationId::from_hash(CampaignHash::from_bytes(self.configuration.id().bytes))
    }

    pub(crate) fn bind_capture(
        self,
        source: &ScenarioDefForm,
        capture: CapturedAttemptCheckpoint,
    ) -> Result<CapturedAttemptCheckpoint, SchedulerError> {
        if capture.scenario() != source.id()
            || capture.configuration() != self.configuration.id()
            || self.configuration.def != source.scenario_def()
        {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "checkpoint choice records differ from the captured boundary",
                ),
            });
        }
        let closure = GuardedCampaignReplayClosure::from_owned_discoveries(
            source,
            &self.configuration.schedule,
            &self.discoveries,
        )
        .map_err(|error| SchedulerError::BoundaryViolation {
            message: format!("authenticate checkpoint choice records: {error}"),
        })?;
        Ok(capture.with_choice_closure(closure))
    }
}

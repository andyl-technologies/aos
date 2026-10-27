//! Backend-neutral measured fuel for the canonical campaign planners.
//!
//! The meter charges the complete scanned frontier plus one invocation before
//! executing a planner. It grants no executor, native, or repository authority.

use std::error::Error;
use std::fmt;

use crucible_campaign::{
    CampaignCodecError, PlannerExecutionSupervisor, PlannerRequest, PurePlannerEngine,
    SupervisedPlannerExecution,
};

pub(crate) struct LocalPlannerMeter;

#[derive(Debug)]
pub(crate) enum LocalPlannerMeterError {
    FuelOverflow,
    FuelExceeded,
}

impl fmt::Display for LocalPlannerMeterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FuelOverflow => formatter.write_str("canonical planner measured fuel overflow"),
            Self::FuelExceeded => {
                formatter.write_str("canonical planner measured fuel exceeds request budget")
            }
        }
    }
}

impl Error for LocalPlannerMeterError {}

impl PlannerExecutionSupervisor<crucible_campaign::CanonicalFrontierPlanner> for LocalPlannerMeter {
    type Error = LocalPlannerMeterError;

    fn execute(
        &mut self,
        engine: &mut crucible_campaign::CanonicalFrontierPlanner,
        request: &PlannerRequest,
    ) -> Result<SupervisedPlannerExecution<CampaignCodecError>, Self::Error> {
        let measured_fuel = u64::try_from(request.invocation().scan_page().positions().len())
            .ok()
            .and_then(|positions| positions.checked_add(1))
            .ok_or(LocalPlannerMeterError::FuelOverflow)?;
        if measured_fuel > request.invocation().budget().fuel() {
            return Err(LocalPlannerMeterError::FuelExceeded);
        }
        Ok(SupervisedPlannerExecution::new(
            engine.plan(request),
            measured_fuel,
        ))
    }
}

impl PlannerExecutionSupervisor<crucible_campaign::CanonicalSearchPlanner> for LocalPlannerMeter {
    type Error = LocalPlannerMeterError;

    fn execute(
        &mut self,
        engine: &mut crucible_campaign::CanonicalSearchPlanner,
        request: &PlannerRequest,
    ) -> Result<SupervisedPlannerExecution<CampaignCodecError>, Self::Error> {
        let measured_fuel = u64::try_from(request.invocation().scan_page().positions().len())
            .ok()
            .and_then(|positions| positions.checked_add(1))
            .ok_or(LocalPlannerMeterError::FuelOverflow)?;
        if measured_fuel > request.invocation().budget().fuel() {
            return Err(LocalPlannerMeterError::FuelExceeded);
        }
        Ok(SupervisedPlannerExecution::new(
            engine.plan(request),
            measured_fuel,
        ))
    }
}

impl PlannerExecutionSupervisor<crucible_campaign::CanonicalPuctPlanner> for LocalPlannerMeter {
    type Error = LocalPlannerMeterError;

    fn execute(
        &mut self,
        engine: &mut crucible_campaign::CanonicalPuctPlanner,
        request: &PlannerRequest,
    ) -> Result<SupervisedPlannerExecution<CampaignCodecError>, Self::Error> {
        let measured_fuel = u64::try_from(request.invocation().scan_page().positions().len())
            .ok()
            .and_then(|positions| positions.checked_add(1))
            .ok_or(LocalPlannerMeterError::FuelOverflow)?;
        if measured_fuel > request.invocation().budget().fuel() {
            return Err(LocalPlannerMeterError::FuelExceeded);
        }
        Ok(SupervisedPlannerExecution::new(
            engine.plan(request),
            measured_fuel,
        ))
    }
}

impl PlannerExecutionSupervisor<crucible_campaign::CanonicalBeamPlanner> for LocalPlannerMeter {
    type Error = LocalPlannerMeterError;

    fn execute(
        &mut self,
        engine: &mut crucible_campaign::CanonicalBeamPlanner,
        request: &PlannerRequest,
    ) -> Result<SupervisedPlannerExecution<CampaignCodecError>, Self::Error> {
        let measured_fuel = u64::try_from(request.invocation().scan_page().positions().len())
            .ok()
            .and_then(|positions| positions.checked_add(1))
            .ok_or(LocalPlannerMeterError::FuelOverflow)?;
        if measured_fuel > request.invocation().budget().fuel() {
            return Err(LocalPlannerMeterError::FuelExceeded);
        }
        Ok(SupervisedPlannerExecution::new(
            engine.plan(request),
            measured_fuel,
        ))
    }
}

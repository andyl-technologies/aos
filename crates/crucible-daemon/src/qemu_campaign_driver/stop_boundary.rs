//! QEMU campaign compatibility adapter for shared modeled stop semantics.

use super::*;

pub(super) use crate::modeled_campaign_driver::stop_boundary::{
    policy_timeout_at, requested_attempt_stop_frontier,
};

pub(super) fn reached_requested_stop(
    requested: &StopCondition,
    evidence: &QuantumStopEvidence<'_>,
) -> Result<Option<ModeledStop>, QemuFreshModeledDriverError> {
    crate::modeled_campaign_driver::stop_boundary::reached_requested_stop(requested, evidence)
        .map_err(Into::into)
}

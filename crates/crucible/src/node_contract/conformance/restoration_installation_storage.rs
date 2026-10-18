//! Borrows the same inactive collecting runtime for prospective Runtime7 storage.
//!
//! Its ordinary runtime and graph remain private. These data facts do not issue
//! an original-restoration member, native operation, readiness or activation.

use super::*;
use crate::node_contract::{
    OriginalLineageRuntimeRecord, OriginalRuntimeRestorationInstallationConstructionData,
};
use crate::node_scheduling::SchedulingSnapshot;
use crate::node_state::VerifiedStateContent;

impl ConformanceRuntime {
    pub(crate) fn original_runtime_restoration_installation_construction_data(
        &self,
        record: &OriginalLineageRuntimeRecord,
        scheduling: &SchedulingSnapshot,
        target: &ActivationRecord,
        content: &VerifiedStateContent,
        coordinator: &crate::node_admission::OriginalRestorationCoordinatorConstructionData,
        maximum: usize,
    ) -> Result<OriginalRuntimeRestorationInstallationConstructionData, RuntimeError> {
        self.observation_data()
            .original_runtime_restoration_installation_construction_data(
                record,
                scheduling,
                target,
                content,
                coordinator,
                maximum,
            )
    }

    pub(crate) fn authenticate_original_runtime_restoration_installation_construction_data(
        &self,
        data: &OriginalRuntimeRestorationInstallationConstructionData,
        record: &OriginalLineageRuntimeRecord,
        scheduling: &SchedulingSnapshot,
        target: &ActivationRecord,
        content: &VerifiedStateContent,
        coordinator: &crate::node_admission::OriginalRestorationCoordinatorConstructionData,
    ) -> Result<(), RuntimeError> {
        self.authenticate_complete_original_restoration_origin()?;
        data.authenticate_inputs_data(
            &self.runtime,
            record,
            scheduling,
            target,
            content,
            coordinator,
        )
    }

    pub(crate) fn original_runtime_restoration_installation_counter_scratch_data()
    -> Result<usize, RuntimeError> {
        NodeRuntime::original_runtime_restoration_installation_counter_scratch_data()?
            .checked_add(ConformanceRuntimeObservation::counter_scratch_data())
            .ok_or(RuntimeError::ResourceLimit)
    }
}

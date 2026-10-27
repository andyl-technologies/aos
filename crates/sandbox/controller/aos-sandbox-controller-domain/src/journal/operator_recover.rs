//! Reborrows the same fixed Source native owner for Recover observation only.
//!
//! No append scope, mutation exception, supplied file or historical DATA can
//! enter this adapter. The genuine current successor C receiver pays before
//! the common physical pair is armed; all after observations remain independent.

use aos_sandbox_broker::controller_receiving::bank_launch::{
    ControllerBankLaunchOriginalV1, ControllerCoordinatorWriterV1,
    ControllerOperatorRecoverReceivingV1,
};
use aos_sandbox_broker::controller_receiving::profile::ControllerSelfProfileOriginalV1;
use aos_sandbox_broker::source_receiving::SourceOperatorRecoverCurrentnessOriginalV1;
use aos_sandbox_broker::controller_receiving::bank_launch::ControllerRecoveredEnrollmentReceivingV2;
use aos_sandbox_broker::source_receiving::SourceRecoveredEnrollmentCurrentnessOriginalV2;
use aos_sandbox_model::ResourceVector;

use super::{Journal, JournalError};
use crate::controller_resource_reservation::ResourceReservationErrorV1;

impl Journal {
    pub(crate) fn require_source_recovered_enrollment_current_v2<C>(&self,
        original: &mut SourceRecoveredEnrollmentCurrentnessOriginalV2,
        receiving: &ControllerRecoveredEnrollmentReceivingV2,
        controller: &ControllerCoordinatorWriterV1<C>, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        match &self.native {
            super::native_backing::JournalNativeBackingV1::Source(source) => source
                .require_recovered_enrollment_readonly_current_v2(original, receiving,
                    controller, launch, profile).map_err(Into::into),
            _ => Err(ResourceReservationErrorV1::Conflict),
        }
    }

    pub(crate) fn begin_source_recovered_enrollment_native_v2<C>(&mut self,
        receiving: &mut ControllerRecoveredEnrollmentReceivingV2,
        controller: &ControllerCoordinatorWriterV1<C>, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1, complete: ResourceVector,
    ) -> Result<SourceRecoveredEnrollmentCurrentnessOriginalV2, ResourceReservationErrorV1> {
        match &mut self.native {
            super::native_backing::JournalNativeBackingV1::Source(source) => source
                .begin_recovered_enrollment_currentness_once_v2(receiving, controller, launch, profile, complete)
                .map_err(Into::into),
            _ => Err(ResourceReservationErrorV1::Conflict),
        }
    }

    pub(crate) fn finish_source_recovered_enrollment_native_v2(&self,
        original: &mut SourceRecoveredEnrollmentCurrentnessOriginalV2,
    ) -> Result<(), JournalError> {
        match &self.native {
            super::native_backing::JournalNativeBackingV1::Source(source) => source
                .finish_recovered_enrollment_currentness_once_v2(original).map_err(JournalError::SourceNative),
            _ => Err(JournalError::ProtectedBoundary),
        }
    }

    pub(crate) fn dispose_source_recovered_enrollment_native_v2<C>(&mut self,
        original: &mut SourceRecoveredEnrollmentCurrentnessOriginalV2,
        receiving: &ControllerRecoveredEnrollmentReceivingV2,
        controller: &ControllerCoordinatorWriterV1<C>, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        match &mut self.native {
            super::native_backing::JournalNativeBackingV1::Source(source) => source
                .dispose_recovered_enrollment_currentness_after_posts_v2(original, receiving,
                    controller, launch, profile).map_err(Into::into),
            _ => Err(ResourceReservationErrorV1::Conflict),
        }
    }

    pub(crate) fn begin_source_operator_recover_native_v1<C>(&mut self,
        receiving: &mut ControllerOperatorRecoverReceivingV1,
        controller: &ControllerCoordinatorWriterV1<C>, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1, complete: ResourceVector,
    ) -> Result<SourceOperatorRecoverCurrentnessOriginalV1, ResourceReservationErrorV1> {
        match &mut self.native {
            super::native_backing::JournalNativeBackingV1::Source(source) => source
                .begin_operator_recover_currentness_once_v1(receiving, controller, launch, profile, complete)
                .map_err(Into::into),
            _ => Err(ResourceReservationErrorV1::Conflict),
        }
    }

    pub(crate) fn finish_source_operator_recover_native_v1(&self,
        original: &mut SourceOperatorRecoverCurrentnessOriginalV1,
    ) -> Result<(), JournalError> {
        match &self.native {
            super::native_backing::JournalNativeBackingV1::Source(source) => source
                .finish_operator_recover_currentness_once_v1(original).map_err(JournalError::SourceNative),
            _ => Err(JournalError::ProtectedBoundary),
        }
    }

    pub(crate) fn dispose_source_operator_recover_native_v1<C>(&mut self,
        original: &mut SourceOperatorRecoverCurrentnessOriginalV1,
        receiving: &ControllerOperatorRecoverReceivingV1,
        controller: &ControllerCoordinatorWriterV1<C>, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        match &mut self.native {
            super::native_backing::JournalNativeBackingV1::Source(source) => source
                .dispose_operator_recover_currentness_after_posts_v1(original, receiving,
                    controller, launch, profile).map_err(Into::into),
            _ => Err(ResourceReservationErrorV1::Conflict),
        }
    }
}

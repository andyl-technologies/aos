//! Lends the same activation Original to closed native Current receiving steps.
//!
//! These methods add no active-currentness check. The real native stage owns
//! its predecessor, once gate, quote and observation order. The caller retains
//! actual L/U exclusion and parks each returned refusal before releasing it.

use aos_sandbox_broker::receiving::{RootObservationErrorV1, RootUpperMutationGuardV1};
use aos_sandbox_model::ResourceVector;
use aos_sandbox_policy::native::{
    RootInitialBundleOwnershipFrameBorrowV1, RootInitialControllerReadonlyPreparedBorrowV1,
    RootInitialControllerReadonlyReplayBorrowV1, RootInitialSubjectFrameBorrowV1,
    RootOwnedCurrentOriginalV1,
};

use super::RootReceivingOriginalV1;
use crate::normal_root::{ProductionNormalRootStartupV1, RootOwnedCurrentStageV1};

use crate::policy_compiler::create_storage_current::initial_owned::RootOwnedControllerPreparedStageV1;

impl RootReceivingOriginalV1 {
    pub(crate) fn drive_owned_current_stage_v1(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
        exclusion: &RootUpperMutationGuardV1<'_>,
        current: &mut RootOwnedCurrentOriginalV1<'_>,
        stage: RootOwnedCurrentStageV1,
        supplements: [Option<ResourceVector>; 2],
    ) -> Result<(), RootObservationErrorV1> {
        let selected = startup
            .native_startup_original_v1()
            .borrow_selected_original_v1()?;
        match stage {
            RootOwnedCurrentStageV1::Writers => current.receive_writers_once_v1(
                &mut self.activation,
                &selected,
                exclusion,
                supplements,
            ),
            RootOwnedCurrentStageV1::OpenEntry => {
                current.begin_initial_open_once_v1(&mut self.activation, &selected, exclusion)
            }
            RootOwnedCurrentStageV1::OpenOuter => {
                current.arm_initial_open_outer_once_v1(&mut self.activation, &selected, exclusion)
            }
            RootOwnedCurrentStageV1::OpenCrossing => current.arm_initial_open_crossing_once_v1(
                &mut self.activation,
                &selected,
                exclusion,
            ),
            RootOwnedCurrentStageV1::ReadyEntry => {
                current.begin_initial_ready_once_v1(&mut self.activation, &selected, exclusion)
            }
            RootOwnedCurrentStageV1::ReadyBytes => {
                current.fund_initial_ready_bytes_once_v1(&mut self.activation, &selected, exclusion)
            }
            RootOwnedCurrentStageV1::ReadyPost => {
                current.arm_initial_ready_post_once_v1(&mut self.activation, &selected, exclusion);
                Ok(())
            }
            RootOwnedCurrentStageV1::PinsEntry => {
                current.begin_initial_pins_once_v1(&mut self.activation, &selected, exclusion)
            }
            RootOwnedCurrentStageV1::PinsPost => {
                current.arm_initial_pins_post_once_v1(&mut self.activation, &selected, exclusion);
                Ok(())
            }
            RootOwnedCurrentStageV1::InputsEntry => current.begin_initial_policy_inputs_once_v1(
                &mut self.activation,
                &selected,
                exclusion,
            ),
            RootOwnedCurrentStageV1::InputsPost => {
                current.arm_initial_policy_inputs_post_once_v1(
                    &mut self.activation,
                    &selected,
                    exclusion,
                );
                Ok(())
            }
            RootOwnedCurrentStageV1::TrustFixed => current.begin_initial_trust_fixed_once_v1(
                &mut self.activation,
                &selected,
                exclusion,
            ),
            RootOwnedCurrentStageV1::TrustEntry => current.enter_initial_trust_capture_once_v1(
                &mut self.activation,
                &selected,
                exclusion,
            ),
            RootOwnedCurrentStageV1::TrustTyped => current.begin_initial_trust_typed_once_v1(
                &mut self.activation,
                &selected,
                exclusion,
            ),
            RootOwnedCurrentStageV1::TrustPost => {
                current.arm_initial_trust_post_once_v1(&mut self.activation, &selected, exclusion);
                Ok(())
            }
            RootOwnedCurrentStageV1::QueryEntry => current.begin_initial_source_query_once_v1(
                &mut self.activation,
                &selected,
                exclusion,
            ),
            RootOwnedCurrentStageV1::ExchangeEntry => current
                .begin_initial_source_exchange_once_v1(&mut self.activation, &selected, exclusion),
            RootOwnedCurrentStageV1::ExchangePost => {
                current.arm_initial_source_exchange_post_once_v1(
                    &mut self.activation,
                    &selected,
                    exclusion,
                );
                Ok(())
            }
            RootOwnedCurrentStageV1::BundleFixed => current
                .begin_initial_bundle_ownership_fixed_once_v1(
                    &mut self.activation,
                    &selected,
                    exclusion,
                ),
            RootOwnedCurrentStageV1::BundlePost => {
                current.arm_initial_bundle_ownership_post_once_v1(
                    &mut self.activation,
                    &selected,
                    exclusion,
                );
                Ok(())
            }
            RootOwnedCurrentStageV1::CacheFixed => current.begin_initial_cache_proof_once_v1(
                &mut self.activation,
                &selected,
                exclusion,
            ),
            RootOwnedCurrentStageV1::CachePost => {
                current.arm_initial_cache_proof_post_once_v1(
                    &mut self.activation,
                    &selected,
                    exclusion,
                );
                Ok(())
            }
            RootOwnedCurrentStageV1::ControllerFixed => current
                .begin_initial_controller_readonly_once_v1(
                    &mut self.activation,
                    &selected,
                    exclusion,
                ),
            RootOwnedCurrentStageV1::ControllerBodyArm => {
                current.arm_initial_controller_readonly_body_once_v1(
                    &mut self.activation,
                    &selected,
                    exclusion,
                );
                Ok(())
            }
            RootOwnedCurrentStageV1::UseAuthorizedFixed => current
                .begin_initial_use_authorized_once_v1(&mut self.activation, &selected, exclusion),
            RootOwnedCurrentStageV1::UseAuthorizedAppend => current
                .arm_initial_use_authorized_append_post_once_v1(
                    &mut self.activation,
                    &selected,
                    exclusion,
                ),
            RootOwnedCurrentStageV1::UseAuthorizedCrossing => current
                .arm_initial_use_authorized_crossing_once_v1(
                    &mut self.activation,
                    &selected,
                    exclusion,
                ),
            RootOwnedCurrentStageV1::UseAuthorizedSend => current
                .arm_initial_use_authorized_send_post_once_v1(
                    &mut self.activation,
                    &selected,
                    exclusion,
                ),
            RootOwnedCurrentStageV1::ReservedFrameFixed => {
                current.begin_use_reserved_frame_once_v1(&mut self.activation, &selected, exclusion)
            }
            RootOwnedCurrentStageV1::ReservedFrameBefore => current
                .arm_use_reserved_frame_before_once_v1(&mut self.activation, &selected, exclusion),
            RootOwnedCurrentStageV1::ReservedFrameAfter => current
                .arm_use_reserved_frame_after_once_v1(&mut self.activation, &selected, exclusion),
            RootOwnedCurrentStageV1::ReservedControllerFixed => current
                .begin_use_reserved_controller_once_v1(&mut self.activation, &selected, exclusion),
            RootOwnedCurrentStageV1::ReservedControllerBodyArm => {
                current.arm_use_reserved_controller_body_once_v1(
                    &mut self.activation,
                    &selected,
                    exclusion,
                );
                Ok(())
            }
            RootOwnedCurrentStageV1::UseQueryEntry => current
                .begin_use_source_query_once_v1(&mut self.activation, &selected, exclusion),
            RootOwnedCurrentStageV1::UseExchangeEntry => current
                .begin_use_source_exchange_once_v1(&mut self.activation, &selected, exclusion),
            RootOwnedCurrentStageV1::UseExchangePost => {
                current.arm_use_source_exchange_post_once_v1(&mut self.activation, &selected, exclusion);
                Ok(())
            }
            RootOwnedCurrentStageV1::UseCacheFixed => current
                .begin_use_cache_proof_once_v1(&mut self.activation, &selected, exclusion),
            RootOwnedCurrentStageV1::UseCachePost => {
                current.arm_use_cache_proof_post_once_v1(&mut self.activation, &selected, exclusion);
                Ok(())
            }
            RootOwnedCurrentStageV1::UseAdmittedFixed => current
                .begin_use_admitted_once_v1(&mut self.activation, &selected, exclusion),
            RootOwnedCurrentStageV1::UseAdmittedAppend => current
                .arm_use_admitted_append_post_once_v1(&mut self.activation, &selected, exclusion),
            RootOwnedCurrentStageV1::UseAdmittedCrossing => current
                .arm_use_admitted_crossing_once_v1(&mut self.activation, &selected, exclusion),
            RootOwnedCurrentStageV1::UseAdmittedSend => current
                .arm_use_admitted_send_post_once_v1(&mut self.activation, &selected, exclusion),
            RootOwnedCurrentStageV1::SignedFixed => current
                .begin_signed_fixed_once_v1(&mut self.activation, &selected, exclusion),
            RootOwnedCurrentStageV1::SignedAppend => current
                .arm_signed_append_post_once_v1(&mut self.activation, &selected, exclusion),
            RootOwnedCurrentStageV1::SignedInputBefore => current
                .arm_signed_input_before_once_v1(&mut self.activation, &selected, exclusion),
            RootOwnedCurrentStageV1::SignedInputAfter => current
                .arm_signed_input_after_once_v1(&mut self.activation, &selected, exclusion),
            RootOwnedCurrentStageV1::SignedVariable => current
                .begin_signed_variable_once_v1(&mut self.activation, &selected, exclusion),
            RootOwnedCurrentStageV1::SignedController => current
                .begin_signed_controller_once_v1(&mut self.activation, &selected, exclusion),
            RootOwnedCurrentStageV1::SignedControllerBodyArm => {
                current.arm_signed_controller_body_once_v1(&mut self.activation, &selected, exclusion);
                Ok(())
            }
            RootOwnedCurrentStageV1::SignedCrossing => current
                .arm_signed_crossing_once_v1(&mut self.activation, &selected, exclusion),
            RootOwnedCurrentStageV1::SignedSend => current
                .arm_signed_send_post_once_v1(&mut self.activation, &selected, exclusion),
        }
    }

    /// Lends the same Initial to one closed prepared-Controller receiving slot.
    ///
    /// # Errors
    /// Returns actual live-stage or selected-original/debit/service refusal.
    pub(crate) fn drive_owned_controller_prepared_v1(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
        exclusion: &RootUpperMutationGuardV1<'_>,
        prepared: &mut RootInitialControllerReadonlyPreparedBorrowV1<'_, '_, '_>,
        stage: RootOwnedControllerPreparedStageV1,
    ) -> Result<(), RootObservationErrorV1> {
        match stage {
            RootOwnedControllerPreparedStageV1::Named => {
                prepared.admit_named_once_v1(&mut self.activation, exclusion)
            }
            RootOwnedControllerPreparedStageV1::Native => {
                let selected = startup
                    .native_startup_original_v1()
                    .borrow_selected_original_v1()?;
                prepared.admit_native_once_v1(&mut self.activation, &selected, exclusion)
            }
            RootOwnedControllerPreparedStageV1::Semantic => {
                let selected = startup
                    .native_startup_original_v1()
                    .borrow_selected_original_v1()?;
                prepared.admit_semantic_once_v1(&mut self.activation, &selected, exclusion)
            }
        }
    }

    /// Lends the same Initial to the constructed replay's original live check.
    ///
    /// # Errors
    /// Returns the actual same-Initial/semantic-stage refusal without adding a
    /// selected-service probe or debit at this existing pure live-check slot.
    pub(crate) fn admit_owned_controller_captured_v1(
        &mut self,
        exclusion: &RootUpperMutationGuardV1<'_>,
        replay: &mut RootInitialControllerReadonlyReplayBorrowV1<'_, '_>,
    ) -> Result<(), RootObservationErrorV1> {
        replay.admit_captured_once_v1(&mut self.activation, exclusion)
    }

    /// Lends only this same Initial to the genuine parsed Ownership frame.
    ///
    /// # Errors
    /// Returns actual selected-original or native typed admission refusal.
    pub(crate) fn begin_owned_current_bundle_typed_v1(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
        exclusion: &RootUpperMutationGuardV1<'_>,
        frame: &mut RootInitialBundleOwnershipFrameBorrowV1<'_, '_>,
    ) -> Result<(), RootObservationErrorV1> {
        let selected = startup
            .native_startup_original_v1()
            .borrow_selected_original_v1()?;
        frame.begin_typed_once_v1(&mut self.activation, &selected, exclusion)
    }

    pub(crate) fn arm_owned_current_frame_before_v1(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
        exclusion: &RootUpperMutationGuardV1<'_>,
        frame: &mut RootInitialSubjectFrameBorrowV1<'_, '_>,
    ) -> Result<(), RootObservationErrorV1> {
        let selected = startup
            .native_startup_original_v1()
            .borrow_selected_original_v1()?;
        frame.arm_before_once_v1(&mut self.activation, &selected, exclusion)
    }

    pub(crate) fn arm_owned_current_frame_after_v1(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
        exclusion: &RootUpperMutationGuardV1<'_>,
        frame: &mut RootInitialSubjectFrameBorrowV1<'_, '_>,
    ) -> Result<(), RootObservationErrorV1> {
        let selected = startup
            .native_startup_original_v1()
            .borrow_selected_original_v1()?;
        frame.arm_after_once_v1(&mut self.activation, &selected, exclusion);
        Ok(())
    }
}

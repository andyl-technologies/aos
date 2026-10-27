//! Rejoins the actual Initial only at the original Current receiving slots.
//!
//! This guard retains the same L then U exclusion. Native observations, slow
//! preparation and socket IO run only after this short loan has been released.

use aos_sandbox_broker::receiving::RootObservationErrorV1;
use aos_sandbox_model::ResourceVector;
use aos_sandbox_policy::native::{
    RootInitialBundleOwnershipFrameBorrowV1, RootInitialControllerReadonlyPreparedBorrowV1,
    RootInitialControllerReadonlyReplayBorrowV1, RootInitialSubjectFrameBorrowV1,
    RootOwnedCurrentOriginalV1,
};

use super::RootReceivingGuardV1;
use crate::normal_root::ProductionNormalRootStartupV1;
use crate::policy_compiler::create_storage_current::initial_owned::RootInitialCurrentActionErrorV1 as Action;

/// Names the closed existing Initial receiving slots without adopting success.
#[derive(Clone, Copy)]
pub(crate) enum RootOwnedCurrentStageV1 {
    /// Enters the actual two-writer receiving stage.
    Writers,
    /// Enters the initial Open fixed stage.
    OpenEntry,
    /// Arms the outer Open history obligation.
    OpenOuter,
    /// Arms the distinct final Open crossing obligation.
    OpenCrossing,
    /// Enters the actual Ready fixed receiving stage.
    ReadyEntry,
    /// Enters the actual declared Ready byte stage.
    ReadyBytes,
    /// Arms the independently owed Ready peer post.
    ReadyPost,
    /// Enters the actual issuer capture stage.
    PinsEntry,
    /// Arms the independently owed issuer peer post.
    PinsPost,
    /// Enters the same genuine signed-input receiving stage after full pins.
    InputsEntry,
    /// Arms the independently owed signed-input peer post.
    InputsPost,
    /// Pays fixed trust custody before its outside-lock Box construction.
    TrustFixed,
    /// Rechecks the actual fixed trust original before the owed post scope.
    TrustEntry,
    /// Pays typed trust decoding from the actual captured policy length.
    TrustTyped,
    /// Arms the independently owed trust peer post.
    TrustPost,
    /// Pays the Initial Source query from the genuine completed trust prefix.
    QueryEntry,
    /// Pays the Initial Source exchange before its native socket/body scope.
    ExchangeEntry,
    /// Arms the independently owed Initial Source exchange peer post.
    ExchangePost,
    /// Pays Bundle framing before borrowing the original Ready fields.
    BundleFixed,
    /// Arms Bundle posts only after real typed admission.
    BundlePost,
    /// Pays Initial Cache proof before its signer and receive preparation.
    CacheFixed,
    /// Arms the Cache peer after its independent native posts.
    CachePost,
    /// Pays the real Controller fixed stage before any reader/archive construction.
    ControllerFixed,
    /// Prearms the real Controller body peer before receipt or file preparation.
    ControllerBodyArm,
    /// Pays the local Root Use append from the completed Controller prefix.
    UseAuthorizedFixed,
    /// Arms the outer append post before entering Root Use body scope.
    UseAuthorizedAppend,
    /// Arms the distinct native append crossing after actual preparation.
    UseAuthorizedCrossing,
    /// Arms the independently owed send post after exact framing.
    UseAuthorizedSend,
    /// Pays Reserved frame from the genuine completed Root2 prefix.
    ReservedFrameFixed,
    /// Arms the first full Reserved frame bookend before IO.
    ReservedFrameBefore,
    /// Arms the distinct after bookend only after the before arm succeeded.
    ReservedFrameAfter,
    /// Pays the distinct Controller read from the actual Reserved frame Stage.
    ReservedControllerFixed,
    /// Prearms this Controller body before mount or file work.
    ReservedControllerBodyArm,
    /// Pays the refreshed query from the actual Reserved Controller prefix.
    UseQueryEntry,
    /// Pays the refreshed native Source exchange before its body.
    UseExchangeEntry,
    /// Arms that exchange's independently owed peer post.
    UseExchangePost,
    /// Pays the refreshed Cache proof from the completed Source prefix.
    UseCacheFixed,
    /// Arms the refreshed Cache peer after its native posts.
    UseCachePost,
    /// Pays the local Root3 append from the same completed Reserved original.
    UseAdmittedFixed,
    /// Arms its outer append post before native preparation.
    UseAdmittedAppend,
    /// Arms the distinct final crossing after genuine Root3 preparation.
    UseAdmittedCrossing,
    /// Arms the independent write post after native Root3 framing.
    UseAdmittedSend,
    /// Pays actual Root4 fixed receivers before construction.
    SignedFixed,
    /// Arms Root4 outer posts before any Signed input body.
    SignedAppend,
    /// Arms the first actual Signed input bookend.
    SignedInputBefore,
    /// Arms the owed Signed input bookend before entering its body.
    SignedInputAfter,
    /// Pays actual Signed index-derived decoding before raw allocation.
    SignedVariable,
    /// Pays C7 from the actual completed Signed variable stage.
    SignedController,
    /// Prearms C7 before native preparation and real reader work.
    SignedControllerBodyArm,
    /// Arms the real Root4 final append crossing.
    SignedCrossing,
    /// Arms Root4 send after exact durable receipt framing.
    SignedSend,
}

use crate::policy_compiler::create_storage_current::initial_owned::RootOwnedControllerPreparedStageV1;

impl RootReceivingGuardV1<'_> {
    /// Runs one named stage while the same original L and U remain held.
    ///
    /// # Errors
    /// Returns the actual selected-original or native stage refusal and denies
    /// this same financial original before either guard is released.
    pub(crate) fn drive_owned_current_stage_v1(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
        current: &mut RootOwnedCurrentOriginalV1<'_>,
        stage: RootOwnedCurrentStageV1,
        supplements: [Option<ResourceVector>; 2],
    ) -> Result<(), RootObservationErrorV1> {
        let returned = self.original.drive_owned_current_stage_v1(
            startup,
            &self.mutation,
            current,
            stage,
            supplements,
        );
        self.finish_returned_v1(returned)
    }

    /// Runs one original Controller receiving slot on its genuine prepared loan.
    ///
    /// # Errors
    /// Retains same-Initial, real selected, live-stage or debit/service refusal.
    pub(crate) fn drive_owned_controller_prepared_v1(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
        prepared: &mut RootInitialControllerReadonlyPreparedBorrowV1<'_, '_, '_>,
        stage: RootOwnedControllerPreparedStageV1,
    ) -> Result<(), RootObservationErrorV1> {
        let returned = self.original.drive_owned_controller_prepared_v1(
            startup,
            &self.mutation,
            prepared,
            stage,
        );
        self.finish_returned_v1(returned)
    }

    /// Rechecks the actual captured semantic entry on the nested replay loan.
    ///
    /// # Errors
    /// Retains live same-Initial or semantic-stage refusal before releasing L/U.
    pub(crate) fn admit_owned_controller_captured_v1(
        &mut self,
        replay: &mut RootInitialControllerReadonlyReplayBorrowV1<'_, '_>,
    ) -> Result<(), RootObservationErrorV1> {
        let returned = self
            .original
            .admit_owned_controller_captured_v1(&self.mutation, replay);
        self.finish_returned_v1(returned)
    }

    /// Admits typed Ownership while the same parsed native frame remains borrowed.
    ///
    /// # Errors
    /// Retains actual selected borrowing, geometry, debit or service refusal and
    /// denies the same invocation before releasing either original guard.
    pub(crate) fn begin_owned_current_bundle_typed_v1(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
        frame: &mut RootInitialBundleOwnershipFrameBorrowV1<'_, '_>,
    ) -> Result<(), RootObservationErrorV1> {
        let returned =
            self.original
                .begin_owned_current_bundle_typed_v1(startup, &self.mutation, frame);
        self.finish_returned_v1(returned)
    }

    /// Arms the genuine frame's before obligation at its original short slot.
    ///
    /// # Errors
    /// Retains selected-original, predecessor, debit or native arm refusal.
    pub(crate) fn arm_owned_current_frame_before_v1(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
        frame: &mut RootInitialSubjectFrameBorrowV1<'_, '_>,
    ) -> Result<(), RootObservationErrorV1> {
        let returned =
            self.original
                .arm_owned_current_frame_before_v1(startup, &self.mutation, frame);
        self.finish_returned_v1(returned)
    }

    /// Arms the independently owed after obligation without observing it.
    ///
    /// # Errors
    /// Retains an actual selected-original borrowing refusal. The upper caller
    /// keeps that cause and invokes the frame's negative-only arm path.
    pub(crate) fn arm_owned_current_frame_after_v1(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
        frame: &mut RootInitialSubjectFrameBorrowV1<'_, '_>,
    ) -> Result<(), RootObservationErrorV1> {
        let returned =
            self.original
                .arm_owned_current_frame_after_v1(startup, &self.mutation, frame);
        self.finish_returned_v1(returned)
    }
}

impl ProductionNormalRootStartupV1 {
    /// Reacquires the actual financial and upper originals for one named slot.
    ///
    /// # Errors
    /// Retains the actual upper lock error or returned native stage error.
    pub(crate) fn drive_owned_current_stage_v1(
        &self,
        current: &mut RootOwnedCurrentOriginalV1<'_>,
        stage: RootOwnedCurrentStageV1,
        supplements: [Option<ResourceVector>; 2],
    ) -> Result<(), Action> {
        let mut receiving = self.lock_receiving_v1().map_err(Action::Upper)?;
        receiving
            .drive_owned_current_stage_v1(self, current, stage, supplements)
            .map_err(Action::Native)
    }

    /// Reacquires actual L/U for the same prepared Controller receiving slot.
    ///
    /// # Errors
    /// Returns the actual lock, original or native receiving refusal.
    pub(crate) fn drive_owned_controller_prepared_v1(
        &self,
        prepared: &mut RootInitialControllerReadonlyPreparedBorrowV1<'_, '_, '_>,
        stage: RootOwnedControllerPreparedStageV1,
    ) -> Result<(), Action> {
        let mut receiving = self.lock_receiving_v1().map_err(Action::Upper)?;
        receiving
            .drive_owned_controller_prepared_v1(self, prepared, stage)
            .map_err(Action::Native)
    }

    /// Reacquires actual L/U for the same constructed Controller replay.
    ///
    /// # Errors
    /// Returns the actual lock or captured semantic-entry refusal. The caller
    /// still runs that replay's independent prefix/tail path after refusal.
    pub(crate) fn admit_owned_controller_captured_v1(
        &self,
        replay: &mut RootInitialControllerReadonlyReplayBorrowV1<'_, '_>,
    ) -> Result<(), Action> {
        let mut receiving = self.lock_receiving_v1().map_err(Action::Upper)?;
        receiving
            .admit_owned_controller_captured_v1(replay)
            .map_err(Action::Native)
    }

    /// Reacquires actual L/U for the same already-parsed Ownership frame.
    ///
    /// # Errors
    /// Returns the actual lock, selected-original or typed-stage refusal.
    pub(crate) fn begin_owned_current_bundle_typed_v1(
        &self,
        frame: &mut RootInitialBundleOwnershipFrameBorrowV1<'_, '_>,
    ) -> Result<(), Action> {
        let mut receiving = self.lock_receiving_v1().map_err(Action::Upper)?;
        receiving
            .begin_owned_current_bundle_typed_v1(self, frame)
            .map_err(Action::Native)
    }

    /// Reacquires the same original only to arm the frame's before slot.
    ///
    /// # Errors
    /// Returns the actual lock, selected-original or native arm refusal.
    pub(crate) fn arm_owned_current_frame_before_v1(
        &self,
        frame: &mut RootInitialSubjectFrameBorrowV1<'_, '_>,
    ) -> Result<(), Action> {
        let mut receiving = self.lock_receiving_v1().map_err(Action::Upper)?;
        receiving
            .arm_owned_current_frame_before_v1(self, frame)
            .map_err(Action::Native)
    }

    /// Reacquires the same original only to arm the owed after slot.
    ///
    /// # Errors
    /// Returns the actual lock or selected-original borrowing refusal.
    pub(crate) fn arm_owned_current_frame_after_v1(
        &self,
        frame: &mut RootInitialSubjectFrameBorrowV1<'_, '_>,
    ) -> Result<(), Action> {
        let mut receiving = self.lock_receiving_v1().map_err(Action::Upper)?;
        receiving
            .arm_owned_current_frame_after_v1(self, frame)
            .map_err(Action::Native)
    }
}

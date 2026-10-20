//! Forwards the same actual Source's purpose-closed C23 native bookends.

use super::*;
use aos_sandbox_broker::controller_receiving::bank_launch::ControllerCreateProvisioningReceivingV1;
use aos_sandbox_broker::source_receiving::SourceProvisioningCurrentnessOriginalV1;
use aos_sandbox_broker::controller_receiving::bank_launch::ControllerRecoveredEnrollmentReceivingV2;
use aos_sandbox_broker::source_receiving::SourceRecoveredEnrollmentCurrentnessOriginalV2;
use aos_sandbox_model::ResourceVector;
use aos_sandbox_broker::controller_receiving::bank_launch::ControllerCatalogMaintenanceReceivingV2;
use aos_sandbox_broker::source_receiving::SourceCatalogMaintenanceCurrentnessOriginalV2;

impl<P> SourceNativeJournalOwnerV1<P> {
    /// Arms this same Source's actual prepaid Maintenance observations.
    ///
    /// # Errors
    /// Preserves original C/Source/profile, receiving and native entry refusals.
    #[doc(hidden)]
    pub fn begin_catalog_maintenance_currentness_once_v2<C>(
        &mut self,
        receiving: &mut ControllerCatalogMaintenanceReceivingV2,
        controller: &ControllerCoordinatorWriterV1<C>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        complete: ResourceVector,
    ) -> Result<SourceCatalogMaintenanceCurrentnessOriginalV2, ControllerBankLaunchErrorV1> {
        self.coordinator.begin_catalog_maintenance_currentness_once_v2(
            receiving, controller, launch, profile, complete,
        )
    }

    /// Rejoins the unchanged actual Source through its genuine Maintenance loan.
    ///
    /// # Errors
    /// Preserves a foreign original, failed native before or changed C/profile.
    #[doc(hidden)]
    pub fn require_catalog_maintenance_readonly_current_v2<C>(
        &self,
        original: &mut SourceCatalogMaintenanceCurrentnessOriginalV2,
        receiving: &ControllerCatalogMaintenanceReceivingV2,
        controller: &ControllerCoordinatorWriterV1<C>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.coordinator.require_catalog_maintenance_readonly_current_v2(
            original, receiving, controller, launch, profile,
        )
    }

    /// Performs the same already-armed Source after despite Maintenance refusal.
    ///
    /// # Errors
    /// Retains the actual native post, original identity or reentry refusal.
    #[doc(hidden)]
    pub fn finish_catalog_maintenance_currentness_once_v2(
        &self,
        original: &mut SourceCatalogMaintenanceCurrentnessOriginalV2,
    ) -> Result<(), SourceNativeErrorV1> {
        self.coordinator.finish_catalog_maintenance_currentness_once_v2(original)
    }

    /// Disposes positive Source custody after the same Maintenance C posts.
    ///
    /// # Errors
    /// Refuses failed, changed, foreign or incomplete native originals.
    #[doc(hidden)]
    pub fn dispose_catalog_maintenance_currentness_after_posts_v2<C>(
        &mut self,
        original: &mut SourceCatalogMaintenanceCurrentnessOriginalV2,
        receiving: &ControllerCatalogMaintenanceReceivingV2,
        controller: &ControllerCoordinatorWriterV1<C>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.coordinator.dispose_catalog_maintenance_currentness_after_posts_v2(
            original, receiving, controller, launch, profile,
        )
    }
}

impl<P> SourceNativeJournalOwnerV1<P> {
    /// Begins this Source's prepaid recovered enrollment observations.
    ///
    /// # Errors
    /// Preserves the original Source/C/profile, capacity and native refusal.
    #[doc(hidden)]
    pub fn begin_recovered_enrollment_currentness_once_v2<C>(
        &mut self,
        receiving: &mut ControllerRecoveredEnrollmentReceivingV2,
        controller: &ControllerCoordinatorWriterV1<C>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        complete: ResourceVector,
    ) -> Result<SourceRecoveredEnrollmentCurrentnessOriginalV2, ControllerBankLaunchErrorV1> {
        self.coordinator.begin_recovered_enrollment_currentness_once_v2(
            receiving, controller, launch, profile, complete,
        )
    }

    /// Rejoins the unchanged Source under the genuine enrollment native owner.
    ///
    /// # Errors
    /// Refuses foreign originals, failed native before or completed custody.
    #[doc(hidden)]
    pub fn require_recovered_enrollment_readonly_current_v2<C>(
        &self,
        original: &mut SourceRecoveredEnrollmentCurrentnessOriginalV2,
        receiving: &ControllerRecoveredEnrollmentReceivingV2,
        controller: &ControllerCoordinatorWriterV1<C>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.coordinator.require_recovered_enrollment_readonly_current_v2(
            original, receiving, controller, launch, profile,
        )
    }

    /// Runs the independent prepaid Source after on every entered outcome.
    ///
    /// # Errors
    /// Retains the original native post, identity or reentry refusal.
    #[doc(hidden)]
    pub fn finish_recovered_enrollment_currentness_once_v2(
        &self,
        original: &mut SourceRecoveredEnrollmentCurrentnessOriginalV2,
    ) -> Result<(), SourceNativeErrorV1> {
        self.coordinator.finish_recovered_enrollment_currentness_once_v2(original)
    }

    /// Disposes positive Source observations after the same enrollment C posts.
    ///
    /// # Errors
    /// Refuses changed originals or failed and incomplete native observations.
    #[doc(hidden)]
    pub fn dispose_recovered_enrollment_currentness_after_posts_v2<C>(
        &mut self,
        original: &mut SourceRecoveredEnrollmentCurrentnessOriginalV2,
        receiving: &ControllerRecoveredEnrollmentReceivingV2,
        controller: &ControllerCoordinatorWriterV1<C>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.coordinator.dispose_recovered_enrollment_currentness_after_posts_v2(
            original, receiving, controller, launch, profile,
        )
    }

    /// Enters native Source bookends using the same actual C23 original.
    ///
    /// # Errors
    /// Preserves original association, receiving and native before refusals.
    #[doc(hidden)]
    pub fn begin_provisioning_currentness_once_v1<C>(&mut self,
        receiving: &mut ControllerCreateProvisioningReceivingV1,
        controller: &ControllerCoordinatorWriterV1<C>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1, complete: ResourceVector,
    ) -> Result<SourceProvisioningCurrentnessOriginalV1, ControllerBankLaunchErrorV1> {
        self.coordinator.begin_provisioning_currentness_once_v1(
            receiving, controller, launch, profile, complete,
        )
    }

    /// Rejoins the same actual Source for the closed paid readonly Start phase.
    ///
    /// No transaction, writer, financial owner or namespace exception is issued.
    ///
    /// # Errors
    /// Preserves the same original Source/C/profile and native-before refusal.
    #[doc(hidden)]
    pub fn require_provisioning_readonly_current_v1<C>(&self,
        original: &mut SourceProvisioningCurrentnessOriginalV1,
        receiving: &ControllerCreateProvisioningReceivingV1,
        controller: &ControllerCoordinatorWriterV1<C>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.coordinator.require_provisioning_readonly_current_v1(
            original, receiving, controller, launch, profile,
        )
    }

    /// Binds only the upper schema's exact current prepared transaction.
    ///
    /// # Errors
    /// Refuses changed Source/C23, another transaction or failed currentness.
    #[doc(hidden)]
    pub fn bind_provisioning_transaction_once_v1<C>(&mut self,
        original: &mut SourceProvisioningCurrentnessOriginalV1,
        receiving: &ControllerCreateProvisioningReceivingV1,
        controller: &ControllerCoordinatorWriterV1<C>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1, transaction: &JournalTransaction,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.coordinator.bind_provisioning_transaction_once_v1(
            original, receiving, controller, launch, profile, transaction,
        )
    }

    /// Rejoins the same native writer's actual Stop binding append and readback.
    ///
    /// The coordinator checks its private publication/custody and original
    /// before sequence. This wrapper preserves the actual compaction owner.
    ///
    /// # Errors
    /// Preserves foreign or repeated entry, changed canonical transaction,
    /// native publication coordinates and unequal protected member readback.
    #[doc(hidden)]
    pub fn require_stop_dispatch_successor_once_v1(&self,
        original: &mut SourceProvisioningCurrentnessOriginalV1,
        transaction: &JournalTransaction, expected_head: u64,
    ) -> Result<(), SourceNativeErrorV1> {
        self.coordinator.require_stop_dispatch_successor_once_v1(
            original, transaction, expected_head,
        )
    }

    /// Rejoins the same native writer's actual independent A8 settlement pair.
    ///
    /// This delegates the sole native publication/readback engine. It grants
    /// no Source22, Host cleanup or semantic append authority.
    ///
    /// # Errors
    /// Preserves wrong purpose, repeated use, foreign publication and changed
    /// or incompletely read back canonical protected members.
    #[doc(hidden)]
    pub fn require_stop_cleanup_completion_successor_once_v1(&self,
        original: &mut SourceProvisioningCurrentnessOriginalV1,
        transaction: &JournalTransaction, expected_head: u64,
    ) -> Result<(), SourceNativeErrorV1> {
        self.coordinator.require_stop_cleanup_completion_successor_once_v1(
            original, transaction, expected_head,
        )
    }

    /// Runs the prepaid Source after independently of body/C23 health.
    ///
    /// # Errors
    /// Retains actual Source native post, identity and reentry refusals.
    #[doc(hidden)]
    pub fn finish_provisioning_currentness_once_v1(&self,
        original: &mut SourceProvisioningCurrentnessOriginalV1,
    ) -> Result<(), SourceNativeErrorV1> {
        self.coordinator.finish_provisioning_currentness_once_v1(original)
    }

    /// Disposes exact positive Source bookends after real C23 completion.
    ///
    /// # Errors
    /// Refuses failed/changed Source/C23, unfinished work or reentry.
    #[doc(hidden)]
    pub fn dispose_provisioning_currentness_after_posts_v1<C>(&mut self,
        original: &mut SourceProvisioningCurrentnessOriginalV1,
        receiving: &ControllerCreateProvisioningReceivingV1,
        controller: &ControllerCoordinatorWriterV1<C>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.coordinator.dispose_provisioning_currentness_after_posts_v1(
            original, receiving, controller, launch, profile,
        )
    }

    /// Arms the original append post only for its exact current transaction.
    ///
    /// # Errors
    /// Refuses overlap, another selected transaction or unprepaid native entry.
    #[doc(hidden)]
    pub fn begin_native_post_for_append_once_v1(&mut self, transaction: &JournalTransaction)
        -> Result<SourceNativePostOriginalV1, SourceNativeErrorV1> {
        self.coordinator.begin_native_post_for_append_once_v1(transaction)
    }
}


impl<P> SourceNativeJournalOwnerV1<P> {
    /// Prepays and arms this same Source's deferred completion bookends.
    ///
    /// # Errors
    /// Preserves same-original, geometry, financial and native arm refusals.
    #[doc(hidden)]
    pub fn prearm_completion_source_currentness_once_v1<C>(&mut self,
        receiving: &mut ControllerCreateProvisioningReceivingV1,
        controller: &ControllerCoordinatorWriterV1<C>, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1, complete: ResourceVector,
    ) -> Result<SourceProvisioningCurrentnessOriginalV1, ControllerBankLaunchErrorV1> {
        self.coordinator.prearm_completion_source_currentness_once_v1(receiving, controller, launch, profile, complete)
    }

    /// Rejoins the same prepaid completion destination and native Source owner.
    ///
    /// # Errors
    /// Preserves the original Source/C/destination/native refusal without IO recreation.
    #[doc(hidden)]
    pub fn enter_completion_source_currentness_once_v1<C>(&self,
        original: &mut SourceProvisioningCurrentnessOriginalV1,
        destination: &aos_sandbox_broker::controller_receiving::bank_launch::ControllerCreateProvisioningCompletionDestinationV1,
        completed: &ControllerCreateProvisioningReceivingV1,
        controller: &ControllerCoordinatorWriterV1<C>, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.coordinator.enter_completion_source_currentness_once_v1(original, destination, completed, controller, launch, profile)
    }

    /// Rejoins the same prepaid completion destination and native Source owner.
    ///
    /// # Errors
    /// Preserves the original Source/C/destination/native refusal without IO recreation.
    #[doc(hidden)]
    pub fn bind_completion_source_transaction_once_v1<C>(&mut self,
        original: &mut SourceProvisioningCurrentnessOriginalV1,
        destination: &aos_sandbox_broker::controller_receiving::bank_launch::ControllerCreateProvisioningCompletionDestinationV1,
        completed: &ControllerCreateProvisioningReceivingV1,
        controller: &ControllerCoordinatorWriterV1<C>, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        transaction: &JournalTransaction,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.coordinator.bind_completion_source_transaction_once_v1(original, destination, completed, controller, launch, profile, transaction)
    }

    /// Rejoins the same prepaid completion destination and native Source owner.
    ///
    /// # Errors
    /// Preserves the original Source/C/destination/native refusal without IO recreation.
    #[doc(hidden)]
    pub fn dispose_completion_source_currentness_once_v1<C>(&mut self,
        original: &mut SourceProvisioningCurrentnessOriginalV1,
        destination: &aos_sandbox_broker::controller_receiving::bank_launch::ControllerCreateProvisioningCompletionDestinationV1,
        completed: &ControllerCreateProvisioningReceivingV1,
        controller: &ControllerCoordinatorWriterV1<C>, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.coordinator.dispose_completion_source_currentness_once_v1(original, destination, completed, controller, launch, profile)
    }
}


impl<P> SourceNativeJournalOwnerV1<P> {
    /// Enters this Source's paid, successor-bound Recover observation interval.
    ///
    /// # Errors
    /// Preserves same-original, funding and native entry refusals.
    #[doc(hidden)]
    pub fn begin_operator_recover_currentness_once_v1<C>(
        &mut self,
        receiving: &mut aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperatorRecoverReceivingV1,
        controller: &ControllerCoordinatorWriterV1<C>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        complete: ResourceVector,
    ) -> Result<aos_sandbox_broker::source_receiving::SourceOperatorRecoverCurrentnessOriginalV1, ControllerBankLaunchErrorV1> {
        self.coordinator.begin_operator_recover_currentness_once_v1(
            receiving, controller, launch, profile, complete,
        )
    }

    /// Runs the already armed Recover Source after on every entered outcome.
    ///
    /// # Errors
    /// Retains the original native post, identity and reentry refusal.
    #[doc(hidden)]
    pub fn finish_operator_recover_currentness_once_v1(
        &self,
        original: &mut aos_sandbox_broker::source_receiving::SourceOperatorRecoverCurrentnessOriginalV1,
    ) -> Result<(), SourceNativeErrorV1> {
        self.coordinator.finish_operator_recover_currentness_once_v1(original)
    }

    /// Disposes positive Recover bookends after their actual C native posts.
    ///
    /// # Errors
    /// Refuses changed originals, failed observations or incomplete posts.
    #[doc(hidden)]
    pub fn dispose_operator_recover_currentness_after_posts_v1<C>(
        &mut self,
        original: &mut aos_sandbox_broker::source_receiving::SourceOperatorRecoverCurrentnessOriginalV1,
        receiving: &aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperatorRecoverReceivingV1,
        controller: &ControllerCoordinatorWriterV1<C>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.coordinator.dispose_operator_recover_currentness_after_posts_v1(
            original, receiving, controller, launch, profile,
        )
    }
}

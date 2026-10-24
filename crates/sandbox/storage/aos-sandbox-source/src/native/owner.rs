//! Retains the genuinely constructed fixed Source writer inside its role package.
//!
//! The single private coordinator keeps its original C association, physical
//! files, index, append/replacement sinks and owed-post state. Named operations
//! forward the same engines for the trusted upper semantic coordinator. They
//! neither establish Source semantics nor grant policy or effect authority.

mod provisioning;

use aos_sandbox_broker::canonical_journal::append_stages::CanonicalAppendPublishedDataV1;
use aos_sandbox_broker::canonical_journal::coordinator::{
    CanonicalCoordinatorAppendV1, CanonicalCoordinatorNativeV1,
    CanonicalCoordinatorReadV1, CanonicalWriterNativeOperationsV1,
    CanonicalWriterReadViewV1,
};
use aos_sandbox_broker::controller_receiving::bank_launch::{
    ControllerBankLaunchErrorV1, ControllerBankLaunchOriginalV1,
    ControllerCoordinatorWriterV1, ControllerOperationIntakeReceivingLoanV1,
};
use aos_sandbox_broker::controller_receiving::profile::ControllerSelfProfileOriginalV1;
use aos_sandbox_broker::source_receiving::{
    SourceCoordinatorWriterV1, SourceNativeErrorV1, SourceNativePostOriginalV1,
    SourcePreparedAppendV1, SourcePreparedReplacementV1, SourceDeleteScopeV1, SourceExecutionScopeV1,
};
use aos_sandbox_protocol::domain_ledger::transaction::{JournalLimits, JournalTransaction};

/// Owns the original fixed Source writer created under its genuine C loan.
///
/// Its constructor is private to actual Source construction. No supplied UID,
/// path, descriptor, native tuple, DATA result or ordinary journal can create
/// this owner. Read and mutation stages remain mechanical operations: the
/// trusted coordinator retains every existing semantic and effect gate.
#[repr(transparent)]
pub struct SourceNativeJournalOwnerV1<P> {
    pub(super) coordinator: SourceCoordinatorWriterV1<P>,
}

impl<P> SourceNativeJournalOwnerV1<P> {
    /// Holds the same Source writer under its actual original's Delete C loan.
    ///
    /// The existing Broker scope retains both actual owners, prepays its two
    /// native name samples and preserves their independently owed completion.
    /// This forwarding method exposes no coordinator, Journal or native tuple;
    /// Source semantic planning, the independent Root floor and deletion
    /// effects remain obligations of the actual trusted upper caller.
    ///
    /// # Errors
    ///
    /// Refuses a foreign Controller original, an Execution purpose, insufficient
    /// declared capacity, overlap or prior native uncertainty through the same
    /// closed scope engine. Failed entered scopes must remain retained.
    #[doc(hidden)]
    pub fn borrow_delete_scope_v1<'scope, 'original, C>(
        &'scope mut self,
        receiving: &'scope mut ControllerOperationIntakeReceivingLoanV1<'original>,
        controller: &ControllerCoordinatorWriterV1<C>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<
        SourceDeleteScopeV1<'scope, 'original, P>,
        ControllerBankLaunchErrorV1,
    > {
        self.coordinator.borrow_delete_scope_v1(receiving, controller, launch, profile)
    }

    /// Holds the same Source writer under its actual original's execution loan.
    ///
    /// This forwards the existing closed Execution18 scope engine. The actual
    /// receiving loan, same Controller, saved Launch and profile remain joined;
    /// both native names samples and their independent completion stay owned by
    /// that scope. This method grants no append, Host effect or Ready proof.
    ///
    /// # Errors
    ///
    /// Refuses another purpose or Controller original, insufficient declared
    /// capacity, overlap or native uncertainty through the same genuine scope
    /// engine. Failed entered scopes retain their original completion debt.
    #[doc(hidden)]
    pub fn borrow_execution_scope_v1<'scope, 'original, C>(
        &'scope mut self,
        receiving: &'scope mut ControllerOperationIntakeReceivingLoanV1<'original>,
        controller: &ControllerCoordinatorWriterV1<C>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<
        SourceExecutionScopeV1<'scope, 'original, P>,
        ControllerBankLaunchErrorV1,
    > {
        self.coordinator.borrow_execution_scope_v1(receiving, controller, launch, profile)
    }

    /// Borrows the same genuine Source construction's inert original association.
    ///
    /// The reference stays tied to this private native owner. It creates no
    /// phase, currentness, completion, funding or native custody permission.
    #[doc(hidden)]
    #[must_use]
    pub fn cache_audit_original_v1(
        &self,
    ) -> &aos_sandbox_broker::controller_receiving::ControllerSourceOriginalRefV1 {
        self.coordinator.cache_audit_original_v1()
    }

    /// Borrows the same held writer's bounded readonly comparison view.
    pub fn coordinator_read_view(&self) -> CanonicalWriterReadViewV1<'_, P> {
        self.coordinator.coordinator_read_view()
    }

    /// Borrows the same sealed confined native-operation port.
    ///
    /// Callers retain the existing descriptor predebits, child-confinement and
    /// semantic gates. This port exposes no File or raw descriptor getter.
    pub fn native_operations(&self) -> CanonicalWriterNativeOperationsV1<'_, P> {
        self.coordinator.native_operations()
    }

    /// Returns the actual writer's next sequence as comparison DATA.
    pub const fn next_sequence(&self) -> u64 {
        self.coordinator.next_sequence()
    }

    /// Returns the actual fixed writer's configured limits as comparison DATA.
    pub const fn limits(&self) -> JournalLimits {
        self.coordinator.limits()
    }

    /// Reports native uncertainty without rejecting the same healthy active stage.
    pub fn has_native_uncertainty_v1(&self) -> bool {
        self.coordinator.has_native_uncertainty_v1()
    }

    /// Reports denial conditions for a fresh role entry.
    pub fn is_closed_or_poisoned_v1(&self) -> bool {
        self.coordinator.is_closed_or_poisoned_v1()
    }

    /// Borrows the permanently retained first append or debit cause.
    pub fn retained_append_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.coordinator.retained_append_failure_v1()
    }

    /// Fences the same actual native writer after an upper refusal.
    pub fn poison(&mut self) {
        self.coordinator.poison();
    }

    /// Prepays the same actual append, upper interval and owed native post.
    ///
    /// # Errors
    /// Preserves the original same-writer stage refusal or native failure.
    #[doc(hidden)]
    pub fn prepay_append_interval_once(&mut self, transaction: &JournalTransaction, upper_interval_bytes: usize) -> Result<(), SourceNativeErrorV1> {
        let shape = (|| {
            let models = aos_sandbox_ledger_replay::geometry::complete_replay_demand_v1(
                self.coordinator.coordinator_read_view().state(), Some(transaction),
            )?;
            let appended = aos_sandbox_protocol::domain_ledger::transaction::encoded_transaction_append_bytes(transaction)
                .map_err(aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1::from)?;
            let end = self.coordinator.durable_end_data_v1().checked_add(appended)
                .ok_or(aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1::JournalTooLarge)?;
            models.checked_add(aos_sandbox_ledger_replay::geometry::retained_challenge_history_demand_v1(end)?)
                .map_err(|_| aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1::JournalTooLarge)
        })();
        match shape {
            Ok(shape) => self.coordinator.prepay_semantic_append_demand_once_v1(transaction, shape)?,
            Err(cause) => return self.coordinator.refuse_semantic_geometry_once(cause),
        }
        self.coordinator.prepay_append_interval_once(transaction, upper_interval_bytes)
    }

    /// Arms the already-paid independent native post before the upper body.
    ///
    /// # Errors
    /// Preserves the original same-writer stage refusal or native failure.
    #[doc(hidden)]
    pub fn begin_independent_native_post_once(&mut self) -> Result<SourceNativePostOriginalV1, SourceNativeErrorV1> {
        self.coordinator.begin_independent_native_post_once()
    }

    /// Attempts the same already-owed native post even after body refusal.
    ///
    /// # Errors
    /// Preserves the original same-writer stage refusal or native failure.
    #[doc(hidden)]
    pub fn finish_independent_native_post_once(&self, post: &mut SourceNativePostOriginalV1) -> Result<(), SourceNativeErrorV1> {
        self.coordinator.finish_independent_native_post_once(post)
    }

    /// Disposes the completed native post after the actual upper posts.
    ///
    /// # Errors
    /// Preserves the original same-writer stage refusal or native failure.
    #[doc(hidden)]
    pub fn dispose_native_post_after_upper_posts_once(&mut self, post: &mut SourceNativePostOriginalV1) -> Result<(), SourceNativeErrorV1> {
        self.coordinator.dispose_native_post_after_upper_posts_once(post)
    }

    /// Prepares the original paid transaction through the sole shared append stages.
    ///
    /// # Errors
    /// Preserves the original same-writer stage refusal or native failure.
    #[doc(hidden)]
    pub fn prepare_append_once(&mut self, transaction: &JournalTransaction) -> Result<SourcePreparedAppendV1, SourceNativeErrorV1> {
        self.coordinator.prepare_append_once(transaction)
    }

    /// Computes the same prepared stage coordinates at the original frontier.
    ///
    /// # Errors
    /// Preserves the original same-writer stage refusal or native failure.
    #[doc(hidden)]
    pub fn append_coordinates_once(&self, stage: &mut SourcePreparedAppendV1) -> Result<(u64, u64), SourceNativeErrorV1> {
        self.coordinator.append_coordinates_once(stage)
    }

    /// Samples the expected append length through the same retained native stage.
    ///
    /// # Errors
    /// Preserves the original same-writer stage refusal or native failure.
    #[doc(hidden)]
    pub fn expected_append_length_once(&self, stage: &mut SourcePreparedAppendV1) -> Result<u64, SourceNativeErrorV1> {
        self.coordinator.expected_append_length_once(stage)
    }

    /// Appends the actual stage frames through the same fixed writer.
    ///
    /// # Errors
    /// Preserves the original same-writer stage refusal or native failure.
    #[doc(hidden)]
    pub fn append_prepared_once(&mut self, stage: &mut SourcePreparedAppendV1) -> Result<u64, SourceNativeErrorV1> {
        self.coordinator.append_prepared_once(stage)
    }

    /// Applies one native record then its index entry before the next record.
    ///
    /// # Errors
    /// Preserves the original same-writer stage refusal or native failure.
    #[doc(hidden)]
    pub fn apply_next_record_once(&mut self, stage: &mut SourcePreparedAppendV1) -> Result<bool, SourceNativeErrorV1> {
        self.coordinator.apply_next_record_once(stage)
    }

    /// Publishes the same actual native coordinates after all record applications.
    ///
    /// # Errors
    /// Preserves the original same-writer stage refusal or native failure.
    #[doc(hidden)]
    pub fn publish_append_once(&mut self, stage: &mut SourcePreparedAppendV1) -> Result<CanonicalAppendPublishedDataV1, SourceNativeErrorV1> {
        self.coordinator.publish_append_once(stage)
    }

    /// Disposes the completed stage after the same actual upper posts.
    ///
    /// # Errors
    /// Preserves the original same-writer stage refusal or native failure.
    #[doc(hidden)]
    pub fn finish_append_after_posts_once(&mut self, stage: &mut SourcePreparedAppendV1) -> Result<(), SourceNativeErrorV1> {
        self.coordinator.finish_append_after_posts_once(stage)
    }

    /// Restricts the same C-funded replacement representation before growth.
    ///
    /// # Errors
    /// Preserves the original same-writer stage refusal or native failure.
    #[doc(hidden)]
    pub fn debit_replacement_semantic_bytes_v1(&mut self, bytes: usize) -> Result<(), SourceNativeErrorV1> {
        // The sole replacement encoder writes precisely this held full State.
        // Its compacted transaction bypasses ordinary transition validation;
        // complete state/family checks still run through the same driver.
        let shape = (|| {
            let models = aos_sandbox_ledger_replay::geometry::complete_replay_demand_v1(
                self.coordinator.coordinator_read_view().state(), None,
            )?;
            let history = aos_sandbox_ledger_replay::geometry::retained_challenge_history_demand_v1(
                self.coordinator.durable_end_data_v1(),
            )?;
            // Old historical checkpoints remain beside the replacement's
            // freshly captured committed rows until actual installation.
            models.checked_add(history).and_then(|value| value.checked_add(history))
                .map_err(|_| aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1::JournalTooLarge)
        })();
        match shape {
            Ok(shape) => self.coordinator.prepay_semantic_demand_once(shape)?,
            Err(cause) => return self.coordinator.refuse_semantic_geometry_once(cause),
        }
        self.coordinator.debit_replacement_semantic_bytes_v1(bytes)
    }

    /// Prepares the same fixed-writer replacement with its prearmed native bookends.
    ///
    /// # Errors
    /// Preserves the original same-writer stage refusal or native failure.
    #[doc(hidden)]
    pub fn prepare_source_replacement_once(&mut self) -> Result<SourcePreparedReplacementV1<P>, SourceNativeErrorV1> {
        self.coordinator.prepare_source_replacement_once()
    }

    /// Installs the actual replacement after its complete replay.
    ///
    /// # Errors
    /// Preserves the original same-writer stage refusal or native failure.
    #[doc(hidden)]
    pub fn install_source_replacement_once(&mut self, replacement: &mut SourcePreparedReplacementV1<P>) -> Result<(), SourceNativeErrorV1> {
        self.coordinator.install_source_replacement_once(replacement)
    }

    /// Attempts the independently owed replacement names post on every entered outcome.
    ///
    /// # Errors
    /// Preserves the original same-writer stage refusal or native failure.
    #[doc(hidden)]
    pub fn observe_source_replacement_after_once(&mut self, replacement: &mut SourcePreparedReplacementV1<P>) -> Result<(), SourceNativeErrorV1> {
        self.coordinator.observe_source_replacement_after_once(replacement)
    }

    /// Disposes the same replacement only after the actual upper posts.
    ///
    /// # Errors
    /// Preserves the original same-writer stage refusal or native failure.
    #[doc(hidden)]
    pub fn finish_source_replacement_after_posts_once(&mut self, replacement: &mut SourcePreparedReplacementV1<P>) -> Result<(), SourceNativeErrorV1> {
        self.coordinator.finish_source_replacement_after_posts_once(replacement)
    }
}

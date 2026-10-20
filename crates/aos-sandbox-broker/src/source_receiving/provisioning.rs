//! Retains Source bookends under the same actual C23 provisioning original.
//!
//! These native names are independent of Source lifecycle semantics. The upper
//! purpose must still lend its exact prepared transaction and current Root
//! window; neither a financial debit nor these samples authorizes a mutation.

use std::error::Error;
use std::path::Path;
use std::sync::Arc;

use aos_sandbox_core::{ResourceDimension, ResourceVector};
use crate::canonical_journal::NativeJournalDataErrorV1;
use crate::canonical_journal::coordinator::selected_append::SelectedAppendCustodyV1;
use crate::controller_receiving::bank_launch::{
    ControllerBankLaunchErrorV1, ControllerBankLaunchOriginalV1,
    ControllerCoordinatorWriterV1, ControllerCreateProvisioningReceivingV1,
    ControllerCreateProvisioningCompletionDestinationV1,
};
use crate::controller_receiving::profile::ControllerSelfProfileOriginalV1;
use crate::writer_currentness::WriterCurrentnessOriginalsV1;
use super::{SourceCoordinatorWriterV1, SourceNativeErrorV1};
use super::append::SourceAppendBodyV1;
use super::recipe::{SOURCE_DOMAIN_DIRECTORY_V1, SOURCE_DOMAIN_JOURNAL_V1};

type Sample = WriterCurrentnessOriginalsV1<NativeJournalDataErrorV1>;

#[derive(Clone, Copy)]
enum StopAuxiliaryPublicationV1 { Dispatch, Completion }

impl StopAuxiliaryPublicationV1 {
    fn selector(self) -> (aos_sandbox_protocol::domain_ledger::lifecycle_auxiliary::LifecycleAuxiliaryEnvelopeFormatV1, u8, u16) {
        use aos_sandbox_protocol::domain_ledger::lifecycle_auxiliary::LifecycleAuxiliaryEnvelopeFormatV1 as Format;
        match self { Self::Dispatch => (Format::StopDispatch, 7, 0x81),
            Self::Completion => (Format::StopCompletion, 8, 0x101) }
    }
}

mod catalog_maintenance;
pub use catalog_maintenance::SourceCatalogMaintenanceCurrentnessOriginalV2;
mod recovered_enrollment;
pub use recovered_enrollment::SourceRecoveredEnrollmentCurrentnessOriginalV2;

/// Retains two independently armed names observations of the original Source.
///
/// No constructor accepts saved names, a descriptor or a success flag. The same
/// Source lock and genuine C23 must be rejoined at the actual upper crossings.
#[must_use = "finish Source and C23 native posts before disposing this original"]
pub struct SourceProvisioningCurrentnessOriginalV1 {
    identity: Arc<SelectedAppendCustodyV1<SourceAppendBodyV1>>,
    sequence: u64,
    completion_prearmed: bool,
    stop_dispatch_successor: bool,
    before: Sample,
    after: Sample,
    before_result: Option<Result<(), NativeJournalDataErrorV1>>,
    after_result: Option<Result<(), NativeJournalDataErrorV1>>,
    after_coordinates: Option<(u64, u64)>,
    entered_after: bool,
    complete: bool,
    reentry: Option<SourceNativeErrorV1>,
}

impl SourceProvisioningCurrentnessOriginalV1 {
    /// Supplies the actual native pair and its compiled retained/constructor peak.
    ///
    /// # Errors
    /// Refuses checked compiled or fixed native name geometry overflow.
    pub fn receiving_demand_v1() -> Result<ResourceVector, ControllerBankLaunchErrorV1> {
        let bytes = std::mem::size_of::<Self>().checked_mul(2)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        let sample = Sample::fixed_demand_v1(
            Path::new(SOURCE_DOMAIN_DIRECTORY_V1), SOURCE_DOMAIN_JOURNAL_V1,
        )?;
        Ok(ResourceVector::ZERO.with(ResourceDimension::MemoryBytes, bytes)
            .checked_add(sample)?.checked_add(sample)?)
    }

    /// Borrows the first native Source cause, with before preceding after.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.before.failure()
            .or_else(|| error(&self.before_result))
            .or_else(|| self.after.failure())
            .or_else(|| error(&self.after_result))
            .or_else(|| self.reentry.as_ref().map(|cause| cause as _))
    }
}

impl<P> SourceCoordinatorWriterV1<P> {
    /// Enters the same Source only under an actual current C23 original.
    ///
    /// The complete bound is admitted before constructing either destination.
    /// Both are armed before the first Source observation; any subsequent
    /// semantic/decode/debit refusal still owes the independent Source after.
    /// Source's original native/index financial owner remains unchanged.
    ///
    /// # Errors
    /// Refuses overlap, another C, failed currentness or insufficient same-C
    /// representation. A returned value may retain failed native before work.
    pub fn begin_provisioning_currentness_once_v1<C>(
        &mut self,
        receiving: &mut ControllerCreateProvisioningReceivingV1,
        controller: &ControllerCoordinatorWriterV1<C>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        co_resident: ResourceVector,
    ) -> Result<SourceProvisioningCurrentnessOriginalV1, ControllerBankLaunchErrorV1> {
        self.require_idle().map_err(|_| ControllerBankLaunchErrorV1::Conflict)?;
        receiving.require_source_original_v1(&self.original, controller, launch, profile)?;
        let complete = co_resident.checked_add(
            SourceProvisioningCurrentnessOriginalV1::receiving_demand_v1()?,
        )?;
        receiving.require_complete_representation_v1(controller, launch, profile, complete)?;

        self.prepare_provisioning_pair_v1(false)
    }

    fn prepare_provisioning_pair_v1(&mut self, completion_prearmed: bool)
        -> Result<SourceProvisioningCurrentnessOriginalV1, ControllerBankLaunchErrorV1> {
        self.provisioning_scope_active = true;
        let mut original = SourceProvisioningCurrentnessOriginalV1 {
            identity: Arc::clone(&self.custody),
            sequence: self.next_sequence(), completion_prearmed,
            stop_dispatch_successor: false,
            before: Sample::new(),
            after: Sample::new(),
            before_result: None,
            after_result: None,
            after_coordinates: None,
            entered_after: false,
            complete: false,
            reentry: None,
        };
        let after_arm = original.after.begin(true);
        let before_arm = original.before.begin(true);
        if completion_prearmed {
            if let Err(cause) = before_arm {
                original.before_result = Some(original.before.finish(Err(cause)));
            }
        } else {
            let before = before_arm.and_then(|()| self.physical.observe_names_into(&mut original.before));
            original.before_result = Some(original.before.finish(before));
        }
        if let Err(cause) = after_arm {
            original.after_result = Some(Err(cause));
        }
        Ok(original)
    }

    /// Selects only the exact transaction already checked by the upper schema.
    ///
    /// This mechanical selection does not bypass the ordinary semantic guard.
    /// The Native lifecycle loan still validates the same original prepared
    /// transaction at preflight and immediately before the shared append.
    ///
    /// # Errors
    /// Refuses changed Source/C23, failed before, reentry or another transaction.
    pub fn bind_provisioning_transaction_once_v1<C>(
        &mut self,
        original: &mut SourceProvisioningCurrentnessOriginalV1,
        receiving: &ControllerCreateProvisioningReceivingV1,
        controller: &ControllerCoordinatorWriterV1<C>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        transaction: &aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.require_provisioning_binding_v1(original)?;
        receiving.require_source_original_v1(&self.original, controller, launch, profile)?;
        self.select_provisioning_transaction_v1(transaction);
        Ok(())
    }

    /// Rejoins a paid readonly use of the same Source and current C original.
    ///
    /// No transaction is selected. Every ordinary append remains fenced while
    /// this independently armed native pair is active.
    ///
    /// # Errors
    /// Refuses changed Source/C/profile, failed before or an entered after.
    pub fn require_provisioning_readonly_current_v1<C>(
        &self, original: &mut SourceProvisioningCurrentnessOriginalV1,
        receiving: &ControllerCreateProvisioningReceivingV1,
        controller: &ControllerCoordinatorWriterV1<C>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.require_provisioning_binding_v1(original)?;
        receiving.require_source_original_v1(&self.original, controller, launch, profile)
    }

    fn require_provisioning_binding_v1(&self, original: &mut SourceProvisioningCurrentnessOriginalV1)
        -> Result<(), ControllerBankLaunchErrorV1> {
        if original.entered_after || original.complete || original.failure().is_some()
            || !matches!(original.before_result, Some(Ok(())))
            || !Arc::ptr_eq(&original.identity, &self.custody)
            || self.next_sequence() != original.sequence
            || !self.provisioning_scope_active || self.provisioning_transaction.is_some() {
            original.reentry.get_or_insert(SourceNativeErrorV1::Closed);
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        Ok(())
    }

    fn select_provisioning_transaction_v1(&mut self,
        transaction: &aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction,
    ) {

        self.provisioning_transaction = Some(
            aos_sandbox_protocol::domain_ledger::transaction::transaction_preflight_comparison_digest_v1(
                std::slice::from_ref(transaction),
            ),
        );
    }

    pub(super) fn require_append_entry_v1(&self,
        transaction: &aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction,
    ) -> Result<(), SourceNativeErrorV1> {
        if !self.provisioning_scope_active {
            return self.require_idle();
        }
        let digest = aos_sandbox_protocol::domain_ledger::transaction::transaction_preflight_comparison_digest_v1(
            std::slice::from_ref(transaction),
        );
        if self.provisioning_transaction != Some(digest) || self.delete_scope_active
            || self.has_native_uncertainty_v1() || !self.custody.is_idle()
            || !self.replacement_custody.is_idle() || !self.physical.replacement_custody.is_idle() {
            return Err(SourceNativeErrorV1::Closed);
        }
        Ok(())
    }

    /// Restricts actual reached Source models for one exact selected append.
    ///
    /// # Errors
    /// Refuses another transaction, overlap or insufficient Source original.
    #[doc(hidden)]
    pub fn prepay_semantic_append_demand_once_v1(&mut self,
        transaction: &aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction,
        demand: ResourceVector,
    ) -> Result<(), SourceNativeErrorV1> {
        self.require_append_entry_v1(transaction)?;
        self.prepay_semantic_demand_inner_v1(demand)
    }

    /// Arms the same independent append post at its exact transaction frontier.
    ///
    /// # Errors
    /// Refuses another transaction or an unprepaid/overlapping native append.
    #[doc(hidden)]
    pub fn begin_native_post_for_append_once_v1(&mut self,
        transaction: &aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction,
    ) -> Result<super::SourceNativePostOriginalV1, SourceNativeErrorV1> {
        self.require_append_entry_v1(transaction)?;
        self.begin_independent_native_post_inner_v1()
    }

    /// Rejoins this interval's actual published Stop dispatch append and readback.
    ///
    /// The original before sequence and deadline remain unchanged. Only the
    /// same writer's successfully disposed canonical append can populate the
    /// private publication slot; supplied transaction DATA cannot do so.
    ///
    /// # Errors
    /// Retains foreign/repeated use, changed selected transaction, another
    /// native head or unequal actual Operation/Dispatch readback as refusal.
    pub fn require_stop_dispatch_successor_once_v1(
        &self, original: &mut SourceProvisioningCurrentnessOriginalV1,
        transaction: &aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction,
        expected_head: u64,
    ) -> Result<(), SourceNativeErrorV1> {
        self.require_stop_auxiliary_successor_once_v1(original, transaction,
            expected_head, StopAuxiliaryPublicationV1::Dispatch)
    }

    /// Rejoins only this interval's actually published independent A8 pair.
    ///
    /// This supplies native publication/readback, never semantic append power.
    /// The genuine Source22/Host3/Root48 loan separately authorizes the write.
    ///
    /// # Errors
    /// Retains repeated/foreign entry, changed Source transaction or publication,
    /// mismatched A8 members, and incomplete actual native member readback.
    pub fn require_stop_cleanup_completion_successor_once_v1(
        &self, original: &mut SourceProvisioningCurrentnessOriginalV1,
        transaction: &aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction,
        expected_head: u64,
    ) -> Result<(), SourceNativeErrorV1> {
        self.require_stop_auxiliary_successor_once_v1(original, transaction,
            expected_head, StopAuxiliaryPublicationV1::Completion)
    }

    fn require_stop_auxiliary_successor_once_v1(
        &self, original: &mut SourceProvisioningCurrentnessOriginalV1,
        transaction: &aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction,
        expected_head: u64, purpose: StopAuxiliaryPublicationV1,
    ) -> Result<(), SourceNativeErrorV1> {
        let checked = (|| {
            use aos_sandbox_protocol::domain_ledger::lifecycle_auxiliary::{
                borrow_lifecycle_auxiliary_member_data_v1,
            };
            let (format, value_kind, expected_members) = purpose.selector();
            let closed = || SourceNativeErrorV1::Closed;
            let digest = aos_sandbox_protocol::domain_ledger::transaction::transaction_preflight_comparison_digest_v1(
                std::slice::from_ref(transaction));
            let (actual_digest, published) = self.provisioning_publication.ok_or_else(closed)?;
            if original.entered_after || original.complete || original.stop_dispatch_successor
                || original.failure().is_some() || !matches!(original.before_result, Some(Ok(())))
                || !Arc::ptr_eq(&original.identity, &self.custody)
                || !self.provisioning_scope_active || !self.custody.is_idle()
                || self.has_native_uncertainty_v1() || self.native_post_active || self.delete_scope_active
                || self.provisioning_transaction != Some(digest) || actual_digest != digest
                || original.sequence != expected_head
                || published.transaction != *transaction.id() || published.head != original.sequence
                || published.following != self.next_sequence() || published.durable_bytes != self.durable_end
                || transaction.records().len() != 2
            {
                return Err(closed());
            }
            let mut members = 0_u16;
            let mut identity = None;
            for record in transaction.records() {
                let value = record.value().ok_or_else(closed)?;
                let frame = borrow_lifecycle_auxiliary_member_data_v1(record.key(), value, transaction.id())
                    .map_err(|_| closed())?;
                if frame.format != format || (frame.kind != 0 && frame.kind != value_kind)
                    || frame.declared_members != expected_members || frame.declared_count != 2
                    || self.physical.native.native().state().iter().find(|((namespace, key), _)|
                        *namespace == record.namespace() && key.as_slice() == record.key())
                        .is_none_or(|(_, actual)| actual.as_slice() != value)
                {
                    return Err(closed());
                }
                let selected = (frame.project, frame.operation, frame.operation_revision,
                    frame.operation_record, frame.atomic_join, frame.join_digest);
                if identity.is_some_and(|previous| previous != selected)
                    || members & (1_u16 << frame.kind) != 0
                {
                    return Err(closed());
                }
                identity = Some(selected);
                members |= 1_u16 << frame.kind;
            }
            if members != expected_members { return Err(closed()); }
            Ok(())
        })();
        if checked.is_err() {
            original.reentry.get_or_insert(SourceNativeErrorV1::Closed);
        } else {
            original.stop_dispatch_successor = true;
        }
        checked
    }

    /// Runs the original Source after without a healthy C23/body prerequisite.
    ///
    /// # Errors
    /// Retains the actual native after error, or refuses foreign/repeated work.
    pub fn finish_provisioning_currentness_once_v1(
        &self, original: &mut SourceProvisioningCurrentnessOriginalV1,
    ) -> Result<(), SourceNativeErrorV1> {
        if original.entered_after || original.complete
            || !Arc::ptr_eq(&original.identity, &self.custody) {
            original.reentry.get_or_insert(SourceNativeErrorV1::Closed);
            return Err(SourceNativeErrorV1::Closed);
        }
        original.entered_after = true;
        if original.completion_prearmed && original.before_result.is_none() {
            let observed = self.physical.observe_names_into(&mut original.before);
            original.before_result = Some(original.before.finish(observed));
        }
        if original.after_result.is_none() {
            let result = self.physical.observe_names_into(&mut original.after);
            original.after_result = Some(original.after.finish(result));
        }
        original.after_coordinates = Some((self.next_sequence(), self.durable_end));
        if original.failure().is_some() { Err(SourceNativeErrorV1::Closed) } else { Ok(()) }
    }

    /// Disposes only the exact completed native pair after actual C23 posts.
    ///
    /// This admits no next turn, semantic publication or financial refund.
    ///
    /// # Errors
    /// Refuses failed Source/C23 posts, changed original/Source prefix or reentry.
    pub fn dispose_provisioning_currentness_after_posts_v1<C>(
        &mut self,
        original: &mut SourceProvisioningCurrentnessOriginalV1,
        receiving: &ControllerCreateProvisioningReceivingV1,
        controller: &ControllerCoordinatorWriterV1<C>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.require_provisioning_disposal_v1(original)?;
        receiving.require_completed_original_v1(controller, launch, profile)?;
        receiving.require_completed_source_original_v1(&self.original)?;
        receiving.require_stop_cleanup_session_disposal_v1()?;
        self.dispose_provisioning_pair_v1(original);
        Ok(())
    }

    fn require_provisioning_disposal_v1(&self, original: &SourceProvisioningCurrentnessOriginalV1)
        -> Result<(), ControllerBankLaunchErrorV1> {
        if original.complete || !original.entered_after || original.failure().is_some()
            || !matches!(original.before_result, Some(Ok(())))
            || !matches!(original.after_result, Some(Ok(())))
            || original.after_coordinates != Some((self.next_sequence(), self.durable_end))
            || !Arc::ptr_eq(&original.identity, &self.custody)
            || !self.provisioning_scope_active || self.native_post_active || self.append_prepaid
            || !self.custody.is_idle() || self.has_native_uncertainty_v1() {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        Ok(())
    }

    fn dispose_provisioning_pair_v1(&mut self, original: &mut SourceProvisioningCurrentnessOriginalV1) {

        original.before.settle_positive_once_v1();
        original.after.settle_positive_once_v1();
        self.provisioning_scope_active = false;
        self.provisioning_transaction = None;
        self.provisioning_publication = None;
        original.complete = true;
    }

}

impl<P> SourceCoordinatorWriterV1<P> {
    /// Prepays both actual Source destinations before the final Root request.
    ///
    /// The same active C23 rejoin and intrinsic Source original remain required.
    /// The body observation is deferred until its typed upper ACK gate succeeds.
    ///
    /// # Errors
    /// Refuses overlap, foreign custody or unpayable complete representation.
    /// A returned negative owner remains retained with its independently owed post.
    pub fn prearm_completion_source_currentness_once_v1<C>(&mut self,
        receiving: &mut ControllerCreateProvisioningReceivingV1,
        controller: &ControllerCoordinatorWriterV1<C>, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1, co_resident: ResourceVector,
    ) -> Result<SourceProvisioningCurrentnessOriginalV1, ControllerBankLaunchErrorV1> {
        self.require_idle().map_err(|_| ControllerBankLaunchErrorV1::Conflict)?;
        receiving.require_source_original_v1(&self.original, controller, launch, profile)?;
        let complete = co_resident.checked_add(SourceProvisioningCurrentnessOriginalV1::receiving_demand_v1()?)?;
        receiving.require_complete_representation_v1(controller, launch, profile, complete)?;
        self.prepare_provisioning_pair_v1(true)
    }

    /// Observes the prearmed Source before under the actual completion native interval.
    ///
    /// The Native upper caller first validates its genuine Root completion/ordinal.
    /// This method supplies no semantic grant and performs no new financial debit.
    ///
    /// # Errors
    /// Retains failed before work or refuses foreign, repeated or unprepared entry.
    pub fn enter_completion_source_currentness_once_v1<C>(&self,
        original: &mut SourceProvisioningCurrentnessOriginalV1,
        destination: &ControllerCreateProvisioningCompletionDestinationV1,
        completed: &ControllerCreateProvisioningReceivingV1,
        controller: &ControllerCoordinatorWriterV1<C>, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        if !original.completion_prearmed || original.entered_after || original.complete
            || original.before_result.is_some() || !Arc::ptr_eq(&original.identity, &self.custody)
            || self.next_sequence() != original.sequence || !self.provisioning_scope_active {
            original.reentry.get_or_insert(SourceNativeErrorV1::Closed);
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        destination.require_current_v1(completed, controller, launch, profile)?;
        completed.require_completed_source_original_v1(&self.original)?;
        let observed = self.physical.observe_names_into(&mut original.before);
        original.before_result = Some(original.before.finish(observed));
        if matches!(original.before_result, Some(Ok(()))) { Ok(()) }
        else { Err(ControllerBankLaunchErrorV1::Conflict) }
    }

    /// Binds only the exact transaction checked by the typed upper completion loan.
    ///
    /// # Errors
    /// Refuses a changed Source/C/destination or missing actual before observation.
    pub fn bind_completion_source_transaction_once_v1<C>(&mut self,
        original: &mut SourceProvisioningCurrentnessOriginalV1,
        destination: &ControllerCreateProvisioningCompletionDestinationV1,
        completed: &ControllerCreateProvisioningReceivingV1,
        controller: &ControllerCoordinatorWriterV1<C>, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        transaction: &aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.require_provisioning_binding_v1(original)?;
        if !original.completion_prearmed { return Err(ControllerBankLaunchErrorV1::Conflict); }
        destination.require_current_v1(completed, controller, launch, profile)?;
        completed.require_completed_source_original_v1(&self.original)?;
        self.select_provisioning_transaction_v1(transaction);
        Ok(())
    }

    /// Disposes the same completed Source pair after the genuine completion interval.
    ///
    /// # Errors
    /// Refuses missing/failed posts, another Source or incomplete native disposition.
    pub fn dispose_completion_source_currentness_once_v1<C>(&mut self,
        original: &mut SourceProvisioningCurrentnessOriginalV1,
        destination: &ControllerCreateProvisioningCompletionDestinationV1,
        completed: &ControllerCreateProvisioningReceivingV1,
        controller: &ControllerCoordinatorWriterV1<C>, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.require_provisioning_disposal_v1(original)?;
        if !original.completion_prearmed { return Err(ControllerBankLaunchErrorV1::Conflict); }
        destination.require_completed_original_v1(completed, controller, launch, profile)?;
        completed.require_completed_source_original_v1(&self.original)?;
        self.dispose_provisioning_pair_v1(original);
        Ok(())
    }
}

impl Drop for SourceProvisioningCurrentnessOriginalV1 {
    fn drop(&mut self) {
        if !self.complete {
            std::process::abort();
        }
    }
}

fn error<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}

/// Retains Source observation under the successor's genuine Recover payer.
///
/// This original has no transaction-binding or append projection. Historical
/// Source/C bytes, including successful completion, remain comparison DATA.
#[must_use = "retain the Source pair through recovery and all original posts"]
pub struct SourceOperatorRecoverCurrentnessOriginalV1 {
    native: SourceProvisioningCurrentnessOriginalV1,
}

impl SourceOperatorRecoverCurrentnessOriginalV1 {
    /// Prices the same actual fixed native pair and constructor storage.
    ///
    /// # Errors
    /// Refuses unrepresentable physical native name or compiled geometry.
    pub fn receiving_demand_v1() -> Result<ResourceVector, ControllerBankLaunchErrorV1> {
        let wrapper = u64::try_from(std::mem::size_of::<Self>())
            .map_err(|_| ControllerBankLaunchErrorV1::Conflict)?;
        Ok(SourceProvisioningCurrentnessOriginalV1::receiving_demand_v1()?
            .checked_add(ResourceVector::ZERO.with(ResourceDimension::MemoryBytes, wrapper))?)
    }

    /// Borrows the retained before/after native refusal.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.native.failure()
    }
}

impl<P> SourceCoordinatorWriterV1<P> {
    /// Arms independent Source observations after actual Recover prepayment.
    ///
    /// # Errors
    /// Refuses overlap, foreign C/Source/profile or insufficient same-C demand.
    /// Returned failed observations remain whole for independently owed posts.
    pub fn begin_operator_recover_currentness_once_v1<C>(
        &mut self,
        receiving: &mut crate::controller_receiving::bank_launch::ControllerOperatorRecoverReceivingV1,
        controller: &ControllerCoordinatorWriterV1<C>, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1, co_resident: ResourceVector,
    ) -> Result<SourceOperatorRecoverCurrentnessOriginalV1, ControllerBankLaunchErrorV1> {
        self.require_idle().map_err(|_| ControllerBankLaunchErrorV1::Conflict)?;
        receiving.require_source_original_v1(&self.original, controller, launch, profile)?;
        let complete = co_resident.checked_add(
            SourceOperatorRecoverCurrentnessOriginalV1::receiving_demand_v1()?,
        )?;
        receiving.require_complete_representation_v1(controller, launch, profile, complete)?;
        Ok(SourceOperatorRecoverCurrentnessOriginalV1 {
            native: self.prepare_provisioning_pair_v1(false)?,
        })
    }

    /// Runs the prepaid independent Source after even when the body refused.
    ///
    /// # Errors
    /// Retains actual same-Source observation or repeated/foreign refusal.
    pub fn finish_operator_recover_currentness_once_v1(&self,
        original: &mut SourceOperatorRecoverCurrentnessOriginalV1,
    ) -> Result<(), SourceNativeErrorV1> {
        self.finish_provisioning_currentness_once_v1(&mut original.native)
    }

    /// Disposes the observed prefix only after actual Recover C native posts.
    ///
    /// # Errors
    /// Refuses changed Source prefix, failed or incomplete C/Source disposal.
    pub fn dispose_operator_recover_currentness_after_posts_v1<C>(
        &mut self, original: &mut SourceOperatorRecoverCurrentnessOriginalV1,
        receiving: &crate::controller_receiving::bank_launch::ControllerOperatorRecoverReceivingV1,
        controller: &ControllerCoordinatorWriterV1<C>, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.require_provisioning_disposal_v1(&original.native)?;
        receiving.require_completed_original_v1(controller, launch, profile)?;
        receiving.require_completed_source_original_v1(&self.original)?;
        self.dispose_provisioning_pair_v1(&mut original.native);
        Ok(())
    }
}

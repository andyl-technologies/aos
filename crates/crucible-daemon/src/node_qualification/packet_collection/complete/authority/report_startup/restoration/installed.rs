//! Connects the actual four-owner proof to common Runtime7 installation.
//!
//! Publisher and concrete directory owners enter the retained capsule before the
//! first window issue. Every subsequent group transition ends its mutable loans
//! and repeats the same full owning observation before dispatching another one.

use super::*;
use crucible_cas::content_store::{DirectoryBlobBackend, DirectoryRefBackend};
use std::sync::Arc;

impl PacketCompleteReportStartupHolder {
    /// Restores the original complete world through its actual installed owners.
    ///
    /// The source, tickets and actual native attempts remain in this registered
    /// holder through failure. Final context issuance requires all three genuine
    /// committed Holds and the fourth actual Host validator. Durable publication
    /// precedes common-runtime installation and the complete three-node World
    /// dispatch. Scheduling Observe starts only after all three actual phases.
    ///
    /// # Errors
    /// Refuses foreign or repeated owners, missing full construction admission,
    /// changed four-owner histories, unavailable durable publication or failed
    /// native/source/currentness/resource checks. Started effects are not retried.
    pub fn execute_original_complete_restoration(
        original: &Rc<RefCell<Self>>,
        activation: &crucible::node_contract::ActivationRecord,
        prepare_ids: &mut Option<[Id; 3]>,
        commit_ids: &mut Option<[Id; 3]>,
        publisher: &mut Option<crate::node_observed_executor::StoredWorldActivationPublisher>,
        blobs: Arc<DirectoryBlobBackend>,
        refs: Arc<DirectoryRefBackend>,
    ) -> Result<(), RuntimeError> {
        {
            let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
            held.authenticate_native_origin_data()?;
            if held.restoration_attempted.get() || held.restoration_publication.get().is_some() {
                return Err(RuntimeError::OutstandingObligations);
            }
            let StartupHolderPurpose::FreshRestoration(capsule) = &held.purpose else {
                return Err(RuntimeError::ForeignAuthority);
            };
            let maximum = held.restoration_policy_data()?.maximum_requested_bytes;
            let owner = capsule
                .try_borrow_mut()
                .map_err(|_| RuntimeError::OwnerBusy)?
                .retain_original_directory_publication_into(publisher, blobs, refs, maximum)?;
            held.restoration_publication
                .set(owner)
                .map_err(|_| RuntimeError::DuplicateOperation)?;
        }
        Self::execute_original_restoration_transfer(original, activation, prepare_ids, commit_ids)?;
        let (window, plan, capsule) = {
            let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
            let StartupHolderPurpose::FreshRestoration(capsule) = &held.purpose else {
                return Err(RuntimeError::ForeignAuthority);
            };
            (
                Rc::clone(
                    held.restoration_window
                        .get()
                        .ok_or(RuntimeError::OwnerUnavailable)?,
                ),
                Rc::clone(&held.plan),
                Rc::clone(capsule),
            )
        };
        capsule
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?
            .construct_original_complete_scope(&window, &plan, activation)?;
        Self::recheck_original_restoration_transaction_data(original, activation)?;
        let context = capsule
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?
            .prepare_original_complete_context(&window, &plan)?;
        capsule
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?
            .prepare_original_complete_scheduler(&window, &plan, &context)?;
        Self::recheck_original_restoration_transaction_data(original, activation)?;
        capsule
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?
            .arm_original_complete_restoration(&window, &plan, &context)?;
        Self::recheck_original_restoration_transaction_data(original, activation)?;
        capsule
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?
            .retain_original_complete_coordinator(&window, &plan, &context)?;
        Self::recheck_original_restoration_transaction_data(original, activation)?;
        capsule
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?
            .publish_original_complete_restoration(&window, &plan, &context)?;
        Self::recheck_original_restoration_transaction_data(original, activation)?;
        capsule
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?
            .install_original_complete_restoration(&window, &plan, &context)?;
        Self::recheck_original_restoration_transaction_data(original, activation)?;
        capsule
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?
            .activate_original_complete_restoration_worlds(&window, &plan, &context)?;
        Self::recheck_original_restoration_transaction_data(original, activation).map(|_| ())
    }
}

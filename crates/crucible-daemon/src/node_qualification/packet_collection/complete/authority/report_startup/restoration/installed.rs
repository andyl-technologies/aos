//! Connects the actual four-owner proof to common Runtime7 installation.
//!
//! Publisher and concrete directory owners enter the retained capsule before the
//! first window issue. Every subsequent group transition ends its mutable loans
//! and repeats the same full owning observation before dispatching another one.

use super::*;
use crucible::node_adapters::cnp::{CnpSemanticSource, PacketCompleteOriginalHostSdk};
use crucible::node_admission::{
    OriginalRestoredInitialSchedulingAdmission, OriginalRestoredSchedulingObservationAdmission,
};
use crucible::node_contract::RuntimePollFailure;
use crucible::node_scheduling::ValidatedSchedulingObservation;
use crucible_node_provider::reference_packet::service::PacketNative5SourceLaunch;

use crucible_cas::content_store::{DirectoryBlobBackend, DirectoryRefBackend};
use std::sync::Arc;

impl PacketCompleteReportStartupHolder {
    /// Releases redundant decoded native and registry imports after real seeding.
    ///
    /// This explicit local administration retains the original archive, decoded
    /// Host and every live journal. It neither changes immutable binding bytes nor
    /// performs Capture, native publication or operation retirement.
    ///
    /// # Errors
    /// Refuses foreign/incomplete installation, previous actions or release,
    /// busy owners, stale evidence and the unchanged full resource policy.
    pub fn release_original_restored_import_duplicates(
        original: &Rc<RefCell<Self>>,
        activation: &crucible::node_contract::ActivationRecord,
    ) -> Result<(usize, usize), RuntimeError> {
        let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        held.authenticate_native_origin_data()?;
        let window = held
            .restoration_window
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let StartupHolderPurpose::FreshRestoration(capsule) = &held.purpose else {
            return Err(RuntimeError::ForeignAuthority);
        };
        let outputs = held
            .host_sdk_outputs
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let sdks = [
            outputs[0].as_ref().ok_or(RuntimeError::OwnerUnavailable)?,
            outputs[1].as_ref().ok_or(RuntimeError::OwnerUnavailable)?,
            outputs[2].as_ref().ok_or(RuntimeError::OwnerUnavailable)?,
        ];
        let capsule = capsule.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        let runtime = capsule.runtime_data()?;
        window.release_original_installed_import_duplicates(
            &held.plan,
            sdks,
            &held.authority.original_launches,
            held.authority
                .private_launches
                .each_ref()
                .map(Vec::as_slice),
            &runtime,
            activation,
        )
    }

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
            if held.fresh_lifecycle.get().is_some() {
                held.authenticate_completed_fresh_runtime_data()?;
            }
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
        // A selected17 world funds and retains its inherited coordinator log
        // before Arm or durable publication. The initializer invalidates the
        // whole census, so the next effect needs a new actual observation.
        let coordinator17_selected = {
            let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
            let mut selected = 0;
            for source in &held.authority.roster.sources {
                if source.is_original_restored_settled_capture_declaration_data()? {
                    selected += 1;
                }
            }
            if selected != 0 && selected != held.authority.roster.sources.len() {
                return Err(RuntimeError::UnsupportedFacet);
            }
            selected != 0
        };
        if coordinator17_selected {
            capsule
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?
                .initialize_original_complete_coordinator17_before_activation(
                    &window, &plan, &context,
                )?;
            Self::recheck_original_restoration_transaction_data(original, activation)?;
        }
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

impl PacketCompleteReportStartupHolder {
    const RESTORATION_FAILURE: &str =
        "complete restoration failed; native effects may have started";

    /// Restores a suffix-selected world and returns its first recurring observation.
    ///
    /// This entrypoint drives the existing complete installation, every original
    /// first Observe, and each separate suffix seed before requesting a current
    /// scheduling observation. The same holder retains all native and protocol
    /// partials after failure; it does not retry an incomplete native phase.
    ///
    /// # Errors
    /// Refuses an unselected source, foreign holder, failed complete restoration,
    /// missing census, incomplete initial roster or any native proof/ACK failure.
    pub fn execute_original_complete_restoration_and_observe(
        original: &Rc<RefCell<Self>>,
        activation: &crucible::node_contract::ActivationRecord,
        prepare_ids: &mut Option<[Id; 3]>,
        commit_ids: &mut Option<[Id; 3]>,
        publisher: &mut Option<crate::node_observed_executor::StoredWorldActivationPublisher>,
        blobs: Arc<DirectoryBlobBackend>,
        refs: Arc<DirectoryRefBackend>,
        node: &Id,
    ) -> Result<ValidatedSchedulingObservation, RuntimePollFailure> {
        {
            let held = original
                .try_borrow()
                .map_err(|_| RuntimePollFailure::Admission(RuntimeError::OwnerBusy))?;
            held.authenticate_native_origin_data()
                .map_err(RuntimePollFailure::Admission)?;
            for source in &held.authority.roster.sources {
                if !source
                    .is_original_restored_suffix_declaration_data()
                    .map_err(RuntimePollFailure::Admission)?
                {
                    return Err(RuntimePollFailure::Admission(
                        RuntimeError::UnsupportedFacet,
                    ));
                }
            }
            if !held
                .authority
                .roster
                .sources
                .iter()
                .any(|source| &source.installation().binding.compatibility.node_id == node)
            {
                return Err(RuntimePollFailure::Admission(RuntimeError::UnknownNode));
            }
        }
        Self::execute_original_complete_restoration(
            original,
            activation,
            prepare_ids,
            commit_ids,
            publisher,
            blobs,
            refs,
        )
        .map_err(|_| {
            // The older installer can fail after native or durable effects; its
            // RuntimeError carries no evidence that those effects did not occur.
            RuntimePollFailure::Native(crucible::node_contract::OperationFailure {
                effects: crucible::node_contract::EffectKnowledge::Unknown,
                reason: Self::RESTORATION_FAILURE.into(),
            })
        })?;
        Self::complete_original_restored_initial_scheduling(original, activation)?;
        Self::observe_original_restored_scheduling(original, node)
    }

    fn complete_original_restored_initial_scheduling(
        original: &Rc<RefCell<Self>>,
        activation: &crucible::node_contract::ActivationRecord,
    ) -> Result<(), RuntimePollFailure> {
        let held = original
            .try_borrow()
            .map_err(|_| RuntimePollFailure::Admission(RuntimeError::OwnerBusy))?;
        held.authenticate_native_origin_data()
            .map_err(RuntimePollFailure::Admission)?;
        let window = held
            .restoration_window
            .get()
            .ok_or(RuntimePollFailure::Admission(
                RuntimeError::OwnerUnavailable,
            ))?;
        let StartupHolderPurpose::FreshRestoration(capsule) = &held.purpose else {
            return Err(RuntimePollFailure::Admission(
                RuntimeError::ForeignAuthority,
            ));
        };

        // Census callbacks reborrow the capsule immutably. End every dispatch
        // RefMut before observing the next phase, including the final roster edge.
        for source in &held.authority.roster.sources {
            let node = &source.installation().binding.compatibility.node_id;
            let mut admission = {
                let outputs = held
                    .host_sdk_outputs
                    .try_borrow()
                    .map_err(|_| RuntimePollFailure::Admission(RuntimeError::OwnerBusy))?;
                let sdks = [
                    outputs[0].as_ref().ok_or(RuntimePollFailure::Admission(
                        RuntimeError::OwnerUnavailable,
                    ))?,
                    outputs[1].as_ref().ok_or(RuntimePollFailure::Admission(
                        RuntimeError::OwnerUnavailable,
                    ))?,
                    outputs[2].as_ref().ok_or(RuntimePollFailure::Admission(
                        RuntimeError::OwnerUnavailable,
                    ))?,
                ];
                let shared = capsule
                    .try_borrow()
                    .map_err(|_| RuntimePollFailure::Admission(RuntimeError::OwnerBusy))?;
                shared
                    .prepare_original_complete_initial_scheduling(
                        window,
                        &held.plan,
                        sdks,
                        &held.authority.original_launches,
                        held.authority
                            .private_launches
                            .each_ref()
                            .map(Vec::as_slice),
                        node,
                    )
                    .map_err(RuntimePollFailure::Admission)?
            };
            capsule
                .try_borrow_mut()
                .map_err(|_| RuntimePollFailure::Admission(RuntimeError::OwnerBusy))?
                .observe_original_complete_initial_scheduling(&mut admission, node)?;
        }
        Self::recheck_original_restoration_transaction_data(original, activation)
            .map_err(RuntimePollFailure::Admission)?;

        // Seeds require all three actual first observations. Each seed dirties
        // the whole observation, so no following seed reuses the previous cut.
        for source in &held.authority.roster.sources {
            let node = &source.installation().binding.compatibility.node_id;
            capsule
                .try_borrow()
                .map_err(|_| RuntimePollFailure::Admission(RuntimeError::OwnerBusy))?
                .seed_original_complete_restored_suffix(window, &held.plan, node)
                .map_err(RuntimePollFailure::Admission)?;
            Self::recheck_original_restoration_transaction_data(original, activation)
                .map_err(RuntimePollFailure::Admission)?;
        }
        Ok(())
    }

    /// Returns a fresh scheduling observation through the actual retained holder.
    ///
    /// Preparation lends the original SDK3, launch3 and canonical launch bodies
    /// under a shared capsule loan. That loan ends before the admitted dispatch
    /// borrows the runtime mutably. No runtime or native handle is extracted.
    ///
    /// # Errors
    /// Refuses incomplete initial observation/seed, changed original ownership,
    /// stale or spent admission, resource excess and native proof/ACK failures.
    pub fn observe_original_restored_scheduling(
        original: &Rc<RefCell<Self>>,
        node: &Id,
    ) -> Result<ValidatedSchedulingObservation, RuntimePollFailure> {
        let held = original
            .try_borrow()
            .map_err(|_| RuntimePollFailure::Admission(RuntimeError::OwnerBusy))?;
        held.authenticate_native_origin_data()
            .map_err(RuntimePollFailure::Admission)?;
        let window = held
            .restoration_window
            .get()
            .ok_or(RuntimePollFailure::Admission(
                RuntimeError::OwnerUnavailable,
            ))?;
        let StartupHolderPurpose::FreshRestoration(capsule) = &held.purpose else {
            return Err(RuntimePollFailure::Admission(
                RuntimeError::ForeignAuthority,
            ));
        };
        let selected = held
            .authority
            .roster
            .sources
            .iter()
            .position(|source| &source.installation().binding.compatibility.node_id == node)
            .ok_or(RuntimePollFailure::Admission(RuntimeError::UnknownNode))?;

        let mut admission = {
            let outputs = held
                .host_sdk_outputs
                .try_borrow()
                .map_err(|_| RuntimePollFailure::Admission(RuntimeError::OwnerBusy))?;
            let sdks = [
                outputs[0].as_ref().ok_or(RuntimePollFailure::Admission(
                    RuntimeError::OwnerUnavailable,
                ))?,
                outputs[1].as_ref().ok_or(RuntimePollFailure::Admission(
                    RuntimeError::OwnerUnavailable,
                ))?,
                outputs[2].as_ref().ok_or(RuntimePollFailure::Admission(
                    RuntimeError::OwnerUnavailable,
                ))?,
            ];
            let shared = capsule
                .try_borrow()
                .map_err(|_| RuntimePollFailure::Admission(RuntimeError::OwnerBusy))?;
            shared
                .prepare_original_complete_restored_scheduling(
                    window,
                    &held.plan,
                    sdks,
                    &held.authority.original_launches,
                    held.authority
                        .private_launches
                        .each_ref()
                        .map(Vec::as_slice),
                    node,
                )
                .map_err(RuntimePollFailure::Admission)?
        };

        let result = capsule
            .try_borrow_mut()
            .map_err(|_| RuntimePollFailure::Admission(RuntimeError::OwnerBusy))?
            .observe_original_complete_restored_scheduling(
                &mut admission,
                &held.authority.original_launches[selected],
                &held.authority.private_launches[selected],
                node,
            );
        result
    }
}

impl PacketCompleteReportStartupHolder {
    pub(super) fn original_restored_scheduling_caller_counter_scratch_data() -> usize {
        use crucible::node_adapters::cnp::PacketCompleteSemanticSource;
        use std::mem::size_of;

        type HolderRef = std::cell::Ref<'static, PacketCompleteReportStartupHolder>;
        type CapsuleRef = std::cell::Ref<'static, PacketCompleteRestorationPrebirth>;
        type CapsuleMut = std::cell::RefMut<'static, PacketCompleteRestorationPrebirth>;
        type OutputsRef = std::cell::Ref<'static, [Option<PacketCompleteOriginalHostSdk>; 3]>;

        PacketCompleteSemanticSource::original_restored_suffix_declaration_counter_scratch_data()
            // The fixed failure diagnostic owns a String even when the older
            // installer stops before the first scheduling admission exists.
            + Self::RESTORATION_FAILURE.len()
            + size_of::<std::cell::Ref<'static, crucible::node_contract::ConformanceRuntime>>()
            + size_of::<Result<std::cell::Ref<'static, crucible::node_contract::ConformanceRuntime>, RuntimeError>>()
            + size_of::<Result<HolderRef, RuntimeError>>()
            + size_of::<Result<CapsuleRef, RuntimeError>>()
            + size_of::<Result<OutputsRef, RuntimeError>>()
            + size_of::<(usize, usize)>()
            + size_of::<Result<(usize, usize), RuntimeError>>()
            + size_of::<HolderRef>()
            + size_of::<Result<HolderRef, std::cell::BorrowError>>()
            + size_of::<Result<HolderRef, RuntimePollFailure>>()
            + size_of::<CapsuleRef>()
            + size_of::<Result<CapsuleRef, std::cell::BorrowError>>()
            + size_of::<Result<CapsuleRef, RuntimePollFailure>>()
            + size_of::<CapsuleMut>()
            + size_of::<Result<CapsuleMut, std::cell::BorrowMutError>>()
            + size_of::<Result<CapsuleMut, RuntimePollFailure>>()
            + size_of::<OutputsRef>()
            + size_of::<Result<OutputsRef, std::cell::BorrowError>>()
            + size_of::<Result<OutputsRef, RuntimePollFailure>>()
            + size_of::<[&PacketCompleteOriginalHostSdk; 3]>()
            + size_of::<[&Vec<u8>; 3]>()
            + size_of::<[&[u8]; 3]>()
            + size_of::<&[PacketNative5SourceLaunch; 3]>()
            + size_of::<std::slice::Iter<'static, Rc<PacketCompleteSemanticSource>>>()
            + size_of::<OriginalRestoredInitialSchedulingAdmission>()
            + size_of::<Result<OriginalRestoredInitialSchedulingAdmission, RuntimeError>>()
            + size_of::<Result<OriginalRestoredInitialSchedulingAdmission, RuntimePollFailure>>()
            + size_of::<OriginalRestoredSchedulingObservationAdmission>()
            + size_of::<Result<OriginalRestoredSchedulingObservationAdmission, RuntimeError>>()
            + size_of::<Result<OriginalRestoredSchedulingObservationAdmission, RuntimePollFailure>>(
            )
            + size_of::<ValidatedSchedulingObservation>()
            + size_of::<Result<ValidatedSchedulingObservation, RuntimePollFailure>>()
            + size_of::<RuntimePollFailure>()
            + size_of::<Result<(), RuntimePollFailure>>()
            + size_of::<Result<bool, RuntimeError>>()
            + size_of::<Result<bool, RuntimePollFailure>>()
            + size_of::<Option<usize>>()
            + size_of::<Result<usize, RuntimePollFailure>>()
    }
}

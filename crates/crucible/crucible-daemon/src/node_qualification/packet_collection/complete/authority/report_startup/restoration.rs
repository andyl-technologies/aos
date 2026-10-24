//! Binds restoration callbacks to the same registered inactive scene holder.
//!
//! The concrete ResourceLimits, Source3/launch3/SDK3, actual restored capsule and
//! once-retained Core window form one conjunction. Request IDs are retained DATA;
//! they grant no capability. Terminal member checks never borrow the mutable
//! runtime, SDK, preparation, Source association or restored capsule banks.

use super::*;
use crucible_engine::node_admission::{
    CompleteOriginalRestorationWindow, OriginalRestorationConstructionPolicy,
    OriginalRestorationConstructionScope, OriginalRestorationConstructionStorage,
    OriginalRestorationMemberScope,
};
use crucible_engine::node_contract::RuntimeError;
use crucible_node_format::Id;
use std::{mem::size_of, rc::Weak};

pub(super) struct OriginalRestorationRequestOwners {
    prepare: Option<[Id; 3]>,
    commit: Option<[Id; 3]>,
}

impl OriginalRestorationRequestOwners {
    pub(super) fn new() -> Self {
        Self {
            prepare: None,
            commit: None,
        }
    }

    fn retained_storage_data(&self) -> Result<usize, RuntimeError> {
        let Self { prepare, commit } = self;
        let mut total = 0usize;
        for ids in [prepare.as_ref(), commit.as_ref()].into_iter().flatten() {
            for id in ids {
                total = total
                    .checked_add(id.allocated_capacity())
                    .ok_or(RuntimeError::ResourceLimit)?;
            }
        }
        Ok(total)
    }
}

impl PacketCompleteReportStartupHolder {
    /// Retains already owned planned IDs before the installed cold-window issue.
    ///
    /// The caller retains and independently funds incoming construction before
    /// this move. These are only routing originals; Core and Source separately
    /// authenticate actual unused query/transaction/mapping correspondence.
    /// Occupied slots or late input leave the caller's original banks untouched.
    ///
    /// # Errors
    /// Refuses a foreign/nonrestoration holder, missing banks, reused phase,
    /// equal per-owner Prepare/Commit IDs or a busy original request slot.
    pub fn retain_original_restoration_request_ids_into(
        original: &Rc<RefCell<Self>>,
        prepare: &mut Option<[Id; 3]>,
        commit: &mut Option<[Id; 3]>,
    ) -> Result<(), RuntimeError> {
        let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        held.authenticate_native_origin_data()?;
        if !matches!(held.purpose, StartupHolderPurpose::FreshRestoration(_))
            || held.restoration_attempted.get()
            || held.original_scene_retired.get()
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        let first = prepare.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        let second = commit.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        if first
            .iter()
            .zip(second)
            .any(|(prepare, commit)| prepare == commit)
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        let mut requests = held
            .restoration_requests
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if requests.prepare.is_some() || requests.commit.is_some() {
            return Err(RuntimeError::OutstandingObligations);
        }
        requests.prepare = prepare.take();
        requests.commit = commit.take();
        Ok(())
    }

    fn authenticate_restoration_scope_data(
        &self,
        authority: &InstalledPacketCompleteCollectionAuthority,
        scope: &OriginalRestorationConstructionScope<'_>,
    ) -> Result<(), RuntimeError> {
        self.authenticate_native_origin_data()?;
        if self.fresh_lifecycle.get().is_some() {
            self.authenticate_completed_fresh_runtime_data()?;
        }
        let inputs = scope.inputs();
        if self.original_scene_retired.get()
            || !std::ptr::eq(self.authority.as_ref(), authority)
            || !scope.is_original_authority(authority)
            || !self.plan.is_original_plan_data(scope.plan())
            || !std::ptr::eq(inputs.launches, &authority.original_launches)
            || (0..3).any(|index| {
                !Rc::ptr_eq(&inputs.sources[index], &authority.roster.sources[index])
                    || inputs.encoded_launches[index].as_ptr()
                        != authority.private_launches[index].as_ptr()
                    || inputs.encoded_launches[index].len()
                        != authority.private_launches[index].len()
            })
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        match self.restoration_window.get() {
            Some(window) if scope.is_original_window(window) => {}
            None if self.restoration_issuing.get() => {}
            _ => return Err(RuntimeError::ForeignAuthority),
        }
        let outputs = self
            .host_sdk_outputs
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        for index in 0..3 {
            if !std::ptr::eq(
                inputs.sdks[index],
                outputs[index]
                    .as_ref()
                    .ok_or(RuntimeError::OwnerUnavailable)?,
            ) {
                return Err(RuntimeError::ForeignAuthority);
            }
        }
        let StartupHolderPurpose::FreshRestoration(capsule) = &self.purpose else {
            return Err(RuntimeError::ForeignAuthority);
        };
        let capsule = capsule.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        capsule.authenticate_restoration_storage_scope_data(
            inputs.archive,
            inputs.runtime,
            scope.plan(),
            inputs.activation,
            Some(scope),
        )?;
        let requests = self
            .restoration_requests
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        match (&requests.prepare, &requests.commit) {
            (Some(prepare), Some(commit))
                if std::ptr::eq(prepare, inputs.prepare_ids)
                    && std::ptr::eq(commit, inputs.commit_ids) => {}
            // Core independently authenticates the exact moved fixed group.
            (None, None) if self.restoration_window.get().is_some() => {}
            _ => return Err(RuntimeError::ForeignAuthority),
        }
        self.graph_owner
            .authenticate_original_report_policy_data(&authority.graph_policy)
            .map_err(|_| RuntimeError::ForeignAuthority)
    }

    fn restoration_policy_data(
        &self,
    ) -> Result<OriginalRestorationConstructionPolicy, RuntimeError> {
        let base = self
            .policy_data()
            .map_err(|_| RuntimeError::ResourceLimit)?;
        let scratch = [
            base.declared_observer_scratch_bytes,
            self.original_restored_result_counter_scratch_data()?,
            crate::node_observed_executor::StoredWorldActivationPublisher::original_directory_publication_counter_scratch_data()?,
            InstalledConformancePlan::original_restoration_construction_counter_scratch_data()?,
            PacketCompleteRestorationPrebirth::restoration_holder_counter_scratch_data(),
            Self::original_restored_scheduling_caller_counter_scratch_data(),
            size_of::<std::cell::Ref<'static, PacketCompleteReportStartupHolder>>(),
            size_of::<std::cell::Ref<'static, PacketCompleteRestorationPrebirth>>(),
            size_of::<std::cell::Ref<'static, OriginalRestorationRequestOwners>>(),
            size_of::<std::cell::RefMut<'static, OriginalRestorationRequestOwners>>(),
            size_of::<std::cell::Ref<'static, Option<Rc<CompleteOriginalRestorationWindow>>>>(),
            size_of::<std::cell::RefMut<'static, Option<Rc<CompleteOriginalRestorationWindow>>>>(),
            size_of::<
                std::cell::Ref<
                    'static,
                    [Option<crucible_engine::node_adapters::cnp::PacketCompleteOriginalHostSdk>; 3],
                >,
            >(),
            size_of::<[Option<&[Id; 3]>; 2]>(),
            size_of::<std::iter::Flatten<std::array::IntoIter<Option<&[Id; 3]>, 2>>>(),
            size_of::<std::slice::Iter<'static, Id>>(),
            size_of::<std::ops::Range<usize>>(),
            size_of::<Rc<RefCell<PacketCompleteReportStartupHolder>>>(),
            size_of::<Result<OriginalRestorationConstructionPolicy, RuntimeError>>(),
            size_of::<Result<OriginalRestorationConstructionStorage, RuntimeError>>(),
        ]
        .into_iter()
        .try_fold(0usize, |sum, bytes| {
            sum.checked_add(bytes).ok_or(RuntimeError::ResourceLimit)
        })?;
        Ok(OriginalRestorationConstructionPolicy {
            maximum_requested_bytes: base.maximum_requested_bytes,
            maximum_owned_descriptors: usize::try_from(self.resources.descriptors.get())
                .map_err(|_| RuntimeError::ResourceLimit)?,
            declared_observer_scratch_bytes: scratch,
        })
    }
}

impl InstalledPacketCompleteCollectionAuthority {
    fn restoration_holder_data(
        &self,
    ) -> Result<Rc<RefCell<PacketCompleteReportStartupHolder>>, RuntimeError> {
        self.graph_policy
            .authenticate_retained_origin_data()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        self.report_startup_holder
            .get()
            .and_then(Weak::upgrade)
            .ok_or(RuntimeError::OwnerUnavailable)
    }

    pub(in crate::node_qualification::packet_collection::complete::authority) fn original_restoration_construction_policy_data(
        &self,
        scope: &OriginalRestorationConstructionScope<'_>,
    ) -> Result<OriginalRestorationConstructionPolicy, RuntimeError> {
        let original = self.restoration_holder_data()?;
        let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        held.authenticate_restoration_scope_data(self, scope)?;
        held.restoration_policy_data()
    }

    pub(in crate::node_qualification::packet_collection::complete::authority) fn authenticate_original_restoration_construction_data(
        &self,
        scope: &OriginalRestorationConstructionScope<'_>,
        policy: &OriginalRestorationConstructionPolicy,
    ) -> Result<OriginalRestorationConstructionStorage, RuntimeError> {
        let original = self.restoration_holder_data()?;
        let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        held.authenticate_restoration_scope_data(self, scope)?;
        if held.restoration_policy_data()? != *policy {
            return Err(RuntimeError::ForeignAuthority);
        }
        let maximum = policy
            .maximum_requested_bytes
            .checked_sub(policy.declared_observer_scratch_bytes)
            .ok_or(RuntimeError::ResourceLimit)?;
        held.authenticate_original_restored_result_candidate_data(scope)?;
        let retained = PacketCompleteReportStartupHolder::original_restoration_holder_storage_data(
            &original, &held, scope, maximum,
        )?;
        let requests = held
            .restoration_requests
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?
            .retained_storage_data()?;
        let retained_holder_bytes = retained
            .checked_add(requests)
            .filter(|total| *total <= maximum)
            .ok_or(RuntimeError::ResourceLimit)?;
        let retained_descriptors = held.original_restoration_holder_descriptor_data(scope)?;
        let StartupHolderPurpose::FreshRestoration(capsule) = &held.purpose else {
            return Err(RuntimeError::ForeignAuthority);
        };
        let (publication_requested, publication_descriptors) = capsule
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?
            .original_publication_future_data(scope, maximum)?;
        held.authenticate_restoration_scope_data(self, scope)?;
        Ok(OriginalRestorationConstructionStorage {
            retained_holder_bytes,
            retained_descriptors,
            maximum_simultaneous_transient_bytes: self
                .original_initial_callback_transient_data()?
                .checked_add(publication_requested)
                .ok_or(RuntimeError::ResourceLimit)?,
            // The real concrete qualification callback opens one kernel File;
            // Core separately counts the actual Source's three nested opens.
            maximum_simultaneous_transient_descriptors: 1usize
                .checked_add(publication_descriptors)
                .ok_or(RuntimeError::ResourceLimit)?,
        })
    }

    pub(in crate::node_qualification::packet_collection::complete::authority) fn authenticate_original_restoration_construction_member_data(
        &self,
        scope: &OriginalRestorationMemberScope<'_>,
    ) -> Result<(), RuntimeError> {
        let original = self.restoration_holder_data()?;
        let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        held.authenticate_native_origin_data()?;
        if held.original_scene_retired.get()
            || !held.restoration_attempted.get()
            || !std::ptr::eq(held.authority.as_ref(), self)
            || !held.plan.is_original_plan_data(scope.plan())
            || !held
                .restoration_window
                .get()
                .is_some_and(|window| scope.is_original_window(window))
            || (0..3).any(|index| !Rc::ptr_eq(&scope.sources()[index], &self.roster.sources[index]))
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        if scope.is_original_publication_member_data() {
            let publisher = *held
                .restoration_publication
                .get()
                .ok_or(RuntimeError::OwnerUnavailable)?;
            if !scope.is_original_publisher_data(publisher) {
                return Err(RuntimeError::ForeignAuthority);
            }
        }
        if let Some(candidate) = scope.original_restored_producer_publication_candidate_data()
            && held.restored_result_publication.get() != Some(&candidate)
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        // No capsule/SDK/preparation/runtime/Source bank is borrowed here.
        // Core repeats the same actual spent ticket and live scheduler fence
        // after this callback, while SourceRead remains armed around it.
        held.graph_owner
            .authenticate_original_report_policy_data(&self.graph_policy)
            .map_err(|_| RuntimeError::ForeignAuthority)
    }
}

impl PacketCompleteReportStartupHolder {
    /// Runs one original restoration transfer through its actual retained nodes.
    ///
    /// Incoming IDs are already owned and independently funded routing inputs;
    /// this method retains them before its first issuer. The caller retains the
    /// actual original activation loan through the transaction. This entrypoint
    /// never returns a final lineage context, readiness or restored activation:
    /// the independent four-owner continuation and journal verifier must run
    /// after verified Commit before those capabilities can be issued.
    ///
    /// # Errors
    /// Refuses a foreign, retired, repeated or incomplete holder/capsule, failed
    /// original cold/transaction admission, any Source/upload/Commit failure,
    /// actual currentness change or complete memory/descriptor excess. Started
    /// phases and every partial owner remain retained on refusal or unwind.
    pub fn execute_original_restoration_transfer(
        original: &Rc<RefCell<Self>>,
        activation: &crucible_engine::node_contract::ActivationRecord,
        prepare_ids: &mut Option<[Id; 3]>,
        commit_ids: &mut Option<[Id; 3]>,
    ) -> Result<(), RuntimeError> {
        Self::retain_original_restoration_request_ids_into(original, prepare_ids, commit_ids)?;
        {
            let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
            held.authenticate_native_origin_data()?;
            if held.restoration_attempted.replace(true)
                || !held.host_sdk_completed.get()
                || held.host_sdk_in_flight.get()
                || held.restoration_window.get().is_some()
            {
                return Err(RuntimeError::OutstandingObligations);
            }
            let StartupHolderPurpose::FreshRestoration(capsule) = &held.purpose else {
                return Err(RuntimeError::ForeignAuthority);
            };
            let capsule = capsule.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
            let outputs = held
                .host_sdk_outputs
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            let sdks = [
                outputs[0].as_ref().ok_or(RuntimeError::OwnerUnavailable)?,
                outputs[1].as_ref().ok_or(RuntimeError::OwnerUnavailable)?,
                outputs[2].as_ref().ok_or(RuntimeError::OwnerUnavailable)?,
            ];
            let requests = held
                .restoration_requests
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            let runtime = capsule.runtime_data()?;
            let inputs = capsule.original_restoration_construction_inputs_data(
                &runtime,
                &held.authority.roster.sources,
                sdks,
                &held.authority.original_launches,
                held.authority
                    .private_launches
                    .each_ref()
                    .map(Vec::as_slice),
                &held.plan,
                activation,
                requests
                    .prepare
                    .as_ref()
                    .ok_or(RuntimeError::OwnerUnavailable)?,
                requests
                    .commit
                    .as_ref()
                    .ok_or(RuntimeError::OwnerUnavailable)?,
            )?;
            held.restoration_issuing.set(true);
            let _issuing = StartupLoan(&held.restoration_issuing);
            let window = held
                .plan
                .reserve_original_restoration_cold_construction(&inputs)?;
            // Retain immediately before cold construction. No callback or
            // allocation separates the issued owner and this fixed destination.
            if let Err(window) = held.restoration_window.set(window) {
                *held
                    .restoration_unplaced_window
                    .try_borrow_mut()
                    .map_err(|_| RuntimeError::OwnerBusy)? = Some(window);
                return Err(RuntimeError::DuplicateOperation);
            }
        }
        Self::construct_original_restoration_cold_and_transaction(original, activation)?;
        Self::move_original_restoration_group_and_targets(original, activation)?;
        Self::recheck_original_restoration_transaction_data(original, activation)?;
        let constructed_publisher = {
            let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
            if held.restored_result_publication.get().is_some() {
                let window = held
                    .restoration_window
                    .get()
                    .ok_or(RuntimeError::OwnerUnavailable)?;
                let StartupHolderPurpose::FreshRestoration(capsule) = &held.purpose else {
                    return Err(RuntimeError::ForeignAuthority);
                };
                capsule
                    .try_borrow()
                    .map_err(|_| RuntimeError::OwnerBusy)?
                    .initialize_original_restored_results_data(window, &held.plan, activation)?;
                true
            } else {
                false
            }
        };
        if constructed_publisher {
            Self::recheck_original_restoration_transaction_data(original, activation)?;
        }
        {
            let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
            let window = held
                .restoration_window
                .get()
                .ok_or(RuntimeError::OwnerUnavailable)?;
            let StartupHolderPurpose::FreshRestoration(capsule) = &held.purpose else {
                return Err(RuntimeError::ForeignAuthority);
            };
            capsule
                .try_borrow_mut()
                .map_err(|_| RuntimeError::OwnerBusy)?
                .execute_original_restoration_prepare(window, &held.plan, activation)?;
        }
        Self::recheck_original_restoration_transaction_data(original, activation)?;
        {
            let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
            let window = held
                .restoration_window
                .get()
                .ok_or(RuntimeError::OwnerUnavailable)?;
            let StartupHolderPurpose::FreshRestoration(capsule) = &held.purpose else {
                return Err(RuntimeError::ForeignAuthority);
            };
            capsule
                .try_borrow_mut()
                .map_err(|_| RuntimeError::OwnerBusy)?
                .execute_original_restoration_inputs(window, &held.plan, activation)?;
        }
        Self::recheck_original_restoration_transaction_data(original, activation)?;
        {
            let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
            let window = held
                .restoration_window
                .get()
                .ok_or(RuntimeError::OwnerUnavailable)?;
            let StartupHolderPurpose::FreshRestoration(capsule) = &held.purpose else {
                return Err(RuntimeError::ForeignAuthority);
            };
            capsule
                .try_borrow_mut()
                .map_err(|_| RuntimeError::OwnerBusy)?
                .execute_original_restoration_commit(window, &held.plan, activation)?;
        }
        Self::recheck_original_restoration_transaction_data(original, activation)?;
        {
            let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
            let window = held
                .restoration_window
                .get()
                .ok_or(RuntimeError::OwnerUnavailable)?;
            let StartupHolderPurpose::FreshRestoration(capsule) = &held.purpose else {
                return Err(RuntimeError::ForeignAuthority);
            };
            capsule
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?
                .inspect_original_restoration_native_continuations(
                    window, &held.plan, activation,
                )?;
        }
        Self::recheck_original_restoration_transaction_data(original, activation).map(|_| ())
    }

    fn construct_original_restoration_cold_and_transaction(
        original: &Rc<RefCell<Self>>,
        activation: &crucible_engine::node_contract::ActivationRecord,
    ) -> Result<(), RuntimeError> {
        let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        let window = held
            .restoration_window
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let StartupHolderPurpose::FreshRestoration(capsule) = &held.purpose else {
            return Err(RuntimeError::ForeignAuthority);
        };
        let capsule = capsule.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        let outputs = held
            .host_sdk_outputs
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let sdks = [
            outputs[0].as_ref().ok_or(RuntimeError::OwnerUnavailable)?,
            outputs[1].as_ref().ok_or(RuntimeError::OwnerUnavailable)?,
            outputs[2].as_ref().ok_or(RuntimeError::OwnerUnavailable)?,
        ];
        let requests = held
            .restoration_requests
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let runtime = capsule.runtime_data()?;
        let inputs = capsule.original_restoration_construction_inputs_data(
            &runtime,
            &held.authority.roster.sources,
            sdks,
            &held.authority.original_launches,
            held.authority
                .private_launches
                .each_ref()
                .map(Vec::as_slice),
            &held.plan,
            activation,
            requests
                .prepare
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
            requests
                .commit
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
        )?;
        window.construct_original_cold_owners(&held.plan, &inputs)?;
        if let Some((pointer, row)) =
            capsule.original_restored_result_candidate_data(&held.plan, &inputs, None)?
        {
            if held.restored_result_publication.get() != Some(&pointer) {
                return Err(RuntimeError::ForeignAuthority);
            }
            window.retain_original_restored_producer_publication_data(
                &held.plan,
                inputs.runtime.original_whole_owner_data()?,
                activation,
                pointer,
                row,
            )?;
        }
        window.admit_original_transaction(&held.plan, &inputs)
    }

    fn move_original_restoration_group_and_targets(
        original: &Rc<RefCell<Self>>,
        activation: &crucible_engine::node_contract::ActivationRecord,
    ) -> Result<(), RuntimeError> {
        let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        let window = held
            .restoration_window
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let StartupHolderPurpose::FreshRestoration(capsule) = &held.purpose else {
            return Err(RuntimeError::ForeignAuthority);
        };
        let mut capsule = capsule
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        {
            let mut requests = held
                .restoration_requests
                .try_borrow_mut()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            let OriginalRestorationRequestOwners { prepare, commit } = &mut *requests;
            capsule.retain_original_restoration_group(
                window, &held.plan, activation, prepare, commit,
            )?;
        }
        capsule.bind_original_restoration_targets(
            window,
            &held.plan,
            &held.authority.roster.sources,
            activation,
        )
    }

    fn recheck_original_restoration_transaction_data(
        original: &Rc<RefCell<Self>>,
        activation: &crucible_engine::node_contract::ActivationRecord,
    ) -> Result<usize, RuntimeError> {
        let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
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
        capsule
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?
            .recheck_original_restoration_inputs_data(
                window,
                &held.plan,
                sdks,
                &held.authority.original_launches,
                held.authority
                    .private_launches
                    .each_ref()
                    .map(Vec::as_slice),
                activation,
            )
    }
}

#[path = "restoration/installed.rs"]
mod installed;

#[path = "restoration/fresh_lifecycle.rs"]
mod fresh_lifecycle;
pub(super) use fresh_lifecycle::FreshLifecycleOwners;
pub use fresh_lifecycle::PacketCompleteFreshRestorationInputs;

#[path = "restoration/restored_publication.rs"]
mod restored_publication;

#[path = "restoration/producer_lifecycle.rs"]
mod producer_lifecycle;

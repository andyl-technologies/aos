//! Admits baseline native allocations beneath the same installed startup holder.
//!
//! The registered holder lends its original Source roster and both launch banks
//! to Core. This action is separate from report publication and HOST queries;
//! finalization preserves partial Source owners without constructing a Child.

mod launch;
pub(super) use launch::NativeLaunchOwners;
pub use launch::PacketCompleteNativeLaunchInputs;

use super::*;
use crucible_engine::{
    node_admission::{
        OriginalNativeStartupMemberScope, OriginalNativeStartupPolicy, OriginalNativeStartupScope,
        OriginalNativeStartupStorage,
    },
    node_contract::RuntimeError,
};

impl PacketCompleteReportStartupHolder {
    /// Reserves and finalizes the three original baseline startup members.
    ///
    /// Core observes the same installed holders, Sources and compiled producer
    /// layouts before issuing the admission. The immutable holder loan remains
    /// live through all three finalizations. Refusal leaves the action spent and
    /// retains every original Source, including any partially finalized member.
    /// Native construction and its private-channel gate are separate operations.
    ///
    /// # Errors
    /// Refuses foreign, revoked, busy or repeated holders, incomplete producer
    /// rows, changed original banks or an installed resource-policy excess.
    pub fn finalize_original_native_startup(
        original: &Rc<RefCell<Self>>,
    ) -> Result<usize, RuntimeError> {
        let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        held.authenticate_native_origin_data()?;
        if held.native_attempted.replace(true)
            || held.native_in_flight.get()
            || held.native_completed.get()
            || held.in_flight.get()
        {
            return Err(RuntimeError::DuplicateOperation);
        }
        held.native_in_flight.set(true);
        let _loan = StartupLoan(&held.native_in_flight);
        // Keep the actual issued owner in place before any fallible Source
        // finalization. Its lifetime borrows these exact retained arrays.
        let invocation_selected = held
            .authority
            .original_launches
            .iter()
            .any(|launch| launch.fresh_restore_allocation_selection.is_some());
        let requested_peak = if held.restored_suffix_startup_selected_data()? {
            let mut admission = held.plan.reserve_original_restored_suffix_startup(
                &held.authority.roster.sources,
                &held.authority.original_launches,
                &held.authority.private_launches,
            )?;
            let requested_peak = admission.requested_peak_data();
            for member in 0..3 {
                admission.finalize_original_source(member)?;
            }
            requested_peak
        } else if invocation_selected {
            let mut admission = held.plan.reserve_original_native_invocation(
                &held.authority.roster.sources,
                &held.authority.original_launches,
                &held.authority.private_launches,
            )?;
            let requested_peak = admission.requested_peak_data();
            for member in 0..3 {
                admission.finalize_original_source(member)?;
            }
            requested_peak
        } else {
            let mut admission = held.plan.reserve_original_native_preflight_startup(
                &held.authority.roster.sources,
                &held.authority.original_launches,
                &held.authority.private_launches,
            )?;
            let requested_peak = admission.requested_peak_data();
            for member in 0..3 {
                admission.finalize_original_source(member)?;
            }
            requested_peak
        };
        held.authenticate_native_origin_data()?;
        held.graph_owner
            .authenticate_original_report_policy_data(&held.authority.graph_policy)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        held.retain_native_launch_admitted_data(held.native_launch_requested_storage_data()?)?;
        held.native_completed.set(true);
        Ok(requested_peak)
    }

    pub(super) fn authenticate_native_origin_data(&self) -> Result<(), RuntimeError> {
        if self.process != std::process::id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.thread != std::thread::current().id() {
            return Err(RuntimeError::ThreadAffinity);
        }
        if self.original_scene_retired.get() {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(())
    }

    fn authenticate_native_scope_data(
        &self,
        authority: &InstalledPacketCompleteCollectionAuthority,
        scope: &OriginalNativeStartupScope<'_>,
    ) -> Result<(), RuntimeError> {
        self.authenticate_native_origin_data()?;
        if !self.native_in_flight.get()
            || self.native_completed.get()
            || self.in_flight.get()
            || !std::ptr::eq(self.authority.as_ref(), authority)
            || !scope.is_original_authority(authority)
            || !scope.is_original_plan(&self.plan)
            || !std::ptr::eq(scope.sources(), &authority.roster.sources)
            || !std::ptr::eq(scope.launches(), &authority.original_launches)
            || !std::ptr::eq(scope.encoded_launches(), &authority.private_launches)
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.graph_owner
            .authenticate_original_report_policy_data(&authority.graph_policy)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        self.receiver_reader
            .original_data()?
            .authenticate_original_group(&self.receiver_group)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        // These loans inspect only the existing effect-group identities. They
        // do not encode a launch or borrow a Source birth/preparation bank.
        for (member, source) in authority.roster.sources.iter().enumerate() {
            source
                .authenticate_original_effect_receiver_binding_data(
                    &self.receiver_group,
                    member,
                    &authority.original_launches[member].effects,
                )
                .map_err(|_| RuntimeError::ForeignAuthority)?;
        }
        match &self.purpose {
            StartupHolderPurpose::OriginalScene => {
                authority.host.authenticate_original_report_startup_data()
            }
            StartupHolderPurpose::FreshRestoration(capsule) => capsule
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?
                .authenticate_native_startup_target_precredit_data(authority, &self.plan),
        }
    }

    fn native_policy_data(&self) -> Result<OriginalNativeStartupPolicy, RuntimeError> {
        // The same complete holder observer can encounter existing known
        // supervisors and completed preparations. Name their actual observers
        // even when this pre-Child invocation has not constructed those owners.
        let holder = self.host_policy_data()?;
        let declared_observer_scratch_bytes = holder
            .declared_observer_scratch_bytes
            .checked_add(InstalledConformancePlan::original_native_startup_counter_scratch_data()?)
            .and_then(|bytes| bytes.checked_add(crucible_engine::node_adapters::cnp::CnpSemanticLaunchReservation::unlaunched_storage_counter_scratch_data()))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<launch::NativeDeadlineWriter<'_>>()))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<[Option<crucible_engine::node_adapters::cnp::PacketCompleteAckPeerBootMaterial<'_>>; 3]>()))
            .and_then(|bytes| {
                bytes.checked_add(std::mem::size_of::<
                    Rc<crucible_engine::node_contract::HostSchedulingSource>,
                >())
            })
            .and_then(|bytes| {
                bytes.checked_add(std::mem::size_of::<[ConformancePlanEvidence<'_>; 2]>())
            })
            .ok_or(RuntimeError::ResourceLimit)?;
        let declared_observer_scratch_bytes = if self
            .authority
            .original_launches
            .iter()
            .any(|launch| launch.fresh_restore_allocation_selection.is_some())
        {
            declared_observer_scratch_bytes
                .checked_add(
                    InstalledConformancePlan::original_native_invocation_counter_scratch_data()?
                        .checked_add(std::mem::size_of::<
                            std::cell::Ref<'_, PacketCompleteReportStartupHolder>,
                        >())
                        .and_then(|bytes| {
                            bytes.checked_add(std::mem::size_of::<
                                std::cell::Ref<'_, PacketCompleteRestorationPrebirth>,
                            >())
                        })
                        .ok_or(RuntimeError::ResourceLimit)?,
                )
                .ok_or(RuntimeError::ResourceLimit)?
        } else {
            declared_observer_scratch_bytes
        };
        let declared_observer_scratch_bytes = declared_observer_scratch_bytes
            .checked_add(Self::restored_suffix_selection_counter_scratch_data())
            .ok_or(RuntimeError::ResourceLimit)?;
        let declared_observer_scratch_bytes = if self.restored_suffix_startup_selected_data()? {
            declared_observer_scratch_bytes
                .checked_add(InstalledConformancePlan::original_restored_suffix_startup_counter_scratch_data()?)
                .and_then(|bytes| bytes.checked_add(Self::restored_suffix_holder_counter_scratch_data()))
                .and_then(|bytes| bytes.checked_add(launch::restored_suffix_wire_counter_scratch_data()))
                .ok_or(RuntimeError::ResourceLimit)?
        } else {
            declared_observer_scratch_bytes
        };
        Ok(OriginalNativeStartupPolicy {
            maximum_requested_bytes: holder.maximum_requested_bytes,
            declared_observer_scratch_bytes,
        })
    }
}

impl InstalledPacketCompleteCollectionAuthority {
    fn original_native_holder_data(
        &self,
    ) -> Result<Rc<RefCell<PacketCompleteReportStartupHolder>>, RuntimeError> {
        // Creator authentication precedes following a retained Weak or RefCell.
        self.graph_policy
            .authenticate_retained_origin_data()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        self.report_startup_holder
            .get()
            .and_then(std::rc::Weak::upgrade)
            .ok_or(RuntimeError::OwnerUnavailable)
    }

    pub(in crate::node_qualification::packet_collection::complete::authority) fn original_native_startup_policy_data(
        &self,
        scope: &OriginalNativeStartupScope<'_>,
    ) -> Result<OriginalNativeStartupPolicy, RuntimeError> {
        let original = self.original_native_holder_data()?;
        let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        held.authenticate_native_scope_data(self, scope)?;
        held.native_policy_data()
    }

    pub(in crate::node_qualification::packet_collection::complete::authority) fn authenticate_original_native_startup_data(
        &self,
        scope: &OriginalNativeStartupScope<'_>,
        policy: &OriginalNativeStartupPolicy,
    ) -> Result<OriginalNativeStartupStorage, RuntimeError> {
        let original = self.original_native_holder_data()?;
        let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        held.authenticate_native_scope_data(self, scope)?;
        if held.native_policy_data()? != *policy {
            return Err(RuntimeError::ForeignAuthority);
        }
        let maximum = policy
            .maximum_requested_bytes
            .checked_sub(policy.declared_observer_scratch_bytes)
            .ok_or(RuntimeError::ResourceLimit)?;
        let retained_holder_bytes = PacketCompleteReportStartupHolder::native_holder_storage_data(
            &original, &held, maximum,
        )?;
        held.authenticate_native_scope_data(self, scope)?;
        Ok(OriginalNativeStartupStorage {
            retained_holder_bytes,
            // The concrete observer creates no new heap bank. Fixed counters,
            // typed metadata views and their simultaneous scratch are in policy.
            maximum_simultaneous_transient_bytes: 0,
            prospective_host_launch_requested_bytes: held.native_launch_requested_storage_data()?,
        })
    }

    pub(in crate::node_qualification::packet_collection::complete::authority) fn authenticate_original_native_startup_member_data(
        &self,
        scope: &OriginalNativeStartupMemberScope<'_>,
    ) -> Result<(), RuntimeError> {
        let original = self.original_native_holder_data()?;
        let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        held.authenticate_native_origin_data()?;
        if (!held.native_in_flight.get() && !held.native_completed.get())
            || !std::ptr::eq(held.authority.as_ref(), self)
            || !scope.is_original_authority(self)
            || !scope.is_original_plan(&held.plan)
            || !self
                .roster
                .sources
                .iter()
                .any(|source| std::ptr::eq(source.as_ref(), scope.source()))
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        // Source finalization/private boot may hold a birth-bank loan here.
        // Follow only registered owner identity and its sticky revision.
        held.graph_owner
            .authenticate_original_report_policy_data(&self.graph_policy)
            .map_err(|_| RuntimeError::ForeignAuthority)
    }
}

#[cfg(test)]
mod tests {
    //! Uses real file/ELF/entropy/socket fixture setup, with no Child or backend.

    #![allow(clippy::unwrap_used)]
    // crucible-lint: allow panic-shortcut -- Control assertions are verdicts.

    use super::*;

    #[test]
    fn actual_native_startup_scratch_shortage_keeps_births_and_spends_attempt() {
        let (_scene, original) =
            crate::node_qualification::packet_collection::complete::tests::report_startup_fixture();
        let before = {
            let held = original.borrow();
            std::array::from_fn::<_, 3, _>(|member| {
                held.authority.roster.sources[member]
                    .original_report_startup_audit_data()
                    .unwrap()
            })
        };
        let fixed =
            InstalledConformancePlan::original_native_startup_counter_scratch_data().unwrap();
        assert!(fixed > 1);
        original.borrow_mut().resources.memory_bytes =
            crucible_node_format::U64::new((fixed - 1) as u64);

        assert!(matches!(
            PacketCompleteReportStartupHolder::finalize_original_native_startup(&original),
            Err(RuntimeError::ResourceLimit)
        ));
        assert!(matches!(
            PacketCompleteReportStartupHolder::finalize_original_native_startup(&original),
            Err(RuntimeError::DuplicateOperation)
        ));

        let held = original.borrow();
        assert!(held.native_attempted.get());
        assert!(!held.native_in_flight.get());
        assert!(!held.native_completed.get());
        assert!(!held.attempted.get());
        assert!(!held.completed.get());
        for (source, before) in held.authority.roster.sources.iter().zip(before) {
            assert_eq!(source.original_report_startup_audit_data().unwrap(), before);
        }
        assert!(held.authority.roster.current_native().is_err());
    }

    #[test]
    fn actual_native_startup_foreign_creator_refuses_before_attempt_or_bank_access() {
        let (_scene, original) =
            crate::node_qualification::packet_collection::complete::tests::report_startup_fixture();
        let creator = original.borrow().process;
        // This is an origin-guard model, not a fork or foreign-child claim.
        original.borrow_mut().process = creator.wrapping_add(1);

        assert!(matches!(
            PacketCompleteReportStartupHolder::finalize_original_native_startup(&original),
            Err(RuntimeError::ForeignAuthority)
        ));
        {
            let held = original.borrow();
            assert!(!held.native_attempted.get());
            assert!(!held.native_in_flight.get());
            assert!(!held.native_completed.get());
        }
        original.borrow_mut().process = creator;
        let held = original.borrow();
        assert!(held.authenticate_native_origin_data().is_ok());
        assert!(!held.native_attempted.get());
        assert!(held.authority.roster.current_native().is_err());
    }
}

mod invocation;

#[path = "native_startup/restored_suffix.rs"]
mod restored_suffix;

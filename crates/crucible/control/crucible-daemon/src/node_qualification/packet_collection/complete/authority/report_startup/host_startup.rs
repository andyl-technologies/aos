//! Retains original HOST SDK inputs and constructors beneath the installed holder.
//!
//! Core's private action is issued after native startup finalization and before
//! any boot-material or Child loan. Immutable content originals and partial SDK
//! outputs survive refusal; callbacks never borrow a mutable constructor bank.

use super::*;
use crucible_engine::{
    node_adapters::cnp::PacketCompleteOriginalHostSdk,
    node_admission::{
        OriginalNativeHostStartupMemberScope, OriginalNativeHostStartupPolicy,
        OriginalNativeHostStartupScope, OriginalNativeHostStartupStorage,
    },
    node_contract::RuntimeError,
};
use crucible_node_format::ContentRef;
use std::collections::BTreeMap;

type ContentBanks = [Rc<BTreeMap<ContentRef, Vec<u8>>>; 3];

impl PacketCompleteReportStartupHolder {
    /// Retains the three original immutable content banks before native admission.
    ///
    /// These actual owners are included in the native holder row before Core
    /// issues either action. An occupied or late holder leaves incoming owners
    /// untouched. Equal content never substitutes for an original allocation.
    ///
    /// # Errors
    /// Refuses foreign, busy, late or repeated holders and missing input banks.
    pub fn retain_original_native_host_content_into(
        original: &Rc<RefCell<Self>>,
        incoming: &mut Option<ContentBanks>,
    ) -> Result<(), RuntimeError> {
        let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        held.authenticate_native_origin_data()?;
        if !held.completed.get()
            || held.native_attempted.get()
            || held.host_sdk_attempted.get()
            || held.host_sdk_content.get().is_some()
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        let content = incoming.take().ok_or(RuntimeError::OwnerUnavailable)?;
        if let Err(content) = held.host_sdk_content.set(content) {
            *incoming = Some(content);
            return Err(RuntimeError::DuplicateOperation);
        }
        Ok(())
    }

    /// Constructs the original SDK owners under Core's distinct installed action.
    ///
    /// The opaque admission borrows these same retained arrays. Each output
    /// slot receives its private member before fallible SDK construction. Full
    /// holder callbacks run after mutable output loans end. Failure leaves the
    /// attempted action spent and preserves all inputs and partial outputs.
    ///
    /// # Errors
    /// Refuses incomplete native finalization, foreign or repeated owners,
    /// unsupported actual storage, changed policy or a constructor failure.
    pub fn prepare_original_native_host_sdk(
        original: &Rc<RefCell<Self>>,
    ) -> Result<usize, RuntimeError> {
        let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        held.authenticate_native_origin_data()?;
        if !held.native_completed.get() || held.native_in_flight.get() || held.in_flight.get() {
            return Err(RuntimeError::OwnerUnavailable);
        }
        let content = held
            .host_sdk_content
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if held.host_sdk_attempted.replace(true)
            || held.host_sdk_completed.get()
            || held.host_sdk_in_flight.get()
        {
            return Err(RuntimeError::DuplicateOperation);
        }
        held.host_sdk_in_flight.set(true);
        let _loan = StartupLoan(&held.host_sdk_in_flight);
        let mut admission = held.plan.reserve_original_native_host_startup(
            &held.authority.roster.sources,
            &held.authority.original_launches,
            content,
        )?;
        let peak = admission.requested_peak_data();
        for member in 0..3 {
            let mut outputs = held
                .host_sdk_outputs
                .try_borrow_mut()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            admission.prepare_original_source_into(member, &mut outputs[member])?;
        }
        // No mutable output or controller loan survives this observation.
        admission.recheck_original_inputs_data()?;
        held.authenticate_native_host_scope_data(
            held.authority.as_ref(),
            &held.plan,
            content,
            &held.authority.roster.sources,
            &held.authority.original_launches,
        )?;
        if held
            .host_sdk_outputs
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?
            .iter()
            .any(Option::is_none)
        {
            return Err(RuntimeError::OwnerUnavailable);
        }
        held.host_sdk_completed.set(true);
        Ok(peak)
    }

    fn authenticate_native_host_scope_data(
        &self,
        authority: &InstalledPacketCompleteCollectionAuthority,
        plan: &InstalledConformancePlan,
        content: &ContentBanks,
        sources: &[Rc<crucible_engine::node_adapters::cnp::PacketCompleteSemanticSource>; 3],
        launches: &[PacketNative5SourceLaunch; 3],
    ) -> Result<(), RuntimeError> {
        self.authenticate_native_origin_data()?;
        let actual = self
            .host_sdk_content
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if !self.native_completed.get()
            || self.native_in_flight.get()
            || self.in_flight.get()
            || !self.host_sdk_in_flight.get()
            || self.host_sdk_completed.get()
            || !std::ptr::eq(self.authority.as_ref(), authority)
            || !self.plan.is_original_plan_data(plan)
            || !std::ptr::eq(launches, &authority.original_launches)
            || !sources
                .iter()
                .zip(&authority.roster.sources)
                .all(|(a, b)| Rc::ptr_eq(a, b))
            || !content.iter().zip(actual).all(|(a, b)| Rc::ptr_eq(a, b))
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

    fn native_host_policy_data(&self) -> Result<OriginalNativeHostStartupPolicy, RuntimeError> {
        let holder = self.host_policy_data()?;
        let core = InstalledConformancePlan::original_native_host_startup_counter_scratch_data()?;
        // Name the holder observer and the actual consumer's overlapping loans;
        // compiler-generated frames and OS socket resources remain separate.
        let counters = std::mem::size_of::<Counter>()
            .checked_mul(2)
            .ok_or(RuntimeError::ResourceLimit)?;
        let declared_observer_scratch_bytes = holder
            .declared_observer_scratch_bytes
            .checked_add(core)
            .and_then(|bytes| bytes.checked_add(counters))
            .and_then(|bytes| {
                bytes.checked_add(std::mem::size_of::<
                    std::cell::Ref<'_, [Option<PacketCompleteOriginalHostSdk>; 3]>,
                >())
            })
            .and_then(|bytes| {
                bytes.checked_add(std::mem::size_of::<
                    std::cell::Ref<'_, PacketCompleteReportStartupHolder>,
                >())
            })
            .and_then(|bytes| {
                bytes.checked_add(std::mem::size_of::<
                    std::cell::Ref<'_, super::native_startup::NativeLaunchOwners>,
                >())
            })
            .and_then(|bytes| {
                bytes.checked_add(std::mem::size_of::<
                    std::cell::RefMut<'_, [Option<std::os::unix::net::UnixStream>; 3]>,
                >())
            })
            .and_then(|bytes| {
                bytes.checked_add(std::mem::size_of::<
                    std::cell::RefMut<'_, [Option<PacketCompleteOriginalHostSdk>; 3]>,
                >())
            })
            .and_then(|bytes| {
                bytes.checked_add(std::mem::size_of::<
                    std::cell::Ref<'_, super::preparation::PreparationOwners>,
                >())
            })
            .ok_or(RuntimeError::ResourceLimit)?;
        Ok(OriginalNativeHostStartupPolicy {
            maximum_requested_bytes: holder.maximum_requested_bytes,
            declared_observer_scratch_bytes,
        })
    }

    pub(super) fn charge_host_sdk_storage_precredit_data(
        &self,
        counter: &mut Counter,
    ) -> Result<(), RuntimeError> {
        self.authenticate_native_origin_data()?;
        if let Some(content) = self.host_sdk_content.get() {
            charge_content_data(content, counter)?;
        }
        let outputs = self
            .host_sdk_outputs
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        for (member, output) in outputs.iter().enumerate() {
            if let Some(output) = output {
                self.charge_original_host_sdk_output_data(member, output, counter)?;
            }
        }
        Ok(())
    }
}

pub(super) fn charge_content_data(
    content: &ContentBanks,
    counter: &mut Counter,
) -> Result<(), RuntimeError> {
    for bank in content {
        if counter.rc(bank).map_err(|_| RuntimeError::ResourceLimit)? {
            counter
                .charge(bank.as_ref())
                .map_err(|_| RuntimeError::ResourceLimit)?;
        }
    }
    Ok(())
}

impl InstalledPacketCompleteCollectionAuthority {
    fn original_native_host_holder_data(
        &self,
    ) -> Result<Rc<RefCell<PacketCompleteReportStartupHolder>>, RuntimeError> {
        self.graph_policy
            .authenticate_retained_origin_data()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        self.report_startup_holder
            .get()
            .and_then(std::rc::Weak::upgrade)
            .ok_or(RuntimeError::OwnerUnavailable)
    }

    fn authenticate_native_host_scope_data(
        &self,
        held: &PacketCompleteReportStartupHolder,
        scope: &OriginalNativeHostStartupScope<'_>,
    ) -> Result<(), RuntimeError> {
        if !scope.is_original_authority(self)
            || !scope.is_original_plan(&held.plan)
            || !scope.is_original_sources(&self.roster.sources)
            || !scope.is_original_launches(&self.original_launches)
            || !scope.is_original_content(
                held.host_sdk_content
                    .get()
                    .ok_or(RuntimeError::OwnerUnavailable)?,
            )
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        held.authenticate_native_host_scope_data(
            self,
            scope.plan(),
            scope.content(),
            scope.sources(),
            scope.launches(),
        )
    }

    pub(in crate::node_qualification::packet_collection::complete::authority) fn original_native_host_startup_policy_data(
        &self,
        scope: &OriginalNativeHostStartupScope<'_>,
    ) -> Result<OriginalNativeHostStartupPolicy, RuntimeError> {
        let original = self.original_native_host_holder_data()?;
        let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        self.authenticate_native_host_scope_data(&held, scope)?;
        held.native_host_policy_data()
    }

    pub(in crate::node_qualification::packet_collection::complete::authority) fn authenticate_original_native_host_startup_data(
        &self,
        scope: &OriginalNativeHostStartupScope<'_>,
        policy: &OriginalNativeHostStartupPolicy,
    ) -> Result<OriginalNativeHostStartupStorage, RuntimeError> {
        let original = self.original_native_host_holder_data()?;
        let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        self.authenticate_native_host_scope_data(&held, scope)?;
        if held.native_host_policy_data()? != *policy {
            return Err(RuntimeError::ForeignAuthority);
        }
        let maximum = policy
            .maximum_requested_bytes
            .checked_sub(policy.declared_observer_scratch_bytes)
            .ok_or(RuntimeError::ResourceLimit)?;
        let retained_holder_bytes = PacketCompleteReportStartupHolder::native_holder_storage_data(
            &original, &held, maximum,
        )?;
        self.authenticate_native_host_scope_data(&held, scope)?;
        Ok(OriginalNativeHostStartupStorage {
            retained_holder_bytes,
            maximum_simultaneous_transient_bytes: 0,
        })
    }

    pub(in crate::node_qualification::packet_collection::complete::authority) fn authenticate_original_native_host_startup_member_data(
        &self,
        scope: &OriginalNativeHostStartupMemberScope<'_>,
    ) -> Result<(), RuntimeError> {
        let original = self.original_native_host_holder_data()?;
        let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        held.authenticate_native_origin_data()?;
        if !held.native_completed.get()
            || !held.host_sdk_attempted.get()
            || (!held.host_sdk_in_flight.get() && !held.host_sdk_completed.get())
            || (scope.requires_completed_construction() && !held.host_sdk_completed.get())
            || !std::ptr::eq(held.authority.as_ref(), self)
            || !scope.is_original_authority(self)
            || !scope.is_original_plan(&held.plan)
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let member = self
            .roster
            .sources
            .iter()
            .position(|source| std::ptr::eq(source.as_ref(), scope.source()))
            .ok_or(RuntimeError::ForeignAuthority)?;
        let content = held
            .host_sdk_content
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if !Rc::ptr_eq(&content[member], scope.content()) {
            return Err(RuntimeError::ForeignAuthority);
        }
        // Source may already hold birth/SDK/connection banks. Only fixed holder
        // identity and the registered graph revision are inspected here.
        held.graph_owner
            .authenticate_original_report_policy_data(&self.graph_policy)
            .map_err(|_| RuntimeError::ForeignAuthority)
    }
}

#[cfg(test)]
mod tests {
    //! Exercises real holder refusal and physical immutable content-bank counting.

    #![allow(clippy::unwrap_used)]
    // crucible-lint: allow panic-shortcut -- Control assertions are verdicts.

    use super::*;

    #[test]
    fn actual_host_sdk_requires_native_finalization_before_spending_constructor() {
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

        assert!(matches!(
            PacketCompleteReportStartupHolder::prepare_original_native_host_sdk(&original),
            Err(RuntimeError::OwnerUnavailable)
        ));

        let held = original.borrow();
        assert!(!held.host_sdk_attempted.get());
        assert!(!held.host_sdk_in_flight.get());
        assert!(!held.host_sdk_completed.get());
        assert!(held.host_sdk_outputs.borrow().iter().all(Option::is_none));
        for (source, before) in held.authority.roster.sources.iter().zip(before) {
            assert_eq!(source.original_report_startup_audit_data().unwrap(), before);
        }
        assert!(held.authority.roster.current_native().is_err());
    }

    #[test]
    fn actual_host_sdk_foreign_creator_precedes_busy_output_and_preserves_inputs() {
        let (_scene, original) =
            crate::node_qualification::packet_collection::complete::tests::report_startup_fixture();
        let process = original.borrow().process;
        original.borrow_mut().process = process.wrapping_add(1);
        let held = original.borrow();
        let _busy = held.host_sdk_outputs.borrow_mut();
        let mut incoming = Some(std::array::from_fn(|_| Rc::new(BTreeMap::new())));
        let identities =
            std::array::from_fn::<_, 3, _>(|index| Rc::as_ptr(&incoming.as_ref().unwrap()[index]));

        assert!(matches!(
            PacketCompleteReportStartupHolder::retain_original_native_host_content_into(
                &original,
                &mut incoming,
            ),
            Err(RuntimeError::ForeignAuthority)
        ));
        assert!(matches!(
            PacketCompleteReportStartupHolder::prepare_original_native_host_sdk(&original),
            Err(RuntimeError::ForeignAuthority)
        ));

        for (bank, identity) in incoming.as_ref().unwrap().iter().zip(identities) {
            assert_eq!(Rc::as_ptr(bank), identity);
        }
        assert!(!held.host_sdk_attempted.get());
        assert!(held.host_sdk_content.get().is_none());
    }

    #[test]
    fn actual_host_content_counts_shared_roots_once_and_independent_spare_bytes() {
        let reference =
            crucible_node_format::canonical::content_ref(b"payload", "application/octet-stream")
                .unwrap();
        let mut first_bytes = Vec::with_capacity(4096);
        first_bytes.extend_from_slice(b"payload");
        let first = Rc::new(BTreeMap::from([(reference.clone(), first_bytes)]));
        let mut second_bytes = Vec::with_capacity(8192);
        second_bytes.extend_from_slice(b"payload");
        let second = Rc::new(BTreeMap::from([(reference, second_bytes)]));
        let banks = [Rc::clone(&first), Rc::clone(&first), Rc::clone(&second)];
        let mut full = Counter::new(usize::MAX);
        charge_content_data(&banks, &mut full).unwrap();
        let peak = full.bytes();
        assert!(peak >= 4096 + 8192);

        let mut first_counter = Counter::new(usize::MAX);
        assert!(first_counter.rc(&first).unwrap());
        first_counter.charge(first.as_ref()).unwrap();
        let mut second_counter = Counter::new(usize::MAX);
        assert!(second_counter.rc(&second).unwrap());
        second_counter.charge(second.as_ref()).unwrap();
        assert_eq!(peak, first_counter.bytes() + second_counter.bytes());
        let mut exact = Counter::new(peak);
        charge_content_data(&banks, &mut exact).unwrap();
        assert_eq!(exact.bytes(), peak);
        assert!(matches!(
            charge_content_data(&banks, &mut Counter::new(peak - 1)),
            Err(RuntimeError::ResourceLimit)
        ));
        assert_eq!(
            first
                .get_key_value(first.keys().next().unwrap())
                .unwrap()
                .1
                .capacity(),
            4096
        );
        assert_eq!(second.values().next().unwrap().capacity(), 8192);
    }
}

#[cfg(test)]
mod constructor_controls {
    //! Uses real files, entropy and UnixStream pairs, with no Child or Hello.
    //!
    //! The flat slot is an unlaunched test custodian with no nested heap while
    //! empty. It refuses a returned custody phase; it supplies no native grant.

    #![allow(clippy::unwrap_used)]
    // crucible-lint: allow panic-shortcut -- Control assertions are verdicts.

    use super::*;
    use crate::node_qualification::packet_collection::complete::tests::{
        POSITIVE_HOST_SDK_SETUP_MEMORY_BYTES, POSITIVE_STARTUP_SETUP_MEMORY_BYTES,
    };
    use crucible_engine::node_adapters::cnp::{CnpSemanticProcessCustody, CnpSemanticProcessSlot};
    use crucible_node_format::U64;
    use std::{os::unix::net::UnixStream, time::Duration};

    struct UnlaunchedSlot {
        identity: U64,
        original: Option<CnpSemanticProcessCustody>,
    }

    impl CnpSemanticProcessSlot for UnlaunchedSlot {
        fn identity(&self) -> U64 {
            self.identity
        }

        fn retained_requested_storage_precredit_data(
            &self,
            _maximum: usize,
        ) -> Result<Option<usize>, RuntimeError> {
            let Self {
                identity: _,
                original,
            } = self;
            if original.is_some() {
                return Err(RuntimeError::UnsupportedFacet);
            }
            // Both fields are inline and the genuine empty slot has no backing.
            Ok(Some(0))
        }

        fn retain(&mut self, custody: CnpSemanticProcessCustody) {
            assert!(self.original.is_none());
            self.original = Some(custody);
        }
    }

    fn fixture() -> (
        crate::node_qualification::packet_collection::complete::tests::Scene,
        Rc<RefCell<PacketCompleteReportStartupHolder>>,
    ) {
        let (scene, original) =
            crate::node_qualification::packet_collection::complete::tests::report_startup_fixture();
        // Use the shared positive setup policy; exact controls later select their peak.
        original.borrow_mut().resources.memory_bytes =
            U64::new(POSITIVE_STARTUP_SETUP_MEMORY_BYTES);
        PacketCompleteReportStartupHolder::reserve_original_preparation_supervisors(&original)
            .unwrap();
        PacketCompleteReportStartupHolder::finalize_original_report_startup(&original).unwrap();
        let content = Rc::new(
            crate::node_qualification::packet_collection::complete::tests::report_startup_content_data(&scene).clone(),
        );
        let mut banks = Some([Rc::clone(&content), Rc::clone(&content), content]);
        PacketCompleteReportStartupHolder::retain_original_native_host_content_into(
            &original, &mut banks,
        )
        .unwrap();
        assert!(banks.is_none());
        let mut inputs = {
            let held = original.borrow();
            std::array::from_fn(|member| {
                let (reader, writer) = UnixStream::pair().unwrap();
                let measurement = &held.authority.graph_policy.measurements()[member].peer;
                Some(super::super::PacketCompleteNativeLaunchInputs {
                    executable_path: measurement.path.clone(),
                    executable: measurement.content.clone(),
                    directory: held.authority.directories[member].clone(),
                    socket: held.authority.directories[member].join("control.sock"),
                    slot: Some(Box::new(UnlaunchedSlot {
                        identity: U64::new(member as u64 + 1),
                        original: None,
                    })),
                    bootstrap_reader: Some(reader),
                    bootstrap_writer: Some(writer),
                    write_watchdog: Duration::from_secs(1),
                })
            })
        };
        PacketCompleteReportStartupHolder::retain_original_native_launch_inputs_into(
            &original,
            &mut inputs,
        )
        .unwrap();
        assert!(inputs.iter().all(Option::is_none));
        PacketCompleteReportStartupHolder::finalize_original_native_startup(&original).unwrap();
        assert!(original.borrow().authority.roster.current_native().is_err());
        (scene, original)
    }

    fn actual_peak(original: &Rc<RefCell<PacketCompleteReportStartupHolder>>) -> usize {
        let held = original.borrow();
        assert!(held.native_completed.get());
        assert!(!held.host_sdk_attempted.get());
        assert!(!held.host_sdk_in_flight.replace(true));
        let _loan = StartupLoan(&held.host_sdk_in_flight);
        let admission = held
            .plan
            .reserve_original_native_host_startup(
                &held.authority.roster.sources,
                &held.authority.original_launches,
                held.host_sdk_content.get().unwrap(),
            )
            .unwrap();
        admission.requested_peak_data()
    }

    #[test]
    fn actual_host_sdk_constructor_exact_policy_retains_all_three_unused_sdk_owners() {
        let (_scene, original) = fixture();
        original.borrow_mut().resources.memory_bytes =
            U64::new(POSITIVE_HOST_SDK_SETUP_MEMORY_BYTES);
        let peak = actual_peak(&original);
        original.borrow_mut().resources.memory_bytes = U64::new(peak as u64);

        assert_eq!(
            PacketCompleteReportStartupHolder::prepare_original_native_host_sdk(&original,)
                .unwrap(),
            peak
        );

        let held = original.borrow();
        assert!(held.host_sdk_attempted.get());
        assert!(held.host_sdk_completed.get());
        assert!(!held.host_sdk_in_flight.get());
        assert!(held.host_sdk_outputs.borrow().iter().all(Option::is_some));
        assert!(held.host_sdk_streams.borrow().iter().all(Option::is_none));
        assert!(held.authority.roster.current_native().is_err());
        assert!(matches!(
            PacketCompleteReportStartupHolder::prepare_original_native_host_sdk(&original,),
            Err(RuntimeError::DuplicateOperation)
        ));
    }

    #[test]
    fn actual_host_sdk_one_short_keeps_all_births_and_constructor_slots_unchanged() {
        let (_scene, original) = fixture();
        original.borrow_mut().resources.memory_bytes =
            U64::new(POSITIVE_HOST_SDK_SETUP_MEMORY_BYTES);
        let peak = actual_peak(&original);
        let before = {
            let held = original.borrow();
            std::array::from_fn::<_, 3, _>(|member| {
                held.authority.roster.sources[member]
                    .original_report_startup_audit_data()
                    .unwrap()
            })
        };
        original.borrow_mut().resources.memory_bytes = U64::new((peak - 1) as u64);

        assert!(matches!(
            PacketCompleteReportStartupHolder::prepare_original_native_host_sdk(&original,),
            Err(RuntimeError::ResourceLimit)
        ));

        let held = original.borrow();
        assert!(held.host_sdk_attempted.get());
        assert!(!held.host_sdk_completed.get());
        assert!(!held.host_sdk_in_flight.get());
        assert!(held.host_sdk_outputs.borrow().iter().all(Option::is_none));
        for (source, before) in held.authority.roster.sources.iter().zip(before) {
            assert_eq!(source.original_report_startup_audit_data().unwrap(), before);
        }
        assert!(held.authority.roster.current_native().is_err());
        assert!(matches!(
            PacketCompleteReportStartupHolder::prepare_original_native_host_sdk(&original,),
            Err(RuntimeError::DuplicateOperation)
        ));
    }

    #[test]
    fn actual_three_sources_keep_broad_members_and_emit_same_selected_initial_rows() {
        let (_scene, original) = fixture();
        let held = original.borrow();
        for (member, source) in held.authority.roster.sources.iter().enumerate() {
            let (broad, selected, wire) = source
                .original_initial_report_refinement_audit_data(source)
                .unwrap()
                .unwrap();
            broad.authenticate_actual_data(&selected).unwrap();
            assert_eq!(wire, selected);
            assert!(selected.retained_growth_bytes <= broad.retained_growth_bytes);
            assert!(
                selected.maximum_simultaneous_transient_bytes
                    <= broad.maximum_simultaneous_transient_bytes
            );
            assert!(
                source
                    .original_report_startup_audit_data()
                    .unwrap()
                    .complete
            );
            let other = &held.authority.roster.sources[(member + 1) % 3];
            assert!(
                source
                    .original_initial_report_refinement_audit_data(other)
                    .is_err()
            );
        }
        assert!(!held.host_sdk_attempted.get());
        assert!(!held.host_sdk_completed.get());
        assert!(held.authority.roster.current_native().is_err());
    }
}

impl PacketCompleteReportStartupHolder {
    /// Retains a fresh operator's actual content before its first report issue.
    ///
    /// The same original content observer counts these banks in report, native
    /// and SDK phases. This early transfer changes no construction permission.
    ///
    /// # Errors
    /// Refuses a nonfresh/foreign/attempted holder, occupied bank or absent input.
    pub(in crate::node_qualification::packet_collection::complete) fn retain_fresh_installation_content_into(
        original: &Rc<RefCell<Self>>,
        incoming: &mut Option<ContentBanks>,
    ) -> Result<(), RuntimeError> {
        let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        held.authenticate_native_origin_data()?;
        if !matches!(held.purpose, StartupHolderPurpose::FreshRestoration(_))
            || held.attempted.get()
            || held.native_attempted.get()
            || held.host_sdk_attempted.get()
            || held.host_sdk_content.get().is_some()
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        let content = incoming.take().ok_or(RuntimeError::OwnerUnavailable)?;
        if let Err(content) = held.host_sdk_content.set(content) {
            *incoming = Some(content);
            return Err(RuntimeError::DuplicateOperation);
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "actual retained-owner test oracle")]
impl PacketCompleteReportStartupHolder {
    /// Checks real original/fresh future rows and foreign-Source refusal.
    ///
    /// # Panics
    /// Panics when genuine completed members disagree with the expected test
    /// role or another actual Source can authenticate that member's quote.
    pub(in crate::node_qualification::packet_collection::complete) fn assert_native_report_commitment_for_test(
        original: &Rc<RefCell<Self>>,
        expected_original: bool,
    ) {
        let held = original.borrow();
        for (index, source) in held.authority.roster.sources.iter().enumerate() {
            let (purpose, original_row, fresh_row) = source
                .original_native_report_commitment_audit_data(source)
                .unwrap();
            assert_eq!(purpose, Some(expected_original));
            assert_eq!(original_row.is_some(), expected_original);
            assert_eq!(fresh_row.is_some(), !expected_original);
            let actual = original_row.or(fresh_row).unwrap();
            assert!(actual.retained_growth_bytes.get() > 0);
            assert!(actual.maximum_simultaneous_transient_bytes.get() > 0);

            let other = &held.authority.roster.sources[(index + 1) % 3];
            assert!(
                source
                    .original_native_report_commitment_audit_data(other)
                    .is_err()
            );
        }
    }
}

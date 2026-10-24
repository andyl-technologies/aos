//! Owns the actual installed scenario policy for pre-Child report publication.
//!
//! The authority keeps only a Weak link to this concrete capsule. Core's
//! nonconstructible scope authenticates the same plan, Source3 and typed launch
//! array before any observation. No callback follows a raw pointer or accepts
//! a caller-computed byte total, and no report admits its own construction.

mod host_startup;
mod native_startup;
pub use native_startup::PacketCompleteNativeLaunchInputs;
mod installed_source;
mod runtime;
pub use runtime::PacketCompleteOriginalSceneSupervisor;
mod scene;
pub use scene::PacketCompleteOriginalSceneInputs;
mod preparation;
mod restoration;
pub use preparation::PacketCompletePreparationConnection;
pub use restoration::PacketCompleteFreshRestorationInputs;

use super::super::retained::Counter;
use super::super::{PacketCompleteGraphOwner, capture_factory::PacketCompleteRestorationPrebirth};
use super::*;
use crucible_engine::node_adapters::cnp::{
    PacketCompleteEffectReceiverGroup, PacketCompleteEffectReceiverReader,
};
use crucible_engine::node_admission::{
    OriginalReportStartupMemberScope, OriginalReportStartupPolicy, OriginalReportStartupScope,
    OriginalReportStartupStorage,
};
use crucible_node_format::ResourceLimits;

/// Retains the original scene or actual fresh-restoration preparation capsule.
///
/// The non-clone graph owner preserves the installed policy's real revision.
/// The explicit ResourceLimits is an installed scenario declaration; only Core
/// can turn the complete owning observation into a report startup admission.
/// Native birth, code currentness, activation, Capture and restoration rights
/// keep their independent guards. A refusal retains every owner in this holder.
#[must_use = "retain the same original holders through launch and cleanup"]
pub struct PacketCompleteReportStartupHolder {
    graph_owner: PacketCompleteGraphOwner,
    authority: Rc<InstalledPacketCompleteCollectionAuthority>,
    plan: Rc<InstalledConformancePlan>,
    resources: ResourceLimits,
    purpose: StartupHolderPurpose,
    receiver_group: Rc<PacketCompleteEffectReceiverGroup>,
    receiver_reader: runtime::OriginalSharedOwner<PacketCompleteEffectReceiverReader>,
    runtime_owners: RefCell<runtime::OriginalRuntimeOwners>,
    runtime_members:
        [OnceCell<crucible_engine::node_admission::CompleteOriginalRuntimeConstructionMember>; 3],
    runtime_attempted: [Cell<bool>; 3],
    runtime_issuing:
        Cell<Option<crucible_engine::node_admission::OriginalRuntimeConstructionPhase>>,
    runtime_in_flight:
        Cell<Option<crucible_engine::node_admission::OriginalRuntimeConstructionPhase>>,
    process: u32,
    thread: std::thread::ThreadId,
    attempted: Cell<bool>,
    in_flight: Cell<bool>,
    completed: Cell<bool>,
    native_attempted: Cell<bool>,
    native_in_flight: Cell<bool>,
    native_completed: Cell<bool>,
    native_launches: RefCell<native_startup::NativeLaunchOwners>,
    host_sdk_content:
        OnceCell<[Rc<std::collections::BTreeMap<crucible_node_format::ContentRef, Vec<u8>>>; 3]>,
    host_sdk_outputs:
        RefCell<[Option<crucible_engine::node_adapters::cnp::PacketCompleteOriginalHostSdk>; 3]>,
    host_sdk_streams: RefCell<[Option<std::os::unix::net::UnixStream>; 3]>,
    host_sdk_connect_attempted: [Cell<bool>; 3],
    host_sdk_attempted: Cell<bool>,
    host_sdk_in_flight: Cell<bool>,
    host_sdk_completed: Cell<bool>,
    preparations: RefCell<preparation::PreparationOwners>,
    original_scene: OnceCell<RefCell<scene::OriginalSceneOwners>>,
    fresh_lifecycle: OnceCell<RefCell<restoration::FreshLifecycleOwners>>,
    fresh_runtime: OnceCell<runtime::FreshRuntimeOwners>,
    installed_host_owner: OnceCell<crucible_engine::node_contract::HostSchedulingOwner>,
    original_scene_retired: Cell<bool>,
    restoration_attempted: Cell<bool>,
    restoration_issuing: Cell<bool>,
    restoration_requests: RefCell<restoration::OriginalRestorationRequestOwners>,
    restoration_window:
        OnceCell<Rc<crucible_engine::node_admission::CompleteOriginalRestorationWindow>>,
    // Identity of the immutable inline publisher slot in the retained capsule.
    restoration_publication: OnceCell<*const ()>,
    // Actual inline target result publisher, independent of World publication.
    restored_result_publication: OnceCell<*const ()>,
    restoration_unplaced_window:
        RefCell<Option<Rc<crucible_engine::node_admission::CompleteOriginalRestorationWindow>>>,
}

enum StartupHolderPurpose {
    OriginalScene,
    FreshRestoration(Rc<RefCell<PacketCompleteRestorationPrebirth>>),
}

impl PacketCompleteReportStartupHolder {
    /// Installs the concrete original scene's report policy before any Child.
    ///
    /// The actual Sources must already retain ready, unstarted private births
    /// before reservation. This owns no decoded archive or synthetic native row.
    ///
    /// # Errors
    /// Refuses foreign actual graph/plan/authority, absent finite resource policy,
    /// unsupported Host phase or a previously registered original holder.
    pub fn install_original_scene(
        graph_owner: PacketCompleteGraphOwner,
        authority: Rc<InstalledPacketCompleteCollectionAuthority>,
        plan: Rc<InstalledConformancePlan>,
        resources: ResourceLimits,
        receiver_group: Rc<PacketCompleteEffectReceiverGroup>,
        receiver_reader: PacketCompleteEffectReceiverReader,
    ) -> Result<Rc<RefCell<Self>>, QualificationError> {
        authority
            .host
            .authenticate_original_report_startup_data()
            .map_err(|_| refused())?;
        Self::install(
            graph_owner,
            authority,
            plan,
            resources,
            StartupHolderPurpose::OriginalScene,
            receiver_group,
            receiver_reader,
        )
    }

    /// Installs the same actual fresh source/Host ticket holders before Child.
    ///
    /// The capsule retains the real signed source and once-issued native3
    /// tickets; the Host must be the same archive-ticketed allocation selected
    /// by this fresh authority. No old source process is required to be alive.
    ///
    /// # Errors
    /// Refuses a foreign, bound, busy or incomplete original capsule, changed
    /// fresh selection, exhausted policy or repeated holder registration.
    pub fn install_fresh_restoration(
        graph_owner: PacketCompleteGraphOwner,
        authority: Rc<InstalledPacketCompleteCollectionAuthority>,
        plan: Rc<InstalledConformancePlan>,
        resources: ResourceLimits,
        capsule: Rc<RefCell<PacketCompleteRestorationPrebirth>>,
        receiver_group: Rc<PacketCompleteEffectReceiverGroup>,
        receiver_reader: PacketCompleteEffectReceiverReader,
    ) -> Result<Rc<RefCell<Self>>, QualificationError> {
        capsule
            .try_borrow()
            .map_err(|_| refused())?
            .authenticate_report_startup_target_data(&authority, &plan)
            .map_err(|_| refused())?;
        capsule
            .try_borrow()
            .map_err(|_| refused())?
            .authenticate_host_source17_resources_data(&resources)
            .map_err(|_| refused())?;
        let holder = Self::install(
            graph_owner,
            authority,
            plan,
            resources,
            StartupHolderPurpose::FreshRestoration(Rc::clone(&capsule)),
            receiver_group,
            receiver_reader,
        )?;
        capsule
            .try_borrow_mut()
            .map_err(|_| refused())?
            .bind_report_startup_holder(&holder)
            .map_err(|_| refused())?;
        Ok(holder)
    }

    /// Retains a fresh holder before reserving its actual preparation supervisors.
    ///
    /// The prebirth capsule, policy, Source3 and archive-ticketed Host keep their
    /// existing authentication. Once installed, the caller's output owns the
    /// holder even if a later constructor or original Hello-slot binding refuses.
    /// This reserves host transport custodians; it does not admit native birth.
    ///
    /// # Errors
    /// Refuses occupied output, foreign installed originals, repeated policy
    /// registration or insufficient storage for all three known reservations.
    pub fn install_fresh_preparation_into(
        graph_owner: PacketCompleteGraphOwner,
        authority: Rc<InstalledPacketCompleteCollectionAuthority>,
        plan: Rc<InstalledConformancePlan>,
        resources: ResourceLimits,
        capsule: Rc<RefCell<PacketCompleteRestorationPrebirth>>,
        receiver_group: Rc<PacketCompleteEffectReceiverGroup>,
        receiver_reader: PacketCompleteEffectReceiverReader,
        output: &mut Option<Rc<RefCell<Self>>>,
    ) -> Result<(), QualificationError> {
        if output.is_some() {
            return Err(refused());
        }
        let original = Self::install_fresh_restoration(
            graph_owner,
            authority,
            plan,
            resources,
            capsule,
            receiver_group,
            receiver_reader,
        )?;
        *output = Some(original);
        Self::reserve_original_preparation_supervisors(output.as_ref().ok_or_else(refused)?)
    }

    fn install(
        graph_owner: PacketCompleteGraphOwner,
        authority: Rc<InstalledPacketCompleteCollectionAuthority>,
        plan: Rc<InstalledConformancePlan>,
        resources: ResourceLimits,
        purpose: StartupHolderPurpose,
        receiver_group: Rc<PacketCompleteEffectReceiverGroup>,
        receiver_reader: PacketCompleteEffectReceiverReader,
    ) -> Result<Rc<RefCell<Self>>, QualificationError> {
        authority.current()?;
        plan.authenticate_authority(authority.as_ref())
            .map_err(evidence_qualification)?;
        graph_owner.authenticate_original_report_policy_data(&authority.graph_policy)?;
        authenticate_resources(&resources)?;
        receiver_reader
            .authenticate_original_group(&receiver_group)
            .map_err(|_| refused())?;
        for (member, source) in authority.roster.sources.iter().enumerate() {
            source
                .authenticate_original_effect_receiver_binding(
                    &receiver_group,
                    member,
                    &authority.original_launches[member].effects,
                )
                .map_err(|_| refused())?;
        }
        if authority.report_startup_holder.get().is_some() {
            return Err(refused());
        }
        let original = Rc::new(RefCell::new(Self {
            graph_owner,
            authority: Rc::clone(&authority),
            plan,
            resources,
            purpose,
            receiver_group,
            receiver_reader: runtime::OriginalSharedOwner::new(receiver_reader),
            runtime_owners: RefCell::new(runtime::OriginalRuntimeOwners::new()),
            runtime_members: std::array::from_fn(|_| OnceCell::new()),
            runtime_attempted: std::array::from_fn(|_| Cell::new(false)),
            runtime_issuing: Cell::new(None),
            runtime_in_flight: Cell::new(None),
            process: std::process::id(),
            thread: std::thread::current().id(),
            attempted: Cell::new(false),
            in_flight: Cell::new(false),
            completed: Cell::new(false),
            native_attempted: Cell::new(false),
            native_in_flight: Cell::new(false),
            native_completed: Cell::new(false),
            native_launches: RefCell::new(native_startup::NativeLaunchOwners::new()),
            host_sdk_content: OnceCell::new(),
            host_sdk_outputs: RefCell::new([None, None, None]),
            host_sdk_streams: RefCell::new([None, None, None]),
            host_sdk_connect_attempted: std::array::from_fn(|_| Cell::new(false)),
            host_sdk_attempted: Cell::new(false),
            host_sdk_in_flight: Cell::new(false),
            host_sdk_completed: Cell::new(false),
            preparations: RefCell::new(preparation::PreparationOwners::new()),
            original_scene: OnceCell::new(),
            fresh_lifecycle: OnceCell::new(),
            fresh_runtime: OnceCell::new(),
            installed_host_owner: OnceCell::new(),
            original_scene_retired: Cell::new(false),
            restoration_attempted: Cell::new(false),
            restoration_issuing: Cell::new(false),
            restoration_requests: RefCell::new(restoration::OriginalRestorationRequestOwners::new()),
            restoration_window: OnceCell::new(),
            restoration_publication: OnceCell::new(),
            restored_result_publication: OnceCell::new(),
            restoration_unplaced_window: RefCell::new(None),
        }));
        authority
            .report_startup_holder
            .set(Rc::downgrade(&original))
            .map_err(|_| refused())?;
        Ok(original)
    }

    /// Reserves and finalizes all three report members under the same real holder.
    ///
    /// Core precharges this installed policy's declared observation scratch,
    /// observes the same owners and Sources, quotes real compiled publication
    /// phases, then issues once-spent members. The holder remains immutably
    /// borrowed while callbacks run; there is no mutable-controller escape.
    /// Failure keeps partial Source birth banks and all original holders.
    ///
    /// # Errors
    /// Refuses foreign or repeated preparation, an unknown owning term, absent
    /// report producer, changed phase/policy or any requested-storage excess.
    pub fn finalize_original_report_startup(
        original: &Rc<RefCell<Self>>,
    ) -> Result<usize, QualificationError> {
        Self::prepare_initial15_control_banks_data(original).map_err(|_| refused())?;
        let held = original.try_borrow().map_err(|_| refused())?;
        held.authenticate_origin()?;
        if held.attempted.replace(true) || held.in_flight.replace(true) {
            return Err(refused());
        }
        let _loan = StartupLoan(&held.in_flight);
        let invocation = held.authority.original_launches.iter().any(|launch| {
            launch
                .selection
                .provider
                .implementation
                .formats
                .iter()
                .any(|schema| schema.id.as_str() == "source-owned.packet-native-continuation/14")
        });
        let mut admission = if invocation {
            held.plan.reserve_original_invocation_report_startup(
                &held.authority.roster.sources,
                &held.authority.original_launches,
            )
        } else {
            held.plan.reserve_original_report_startup(
                &held.authority.roster.sources,
                &held.authority.original_launches,
            )
        }
        .map_err(evidence_qualification)?;
        let peak = admission.requested_peak_data();
        for member in 0..3 {
            admission
                .finalize_original_source(member)
                .map_err(evidence_qualification)?;
        }
        held.completed.set(true);
        Ok(peak)
    }

    pub(in crate::node_qualification::packet_collection::complete) fn authenticates_target_data(
        &self,
        authority: &InstalledPacketCompleteCollectionAuthority,
        plan: &InstalledConformancePlan,
    ) -> Result<(), QualificationError> {
        self.authenticate_origin()?;
        if !std::ptr::eq(self.authority.as_ref(), authority)
            || !self.plan.is_original_plan_data(plan)
            || !self.completed.get()
        {
            return Err(refused());
        }
        self.graph_owner
            .authenticate_original_report_policy_data(&authority.graph_policy)
    }

    pub(super) fn charge_fresh_host_archive_precredit_data(
        &self,
        authority: &InstalledPacketCompleteCollectionAuthority,
        counter: &mut Counter,
    ) -> Result<(), crucible_engine::node_contract::RuntimeError> {
        self.authenticate_origin()
            .map_err(|_| crucible_engine::node_contract::RuntimeError::ForeignAuthority)?;
        if !std::ptr::eq(self.authority.as_ref(), authority) {
            return Err(crucible_engine::node_contract::RuntimeError::ForeignAuthority);
        }
        self.graph_owner
            .authenticate_original_report_policy_data(&authority.graph_policy)
            .map_err(|_| crucible_engine::node_contract::RuntimeError::ForeignAuthority)?;
        let StartupHolderPurpose::FreshRestoration(capsule) = &self.purpose else {
            return Err(crucible_engine::node_contract::RuntimeError::UnsupportedFacet);
        };
        let capsule = capsule
            .try_borrow()
            .map_err(|_| crucible_engine::node_contract::RuntimeError::OwnerBusy)?;
        let bytes = if self.fresh_runtime.get().is_some() {
            capsule.retained_fresh_construction_source_data(&authority.host, counter.remaining())?
        } else {
            capsule
                .retained_fresh_host_archive_precredit_data(&authority.host, counter.remaining())?
        };
        counter
            .add(bytes)
            .map_err(|_| crucible_engine::node_contract::RuntimeError::ResourceLimit)
    }

    fn authenticate_origin(&self) -> Result<(), QualificationError> {
        if self.process != std::process::id() || self.thread != std::thread::current().id() {
            return Err(refused());
        }
        Ok(())
    }

    fn authenticate_scope_data(
        &self,
        authority: &InstalledPacketCompleteCollectionAuthority,
        scope: &OriginalReportStartupScope<'_>,
    ) -> Result<(), QualificationError> {
        self.authenticate_origin()?;
        if self.original_scene_retired.get()
            || !self.in_flight.get()
            || self.completed.get()
            || !std::ptr::eq(self.authority.as_ref(), authority)
            || !scope.is_original_authority(authority)
            || !scope.is_original_plan(&self.plan)
            || !std::ptr::eq(scope.sources(), &authority.roster.sources)
            || !std::ptr::eq(scope.launches(), &authority.original_launches)
        {
            return Err(refused());
        }
        self.graph_owner
            .authenticate_original_report_policy_data(&authority.graph_policy)?;
        self.receiver_reader
            .original_data()
            .map_err(|_| refused())?
            .authenticate_original_group(&self.receiver_group)
            .map_err(|_| refused())?;
        for (member, source) in authority.roster.sources.iter().enumerate() {
            source
                .authenticate_original_effect_receiver_binding_data(
                    &self.receiver_group,
                    member,
                    &authority.original_launches[member].effects,
                )
                .map_err(|_| refused())?;
        }
        match &self.purpose {
            StartupHolderPurpose::OriginalScene => authority
                .host
                .authenticate_original_report_startup_data()
                .map_err(|_| refused()),
            StartupHolderPurpose::FreshRestoration(capsule) => capsule
                .try_borrow()
                .map_err(|_| refused())?
                .authenticate_report_startup_target_data(authority, &self.plan)
                .map_err(|_| refused()),
        }
    }

    fn policy_data(&self) -> Result<OriginalReportStartupPolicy, QualificationError> {
        let maximum = usize::try_from(self.resources.memory_bytes.get()).map_err(|_| refused())?;
        // These are actual compiled observers. Source and publication producer
        // scratch is independently precharged by Core, never replaced here.
        let counters = std::mem::size_of::<Counter>()
            .checked_mul(4)
            .ok_or_else(refused)?;
        let scratch = counters.checked_add(
            crucible_engine::node_admission::CompleteArchiveCodeGraph::retained_requested_storage_scratch_bytes())
            .and_then(|bytes| bytes.checked_add(crucible_node_transport::retained_metadata::original_metadata_observer_layout_bytes()))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<crucible_node_transport::retained_metadata::RetainedProtocolMetadataFacts>()))
            .ok_or_else(refused)?;
        let scratch = scratch
            .checked_add(
                self.original_scene_counter_scratch_data()
                    .map_err(|_| refused())?,
            )
            .ok_or_else(refused)?;
        let scratch = scratch
            .checked_add(super::super::InstalledCompleteRestoration::counter_scratch_data())
            .ok_or_else(refused)?;
        let scratch = if matches!(&self.purpose, StartupHolderPurpose::FreshRestoration(_)) {
            scratch
                .checked_add(
                    Self::initial15_control_classification_counter_scratch_data()
                        .map_err(|_| refused())?,
                )
                .ok_or_else(refused)?
        } else {
            scratch
        };
        Ok(OriginalReportStartupPolicy {
            maximum_requested_bytes: maximum,
            declared_observer_scratch_bytes: scratch,
        })
    }

    fn storage_data(
        original: &Rc<RefCell<Self>>,
        held: &Self,
        maximum: usize,
    ) -> Result<OriginalReportStartupStorage, QualificationError> {
        let mut counter = Counter::new(maximum);
        counter.rc(original)?;
        counter.add(
            held.receiver_group
                .original_retained_requested_storage_precredit_data(counter.remaining())
                .map_err(|_| refused())?,
        )?;
        if counter.rc(&held.authority)? {
            match &held.purpose {
                StartupHolderPurpose::OriginalScene => {
                    held.authority.charge_retained_storage(&mut counter)?
                }
                StartupHolderPurpose::FreshRestoration(_) => held
                    .authority
                    .charge_report_startup_retained_storage(&mut counter)?,
            }
        }
        if counter.rc(&held.plan)? {
            counter.add(
                held.plan
                    .retained_allocation_bytes_excluding_authority_precredit_data()
                    .map_err(|_| refused())?,
            )?;
        }
        if let StartupHolderPurpose::FreshRestoration(capsule) = &held.purpose {
            counter.add(
                capsule
                    .try_borrow()
                    .map_err(|_| refused())?
                    .retained_host_holder_precredit_data(capsule, counter.remaining())
                    .map_err(|_| refused())?,
            )?;
        }
        held.charge_original_scene_storage_precredit_data(&mut counter)
            .map_err(|_| refused())?;
        held.charge_native_launch_storage_precredit_data(&mut counter)
            .map_err(|_| refused())?;
        held.charge_host_sdk_storage_precredit_data(&mut counter)
            .map_err(|_| refused())?;
        held.preparations
            .try_borrow()
            .map_err(|_| refused())?
            .charge_supervisors(&mut counter)?;
        // This selected success path walks borrowed capacities without a new
        // temporary heap bank. All compiled counters/metadata views are already
        // admitted by policy_data; source/finalization phases are Core terms.
        Ok(OriginalReportStartupStorage {
            retained_holder_bytes: counter.bytes(),
            maximum_simultaneous_transient_bytes: 0,
        })
    }
}

struct StartupLoan<'a>(&'a Cell<bool>);

impl Drop for StartupLoan<'_> {
    fn drop(&mut self) {
        self.0.set(false);
    }
}

impl InstalledPacketCompleteCollectionAuthority {
    pub(super) fn original_report_startup_policy_data(
        &self,
        scope: &OriginalReportStartupScope<'_>,
    ) -> Result<OriginalReportStartupPolicy, EvidenceError> {
        // Raw original checks precede any inherited Weak/RefCell owner loan.
        self.graph_policy
            .authenticate_retained_origin_data()
            .map_err(evidence_error)?;
        let original = self
            .report_startup_holder
            .get()
            .and_then(std::rc::Weak::upgrade)
            .ok_or_else(|| evidence_error(refused()))?;
        let held = original
            .try_borrow()
            .map_err(|_| evidence_error(refused()))?;
        held.authenticate_scope_data(self, scope)
            .map_err(evidence_error)?;
        held.policy_data().map_err(evidence_error)
    }

    pub(super) fn authenticate_original_report_startup_member_data(
        &self,
        scope: &OriginalReportStartupMemberScope<'_>,
    ) -> Result<(), EvidenceError> {
        self.graph_policy
            .authenticate_retained_origin_data()
            .map_err(evidence_error)?;
        let original = self
            .report_startup_holder
            .get()
            .and_then(std::rc::Weak::upgrade)
            .ok_or_else(|| evidence_error(refused()))?;
        let held = original
            .try_borrow()
            .map_err(|_| evidence_error(refused()))?;
        held.authenticate_origin().map_err(evidence_error)?;
        if held.original_scene_retired.get()
            || !std::ptr::eq(held.authority.as_ref(), self)
            || !scope.is_original_authority(self)
            || !scope.is_original_plan(&held.plan)
            || (!held.in_flight.get() && !held.completed.get())
            || !self
                .roster
                .sources
                .iter()
                .any(|source| std::ptr::eq(source.as_ref(), scope.source()))
        {
            return Err(evidence_error(refused()));
        }
        // Member authentication may occur under the Source birth's immutable
        // RefCell loan. Follow only the registered holder's original identities
        // and revision here; never reborrow birth or invoke current()/hash/IO.
        // Actual private launch and boot retain their separate full byte fences.
        held.graph_owner
            .authenticate_original_report_policy_data(&self.graph_policy)
            .map_err(evidence_error)
    }

    pub(super) fn original_report_startup_storage_data(
        &self,
        scope: &OriginalReportStartupScope<'_>,
        policy: &OriginalReportStartupPolicy,
    ) -> Result<OriginalReportStartupStorage, EvidenceError> {
        self.graph_policy
            .authenticate_retained_origin_data()
            .map_err(evidence_error)?;
        let original = self
            .report_startup_holder
            .get()
            .and_then(std::rc::Weak::upgrade)
            .ok_or_else(|| evidence_error(refused()))?;
        let held = original
            .try_borrow()
            .map_err(|_| evidence_error(refused()))?;
        held.authenticate_scope_data(self, scope)
            .map_err(evidence_error)?;
        if &held.policy_data().map_err(evidence_error)? != policy {
            return Err(evidence_error(refused()));
        }
        let result = PacketCompleteReportStartupHolder::storage_data(
            &original,
            &held,
            policy.maximum_requested_bytes,
        )
        .map_err(evidence_error)?;
        held.authenticate_scope_data(self, scope)
            .map_err(evidence_error)?;
        Ok(result)
    }
}

fn authenticate_resources(resources: &ResourceLimits) -> Result<(), QualificationError> {
    if !resources.extensions.is_empty()
        || resources.processes.get() < 3
        || [
            resources.cpu_budget_ns,
            resources.memory_bytes,
            resources.writable_bytes,
            resources.descriptors,
            resources.pending_events,
            resources.content_bytes,
            resources.maximum_operations,
        ]
        .iter()
        .any(|value| value.get() == 0)
        || usize::try_from(resources.memory_bytes.get()).is_err()
    {
        return Err(refused());
    }
    Ok(())
}

fn evidence_qualification(error: EvidenceError) -> QualificationError {
    QualificationError::Evidence(error.message)
}

#[cfg(test)]
#[path = "report_startup_tests.rs"]
mod tests;

#[path = "report_startup/initial15_control.rs"]
mod initial15_control;

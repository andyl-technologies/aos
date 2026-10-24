//! Constructs a genuine ticketed target runtime under the retained installed action.
//!
//! Original native preparations stay in their holder until its real Core member
//! admits each phase. The graph binds once to the archive source; the ticketed
//! Host and actual native nodes then move into the capsule's inactive runtime.
//! The real dormant scene serves admission only; the archive-bound runtime remains distinct.

use super::*;
use crucible_engine::node_contract::{
    ActivationRecord, NodeRuntime, PreparedRealization, SimulationNode,
};
use std::{
    cell::{BorrowError, BorrowMutError, Ref, RefMut},
    mem::{align_of, size_of, size_of_val},
};

pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) struct FreshRuntimeOwners
{
    graph: RefCell<Option<Rc<ConformanceGraph>>>,
    prepared: RefCell<Option<PreparedRealization>>,
    in_progress: Cell<bool>,
    complete: Cell<bool>,
}

impl FreshRuntimeOwners {
    pub(super) fn empty() -> Self {
        Self {
            graph: RefCell::new(None),
            prepared: RefCell::new(None),
            in_progress: Cell::new(true),
            complete: Cell::new(false),
        }
    }
}

struct Flight<'a>(&'a Cell<bool>);

impl Drop for Flight<'_> {
    fn drop(&mut self) {
        self.0.set(false);
    }
}

impl PacketCompleteReportStartupHolder {
    /// Constructs this actual fresh holder's source-bound inactive target runtime.
    ///
    /// All three actual baseline and authenticated fresh HOST queries must have
    /// completed. The same installed Core phase actions admit construction before
    /// new allocation; the holder retains each member and every surviving owner.
    /// A refused or unwound flight cannot be restarted or used for restoration.
    ///
    /// # Errors
    /// Refuses original-scene, foreign, incomplete, repeated or retired custody,
    /// unknown owner storage, exhausted installed policy or constructor failure.
    pub fn prepare_original_fresh_runtime(
        original: &Rc<RefCell<Self>>,
    ) -> Result<(), RuntimeError> {
        {
            let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
            held.authenticate_native_origin_data()?;
            if !matches!(&held.purpose, StartupHolderPurpose::FreshRestoration(_))
                || held.original_scene.get().is_some()
                || held.original_scene_retired.get()
                || held.fresh_runtime.get().is_some()
            {
                return Err(RuntimeError::OutstandingObligations);
            }
            let fresh = held
                .fresh_lifecycle
                .get()
                .ok_or(RuntimeError::OwnerUnavailable)?
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            if !fresh.staged
                || !fresh.launched.get()
                || !fresh.initial_completed.iter().all(Cell::get)
                || !fresh.host_completed.iter().all(Cell::get)
                || fresh.inputs.is_none()
                || fresh.runtime_slot.is_none()
            {
                return Err(RuntimeError::OutstandingObligations);
            }
            held.fresh_runtime
                .set(FreshRuntimeOwners::empty())
                .map_err(|_| RuntimeError::DuplicateOperation)?;
        }
        let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        let state = held
            .fresh_runtime
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let _flight = Flight(&state.in_progress);
        Self::prepare_runtime_construction_data(original)?;
        state.complete.set(true);
        Ok(())
    }

    pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) fn authenticate_fresh_runtime_flight_data(
        &self,
    ) -> Result<(), RuntimeError> {
        let state = self
            .fresh_runtime
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if !matches!(&self.purpose, StartupHolderPurpose::FreshRestoration(_))
            || self.original_scene.get().is_some()
            || self.original_scene_retired.get()
            || (!state.in_progress.get() && !state.complete.get())
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(())
    }

    pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) fn authenticate_completed_fresh_runtime_data(
        &self,
    ) -> Result<(), RuntimeError> {
        self.authenticate_fresh_runtime_flight_data()?;
        let state = self
            .fresh_runtime
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if !state.complete.get()
            || state.in_progress.get()
            || self
                .runtime_members
                .iter()
                .any(|member| member.get().is_none())
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(())
    }

    pub(super) fn runtime_host_node_construction_data(
        &self,
        activation: &ActivationRecord,
        maximum: usize,
    ) -> Result<(usize, usize, usize), RuntimeError> {
        match &self.purpose {
            StartupHolderPurpose::OriginalScene => {
                let row = self
                    .authority
                    .host_source()
                    .original_collection_node_construction_storage_data(activation, maximum)?;
                Ok((
                    row.retained_requested_bytes(),
                    row.maximum_simultaneous_transient_bytes(),
                    row.declared_counter_scratch_bytes(),
                ))
            }
            StartupHolderPurpose::FreshRestoration(capsule) => capsule
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?
                .original_fresh_host_node_construction_data(activation, maximum),
        }
    }

    pub(super) fn fresh_graph_wrapper_construction_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        let mut counter = Counter::new(maximum);
        counter
            .add(
                super::super::super::super::retained::shared_requested_storage(
                    size_of::<ConformanceGraph>(),
                    align_of::<ConformanceGraph>(),
                )
                .map_err(storage_error)?,
            )
            .map_err(storage_error)?;
        // These input vectors remain owned beside the graph's independent copies.
        counter
            .add(
                4 * (size_of::<NodeDescriptor>()
                    + size_of::<NodeBinding>()
                    + size_of::<OwnerBinding>()),
            )
            .map_err(storage_error)?;
        for source in &self.authority.roster.sources {
            let selected = source.installation();
            counter
                .charge(&selected.descriptor)
                .map_err(storage_error)?;
            counter.charge(&selected.binding).map_err(storage_error)?;
            counter.charge(&selected.owner).map_err(storage_error)?;
        }
        let host = self.authority.host_source().selection();
        counter.charge(&host.descriptor).map_err(storage_error)?;
        counter.charge(&host.binding).map_err(storage_error)?;
        counter.charge(&host.owner).map_err(storage_error)?;
        Ok(counter.bytes())
    }

    pub(super) fn prepare_runtime_host_node_into(
        &self,
        owners: &mut OriginalRuntimeOwners,
        activation: &ActivationRecord,
    ) -> Result<(), RuntimeError> {
        match &self.purpose {
            StartupHolderPurpose::OriginalScene => {
                owners.host = Some(
                    self.authority
                        .host_source()
                        .prepare_collection_node(
                            owners
                                .graph
                                .as_ref()
                                .ok_or(RuntimeError::OwnerUnavailable)?,
                            activation,
                        )
                        .map_err(|_| RuntimeError::ForeignAuthority)?,
                );
                Ok(())
            }
            StartupHolderPurpose::FreshRestoration(capsule) => {
                self.authenticate_fresh_runtime_flight_data()?;
                let state = self
                    .fresh_runtime
                    .get()
                    .ok_or(RuntimeError::OwnerUnavailable)?;
                if state
                    .graph
                    .try_borrow()
                    .map_err(|_| RuntimeError::OwnerBusy)?
                    .is_some()
                {
                    return Err(RuntimeError::DuplicateOperation);
                }
                let graph = Rc::new(owners.graph.take().ok_or(RuntimeError::OwnerUnavailable)?);
                *state
                    .graph
                    .try_borrow_mut()
                    .map_err(|_| RuntimeError::OwnerBusy)? = Some(Rc::clone(&graph));
                let mut incoming = Some(graph);
                let factory = owners
                    .factory
                    .as_ref()
                    .ok_or(RuntimeError::OwnerUnavailable)?;
                let mut capsule = capsule
                    .try_borrow_mut()
                    .map_err(|_| RuntimeError::OwnerBusy)?;
                capsule
                    .bind_original_target_graph(&mut incoming, factory)
                    .map_err(|_| RuntimeError::ForeignAuthority)?;
                capsule
                    .prepare_original_host_node_into(activation, &mut owners.host)
                    .map_err(|_| RuntimeError::ForeignAuthority)
            }
        }
    }

    pub(super) fn quote_fresh_inactive_data(
        &self,
        maximum: usize,
    ) -> Result<(usize, usize, usize), RuntimeError> {
        self.authenticate_fresh_runtime_flight_data()?;
        let state = self
            .fresh_runtime
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let graph = state
            .graph
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let graph = graph.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        let fresh = self.runtime_construction_owner_data()?;
        let activation = fresh.activation()?;
        let owners = self
            .runtime_owners
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let [a, b, c] = owners
            .nodes
            .each_ref()
            .map(|node| node.as_ref().ok_or(RuntimeError::OwnerUnavailable));
        let (a, b, c) = (a?, b?, c?);
        let host = owners.host.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        let runtime = NodeRuntime::original_fixed_four_construction_storage_data(
            graph,
            [
                a.original_conformance_route_data(),
                b.original_conformance_route_data(),
                c.original_conformance_route_data(),
                host.route(),
            ],
            [
                a.original_conformance_facets_data(&self.authority.roster.sources[0])?,
                b.original_conformance_facets_data(&self.authority.roster.sources[1])?,
                c.original_conformance_facets_data(&self.authority.roster.sources[2])?,
                host.facets(),
            ],
            activation,
            fresh.limits()?,
            maximum,
        )?;
        let prepared =
            CnpSemanticConformanceNode::original_restoration_prepared_construction_storage_data(
                activation, maximum,
            )?;
        Ok((
            add(runtime.retained_requested_bytes, prepared.0, maximum)?,
            add(
                runtime.maximum_simultaneous_transient_bytes,
                prepared.1,
                maximum,
            )?,
            add(runtime.declared_counter_scratch_bytes, prepared.2, maximum)?,
        ))
    }

    pub(super) fn construct_fresh_inactive_data(&self) -> Result<(), RuntimeError> {
        self.authenticate_fresh_runtime_flight_data()?;
        let state = self
            .fresh_runtime
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let mut owners = self
            .runtime_owners
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        owners
            .native
            .try_reserve_exact(4)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        if owners.native.capacity() != 4 {
            return Err(RuntimeError::ResourceLimit);
        }
        let mut prepared = state
            .prepared
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        {
            let mut fresh = self
                .fresh_lifecycle
                .get()
                .ok_or(RuntimeError::OwnerUnavailable)?
                .try_borrow_mut()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            let super::super::restoration::FreshLifecycleOwners {
                inputs,
                runtime_slot,
                ..
            } = &mut *fresh;
            let inputs = inputs.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
            let OriginalRuntimeOwners {
                nodes,
                host,
                native,
                ..
            } = &mut *owners;
            CnpSemanticConformanceNode::prepare_original_restoration_inputs_into(
                nodes,
                host,
                native,
                runtime_slot,
                &inputs.activation,
                inputs.runtime_limits,
                &mut prepared,
            )?;
        }
        drop(owners);
        let StartupHolderPurpose::FreshRestoration(capsule) = &self.purpose else {
            return Err(RuntimeError::ForeignAuthority);
        };
        capsule
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?
            .prepare_original_runtime(&mut prepared)
            .map_err(|_| RuntimeError::InvalidReceipt)
    }

    /// Retires this same fresh holder's original runtime and native custody.
    ///
    /// Containment remains available after graph revocation or failed construction.
    /// Each partial owner stays retained; no new slot, supervisor or native request
    /// is substituted to complete cleanup.
    ///
    /// # Errors
    /// Refuses foreign creator/thread, wrong holder family, busy owners or a
    /// refused actual custody transfer. Repeated cleanup may drive the same owner.
    ///
    /// # Panics
    /// Installed custody slots must obey their non-unwinding retirement contract.
    pub fn retire_original_fresh_restoration(
        original: &Rc<RefCell<Self>>,
    ) -> Result<(), RuntimeError> {
        let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        if held.process != std::process::id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if held.thread != std::thread::current().id() {
            return Err(RuntimeError::ThreadAffinity);
        }
        let StartupHolderPurpose::FreshRestoration(capsule) = &held.purpose else {
            return Err(RuntimeError::ForeignAuthority);
        };
        held.original_scene_retired.set(true);
        if let Some(state) = held.fresh_runtime.get() {
            if let Some(prepared) = state
                .prepared
                .try_borrow_mut()
                .map_err(|_| RuntimeError::OwnerBusy)?
                .as_mut()
            {
                prepared.retire_original()?;
            }
        }
        capsule
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?
            .retire_retained_fresh_runtime_data()?;
        // No constructor can acquire runtime owners before the retained
        // lifecycle exists. Installation may retain its output earlier.
        if held.fresh_lifecycle.get().is_some() {
            held.retire_original_runtime_owners()?;
        }
        held.retire_original_scene_native_guards()?;
        held.retire_original_scene_preparations()?;
        if let Some(fresh) = held.fresh_lifecycle.get() {
            let mut fresh = fresh
                .try_borrow_mut()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            if let Some(inputs) = &mut fresh.inputs {
                for launch in inputs.launches.iter_mut().flatten() {
                    drop(launch.slot.take());
                }
            }
            drop(fresh.runtime_slot.take());
        }
        Ok(())
    }

    /// Drives the actual retained fresh supervisor after retirement.
    ///
    /// # Errors
    /// Refuses another family/creator, busy or unretired custody, invalid pass
    /// bounds or the original selected supervisor's sticky cleanup failure.
    pub fn drive_original_fresh_reclamation(
        original: &Rc<RefCell<Self>>,
        maximum_passes: usize,
    ) -> Result<
        std::task::Poll<
            Result<
                crate::node_qualification::packet_collection::PacketWorldSupervisionObservation,
                crate::node_qualification::packet_collection::PacketSupervisionFailure,
            >,
        >,
        QualificationError,
    > {
        let held = original.try_borrow().map_err(|_| refused())?;
        held.authenticate_origin()?;
        if !matches!(&held.purpose, StartupHolderPurpose::FreshRestoration(_))
            || !held.original_scene_retired.get()
        {
            return Err(refused());
        }
        let fresh = held
            .fresh_lifecycle
            .get()
            .ok_or_else(refused)?
            .try_borrow()
            .map_err(|_| refused())?;
        fresh
            .inputs
            .as_ref()
            .ok_or_else(refused)?
            .supervisor
            .original_data()
            .map_err(|_| refused())?
            .drive_complete_original_reclamation(maximum_passes)
    }

    pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) fn charge_fresh_runtime_storage_data(
        &self,
        counter: &mut Counter,
    ) -> Result<(), RuntimeError> {
        let Some(state) = self.fresh_runtime.get() else {
            return Ok(());
        };
        // A failed move retains the exact preparation for cleanup. It cannot
        // become a zero-cost hole or authorize another constructor phase.
        if state
            .prepared
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?
            .is_some()
        {
            return Err(RuntimeError::UnsupportedFacet);
        }
        if let Some(graph) = state
            .graph
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?
            .as_ref()
        {
            if counter.rc(graph).map_err(storage_error)? {
                counter
                    .add(graph.original_retained_storage_precredit_data(counter.remaining())?)
                    .map_err(storage_error)?;
            }
        }
        Ok(())
    }

    pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) fn authenticate_fresh_preparation_destination_data(
        &self,
        selected: usize,
        activation: &ActivationRecord,
    ) -> Result<(), RuntimeError> {
        self.authenticate_fresh_runtime_flight_data()?;
        let owners = self
            .runtime_owners
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if let Some(node) = owners
            .nodes
            .get(selected)
            .ok_or(RuntimeError::ForeignAuthority)?
            .as_ref()
        {
            node.original_conformance_facets_data(&self.authority.roster.sources[selected])?;
            return Ok(());
        }
        drop(owners);
        let StartupHolderPurpose::FreshRestoration(capsule) = &self.purpose else {
            return Err(RuntimeError::ForeignAuthority);
        };
        // The distinct runtime visitor checks SAME archive, plan, proposal and
        // actual four-node runtime; neither an empty slot nor a phase bit suffices.
        capsule
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?
            .retained_fresh_construction_runtime_descriptor_data(activation)?;
        Ok(())
    }

    pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) fn fresh_runtime_descriptor_data(
        &self,
    ) -> Result<usize, RuntimeError> {
        if self.fresh_runtime.get().is_none() {
            return Ok(0);
        }
        let StartupHolderPurpose::FreshRestoration(capsule) = &self.purpose else {
            return Err(RuntimeError::ForeignAuthority);
        };
        let owner = self.runtime_construction_owner_data()?;
        capsule
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?
            .retained_fresh_construction_descriptor_data(owner.activation()?)
    }
}

pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) fn counter_scratch_data()
-> Result<usize, RuntimeError> {
    use super::super::restoration::{FreshLifecycleOwners, PacketCompleteFreshRestorationInputs};
    let terms = [
        super::family::counter_scratch_data(),
        PacketCompleteRestorationPrebirth::original_fresh_construction_counter_scratch_data()?,
        PacketCompleteRestorationPrebirth::fresh_runtime_custody_counter_scratch_data(),
        CnpSemanticConformanceNode::original_restoration_prepared_counter_scratch_data(),
        NodeRuntime::original_fixed_four_construction_counter_scratch_data(),
        size_of::<FreshRuntimeOwners>(), size_of::<Flight<'_>>(),
        size_of::<Option<&mut PreparedRealization>>(),
        size_of::<Result<(), QualificationError>>(),
        size_of::<std::task::Poll<Result<crate::node_qualification::packet_collection::PacketWorldSupervisionObservation,
            crate::node_qualification::packet_collection::PacketSupervisionFailure>>>(),
        size_of::<Result<std::task::Poll<Result<crate::node_qualification::packet_collection::PacketWorldSupervisionObservation,
            crate::node_qualification::packet_collection::PacketSupervisionFailure>>, QualificationError>>(),
        size_of::<&FreshRuntimeOwners>(), size_of::<Option<&FreshRuntimeOwners>>(),
        size_of::<Result<&FreshRuntimeOwners, RuntimeError>>(),
        size_of::<&OnceCell<FreshRuntimeOwners>>(),
        size_of::<Result<(), FreshRuntimeOwners>>(),
        size_of::<Ref<'_, PacketCompleteReportStartupHolder>>(),
        size_of::<Result<Ref<'_, PacketCompleteReportStartupHolder>, BorrowError>>(),
        size_of::<Result<Ref<'_, PacketCompleteReportStartupHolder>, RuntimeError>>(),
        size_of::<Ref<'_, FreshLifecycleOwners>>(), size_of::<RefMut<'_, FreshLifecycleOwners>>(),
        size_of::<Result<Ref<'_, FreshLifecycleOwners>, BorrowError>>(),
        size_of::<Result<Ref<'_, FreshLifecycleOwners>, RuntimeError>>(),
        size_of::<Result<RefMut<'_, FreshLifecycleOwners>, BorrowMutError>>(),
        size_of::<Result<RefMut<'_, FreshLifecycleOwners>, RuntimeError>>(),
        size_of::<Option<&PacketCompleteFreshRestorationInputs>>(),
        size_of::<Result<&PacketCompleteFreshRestorationInputs, RuntimeError>>(),
        size_of::<Ref<'_, Option<Rc<ConformanceGraph>>>>(),
        size_of::<Result<Ref<'_, Option<Rc<ConformanceGraph>>>, BorrowError>>(),
        size_of::<Result<Ref<'_, Option<Rc<ConformanceGraph>>>, RuntimeError>>(),
        size_of::<RefMut<'_, Option<Rc<ConformanceGraph>>>>(),
        size_of::<Result<RefMut<'_, Option<Rc<ConformanceGraph>>>, BorrowMutError>>(),
        size_of::<Result<RefMut<'_, Option<Rc<ConformanceGraph>>>, RuntimeError>>(),
        size_of::<Rc<ConformanceGraph>>(), size_of::<Option<Rc<ConformanceGraph>>>(),
        size_of::<&Rc<ConformanceGraph>>(), size_of::<Option<&Rc<ConformanceGraph>>>(),
        size_of::<Result<&Rc<ConformanceGraph>, RuntimeError>>(),
        size_of::<Ref<'_, Option<PreparedRealization>>>(),
        size_of::<Result<Ref<'_, Option<PreparedRealization>>, BorrowError>>(),
        size_of::<Result<Ref<'_, Option<PreparedRealization>>, RuntimeError>>(),
        size_of::<RefMut<'_, Option<PreparedRealization>>>(),
        size_of::<Result<RefMut<'_, Option<PreparedRealization>>, BorrowMutError>>(),
        size_of::<Result<RefMut<'_, Option<PreparedRealization>>, RuntimeError>>(),
        size_of::<Ref<'_, OriginalRuntimeOwners>>(), size_of::<RefMut<'_, OriginalRuntimeOwners>>(),
        size_of::<Result<Ref<'_, OriginalRuntimeOwners>, BorrowError>>(),
        size_of::<Result<Ref<'_, OriginalRuntimeOwners>, RuntimeError>>(),
        size_of::<Result<RefMut<'_, OriginalRuntimeOwners>, BorrowMutError>>(),
        size_of::<Result<RefMut<'_, OriginalRuntimeOwners>, RuntimeError>>(),
        size_of::<Ref<'_, PacketCompleteRestorationPrebirth>>(), size_of::<RefMut<'_, PacketCompleteRestorationPrebirth>>(),
        size_of::<Result<Ref<'_, PacketCompleteRestorationPrebirth>, BorrowError>>(),
        size_of::<Result<Ref<'_, PacketCompleteRestorationPrebirth>, RuntimeError>>(),
        size_of::<Result<RefMut<'_, PacketCompleteRestorationPrebirth>, BorrowMutError>>(),
        size_of::<Result<RefMut<'_, PacketCompleteRestorationPrebirth>, RuntimeError>>(),
        size_of::<[&CnpSemanticConformanceNode; 3]>(),
        size_of::<[Result<&CnpSemanticConformanceNode, RuntimeError>; 3]>(),
        size_of::<&CnpSemanticConformanceNode>(), size_of::<Option<&CnpSemanticConformanceNode>>(),
        size_of::<Result<&CnpSemanticConformanceNode, RuntimeError>>(),
        size_of::<Option<&Option<CnpSemanticConformanceNode>>>(),
        size_of::<Result<&Option<CnpSemanticConformanceNode>, RuntimeError>>(),
        size_of::<&PreparedHostSchedulingNode>(), size_of::<Option<&PreparedHostSchedulingNode>>(),
        size_of::<Result<&PreparedHostSchedulingNode, RuntimeError>>(),
        size_of::<crucible_engine::node_contract::OriginalFixedFourRuntimeConstructionStorageData>(),
        size_of::<Result<crucible_engine::node_contract::OriginalFixedFourRuntimeConstructionStorageData, RuntimeError>>(),
        size_of::<(usize,usize,usize)>(), size_of::<Result<(usize,usize,usize),RuntimeError>>(),
        size_of::<Counter>(), size_of::<[usize; 3]>(),
        size_of::<Result<usize, RuntimeError>>(), size_of::<Result<(), RuntimeError>>(),
    ];
    terms.iter().try_fold(size_of_val(&terms), |total, bytes| {
        add(total, *bytes, usize::MAX)
    })
}

//! Retains the actual completed-Admit preparations beneath the installed holder.
//!
//! Operational supervisor handles and their non-cloneable metadata owners are
//! constructed together before Child. Preparation/query owners remain in fixed
//! original slots through refusals; typed observations never mint native rights.

mod connection;
mod runtime;
mod scene;
pub use connection::PacketCompletePreparationConnection;

use super::*;
use crucible_engine::node_adapters::cnp::{
    CnpPreparationStorageScratch, CnpSemanticPreparation, PacketCompleteSemanticSource,
};
use crucible_engine::node_contract::RuntimeError;
use crucible_node_format::Id;
use crucible_node_transport::{
    connection::{ConnectionSupervisor, OriginalRetainedSupervisor},
    handshake::OriginalExtensionRegistryOwner,
};

// Each actual caller selects one closed owning phase. Query independently
// counts its selected preparation in Core; initial lifecycle retains the live
// guard/preparation union, and prebirth refuses any such live owner.
#[derive(Clone, Copy)]
enum HolderStoragePhase<'a> {
    HostQuery,
    NativeStartup,
    InitialLifecycle,
    Restoration(&'a crucible_engine::node_admission::OriginalRestorationConstructionScope<'a>),
    RuntimeConstruction(&'a crucible_engine::node_admission::OriginalRuntimeConstructionScope<'a>),
}

pub(super) struct PreparationOwners {
    attempted: bool,
    peers: [PreparationPeer; 3],
    scratch: Option<CnpPreparationStorageScratch>,
}

struct PreparationPeer {
    hello_slot: Option<Rc<RefCell<Option<crucible_node_transport::client::OriginalHelloJournal>>>>,
    connection: Option<PacketCompletePreparationConnection>,
    connection_attempted: bool,
    admit_response: Option<crucible_node_transport::bodies::ResponseBody>,
    operational: Option<Rc<dyn ConnectionSupervisor>>,
    supervisor: Option<OriginalRetainedSupervisor>,
    registry: Option<OriginalExtensionRegistryOwner>,
    preparation: Option<CnpSemanticPreparation>,
    planned_id: Option<Id>,
    host_attempted: bool,
    ticket:
        OnceCell<RefCell<crucible_engine::node_admission::CompleteOriginalFreshRestoreHostWindow>>,
}

impl PreparationOwners {
    pub(super) fn new() -> Self {
        Self {
            attempted: false,
            peers: std::array::from_fn(|_| PreparationPeer {
                hello_slot: None,
                connection: None,
                connection_attempted: false,
                admit_response: None,
                operational: None,
                supervisor: None,
                registry: None,
                preparation: None,
                planned_id: None,
                host_attempted: false,
                ticket: OnceCell::new(),
            }),
            scratch: None,
        }
    }

    // The original scene moved this exact reserved ID into the peer before
    // Child. It remains owned and counted, but no host Query was attempted.
    pub(super) fn authenticate_original_admitted_peer_data(
        &self,
        selected: usize,
    ) -> Result<(), RuntimeError> {
        let peer = self
            .peers
            .get(selected)
            .ok_or(RuntimeError::ForeignAuthority)?;
        if peer.host_attempted
            || peer.ticket.get().is_some()
            || peer.planned_id.is_none()
            || peer.preparation.is_some()
            || peer.connection.is_some()
            || peer.registry.is_some()
            || peer.supervisor.is_some()
            || peer.operational.is_some()
        {
            return Err(RuntimeError::OwnerUnavailable);
        }
        Ok(())
    }

    pub(super) fn original_admitted_peer_counter_scratch_data() -> usize {
        std::mem::size_of::<&Self>()
            + std::mem::size_of::<&PreparationPeer>()
            + std::mem::size_of::<Option<&PreparationPeer>>()
            + std::mem::size_of::<usize>()
            + std::mem::size_of::<Result<(), RuntimeError>>()
    }

    #[cfg(test)]
    pub(super) fn original_initial_query_attempted_for_test(
        &self,
        selected: usize,
    ) -> Result<bool, RuntimeError> {
        self.peers
            .get(selected)
            .map(|peer| peer.host_attempted)
            .ok_or(RuntimeError::ForeignAuthority)
    }

    #[cfg(test)]
    pub(super) fn original_initial_ticket_data(
        &self,
        selected: usize,
    ) -> Result<
        std::cell::Ref<'_, crucible_engine::node_admission::CompleteOriginalFreshRestoreHostWindow>,
        RuntimeError,
    > {
        self.peers
            .get(selected)
            .ok_or(RuntimeError::ForeignAuthority)?
            .ticket
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)
    }

    #[cfg(test)]
    pub(super) fn original_initial_scratch_for_test(
        &self,
    ) -> Option<&CnpPreparationStorageScratch> {
        self.scratch.as_ref()
    }

    // These roots live inline in the actual holder. Only the concrete supervisor
    // backing is charged here; completed preparation/query rows are phase terms.
    pub(super) fn charge_supervisors(
        &self,
        counter: &mut Counter,
    ) -> Result<(), QualificationError> {
        for peer in &self.peers {
            if peer.connection.is_some() || peer.admit_response.is_some() {
                return Err(refused());
            }
            if let Some(slot) = &peer.hello_slot {
                counter.rc(slot)?;
                if slot.try_borrow().map_err(|_| refused())?.is_some() {
                    return Err(refused());
                }
            }
            if let Some(owner) = &peer.supervisor {
                let facts = owner
                    .original_retained_metadata_facts()
                    .map_err(|_| refused())?;
                counter.metadata(&facts)?;
            }
            if peer.preparation.is_some() || peer.ticket.get().is_some() || peer.registry.is_some()
            {
                return Err(refused());
            }
            counter.charge(&peer.planned_id)?;
        }
        Ok(())
    }
}

impl PacketCompleteReportStartupHolder {
    /// Reserves the known retention-only connection supervisors before native birth.
    ///
    /// The installed scenario's actual holder and Source rows plus the three
    /// closed reservation layouts must fit together before construction. Each
    /// actual owner is retained before checking allocator capacity; a failure
    /// never drops a previously retained peer or reopens this one-shot attempt.
    ///
    /// # Errors
    /// Refuses foreign/busy holders, repeated or late preparation, unknown actual
    /// backing, missing finite installed policy or any storage/allocator failure.
    pub fn reserve_original_preparation_supervisors(
        original: &Rc<RefCell<Self>>,
    ) -> Result<(), QualificationError> {
        let held = original.try_borrow().map_err(|_| refused())?;
        held.authenticate_origin()?;
        if held.attempted.get() || held.completed.get() {
            return Err(refused());
        }
        {
            let owners = held.preparations.try_borrow().map_err(|_| refused())?;
            if owners.attempted {
                return Err(refused());
            }
        }
        let policy = held.policy_data()?;
        let (total, fixed, _) = Self::preparation_supervisor_reservation_data(original, &held)?;
        let mut owners = held.preparations.try_borrow_mut().map_err(|_| refused())?;
        if owners.attempted {
            return Err(refused());
        }
        owners.attempted = true;
        owners.scratch = Some(
            CnpPreparationStorageScratch::new(CnpPreparationStorageScratch::requested_bytes())
                .map_err(|_| refused())?,
        );
        for peer in &mut owners.peers {
            peer.hello_slot = Some(Rc::new(RefCell::new(None)));
            let (operational, owner) =
                OriginalRetainedSupervisor::reserve().map_err(|_| refused())?;
            peer.operational = Some(operational);
            peer.supervisor = Some(owner);
        }
        // Register all three original empty Hello slots before any connection
        // callback can start. Partial constructor/binding refusal retains them.
        for (member, peer) in owners.peers.iter().enumerate() {
            held.authority.bind_original_ack_hello_slot(
                member,
                Rc::clone(peer.hello_slot.as_ref().ok_or_else(refused)?),
            )?;
        }
        let mut actual = Counter::new(
            policy
                .maximum_requested_bytes
                .checked_sub(fixed)
                .and_then(|bytes| bytes.checked_sub(total))
                .ok_or_else(refused)?,
        );
        owners.charge_supervisors(&mut actual)?;
        held.authenticate_origin()
    }

    fn preparation_supervisor_reservation_data(
        original: &Rc<RefCell<Self>>,
        held: &Self,
    ) -> Result<(usize, usize, usize), QualificationError> {
        let policy = held.policy_data()?;
        let owner_scratch = OriginalRetainedSupervisor::metadata_counter_scratch_data();
        let fixed = policy
            .declared_observer_scratch_bytes
            .checked_add(owner_scratch)
            .and_then(|bytes| {
                bytes.checked_add(
                    PacketCompleteSemanticSource::retained_requested_storage_precredit_scratch_data(
                    ),
                )
            })
            .and_then(|bytes| bytes.checked_add(CnpPreparationStorageScratch::requested_bytes()))
            .ok_or_else(refused)?;
        let hello_slot = super::super::super::retained::shared_requested_storage(
            std::mem::size_of::<
                RefCell<Option<crucible_node_transport::client::OriginalHelloJournal>>,
            >(),
            std::mem::align_of::<
                RefCell<Option<crucible_node_transport::client::OriginalHelloJournal>>,
            >(),
        )?;
        let reserve = OriginalRetainedSupervisor::reservation_requested_bytes()
            .map_err(|_| refused())?
            .checked_add(hello_slot)
            .and_then(|bytes| bytes.checked_mul(3))
            .ok_or_else(refused)?;
        let available = policy
            .maximum_requested_bytes
            .checked_sub(fixed)
            .and_then(|bytes| bytes.checked_sub(reserve))
            .ok_or_else(refused)?;
        let mut total = Self::storage_data(original, &held, available)?.retained_holder_bytes;
        for source in &held.authority.roster.sources {
            let next = source
                .original_complete_report_startup_retained_storage_precredit_data(
                    available.checked_sub(total).ok_or_else(refused)?,
                )
                .map_err(|_| refused())?;
            total = total
                .checked_add(next)
                .filter(|bytes| *bytes <= available)
                .ok_or_else(refused)?;
        }
        Ok((total, fixed, reserve))
    }

    /// Lends a clone of the exact operational handle paired with the retained owner.
    ///
    /// The actual ClientSession constructor installs this same Rc. The later
    /// preparation observer verifies that installation before counting backing.
    /// This handle creates no query ticket or semantic/currentness permission.
    ///
    /// # Errors
    /// Refuses foreign/busy holders, missing reservation or an invalid member.
    pub fn original_preparation_supervisor(
        original: &Rc<RefCell<Self>>,
        member: usize,
    ) -> Result<Rc<dyn ConnectionSupervisor>, RuntimeError> {
        let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        held.authenticate_origin()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let owners = held
            .preparations
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let peer = owners
            .peers
            .get(member)
            .ok_or(RuntimeError::ForeignAuthority)?;
        peer.operational
            .as_ref()
            .map(Rc::clone)
            .ok_or(RuntimeError::OwnerUnavailable)
    }

    /// Retains the same completed-Admit preparation before any final data guard.
    ///
    /// The descriptor/binding checks precede the move. The same actual Source Rc,
    /// completed-Admit and empty runtime are checked after storage, so a terminal
    /// refusal preserves the original native/controller owners in this holder.
    /// The query issuer will independently repeat those genuine identity gates.
    ///
    /// # Errors
    /// Refuses a foreign/busy holder, changed member, occupied output or absent
    /// incoming preparation. A post-move refusal leaves the holder populated.
    pub fn retain_original_preparation_into(
        original: &Rc<RefCell<Self>>,
        member: usize,
        incoming: &mut Option<CnpSemanticPreparation>,
        planned_id: &mut Option<Id>,
        registry: &mut Option<OriginalExtensionRegistryOwner>,
    ) -> Result<(), RuntimeError> {
        let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        held.authenticate_origin()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let source = held
            .authority
            .roster
            .sources
            .get(member)
            .ok_or(RuntimeError::ForeignAuthority)?;
        let preparation = incoming.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        if preparation.descriptor() != &source.installation().descriptor
            || preparation.binding() != &source.installation().binding
            || preparation.owner_binding() != &source.installation().owner
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        if planned_id.is_none() {
            return Err(RuntimeError::OwnerUnavailable);
        }
        let mut owners = held
            .preparations
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let peer = owners
            .peers
            .get_mut(member)
            .ok_or(RuntimeError::ForeignAuthority)?;
        if peer.preparation.is_some()
            || peer.planned_id.is_some()
            || peer.registry.is_some()
            || peer.ticket.get().is_some()
            || peer.supervisor.is_none()
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        peer.preparation = incoming.take();
        peer.planned_id = planned_id.take();
        peer.registry = registry.take();
        peer.preparation
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .authenticate_original_fresh_query_preparation_data(source)?;
        held.authenticate_origin()
            .map_err(|_| RuntimeError::ForeignAuthority)
    }
}

impl PacketCompleteReportStartupHolder {
    /// Issues the actual Core host window and dispatches through the same preparation.
    ///
    /// The immutable preparation loan ends before the ticket is stored. The
    /// mutable original preparation then lends its existing controller to the
    /// selected into-slot callback; the SDK result stays in its completed-Admit
    /// owner before any final guard. Error and unwind leave all owners retained.
    ///
    /// # Errors
    /// Refuses missing/foreign original owners, repeated dispatch, incomplete
    /// typed storage, absent Core policy/ticket or native/SDK dispatch refusal.
    pub fn call_original_fresh_restore_query(
        original: &Rc<RefCell<Self>>,
        member: usize,
    ) -> Result<(), RuntimeError> {
        let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        held.authenticate_origin()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        {
            let mut owners = held
                .preparations
                .try_borrow_mut()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            let peer = owners
                .peers
                .get_mut(member)
                .ok_or(RuntimeError::ForeignAuthority)?;
            if peer.host_attempted || peer.ticket.get().is_some() {
                return Err(RuntimeError::OutstandingObligations);
            }
            peer.host_attempted = true;
        }
        {
            let owners = held
                .preparations
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            let peer = owners
                .peers
                .get(member)
                .ok_or(RuntimeError::ForeignAuthority)?;
            let preparation = peer
                .preparation
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?;
            let planned_id = peer
                .planned_id
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?;
            let source = held
                .authority
                .roster
                .sources
                .get(member)
                .ok_or(RuntimeError::ForeignAuthority)?;
            let ticket = held.plan.reserve_original_fresh_restore_host_window(
                preparation,
                source,
                planned_id,
                owners
                    .scratch
                    .as_ref()
                    .ok_or(RuntimeError::OwnerUnavailable)?,
                peer.registry.as_ref(),
                peer.supervisor.as_ref(),
            )?;
            // Retain the issued owner before its fallible final count/current
            // recheck. OnceCell permits this while the preparation loan is
            // immutable; a refusal never drops the ticket's original quote.
            peer.ticket
                .set(RefCell::new(ticket))
                .map_err(|_| RuntimeError::OutstandingObligations)?;
            peer.ticket
                .get()
                .ok_or(RuntimeError::OwnerUnavailable)?
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?
                .recheck_original_preparation_data(
                    preparation,
                    source,
                    owners
                        .scratch
                        .as_ref()
                        .ok_or(RuntimeError::OwnerUnavailable)?,
                    peer.registry.as_ref(),
                    peer.supervisor.as_ref(),
                )?;
        }
        let result = {
            let mut owners = held
                .preparations
                .try_borrow_mut()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            let peer = owners
                .peers
                .get_mut(member)
                .ok_or(RuntimeError::ForeignAuthority)?;
            let PreparationPeer {
                preparation,
                planned_id,
                ticket,
                ..
            } = peer;
            let mut ticket = ticket
                .get()
                .ok_or(RuntimeError::OwnerUnavailable)?
                .try_borrow_mut()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            preparation
                .as_mut()
                .ok_or(RuntimeError::OwnerUnavailable)?
                .call_original_fresh_restore_allocation_into(
                    &mut ticket,
                    planned_id.as_ref().ok_or(RuntimeError::OwnerUnavailable)?,
                )
        };
        held.authenticate_origin()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        // The mutable controller/peer loan ended above. Recount the actual
        // retained post-dispatch owners under the same installed policy, with
        // every preparation now included and no replacement of unknown rows.
        let policy = held.host_policy_data()?;
        let remaining = policy
            .maximum_requested_bytes
            .checked_sub(policy.declared_observer_scratch_bytes)
            .ok_or(RuntimeError::ResourceLimit)?;
        let observed = Self::host_holder_storage_data(original, &held, None, remaining);
        if observed.is_err() {
            // This is quarantine of the same original process after a widened
            // owner row, not rollback. Its Query/ticket and all protocol data
            // remain in place while the preowned native supervisor takes custody.
            let mut owners = held
                .preparations
                .try_borrow_mut()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            if let Some(preparation) = owners
                .peers
                .get_mut(member)
                .and_then(|peer| peer.preparation.as_mut())
            {
                preparation.retire_original();
            }
        }
        result?;
        observed?;
        Ok(())
    }
}

impl PacketCompleteReportStartupHolder {
    fn host_scope_member_data(
        &self,
        authority: &InstalledPacketCompleteCollectionAuthority,
        scope: &crucible_engine::node_admission::OriginalFreshRestoreHostScope<'_>,
    ) -> Result<usize, RuntimeError> {
        self.authenticate_origin()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        if !self.completed.get()
            || !std::ptr::eq(self.authority.as_ref(), authority)
            || !scope.is_original_authority(authority)
            || !scope.is_original_plan(&self.plan)
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.graph_owner
            .authenticate_original_report_policy_data(&authority.graph_policy)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let member = authority
            .roster
            .sources
            .iter()
            .position(|source| Rc::ptr_eq(source, scope.source()))
            .ok_or(RuntimeError::ForeignAuthority)?;
        let owners = self
            .preparations
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if owners
            .peers
            .iter()
            .any(|peer| peer.preparation.is_none() || peer.supervisor.is_none())
        {
            return Err(RuntimeError::OwnerUnavailable);
        }
        let peer = &owners.peers[member];
        if !scope.is_original_preparation(
            peer.preparation
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
        ) || !std::ptr::eq(
            peer.planned_id
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
            scope.planned_id(),
        ) || !same_original_option(peer.registry.as_ref(), scope.registry())
            || !same_original_option(peer.supervisor.as_ref(), scope.supervisor())
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(member)
    }

    pub(super) fn host_policy_data(
        &self,
    ) -> Result<crucible_engine::node_admission::OriginalFreshRestoreHostPolicy, RuntimeError> {
        let counter_bytes = std::mem::size_of::<Counter>()
            .checked_mul(6)
            .ok_or(RuntimeError::ResourceLimit)?;
        // Core owns the complete compiled quote for its private Source read
        // guard, Scope/ticket and SDK/Source observers. Reuse that exact getter
        // instead of allowing unrelated daemon scratch to hide a missing term.
        let core = InstalledConformancePlan::original_fresh_restore_host_counter_scratch_data()?;
        let fresh = if matches!(&self.purpose, StartupHolderPurpose::FreshRestoration(_)) {
            super::restoration::FreshLifecycleOwners::counter_scratch_data()?
        } else {
            0
        };
        let declared_observer_scratch_bytes = counter_bytes
            .checked_add(fresh)
            .and_then(|bytes| bytes.checked_add(core))
            .and_then(|bytes| bytes.checked_add(OriginalRetainedSupervisor::metadata_counter_scratch_data()))
            .and_then(|bytes| bytes.checked_add(crucible_node_transport::retained_metadata::RetainedCommonProtocolData::admit_response_counter_scratch_data()))
            .and_then(|bytes| bytes.checked_add(crucible_engine::node_admission::CompleteArchiveCodeGraph::retained_requested_storage_scratch_bytes()))
            .ok_or(RuntimeError::ResourceLimit)?;
        Ok(
            crucible_engine::node_admission::OriginalFreshRestoreHostPolicy {
                maximum_requested_bytes: usize::try_from(self.resources.memory_bytes.get())
                    .map_err(|_| RuntimeError::ResourceLimit)?,
                declared_observer_scratch_bytes,
            },
        )
    }

    fn host_holder_storage_data(
        original: &Rc<RefCell<Self>>,
        held: &Self,
        selected: Option<usize>,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        Self::holder_storage_data(
            original,
            held,
            selected,
            maximum,
            HolderStoragePhase::HostQuery,
        )
    }

    pub(super) fn native_holder_storage_data(
        original: &Rc<RefCell<Self>>,
        held: &Self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        Self::holder_storage_data(
            original,
            held,
            None,
            maximum,
            HolderStoragePhase::NativeStartup,
        )
    }

    /// Counts the actual complete initial-lifecycle holder through its typed live owners.
    ///
    /// # Errors
    /// Refuses foreign, busy, unsupported or incomplete owners or exhausted byte credit.
    pub(super) fn original_initial_holder_storage_data(
        original: &Rc<RefCell<Self>>,
        held: &Self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        Self::holder_storage_data(
            original,
            held,
            None,
            maximum,
            HolderStoragePhase::InitialLifecycle,
        )
    }

    pub(super) fn runtime_construction_holder_storage_data(
        original: &Rc<RefCell<Self>>,
        held: &Self,
        scope: &crucible_engine::node_admission::OriginalRuntimeConstructionScope<'_>,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        if matches!(&held.purpose, StartupHolderPurpose::FreshRestoration(_)) {
            held.authenticate_fresh_runtime_flight_data()?;
        }
        Self::holder_storage_data(
            original,
            held,
            None,
            maximum,
            HolderStoragePhase::RuntimeConstruction(scope),
        )
    }

    /// Observes the genuine inactive restoration holder after its preparation move.
    ///
    /// The capsule proves the actual same runtime/archive/plan/proposal before
    /// selecting this closed phase. Core independently observes that runtime's
    /// real node preparations and Sources. A retained lifecycle ticket remains
    /// counted even though its original preparation has moved into that runtime;
    /// an untransferred registry or unknown partial connection still refuses.
    ///
    /// # Errors
    /// Refuses another holder/capsule/runtime, busy or unsupported owners,
    /// inconsistent moved preparation custody or requested storage excess.
    pub(super) fn original_restoration_holder_descriptor_data(
        &self,
        scope: &crucible_engine::node_admission::OriginalRestorationConstructionScope<'_>,
    ) -> Result<usize, crucible_engine::node_contract::RuntimeError> {
        use crucible_engine::node_contract::RuntimeError;
        self.authenticate_native_origin_data()?;
        let StartupHolderPurpose::FreshRestoration(capsule) = &self.purpose else {
            return Err(RuntimeError::ForeignAuthority);
        };
        let capsule = capsule.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        let inputs = scope.inputs();
        let nested = capsule.retained_restoration_holder_descriptor_for_scope_data(
            inputs.archive,
            inputs.runtime,
            scope.plan(),
            inputs.activation,
            Some(scope),
        )?;
        self.original_host_descriptor_views_data()?
            .checked_add(nested)
            .ok_or(RuntimeError::ResourceLimit)
    }

    pub(super) fn original_restoration_holder_storage_data(
        original: &Rc<RefCell<Self>>,
        held: &Self,
        scope: &crucible_engine::node_admission::OriginalRestorationConstructionScope<'_>,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        let StartupHolderPurpose::FreshRestoration(capsule) = &held.purpose else {
            return Err(RuntimeError::ForeignAuthority);
        };
        capsule
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?
            .authenticate_restoration_storage_scope_data(
                scope.inputs().archive,
                scope.inputs().runtime,
                scope.plan(),
                scope.inputs().activation,
                Some(scope),
            )?;
        Self::holder_storage_data(
            original,
            held,
            None,
            maximum,
            HolderStoragePhase::Restoration(scope),
        )
    }

    fn holder_storage_data(
        original: &Rc<RefCell<Self>>,
        held: &Self,
        selected: Option<usize>,
        maximum: usize,
        phase: HolderStoragePhase<'_>,
    ) -> Result<usize, RuntimeError> {
        let require_complete_preparations = matches!(phase, HolderStoragePhase::HostQuery);
        let initial_sources = matches!(phase, HolderStoragePhase::InitialLifecycle)
            || (matches!(phase, HolderStoragePhase::RuntimeConstruction(_))
                && matches!(&held.purpose, StartupHolderPurpose::OriginalScene));
        let live_original_scene = matches!(
            phase,
            HolderStoragePhase::InitialLifecycle
                | HolderStoragePhase::Restoration(_)
                | HolderStoragePhase::RuntimeConstruction(_)
        );
        held.authenticate_origin()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let mut counter = Counter::new(maximum);
        counter.rc(original).map_err(storage_failure)?;
        counter
            .add(
                held.receiver_group
                    .original_retained_requested_storage_precredit_data(counter.remaining())?,
            )
            .map_err(storage_failure)?;
        if counter.rc(&held.authority).map_err(storage_failure)? {
            counter
                .add(
                    held.authority
                        .original_retained_requested_storage_precredit_data(counter.remaining())?,
                )
                .map_err(storage_failure)?;
        }
        if counter.rc(&held.plan).map_err(storage_failure)? {
            counter
                .add(
                    held.plan
                        .retained_allocation_bytes_excluding_authority_precredit_data()?,
                )
                .map_err(storage_failure)?;
        }
        if let StartupHolderPurpose::FreshRestoration(capsule) = &held.purpose {
            let capsule_data = capsule.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
            let capsule_bytes = match phase {
                HolderStoragePhase::Restoration(scope) => {
                    let inputs = scope.inputs();
                    capsule_data.retained_restoration_holder_storage_for_scope_data(
                        capsule,
                        inputs.archive,
                        inputs.runtime,
                        scope.plan(),
                        inputs.activation,
                        counter.remaining(),
                        Some(scope),
                    )?
                }
                HolderStoragePhase::RuntimeConstruction(scope) => capsule_data
                    .retained_fresh_construction_holder_data(
                        capsule,
                        scope.activation(),
                        counter.remaining(),
                    )?,
                _ => capsule_data
                    .retained_host_holder_precredit_data(capsule, counter.remaining())?,
            };
            counter.add(capsule_bytes).map_err(storage_failure)?;
        }
        held.charge_original_scene_storage_precredit_data(&mut counter)?;
        if live_original_scene {
            held.charge_original_live_launch_storage_precredit_data(&mut counter)?;
        } else {
            held.charge_native_launch_storage_precredit_data(&mut counter)?;
        }
        held.charge_host_sdk_storage_precredit_data(&mut counter)?;
        let owners = held
            .preparations
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if require_complete_preparations && owners.scratch.is_none() {
            return Err(RuntimeError::OwnerUnavailable);
        }
        for (member, peer) in owners.peers.iter().enumerate() {
            // A partial baseline constructor has no complete typed row. It
            // cannot become a zero-cost hole in the subsequent HOST admission.
            if peer.connection.is_some() {
                return Err(RuntimeError::UnsupportedFacet);
            }
            if let Some(slot) = &peer.hello_slot {
                counter.rc(slot).map_err(storage_failure)?;
                let journal = slot.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
                if let Some(journal) = journal.as_ref() {
                    let facts = journal
                        .original_retained_metadata_facts()
                        .map_err(|_| RuntimeError::UnsupportedFacet)?;
                    counter.add(PacketCompleteSemanticSource::complete_retained_metadata_storage_precredit_data(
                        &facts, counter.remaining(),
                    )?).map_err(storage_failure)?;
                }
            }
            if let Some(response) = &peer.admit_response {
                let facts = crucible_node_transport::retained_metadata::RetainedCommonProtocolData::AdmitResponse(response)
                    .observe_retained_metadata().map_err(|_| RuntimeError::UnsupportedFacet)?;
                counter.metadata(&facts).map_err(storage_failure)?;
            }
            // Core independently observes the selected preparation. Other peers
            // remain simultaneous original owners and cannot disappear by label.
            if let Some(preparation) = &peer.preparation {
                let scratch = owners
                    .scratch
                    .as_ref()
                    .ok_or(RuntimeError::OwnerUnavailable)?;
                if Some(member) != selected {
                    // Every completed peer stays in its original initial
                    // phase until this whole lifecycle finishes, including
                    // earlier reactive peers in the third member's census.
                    let report = if initial_sources {
                        preparation.retained_initial_lifecycle_requested_storage_precredit_data(
                            &held.authority.roster.sources[member],
                            scratch,
                            peer.registry.as_ref(),
                            peer.supervisor.as_ref(),
                            counter.remaining(),
                        )?
                    } else {
                        preparation.retained_requested_storage_precredit_data(
                            scratch,
                            peer.registry.as_ref(),
                            peer.supervisor.as_ref(),
                            counter.remaining(),
                        )?
                    };
                    counter
                        .add(report.complete_requested_bytes_precredit_data()?)
                        .map_err(storage_failure)?;
                }
            } else if initial_sources
                && matches!(&held.purpose, StartupHolderPurpose::OriginalScene)
                && (matches!(phase, HolderStoragePhase::RuntimeConstruction(_))
                    || (matches!(phase, HolderStoragePhase::InitialLifecycle)
                        && held.original_collecting_graph_started_data()))
                && !peer.host_attempted
                && peer.ticket.get().is_none()
            {
                owners.authenticate_original_admitted_peer_data(member)?;
                held.authenticate_original_scene_admitted_destination_data(member)?;
            } else if initial_sources && peer.ticket.get().is_some() {
                if peer.registry.is_some()
                    || peer.operational.is_some()
                    || peer.supervisor.is_some()
                {
                    return Err(RuntimeError::OwnerUnavailable);
                }
                // The same ticket remains retained after its preparation and
                // metadata owners move. Follow that actual destination node;
                // an empty source slot or a phase flag cannot establish it.
                let ticket = peer
                    .ticket
                    .get()
                    .ok_or(RuntimeError::OwnerUnavailable)?
                    .try_borrow()
                    .map_err(|_| RuntimeError::OwnerBusy)?;
                held.authenticate_original_scene_preparation_destination_data(member, &ticket)?;
            } else if let HolderStoragePhase::RuntimeConstruction(scope) = phase {
                if peer.registry.is_some()
                    || peer.operational.is_some()
                    || peer.supervisor.is_some()
                {
                    return Err(RuntimeError::OwnerUnavailable);
                }
                if matches!(&held.purpose, StartupHolderPurpose::OriginalScene) {
                    return Err(RuntimeError::OwnerUnavailable);
                }
                held.authenticate_fresh_preparation_destination_data(member, scope.activation())?;
            } else if require_complete_preparations
                || peer.registry.is_some()
                || (peer.ticket.get().is_some()
                    && !matches!(phase, HolderStoragePhase::Restoration(_)))
            {
                // A partial row cannot stand in for a complete preparation.
                return Err(RuntimeError::OwnerUnavailable);
            }
            counter.charge(&peer.planned_id).map_err(storage_failure)?;
            if let Some(ticket) = peer.ticket.get() {
                let ticket = ticket.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
                counter
                    .add(ticket.retained_requested_storage_precredit_data(counter.remaining())?)
                    .map_err(storage_failure)?;
            }
            // The known SDK owner aliases the installed operational supervisor;
            // per-view charging is conservative and explicitly takes no refund.
            match (&peer.supervisor, &peer.operational) {
                (Some(owner), Some(_)) => {
                    let facts = owner
                        .original_retained_metadata_facts()
                        .map_err(|_| RuntimeError::UnsupportedFacet)?;
                    counter.metadata(&facts).map_err(storage_failure)?;
                }
                (None, None) if !require_complete_preparations && peer.preparation.is_none() => {}
                _ => return Err(RuntimeError::OwnerUnavailable),
            }
        }
        held.charge_original_runtime_storage_data(&mut counter)?;
        held.authenticate_origin()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        Ok(counter.bytes())
    }
}

impl InstalledPacketCompleteCollectionAuthority {
    fn original_host_holder_data(
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

    pub(in crate::node_qualification::packet_collection::complete::authority) fn original_fresh_restore_host_policy_data(
        &self,
        scope: &crucible_engine::node_admission::OriginalFreshRestoreHostScope<'_>,
    ) -> Result<crucible_engine::node_admission::OriginalFreshRestoreHostPolicy, RuntimeError> {
        let original = self.original_host_holder_data()?;
        let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        held.host_scope_member_data(self, scope)?;
        held.host_policy_data()
    }

    pub(in crate::node_qualification::packet_collection::complete::authority) fn authenticate_original_fresh_restore_host_data(
        &self,
        scope: &crucible_engine::node_admission::OriginalFreshRestoreHostScope<'_>,
        policy: &crucible_engine::node_admission::OriginalFreshRestoreHostPolicy,
    ) -> Result<crucible_engine::node_admission::OriginalFreshRestoreHostStorage, RuntimeError>
    {
        let original = self.original_host_holder_data()?;
        let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        let member = held.host_scope_member_data(self, scope)?;
        let observed = held.host_policy_data()?;
        if observed.maximum_requested_bytes != policy.maximum_requested_bytes
            || observed.declared_observer_scratch_bytes != policy.declared_observer_scratch_bytes
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let retained_holder_bytes = PacketCompleteReportStartupHolder::host_holder_storage_data(
            &original,
            &held,
            Some(member),
            policy.maximum_requested_bytes,
        )?;
        held.host_scope_member_data(self, scope)?;
        Ok(
            crucible_engine::node_admission::OriginalFreshRestoreHostStorage {
                retained_holder_bytes,
                maximum_simultaneous_transient_bytes: 0,
            },
        )
    }
}

fn same_original_option<T>(left: Option<&T>, right: Option<&T>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => std::ptr::eq(left, right),
        (None, None) => true,
        _ => false,
    }
}

fn storage_failure(_: QualificationError) -> RuntimeError {
    RuntimeError::ResourceLimit
}

impl InstalledPacketCompleteCollectionAuthority {
    pub(in crate::node_qualification::packet_collection::complete::authority) fn authenticate_original_fresh_restore_host_member_data(
        &self,
        scope: &crucible_engine::node_admission::OriginalFreshRestoreHostMemberScope<'_>,
    ) -> Result<(), RuntimeError> {
        let original = self.original_host_holder_data()?;
        let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        held.authenticate_origin()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        if !held.completed.get()
            || !std::ptr::eq(held.authority.as_ref(), self)
            || !scope.is_original_authority(self)
            || !scope.is_original_plan(&held.plan)
            || !self
                .roster
                .sources
                .iter()
                .any(|source| Rc::ptr_eq(source, scope.source()))
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        // The private Core ticket already checks the original ReadOwner and
        // Source/Plan Weak identities. Dispatch holds the preparation RefMut;
        // follow only registered holder identities and revision at this fence.
        held.graph_owner
            .authenticate_original_report_policy_data(&self.graph_policy)
            .map_err(|_| RuntimeError::ForeignAuthority)
    }
}

#[cfg(test)]
mod tests;

impl PacketCompleteReportStartupHolder {
    pub(super) fn charge_original_host_sdk_output_data(
        &self,
        member: usize,
        output: &crucible_engine::node_adapters::cnp::PacketCompleteOriginalHostSdk,
        counter: &mut Counter,
    ) -> Result<(), RuntimeError> {
        let owners = self
            .preparations
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let peer = owners
            .peers
            .get(member)
            .ok_or(RuntimeError::ForeignAuthority)?;
        counter
            .add(output.retained_requested_storage_precredit_data(
                peer.supervisor.as_ref(),
                counter.remaining(),
            )?)
            .map_err(|_| RuntimeError::ResourceLimit)
    }

    pub(super) fn connect_original_host_sdk_peer_data(
        &self,
        member: usize,
        output: &mut crucible_engine::node_adapters::cnp::PacketCompleteOriginalHostSdk,
        guard: &crucible_engine::node_adapters::cnp::CnpSemanticLaunchGuard,
        stream: &mut Option<std::os::unix::net::UnixStream>,
    ) -> Result<(), RuntimeError> {
        let owners = self
            .preparations
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let peer = owners
            .peers
            .get(member)
            .ok_or(RuntimeError::ForeignAuthority)?;
        output.connect_original_into(
            guard,
            stream,
            peer.operational
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
            peer.supervisor
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
        )
    }
}

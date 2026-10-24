//! Drives one trusted complete scene through its original fixed owner banks.
//!
//! Inputs are actual already-owned content, paths and bootstrap endpoints. The
//! complete supervisor issues the three concrete native slots and one runtime
//! reservation. Those same owners enter the registered holder before report or
//! native admission; no proposal, content digest or data count grants effects.

mod initial_lifecycle;
pub(super) use initial_lifecycle::fresh_view_counter_scratch_data;

use super::*;
use crate::node_qualification::packet_collection::{
    PacketPeerJournalSlot, PacketWorldHostSupervisor, PacketWorldOriginalReservations,
};
use crucible_engine::{
    node_adapters::cnp::{CnpSemanticRegistry, InstalledCnpConformanceRole},
    node_contract::{ActivationRecord, RuntimeCustodySlot, RuntimeError, RuntimeLimits},
};
use crucible_node_format::{ContentRef, Id};
use std::collections::BTreeMap;

/// Owns the independently installed scene inputs before original admission.
///
/// Each launch retains both actual bootstrap endpoints and has no process slot:
/// this driver obtains the concrete slot from this same complete supervisor.
/// These inputs confer no native permission. All protocol bodies still pass the
/// installed Source and opaque Core actions before construction or dispatch.
pub struct PacketCompleteOriginalSceneInputs {
    /// Retains the selected complete-world cleanup owner before the first Child.
    pub supervisor: super::PacketCompleteOriginalSceneSupervisor,
    /// Retains a complete initial proposal without claiming Ready or activation.
    pub activation: ActivationRecord,
    /// Bounds the single original runtime reservation, separately from native3.
    pub runtime_limits: RuntimeLimits,
    /// Owns the actual immutable per-peer content banks until the holder takes them.
    pub content: Option<[Rc<BTreeMap<ContentRef, Vec<u8>>>; 3]>,
    /// Owns the original paths and bootstrap endpoints in installed Source order.
    pub launches: [Option<PacketCompleteNativeLaunchInputs>; 3],
    /// Retains the original per-peer query IDs before initial protocol work.
    pub planned_query_ids: [Option<Id>; 3],
    /// Retains the original keyed once-Admit IDs before the lifecycle issuer.
    pub admit_ids: [Id; 3],
    /// Retains the actual independently installed Source registry.
    pub registry: CnpSemanticRegistry,
    /// Retains the three genuine installed roles before any native action.
    pub roles: [Option<InstalledCnpConformanceRole>; 3],
}

pub(super) struct OriginalSceneOwners {
    pub(super) inputs: PacketCompleteOriginalSceneInputs,
    journal_slots: [Option<Box<dyn PacketPeerJournalSlot>>; 3],
    pub(super) runtime_slot: Option<Box<dyn RuntimeCustodySlot>>,
    roles: RefCell<[Option<InstalledCnpConformanceRole>; 3]>,
    reservation_attempted: Cell<bool>,
    pub(super) staged: bool,
    pub(super) launched: Cell<bool>,
    initial_attempted: [Cell<bool>; 3],
    initial_in_flight: [Cell<bool>; 3],
    pub(super) initial_completed: [Cell<bool>; 3],
    windows: [OnceCell<
        RefCell<crucible_engine::node_admission::CompleteOriginalHostInitialLifecycleWindow>,
    >; 3],
}

impl PacketCompleteReportStartupHolder {
    /// Retains and stages a complete scene before report and native admissions.
    ///
    /// The output is this already registered holder. It takes the full incoming
    /// bank before the first reservation callback. Actual slots,
    /// roles and bootstrap endpoints remain in fixed banks across every refusal.
    /// Repeated or foreign calls leave incoming owners untouched. Staging never
    /// constructs a Child, control socket, SDK controller or acceptance token.
    ///
    /// # Errors
    /// Refuses a foreign, late, repeated or non-original holder, incomplete
    /// bootstrap inputs, unknown supervision, changed installed source selection
    /// or unsuccessful concrete reservation. A failed staged attempt is spent.
    pub fn stage_original_scene_into(
        original: &Rc<RefCell<Self>>,
        incoming: &mut Option<PacketCompleteOriginalSceneInputs>,
    ) -> Result<(), RuntimeError> {
        Self::retain_original_scene_data(original, incoming)?;
        Self::reserve_original_scene_data(original)
    }

    fn retain_original_scene_data(
        original: &Rc<RefCell<Self>>,
        incoming: &mut Option<PacketCompleteOriginalSceneInputs>,
    ) -> Result<(), RuntimeError> {
        let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        held.authenticate_native_origin_data()?;
        if !matches!(&held.purpose, StartupHolderPurpose::OriginalScene)
            || held.attempted.get()
            || held.native_attempted.get()
            || held.host_sdk_attempted.get()
            || held.original_scene.get().is_some()
            || held.host_sdk_content.get().is_some()
            || incoming.is_none()
        {
            return Err(RuntimeError::DuplicateOperation);
        }
        let inputs = incoming.take().ok_or(RuntimeError::OwnerUnavailable)?;
        let owner = RefCell::new(OriginalSceneOwners {
            inputs,
            journal_slots: std::array::from_fn(|_| None),
            runtime_slot: None,
            roles: RefCell::new(std::array::from_fn(|_| None)),
            reservation_attempted: Cell::new(false),
            staged: false,
            launched: Cell::new(false),
            initial_attempted: std::array::from_fn(|_| Cell::new(false)),
            initial_in_flight: std::array::from_fn(|_| Cell::new(false)),
            initial_completed: std::array::from_fn(|_| Cell::new(false)),
            windows: std::array::from_fn(|_| OnceCell::new()),
        });
        if let Err(owner) = held.original_scene.set(owner) {
            *incoming = Some(owner.into_inner().inputs);
            return Err(RuntimeError::DuplicateOperation);
        }
        let mut scene = held
            .original_scene
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if scene.inputs.content.is_none()
            || scene.inputs.roles.iter().any(Option::is_none)
            || scene.inputs.activation.owners.len() != 4
            || scene.inputs.runtime_limits.maximum_nodes != 4
            || scene.inputs.runtime_limits.maximum_owners != 4
            || scene.inputs.launches.iter().any(|input| {
                input.as_ref().is_none_or(|input| {
                    input.slot.is_some()
                        || input.bootstrap_reader.is_none()
                        || input.bootstrap_writer.is_none()
                })
            })
        {
            return Err(RuntimeError::OwnerUnavailable);
        }
        {
            let OriginalSceneOwners { inputs, roles, .. } = &mut *scene;
            for (destination, original) in roles.get_mut().iter_mut().zip(&mut inputs.roles) {
                *destination = original.take();
            }
        }
        held.stage_original_scene_query_ids_data(&mut scene.inputs.planned_query_ids)?;
        Ok(())
    }

    fn reserve_original_scene_data(original: &Rc<RefCell<Self>>) -> Result<(), RuntimeError> {
        let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        held.authenticate_native_origin_data()?;
        let scene = held
            .original_scene
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if scene.reservation_attempted.replace(true) || scene.staged {
            return Err(RuntimeError::DuplicateOperation);
        }
        drop(scene);
        // The complete retained bank and exact future slots must fit before
        // their first allocation. No whole callback keeps a mutable scene loan.
        let peak = Self::preflight_original_scene_reservation_data(original, &held)?;
        let mut scene = held
            .original_scene
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let PacketWorldOriginalReservations {
            native,
            journal,
            runtime,
        } = scene
            .inputs
            .supervisor
            .original_data()?
            .reserve_original(&scene.inputs.activation, scene.inputs.runtime_limits)
            .map_err(|_| RuntimeError::OwnerUnavailable)?;
        scene.runtime_slot = Some(runtime);
        for (destination, slot) in scene.journal_slots.iter_mut().zip(journal) {
            *destination = Some(slot);
        }
        for (destination, slot) in scene.inputs.launches.iter_mut().zip(native) {
            destination
                .as_mut()
                .ok_or(RuntimeError::OwnerUnavailable)?
                .slot = Some(slot);
        }
        held.stage_original_native_launch_inputs_data(&mut scene.inputs.launches)?;
        let content = scene
            .inputs
            .content
            .take()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if let Err(content) = held.host_sdk_content.set(content) {
            scene.inputs.content = Some(content);
            return Err(RuntimeError::DuplicateOperation);
        }
        drop(scene);
        if Self::current_original_scene_peak_data(original, &held)? > peak {
            return Err(RuntimeError::ResourceLimit);
        }
        held.original_scene
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?
            .staged = true;
        Ok(())
    }

    /// Runs the original report, native and SDK constructors for a staged scene.
    ///
    /// The real installed actions preserve their separate Source/member scopes.
    /// Native finalization runs once inside the selected launcher, followed by
    /// SDK construction before BootMaterial or Child. This phase leaves initial
    /// socket, Hello and protocol lifecycle to their distinct installed window.
    ///
    /// # Errors
    /// Refuses an unstaged or repeated scene, incomplete owning data, exhausted
    /// installed resources or failure of an original constructor or launch.
    pub fn launch_original_scene(original: &Rc<RefCell<Self>>) -> Result<(), RuntimeError> {
        Self::launch_original_scene_phases(original, false)
    }

    /// Launches each original child beside its admitted initial lifecycle.
    ///
    /// All commands and cleanup reservations precede the first child. Each
    /// child completes Hello and preparation before the next child starts its
    /// original birth cut. Failure retains every spent member and reservation.
    ///
    /// # Errors
    /// Refuses the same original launch and lifecycle failures as the separate
    /// phases, without renewing a deadline or repeating a completed member.
    pub(in crate::node_qualification::packet_collection::complete) fn launch_and_complete_original_scene(
        original: &Rc<RefCell<Self>>,
    ) -> Result<(), RuntimeError> {
        Self::launch_original_scene_phases(original, true)
    }

    fn launch_original_scene_phases(
        original: &Rc<RefCell<Self>>,
        initial_per_member: bool,
    ) -> Result<(), RuntimeError> {
        {
            let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
            held.authenticate_native_origin_data()?;
            if held.original_scene_retired.get()
                || !held
                    .original_scene
                    .get()
                    .ok_or(RuntimeError::OwnerUnavailable)?
                    .try_borrow()
                    .map_err(|_| RuntimeError::OwnerBusy)?
                    .staged
            {
                return Err(RuntimeError::OwnerUnavailable);
            }
        }
        Self::reserve_original_preparation_supervisors(original)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        Self::finalize_original_report_startup(original)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        if initial_per_member {
            Self::launch_original_native_startup_with_initial_lifecycle(original)?;
        } else {
            Self::launch_original_native_startup(original)?;
        }
        let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        held.authenticate_native_origin_data()?;
        held.original_scene
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?
            .launched
            .set(true);
        Ok(())
    }
}

impl PacketCompleteReportStartupHolder {
    /// Counts the actual fixed scene observer and consumer loan headers.
    ///
    /// # Errors
    /// Refuses checked layout arithmetic overflow.
    pub(super) fn original_scene_counter_scratch_data(&self) -> Result<usize, RuntimeError> {
        if matches!(&self.purpose, StartupHolderPurpose::FreshRestoration(_)) {
            return super::restoration::FreshLifecycleOwners::counter_scratch_data();
        }
        if self.original_scene.get().is_none() {
            return Ok(0);
        }
        Self::shared_initial_lifecycle_counter_scratch_data()
    }

    pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) fn shared_initial_lifecycle_counter_scratch_data()
    -> Result<usize, RuntimeError> {
        [
            std::mem::size_of::<Counter>() * 2,
            initial_lifecycle::paired_launch_counter_scratch_data(),
            super::runtime::lifecycle_counter_scratch_data()?,
            super::runtime::fresh_counter_scratch_data()?,
            super::runtime::initial_preparation_counter_scratch_data()?,
            std::mem::size_of::<std::cell::Ref<'_, OriginalSceneOwners>>(),
            std::mem::size_of::<std::cell::RefMut<'_, OriginalSceneOwners>>(),
            std::mem::size_of::<std::cell::Ref<'_, [Option<InstalledCnpConformanceRole>; 3]>>(),
            std::mem::size_of::<std::cell::RefMut<'_, [Option<InstalledCnpConformanceRole>; 3]>>(),
            std::mem::size_of::<std::cell::Ref<'_, crucible_engine::node_admission::CompleteOriginalHostInitialLifecycleWindow>>(),
            std::mem::size_of::<std::cell::RefMut<'_, crucible_engine::node_admission::CompleteOriginalHostInitialLifecycleWindow>>(),
            std::mem::size_of::<std::cell::Ref<'_, [Option<std::os::unix::net::UnixStream>; 3]>>(),
            std::mem::size_of::<std::cell::RefMut<'_, [Option<std::os::unix::net::UnixStream>; 3]>>(),
            // Whole descriptor/retained callbacks keep their running totals and
            // independent subrow values while the nested fixed observers run.
            std::mem::size_of::<[usize; 4]>(),
            crucible_node_transport::client::original_packet_host_descriptor_counter_scratch_data(),
            PacketWorldHostSupervisor::retained_requested_storage_counter_scratch_data()?,
            crucible_engine::node_contract::RuntimeCustodyQueue::retained_requested_storage_counter_scratch_data()?,
            CnpSemanticRegistry::retained_requested_storage_counter_scratch_data(),
            InstalledCnpConformanceRole::retained_requested_storage_counter_scratch_data(),
            crucible_engine::node_adapters::cnp::PacketCompleteSemanticSource::retained_requested_storage_precredit_scratch_data(),
        ].into_iter().try_fold(0usize, |sum, bytes| {
            sum.checked_add(bytes).ok_or(RuntimeError::ResourceLimit)
        })
    }

    /// Charges the same retained scene inputs, supervisor, roles and private windows.
    ///
    /// # Errors
    /// Refuses foreign, busy or unknown original owners or exhausted byte credit.
    pub(super) fn charge_original_scene_storage_precredit_data(
        &self,
        counter: &mut Counter,
    ) -> Result<(), RuntimeError> {
        self.authenticate_native_origin_data()?;
        self.charge_fresh_lifecycle_storage_data(counter)?;
        self.charge_fresh_runtime_storage_data(counter)?;
        if self.installed_host_owner.get().is_some() {
            // The installed actor's actual outer slot remains inline in its
            // catalog. Its input bank has moved here before this first walk;
            // charge the entire fixed wrapper, including its empty Option.
            counter
                .add(std::mem::size_of::<
                    Option<super::super::super::installed::InstalledCompleteScene>,
                >())
                .map_err(|_| RuntimeError::ResourceLimit)?;
        }
        let Some(scene) = self.original_scene.get() else {
            return Ok(());
        };
        let scene = scene.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        let supervisor = if scene.staged || scene.runtime_slot.is_some() {
            scene
                .inputs
                .supervisor
                .original_data()?
                .retained_requested_storage_precredit_data(counter.remaining())?
        } else {
            scene
                .inputs
                .supervisor
                .original_data()?
                .unreserved_requested_storage_precredit_data(counter.remaining())?
        };
        counter
            .add(supervisor)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        counter
            .charge(&scene.inputs.activation)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        counter
            .charge(&scene.inputs.planned_query_ids)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        counter
            .charge(&scene.inputs.admit_ids)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        counter
            .add(
                scene
                    .inputs
                    .registry
                    .retained_requested_storage_precredit_data(counter.remaining())?,
            )
            .map_err(|_| RuntimeError::ResourceLimit)?;
        for (member, role) in scene.inputs.roles.iter().enumerate() {
            if let Some(role) = role {
                counter
                    .add(
                        role.retained_requested_storage_excluding_original_source_precredit_data(
                            &self.authority.roster.sources[member],
                            counter.remaining(),
                        )?,
                    )
                    .map_err(|_| RuntimeError::ResourceLimit)?;
            }
        }
        let roles = scene
            .roles
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        for (member, role) in roles.iter().enumerate() {
            if let Some(role) = role {
                counter
                    .add(
                        role.retained_requested_storage_excluding_original_source_precredit_data(
                            &self.authority.roster.sources[member],
                            counter.remaining(),
                        )?,
                    )
                    .map_err(|_| RuntimeError::ResourceLimit)?;
            }
        }
        for window in &scene.windows {
            if let Some(window) = window.get() {
                counter
                    .add(
                        window
                            .try_borrow()
                            .map_err(|_| RuntimeError::OwnerBusy)?
                            .retained_requested_storage_precredit_data(counter.remaining())?,
                    )
                    .map_err(|_| RuntimeError::ResourceLimit)?;
            }
        }
        if let Some(content) = &scene.inputs.content {
            super::host_startup::charge_content_data(content, counter)?;
        }
        for input in scene.inputs.launches.iter().flatten() {
            Self::charge_original_native_launch_input_storage_data(input, counter)?;
        }
        // Only this driver's concrete supervisor constructor populates these
        // slots. Their Rc mailbox payloads are already in the real supervisor
        // observation; count the actual owning Box headers independently.
        for slot in scene.journal_slots.iter().flatten() {
            counter
                .add(std::mem::size_of_val(slot.as_ref()))
                .map_err(|_| RuntimeError::ResourceLimit)?;
        }
        if let Some(slot) = &scene.runtime_slot {
            counter
                .add(std::mem::size_of_val(slot.as_ref()))
                .map_err(|_| RuntimeError::ResourceLimit)?;
            counter
                .add(
                    slot.retained_requested_storage_data(counter.remaining())?
                        .ok_or(RuntimeError::UnsupportedFacet)?,
                )
                .map_err(|_| RuntimeError::ResourceLimit)?;
        }
        Ok(())
    }

    fn preflight_original_scene_reservation_data(
        original: &Rc<RefCell<Self>>,
        held: &Self,
    ) -> Result<usize, RuntimeError> {
        let policy = held
            .policy_data()
            .map_err(|_| RuntimeError::ResourceLimit)?;
        let future = {
            let scene = held
                .original_scene
                .get()
                .ok_or(RuntimeError::OwnerUnavailable)?
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            scene
                .inputs
                .supervisor
                .original_data()?
                .quote_original_scene_reservation_requested_storage_data(
                    &scene.inputs.activation,
                    policy.maximum_requested_bytes,
                )?
        };
        let available = policy
            .maximum_requested_bytes
            .checked_sub(policy.declared_observer_scratch_bytes)
            .and_then(|bytes| bytes.checked_sub(future))
            .ok_or(RuntimeError::ResourceLimit)?;
        let mut total = Self::native_holder_storage_data(original, held, available)?;
        for source in &held.authority.roster.sources {
            let bytes = source.original_complete_report_startup_retained_storage_precredit_data(
                available
                    .checked_sub(total)
                    .ok_or(RuntimeError::ResourceLimit)?,
            )?;
            total = total
                .checked_add(bytes)
                .filter(|bytes| *bytes <= available)
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        total
            .checked_add(future)
            .and_then(|bytes| bytes.checked_add(policy.declared_observer_scratch_bytes))
            .filter(|bytes| *bytes <= policy.maximum_requested_bytes)
            .ok_or(RuntimeError::ResourceLimit)
    }
}

impl PacketCompleteReportStartupHolder {
    /// Retires actual scene guards into their original complete supervisor.
    ///
    /// This is containment, with no reclamation or effect rollback claim. The
    /// fixed scene, SDK, preparation and response banks remain owned. Its
    /// unused native and runtime reservations are released only after both
    /// guard inventories transfer their same original custody. The scene
    /// stays permanently retired and cannot renew any initial window.
    ///
    /// # Errors
    /// Refuses foreign creator or busy original loans. A partial retirement
    /// remains sticky, and all untransferred owners stay in their fixed slots.
    ///
    /// # Panics
    /// The installed original process slots must retain custody without
    /// unwinding, as required by the same guard's ordinary Drop contract.
    pub fn retire_original_scene(original: &Rc<RefCell<Self>>) -> Result<(), RuntimeError> {
        let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        // Retirement remains callable after its own sticky revocation and after
        // graph/source failure; it checks the actual creator, not live evidence.
        if held.process != std::process::id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if held.thread != std::thread::current().id() {
            return Err(RuntimeError::ThreadAffinity);
        }
        let scene = held
            .original_scene
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        held.original_scene_retired.set(true);
        held.retire_original_runtime_owners()?;
        held.retire_original_scene_native_guards()?;
        held.retire_original_scene_preparations()?;
        let mut scene = scene
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        // Inputs still here never entered the native launch bank. Any slots
        // were issued only by this scene's concrete supervisor and remain unused.
        for inputs in scene.inputs.launches.iter_mut().flatten() {
            drop(inputs.slot.take());
        }
        drop(scene.runtime_slot.take());
        Ok(())
    }

    /// Drives cleanup of the same retired original complete scene.
    ///
    /// Source or graph revocation cannot disable containment of actual retained
    /// native custody. This checks creator identity and uses the same bounded
    /// original notifier; it neither extracts owners nor replaces reservations.
    /// Pending or a failure keeps all original SDK and evidence banks owned.
    ///
    /// # Errors
    /// Refuses foreign or busy holders, a scene not yet retired, invalid bounded
    /// pass count or the same selected notifier's sticky transport failure.
    pub fn drive_original_scene_reclamation(
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
        let scene = held
            .original_scene
            .get()
            .ok_or_else(refused)?
            .try_borrow()
            .map_err(|_| refused())?;
        if !held.original_scene_retired.get() {
            return Err(refused());
        }
        scene
            .inputs
            .supervisor
            .original_data()
            .map_err(|_| refused())?
            .drive_complete_original_reclamation(maximum_passes)
    }
}

impl PacketCompleteReportStartupHolder {
    pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) fn current_original_scene_peak_data(
        original: &Rc<RefCell<Self>>,
        held: &Self,
    ) -> Result<usize, RuntimeError> {
        let policy = held
            .policy_data()
            .map_err(|_| RuntimeError::ResourceLimit)?;
        let available = policy
            .maximum_requested_bytes
            .checked_sub(policy.declared_observer_scratch_bytes)
            .ok_or(RuntimeError::ResourceLimit)?;
        let mut total = Self::native_holder_storage_data(original, held, available)?;
        for source in &held.authority.roster.sources {
            total = total
                .checked_add(
                    source.original_complete_report_startup_retained_storage_precredit_data(
                        available
                            .checked_sub(total)
                            .ok_or(RuntimeError::ResourceLimit)?,
                    )?,
                )
                .filter(|bytes| *bytes <= available)
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        total
            .checked_add(policy.declared_observer_scratch_bytes)
            .ok_or(RuntimeError::ResourceLimit)
    }
}

#[cfg(test)]
mod tests;

//! Drives the fresh suffix target through its own retained baseline protocol.
//!
//! The real Core initial-lifecycle action governs socket, Hello, Discover,
//! Realize and once-Admit. Fresh allocation Query uses the separate HOST action.
//! No original actor, launch guard, SDK controller or permission is extracted.

use super::super::PacketCompleteOriginalSceneSupervisor;
use super::*;
use crate::node_qualification::packet_collection::{
    PacketPeerJournalSlot, PacketWorldOriginalReservations,
};
use crucible_engine::node_adapters::cnp::{CnpSemanticRegistry, InstalledCnpConformanceRole};
use crucible_engine::node_admission::CompleteOriginalHostInitialLifecycleWindow;
use crucible_engine::node_contract::{ActivationRecord, RuntimeCustodySlot, RuntimeLimits};
use std::mem::{size_of, size_of_val};

/// Owns the actual fresh target's supervisor and baseline lifecycle inputs.
///
/// The driver reserves all process, journal and runtime slots from this same
/// supervisor. Caller-supplied native slots are rejected, so a foreign census
/// cannot stand in for the cleanup owner of the launched children.
pub struct PacketCompleteFreshRestorationInputs {
    /// Retains the concrete cleanup owner before it reserves any slot.
    pub supervisor: PacketCompleteOriginalSceneSupervisor,
    /// Retains the actual four-owner proposal for the fresh target runtime.
    pub activation: ActivationRecord,
    /// Bounds this same target's runtime reservation independently of permission.
    pub runtime_limits: RuntimeLimits,
    /// Retains bootstrap endpoints and measured paths; every slot must be None.
    pub launches: [Option<PacketCompleteNativeLaunchInputs>; 3],
    /// Retains the actual independently installed source registry.
    pub registry: Option<CnpSemanticRegistry>,
    /// Retains each genuine registered role until its guarded preparation.
    pub roles: [Option<InstalledCnpConformanceRole>; 3],
    /// Retains the planned independent fresh allocation Query identifiers.
    pub query_ids: [Option<Id>; 3],
    /// Retains the planned keyed once-Admit identifiers.
    pub admit_ids: Option<[Id; 3]>,
}

pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) struct FreshLifecycleOwners
{
    pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) inputs:
        Option<PacketCompleteFreshRestorationInputs>,
    pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) runtime_slot:
        Option<Box<dyn RuntimeCustodySlot>>,
    journal_slots: [Option<Box<dyn PacketPeerJournalSlot>>; 3],
    reservation_attempted: bool,
    pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) registry:
        Option<CnpSemanticRegistry>,
    pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) roles:
        RefCell<[Option<InstalledCnpConformanceRole>; 3]>,
    pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) admit_ids:
        Option<[Id; 3]>,
    pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) staged:
        bool,
    pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) launched:
        Cell<bool>,
    pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) initial_attempted:
        [Cell<bool>; 3],
    pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) initial_in_flight:
        [Cell<bool>; 3],
    pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) initial_completed:
        [Cell<bool>; 3],
    pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) host_completed:
        [Cell<bool>; 3],
    pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) windows:
        [OnceCell<RefCell<CompleteOriginalHostInitialLifecycleWindow>>; 3],
}

impl FreshLifecycleOwners {
    pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) fn supervisor_descriptor_data(
        &self,
    ) -> Result<usize, RuntimeError> {
        self.inputs
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .supervisor
            .original_data()?
            .retained_descriptor_count_data()
    }

    fn empty() -> Self {
        Self {
            inputs: None,
            runtime_slot: None,
            journal_slots: std::array::from_fn(|_| None),
            reservation_attempted: false,
            registry: None,
            roles: RefCell::new(std::array::from_fn(|_| None)),
            admit_ids: None,
            staged: false,
            launched: Cell::new(false),
            initial_attempted: std::array::from_fn(|_| Cell::new(false)),
            initial_in_flight: std::array::from_fn(|_| Cell::new(false)),
            initial_completed: std::array::from_fn(|_| Cell::new(false)),
            windows: std::array::from_fn(|_| OnceCell::new()),
            host_completed: std::array::from_fn(|_| Cell::new(false)),
        }
    }

    pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) fn counter_scratch_data()
    -> Result<usize, RuntimeError> {
        let terms = [
            PacketCompleteReportStartupHolder::shared_initial_lifecycle_counter_scratch_data()?,
            super::super::scene::fresh_view_counter_scratch_data(),
            InstalledConformancePlan::original_host_initial_lifecycle_counter_scratch_data()?,
            crucible_engine::node_adapters::cnp::CnpSemanticLaunchGuard::original_initial_lifecycle_storage_counter_scratch_data(),
            CnpSemanticRegistry::retained_requested_storage_counter_scratch_data(),
            InstalledCnpConformanceRole::retained_requested_storage_counter_scratch_data(),
            size_of::<PacketCompleteFreshRestorationInputs>(),
            size_of::<Option<PacketCompleteFreshRestorationInputs>>(),
            size_of::<&mut Option<PacketCompleteFreshRestorationInputs>>(),
            size_of::<PacketWorldOriginalReservations>(),
            size_of::<&PacketCompleteFreshRestorationInputs>(),
            size_of::<&mut PacketCompleteFreshRestorationInputs>(),
            size_of::<Option<&PacketCompleteFreshRestorationInputs>>(),
            size_of::<Option<&mut PacketCompleteFreshRestorationInputs>>(),
            size_of::<Result<&PacketCompleteFreshRestorationInputs, RuntimeError>>(),
            size_of::<Result<&mut PacketCompleteFreshRestorationInputs, RuntimeError>>(),
            size_of::<Result<PacketWorldOriginalReservations, QualificationError>>(),
            size_of::<Option<Box<dyn RuntimeCustodySlot>>>(),
            size_of::<[Option<Box<dyn PacketPeerJournalSlot>>; 3]>(),
            size_of::<Self>(), size_of::<RefCell<Self>>(),
            size_of::<std::cell::Ref<'static, Self>>(),
            size_of::<std::cell::RefMut<'static, Self>>(),
            size_of::<Result<std::cell::Ref<'static, Self>, std::cell::BorrowError>>(),
            size_of::<Result<std::cell::RefMut<'static, Self>, std::cell::BorrowMutError>>(),
            size_of::<Option<CnpSemanticRegistry>>(),
            size_of::<[Option<InstalledCnpConformanceRole>; 3]>(),
            size_of::<&mut [Option<PacketCompleteNativeLaunchInputs>; 3]>(),
            size_of::<&mut Option<CnpSemanticRegistry>>(),
            size_of::<&mut [Option<InstalledCnpConformanceRole>; 3]>(),
            size_of::<&mut [Option<Id>; 3]>(), size_of::<&mut Option<[Id; 3]>>(),
            size_of::<Option<[Id; 3]>>(), size_of::<&[Id; 3]>(),
            size_of::<Result<&[Id; 3], RuntimeError>>(),
            size_of::<CompleteOriginalHostInitialLifecycleWindow>(),
            size_of::<std::cell::Ref<'static, CompleteOriginalHostInitialLifecycleWindow>>(),
            size_of::<std::cell::RefMut<'static, CompleteOriginalHostInitialLifecycleWindow>>(),
            size_of::<[Cell<bool>; 3]>(), size_of::<Result<bool, RuntimeError>>(),
            size_of::<Result<(), RuntimeError>>(), size_of::<Result<usize, RuntimeError>>(),
            size_of::<std::slice::Iter<'static, usize>>(),
            size_of::<std::slice::Iter<'static, Cell<bool>>>(),
            size_of::<Counter>(),
        ];
        terms.iter().try_fold(size_of_val(&terms), |total, bytes| {
            total.checked_add(*bytes).ok_or(RuntimeError::ResourceLimit)
        })
    }
}

impl PacketCompleteReportStartupHolder {
    /// Starts the fresh target under its same retained cleanup supervisor.
    ///
    /// The holder takes the complete input before fallible admission, quotes
    /// its actual supervisor and independently reserves Native3, journal3 and
    /// the runtime slot from that owner. All incoming native slots must be empty.
    /// No supplied descriptor count or unrelated supervisor can cover children.
    ///
    /// The same real Core baseline actions govern socket, Hello, Discover,
    /// Realize and once-Admit; only then run the separate fresh HOST queries.
    /// This creates no OriginalScene, actor, controller extractor or readiness.
    ///
    /// # Errors
    /// Refuses a foreign/nonfresh/repeated holder, incomplete or prepopulated
    /// inputs, unsupported reservation, resource excess or native/SDK failure.
    /// Surviving originals, cleanup ownership and partial slots stay retained.
    pub fn start_original_fresh_restoration_into(
        original: &Rc<RefCell<Self>>,
        incoming: &mut Option<PacketCompleteFreshRestorationInputs>,
    ) -> Result<(), RuntimeError> {
        {
            let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
            held.authenticate_native_origin_data()?;
            if !matches!(&held.purpose, StartupHolderPurpose::FreshRestoration(_))
                || !held.restored_suffix_startup_selected_data()?
                || held.fresh_lifecycle.get().is_some()
                || held.original_scene.get().is_some()
                || held.attempted.get()
                || held.native_attempted.get()
                || held.host_sdk_attempted.get()
                || held.host_sdk_content.get().is_none()
                || incoming.is_none()
            {
                return Err(RuntimeError::OutstandingObligations);
            }
            held.fresh_lifecycle
                .set(RefCell::new(FreshLifecycleOwners::empty()))
                .map_err(|_| RuntimeError::DuplicateOperation)?;
            {
                let mut fresh = held
                    .fresh_lifecycle
                    .get()
                    .ok_or(RuntimeError::OwnerUnavailable)?
                    .try_borrow_mut()
                    .map_err(|_| RuntimeError::OwnerBusy)?;
                fresh.inputs = incoming.take();
                let inputs = fresh
                    .inputs
                    .as_mut()
                    .ok_or(RuntimeError::OwnerUnavailable)?;
                if inputs
                    .launches
                    .iter()
                    .any(|one| one.as_ref().is_none_or(|one| one.slot.is_some()))
                    || inputs.roles.iter().any(Option::is_none)
                    || inputs.registry.is_none()
                    || inputs.query_ids.iter().any(Option::is_none)
                    || inputs.admit_ids.is_none()
                    || inputs.activation.owners.len() != 4
                    || &inputs.activation.world_binding_hash != held.authority.host_source().world()
                    || inputs.runtime_limits.maximum_nodes != 4
                    || inputs.runtime_limits.maximum_owners != 4
                    || inputs.runtime_limits.maximum_operations == 0
                    || inputs.runtime_limits.maximum_operations
                        > usize::try_from(held.resources.maximum_operations.get())
                            .map_err(|_| RuntimeError::ResourceLimit)?
                {
                    return Err(RuntimeError::ForeignAuthority);
                }
                held.stage_original_fresh_query_ids_data(&mut inputs.query_ids)?;
            }
            let policy = held
                .policy_data()
                .map_err(|_| RuntimeError::ResourceLimit)?;
            let future = {
                let fresh = held
                    .fresh_lifecycle
                    .get()
                    .ok_or(RuntimeError::OwnerUnavailable)?
                    .try_borrow()
                    .map_err(|_| RuntimeError::OwnerBusy)?;
                let inputs = fresh
                    .inputs
                    .as_ref()
                    .ok_or(RuntimeError::OwnerUnavailable)?;
                inputs
                    .supervisor
                    .original_data()?
                    .quote_original_scene_reservation_requested_storage_data(
                        &inputs.activation,
                        policy.maximum_requested_bytes,
                    )?
            };
            // Preserve the defining whole-holder + all three actual Source rows
            // before reserving any slot, exactly as the original scene preflight.
            let admitted = Self::current_original_scene_peak_data(original, &held)?
                .checked_add(future)
                .filter(|peak| *peak <= policy.maximum_requested_bytes)
                .ok_or(RuntimeError::ResourceLimit)?;
            {
                let mut fresh = held
                    .fresh_lifecycle
                    .get()
                    .ok_or(RuntimeError::OwnerUnavailable)?
                    .try_borrow_mut()
                    .map_err(|_| RuntimeError::OwnerBusy)?;
                fresh.reservation_attempted = true;
                let inputs = fresh
                    .inputs
                    .as_ref()
                    .ok_or(RuntimeError::OwnerUnavailable)?;
                let PacketWorldOriginalReservations {
                    native,
                    journal,
                    runtime,
                } = inputs
                    .supervisor
                    .original_data()?
                    .reserve_original(&inputs.activation, inputs.runtime_limits)
                    .map_err(|_| RuntimeError::OwnerUnavailable)?;
                fresh.runtime_slot = Some(runtime);
                for (destination, slot) in fresh.journal_slots.iter_mut().zip(journal) {
                    *destination = Some(slot);
                }
                let FreshLifecycleOwners {
                    inputs,
                    registry,
                    roles,
                    admit_ids,
                    ..
                } = &mut *fresh;
                let inputs = inputs.as_mut().ok_or(RuntimeError::OwnerUnavailable)?;
                for (destination, slot) in inputs.launches.iter_mut().zip(native) {
                    destination
                        .as_mut()
                        .ok_or(RuntimeError::OwnerUnavailable)?
                        .slot = Some(slot);
                }
                held.stage_original_native_launch_inputs_data(&mut inputs.launches)?;
                *registry = inputs.registry.take();
                *admit_ids = inputs.admit_ids.take();
                *roles.get_mut() = std::array::from_fn(|index| inputs.roles[index].take());
            }
            if Self::current_original_scene_peak_data(original, &held)? > admitted {
                return Err(RuntimeError::ResourceLimit);
            }
            held.fresh_lifecycle
                .get()
                .ok_or(RuntimeError::OwnerUnavailable)?
                .try_borrow_mut()
                .map_err(|_| RuntimeError::OwnerBusy)?
                .staged = true;
        }
        Self::finalize_original_report_startup(original)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        Self::launch_original_native_startup_with_initial_lifecycle(original)?;
        {
            let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
            held.fresh_lifecycle
                .get()
                .ok_or(RuntimeError::OwnerUnavailable)?
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?
                .launched
                .set(true);
        }
        for selected in 0..3 {
            Self::call_original_fresh_restore_query(original, selected)?;
            // This marks the actual HOST continuation only after its full
            // response and owning post-census succeeded; baseline Admit alone
            // cannot qualify the later node preparation move.
            original
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?
                .fresh_lifecycle
                .get()
                .ok_or(RuntimeError::OwnerUnavailable)?
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?
                .host_completed[selected]
                .set(true);
        }
        Ok(())
    }

    pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) fn charge_fresh_lifecycle_storage_data(
        &self,
        counter: &mut Counter,
    ) -> Result<(), RuntimeError> {
        let Some(owner) = self.fresh_lifecycle.get() else {
            return Ok(());
        };
        if !matches!(&self.purpose, StartupHolderPurpose::FreshRestoration(_))
            || self.original_scene.get().is_some()
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let owner = owner.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        if let Some(inputs) = &owner.inputs {
            let supervisor = inputs.supervisor.original_data()?;
            let requested = if owner.reservation_attempted {
                supervisor.retained_requested_storage_precredit_data(counter.remaining())?
            } else {
                supervisor.unreserved_requested_storage_precredit_data(counter.remaining())?
            };
            counter
                .add(requested)
                .map_err(|_| RuntimeError::ResourceLimit)?;
            counter
                .charge(&inputs.activation)
                .map_err(|_| RuntimeError::ResourceLimit)?;
            counter
                .charge(&inputs.query_ids)
                .map_err(|_| RuntimeError::ResourceLimit)?;
            counter
                .charge(&inputs.admit_ids)
                .map_err(|_| RuntimeError::ResourceLimit)?;
            if let Some(registry) = &inputs.registry {
                counter
                    .add(registry.retained_requested_storage_precredit_data(counter.remaining())?)
                    .map_err(|_| RuntimeError::ResourceLimit)?;
            }
            for (index, role) in inputs.roles.iter().enumerate() {
                if let Some(role) = role {
                    counter.add(role.retained_requested_storage_excluding_original_source_precredit_data(&self.authority.roster.sources[index], counter.remaining())?).map_err(|_| RuntimeError::ResourceLimit)?;
                }
            }
            for input in inputs.launches.iter().flatten() {
                Self::charge_original_native_launch_input_storage_data(input, counter)?;
            }
        }
        for slot in owner.journal_slots.iter().flatten() {
            counter
                .add(size_of_val(slot.as_ref()))
                .map_err(|_| RuntimeError::ResourceLimit)?;
        }
        if let Some(slot) = &owner.runtime_slot {
            counter
                .add(size_of_val(slot.as_ref()))
                .map_err(|_| RuntimeError::ResourceLimit)?;
            counter
                .add(
                    slot.retained_requested_storage_data(counter.remaining())?
                        .ok_or(RuntimeError::UnsupportedFacet)?,
                )
                .map_err(|_| RuntimeError::ResourceLimit)?;
        }
        counter
            .charge(&owner.admit_ids)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        if let Some(registry) = &owner.registry {
            counter
                .add(registry.retained_requested_storage_precredit_data(counter.remaining())?)
                .map_err(|_| RuntimeError::ResourceLimit)?;
        }
        let roles = owner
            .roles
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        for (index, role) in roles.iter().enumerate() {
            if let Some(role) = role {
                counter
                    .add(
                        role.retained_requested_storage_excluding_original_source_precredit_data(
                            &self.authority.roster.sources[index],
                            counter.remaining(),
                        )?,
                    )
                    .map_err(|_| RuntimeError::ResourceLimit)?;
            }
        }
        for window in &owner.windows {
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
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn original_holder_cannot_be_relabelled_as_a_fresh_suffix_driver() {
        let (_scene, original) =
            crate::node_qualification::packet_collection::complete::tests::report_startup_fixture();
        let before = original
            .borrow()
            .authority
            .roster
            .sources
            .each_ref()
            .map(|source| source.original_report_startup_audit_data().unwrap());
        let mut incoming = None;
        assert!(matches!(
            PacketCompleteReportStartupHolder::start_original_fresh_restoration_into(
                &original,
                &mut incoming
            ),
            Err(RuntimeError::OutstandingObligations)
        ));
        assert!(incoming.is_none());
        let held = original.borrow();
        assert!(held.fresh_lifecycle.get().is_none());
        assert!(!held.attempted.get());
        assert!(!held.native_attempted.get());
        assert_eq!(
            held.authority
                .roster
                .sources
                .each_ref()
                .map(|source| source.original_report_startup_audit_data().unwrap()),
            before
        );
    }

    #[test]
    fn same_cleanup_owner_keeps_wake_descriptors_outside_untouched_native_slots() {
        use crate::node_qualification::packet_collection::PacketWorldHostSupervisor;
        use crucible_engine::node_contract::SavedRuntimeActivation;
        let (_scene, original) =
            crate::node_qualification::packet_collection::complete::tests::report_startup_fixture();
        let saved: SavedRuntimeActivation = serde_json::from_value(
            original.borrow().authority.roster.coordinator.template["activation"].clone(),
        )
        .unwrap();
        let activation = ActivationRecord {
            generation: saved.generation,
            activation_id: saved.activation_id,
            world_binding_hash: saved.world_binding_hash,
            owners: saved.owners,
            boundary: saved.boundary,
        };
        let limits = RuntimeLimits {
            maximum_nodes: 4,
            maximum_owners: 4,
            maximum_operations: 64,
            maximum_retained_outputs: 64,
        };
        let supervisor = PacketWorldHostSupervisor::new_complete_original().unwrap();
        let reserved = supervisor.reserve_original(&activation, limits).unwrap();
        let slots = reserved
            .native
            .iter()
            .map(|slot| {
                slot.retained_descriptor_views_precredit_data()
                    .unwrap()
                    .unwrap()
            })
            .sum::<usize>();
        assert_eq!(slots, 0);
        let mut owners = FreshLifecycleOwners::empty();
        owners.inputs = Some(PacketCompleteFreshRestorationInputs {
            supervisor: supervisor.into(),
            activation,
            runtime_limits: limits,
            launches: std::array::from_fn(|_| None),
            registry: None,
            roles: std::array::from_fn(|_| None),
            query_ids: std::array::from_fn(|_| None),
            admit_ids: None,
        });
        // These are the genuine eventfd plus duplicated bounded reader owned by
        // the SAME supervisor. Slot-only metadata cannot replace this observer.
        assert_eq!(owners.supervisor_descriptor_data().unwrap(), 2);
        assert!(owners.supervisor_descriptor_data().unwrap() > slots);
        drop(reserved);
    }
}

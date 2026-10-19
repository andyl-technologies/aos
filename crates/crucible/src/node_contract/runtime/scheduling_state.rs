//! Retains one original scheduler allocation through lazy setup and containment.
//!
//! The runtime alone mutates the queue. A host source retains a read-only view of
//! the same allocation; copying that view cannot extend live dispatch permission.
//! Original process/thread/world/authority checks precede every RefCell borrow.

use std::{
    cell::{Cell, Ref, RefCell, RefMut},
    rc::{Rc, Weak},
    thread::{self, ThreadId},
};

use crucible_node_contract::{ContentRef, HashRef, Position, U64};

use crate::node_scheduling::{CausalScheduler, SchedulingSnapshot};

use super::super::RuntimeError;

struct Original {
    process: u32,
    thread: ThreadId,
    world: HashRef,
    authority: Weak<()>,
    live: Cell<bool>,
    scheduler: RefCell<Option<CausalScheduler>>,
    restored: RefCell<Option<OriginalLineageSchedulingIdentity>>,
    coordinator17: RefCell<Option<super::coordinator_commitment::CoordinatorCommitments17>>,
}

/// Records the core-checked source installed into this same original allocation.
///
/// Equal public snapshots cannot mint this private marker. The owning runtime
/// writes it atomically with the prepared scheduler before native installation.
#[derive(PartialEq)]
struct OriginalLineageSchedulingIdentity {
    source: ContentRef,
    scheduling: HashRef,
    target: super::super::ActivationRecord,
}

/// Retains the runtime's original scheduler storage, including its uninitialized cut.
pub(in super::super) struct OriginalSchedulingState(Rc<Original>);

/// Keeps a read-only weak view for terminal checks during a mutable node loan.
///
/// This private identity grants no restoration, scheduler setup or dispatch.
/// Only the same runtime can create it; the live bit and actual authority are
/// checked again after every installed member callback.
pub(in crate::node_contract) struct OriginalRestorationSchedulingFence(Weak<Original>);

impl OriginalRestorationSchedulingFence {
    pub(in crate::node_contract) fn authenticate_current(
        &self,
        authority: &Rc<()>,
        world: &HashRef,
    ) -> Result<(), RuntimeError> {
        let original = self.0.upgrade().ok_or(RuntimeError::ForeignAuthority)?;
        OriginalSchedulingState(original).authenticate(authority, world)
    }

    pub(in crate::node_contract) fn authenticate_coordinator17_boundary_data(
        &self,
        authority: &Rc<()>,
        world: &HashRef,
        boundary: &crate::node_contract::OriginalRestoredCoordinatorBoundary17,
        host_node: &crucible_node_contract::Id,
        host_owner: &crucible_node_contract::Id,
    ) -> Result<(), RuntimeError> {
        let original = self.0.upgrade().ok_or(RuntimeError::ForeignAuthority)?;
        let state = OriginalSchedulingState(original);
        state.authenticate(authority, world)?;
        let log = state
            .0
            .coordinator17
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        log.as_ref()
            .ok_or(RuntimeError::UnsupportedFacet)?
            .authenticate_boundary_data(boundary)?;
        state
            .retained()?
            .authenticate_coordinator17_capture_boundary_data(
                boundary.cut_data(),
                host_node,
                host_owner,
            )?;
        state.authenticate(authority, world)
    }

    pub(in crate::node_contract) fn retained_backing_storage_data(
        &self,
    ) -> Result<usize, RuntimeError> {
        let original = self.0.upgrade().ok_or(RuntimeError::ForeignAuthority)?;
        OriginalSchedulingState(original).current()?;
        Ok(super::super::NodeRuntime::capture_shared_allocation_storage::<Original>())
    }

    pub(in crate::node_contract) fn counter_scratch_data() -> usize {
        std::mem::size_of::<Rc<Original>>()
            + std::mem::size_of::<OriginalSchedulingState>()
            + 2 * std::mem::size_of::<Rc<()>>()
            + std::mem::size_of::<&HashRef>()
            + std::mem::size_of::<Result<(), RuntimeError>>()
    }
}

impl OriginalSchedulingState {
    pub(in crate::node_contract) fn restoration_member_fence_data(
        &self,
        authority: &Rc<()>,
        world: &HashRef,
    ) -> Result<OriginalRestorationSchedulingFence, RuntimeError> {
        self.authenticate(authority, world)?;
        Ok(OriginalRestorationSchedulingFence(Rc::downgrade(&self.0)))
    }

    /// Names the real scheduler constructor's fixed owned-value and Rc views.
    pub(super) fn construction_counter_scratch_data() -> usize {
        std::mem::size_of::<Original>()
            + std::mem::size_of::<HashRef>()
            + std::mem::size_of::<Rc<Original>>()
            + std::mem::size_of::<Rc<()>>()
    }

    /// Counts this real uninitialized scheduler allocation and cloned world key.
    ///
    /// The caller separately includes its inline Rc handle and fixed counter
    /// views. This DATA quote constructs no Rc or weak authority alias.
    ///
    /// # Errors
    /// Refuses unsupported owned data, arithmetic overflow or the bound.
    pub(super) fn construction_storage_data(
        world: &HashRef,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        use super::RuntimeOwnedStorage;
        let header = super::NodeRuntime::capture_protocol_shared_header_storage(
            1,
            std::mem::align_of::<Original>(),
            maximum,
        )?;
        let world = world.owned_storage()?;
        header
            .checked_add(std::mem::size_of::<Original>())
            .and_then(|bytes| bytes.checked_add(world))
            .filter(|bytes| *bytes <= maximum)
            .ok_or(RuntimeError::ResourceLimit)
    }

    pub(in super::super) fn charge_original_retained_storage(
        &self,
        counter: &mut super::super::runtime_owned_counter::RetainedRuntimeCounter,
    ) -> Result<(), RuntimeError> {
        self.original()?;
        let Original {
            process: _,
            thread: _,
            world,
            authority: _,
            live: _,
            scheduler,
            restored,
            coordinator17,
        } = self.0.as_ref();
        let state = scheduler
            .try_borrow()
            .map_err(|_| RuntimeError::OutstandingObligations)?;
        let restored = restored
            .try_borrow()
            .map_err(|_| RuntimeError::OutstandingObligations)?;
        let coordinator17 = coordinator17
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if counter.rc(&self.0)? {
            counter.owned(world)?;
            if let Some(log) = coordinator17.as_ref() {
                counter.add(log.retained_requested_storage_data()?)?;
                counter.add(log.future_requested_storage_data()?)?;
            }
            if let Some(state) = state.as_ref() {
                state.charge_original_retained_storage(counter)?;
            }
            if let Some(identity) = restored.as_ref() {
                let OriginalLineageSchedulingIdentity {
                    source,
                    scheduling,
                    target,
                } = identity;
                counter.owned(source)?;
                counter.owned(scheduling)?;
                counter.owned(target)?;
            }
        }
        self.original()
    }

    /// Retains the independently admitted once owner before its first reserve.
    pub(super) fn initialize_coordinator17_data(
        &self,
        owner: super::coordinator_commitment::CoordinatorCommitments17,
        maximum: usize,
        parent: &ContentRef,
    ) -> Result<(), RuntimeError> {
        self.current()?;
        let mut slot = self
            .0
            .coordinator17
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if slot.is_some() {
            return Err(RuntimeError::OutstandingObligations);
        }
        *slot = Some(owner);
        let owner = slot.as_mut().ok_or(RuntimeError::OwnerUnavailable)?;
        owner.initialize_data(maximum)?;
        owner.retain_parent_data(parent)
    }

    /// Installs the actual admitted initial bank before World publication.
    pub(super) fn initialize_initial_coordinator17_data(
        &self,
        owner: super::coordinator_commitment::CoordinatorCommitments17,
        maximum: usize,
    ) -> Result<(), RuntimeError> {
        self.current()?;
        if self.initialized()? {
            return Err(RuntimeError::ForeignAuthority);
        }
        let mut slot = self
            .0
            .coordinator17
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if slot.is_some() {
            return Err(RuntimeError::OutstandingObligations);
        }
        *slot = Some(owner);
        slot.as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .initialize_data(maximum)
    }

    /// Lends the same optional log only while its original authority stays live.
    pub(super) fn with_coordinator17_data<R>(
        &self,
        inspect: impl FnOnce(
            Option<&mut super::coordinator_commitment::CoordinatorCommitments17>,
        ) -> Result<R, RuntimeError>,
    ) -> Result<R, RuntimeError> {
        let mut slot = self
            .0
            .coordinator17
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if slot.is_none() {
            return inspect(None);
        }
        self.current()?;
        let result = inspect(slot.as_mut());
        self.current()?;
        result
    }

    pub(in super::super) fn new(authority: &Rc<()>, world: HashRef) -> Self {
        Self(Rc::new(Original {
            process: std::process::id(),
            thread: thread::current().id(),
            world,
            authority: Rc::downgrade(authority),
            live: Cell::new(true),
            scheduler: RefCell::new(None),
            restored: RefCell::new(None),
            coordinator17: RefCell::new(None),
        }))
    }

    fn original(&self) -> Result<(), RuntimeError> {
        if self.0.process != std::process::id()
            || self.0.thread != thread::current().id()
            || self.0.authority.upgrade().is_none()
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    pub(in super::super) fn current(&self) -> Result<(), RuntimeError> {
        self.original()?;
        if !self.0.live.get() {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(())
    }

    pub(in super::super) fn authenticate(
        &self,
        authority: &Rc<()>,
        world: &HashRef,
    ) -> Result<(), RuntimeError> {
        self.current()?;
        self.authenticate_retained(authority, world)
    }

    pub(in super::super) fn authenticate_retained(
        &self,
        authority: &Rc<()>,
        world: &HashRef,
    ) -> Result<(), RuntimeError> {
        self.original()?;
        let original = self
            .0
            .authority
            .upgrade()
            .ok_or(RuntimeError::ForeignAuthority)?;
        if !Rc::ptr_eq(&original, authority) || &self.0.world != world {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    pub(in super::super) fn revoke(&self) {
        if self.original().is_ok() {
            self.0.live.set(false);
        }
    }

    pub(in super::super) fn initialized(&self) -> Result<bool, RuntimeError> {
        self.original()?;
        let state = self
            .0
            .scheduler
            .try_borrow()
            .map_err(|_| RuntimeError::OutstandingObligations)?;
        Ok(state.is_some())
    }

    pub(in super::super) fn install(&self, scheduler: CausalScheduler) -> Result<(), RuntimeError> {
        self.current()?;
        if scheduler.activation().record().world_binding_hash != self.0.world {
            return Err(RuntimeError::ForeignAuthority);
        }
        let mut state = self
            .0
            .scheduler
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OutstandingObligations)?;
        if state.is_some() {
            return Err(RuntimeError::ForeignAuthority);
        }
        *state = Some(scheduler);
        Ok(())
    }

    pub(in super::super) fn install_original_lineage(
        &self,
        scheduler: CausalScheduler,
        source: &ContentRef,
        scheduling: &HashRef,
        target: &super::super::ActivationRecord,
    ) -> Result<(), RuntimeError> {
        self.current()?;
        if scheduler.activation().record() != target || target.world_binding_hash != self.0.world {
            return Err(RuntimeError::ForeignAuthority);
        }
        // All metadata is bounded by the already checked restoration context.
        // Reserve both cells before retaining any changed state: reentrancy can
        // refuse, but cannot leave a scheduler without its original source seal.
        let mut restored = self
            .0
            .restored
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OutstandingObligations)?;
        let mut state = self
            .0
            .scheduler
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OutstandingObligations)?;
        if restored.is_some() || state.is_some() {
            return Err(RuntimeError::ForeignAuthority);
        }
        let identity = OriginalLineageSchedulingIdentity {
            source: source.clone(),
            scheduling: scheduling.clone(),
            target: target.clone(),
        };
        *state = Some(scheduler);
        *restored = Some(identity);
        Ok(())
    }

    pub(in super::super) fn borrow_mut(&self) -> Result<RefMut<'_, CausalScheduler>, RuntimeError> {
        self.current()?;
        let state = self
            .0
            .scheduler
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OutstandingObligations)?;
        RefMut::filter_map(state, Option::as_mut).map_err(|_| RuntimeError::NotActivated)
    }

    pub(in super::super) fn borrow_if_initialized(
        &self,
    ) -> Result<Option<RefMut<'_, CausalScheduler>>, RuntimeError> {
        self.current()?;
        let state = self
            .0
            .scheduler
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OutstandingObligations)?;
        Ok(RefMut::filter_map(state, Option::as_mut).ok())
    }

    pub(in super::super) fn retained(&self) -> Result<Ref<'_, CausalScheduler>, RuntimeError> {
        self.original()?;
        let state = self
            .0
            .scheduler
            .try_borrow()
            .map_err(|_| RuntimeError::OutstandingObligations)?;
        Ref::filter_map(state, Option::as_ref).map_err(|_| RuntimeError::NotActivated)
    }

    pub(in super::super) fn snapshot(
        &self,
        cut: Position,
        ordinal: U64,
    ) -> Result<SchedulingSnapshot, RuntimeError> {
        self.retained()?
            .snapshot(cut, ordinal)
            .map_err(|error| RuntimeError::SchedulerRefused(error.to_string()))
    }

    pub(in super::super) fn source(&self) -> OriginalSchedulingSource {
        OriginalSchedulingSource {
            original: Rc::downgrade(&self.0),
            process: self.0.process,
            thread: self.0.thread,
            world: self.0.world.clone(),
        }
    }
}

/// Reads the identity of the actual scheduler owner without exposing mutable queues.
///
/// Only an original runtime creates this handle. A copied handle retains no
/// live permission after revocation, quarantine, transfer or destruction. It
/// cannot initialize, restore, reserve, advance, commit or drain scheduling state.
#[derive(Clone)]
pub struct OriginalSchedulingSource {
    original: Weak<Original>,
    process: u32,
    thread: ThreadId,
    world: HashRef,
}

impl OriginalSchedulingSource {
    /// Separates the new world clone from the repeated Weak-root observation.
    ///
    /// # Errors
    /// Refuses unsupported hash storage, overflow or the supplied data bound.
    pub(in crate::node_contract) fn construction_metadata_storage_data(
        world: &HashRef,
        maximum: usize,
    ) -> Result<(usize, usize), RuntimeError> {
        let world = super::super::NodeRuntime::capture_hash_storage(world)?;
        let weak = super::super::NodeRuntime::capture_shared_allocation_storage::<Original>();
        world
            .checked_add(weak)
            .filter(|bytes| *bytes <= maximum)
            .ok_or(RuntimeError::ResourceLimit)?;
        Ok((world, weak))
    }

    pub(in crate::node_contract) fn retained_metadata_bytes_excluding_runtime(
        &self,
    ) -> Result<usize, RuntimeError> {
        self.birth(&self.world)?;
        // This Weak keeps the original inline allocation reserved after the
        // runtime releases its strong owner. Scheduler heap fields are owned by
        // that runtime and are not followed through a dead or foreign pointer.
        super::super::NodeRuntime::capture_hash_storage(&self.world)?
            .checked_add(super::super::NodeRuntime::capture_shared_allocation_storage::<Original>())
            .ok_or(RuntimeError::ResourceLimit)
    }

    /// Checks original process/thread/world custody before observing shared storage.
    ///
    /// # Errors
    /// Refuses dead or revoked original authority and foreign process/thread/world.
    pub fn authenticate_current(&self, world: &HashRef) -> Result<(), RuntimeError> {
        self.birth(world)?;
        let state = self
            .original
            .upgrade()
            .ok_or(RuntimeError::ForeignAuthority)?;
        let original = OriginalSchedulingState(state);
        original.current()?;
        if &original.0.world != world {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    fn birth(&self, world: &HashRef) -> Result<(), RuntimeError> {
        if self.process != std::process::id()
            || self.thread != thread::current().id()
            || &self.world != world
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    pub(in super::super) fn authenticate_runtime_authority(
        &self,
        world: &HashRef,
        authority: &Rc<()>,
    ) -> Result<(), RuntimeError> {
        self.authenticate_current(world)?;
        let state = self
            .original
            .upgrade()
            .ok_or(RuntimeError::ForeignAuthority)?;
        OriginalSchedulingState(state).authenticate(authority, world)
    }

    pub(in super::super) fn authenticate_original_lineage_installation(
        &self,
        world: &HashRef,
        source: &ContentRef,
        scheduling: &HashRef,
        target: &super::super::ActivationRecord,
    ) -> Result<(), RuntimeError> {
        self.authenticate_current(world)?;
        let state = self
            .original
            .upgrade()
            .ok_or(RuntimeError::ForeignAuthority)?;
        let original = OriginalSchedulingState(state);
        let restored = original
            .0
            .restored
            .try_borrow()
            .map_err(|_| RuntimeError::OutstandingObligations)?;
        let identity = restored.as_ref().ok_or(RuntimeError::UnsupportedFacet)?;
        if &identity.source != source
            || &identity.scheduling != scheduling
            || &identity.target != target
            || original.retained()?.activation().record() != target
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        original.current()
    }

    pub(in super::super) fn authenticate_input_batch(
        &self,
        batch: &crate::node_scheduling::RuntimeInputBatch,
    ) -> Result<(), RuntimeError> {
        self.authenticate_current(&batch.activation().record().world_binding_hash)?;
        let state = self
            .original
            .upgrade()
            .ok_or(RuntimeError::ForeignAuthority)?;
        OriginalSchedulingState(state)
            .retained()?
            .authenticate_original_input_batch(batch)
            .map_err(|error| RuntimeError::SchedulerRefused(error.to_string()))
    }

    pub(in super::super) fn authenticate_initial(
        &self,
        world: &HashRef,
    ) -> Result<(), RuntimeError> {
        self.authenticate_current(world)?;
        let state = self
            .original
            .upgrade()
            .ok_or(RuntimeError::ForeignAuthority)?;
        if OriginalSchedulingState(state).initialized()? {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(())
    }

    pub(in super::super) fn revoke(&self, world: &HashRef) -> Result<(), RuntimeError> {
        self.birth(world)?;
        let state = self
            .original
            .upgrade()
            .ok_or(RuntimeError::ForeignAuthority)?;
        let state = OriginalSchedulingState(state);
        state.original()?;
        state.revoke();
        Ok(())
    }

    pub(in super::super) fn authenticate_closed(
        &self,
        world: &HashRef,
    ) -> Result<(), RuntimeError> {
        self.birth(world)?;
        let state = self
            .original
            .upgrade()
            .ok_or(RuntimeError::ForeignAuthority)?;
        let state = OriginalSchedulingState(state);
        state.original()?;
        if state.0.live.get() {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(())
    }

    pub(in super::super) fn same_original(&self, state: &OriginalSchedulingState) -> bool {
        self.original.ptr_eq(&Rc::downgrade(&state.0))
    }
}

#[cfg(test)]
mod tests {
    // A busy original fixture is mandatory; failure to establish it must panic.
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn revoked_uninitialized_scheduler_retains_data_but_refuses_target_currency() {
        let authority = Rc::new(());
        let world = HashRef {
            algorithm: "blake3-256".into(),
            domain: "cnp.world-binding.v1".into(),
            digest: "1".repeat(64),
        };
        let state = OriginalSchedulingState::new(&authority, world.clone());
        assert!(!state.initialized().unwrap());
        state.authenticate(&authority, &world).unwrap();

        state.revoke();

        state.authenticate_retained(&authority, &world).unwrap();
        assert!(matches!(
            state.authenticate(&authority, &world),
            Err(RuntimeError::OutstandingObligations)
        ));
        assert!(state.0.scheduler.borrow().is_none());
        assert!(!state.0.live.get());
        assert!(state.authenticate(&Rc::new(()), &world).is_err());
    }

    #[test]
    fn modeled_foreign_origin_refuses_before_busy_storage_and_dead_authority() {
        // PID erasure is modeled. The actual original slot and busy RefCell are
        // genuine; this is not an executed fork or native packet qualification.
        let authority = Rc::new(());
        let world = HashRef {
            algorithm: "blake3-256".into(),
            domain: "cnp.world-binding.v1".into(),
            digest: "1".repeat(64),
        };
        let state = OriginalSchedulingState::new(&authority, world.clone());
        let mut foreign = state.source();
        foreign.process = std::process::id().wrapping_add(1);
        let retained = state.source();
        let busy = state.0.scheduler.try_borrow_mut().unwrap();
        assert!(matches!(
            foreign.authenticate_current(&world),
            Err(RuntimeError::ForeignAuthority)
        ));
        assert!(matches!(
            retained.authenticate_initial(&world),
            Err(RuntimeError::OutstandingObligations)
        ));
        drop(authority);
        assert!(matches!(
            retained.authenticate_current(&world),
            Err(RuntimeError::ForeignAuthority)
        ));
        drop(busy);
    }

    fn modeled_scheduler() -> (Rc<()>, CausalScheduler) {
        // The queue and private allocation are actual. Native readiness and
        // durable publication are explicitly modeled for these slot controls.
        let (graph, _) = crate::node_admission::test_fixture_isolated_execution(false);
        let mut owners = std::collections::BTreeMap::new();
        for node in graph.node_ids() {
            let binding = graph.binding(node).unwrap();
            owners.insert(
                binding.compatibility.execution_owner.id.clone(),
                super::super::OwnerIdentity {
                    owner: binding.compatibility.execution_owner.id.clone(),
                    incarnation: binding.authority.incarnation_id.clone(),
                    generation: binding.authority.owner_generation,
                },
            );
        }
        let authority = Rc::new(());
        let activation = super::super::WorldActivation {
            nodes: Rc::from([]),
            preparation: None,
            authority: Rc::clone(&authority),
            record: super::super::ActivationRecord {
                activation_id: crucible_node_contract::Id::new("modeled/restore-slot").unwrap(),
                generation: 1.into(),
                world_binding_hash: graph.world_binding_hash().clone(),
                owners: owners.into_values().collect(),
                boundary: Position::new(
                    0.into(),
                    0.into(),
                    crucible_node_contract::Phase::BoundaryControl,
                ),
            },
        };
        (authority, CausalScheduler::new(&graph, activation).unwrap())
    }

    #[test]
    fn original_restore_slot_requires_core_seal_not_equal_initialized_state() {
        let (authority, scheduler) = modeled_scheduler();
        let target = scheduler.activation().record().clone();
        let state = OriginalSchedulingState::new(&authority, target.world_binding_hash.clone());
        let source = state.source();
        let runtime_record =
            crucible_node_contract::canonical::content_ref(b"captured runtime", "application/json")
                .unwrap();
        let scheduling = scheduler
            .snapshot(target.boundary, 0.into())
            .unwrap()
            .continuation_hash()
            .unwrap();
        state.install(scheduler).unwrap();

        assert!(matches!(
            source.authenticate_original_lineage_installation(
                &target.world_binding_hash,
                &runtime_record,
                &scheduling,
                &target,
            ),
            Err(RuntimeError::UnsupportedFacet)
        ));
        assert_eq!(
            state
                .snapshot(target.boundary, 0.into())
                .unwrap()
                .continuation_hash()
                .unwrap(),
            scheduling
        );
    }

    #[test]
    fn original_restore_slot_seal_preserves_queue_and_refuses_other_source_and_repeat() {
        let (authority, scheduler) = modeled_scheduler();
        let target = scheduler.activation().record().clone();
        let snapshot = scheduler.snapshot(target.boundary, 0.into()).unwrap();
        let scheduling = snapshot.continuation_hash().unwrap();
        let runtime_record =
            crucible_node_contract::canonical::content_ref(b"captured runtime", "application/json")
                .unwrap();
        let state = OriginalSchedulingState::new(&authority, target.world_binding_hash.clone());
        let source = state.source();
        state
            .install_original_lineage(scheduler, &runtime_record, &scheduling, &target)
            .unwrap();

        source
            .authenticate_runtime_authority(&target.world_binding_hash, &authority)
            .unwrap();
        source
            .authenticate_original_lineage_installation(
                &target.world_binding_hash,
                &runtime_record,
                &scheduling,
                &target,
            )
            .unwrap();
        let foreign =
            crucible_node_contract::canonical::content_ref(b"other runtime", "application/json")
                .unwrap();
        assert!(matches!(
            source.authenticate_original_lineage_installation(
                &target.world_binding_hash,
                &foreign,
                &scheduling,
                &target,
            ),
            Err(RuntimeError::ForeignAuthority)
        ));
        assert!(
            source
                .authenticate_runtime_authority(&target.world_binding_hash, &Rc::new(()))
                .is_err()
        );
        let (_, another) = modeled_scheduler();
        assert!(
            state
                .install_original_lineage(another, &runtime_record, &scheduling, &target)
                .is_err()
        );
        assert_eq!(state.snapshot(target.boundary, 0.into()).unwrap(), snapshot);
        state.revoke();
        assert!(
            source
                .authenticate_original_lineage_installation(
                    &target.world_binding_hash,
                    &runtime_record,
                    &scheduling,
                    &target,
                )
                .is_err()
        );
        assert_eq!(state.snapshot(target.boundary, 0.into()).unwrap(), snapshot);
    }

    #[test]
    fn busy_original_restore_slot_refuses_before_install_and_foreign_authority_before_borrow() {
        let (authority, scheduler) = modeled_scheduler();
        let target = scheduler.activation().record().clone();
        let scheduling = scheduler
            .snapshot(target.boundary, 0.into())
            .unwrap()
            .continuation_hash()
            .unwrap();
        let runtime_record =
            crucible_node_contract::canonical::content_ref(b"captured runtime", "application/json")
                .unwrap();
        let state = OriginalSchedulingState::new(&authority, target.world_binding_hash.clone());
        let source = state.source();
        let busy = state.0.scheduler.try_borrow_mut().unwrap();

        assert!(matches!(
            source.authenticate_runtime_authority(&target.world_binding_hash, &Rc::new(())),
            Err(RuntimeError::ForeignAuthority)
        ));
        assert!(matches!(
            state.install_original_lineage(scheduler, &runtime_record, &scheduling, &target),
            Err(RuntimeError::OutstandingObligations)
        ));
        assert!(state.0.restored.try_borrow().unwrap().is_none());
        assert!(busy.is_none());
        drop(busy);
        assert!(!state.initialized().unwrap());
    }
}

#[cfg(test)]
mod restoration_member_tests {
    use super::*;

    #[test]
    fn terminal_member_fence_observes_revocation_without_a_runtime_or_scheduler_loan() {
        let authority = Rc::new(());
        let world = HashRef {
            algorithm: "blake3-256".into(),
            domain: "cnp.world-binding.v1".into(),
            digest: "2".repeat(64),
        };
        let scheduler = OriginalSchedulingState::new(&authority, world.clone());
        let fence = scheduler
            .restoration_member_fence_data(&authority, &world)
            .unwrap();
        let outstanding = scheduler.0.scheduler.borrow_mut();
        fence.authenticate_current(&authority, &world).unwrap();

        scheduler.revoke();

        assert!(matches!(
            fence.authenticate_current(&authority, &world),
            Err(RuntimeError::OutstandingObligations)
        ));
        assert!(scheduler.authenticate_retained(&authority, &world).is_ok());
        drop(outstanding);
    }
}

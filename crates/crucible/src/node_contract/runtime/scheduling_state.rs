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

use crucible_node_contract::{HashRef, Position, U64};

use crate::node_scheduling::{CausalScheduler, SchedulingSnapshot};

use super::super::RuntimeError;

struct Original {
    process: u32,
    thread: ThreadId,
    world: HashRef,
    authority: Weak<()>,
    live: Cell<bool>,
    scheduler: RefCell<Option<CausalScheduler>>,
}

/// Retains the runtime's original scheduler storage, including its uninitialized cut.
pub(in super::super) struct OriginalSchedulingState(Rc<Original>);

impl OriginalSchedulingState {
    pub(in super::super) fn new(authority: &Rc<()>, world: HashRef) -> Self {
        Self(Rc::new(Original {
            process: std::process::id(),
            thread: thread::current().id(),
            world,
            authority: Rc::downgrade(authority),
            live: Cell::new(true),
            scheduler: RefCell::new(None),
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
}

//! Idempotent holders for one session's exclusive debugger controller lease.
//!
//! The session coordinator deliberately treats reacquisition by one principal
//! as an idempotent repeated acquisition. This API-layer registry distinguishes
//! independent command and relay lifetimes for that principal without weakening
//! the coordinator's single-controller security boundary. Server transitions
//! lock the coordinator before this registry and perform both mutations without
//! an intervening await, so request cancellation cannot split their state.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crucible_session::DebugControllerLease;
use thiserror::Error;
use uuid::Uuid;

use crate::SessionRef;

const DEBUG_HOLDER_TOMBSTONE_LIMIT: usize = 128;

/// Client-generated idempotency key for one controller acquisition lifetime.
pub(crate) type DebugControllerHolderId = Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DebugHolderRelease {
    Retained,
    Final,
    AlreadyReleased,
}

#[derive(Default)]
pub(crate) struct DebugControllerHolderRegistry {
    sessions: BTreeMap<SessionRef, DebugControllerHolders>,
    released: VecDeque<ReleasedDebugControllerHolder>,
}

struct DebugControllerHolders {
    lease: DebugControllerLease,
    holders: BTreeSet<DebugControllerHolderId>,
}

struct ReleasedDebugControllerHolder {
    session: SessionRef,
    lease: DebugControllerLease,
    holder: DebugControllerHolderId,
}

impl DebugControllerHolderRegistry {
    pub(crate) fn has_active_session(&self, session: SessionRef) -> bool {
        self.sessions.contains_key(&session)
    }

    pub(crate) fn authorize(
        &self,
        session: SessionRef,
        lease: &DebugControllerLease,
        holder: DebugControllerHolderId,
    ) -> Result<(), DebugHolderError> {
        let active = self
            .sessions
            .get(&session)
            .ok_or(DebugHolderError::UnknownHolder)?;
        if active.lease != *lease {
            return Err(DebugHolderError::StaleOrForeignLease);
        }
        if !active.holders.contains(&holder) {
            return Err(DebugHolderError::UnknownHolder);
        }
        Ok(())
    }

    pub(crate) fn register(
        &mut self,
        session: SessionRef,
        lease: DebugControllerLease,
        holder: DebugControllerHolderId,
    ) -> Result<(), DebugHolderError> {
        self.preflight_register(session, holder)?;
        match self.sessions.get_mut(&session) {
            Some(active) if active.lease != lease => Err(DebugHolderError::StaleOrForeignLease),
            Some(active) => {
                active.holders.insert(holder);
                Ok(())
            }
            None => {
                self.sessions.insert(
                    session,
                    DebugControllerHolders {
                        lease,
                        holders: BTreeSet::from([holder]),
                    },
                );
                Ok(())
            }
        }
    }

    pub(crate) fn preflight_register(
        &self,
        session: SessionRef,
        holder: DebugControllerHolderId,
    ) -> Result<(), DebugHolderError> {
        if self
            .released
            .iter()
            .any(|released| released.session == session && released.holder == holder)
        {
            return Err(DebugHolderError::ReleasedHolder);
        }
        Ok(())
    }

    pub(crate) fn release(
        &mut self,
        session: SessionRef,
        lease: &DebugControllerLease,
        holder: DebugControllerHolderId,
    ) -> Result<DebugHolderRelease, DebugHolderError> {
        if self.released.iter().any(|released| {
            released.session == session && released.lease == *lease && released.holder == holder
        }) {
            return Ok(DebugHolderRelease::AlreadyReleased);
        }
        let Some(active) = self.sessions.get_mut(&session) else {
            return Err(DebugHolderError::UnknownHolder);
        };
        if active.lease != *lease {
            return Err(DebugHolderError::StaleOrForeignLease);
        }
        if !active.holders.remove(&holder) {
            return Err(DebugHolderError::UnknownHolder);
        }
        let final_release = active.holders.is_empty();
        self.released.push_back(ReleasedDebugControllerHolder {
            session,
            lease: lease.clone(),
            holder,
        });
        while self.released.len() > DEBUG_HOLDER_TOMBSTONE_LIMIT {
            self.released.pop_front();
        }
        if !final_release {
            return Ok(DebugHolderRelease::Retained);
        }
        self.sessions.remove(&session);
        Ok(DebugHolderRelease::Final)
    }

    pub(crate) fn restore(
        &mut self,
        session: SessionRef,
        lease: DebugControllerLease,
        holder: DebugControllerHolderId,
    ) {
        self.released.retain(|released| {
            released.session != session || released.lease != lease || released.holder != holder
        });
        let _ = self.register(session, lease, holder);
    }

    pub(crate) fn remove_session(&mut self, session: SessionRef) {
        self.sessions.remove(&session);
        self.released.retain(|released| released.session != session);
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub(crate) enum DebugHolderError {
    #[error("debug controller holder used a stale or foreign lease")]
    StaleOrForeignLease,
    #[error("debug controller holder identity is unknown")]
    UnknownHolder,
    #[error("debug controller holder identity was already released")]
    ReleasedHolder,
}

#[cfg(test)]
mod tests {
    use crucible::Seed;
    use crucible_session::{DebugCapability, DebugClientId, DebugCoordinator, DebugRole};

    use super::*;

    fn session() -> SessionRef {
        SessionRef::new(crate::SessionId::new(1), 2, Seed::from_u64(3))
    }

    fn lease() -> DebugControllerLease {
        DebugControllerLease {
            client: DebugClientId::new("holder-test")
                .unwrap_or_else(|error| panic!("test client should be valid: {error}")),
            generation: 4,
        }
    }

    #[test]
    fn independent_holders_release_only_the_final_controller_reference() {
        let mut registry = DebugControllerHolderRegistry::default();
        let first = Uuid::from_u128(1);
        let second = Uuid::from_u128(2);
        registry
            .register(session(), lease(), first)
            .unwrap_or_else(|error| panic!("first holder should register: {error}"));
        registry
            .register(session(), lease(), first)
            .unwrap_or_else(|error| {
                panic!("repeated holder registration should be idempotent: {error}")
            });
        registry
            .register(session(), lease(), second)
            .unwrap_or_else(|error| panic!("second holder should register: {error}"));

        assert_eq!(
            registry.release(session(), &lease(), first),
            Ok(DebugHolderRelease::Retained)
        );
        assert_eq!(
            registry.release(session(), &lease(), second),
            Ok(DebugHolderRelease::Final)
        );
        assert_eq!(
            registry.release(session(), &lease(), second),
            Ok(DebugHolderRelease::AlreadyReleased)
        );
    }

    #[test]
    fn final_release_retains_a_bounded_repeated_release_tombstone() {
        let mut registry = DebugControllerHolderRegistry::default();
        let holder = Uuid::from_u128(7);
        registry
            .register(session(), lease(), holder)
            .unwrap_or_else(|error| panic!("holder should register: {error}"));

        assert_eq!(
            registry.release(session(), &lease(), holder),
            Ok(DebugHolderRelease::Final)
        );
        assert_eq!(
            registry.release(session(), &lease(), holder),
            Ok(DebugHolderRelease::AlreadyReleased)
        );
        assert_eq!(
            registry.register(session(), lease(), holder),
            Err(DebugHolderError::ReleasedHolder)
        );
        assert_eq!(
            registry.release(session(), &lease(), Uuid::from_u128(8)),
            Err(DebugHolderError::UnknownHolder)
        );
    }

    #[test]
    fn relay_holder_preserves_exclusivity_against_another_principal() {
        let role = DebugRole::new([DebugCapability::Observe, DebugCapability::Control]);
        let owner = DebugClientId::new("relay-owner")
            .unwrap_or_else(|error| panic!("relay owner should be valid: {error}"));
        let other = DebugClientId::new("other-controller")
            .unwrap_or_else(|error| panic!("other controller should be valid: {error}"));
        let mut coordinator = DebugCoordinator::new();
        let lease = coordinator
            .acquire_controller(owner, &role)
            .unwrap_or_else(|error| panic!("owner should acquire controller: {error}"));
        let relay_holder = Uuid::from_u128(11);
        let command_holder = Uuid::from_u128(12);
        let mut registry = DebugControllerHolderRegistry::default();
        registry
            .register(session(), lease.clone(), relay_holder)
            .unwrap_or_else(|error| panic!("relay holder should register: {error}"));
        registry
            .register(session(), lease.clone(), command_holder)
            .unwrap_or_else(|error| panic!("command holder should register: {error}"));

        assert_eq!(
            registry.release(session(), &lease, command_holder),
            Ok(DebugHolderRelease::Retained)
        );
        assert!(
            coordinator
                .acquire_controller(other.clone(), &role)
                .is_err()
        );
        assert_eq!(
            registry.release(session(), &lease, relay_holder),
            Ok(DebugHolderRelease::Final)
        );
        coordinator
            .release_controller(&lease)
            .unwrap_or_else(|error| panic!("final relay holder should release: {error}"));
        coordinator
            .acquire_controller(other, &role)
            .unwrap_or_else(|error| panic!("other controller should acquire after close: {error}"));
    }
}

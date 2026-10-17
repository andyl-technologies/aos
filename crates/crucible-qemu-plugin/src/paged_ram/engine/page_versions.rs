//! Retains a whole page-vector fence in its actual existing mutation mutex.
//!
//! Immutable reads borrow the same vector; mutable element admission refuses
//! while a held native transaction owns its fence. No vector copy, per-page hash
//! or version-counter equality creates source authority. The native witness types
//! derive from the actual active root after worker ACK and mailbox/work checks.
//! Source-read enrollment and native completion remain independently required.

// SPDX-License-Identifier: GPL-2.0-or-later

use std::ops::Deref;

use super::PageState;
use crate::ram_error::RamError;

#[derive(Clone, Copy, PartialEq, Eq)]
struct FenceIdentity {
    transaction: u64,
    source_owner: u64,
    page_owner: u64,
}

/// Names the complete retained owner slots of an authenticated native fence.
///
/// These identities name actual retained source/vector allocations, not page
/// versions. Production construction independently checks the active native root
/// after the real service, worker and mailbox owners have been retained.
#[derive(Clone)]
pub(super) struct NativePageFence {
    identity: FenceIdentity,
}

impl NativePageFence {
    /// Binds the same retained source/vector owners to an actual active root.
    ///
    /// # Errors
    /// Refuses the authentic root check or absent whole owner identities.
    pub(super) fn from_active_root(
        root: &crate::runtime::NativeRoot,
        source_owner: u64,
        page_owner: u64,
    ) -> Result<Self, RamError> {
        root.check_active()?;
        if source_owner == 0 || page_owner == 0 {
            return Err(RamError::Invariant("checkpoint whole page owner absent"));
        }
        Ok(Self {
            identity: FenceIdentity {
                transaction: root.transaction(),
                source_owner,
                page_owner,
            },
        })
    }

    /// Borrows the same vector identity during actual native local disposition.
    ///
    /// # Errors
    /// Refuses a foreign live observer loan; copied stage scalars cannot issue it.
    pub(super) fn disposed(
        &self,
        disposition: &crate::runtime::LocalDisposition<'_>,
    ) -> Result<DisposedNativePageFence, RamError> {
        if disposition.transaction() != self.identity.transaction {
            return Err(RamError::Invariant(
                "checkpoint page disposition root changed",
            ));
        }
        Ok(DisposedNativePageFence {
            identity: self.identity,
        })
    }
}

/// Names final native disposition while retaining the same complete fence proof.
///
/// Only a live native LOCAL_DISPOSITION observer can derive this same identity;
/// a copied stage or successful Drop cannot reopen the vector.
pub(super) struct DisposedNativePageFence {
    identity: FenceIdentity,
}

#[derive(Default)]
struct PageVersionGate {
    issued_transaction: u64,
    held: Option<FenceIdentity>,
    ordinary: Option<u64>,
}

/// Keeps the exact live vector and its admission gate in one existing mutex body.
pub(super) struct PageStates {
    values: Vec<PageState>,
    gate: PageVersionGate,
}

impl PageStates {
    /// Moves the existing admitted vector without allocating or copying its pages.
    pub(super) fn new(values: Vec<PageState>) -> Self {
        Self {
            values,
            gate: PageVersionGate::default(),
        }
    }

    /// Returns the actual added inline control extent before vector/actor birth.
    pub(super) const fn control_bytes() -> usize {
        std::mem::size_of::<Self>() - std::mem::size_of::<Vec<PageState>>()
    }

    /// Borrows one mutable page only while no checkpoint owns the whole vector.
    pub(super) fn get_mut(&mut self, index: usize) -> Option<&mut PageState> {
        if self.gate.held.is_some() || self.gate.ordinary.is_some() {
            return None;
        }
        self.values.get_mut(index)
    }

    pub(super) fn hold_ordinary(&mut self, identity: u64) -> Result<(), RamError> {
        if identity == 0
            || self.gate.held.is_some()
            || self.gate.ordinary.is_some_and(|held| held != identity)
        {
            return Err(RamError::Invariant("ordinary page capture is occupied"));
        }
        self.gate.ordinary = Some(identity);
        Ok(())
    }

    pub(super) fn check_ordinary(&self, identity: u64) -> Result<(), RamError> {
        if self.gate.ordinary != Some(identity) || self.gate.held.is_some() {
            return Err(RamError::Invariant("ordinary page capture changed"));
        }
        Ok(())
    }

    pub(super) fn get_mut_ordinary(
        &mut self,
        identity: u64,
        index: usize,
    ) -> Option<&mut PageState> {
        if self.check_ordinary(identity).is_err() {
            return None;
        }
        self.values.get_mut(index)
    }

    pub(super) fn release_ordinary(&mut self, identity: u64) -> Result<(), RamError> {
        self.check_ordinary(identity)?;
        self.gate.ordinary = None;
        Ok(())
    }

    /// Retains the whole vector under the independently authenticated native fence.
    ///
    /// # Errors
    /// Refuses missing proof slots, a stale transaction or another retained fence.
    /// Worker ACK, mailbox detach, writer exclusion and original checks must precede
    /// the future receiver's production construction of the supplied witness.
    pub(super) fn hold(&mut self, fence: &NativePageFence) -> Result<(), RamError> {
        let identity = fence.identity;
        if self.gate.ordinary.is_some() {
            return Err(RamError::Invariant(
                "ordinary capture retains page versions",
            ));
        }
        if let Some(held) = self.gate.held {
            return if held == identity {
                Ok(())
            } else {
                Err(RamError::Invariant(
                    "another checkpoint retains page versions",
                ))
            };
        }
        if identity.transaction == 0
            || identity.transaction <= self.gate.issued_transaction
            || identity.source_owner == 0
            || identity.page_owner == 0
        {
            return Err(RamError::Invariant(
                "checkpoint page fence is stale or absent",
            ));
        }
        self.gate.issued_transaction = identity.transaction;
        self.gate.held = Some(identity);
        Ok(())
    }

    /// Checks identity against the whole owner retained in this same mutex body.
    ///
    /// # Errors
    /// Refuses missing, changed or foreign native transaction owner slots.
    pub(super) fn check(&self, fence: &NativePageFence) -> Result<(), RamError> {
        if self.gate.held != Some(fence.identity) {
            return Err(RamError::Invariant("checkpoint page fence does not match"));
        }
        Ok(())
    }

    /// Reopens mutable admission only after exact native final disposition.
    ///
    /// # Errors
    /// Refuses an absent or unmatched whole fence; refusal leaves its gate held.
    pub(super) fn release(&mut self, disposed: &DisposedNativePageFence) -> Result<(), RamError> {
        if self.gate.held != Some(disposed.identity) {
            return Err(RamError::Invariant(
                "checkpoint page disposition does not match",
            ));
        }
        self.gate.held = None;
        Ok(())
    }
}

impl Deref for PageStates {
    type Target = [PageState];

    fn deref(&self) -> &Self::Target {
        &self.values
    }
}

#[cfg(test)]
mod tests;

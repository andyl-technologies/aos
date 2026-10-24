//! Bounded owning retention reserved before an original setup intent.
//!
//! Each wrapper shares one private ticket with its callback generation and
//! retained epoch owner. The ticket reserves an actual quarantine slot before
//! a fence or native getter admission, then transfers the same mapping Arc
//! into that store on Drop. Ordinary unused tickets return their reservation.

use std::sync::OnceLock;

use super::{
    Arc, AtomicBool, MappedSetupRegion, Ordering, WholeMappingCustodyError, quarantine,
    reserve_quarantine,
};

pub(super) struct RetentionSlot {
    process: u32,
    ticket: OnceLock<RetentionTicket>,
}

impl Default for RetentionSlot {
    fn default() -> Self {
        Self {
            process: std::process::id(),
            ticket: OnceLock::new(),
        }
    }
}

struct RetentionTicket {
    process: u32,
    transferred: AtomicBool,
}

impl RetentionSlot {
    pub(super) fn reserve(&self) -> Result<(), WholeMappingCustodyError> {
        // An inherited OnceLock can be INCOMPLETE with its initializing
        // thread gone. Reject the immutable slot generation before get/set.
        if self.process != std::process::id() {
            return Err(WholeMappingCustodyError::Unregistered);
        }
        if let Some(ticket) = self.ticket.get() {
            return if ticket.process == std::process::id() {
                Ok(())
            } else {
                Err(WholeMappingCustodyError::Unregistered)
            };
        }
        reserve_quarantine()?;
        let ticket = RetentionTicket {
            process: std::process::id(),
            transferred: AtomicBool::new(false),
        };
        // A competing reservation loses only its unused ticket. Its Drop
        // returns that exact reservation after reserve_quarantine unlocked.
        let _ = self.ticket.set(ticket);
        Ok(())
    }

    pub(super) fn armed(&self) -> bool {
        self.process == std::process::id()
            && self
                .ticket
                .get()
                .is_some_and(|ticket| ticket.process == std::process::id())
    }

    pub(super) fn retain(&self, mapping: Arc<MappedSetupRegion>) {
        if self.process != std::process::id() {
            // Already-admitted parent custody stays retained; no inherited
            // initializer or quarantine mutex may be entered in the child.
            std::mem::forget(mapping);
            return;
        }
        let Some(ticket) = self.ticket.get() else {
            return;
        };
        if ticket.process != std::process::id() {
            // A copied parent owner has a parent-budgeted ticket, but cannot
            // enter that generation's potentially inherited quarantine lock.
            std::mem::forget(mapping);
            return;
        }
        if ticket.transferred.swap(true, Ordering::AcqRel) {
            return;
        }
        // Poisoning never discards the reserved owner. No user code runs
        // while holding this store, and its existing allocation has room.
        let mut owners = match quarantine().lock() {
            Ok(owners) => owners,
            Err(poisoned) => poisoned.into_inner(),
        };
        owners.reserved -= 1;
        owners.owners.push(mapping);
    }
}

impl Drop for RetentionTicket {
    fn drop(&mut self) {
        if self.process != std::process::id() || self.transferred.load(Ordering::Acquire) {
            return;
        }
        let mut owners = match quarantine().lock() {
            Ok(owners) => owners,
            Err(poisoned) => poisoned.into_inner(),
        };
        owners.reserved -= 1;
    }
}

#[cfg(all(
    test,
    target_os = "linux",
    target_arch = "x86_64",
    target_env = "gnu",
    target_abi = "",
    target_endian = "little",
    target_pointer_width = "64"
))]
#[path = "retention_tests.rs"]
mod tests;

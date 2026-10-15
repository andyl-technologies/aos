//! Keeps fixed incarnation accounting until both real borrowers have closed.
//!
//! The containing authenticated purpose performs admission before calling this
//! journal. Numerical accounting here cannot construct a process or loan.

use super::{InstalledProcessPurposeError, SetupMappingRequest};

#[derive(Clone, Copy)]
pub(super) struct IncarnationAllocation {
    pub(super) process_generation: u64,
    pub(super) guest_ram_bytes: u64,
    pub(super) startup_bytes: u64,
    pub(super) setup_mapping: SetupMappingRequest,
    pub(super) borrower_closed: bool,
    pub(super) physical_retired: bool,
}

impl IncarnationAllocation {
    pub(super) fn reusable(&self) -> bool {
        self.borrower_closed && self.physical_retired
    }
}

/// Keeps the two live shares and their exact pending/assigned accounting.
/// This storage issues no process authority; only the containing purpose can
/// admit it after authentic contract, artifact and compulsory-floor checks.
pub(super) struct IncarnationJournal {
    pub(super) pending_startup_bytes: u64,
    pub(super) assigned_startup_bytes: u64,
    pub(super) live_guest_ram_bytes: u64,
    pub(super) loans: u8,
    pub(super) incarnations: [Option<IncarnationAllocation>;
        super::super::MAX_ORIGINAL_NATIVE_NODE_GENERATIONS as usize],
    pub(super) last_process_generation: u64,
}

impl IncarnationJournal {
    pub(super) fn new(pending_startup_bytes: u64) -> Self {
        Self {
            pending_startup_bytes,
            assigned_startup_bytes: 0,
            live_guest_ram_bytes: 0,
            loans: 0,
            incarnations: [None; super::super::MAX_ORIGINAL_NATIVE_NODE_GENERATIONS as usize],
            last_process_generation: 0,
        }
    }

    pub(super) fn issue(
        &mut self,
        process_generation: u64,
        guest_ram_bytes: u64,
        startup_bytes: u64,
        setup_mapping: SetupMappingRequest,
    ) -> Result<usize, InstalledProcessPurposeError> {
        if process_generation <= self.last_process_generation {
            return Err(InstalledProcessPurposeError::Identity);
        }
        let index = self
            .incarnations
            .iter()
            .position(Option::is_none)
            .ok_or(InstalledProcessPurposeError::Capacity)?;
        let loans = self
            .loans
            .checked_add(1)
            .filter(|count| *count <= super::super::MAX_ORIGINAL_NATIVE_NODE_GENERATIONS)
            .ok_or(InstalledProcessPurposeError::Capacity)?;
        let guest = self
            .live_guest_ram_bytes
            .checked_add(guest_ram_bytes)
            .ok_or(InstalledProcessPurposeError::Capacity)?;
        let pending = self
            .pending_startup_bytes
            .checked_sub(startup_bytes)
            .ok_or(InstalledProcessPurposeError::Capacity)?;
        let assigned = self
            .assigned_startup_bytes
            .checked_add(startup_bytes)
            .ok_or(InstalledProcessPurposeError::Capacity)?;

        self.incarnations[index] = Some(IncarnationAllocation {
            process_generation,
            guest_ram_bytes,
            startup_bytes,
            setup_mapping,
            borrower_closed: false,
            physical_retired: false,
        });
        self.loans = loans;
        self.live_guest_ram_bytes = guest;
        self.pending_startup_bytes = pending;
        self.assigned_startup_bytes = assigned;
        self.last_process_generation = process_generation;
        Ok(index)
    }

    pub(super) fn live_setup_mapping_bytes(&self) -> Result<u64, InstalledProcessPurposeError> {
        self.incarnations
            .iter()
            .flatten()
            .try_fold(0_u64, |total, allocation| {
                total
                    .checked_add(allocation.setup_mapping.backing_bytes())
                    .ok_or(InstalledProcessPurposeError::Capacity)
            })
    }

    pub(super) fn close_incarnation(
        &mut self,
        index: usize,
    ) -> Result<(), InstalledProcessPurposeError> {
        let allocation = self
            .incarnations
            .get(index)
            .copied()
            .flatten()
            .ok_or(InstalledProcessPurposeError::Identity)?;
        if !allocation.reusable() {
            return Ok(());
        }
        let loans = self
            .loans
            .checked_sub(1)
            .ok_or(InstalledProcessPurposeError::Capacity)?;
        let guest = self
            .live_guest_ram_bytes
            .checked_sub(allocation.guest_ram_bytes)
            .ok_or(InstalledProcessPurposeError::Capacity)?;
        let assigned = self
            .assigned_startup_bytes
            .checked_sub(allocation.startup_bytes)
            .ok_or(InstalledProcessPurposeError::Capacity)?;
        let pending = self
            .pending_startup_bytes
            .checked_add(allocation.startup_bytes)
            .ok_or(InstalledProcessPurposeError::Capacity)?;

        self.loans = loans;
        self.live_guest_ram_bytes = guest;
        self.assigned_startup_bytes = assigned;
        self.pending_startup_bytes = pending;
        self.incarnations[index] = None;
        Ok(())
    }
}

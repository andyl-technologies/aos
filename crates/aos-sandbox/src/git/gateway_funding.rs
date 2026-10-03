//! Funds one known-local transport entry and its actual original body backing.
//!
//! This private ledger uses the shared pure resource arithmetic. Its memory
//! charge covers Vec capacity plus one logical delivered-frame allowance, not
//! a frame's potentially larger shared H2 backing, allocator metadata, kernel
//! socket buffers, opaque TLS/H2 allocations, service RSS or Git quotas.

use std::collections::TryReserveError;

use aos_sandbox_core::{
    AccountingError, ReservationClass, ResourceBudget, ResourceCeilings,
    ResourceDimension, ResourceVector,
};

use super::http_owner::{FRAME_BYTES, MAXIMUM_BODY_BYTES};

/// Owns the one allocated backing; no caller bytes can construct it.
pub(super) struct FundedBodyBackingV1 {
    bytes: Vec<u8>,
}

impl FundedBodyBackingV1 {
    pub(super) fn into_vec(self) -> Vec<u8> {
        self.bytes
    }
}

#[derive(Clone, Copy)]
enum ChargeV1 {
    Reserved(ResourceVector),
    Committed(ResourceVector),
}

/// Retains the actual local allocation and charge until explicit disposal.
pub(super) struct GatewayFundingV1 {
    budget: ResourceBudget,
    charge: Option<ChargeV1>,
    backing: Option<FundedBodyBackingV1>,
    failed: bool,
}

/// Preserves the actual allocation/accounting source without quota authority.
#[derive(Debug, thiserror::Error)]
pub(super) enum GatewayFundingErrorV1 {
    #[error("local Gateway funding arithmetic failed")]
    Accounting(#[from] AccountingError),
    #[error("local Gateway original backing allocation failed")]
    Allocation(#[source] TryReserveError),
    #[error("local Gateway funding state is unavailable")]
    State,
    #[error("local Gateway original backing capacity is invalid")]
    Capacity,
}

impl GatewayFundingV1 {
    pub(super) fn new() -> Self {
        Self {
            budget: ResourceBudget::new(
                ResourceCeilings::bounded(closed_charge()),
                ResourceCeilings::bounded(ResourceVector::ZERO),
            ),
            charge: None,
            backing: None,
            failed: false,
        }
    }

    /// Reserves and allocates before polling the real listener.
    ///
    /// # Errors
    /// Retains any failed reservation/backing until explicit empty disposal.
    pub(super) fn prepare(&mut self) -> Result<(), GatewayFundingErrorV1> {
        if !self.is_vacant() {
            return Err(GatewayFundingErrorV1::State);
        }
        let amount = closed_charge();
        self.budget = self.budget.reserve(ReservationClass::Hard, amount)?;
        self.charge = Some(ChargeV1::Reserved(amount));
        self.backing = Some(FundedBodyBackingV1 { bytes: Vec::new() });

        let backing = self.backing.as_mut().ok_or(GatewayFundingErrorV1::State)?;
        backing.bytes.try_reserve_exact(MAXIMUM_BODY_BYTES)
            .map_err(GatewayFundingErrorV1::Allocation)?;
        // Vec may overallocate. The closed envelope never silently expands.
        if charge_for_capacity(backing.bytes.capacity())? != amount {
            return Err(GatewayFundingErrorV1::Capacity);
        }
        Ok(())
    }

    /// Commits only after the actual original entered registry custody.
    ///
    /// # Errors
    /// Preserves missing reservation or checked accounting failure.
    pub(super) fn commit(&mut self) -> Result<(), GatewayFundingErrorV1> {
        let Some(ChargeV1::Reserved(amount)) = self.charge else {
            return Err(GatewayFundingErrorV1::State);
        };
        self.budget = self.budget.commit(ReservationClass::Hard, amount)?;
        self.charge = Some(ChargeV1::Committed(amount));
        Ok(())
    }

    /// Moves the one backing only from a committed local entry.
    ///
    /// # Errors
    /// Rejects uncommitted state or a backing already transferred.
    pub(super) fn take_backing(&mut self) -> Result<FundedBodyBackingV1, GatewayFundingErrorV1> {
        if !matches!(self.charge, Some(ChargeV1::Committed(_))) {
            return Err(GatewayFundingErrorV1::State);
        }
        self.backing.take().ok_or(GatewayFundingErrorV1::State)
    }

    // A rejected park returns the SAME allocation, never a replacement.
    pub(super) fn restore_backing(&mut self, backing: FundedBodyBackingV1) {
        self.backing = Some(backing);
    }

    pub(super) fn is_vacant(&self) -> bool {
        !self.failed && self.charge.is_none() && self.backing.is_none()
    }

    /// Releases only after the registry destroyed all local original owners.
    ///
    /// Empty pre-accept cancellation is the only other caller. No live IO,
    /// peer clone, request loan, child, effect or remote reservation enters here.
    ///
    /// # Errors
    /// Latches checked release failure and never resets failed accounting.
    pub(super) fn release_destroyed(&mut self) -> Result<(), GatewayFundingErrorV1> {
        if self.failed {
            return Err(GatewayFundingErrorV1::State);
        }
        // Any backing not transferred into the connection is destroyed first.
        drop(self.backing.take());
        let result = match self.charge {
            Some(ChargeV1::Reserved(amount)) => {
                self.budget.release_reservation(ReservationClass::Hard, amount)
            }
            Some(ChargeV1::Committed(amount)) => {
                self.budget.release_committed(ReservationClass::Hard, amount)
            }
            None => return Ok(()),
        };
        match result {
            Ok(budget) => {
                self.budget = budget;
                self.charge = None;
                Ok(())
            }
            Err(cause) => {
                // A destroyed allocation does not justify an accounting reset.
                self.failed = true;
                Err(GatewayFundingErrorV1::Accounting(cause))
            }
        }
    }
}

fn closed_charge() -> ResourceVector {
    // Both fixed existing widths fit u32; this sum cannot overflow u64.
    ResourceVector::ZERO
        .with(ResourceDimension::ConcurrentOperations, 1)
        .with(ResourceDimension::OpenFiles, 2)
        .with(ResourceDimension::MemoryBytes, MAXIMUM_BODY_BYTES as u64 + FRAME_BYTES as u64)
}

fn charge_for_capacity(capacity: usize) -> Result<ResourceVector, GatewayFundingErrorV1> {
    let capacity = u64::try_from(capacity).map_err(|_| GatewayFundingErrorV1::Capacity)?;
    let memory = capacity.checked_add(FRAME_BYTES as u64)
        .ok_or(GatewayFundingErrorV1::Capacity)?;
    Ok(closed_charge().with(ResourceDimension::MemoryBytes, memory))
}

#[cfg(test)]
mod tests;

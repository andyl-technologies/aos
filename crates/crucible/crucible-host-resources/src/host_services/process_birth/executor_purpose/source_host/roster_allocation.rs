//! Funds the complete roster allocation through its final weak-reference free.
//!
//! An Arc retains its entire allocation after its value dies, not just two
//! counters. This independent Main loan covers that allocation and its own
//! shared control before roster birth. The gate seals nominal weak upgrades;
//! it supplies no operation, Source, process or native credit.
// SPDX-License-Identifier: Apache-2.0

use super::{
    Arc, AuthenticatedNativeSlotPurpose, AuthenticatedNativeSubdivision, HostOperationGuard,
    HostServiceLease, HostServiceLeasePair, RetainedControl, ServiceBirthError,
};
use crate::host_services::HostServiceError;
use std::sync::{Mutex, MutexGuard};

/// Keeps the complete roster allocation funded after its native body closes.
///
/// Every strong and weak roster wrapper must keep this same loan after its Arc
/// field. Cloning allocates nothing. Final loan destruction frees its own shared
/// control before returning either original Main counter reservation.
#[derive(Clone)]
pub struct NativeRosterAllocationFunding {
    held: RetainedControl<AllocationState>,
}

struct AllocationState {
    sealed: Mutex<bool>,
    _payer: AllocationPayer,
}

enum AllocationPayer {
    Main {
        _issuer: Arc<AuthenticatedNativeSlotPurpose>,
        _metadata: HostServiceLeasePair,
    },
    #[cfg(any(test, feature = "test-support"))]
    Component { _metadata: HostServiceLeasePair },
}

/// Excludes sealing while a nominal roster weak upgrade takes place.
///
/// This guard only synchronizes physical ownership. It grants no permission to
/// access a roster body or continue an operation.
pub struct NativeRosterUpgradeGate<'a> {
    _held: MutexGuard<'a, bool>,
}

impl NativeRosterUpgradeGate<'_> {
    /// Irreversibly seals upgrades after actual strong borrowers are excluded.
    ///
    /// The caller checks its real strong-owner count while holding this gate.
    /// Closing the gate returns no funding and certifies no body destruction.
    pub fn seal(mut self) {
        *self._held = true;
    }
}

impl std::fmt::Debug for NativeRosterAllocationFunding {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeRosterAllocationFunding")
            .finish_non_exhaustive()
    }
}

impl NativeRosterAllocationFunding {
    /// Opens the existing allocation's nominal weak-upgrade interval.
    ///
    /// The caller must perform its actual Arc upgrade while this guard lives.
    /// The containing roster still independently checks every semantic lender.
    ///
    /// # Errors
    /// Refuses a sealed allocation, contention or poisoned ownership.
    pub fn try_open(&self) -> Result<NativeRosterUpgradeGate<'_>, HostServiceError> {
        let held = self
            .held
            .sealed
            .try_lock()
            .map_err(|_| HostServiceError::Unavailable)?;
        if *held {
            return Err(HostServiceError::Unavailable);
        }
        Ok(NativeRosterUpgradeGate { _held: held })
    }

    /// Constructs an allocation-only component payer from real paired charges.
    ///
    /// This fixture issues no authenticated Main, Source, native account or
    /// roster admission. Production roster publication obtains its funding only
    /// through the genuine native subdivision below.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn component_payer(metadata: HostServiceLeasePair) -> Self {
        construct(AllocationPayer::Component {
            _metadata: metadata,
        })
    }
}

impl AuthenticatedNativeSubdivision {
    /// Prepays complete roster storage outside its native account lifetime.
    ///
    /// The actual same Main reserves both original counters before any shared
    /// funding control or roster allocation is born. The supplied extent is a
    /// price, not a grant. It must include the complete retained Arc allocation,
    /// including value storage that remains reserved while Weak handles exist.
    /// This creates no Source or native reservation and starts no operation.
    ///
    /// # Errors
    /// Refuses another or expired Preparation, changed Main custody, zero or
    /// overflowing extent, exhausted original counters, or independent post.
    /// A post refusal destroys only the not-yet-published funding control before
    /// returning its charge; no roster has been allocated at that point.
    pub fn reserve_roster_allocation(
        &self,
        allocation_bytes: u64,
        original: &Arc<HostOperationGuard>,
    ) -> Result<NativeRosterAllocationFunding, ServiceBirthError> {
        self.verify_native_preparation(original)?;
        self.check()?;
        let extent = funding_extent(allocation_bytes)?;
        let metadata = self
            .owner
            .owner
            .reserve_metadata(extent)
            .map_err(ServiceBirthError::from)?;

        let funding = construct(AllocationPayer::Main {
            _issuer: Arc::clone(&self.owner),
            _metadata: metadata,
        });
        self.verify_native_preparation(original)?;
        Ok(funding)
    }
}

fn funding_extent(allocation_bytes: u64) -> Result<u64, ServiceBirthError> {
    let (layout, _) = std::alloc::Layout::new::<(
        std::sync::atomic::AtomicUsize,
        std::sync::atomic::AtomicUsize,
    )>()
    .extend(std::alloc::Layout::new::<AllocationState>())
    .map_err(|_| ServiceBirthError::from(HostServiceError::Unavailable))?;
    u64::try_from(layout.pad_to_align().size())
        .ok()
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<AllocationState>() as u64))
        .and_then(|bytes| bytes.checked_add(2 * HostServiceLease::metadata_bytes()))
        .and_then(|bytes| bytes.checked_add(allocation_bytes))
        .filter(|_| allocation_bytes != 0)
        .ok_or_else(|| ServiceBirthError::from(HostServiceError::Unavailable))
}

fn construct(payer: AllocationPayer) -> NativeRosterAllocationFunding {
    NativeRosterAllocationFunding {
        held: RetainedControl::new(AllocationState {
            sealed: Mutex::new(false),
            _payer: payer,
        }),
    }
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- component controls panic only on failed real allocation, paired-charge or upgrade-exclusion assertions; they issue no native authority.
#[allow(clippy::unwrap_used)]
mod tests;

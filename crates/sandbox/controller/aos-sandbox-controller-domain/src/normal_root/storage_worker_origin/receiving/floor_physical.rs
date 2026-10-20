//! Keeps physical floor programs on the same original Storage F ledger.
//!
//! A program receipt proves only the actual debit and intrinsic pair binding.
//! It creates no native helper, TPM observation, current floor or method grant.
//! The private physical engine retains its independent native originals. Losing
//! an issued receipt leaves the real F program outstanding and cannot refund it.

use super::*;
use aos_sandbox_model::{AccountingError, component_receiving::complete_bound_delta_v1};
use aos_sandbox_linux::cgroup::StorageCgroupLayoutV1;
use crate::journal::StorageNativeOpeningOwnerLinkV1;

#[derive(Clone, Copy)]
enum First { Binding, Growth, Debit, Finish }

pub(super) struct StorageFloorPhysicalReceivingOriginalV2 {
    bound: ResourceVector,
    serial: u64,
    outstanding: bool,
    binding: Option<Result<(), StorageReceivingClosedV1>>,
    growth: Option<Result<(ResourceVector, ResourceVector, u64), AccountingError>>,
    debit: Option<Result<(), AccountingError>>,
    finish: Option<Result<(), StorageReceivingClosedV1>>,
    first: Option<First>,
}

impl StorageFloorPhysicalReceivingOriginalV2 {
    pub(super) const fn new() -> Self {
        Self {
            bound: ResourceVector::ZERO, serial: 0, outstanding: false,
            binding: None, growth: None, debit: None, finish: None, first: None,
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::Binding => self.binding.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Growth => self.growth.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Debit => self.debit.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Finish => self.finish.as_ref()?.as_ref().err().map(|cause| cause as _),
        }
    }
}

/// Keeps one actual paid program bound to the original captured writer pair.
///
/// Construction requires the real F, its own positive native sidecar take and
/// actual launch-image association. This receipt supplies financial comparison
/// only; the sole physical engine separately authenticates every TPM response,
/// retains native posts and gates Required readiness. It cannot be cloned.
#[must_use = "retain this debit through the whole physical program and its native disposition"]
pub struct StorageFloorPhysicalProgramReceivingV2 {
    main: StorageNativeOpeningOwnerLinkV1,
    sidecar: StorageNativeOpeningOwnerLinkV1,
    serial: u64,
    layout: StorageCgroupLayoutV1,
}

impl StorageFloorPhysicalProgramReceivingV2 {
    /// Compares this debit's actual writer identities without observing native IO.
    ///
    /// # Errors
    /// Refuses another main or sidecar, including a pair alias.
    pub fn require_held_pair_v2(&self, main: &crate::Journal, sidecar: &crate::Journal)
        -> Result<(), StorageReceivingClosedV1>
    {
        if self.main.same_journal(main) && self.sidecar.same_journal(sidecar)
            && !self.main.same_journal(sidecar)
        { Ok(()) } else { Err(StorageReceivingClosedV1) }
    }

    /// Borrows the layout from the actual original launch-image association.
    ///
    /// This DATA supplies no service currentness, process or scheduling grant.
    #[must_use]
    pub fn associated_layout_data_v2(&self) -> StorageCgroupLayoutV1 { self.layout }
}

impl StoragePrepareReceivingLoanV1<'_> {
    /// Prepays one finite complete physical program before its native entrance.
    ///
    /// The actual producer includes all already-spent wire/log/output amounts
    /// in its complete demand. Capture and physical representation are distinct
    /// ledger planes; one cannot consume the other's retained capacity. The
    /// fixed receipt constructor is reused at high water, never added per call.
    ///
    /// # Errors
    /// Retains missing actual sidecar/image association, overlap, arithmetic or
    /// same-F refusal. A failed or forgotten program cannot be replaced.
    pub fn begin_floor_physical_program_v2(&mut self, main: &crate::Journal,
        sidecar: &crate::Journal, complete: ResourceVector)
        -> Result<StorageFloorPhysicalProgramReceivingV2, StorageReceivingClosedV1>
    {
        let receiving = self.receiving()?;
        let layout = receiving.launch_association.completed_layout_v2();
        let matches = receiving.session_identity.as_ref().is_some_and(|identity| identity.same_journal(main))
            && receiving.floor_capture.matches_taken_pair_v2(main, sidecar)
            && layout.is_some();
        let floor = &mut receiving.floor_physical;
        if floor.first.is_some() { return Err(StorageReceivingClosedV1); }
        floor.binding = Some(if matches && !floor.outstanding {
            Ok(())
        } else { Err(StorageReceivingClosedV1) });
        if !matches!(floor.binding, Some(Ok(()))) {
            floor.first = Some(First::Binding);
            receiving.first.get_or_insert(Failure::FloorPhysical);
            return Err(StorageReceivingClosedV1);
        }
        floor.growth = Some((|| {
            let bytes = std::mem::size_of::<StorageFloorPhysicalProgramReceivingV2>()
                .checked_mul(2).and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or(AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes })?;
            let requirement = complete.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))?;
            let (bound, delta) = complete_bound_delta_v1(floor.bound, requirement)?;
            let serial = floor.serial.checked_add(1)
                .ok_or(AccountingError::ArithmeticOverflow { dimension: D::ConcurrentOperations })?;
            Ok((bound, delta, serial))
        })());
        let Some(Ok((bound, delta, serial))) = floor.growth.as_ref() else {
            floor.first = Some(First::Growth);
            receiving.first.get_or_insert(Failure::FloorPhysical);
            return Err(StorageReceivingClosedV1);
        };
        let (bound, delta, serial) = (*bound, *delta, *serial);
        floor.debit = Some(receiving.ledger.reserve(delta).map_err(|cause| *cause));
        if !matches!(floor.debit, Some(Ok(()))) {
            floor.first = Some(First::Debit);
            receiving.first.get_or_insert(Failure::FloorPhysical);
            return Err(StorageReceivingClosedV1);
        }
        let Some(layout) = layout else { return Err(StorageReceivingClosedV1); };
        floor.bound = bound;
        floor.serial = serial;
        floor.outstanding = true;
        floor.finish = None;
        Ok(StorageFloorPhysicalProgramReceivingV2 {
            main: main.held_session_owner_link_v1(),
            sidecar: sidecar.held_session_owner_link_v1(),
            serial,
            layout,
        })
    }

    /// Returns the same financial receipt after the native program's disposition.
    ///
    /// The private native caller separately owns that positive disposition.
    /// This method performs no IO and grants no floor, effect or readiness;
    /// charged resident high water and cumulative traffic are never refunded.
    ///
    /// # Errors
    /// Refuses another receipt, a stale pair, missing outstanding program or any
    /// original failure. The caller must retain a rejected receipt on its owner.
    pub fn finish_floor_physical_program_v2(&mut self, receipt: &StorageFloorPhysicalProgramReceivingV2,
        main: &crate::Journal, sidecar: &crate::Journal)
        -> Result<(), StorageReceivingClosedV1>
    {
        let receiving = self.receiving()?;
        let floor = &mut receiving.floor_physical;
        if floor.first.is_some() { return Err(StorageReceivingClosedV1); }
        floor.finish = Some(if floor.outstanding && floor.serial == receipt.serial
            && receipt.require_held_pair_v2(main, sidecar).is_ok()
            && receiving.session_identity.as_ref().is_some_and(|identity| identity.same_journal(main))
            && receiving.floor_capture.matches_taken_pair_v2(main, sidecar)
        { Ok(()) } else { Err(StorageReceivingClosedV1) });
        if !matches!(floor.finish, Some(Ok(()))) {
            floor.first = Some(First::Finish);
            receiving.first.get_or_insert(Failure::FloorPhysical);
            return Err(StorageReceivingClosedV1);
        }
        floor.outstanding = false;
        Ok(())
    }
}

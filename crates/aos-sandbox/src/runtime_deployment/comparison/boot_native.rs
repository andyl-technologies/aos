//! Retains the normal publisher's finite prepaid current-boot observations.
//!
//! This owner borrows actual normal Origins and their Source. No request, boot
//! scalar, deadline, descriptor, native permission or preimage enters its sole
//! constructor. Current-boot checks grant no journal or physical-floor effect.

use std::cell::{Cell, RefCell};
use std::fmt;

use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::boot::RootOriginalKernelBootIdAttemptV1;

use super::super::RuntimeDeploymentOriginalClockCauseV3;
use super::*;

// Every reached native action has a finite closed caller. Exhaustion refuses
// before another native read; it cannot turn this cap into fresh Source funds.
const MAXIMUM_OBSERVATIONS: usize = 128;
const MAXIMUM_OWED_OBSERVATIONS: usize = 32;
const TOTAL_OBSERVATIONS: usize = MAXIMUM_OBSERVATIONS + MAXIMUM_OWED_OBSERVATIONS;

#[derive(Clone, Copy)]
enum FirstNative {
    Clock(usize),
    Outer,
}

/// Retains actual Source-bound current-boot observations for one normal actor.
///
/// Each native destination is prepaid and parked before the first effect. Even
/// after a prior observation refuses, later owed checks still use the remaining
/// already paid destinations. This owner grants neither NV nor publication.
#[must_use = "retain this entire normal original through the last owed check"]
pub struct RuntimeBootPreparationNativeOriginalV1<'origin, 'startup> {
    origins: &'origin RuntimeDeploymentComparisonOriginsV1<'startup>,
    boot: [u8; 16],
    observations: RefCell<Vec<RootOriginalKernelBootIdAttemptV1>>,
    allocation: RefCell<Option<Result<(), std::collections::TryReserveError>>>,
    prepare_attempted: Cell<bool>,
    prepared: Cell<bool>,
    next: Cell<usize>,
    next_owed: Cell<usize>,
    first: Cell<Option<FirstNative>>,
    outer_next: Cell<usize>,
    outer_pending: Cell<Option<(usize, usize)>>,
    outer_credentials_entered: Cell<u32>,
    outer_credentials: RefCell<[Option<Result<(), RuntimeDeploymentComparisonErrorV1>>; MAXIMUM_OWED_OBSERVATIONS]>,
    outer_startup: RefCell<[Option<Result<(), super::super::RuntimeBootPreparationStartupClosedV1>>; MAXIMUM_OWED_OBSERVATIONS]>,
    exhausted: Cell<bool>,
}

impl<'origin, 'startup> RuntimeBootPreparationNativeOriginalV1<'origin, 'startup> {
    pub(super) fn new(
        origins: &'origin RuntimeDeploymentComparisonOriginsV1<'startup>,
    ) -> Result<Self, RuntimeDeploymentComparisonErrorV1> {
        origins.recheck()?;
        let startup = origins
            .genesis
            .startup()
            .boot()
            .ok_or(NvCustodyErrorV1::Provisioning)?;
        let demand = (|| {
            let each = RootOriginalKernelBootIdAttemptV1::dominant_requested_bytes_v1()?;
            let memory = std::mem::size_of::<Self>()
                .checked_mul(2)?
                .checked_add(each.checked_mul(TOTAL_OBSERVATIONS)?)?
                .checked_add(std::mem::size_of::<RootOriginalKernelBootIdAttemptV1>())?;
            Some(
                ResourceVector::ZERO
                    .with(D::MemoryBytes, u64::try_from(memory).ok()?)
                    .with(
                        D::OpenFiles,
                        u64::try_from(TOTAL_OBSERVATIONS.checked_mul(
                            RootOriginalKernelBootIdAttemptV1::MAXIMUM_RETAINED_FILES_V1,
                        )?)
                        .ok()?,
                    )
                    .with(
                        D::MetadataEntries,
                        u64::try_from(TOTAL_OBSERVATIONS.checked_mul(
                            RootOriginalKernelBootIdAttemptV1::receiving_metadata_cells_v1(),
                        )?)
                        .ok()?,
                    )
                    .with(
                        D::OutputBytes,
                        u64::try_from(TOTAL_OBSERVATIONS.checked_mul(
                            RootOriginalKernelBootIdAttemptV1::maximum_requested_read_bytes_v2(),
                        )?)
                        .ok()?,
                    ),
            )
        })();
        startup.fund_additional(demand)?;
        let boot = startup.origin_data_v1()?.boot;
        Ok(Self {
            origins,
            boot,
            observations: RefCell::new(Vec::new()),
            allocation: RefCell::new(None),
            prepare_attempted: Cell::new(false),
            prepared: Cell::new(false),
            next: Cell::new(0),
            next_owed: Cell::new(0),
            first: Cell::new(None),
            outer_next: Cell::new(0),
            outer_pending: Cell::new(None),
            outer_credentials_entered: Cell::new(0),
            outer_credentials: RefCell::new(std::array::from_fn(|_| None)),
            outer_startup: RefCell::new([None; MAXIMUM_OWED_OBSERVATIONS]),
            exhausted: Cell::new(false),
        })
    }

    /// Parks all prepaid finite native destinations before any clock read.
    ///
    /// # Errors
    /// Retains allocation failure and refuses borrowing conflicts or reentry.
    /// No failed preparation can produce a positive current-boot observation.
    pub fn prepare_once_v1(&self) -> Result<(), RuntimeDeploymentOriginalClockCauseV3> {
        if self.prepare_attempted.replace(true) {
            self.exhausted.set(true);
            return Err(RuntimeDeploymentOriginalClockCauseV3::Changed);
        }
        let mut observations = self
            .observations
            .try_borrow_mut()
            .map_err(|_| RuntimeDeploymentOriginalClockCauseV3::Changed)?;
        let mut allocation = self
            .allocation
            .try_borrow_mut()
            .map_err(|_| RuntimeDeploymentOriginalClockCauseV3::Changed)?;
        *allocation = Some(observations.try_reserve_exact(TOTAL_OBSERVATIONS));
        if !matches!(*allocation, Some(Ok(()))) {
            self.exhausted.set(true);
            return Err(RuntimeDeploymentOriginalClockCauseV3::Changed);
        }
        for _ in 0..TOTAL_OBSERVATIONS {
            observations.push(RootOriginalKernelBootIdAttemptV1::new());
        }
        self.prepared.set(true);
        Ok(())
    }

    /// Compares a prepaid actual kernel observation with this Source's boot.
    ///
    /// This deliberately does not call the Source's healthy/debit gate. It is
    /// also used for independently owed terminal checks after a body refusal.
    /// The caller must separately hold healthy current Origins before effects.
    ///
    /// # Errors
    /// Refuses exhausted destinations, borrowing conflict, any original read or
    /// parse failure, changed boot, or an earlier retained observation failure.
    pub fn require_clock(&self) -> Result<(), RuntimeDeploymentOriginalClockCauseV3> {
        let index = self.next.get();
        if !self.prepared.get() || index >= MAXIMUM_OBSERVATIONS {
            self.exhausted.set(true);
            return Err(RuntimeDeploymentOriginalClockCauseV3::Changed);
        }
        self.next.set(index + 1);
        self.observe(index)
    }

    /// Runs a separately prepaid terminal observation after any body refusal.
    ///
    /// Primary retry exhaustion cannot consume these distinct destinations.
    /// The fixed finite actor retains this owner through its last owed post.
    ///
    /// # Errors
    /// Refuses exhausted terminal destinations, absent preparation, borrowing
    /// conflicts, a failed read, changed boot or any prior sticky refusal.
    pub fn require_clock_owed_once_v1(&self) -> Result<(), RuntimeDeploymentOriginalClockCauseV3> {
        let owed = self.next_owed.get();
        if !self.prepared.get() || owed >= MAXIMUM_OWED_OBSERVATIONS {
            self.exhausted.set(true);
            return Err(RuntimeDeploymentOriginalClockCauseV3::Changed);
        }
        self.next_owed.set(owed + 1);
        self.observe(MAXIMUM_OBSERVATIONS + owed)
    }

    fn observe(&self, index: usize) -> Result<(), RuntimeDeploymentOriginalClockCauseV3> {
        let mut observations = self
            .observations
            .try_borrow_mut()
            .map_err(|_| RuntimeDeploymentOriginalClockCauseV3::Changed)?;
        let original = observations
            .get_mut(index)
            .ok_or(RuntimeDeploymentOriginalClockCauseV3::Changed)?;
        let same = match original.observe_once() {
            Ok(boot) => boot.into_bytes() == self.boot,
            Err(_) => false,
        };
        if !same {
            self.first.set(self.first.get().or(Some(FirstNative::Clock(index))));
        }
        if self.first.get().is_some() || self.exhausted.get() {
            Err(RuntimeDeploymentOriginalClockCauseV3::Changed)
        } else {
            Ok(())
        }
    }

    /// Borrows the same normal comparison owner without extracting any input.
    #[must_use]
    pub fn origins_v1(&self) -> &RuntimeDeploymentComparisonOriginsV1<'startup> {
        self.origins
    }

    /// Reserves a distinct same-Source startup after before a native operation.
    ///
    /// This creates only a prepaid original destination. It grants no healthy
    /// startup, signing, TPM, writer, generation or successful currentness loan.
    ///
    /// # Errors
    /// Refuses a foreign/non-normal origin, pending/repeated entry, exhausted
    /// fixed destinations, or the original Source financial/allocation cause.
    pub fn begin_outer_startup_after_v1(&self) -> Result<(), RuntimeDeploymentComparisonErrorV1> {
        let slot = self.outer_next.get();
        if !self.prepared.get() || self.outer_pending.get().is_some()
            || slot >= MAXIMUM_OWED_OBSERVATIONS || self.first.get().is_some()
        {
            return Err(NvCustodyErrorV1::Provisioning.into());
        }
        self.outer_next.set(slot + 1);
        match self.origins.genesis.prepare_boot_outer_recheck_v1() {
            Ok(index) => { self.outer_pending.set(Some((slot, index))); Ok(()) }
            Err(cause) => {
                self.first.set(self.first.get().or(Some(FirstNative::Outer)));
                self.outer_credentials.try_borrow_mut().map_err(|_| NvCustodyErrorV1::Provisioning)?[slot] = Some(Err(cause));
                Err(NvCustodyErrorV1::Provisioning.into())
            }
        }
    }

    /// Observes the already parked outer after without a new Source debit.
    ///
    /// An earlier operation or Source failure cannot skip the actual native
    /// body and its independent subposts. An absent pending lane does no IO;
    /// callers use the same method to finish an interrupted operation once.
    ///
    /// # Errors
    /// Preserves the actual retained startup refusal or borrowing/order error.
    /// This observation never clears prior failure or issues positive authority.
    pub fn finish_outer_startup_after_owed_once_v1(&self) -> Result<(), RuntimeDeploymentOriginalClockCauseV3> {
        let Some((slot, index)) = self.outer_pending.get() else { return Ok(()); };
        let mut credentials = self.outer_credentials.try_borrow_mut().map_err(|_| RuntimeDeploymentOriginalClockCauseV3::Changed)?;
        if credentials[slot].is_none() {
            // Hold the destination before native entry, so a returned result
            // parks without another fallible borrow or allocation. Unwinding
            // selects the actual same-custody negative drain, which resumes
            // only unentered native groups and cannot restore healthy custody.
            let bit = 1_u32.checked_shl(u32::try_from(slot).map_err(|_| RuntimeDeploymentOriginalClockCauseV3::Changed)?)
                .ok_or(RuntimeDeploymentOriginalClockCauseV3::Changed)?;
            let interrupted = self.outer_credentials_entered.get() & bit != 0;
            self.outer_credentials_entered.set(self.outer_credentials_entered.get() | bit);
            credentials[slot] = Some(if interrupted {
                self.origins.genesis.drain_boot_credential_recheck_after_unwind_once_v1()
            } else {
                self.origins.genesis.observe_boot_credential_recheck_owed_once_v1()
            });
        }
        let credential_failed = !matches!(credentials[slot], Some(Ok(())));
        drop(credentials);
        let mut startup = self.outer_startup.try_borrow_mut().map_err(|_| RuntimeDeploymentOriginalClockCauseV3::Changed)?;
        if startup[slot].is_none() {
            startup[slot] = Some(self.origins.genesis.observe_boot_startup_recheck_owed_once_v1(index));
        }
        let failed = credential_failed || !matches!(startup[slot], Some(Ok(())));
        drop(startup);
        if failed { self.first.set(self.first.get().or(Some(FirstNative::Outer))); }
        self.outer_pending.set(None);
        if failed { Err(RuntimeDeploymentOriginalClockCauseV3::Changed) } else { Ok(()) }
    }

    /// Borrows a formatter for the actual first retained kernel-read cause.
    #[must_use]
    pub fn failure_view_v1(
        &self,
    ) -> RuntimeBootPreparationNativeFailureViewV1<'_, 'origin, 'startup> {
        RuntimeBootPreparationNativeFailureViewV1(self)
    }
}

/// Formats a retained kernel failure without moving its native owner.
pub struct RuntimeBootPreparationNativeFailureViewV1<'a, 'origin, 'startup>(
    &'a RuntimeBootPreparationNativeOriginalV1<'origin, 'startup>,
);

impl fmt::Display for RuntimeBootPreparationNativeFailureViewV1<'_, '_, '_> {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Ok(allocation) = self.0.allocation.try_borrow() {
            if let Some(Err(cause)) = allocation.as_ref() {
                return write!(output, "{cause}");
            }
        }
        if let Some(FirstNative::Clock(index)) = self.0.first.get() {
            if let Ok(observations) = self.0.observations.try_borrow() {
                if let Some(cause) = observations
                    .get(index)
                    .and_then(|original| original.failure())
                {
                    return write!(output, "{cause}");
                }
            }
        }
        if matches!(self.0.first.get(), Some(FirstNative::Outer)) {
            if let Ok(results) = self.0.outer_credentials.try_borrow() {
                if let Some(cause) = results.iter().filter_map(Option::as_ref).find_map(|result| result.as_ref().err()) {
                    if !matches!(&cause.cause, ComparisonFailureV1::BootStartup(_)) {
                        let mut current: &(dyn std::error::Error + 'static) = cause;
                        write!(output, "{current}")?;
                        while let Some(next) = current.source() {
                            write!(output, ": {next}")?;
                            current = next;
                        }
                        return Ok(());
                    }
                }
            }
            if let Some(startup) = self.0.origins.genesis.startup().boot() {
                return write!(output, "{}", startup.failure_view_v1());
            }
        }
        output.write_str("normal publisher current-boot original is incomplete or refused")
    }
}

impl<'startup> RuntimeDeploymentComparisonOriginsV1<'startup> {
    /// Prepays a finite actual normal native-clock owner on the same Source.
    ///
    /// # Errors
    /// Refuses another purpose, current Source/input drift, geometry, receiving
    /// exhaustion or allocation failure before any native clock observation.
    pub fn prepare_boot_native_original_v1<'origin>(
        &'origin self,
    ) -> Result<
        RuntimeBootPreparationNativeOriginalV1<'origin, 'startup>,
        RuntimeDeploymentComparisonErrorV1,
    > {
        RuntimeBootPreparationNativeOriginalV1::new(self)
    }
}

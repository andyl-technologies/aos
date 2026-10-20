//! Owns the healthy Stop challenge on its genuine same-B Source interval.
//!
//! Kernel entropy and its trailing native pair are prepaid before entry. The
//! existing protected absence/challenge recipe binds the captured Source row
//! and projection; neither nonce nor caller DATA creates effect permission.

use super::*;
use aos_sandbox_broker::{bounded_entropy::RetainedKernelNonceOriginalV1,
    kernel_clock::RetainedKernelPairedClockAttemptV1};
use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use aos_sandbox_core::{RawPairedClockSample, OwnershipLeaseVerificationError};
use crate::lifecycle::{LifecycleBootInventoryBootstrapChallengeV1, LifecycleProtectedJournalErrorV1,
    CurrentLifecycleEffectV1, LifecycleSuspensionPlanV1};

type Pair = RetainedKernelPairedClockAttemptV1<SourceGenesisErrorV1>;

#[derive(Default)]
pub(super) struct StopInventoryChallengeOriginalV5 {
    entered: bool,
    nonce: [RetainedKernelNonceOriginalV1; 2],
    clock: Pair,
    sample: Option<std::result::Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    continuity: Option<std::result::Result<(), OwnershipLeaseVerificationError>>,
    challenge: Option<std::result::Result<LifecycleBootInventoryBootstrapChallengeV1, LifecycleProtectedJournalErrorV1>>,
    closed: Option<ResourceReservationErrorV1>,
}

impl StopInventoryChallengeOriginalV5 {
    fn demand_v5() -> Result<ResourceVector> {
        let bytes = std::mem::size_of::<Self>().checked_mul(2)
            .and_then(|n| n.checked_add(RetainedKernelNonceOriginalV1::construction_bytes_v1()?.checked_mul(2)?))
            .and_then(|n| n.checked_add(Pair::dominant_requested_bytes_v1()?))
            .and_then(|n| n.checked_add(crate::lifecycle::stop_inventory_challenge_receiving_bytes_v5()?))
            .and_then(|n| u64::try_from(n).ok()).ok_or(ResourceReservationErrorV1::Conflict)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes)
            .with(D::OpenFiles, u64::try_from(Pair::MAXIMUM_RETAINED_FILES_V1).map_err(|_| ResourceReservationErrorV1::Conflict)?)
            .with(D::MetadataEntries, u64::try_from(Pair::receiving_metadata_cells_v1().ok_or(ResourceReservationErrorV1::Conflict)?).map_err(|_| ResourceReservationErrorV1::Conflict)?))
    }

    fn observe_once_v5(&mut self, source: &source::StopSourceTurnOriginalV4) -> Result<()> {
        if self.entered { self.closed.get_or_insert(ResourceReservationErrorV1::Conflict); return Err(ResourceReservationErrorV1::Conflict); }
        self.entered = true;
        let before = source.sample_data_v4()?;
        let first = self.nonce[0].observe_once();
        let second = if first.is_ok() { Some(self.nonce[1].observe_once()) } else { None };
        // Once entropy enters, its genuine same-baseline trailing pair is owed
        // independently, including partial/random-source refusal.
        self.sample = Some(self.clock.observe_once(Some(before)));
        if let Some(Ok(sample)) = self.sample.as_ref() {
            self.continuity = Some(before.validate_later_sample(*sample));
        }
        if let (Ok(first), Some(Ok(second)), Some(Ok(sample)), Some(Ok(()))) =
            (first, second, self.sample.as_ref(), self.continuity.as_ref()) {
            let mut nonce = [0; 32];
            nonce[..16].copy_from_slice(&first);
            nonce[16..].copy_from_slice(&second);
            self.challenge = Some(source.inventory_challenge_data_v5(nonce, sample.host_boot_id()));
        }
        if self.completed_v5().is_some() { Ok(()) }
        else { Err(ResourceReservationErrorV1::Conflict) }
    }

    fn completed_v5(&self) -> Option<LifecycleBootInventoryBootstrapChallengeV1> {
        if self.closed.is_some() || self.nonce.iter().any(|original| original.failure().is_some())
            || !matches!(self.continuity, Some(Ok(()))) { return None; }
        self.challenge.as_ref()?.as_ref().ok().copied()
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.nonce.iter().find_map(RetainedKernelNonceOriginalV1::failure)
            .or_else(|| self.clock.failure())
            .or_else(|| self.sample.as_ref()?.as_ref().err().map(|e| e as _))
            .or_else(|| self.continuity.as_ref()?.as_ref().err().map(|e| e as _))
            .or_else(|| self.challenge.as_ref()?.as_ref().err().map(|e| e as _))
            .or_else(|| self.closed.as_ref().map(|e| e as _))
    }
}

impl ControllerLifecycleStopOriginalV4 {
    /// Prices the actual native challenge before any healthy Stop preparation.
    ///
    /// # Errors
    /// Refuses checked geometry overflow; this DATA grants no work or effect.
    pub fn inventory_preparation_demand_v5() -> Result<ResourceVector> {
        StopInventoryChallengeOriginalV5::demand_v5()
    }

    /// Prepares the same protected challenge before the actual signed Stop.
    ///
    /// # Errors
    /// Retains currentness, kernel entropy, elapsed-pair or protected absence refusal.
    pub fn prepare_inventory_challenge_once_v5(&mut self, controller: &Journal) -> Result<()> {
        self.require_host_stop_current_v4(controller)?;
        self.inventory.observe_once_v5(&self.host_turn)
    }

    /// Borrows only a completed challenge from its actual native owner.
    ///
    /// # Errors
    /// Refuses a changed Source/B interval or incomplete native bookend.
    pub fn inventory_challenge_v5(&self, controller: &Journal) -> Result<LifecycleBootInventoryBootstrapChallengeV1> {
        self.require_host_stop_current_v4(controller)?;
        self.inventory.completed_v5().ok_or(ResourceReservationErrorV1::Conflict)
    }

    /// Lends the exact reserved Stop effect only for this immediate consumer.
    ///
    /// # Errors
    /// Refuses a stale actual Source/B interval or changed reserved Stop step.
    pub fn with_host_stop_effect_v5<T>(&self, controller: &Journal,
        use_effect: impl for<'effect> FnOnce(CurrentLifecycleEffectV1<'effect>) -> T,
    ) -> Result<T> {
        self.require_host_stop_current_v4(controller)?;
        let current = self.host_turn.current_host_operation_v4().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let effect = LifecycleSuspensionPlanV1::stop(&current).map_err(|_| ResourceReservationErrorV1::Conflict)?
            .next_effect(&current).map_err(|_| ResourceReservationErrorV1::Conflict)?;
        Ok(use_effect(effect))
    }
}

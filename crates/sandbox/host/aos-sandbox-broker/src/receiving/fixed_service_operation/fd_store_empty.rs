//! Pays finite same-service descriptor-store absence on the real F interval.
//!
//! The SDK and raw manager engines remain shared with ordinary Network Store
//! observations. Only the actual Mount16 or Network19 loan selects this owner;
//! saved descriptors, changed recipient, native refusal and ambiguity stay held.

use super::*;
use aos_sandbox_model::{OwnershipLeaseVerificationError, RawPairedClockSample};
use crate::kernel_clock::{KernelPairedClockErrorV1, RetainedKernelPairedClockAttemptV1};
use aos_systemd_client::fd_store::{NetworkFdStoreInspectionOriginalV4 as Sdk,
    NetworkFdStoreInspectionRefusalV4, NetworkFdStoreFailureViewV4};

#[derive(Clone, Copy)]
enum Role { Mount, Network }

#[derive(Clone, Copy)]
enum First { Current, Shape, Funding, Horizon, Clock, Connect, Before, BeforeComparison, After, AfterComparison, PopulationBefore, PopulationAfter, Order }

type PopulationClockAttempt = RetainedKernelPairedClockAttemptV1<PopulationClockError>;

#[derive(Debug, thiserror::Error)]
enum PopulationClockError {
    #[error("fixed-service inventory population clock is not current")]
    Stale,
    #[error(transparent)]
    Kernel(aos_sandbox_linux::Error),
    #[error(transparent)]
    Continuity(OwnershipLeaseVerificationError),
}

impl KernelPairedClockErrorV1 for PopulationClockError {
    fn stale() -> Self { Self::Stale }
    fn kernel(error: aos_sandbox_linux::Error) -> Self { Self::Kernel(error) }
}

/// Retains both paid descriptor-store observations and their exact SDK sources.
///
/// This owner supplies no descriptor, effect, refund or ordinary enrollment.
#[must_use = "retain every native/SDK prefix through the enclosing F posts"]
pub struct FixedServiceInventoryFdStoreEmptyOriginalV2 {
    role: Option<Role>,
    ordinal: Option<u64>,
    invocation: Option<[u8; 16]>,
    current: Option<Result<(), FixedServiceOperationClosedV4>>,
    shape: Option<Result<ResourceVector, AccountingError>>,
    funding: Option<Result<(), FixedServiceOperationClosedV4>>,
    horizon: Option<Result<(aos_sandbox_model::RawPairedClockSample, u64, Option<i64>), FixedServiceOperationClosedV4>>,
    clock: Option<rustix::time::Timespec>,
    clock_comparison: Option<Result<tokio::time::Instant, FixedServiceOperationClosedV4>>,
    sdk: Option<Sdk>,
    connect: Option<Result<(), NetworkFdStoreInspectionRefusalV4>>,
    before: Option<Result<(), NetworkFdStoreInspectionRefusalV4>>,
    before_comparison: Option<Result<(u32, [u8; 16]), FixedServiceOperationClosedV4>>,
    after: Option<Result<(), NetworkFdStoreInspectionRefusalV4>>,
    after_comparison: Option<Result<(), FixedServiceOperationClosedV4>>,
    population_before: PopulationClockAttempt,
    population_before_result: Option<Result<RawPairedClockSample, PopulationClockError>>,
    population_after: PopulationClockAttempt,
    population_after_result: Option<Result<RawPairedClockSample, PopulationClockError>>,
    first: Option<First>,
    closed: FixedServiceOperationClosedV4,
}

impl Default for FixedServiceInventoryFdStoreEmptyOriginalV2 {
    fn default() -> Self {
        Self { role: None, ordinal: None, invocation: None, current: None, shape: None,
            funding: None, horizon: None, clock: None, clock_comparison: None, sdk: None,
            connect: None, before: None, before_comparison: None, after: None,
            after_comparison: None, population_before: Default::default(), population_before_result: None,
            population_after: Default::default(), population_after_result: None,
            first: None, closed: FixedServiceOperationClosedV4 }
    }
}

impl FixedServiceInventoryFdStoreEmptyOriginalV2 {
    pub(super) fn network_worker_context_v4(&self, ordinal: Option<u64>, invocation: Option<[u8; 16]>)
        -> Result<(&Sdk, tokio::time::Instant, u64, Option<i64>), FixedServiceOperationClosedV4> {
        if !matches!(self.role, Some(Role::Network)) || self.ordinal != ordinal
            || self.invocation != invocation || !matches!(self.funding, Some(Ok(()))) {
            return Err(self.closed);
        }
        let (_, cutoff, wall) = self.horizon.as_ref().and_then(|result| result.as_ref().ok())
            .copied().ok_or(self.closed)?;
        let deadline = self.clock_comparison.as_ref().and_then(|result| result.as_ref().ok())
            .copied().ok_or(self.closed)?;
        Ok((self.sdk.as_ref().ok_or(self.closed)?, deadline, cutoff, wall))
    }

    fn bounds() -> Option<(usize, usize)> {
        let raw = zbus_schedule_shape()?;
        let message = raw.0;
        Some((message, message.checked_mul(raw.1)?))
    }

    fn shape() -> Result<ResourceVector, AccountingError> {
        let overflow = AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes };
        let (message, materialized) = Self::bounds().ok_or(overflow)?;
        let footprint = Sdk::receiving_footprint_v4(message, materialized).ok_or(overflow)?;
        // Both independent native destinations are inline in Self. Their boot
        // readers' dynamic diagnostics and failed files remain separately paid.
        let clock_dynamic = PopulationClockAttempt::dominant_requested_bytes_v1()
            .and_then(|bytes| bytes.checked_sub(std::mem::size_of::<PopulationClockAttempt>()))
            .and_then(|bytes| bytes.checked_mul(2)).ok_or(overflow)?;
        let bytes = footprint.memory_bytes.checked_add(
            std::mem::size_of::<Self>().checked_mul(2).ok_or(overflow)?)
            .and_then(|bytes| bytes.checked_add(clock_dynamic)).ok_or(overflow)?;
        let files = PopulationClockAttempt::MAXIMUM_RETAINED_FILES_V1.checked_mul(2)
            .and_then(|files| files.checked_add(footprint.open_files)).ok_or(overflow)?;
        let names = PopulationClockAttempt::receiving_metadata_cells_v1()
            .and_then(|names| names.checked_mul(2))
            .and_then(|names| names.checked_add(footprint.metadata_entries)).ok_or(overflow)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).map_err(|_| overflow)?)
            .with(D::OpenFiles, u64::try_from(files).map_err(|_| overflow)?)
            .with(D::MetadataEntries, u64::try_from(names).map_err(|_| overflow)?)
            .with(D::NetworkBytes, u64::try_from(footprint.network_bytes).map_err(|_| overflow)?)
            .with(D::LogBytes, u64::try_from(footprint.maximum_log_bytes).map_err(|_| overflow)?))
    }

    fn compare_snapshot(&self) -> Result<(u32, [u8; 16]), FixedServiceOperationClosedV4> {
        let sdk = self.sdk.as_ref().ok_or(self.closed)?;
        let snapshot = sdk.completed_snapshot_v4().ok_or(self.closed)?;
        let invocation = sdk.completed_invocation_data_v2().ok_or(self.closed)?;
        if snapshot.reported_entries != 0 || !snapshot.rows.is_empty()
            || Some(invocation) != self.invocation {
            return Err(self.closed);
        }
        Ok((snapshot.maximum_entries, invocation))
    }

    /// Requires both actual zero snapshots and the same enrolled recipient.
    ///
    /// # Errors
    /// Refuses missing, failed or changed native/SDK originals. Enclosing
    /// operation and Session afters remain independently mandatory.
    pub fn require_complete_v2(&self) -> Result<(), FixedServiceOperationClosedV4> {
        if self.first.is_none() && matches!(self.before, Some(Ok(())))
            && matches!(self.before_comparison, Some(Ok(_)))
            && matches!(self.after, Some(Ok(())))
            && matches!(self.after_comparison, Some(Ok(()))) {
            Ok(())
        } else { Err(self.closed) }
    }

    /// Returns actual recipient comparison DATA after the complete pair.
    pub fn recipient_invocation_data_v2(&self) -> Option<[u8; 16]> {
        self.require_complete_v2().ok()?;
        self.invocation
    }

    /// Returns the actual manager capacity after the complete comparison pair.
    pub fn maximum_entries_data_v2(&self) -> Option<u32> {
        self.require_complete_v2().ok()?;
        Some(self.before_comparison.as_ref()?.as_ref().ok()?.0)
    }

    /// Returns both actual population observations after all comparisons pass.
    pub fn population_interval_data_v2(&self) -> Option<(RawPairedClockSample, RawPairedClockSample)> {
        self.require_complete_v2().ok()?;
        Some((*self.population_before_result.as_ref()?.as_ref().ok()?,
            *self.population_after_result.as_ref()?.as_ref().ok()?))
    }

    fn require_population_sample(&self, sample: RawPairedClockSample)
        -> Result<RawPairedClockSample, PopulationClockError>
    {
        let (original, cutoff, wall) = self.horizon.as_ref().and_then(|value| value.as_ref().ok())
            .copied().ok_or(PopulationClockError::Stale)?;
        original.validate_later_sample(sample).map_err(PopulationClockError::Continuity)?;
        if sample.boottime_nanoseconds() >= cutoff
            || wall.is_some_and(|expiry| sample.wall_seconds() >= expiry) {
            return Err(PopulationClockError::Stale);
        }
        Ok(sample)
    }

    /// Selects the actual enclosing native/financial cause for its upper owner.
    pub fn original_failure_selected_v2(&self) -> bool {
        matches!(self.first, Some(First::Current | First::Funding | First::Horizon))
    }

    /// Borrows a precise SDK cause or stable same-native marker.
    ///
    /// Raw native archive guards are rendered through `failure_view_v2`.
    pub fn failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::Current => self.current.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Shape => self.shape.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Funding => self.funding.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Horizon => self.horizon.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Clock => self.clock_comparison.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Connect | First::Before | First::After =>
                self.sdk.as_ref()?.failure_cause_v2().or(Some(&self.closed)),
            First::BeforeComparison => self.before_comparison.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::AfterComparison => self.after_comparison.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::PopulationBefore => self.population_before.failure().or_else(||
                self.population_before_result.as_ref()?.as_ref().err().map(|cause| cause as _)),
            First::PopulationAfter => self.population_after.failure().or_else(||
                self.population_after_result.as_ref()?.as_ref().err().map(|cause| cause as _)),
            First::Order => Some(&self.closed),
        }
    }

    /// Borrows the original raw native error guard only when it was first.
    pub fn failure_view_v2(&self) -> Option<NetworkFdStoreFailureViewV4<'_>> {
        if matches!(self.first, Some(First::Connect | First::Before | First::After)) {
            self.sdk.as_ref()?.failure_view_v4()
        } else { self.failure_v2().map(NetworkFdStoreFailureViewV4::Cause) }
    }
}

impl FixedServiceOperationLoanV4<'_> {
    fn require_same_population_original_v2(&self, original: &FixedServiceInventoryFdStoreEmptyOriginalV2)
        -> Result<(), FixedServiceOperationClosedV4>
    {
        let same_role = matches!((original.role, self.operation.purpose),
            (Some(Role::Mount), Some(Purpose::MountInventory))
            | (Some(Role::Network), Some(Purpose::NetworkInventory)));
        if !matches!(original.funding, Some(Ok(()))) || !same_role
            || original.ordinal != self.operation.operation_ordinal
            || original.invocation != self.operation.invocation || !self.operation.armed {
            return Err(original.closed);
        }
        Ok(())
    }

    /// Observes the prepaid population interval before its native census.
    ///
    /// # Errors
    /// Refuses another interval, repeated entry, failed native observation or
    /// progression outside the original request's absolute horizon.
    pub fn observe_inventory_population_clock_before_v2(&mut self,
        original: &mut FixedServiceInventoryFdStoreEmptyOriginalV2,
    ) -> Result<RawPairedClockSample, FixedServiceOperationClosedV4> {
        if self.require_same_population_original_v2(original).is_err()
            || original.population_before_result.is_some() || original.first.is_some() {
            original.first.get_or_insert(First::Order);
            return Err(original.closed);
        }
        original.population_before_result = Some(match original.population_before.observe_once(None) {
            Ok(sample) => original.require_population_sample(sample),
            Err(error) => Err(error),
        });
        match original.population_before_result.as_ref() {
            Some(Ok(sample)) => Ok(*sample),
            _ => { original.first.get_or_insert(First::PopulationBefore); Err(original.closed) }
        }
    }

    /// Attempts the separately prepaid population after despite body refusal.
    ///
    /// # Errors
    /// Refuses another interval, repeated entry, native failure or original
    /// horizon/provenance mismatch. Earlier causes and both readers stay held.
    pub fn observe_inventory_population_clock_after_owed_v2(&mut self,
        original: &mut FixedServiceInventoryFdStoreEmptyOriginalV2,
    ) -> Result<RawPairedClockSample, FixedServiceOperationClosedV4> {
        if self.require_same_population_original_v2(original).is_err()
            || original.population_after_result.is_some() {
            original.first.get_or_insert(First::Order);
            return Err(original.closed);
        }
        // No healthy-primary check can suppress this independent destination.
        original.population_after_result = Some(match original.population_after.observe_once(None) {
            Ok(sample) => original.require_population_sample(sample).and_then(|sample| {
                let before = original.population_before_result.as_ref().and_then(|value| value.as_ref().ok())
                    .copied().ok_or(PopulationClockError::Stale)?;
                before.validate_later_sample(sample).map_err(PopulationClockError::Continuity)?;
                Ok(sample)
            }),
            Err(error) => Err(error),
        });
        match original.population_after_result.as_ref() {
            Some(Ok(sample)) => Ok(*sample),
            _ => { original.first.get_or_insert(First::PopulationAfter); Err(original.closed) }
        }
    }

    /// Pays and enters only this actual inventory's fixed before observation.
    ///
    /// # Errors
    /// Retains payment, original horizon, SDK/native or nonempty-store refusal.
    pub fn observe_inventory_fd_store_empty_before_v2(&mut self,
        original: &mut FixedServiceInventoryFdStoreEmptyOriginalV2,
    ) -> Result<(), FixedServiceOperationClosedV4> {
        if original.current.is_some() {
            original.first.get_or_insert(First::Order);
            return Err(original.closed);
        }
        let role = match self.operation.purpose {
            Some(Purpose::MountInventory) => Role::Mount,
            Some(Purpose::NetworkInventory) => Role::Network,
            _ => { original.first = Some(First::Order); return Err(original.closed); }
        };
        original.current = Some(match role {
            Role::Mount => self.require_inventory_current_v4(),
            Role::Network => self.require_network_inventory_current_v4(),
        });
        if !matches!(original.current, Some(Ok(()))) {
            original.first = Some(First::Current);
            return Err(original.closed);
        }
        original.role = Some(role);
        original.ordinal = self.operation.operation_ordinal;
        original.invocation = self.operation.invocation;
        original.shape = Some(FixedServiceInventoryFdStoreEmptyOriginalV2::shape());
        let Some(Ok(demand)) = original.shape.as_ref().copied() else {
            original.first = Some(First::Shape); return Err(original.closed);
        };
        original.funding = Some(self.require_additional_representation_v4(demand));
        if !matches!(original.funding, Some(Ok(()))) {
            original.first = Some(First::Funding); return Err(original.closed);
        }
        original.horizon = Some((|| {
            let (sample, cutoff) = self.operation.clock.retained_interval_data_v4()?;
            let wall = self.operation.clock.retained_wall_ceiling_data_v4()?;
            Ok((sample, cutoff, wall))
        })());
        let Some(Ok((_, cutoff, wall))) = original.horizon.as_ref().copied() else {
            original.first = Some(First::Horizon); return Err(original.closed);
        };
        // This deny-only scalar maps an unchanged absolute cutoff to a bounded
        // mechanical wait. The raw native transport rechecks actual BOOTTIME
        // and the original wall ceiling at every connect/read/write frontier.
        let reference = tokio::time::Instant::now();
        original.clock = Some(rustix::time::clock_gettime(rustix::time::ClockId::Boottime));
        original.clock_comparison = Some((|| {
            let now = original.clock.as_ref().ok_or(original.closed)?;
            let nanos = u64::try_from(now.tv_sec).ok().and_then(|seconds| seconds.checked_mul(1_000_000_000))
                .and_then(|seconds| u64::try_from(now.tv_nsec).ok().and_then(|fraction| seconds.checked_add(fraction)))
                .ok_or(original.closed)?;
            let remaining = cutoff.checked_sub(nanos).filter(|remaining| *remaining != 0).ok_or(original.closed)?;
            reference.checked_add(std::time::Duration::from_nanos(remaining.min(5_000_000_000)))
                .ok_or(original.closed)
        })());
        let Some(Ok(deadline)) = original.clock_comparison.as_ref().copied() else {
            original.first = Some(First::Clock); return Err(original.closed);
        };
        original.sdk = Some(match role { Role::Network => Sdk::new(), Role::Mount => Sdk::new_mount_inventory_v2() });
        let Some((message, materialized)) = FixedServiceInventoryFdStoreEmptyOriginalV2::bounds() else {
            original.first = Some(First::Order); return Err(original.closed);
        };
        let sdk = original.sdk.as_mut().ok_or(original.closed)?;
        original.connect = Some(sdk.connect_once_v4(message, materialized, deadline, cutoff, wall));
        if !matches!(original.connect, Some(Ok(()))) {
            original.first = Some(First::Connect); return Err(original.closed);
        }
        original.before = Some(sdk.snapshot_next_once_v4());
        if !matches!(original.before, Some(Ok(()))) {
            original.first = Some(First::Before); return Err(original.closed);
        }
        original.before_comparison = Some(original.compare_snapshot());
        if !matches!(original.before_comparison, Some(Ok(_))) {
            original.first = Some(First::BeforeComparison); return Err(original.closed);
        }
        Ok(())
    }

    /// Attempts the same prepaid independent descriptor-store after once.
    ///
    /// # Errors
    /// Retains earlier failure and refuses another interval or changed/nonempty
    /// store. It never requires a healthy body or pays a new allowance.
    pub fn observe_inventory_fd_store_empty_after_owed_v2(&mut self,
        original: &mut FixedServiceInventoryFdStoreEmptyOriginalV2,
    ) -> Result<(), FixedServiceOperationClosedV4> {
        let same_role = matches!((original.role, self.operation.purpose),
            (Some(Role::Mount), Some(Purpose::MountInventory))
            | (Some(Role::Network), Some(Purpose::NetworkInventory)));
        if !matches!(original.funding, Some(Ok(()))) || !same_role
            || original.ordinal != self.operation.operation_ordinal
            || original.invocation != self.operation.invocation || !self.operation.armed
            || original.after.is_some() {
            original.first.get_or_insert(First::Order);
            return Err(original.closed);
        }
        original.after = Some(match original.sdk.as_mut() {
            Some(sdk) => sdk.snapshot_owed_next_once_v2(),
            None => Err(NetworkFdStoreInspectionRefusalV4),
        });
        if !matches!(original.after, Some(Ok(()))) { original.first.get_or_insert(First::After); }
        original.after_comparison = Some((|| {
            let after = original.compare_snapshot()?;
            let before = original.before_comparison.as_ref().and_then(|value| value.as_ref().ok())
                .ok_or(original.closed)?;
            if after != *before { return Err(original.closed); }
            Ok(())
        })());
        if !matches!(original.after_comparison, Some(Ok(()))) { original.first.get_or_insert(First::AfterComparison); }
        original.require_complete_v2()
    }
}

fn zbus_schedule_shape() -> Option<(usize, usize)> {
    // The complete fixed request/header bound also bounds the selected empty
    // response profile. Larger replies fail closed in the same raw receiver.
    let raw = aos_systemd_client::fd_store::NetworkFdStoreInspectionOriginalV4::fixed_schedule_shape_v2()?;
    Some(raw)
}

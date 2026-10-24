//! Shares physical Controller append bookkeeping across closed cleanup payers.
//!
//! This inert carrier holds the same native names, clocks, forecast, literal
//! transaction, COMMIT readback and independent posts. It creates no financial
//! original or append permission: the role-specific sealed loan still joins its
//! actual Source payer, exact recipe and final currentness at the common writer.

use crate::controller_execution_operation::ControllerExecutionClockOriginalV1;
use crate::controller_resource_reservation::ResourceReservationErrorV1;
use crate::journal::{
    CommitResult, Journal, JournalAppendReceivingDemandErrorV1, JournalAuthorityComparisonStampV1,
    JournalError, JournalTransaction, ProtectedJournalCurrentnessOriginalsV1,
    ProtectedJournalNamesV1,
};
use aos_sandbox_model::{RawPairedClockSample, ResourceDimension as D, ResourceVector};
use aos_sandbox_journal::geometry::RecordShape;
use aos_sandbox_protocol::domain_ledger::execution_no_apply_floor::RootExecutionNoApplyControllerCutDataV2 as Cut;
use std::error::Error;
use std::mem::size_of;

type Witness = aos_sandbox_journal::protected_storage::WriterWitnessOriginalsV1<JournalError>;
type ClockError = aos_sandbox_broker::paired_clock::ProtectedOwnershipClockError;

#[derive(Clone, Copy)]
pub(crate) enum ClosedControllerAppendFirstV2 {
    Before,
    Forecast,
    Funding,
    Append,
    Readback,
    After,
}

pub(crate) struct ClosedControllerAppendOriginalV2 {
    pub(crate) first: Option<ClosedControllerAppendFirstV2>,
    names: [ProtectedJournalCurrentnessOriginalsV1; 2],
    witness: [Witness; 2],
    observed: [Option<Result<ProtectedJournalNamesV1, JournalError>>; 2],
    pub(crate) clocks: [ControllerExecutionClockOriginalV1; 3],
    pub(crate) samples: [Option<Result<RawPairedClockSample, ClockError>>; 3],
    pub(crate) before: Option<Result<(), JournalError>>,
    after: Option<Result<(), JournalError>>,
    stamp: Option<JournalAuthorityComparisonStampV1>,
    metadata: Option<std::io::Result<std::fs::Metadata>>,
    pub(crate) forecast: Option<Result<ResourceVector, JournalAppendReceivingDemandErrorV1>>,
    pub(crate) funding: Option<Result<(), ResourceReservationErrorV1>>,
    pub(crate) transaction: Option<JournalTransaction>,
    pub(crate) transition: Option<Result<(), JournalError>>,
    pub(crate) crossing: Option<Result<(), JournalError>>,
    pub(crate) append: Option<Result<CommitResult, JournalError>>,
    pub(crate) readback: Option<Result<Cut, JournalError>>,
    pub(crate) replay: Option<Result<(), JournalError>>,
    pub(crate) cleanup_horizon: Option<(RawPairedClockSample, i64)>,
}

impl ClosedControllerAppendOriginalV2 {
    pub(crate) fn new() -> Self {
        Self {
            first: None,
            names: std::array::from_fn(|_| Default::default()),
            witness: std::array::from_fn(|_| Default::default()),
            observed: std::array::from_fn(|_| None),
            clocks: std::array::from_fn(|_| ControllerExecutionClockOriginalV1::new()),
            samples: std::array::from_fn(|_| None),
            before: None,
            after: None,
            stamp: None,
            metadata: None,
            forecast: None,
            funding: None,
            transaction: None,
            transition: None,
            crossing: None,
            append: None,
            readback: None,
            replay: None,
            cleanup_horizon: None,
        }
    }

    pub(crate) fn fixed_demand(
        controller: &Journal,
        loan_carrier_bytes: usize,
    ) -> Result<ResourceVector, JournalError> {
        let names = controller.held_names_receiving_demand_v2()?;
        let witness = Witness::receiving_footprint_v1().ok_or(JournalError::JournalTooLarge)?;
        let bytes = size_of::<Self>()
            .checked_mul(3)
            .and_then(|n| n.checked_add(loan_carrier_bytes.checked_mul(3)?))
            .and_then(|n| n.checked_add(witness.memory_bytes.checked_mul(2)?))
            .and_then(|n| u64::try_from(n).ok())
            .ok_or(JournalError::JournalTooLarge)?;
        let clock = ControllerExecutionClockOriginalV1::fixed_demand_v1()
            .ok_or(JournalError::JournalTooLarge)?;
        Ok(names
            .checked_add(names)?
            .checked_add(clock)?
            .checked_add(clock)?
            .checked_add(clock)?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))?)
    }

    pub(crate) fn observe_names(&mut self, controller: &Journal, index: usize) {
        self.observed[index] = Some(controller.observe_held_physical_names_retaining_v1(
            &mut self.names[index],
            &mut self.witness[index],
        ));
    }

    pub(crate) fn physical_cut(
        &self,
        controller: &Journal,
        index: usize,
    ) -> Result<Cut, JournalError> {
        let names = *positive(&self.observed[index])?;
        let (_, _, end) = self.names[index]
            .completed_held_file_boundary_data_v1()
            .ok_or(JournalError::ProtectedBoundary)?;
        Cut::from_rows_data_v2(
            names,
            controller.snapshot_sequence(),
            end,
            controller.all_records(),
        )
        .map_err(|_| JournalError::ProtectedBoundary)
    }

    pub(crate) fn begin(
        &mut self,
        controller: &Journal,
        expected: Cut,
        boot: [u8; 16],
        cutoff: u64,
    ) {
        self.begin_observation(controller, Some(expected), boot, cutoff);
    }

    /// Captures the initial full native cut for a role without a prior Root cut.
    ///
    /// The caller pays this carrier before entry and still supplies its actual
    /// sealed role loan at the writer. This capture supplies no append authority.
    pub(crate) fn begin_current(
        &mut self,
        controller: &Journal,
        boot: [u8; 16],
        cutoff: u64,
    ) -> Result<Cut, JournalError> {
        if self.stamp.is_some() || self.before.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        self.begin_observation(controller, None, boot, cutoff);
        positive(&self.before)?;
        self.physical_cut(controller, 0)
    }

    fn begin_observation(
        &mut self,
        controller: &Journal,
        expected: Option<Cut>,
        boot: [u8; 16],
        cutoff: u64,
    ) {
        self.stamp = Some(controller.authority_comparison_stamp_v1());
        self.observe_names(controller, 0);
        self.samples[0] = Some(self.clocks[0].sample_v1());
        self.before = Some((|| {
            require_clock(&self.samples[0], boot, cutoff, self.cleanup_horizon)?;
            let observed = self.physical_cut(controller, 0)?;
            if expected.is_some_and(|expected| observed != expected) {
                return Err(JournalError::StaleAuthoritySnapshot);
            }
            require_current_map(controller, observed)
        })());
        if !matches!(self.before, Some(Ok(()))) {
            self.first
                .get_or_insert(ClosedControllerAppendFirstV2::Before);
        }
    }

    pub(crate) fn finish(
        &mut self,
        controller: &Journal,
        expected: Cut,
        boot: [u8; 16],
        cutoff: u64,
    ) {
        self.finish_observation(controller, Some(expected), boot, cutoff);
    }

    /// Drains the already-paid afters when initial cut capture refused.
    ///
    /// This path always retains a failed entry. It never substitutes a cut or
    /// creates an append, replay, readback or successful completion.
    pub(crate) fn finish_failed_entry(
        &mut self,
        controller: &Journal,
        boot: [u8; 16],
        cutoff: u64,
    ) {
        self.first
            .get_or_insert(ClosedControllerAppendFirstV2::Before);
        self.finish_observation(controller, None, boot, cutoff);
    }

    fn finish_observation(
        &mut self,
        controller: &Journal,
        expected: Option<Cut>,
        boot: [u8; 16],
        cutoff: u64,
    ) {
        // These destinations are independent of final-crossing failure and
        // remain owed even when the common append poisons the same writer.
        self.observe_names(controller, 1);
        self.samples[2] = Some(self.clocks[2].sample_v1());
        self.after = Some((|| {
            require_clock(&self.samples[2], boot, cutoff, self.cleanup_horizon)?;
            positive(&self.observed[1])?;
            let stamp = self.stamp.as_ref().ok_or(JournalError::ProtectedBoundary)?;
            if !controller.matches_authority_comparison_stamp_v1(stamp) {
                return Err(JournalError::StaleAuthoritySnapshot);
            }
            controller.ensure_protected_authority()?;
            if self.append.is_none()
                && self.physical_cut(controller, 1)?
                    != expected.ok_or(JournalError::ProtectedBoundary)?
            {
                return Err(JournalError::StaleAuthoritySnapshot);
            }
            Ok(())
        })());
        if !matches!(self.after, Some(Ok(()))) {
            self.first
                .get_or_insert(ClosedControllerAppendFirstV2::After);
        }
    }

    pub(crate) fn forecast_once(&mut self, controller: &Journal) -> Result<(), JournalError> {
        if self.first.is_none() {
            let shapes = self
                .transaction
                .as_ref()
                .ok_or(JournalError::ProtectedBoundary)?
                .records()
                .iter()
                .map(|record| RecordShape {
                    key_bytes: record.key().len(),
                    value_bytes: record.value().map(<[u8]>::len),
                });
            self.forecast = Some(
                controller.append_sequence_receiving_demand_retaining_metadata_v7(
                    std::iter::once(Ok(shapes)),
                    &mut self.metadata,
                ),
            );
            if !matches!(self.forecast, Some(Ok(_))) {
                self.first
                    .get_or_insert(ClosedControllerAppendFirstV2::Forecast);
            }
        }
        Ok(())
    }

    pub(crate) fn finish_append_once(
        &mut self,
        controller: &Journal,
        expected: Cut,
        boot: [u8; 16],
        cutoff: u64,
    ) -> Result<(), JournalError> {
        self.finish(controller, expected, boot, cutoff);
        if self.first.is_none() {
            self.readback = Some((|| {
                let commit = positive(&self.append)?;
                let transaction = self
                    .transaction
                    .as_ref()
                    .ok_or(JournalError::ProtectedBoundary)?;
                let count = u64::try_from(transaction.records().len())
                    .map_err(|_| JournalError::JournalTooLarge)?;
                let next = expected
                    .next()
                    .checked_add(count)
                    .and_then(|n| n.checked_add(2))
                    .ok_or(JournalError::JournalTooLarge)?;
                let cut = self.physical_cut(controller, 1)?;
                if cut.names() != expected.names()
                    || cut.next() != next
                    || commit.commit_sequence.checked_add(1) != Some(next)
                    || commit.durable_bytes != cut.end()
                {
                    return Err(JournalError::StaleAuthoritySnapshot);
                }
                for row in transaction.records() {
                    if controller.get(row.namespace(), row.key()) != row.value() {
                        return Err(JournalError::ProtectedBoundary);
                    }
                }
                require_current_map(controller, cut)?;
                Ok(cut)
            })());
            if !matches!(self.readback, Some(Ok(_))) {
                self.first
                    .get_or_insert(ClosedControllerAppendFirstV2::Readback);
            }
        }
        self.complete()
    }

    pub(crate) fn final_crossing_once(
        &mut self,
        controller: &Journal,
        expected: Cut,
        boot: [u8; 16],
        cutoff: u64,
    ) -> Result<(), JournalError> {
        if self.crossing.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        self.samples[1] = Some(self.clocks[1].sample_v1());
        self.crossing = Some((|| {
            positive(&self.transition)?;
            require_clock(&self.samples[1], boot, cutoff, self.cleanup_horizon)?;
            if !controller.matches_authority_comparison_stamp_v1(
                self.stamp.as_ref().ok_or(JournalError::ProtectedBoundary)?,
            ) {
                return Err(JournalError::StaleAuthoritySnapshot);
            }
            require_current_map(controller, expected)
        })());
        positive(&self.crossing).map(|_| ())
    }

    pub(crate) fn complete(&self) -> Result<(), JournalError> {
        if self.first.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        positive(&self.before)?;
        if self.replay.is_some() {
            positive(&self.replay)?;
            positive(&self.crossing)?;
            positive(&self.readback)?;
            positive(&self.after)?;
            return Ok(());
        }
        positive(&self.forecast)?;
        positive(&self.funding)?;
        positive(&self.transition)?;
        positive(&self.crossing)?;
        positive(&self.append)?;
        positive(&self.readback)?;
        positive(&self.after)?;
        Ok(())
    }

    pub(crate) fn after_cut(&self) -> Result<Cut, JournalError> {
        self.complete()?;
        Ok(*positive(&self.readback)?)
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            ClosedControllerAppendFirstV2::Before => self.names[0]
                .failure()
                .or_else(|| self.witness[0].failure())
                .or_else(|| self.clocks[0].failure())
                .or_else(|| error(&self.samples[0]))
                .or_else(|| error(&self.observed[0]))
                .or_else(|| error(&self.before)),
            ClosedControllerAppendFirstV2::Forecast => {
                error(&self.metadata).or_else(|| error(&self.forecast))
            }
            ClosedControllerAppendFirstV2::Funding => error(&self.funding),
            ClosedControllerAppendFirstV2::Append => error(&self.transition)
                .or_else(|| error(&self.replay))
                .or_else(|| self.clocks[1].failure())
                .or_else(|| error(&self.samples[1]))
                .or_else(|| error(&self.crossing))
                .or_else(|| error(&self.append)),
            ClosedControllerAppendFirstV2::Readback => error(&self.readback),
            ClosedControllerAppendFirstV2::After => self.names[1]
                .failure()
                .or_else(|| self.witness[1].failure())
                .or_else(|| self.clocks[2].failure())
                .or_else(|| error(&self.samples[2]))
                .or_else(|| error(&self.observed[1]))
                .or_else(|| error(&self.after)),
        }
    }
}

pub(crate) fn require_current_map(controller: &Journal, expected: Cut) -> Result<(), JournalError> {
    controller.ensure_protected_authority()?;
    if controller.snapshot_sequence() != expected.next()
        || Cut::from_rows_data_v2(
            expected.names(),
            controller.snapshot_sequence(),
            expected.end(),
            controller.all_records(),
        )
        .map_err(|_| JournalError::ProtectedBoundary)?
            != expected
    {
        return Err(JournalError::StaleAuthoritySnapshot);
    }
    Ok(())
}

pub(crate) fn require_clock(
    sample: &Option<Result<RawPairedClockSample, ClockError>>,
    boot: [u8; 16],
    cutoff: u64,
    cleanup: Option<(RawPairedClockSample, i64)>,
) -> Result<(), JournalError> {
    let sample = positive(sample)?;
    if sample.host_boot_id() != boot || sample.boottime_nanoseconds() >= cutoff {
        return Err(JournalError::ProtectedBoundary);
    }
    if let Some((first, expiry)) = cleanup {
        if first.validate_later_sample(*sample).is_err() || sample.wall_seconds() >= expiry {
            return Err(JournalError::ProtectedBoundary);
        }
    }
    Ok(())
}

fn positive<T, E>(value: &Option<Result<T, E>>) -> Result<&T, JournalError> {
    value
        .as_ref()
        .and_then(|value| value.as_ref().ok())
        .ok_or(JournalError::ProtectedBoundary)
}

fn error<T, E: Error + 'static>(value: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    value.as_ref()?.as_ref().err().map(|cause| cause as _)
}

#[cfg(test)]
mod clock_tests {
    use super::*;
    use aos_sandbox_model::RawClockProvenance;

    #[test]
    fn cleanup_wall_expiry_is_checked_while_original_boottime_is_still_live() {
        let provenance = RawClockProvenance::new_untrusted(*b"aos-kernel-clock").unwrap();
        let first =
            RawPairedClockSample::new_untrusted(provenance, [1; 16], 100, 1_000_000_000).unwrap();
        let later =
            RawPairedClockSample::new_untrusted(provenance, [1; 16], 101, 1_500_000_000).unwrap();
        assert!(require_clock(&Some(Ok(later)), [1; 16], 3_000_000_000, None).is_ok());
        assert!(
            require_clock(&Some(Ok(later)), [1; 16], 3_000_000_000, Some((first, 110))).is_ok()
        );
        assert!(
            require_clock(&Some(Ok(later)), [1; 16], 3_000_000_000, Some((first, 101))).is_err()
        );

        let rollback =
            RawPairedClockSample::new_untrusted(provenance, [1; 16], 99, 2_000_000_000).unwrap();
        assert!(
            require_clock(
                &Some(Ok(rollback)),
                [1; 16],
                3_000_000_000,
                Some((first, 110))
            )
            .is_err()
        );
    }

    #[test]
    fn a_closed_cleanup_crossing_cannot_change_clock_origin_or_extend_original_d() {
        let kernel = RawClockProvenance::new_untrusted(*b"aos-kernel-clock").unwrap();
        let other = RawClockProvenance::new_untrusted(*b"aos-cli-clock-v1").unwrap();
        let first =
            RawPairedClockSample::new_untrusted(kernel, [1; 16], 100, 1_000_000_000).unwrap();
        let horizon = Some((first, 110));

        for sample in [
            RawPairedClockSample::new_untrusted(kernel, [2; 16], 101, 1_500_000_000).unwrap(),
            RawPairedClockSample::new_untrusted(other, [1; 16], 101, 1_500_000_000).unwrap(),
            RawPairedClockSample::new_untrusted(kernel, [1; 16], 101, 3_000_000_000).unwrap(),
        ] {
            assert!(require_clock(&Some(Ok(sample)), [1; 16], 3_000_000_000, horizon).is_err());
        }
    }
}

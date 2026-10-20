//! Owns the genuine Cache current-purpose native clock bracket under private F.
//!
//! The existing shared paired reader captures its own boot original and real
//! clocks. It never retags a Controller or Root sample. The enclosing service
//! pays this owner before construction, retains its five possible Files through
//! all final posts, and uses only a fully completed bracket for a signed body.

use std::error::Error;
use std::mem::size_of;

use aos_sandbox_broker::paired_clock::{
    PairedClockBaselineV1, PairedClockSamplesV1, ProtectedOwnershipClockError,
};
use aos_sandbox_core::{
    RawClockProvenance, RawPairedClockSample, ResourceDimension as D, ResourceVector,
};
use aos_sandbox_protocol::domain_ledger::create_storage_history::cache_held::current_proof::CACHE_CURRENT_PROOF_CLOCK_PROVENANCE_BYTES_V1;

use super::{
    CachePurposeReceivingV1, CacheSignerReceivingClosedV1 as Closed, First, admit_stage, cause,
    observe_original, sample_pair_demand,
};

#[derive(Clone, Copy)]
enum ClockFailure {
    Initial,
    Before,
    BeforeBinding,
    After,
    AfterBinding,
    Closed,
}

pub(super) struct CacheCurrentClockOriginalV1 {
    baseline: PairedClockBaselineV1,
    samples: PairedClockSamplesV1,
    before: Option<Result<RawPairedClockSample, ProtectedOwnershipClockError>>,
    before_binding: Option<Result<(), Closed>>,
    after: Option<Result<RawPairedClockSample, ProtectedOwnershipClockError>>,
    after_binding: Option<Result<(), Closed>>,
    first: Option<ClockFailure>,
}

impl CacheCurrentClockOriginalV1 {
    fn new() -> Self {
        Self {
            baseline: PairedClockBaselineV1::capture(RawClockProvenance::new_untrusted(
                CACHE_CURRENT_PROOF_CLOCK_PROVENANCE_BYTES_V1,
            )),
            samples: PairedClockSamplesV1::new(),
            before: None,
            before_binding: None,
            after: None,
            after_binding: None,
            first: None,
        }
    }

    fn receiving_demand_v1() -> Option<ResourceVector> {
        let construction = size_of::<Self>()
            .checked_mul(2)?
            .checked_add(2 * size_of::<RawPairedClockSample>())?;
        // The inherited shared field census is not a namespace charge.
        PairedClockSamplesV1::receiving_demand_v1()?
            .with(D::MetadataEntries, 0)
            .checked_add(
                ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(construction).ok()?),
            )
            .ok()
    }

    fn begin_once(&mut self, boot: [u8; 16], started: u64, cutoff: u64) -> Result<(), Closed> {
        if self.before.is_some() {
            return self.refuse(ClockFailure::Closed);
        }
        if self.baseline.failure().is_some() {
            return self.refuse(ClockFailure::Initial);
        }
        self.before = Some(self.samples.sample(&mut self.baseline));
        if !matches!(self.before, Some(Ok(_))) {
            return self.refuse(ClockFailure::Before);
        }
        self.before_binding = Some(match self.before {
            Some(Ok(sample))
                if sample.host_boot_id() == boot
                    && sample.boottime_nanoseconds() >= started
                    && sample.boottime_nanoseconds() < cutoff =>
            {
                Ok(())
            }
            _ => Err(Closed),
        });
        if matches!(self.before_binding, Some(Ok(()))) {
            Ok(())
        } else {
            self.refuse(ClockFailure::BeforeBinding)
        }
    }

    fn finish_once(&mut self, boot: [u8; 16], started: u64, cutoff: u64) -> Result<(), Closed> {
        if self.after.is_some() {
            return self.refuse(ClockFailure::Closed);
        }
        // This native observation is independently owed even if the before or
        // an intervening body refused. The baseline itself prevents rollback.
        self.after = Some(self.samples.sample(&mut self.baseline));
        if !matches!(self.after, Some(Ok(_))) {
            self.first.get_or_insert(ClockFailure::After);
        }
        self.after_binding = Some(match (self.before, self.after) {
            (Some(Ok(before)), Some(Ok(after)))
                if before.host_boot_id() == boot
                    && after.host_boot_id() == boot
                    && after.boottime_nanoseconds() >= started
                    && after.boottime_nanoseconds() < cutoff
                    && before.validate_later_sample(after).is_ok() =>
            {
                Ok(())
            }
            _ => Err(Closed),
        });
        if !matches!(self.after_binding, Some(Ok(()))) {
            self.first.get_or_insert(ClockFailure::AfterBinding);
        }
        if self.first.is_none() {
            Ok(())
        } else {
            Err(Closed)
        }
    }

    pub(super) fn before_sample_v1(&self) -> Result<RawPairedClockSample, Closed> {
        if self.first.is_some() || !matches!(self.before_binding, Some(Ok(()))) {
            return Err(Closed);
        }
        self.before
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .copied()
            .ok_or(Closed)
    }

    pub(super) fn completed_sample_v1(&self) -> Result<RawPairedClockSample, Closed> {
        if self.first.is_some()
            || !matches!(self.before_binding, Some(Ok(())))
            || !matches!(self.after_binding, Some(Ok(())))
        {
            return Err(Closed);
        }
        self.after
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .copied()
            .ok_or(Closed)
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            ClockFailure::Initial => self.baseline.failure(),
            ClockFailure::Before => self
                .samples
                .observation_failure(0)
                .or_else(|| cause(&self.before)),
            ClockFailure::BeforeBinding => cause(&self.before_binding),
            ClockFailure::After => self
                .samples
                .observation_failure(usize::from(self.before.is_some()))
                .or_else(|| cause(&self.after)),
            ClockFailure::AfterBinding => cause(&self.after_binding),
            ClockFailure::Closed => Some(&Closed),
        }
    }

    fn refuse(&mut self, stage: ClockFailure) -> Result<(), Closed> {
        self.first.get_or_insert(stage);
        Err(Closed)
    }
}

impl CachePurposeReceivingV1<'_> {
    pub(super) fn begin_current_clock_once(&mut self) -> Result<(), Closed> {
        if self.original.first.is_some()
            || !matches!(self.original.join_binding, Some(Ok(())))
            || !self.original.join_stage.native_retired
            || self.original.current_clock_stage.demand.is_some()
        {
            return Err(self.fail(First::Closed));
        }
        self.original.current_clock_stage.demand = Some((|| {
            let missing = aos_sandbox_core::AccountingError::ArithmeticOverflow {
                dimension: D::MemoryBytes,
            };
            CacheCurrentClockOriginalV1::receiving_demand_v1()
                .ok_or(missing)?
                .checked_add(sample_pair_demand()?)
        })());
        let resident = self.current_purpose_resident_files_v1()?;
        if admit_stage(
            &mut self.startup.common,
            &mut self.original.current_clock_stage,
            resident,
        )
        .is_err()
        {
            return Err(self.fail(First::CurrentClockFunding));
        }
        self.original.current_clock_stage.before_result = Some(observe_original(
            &mut self.startup.common,
            &mut self.original.current_clock_stage.before,
        ));
        if !matches!(
            self.original.current_clock_stage.before_result,
            Some(Ok(()))
        ) {
            return Err(self.fail(First::CurrentClockBefore));
        }
        self.original.current_clock = Some(CacheCurrentClockOriginalV1::new());
        let challenge = *self.original.root_challenge.data()?;
        self.original.current_clock_before = Some(
            self.original
                .current_clock
                .as_mut()
                .ok_or(Closed)?
                .begin_once(
                    challenge.root.boot,
                    challenge
                        .root
                        .started
                        .max(challenge.held.association.started),
                    challenge.cutoff,
                ),
        );
        if !matches!(self.original.current_clock_before, Some(Ok(()))) {
            self.fail(First::CurrentClock);
        }
        if self.original.first.is_none() {
            Ok(())
        } else {
            Err(Closed)
        }
    }

    pub(super) fn finish_current_clock_once(&mut self) -> Result<(), Closed> {
        if !self.original.current_clock_stage.admitted()
            || self.original.current_clock_stage.before_result.is_none()
            || self.original.current_clock_after.is_some()
            || self.original.current_clock_stage.after_result.is_some()
        {
            return Err(self.fail(First::Closed));
        }
        let challenge = *self.original.root_challenge.data()?;
        if let Some(clock) = self.original.current_clock.as_mut() {
            self.original.current_clock_after = Some(
                clock.finish_once(
                    challenge.root.boot,
                    challenge
                        .root
                        .started
                        .max(challenge.held.association.started),
                    challenge.cutoff,
                ),
            );
            if !matches!(self.original.current_clock_after, Some(Ok(()))) {
                self.fail(First::CurrentClockAfter);
            }
        }
        self.original.current_clock_stage.after_result = Some(observe_original(
            &mut self.startup.common,
            &mut self.original.current_clock_stage.after,
        ));
        if !matches!(self.original.current_clock_stage.after_result, Some(Ok(()))) {
            self.fail(First::CurrentClockAfter);
        }
        // No native retirement here: both samples and their boot originals
        // remain resident through signing, reply and every final purpose post.
        if self.original.first.is_none() {
            Ok(())
        } else {
            Err(Closed)
        }
    }

    pub(super) fn current_purpose_resident_files_v1(&self) -> Result<u64, Closed> {
        use aos_sandbox_broker::receiving::{
            FixedSignerListenerOriginalV1, RootPeerImageObservationsV1,
            RootProfileOriginalCaptureV1,
        };
        let profile = self.startup.profile.profile().ok_or(Closed)?;
        let failure = aos_sandbox_core::AccountingError::ArithmeticOverflow {
            dimension: D::OpenFiles,
        };
        let result = (|| {
            RootProfileOriginalCaptureV1::fixed_demand()
                .ok_or(failure)?
                .checked_add(
                    RootPeerImageObservationsV1::receiving_demand_v1(profile).ok_or(failure)?,
                )?
                .checked_add(FixedSignerListenerOriginalV1::receiving_demand_v1().ok_or(failure)?)?
                .checked_add(
                    super::request::CacheCurrentRequestOriginalV1::receiving_demand_v1()
                        .ok_or(failure)?,
                )?
                .checked_add(
                    super::request::CacheCurrentRequestOriginalV1::receiving_demand_v1()
                        .ok_or(failure)?,
                )?
                .checked_add(
                    super::root_interval::CacheRootIntervalOriginalV1::receiving_demand_v1()
                        .ok_or(failure)?,
                )?
                .checked_add(sample_pair_demand()?)
        })();
        result
            .map(|demand| demand.get(D::OpenFiles))
            .map_err(|_| Closed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrong_root_boot_keeps_the_real_before_and_runs_the_independent_after() {
        let mut clock = CacheCurrentClockOriginalV1::new();

        assert!(clock.begin_once([0; 16], 0, u64::MAX).is_err());
        let before = clock.before.as_ref().unwrap().as_ref().unwrap();
        assert_ne!(before.host_boot_id(), [0; 16]);
        assert_eq!(
            before.provenance().as_bytes(),
            CACHE_CURRENT_PROOF_CLOCK_PROVENANCE_BYTES_V1
        );
        let original = *before;
        assert!(clock.finish_once([0; 16], 0, u64::MAX).is_err());

        assert_eq!(clock.before.as_ref().unwrap().as_ref().unwrap(), &original);
        assert!(matches!(clock.after, Some(Ok(_))));
        assert!(matches!(clock.first, Some(ClockFailure::BeforeBinding)));
        assert!(clock.completed_sample_v1().is_err());
        assert!(clock.finish_once([0; 16], 0, u64::MAX).is_err());
        assert!(matches!(clock.first, Some(ClockFailure::BeforeBinding)));
    }
}

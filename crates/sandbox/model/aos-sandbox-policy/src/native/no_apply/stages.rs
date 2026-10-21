//! Owns NoApply's original finite continuation coordinates and resident ledger.
//!
//! These coordinates describe reached work only. The actual native purpose
//! admission owns this ledger and checks its genuine listener, Initial, peer,
//! and financial originals before any Stage or consumable debit.

use std::error::Error;

use aos_sandbox_broker::receiving::RootJournalFinancialOriginalV1;
use aos_sandbox_model::{AccountingError, ResourceVector};

// Preserve the original shared ledger geometry. NoApply can select only its
// own closed subset; an unused coordinate is never a paid permission.
const STAGES: usize = 307;

/// Names the same fixed native/semantic read planes without granting access.
#[derive(Clone, Copy)]
pub enum RootExecutionNoApplyReadPhaseV2 {
    /// The fixed Controller native reader destination.
    ControllerFixed,
    /// The same Controller reader's native replay plane.
    ControllerNative,
    /// The same Controller reader's complete semantic model plane.
    ControllerSemantic,
    /// The fixed Host Session native reader destination.
    HostSessionFixed,
    /// The same Host Session reader's native replay plane.
    HostSessionNative,
    /// The same Host Session reader's complete semantic model plane.
    HostSessionSemantic,
    /// The fixed Source native reader destination.
    SourceFixed,
    /// The same Source reader's native replay plane.
    SourceNative,
    /// The same Source reader's complete semantic model plane.
    SourceSemantic,
}

impl RootExecutionNoApplyReadPhaseV2 {
    fn index_v2(self) -> usize {
        match self {
            Self::ControllerFixed => 218,
            Self::ControllerNative => 219,
            Self::ControllerSemantic => 220,
            Self::HostSessionFixed => 221,
            Self::HostSessionNative => 222,
            Self::HostSessionSemantic => 223,
            Self::SourceFixed => 224,
            Self::SourceNative => 225,
            Self::SourceSemantic => 226,
        }
    }

    fn final_index_v2(self) -> usize {
        match self {
            Self::ControllerFixed => 266,
            Self::ControllerNative => 267,
            Self::ControllerSemantic => 268,
            Self::HostSessionFixed => 269,
            Self::HostSessionNative => 270,
            Self::HostSessionSemantic => 271,
            Self::SourceFixed => 272,
            Self::SourceNative => 273,
            Self::SourceSemantic => 274,
        }
    }

    fn acquisition_index_v2(self) -> usize {
        match self {
            Self::ControllerFixed => 276,
            Self::ControllerNative => 277,
            Self::ControllerSemantic => 278,
            Self::HostSessionFixed => 279,
            Self::HostSessionNative => 280,
            Self::HostSessionSemantic => 281,
            Self::SourceFixed => 282,
            Self::SourceNative => 283,
            Self::SourceSemantic => 284,
        }
    }
}

/// Names only the real NoApply continuation's finite reached stages.
///
/// Neither this DATA nor an amount can construct a native purpose original.
#[derive(Clone, Copy)]
pub enum RootNoApplyStageDataV2 {
    /// The initial fixed/native/semantic reader programme.
    Read(RootExecutionNoApplyReadPhaseV2),
    /// The complete initial NoApply model comparison.
    Models,
    /// The independently installed Host manifest and original challenge.
    HostTrust,
    /// The authenticated Host current43 or cleanup43 lease and outcome.
    HostCurrentLease,
    /// The actual signed Root floor construction and native append.
    Floor,
    /// The independent post-floor fixed/native/semantic reader programme.
    FinalRead(RootExecutionNoApplyReadPhaseV2),
    /// The final original ACK projection after every final reader.
    Ack,
    /// The distinct fresh cleanup acquisition reader programme.
    AcquisitionRead(RootExecutionNoApplyReadPhaseV2),
    /// The distinct cleanup acquisition trust destination.
    AcquisitionTrust,
    /// The complete cleanup acquisition model comparison.
    AcquisitionModels,
    /// The same cleanup acquisition's actual signing destination.
    AcquisitionSign,
}

impl RootNoApplyStageDataV2 {
    pub(super) fn index_v2(self) -> usize {
        match self {
            Self::Read(phase) => phase.index_v2(),
            Self::Models => 235,
            Self::HostTrust => 252,
            Self::HostCurrentLease => 253,
            Self::Floor => 254,
            Self::FinalRead(phase) => phase.final_index_v2(),
            Self::Ack => 275,
            Self::AcquisitionRead(phase) => phase.acquisition_index_v2(),
            Self::AcquisitionTrust => 285,
            Self::AcquisitionModels => 286,
            Self::AcquisitionSign => 287,
        }
    }

    pub(super) fn prerequisites_positive_v2(self, stages: &RootNoApplyStagesOriginalV2) -> bool {
        match self {
            Self::Read(RootExecutionNoApplyReadPhaseV2::ControllerFixed)
            | Self::HostTrust
            | Self::AcquisitionRead(RootExecutionNoApplyReadPhaseV2::ControllerFixed)
            | Self::AcquisitionTrust => true,
            Self::Read(_) | Self::AcquisitionRead(_) => stages.positive(self.index_v2() - 1),
            Self::Models => stages.positive(226),
            Self::HostCurrentLease => stages.positive(252) && stages.positive(226),
            Self::Floor => stages.positive(253) && stages.positive(235),
            Self::FinalRead(RootExecutionNoApplyReadPhaseV2::ControllerFixed) => {
                stages.positive(254)
            }
            Self::FinalRead(_) => stages.positive(self.index_v2() - 1),
            Self::Ack => stages.positive(254) && stages.positive(274),
            Self::AcquisitionModels => stages.positive(284) && stages.positive(285),
            Self::AcquisitionSign => stages.positive(286),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(super) enum RootNoApplyReceivingErrorV2 {
    #[error("the actual NoApply continuation is closed or out of order")]
    Conflict,
    #[error("the actual completed Root listener or receiving image is unavailable")]
    EnrollmentUnavailable,
    #[error(transparent)]
    Accounting(#[from] AccountingError),
    #[error(transparent)]
    Observation(#[from] aos_sandbox_broker::receiving::RootObservationErrorV1),
    #[error(transparent)]
    Financial(RootJournalFinancialOriginalV1),
}

pub(super) struct RootNoApplyStagesOriginalV2 {
    pub(super) complete: Option<ResourceVector>,
    pub(super) requirements: [Option<Result<ResourceVector, RootNoApplyReceivingErrorV2>>; STAGES],
    pub(super) traffic: [Option<Result<(), RootNoApplyReceivingErrorV2>>; STAGES],
    pub(super) first: Option<usize>,
    pub(super) closed: Option<RootNoApplyReceivingErrorV2>,
}

impl Default for RootNoApplyStagesOriginalV2 {
    fn default() -> Self {
        Self {
            complete: None,
            requirements: std::array::from_fn(|_| None),
            traffic: std::array::from_fn(|_| None),
            first: None,
            closed: None,
        }
    }
}

impl RootNoApplyStagesOriginalV2 {
    // Charge the actual Default work/return and both from_fn array controls
    // before constructing this nested stage ledger in the real peer owner.
    pub(super) fn construction_control_bytes_v2() -> Option<usize> {
        use std::mem::size_of;

        size_of::<Self>()
            .checked_mul(2)?
            .checked_add(
                size_of::<[Option<Result<ResourceVector, RootNoApplyReceivingErrorV2>>; STAGES]>()
                    .checked_mul(2)?,
            )?
            .checked_add(
                size_of::<[Option<Result<(), RootNoApplyReceivingErrorV2>>; STAGES]>()
                    .checked_mul(2)?,
            )?
            .checked_add(size_of::<usize>().checked_mul(4)?)
    }

    fn positive(&self, index: usize) -> bool {
        matches!(self.requirements[index], Some(Ok(_)))
            && matches!(self.traffic[index], Some(Ok(())))
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let Some(index) = self.first else {
            return self.closed.as_ref().map(|cause| cause as _);
        };
        self.requirements[index]
            .as_ref()
            .and_then(|result| result.as_ref().err())
            .map(|cause| cause as _)
            .or_else(|| {
                self.traffic[index]
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paid(stages: &mut RootNoApplyStagesOriginalV2, stage: RootNoApplyStageDataV2) {
        stages.requirements[stage.index_v2()] = Some(Ok(ResourceVector::ZERO));
        stages.traffic[stage.index_v2()] = Some(Ok(()));
    }

    #[test]
    fn execution_models_requires_the_actual_ninth_reader_debit() {
        let mut stages = RootNoApplyStagesOriginalV2::default();
        let models = RootNoApplyStageDataV2::Models;
        assert_eq!(models.index_v2(), 235);
        assert!(models.index_v2() < STAGES);
        assert!(!models.prerequisites_positive_v2(&stages));

        // Earlier readers and an unrelated positive Network tail cannot pay it.
        for index in [218, 219, 220, 221, 222, 223, 224, 225, 234] {
            stages.requirements[index] = Some(Ok(ResourceVector::ZERO));
            stages.traffic[index] = Some(Ok(()));
        }
        assert!(!models.prerequisites_positive_v2(&stages));
        stages.requirements[226] = Some(Ok(ResourceVector::ZERO));
        assert!(!models.prerequisites_positive_v2(&stages));
        stages.traffic[226] = Some(Ok(()));
        assert!(models.prerequisites_positive_v2(&stages));
        stages.traffic[226] = Some(Err(RootNoApplyReceivingErrorV2::Conflict));
        assert!(!models.prerequisites_positive_v2(&stages));
    }

    #[test]
    fn execution_ack_requires_completed_floor_and_new_ordered_native_readers() {
        use RootExecutionNoApplyReadPhaseV2 as P;
        let readers = [
            P::ControllerFixed,
            P::ControllerNative,
            P::ControllerSemantic,
            P::HostSessionFixed,
            P::HostSessionNative,
            P::HostSessionSemantic,
            P::SourceFixed,
            P::SourceNative,
            P::SourceSemantic,
        ];
        let mut stages = RootNoApplyStagesOriginalV2::default();
        let first = RootNoApplyStageDataV2::FinalRead(readers[0]);
        let ack = RootNoApplyStageDataV2::Ack;
        assert_eq!((first.index_v2(), ack.index_v2()), (266, 275));
        assert!(ack.index_v2() < STAGES);
        assert!(!first.prerequisites_positive_v2(&stages));
        assert!(!ack.prerequisites_positive_v2(&stages));

        paid(&mut stages, RootNoApplyStageDataV2::Floor);
        for (offset, phase) in readers.into_iter().enumerate() {
            let reader = RootNoApplyStageDataV2::FinalRead(phase);
            assert_eq!(reader.index_v2(), 266 + offset);
            assert!(reader.prerequisites_positive_v2(&stages));
            assert!(!ack.prerequisites_positive_v2(&stages));
            paid(&mut stages, reader);
        }
        assert!(ack.prerequisites_positive_v2(&stages));

        stages.traffic[274] = Some(Err(RootNoApplyReceivingErrorV2::Conflict));
        assert!(!ack.prerequisites_positive_v2(&stages));
        stages.traffic[274] = Some(Ok(()));
        stages.traffic[254] = Some(Err(RootNoApplyReceivingErrorV2::Conflict));
        assert!(!ack.prerequisites_positive_v2(&stages));
    }

    #[test]
    fn acquisition_signature_requires_its_own_native_reads_trust_and_classifier() {
        use RootExecutionNoApplyReadPhaseV2 as P;
        let mut stages = RootNoApplyStagesOriginalV2::default();
        let models = RootNoApplyStageDataV2::AcquisitionModels;
        let sign = RootNoApplyStageDataV2::AcquisitionSign;
        assert_eq!((models.index_v2(), sign.index_v2()), (286, 287));
        assert!(sign.index_v2() < STAGES);
        assert!(!models.prerequisites_positive_v2(&stages));
        assert!(!sign.prerequisites_positive_v2(&stages));

        paid(
            &mut stages,
            RootNoApplyStageDataV2::AcquisitionRead(P::SourceSemantic),
        );
        assert!(!models.prerequisites_positive_v2(&stages));
        paid(&mut stages, RootNoApplyStageDataV2::AcquisitionTrust);
        assert!(models.prerequisites_positive_v2(&stages));
        assert!(!sign.prerequisites_positive_v2(&stages));
        paid(&mut stages, models);
        assert!(sign.prerequisites_positive_v2(&stages));
        stages.traffic[286] = Some(Err(RootNoApplyReceivingErrorV2::Conflict));
        assert!(!sign.prerequisites_positive_v2(&stages));
    }

    #[test]
    fn execution_current_lease_requires_its_own_trust_and_complete_native_readers() {
        let mut stages = RootNoApplyStagesOriginalV2::default();
        let trust = RootNoApplyStageDataV2::HostTrust;
        let lease = RootNoApplyStageDataV2::HostCurrentLease;
        assert_eq!((trust.index_v2(), lease.index_v2()), (252, 253));
        assert!(lease.index_v2() < STAGES);
        assert!(trust.prerequisites_positive_v2(&stages));
        assert!(!lease.prerequisites_positive_v2(&stages));

        paid(&mut stages, trust);
        assert!(!lease.prerequisites_positive_v2(&stages));
        stages.requirements[226] = Some(Ok(ResourceVector::ZERO));
        assert!(!lease.prerequisites_positive_v2(&stages));
        stages.traffic[226] = Some(Ok(()));
        assert!(lease.prerequisites_positive_v2(&stages));

        stages.traffic[252] = Some(Err(RootNoApplyReceivingErrorV2::Conflict));
        assert!(!lease.prerequisites_positive_v2(&stages));
    }

    #[test]
    fn execution_floor_requires_both_actual_current_host_and_three_row_models() {
        let mut stages = RootNoApplyStagesOriginalV2::default();
        let floor = RootNoApplyStageDataV2::Floor;
        assert_eq!(floor.index_v2(), 254);
        assert!(floor.index_v2() < STAGES);
        paid(&mut stages, RootNoApplyStageDataV2::HostCurrentLease);
        assert!(!floor.prerequisites_positive_v2(&stages));
        paid(&mut stages, RootNoApplyStageDataV2::Models);
        assert!(floor.prerequisites_positive_v2(&stages));
        stages.traffic[253] = Some(Err(RootNoApplyReceivingErrorV2::Conflict));
        assert!(!floor.prerequisites_positive_v2(&stages));
    }
}

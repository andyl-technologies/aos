//! Retains actual typed Ownership verification of the same Ready bundle.
//!
//! Fixed framing precedes typed admission; the same scoped Ready borrow survives
//! that short real receiving loan. Decoder capsules and native observations are
//! created only after typed admission. Proposed Controller DATA never supplies
//! the trust anchor, financial prefix, retained clock or completed native owner.

use std::error::Error;
use std::mem::size_of;

use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as Mechanical;
use aos_sandbox_broker::kernel_clock::RetainedKernelPairedClockAttemptV1;
use aos_sandbox_broker::receiving::{
    RootObservationErrorV1, RootSelectedStartupBorrowV1, RootUpperMutationGuardV1,
};
use aos_sandbox_model::{
    CanonicalAssignmentManifestV1, CanonicalCborError, RawPairedClockSample,
    ResourceDimension as D, ResourceVector,
};
use aos_sandbox_model::format::assignment_capture::CanonicalAssignmentDecodeCaptureV1;
use aos_sandbox_ownership_protocol::{
    OwnershipClaimError, OwnershipLeaseAcquisitionError,
    response_verification::{OwnershipClaimDecodeCaptureV1, OwnershipResponseVerifyCaptureV1},
};
use aos_sandbox_protocol::domain_ledger::create_storage_history::HistoryErrorV1;
use aos_sandbox_protocol::domain_ledger::create_storage_history::readback::HistoryPairReadbackDataV1;

use crate::native::PolicyNativeJournalErrorV1 as NativeError;
use crate::native::startup::RootCurrentWritersPredecessorV1;

use super::history_post::RootCurrentHistoryPostOriginalV1;
use super::initial_location::RootInitialLocationPairOriginalV1;
use super::initial_open::{
    RootInitialClockErrorV1, RootInitialOpenErrorV1,
    RootInitialOpenPreparedOriginalV1, ROOT_RECORD_BYTES,
};
use super::initial_ready::RootInitialReadyOriginalV1;
use super::initial_receiving::RootInitialStageOriginalV1;
use super::initial_source_exchange::{RootInitialSourceExchangeErrorV1, RootInitialSourceExchangeOriginalV1};
use super::initial_trust::{RootInitialTrustErrorV1, RootInitialTrustOriginalV1};
use super::owned::RootCurrentAcceptedOriginalsV1;
use super::writers::RootCurrentWritersOriginalV1;

mod frame;
pub use frame::RootInitialBundleOwnershipFrameBorrowV1;

/// Retains refusal of actual same-owner typed Ownership bundle verification.
#[derive(Debug, thiserror::Error)]
pub enum RootInitialBundleOwnershipErrorV1 {
    /// Retains original Open, writer, native or clock refusal.
    #[error(transparent)]
    Open(#[from] RootInitialOpenErrorV1),
    /// Retains refusal of the actual independent Source exchange.
    #[error(transparent)]
    Source(#[from] RootInitialSourceExchangeErrorV1),
    /// Retains refusal of the independently captured public Ownership trust.
    #[error(transparent)]
    Trust(#[from] RootInitialTrustErrorV1),
    /// Retains canonical historical framing or association refusal.
    #[error(transparent)]
    Format(#[from] HistoryErrorV1),
    /// The real fixed/typed stage, decoder or independently owed post is incomplete.
    #[error("initial Ownership bundle verification is incomplete")]
    Incomplete,
}

type E = RootInitialBundleOwnershipErrorV1;
type Clock = RetainedKernelPairedClockAttemptV1<RootInitialClockErrorV1>;
type Readback = HistoryPairReadbackDataV1<ROOT_RECORD_BYTES>;

pub(super) struct RootInitialBundleOwnershipOriginalV1 {
    fixed: RootInitialStageOriginalV1,
    typed: RootInitialStageOriginalV1,
    predecessor: Option<RootObservationErrorV1>,
    framing: Option<Result<(), HistoryErrorV1>>,
    assignment_framing: Option<Result<(), HistoryErrorV1>>,
    geometry: Option<Result<ResourceVector, NativeError>>,
    before: RootInitialLocationPairOriginalV1,
    before_readback: Option<Result<Readback, RootInitialOpenErrorV1>>,
    before_clock: Clock,
    before_sample: Option<Result<RawPairedClockSample, RootInitialClockErrorV1>>,
    before_cutoff: Option<Result<(), RootInitialOpenErrorV1>>,
    assignment: Option<Box<CanonicalAssignmentDecodeCaptureV1>>,
    assignment_decode: Option<Result<(), CanonicalCborError>>,
    claim: Option<Box<OwnershipClaimDecodeCaptureV1>>,
    claim_decode: Option<Result<(), OwnershipClaimError>>,
    association: Option<Result<(), HistoryErrorV1>>,
    response: Option<Box<OwnershipResponseVerifyCaptureV1>>,
    verification: Option<Result<(), OwnershipLeaseAcquisitionError>>,
    primary: Option<Result<(), E>>,
    after: RootInitialLocationPairOriginalV1,
    after_readback: Option<Result<Readback, RootInitialOpenErrorV1>>,
    peer_history: Option<RootCurrentHistoryPostOriginalV1>,
    peer_arm: Option<Result<(), RootObservationErrorV1>>,
    peer: Option<Result<(), RootObservationErrorV1>>,
    after_clock: Clock,
    after_sample: Option<Result<RawPairedClockSample, RootInitialClockErrorV1>>,
    after_cutoff: Option<Result<(), RootInitialOpenErrorV1>>,
    interval: Option<Result<(), aos_sandbox_model::OwnershipLeaseVerificationError>>,
    body_entered: bool,
    closed: bool,
}

impl RootInitialBundleOwnershipOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            fixed: RootInitialStageOriginalV1::new(),
            typed: RootInitialStageOriginalV1::new(),
            predecessor: None,
            framing: None,
            assignment_framing: None,
            geometry: None,
            before: RootInitialLocationPairOriginalV1::new(),
            before_readback: None,
            before_clock: Clock::default(),
            before_sample: None,
            before_cutoff: None,
            assignment: None,
            assignment_decode: None,
            claim: None,
            claim_decode: None,
            association: None,
            response: None,
            verification: None,
            primary: None,
            after: RootInitialLocationPairOriginalV1::new(),
            after_readback: None,
            peer_history: None,
            peer_arm: None,
            peer: None,
            after_clock: Clock::default(),
            after_sample: None,
            after_cutoff: None,
            interval: None,
            body_entered: false,
            closed: false,
        }
    }

    pub(super) fn entered_v1(&self) -> bool {
        self.fixed.entered || self.body_entered
    }

    pub(super) fn claim_fixed_once_v1(&mut self) -> Result<(), RootObservationErrorV1> {
        if self.fixed.entered || self.closed {
            self.closed = true;
            return Err(RootObservationErrorV1::Service);
        }
        self.fixed.entered = true;
        Ok(())
    }

    pub(super) fn refuse_unprepared_v1(&mut self) {
        self.closed = true;
    }

    pub(super) fn park_predecessor_refusal_v1(&mut self, error: RootObservationErrorV1) {
        self.predecessor.get_or_insert(error);
        self.closed = true;
    }

    pub(super) fn begin_fixed_once_v1(
        &mut self,
        open: &RootInitialOpenPreparedOriginalV1,
        source: &RootInitialSourceExchangeOriginalV1,
        trust: &RootInitialTrustOriginalV1,
        mut predecessor: RootCurrentWritersPredecessorV1<'_, '_, '_>,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        let (initial, financial) = predecessor.split_initial_v1();
        if !self.fixed.entered || self.fixed.permit.is_some() || self.closed {
            self.closed = true;
            initial.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        }
        self.fixed.financial = Some(financial.clone());
        self.fixed.permit = Some((|| {
            source.require_complete_v1().map_err(|_| NativeError::boundary())?;
            trust.require_complete_v1().map_err(|_| NativeError::boundary())?;
            let body = open.body_v1().map_err(|_| NativeError::boundary())?;
            let enrollment = initial.enrollment_v1().ok_or_else(NativeError::boundary)?;
            if initial.failure().is_some()
                || !matches!(initial.recipient_binding_result_v1(), Some(Ok(())))
                || (body.root_recipient, body.root_producer)
                    != (enrollment.recipient_invocation, enrollment.identity.native_fields().invocation)
                || !source.same_financial_v1(financial)
                || !startup.same_financial_original_data_v1(financial)
            {
                return Err(NativeError::boundary());
            }
            let base = source.completed_prefix_v1().map_err(|_| NativeError::boundary())?;
            let demand = base.checked_add(Self::fixed_demand_v1()?)
                .map_err(|_| NativeError::boundary())?;
            if financial.require_receiving_demand_under_upper_exclusion_v1(exclusion, demand).is_err() {
                return Err(NativeError::Financial(financial.clone()));
            }
            Ok(demand)
        })());
        self.fixed.finish_v1(initial, startup, exclusion)
    }

    pub(super) fn borrow_frame_once_v1<'cut, 'startup>(
        &'cut mut self,
        writers: &'cut RootCurrentWritersOriginalV1,
        open: &'cut RootInitialOpenPreparedOriginalV1,
        ready: &'cut RootInitialReadyOriginalV1,
        source: &'cut RootInitialSourceExchangeOriginalV1,
        trust: &'cut RootInitialTrustOriginalV1,
        originals: &'cut RootCurrentAcceptedOriginalsV1<'startup>,
    ) -> Result<RootInitialBundleOwnershipFrameBorrowV1<'cut, 'startup>, E> {
        frame::RootInitialBundleOwnershipFrameBorrowV1::prepare_once_v1(
            self, writers, open, ready, source, trust, originals,
        )
    }

    pub(super) fn observe_native_posts_once_v1(
        &mut self,
        writers: &RootCurrentWritersOriginalV1,
        open: &RootInitialOpenPreparedOriginalV1,
    ) {
        // Framing and typed refusal precede entry into the old native post scope.
        // Once typed admission succeeds, primary failure cannot suppress posts.
        if self.typed.require_complete_v1().is_err() || self.after_readback.is_some() {
            return;
        }
        match writers.opened_pair_view_v1() {
            Ok((authority, policy)) => {
                self.after.observe_once_v1(authority, policy);
                self.after_readback = Some(open.readback_current_v1(authority, policy));
            }
            Err(error) => {
                self.after_readback = Some(Err(RootInitialOpenErrorV1::Root(error)));
            }
        }
    }

    pub(super) fn arm_peer_once_v1(
        &mut self,
        predecessor: RootCurrentWritersPredecessorV1<'_, '_, '_>,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), ()> {
        if self.typed.require_complete_v1().is_err() || self.after_readback.is_none()
            || self.peer_arm.is_some() || self.peer.is_some()
        {
            self.closed = true;
            return Err(());
        }
        self.peer_history = Some(RootCurrentHistoryPostOriginalV1::arm_once_v1(
            predecessor, startup, exclusion,
        ));
        self.peer_arm = Some(match &self.peer_history {
            Some(history) => history.require_armed_v1(),
            None => Err(RootObservationErrorV1::Service),
        });
        if matches!(self.peer_arm, Some(Ok(()))) {
            Ok(())
        } else {
            Err(())
        }
    }

    pub(super) fn refuse_peer_arm_once_v1(&mut self) {
        if self.peer_arm.is_none() && self.peer.is_none() {
            self.peer_arm = Some(Err(RootObservationErrorV1::Service));
        }
        self.closed = true;
    }

    pub(super) fn park_peer_refusal_v1(&mut self, error: RootObservationErrorV1) {
        if self.peer_arm.is_none() {
            self.peer_arm = Some(Err(error));
        } else {
            self.closed = true;
        }
    }

    pub(super) fn observe_peer_and_clock_once_v1(
        &mut self,
        originals: &RootCurrentAcceptedOriginalsV1<'_>,
        open: &RootInitialOpenPreparedOriginalV1,
        source: &RootInitialSourceExchangeOriginalV1,
    ) {
        if self.typed.require_complete_v1().is_err() || self.after_readback.is_none()
            || self.peer_arm.is_none() || self.peer.is_some()
        {
            return;
        }
        self.peer = Some(match &mut self.peer_history {
            Some(history) => match history.borrow_accepted_v1(&originals.peer, &originals.stream) {
                Ok(mut accepted) => accepted.observe_shared_once_v1(),
                Err(error) => Err(error),
            },
            None => Err(RootObservationErrorV1::Service),
        });
        if matches!(self.peer, Some(Ok(()))) {
            drop(self.peer_history.take());
        }
        self.after_sample = Some(self.after_clock.observe_once(None));
        self.after_cutoff = Some(require_clock(open, source, &self.after_sample));
        if let (Some(Ok(before)), Some(Ok(after))) = (&self.before_sample, &self.after_sample) {
            self.interval = Some(before.validate_later_sample(*after));
        }
    }

    pub(super) fn require_complete_v1(&self) -> Result<(), E> {
        if self.closed || self.failure_v1().is_some() {
            return Err(E::Incomplete);
        }
        self.fixed.require_complete_v1()?;
        self.typed.require_complete_v1()?;
        positive(&self.primary)?;
        self.after.require_complete_v1()?;
        positive(&self.after_readback)?;
        positive(&self.peer_arm)?;
        positive(&self.peer)?;
        positive(&self.after_cutoff)?;
        positive(&self.interval)?;
        self.assignment.as_ref().and_then(|capture| capture.value()).ok_or(E::Incomplete)?;
        self.response.as_ref().and_then(|capture| capture.value()).ok_or(E::Incomplete)?;
        Ok(())
    }

    pub(super) fn completed_manifest_v1(&self) -> Result<&CanonicalAssignmentManifestV1, E> {
        self.require_complete_v1()?;
        self.assignment.as_ref().and_then(|capture| capture.value()).ok_or(E::Incomplete)
    }

    pub(super) fn completed_response_v1(&self) -> Result<&OwnershipResponseVerifyCaptureV1, E> {
        self.require_complete_v1()?;
        self.response.as_deref().ok_or(E::Incomplete)
    }

    pub(super) fn completed_prefix_v1(&self) -> Result<ResourceVector, E> {
        self.require_complete_v1()?;
        Ok(self.typed.require_complete_v1()?)
    }

    pub(super) fn same_financial_v1(
        &self,
        financial: &aos_sandbox_broker::receiving::RootJournalFinancialOriginalV1,
    ) -> bool {
        match &self.typed.financial {
            Some(original) => original.same_original_data_v1(financial),
            None => false,
        }
    }

    pub(super) fn fixed_demand_v1() -> Result<ResourceVector, NativeError> {
        let invalid = || NativeError::Mechanical(Mechanical::JournalTooLarge);
        let names = RootInitialLocationPairOriginalV1::additional_native_demand_v1()?;
        let work = crate::bundle_ownership_data::fixed_prelude_work_receiving_bytes_v1()
            .ok_or_else(invalid)?;
        let pair = Clock::dominant_requested_bytes_v1()
            .and_then(|bytes| bytes.checked_mul(2)).ok_or_else(invalid)?;
        let memory = size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(work))
            .and_then(|bytes| bytes.checked_add(pair))
            .and_then(|bytes| bytes.checked_add(2 * size_of::<usize>()))
            .and_then(|bytes| bytes.checked_add(
                crate::bundle_ownership_data::assignment_prelude_geometry_receiving_bytes_v1::<NativeError>()?,
            ))
            .and_then(|bytes| bytes.checked_add(
                super::initial_bundle_controls::frame_control_bytes_v1()?,
            )).ok_or_else(invalid)?;
        let cells = Clock::receiving_metadata_cells_v1()
            .and_then(|cells| cells.checked_mul(2)).ok_or_else(invalid)?;
        let fixed = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(memory).map_err(|_| invalid())?)
            .with(D::MetadataEntries, u64::try_from(cells).map_err(|_| invalid())?)
            .with(D::OpenFiles, 2 * Clock::MAXIMUM_RETAINED_FILES_V1 as u64);
        names.checked_add(names).and_then(|names| names.checked_add(fixed))
            .map_err(|_| invalid())
    }

    pub(super) fn failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.predecessor.as_ref().map(|error| error as _)
            .or_else(|| self.fixed.failure_v1())
            .or_else(|| cause(&self.framing))
            .or_else(|| cause(&self.assignment_framing))
            .or_else(|| cause(&self.geometry))
            .or_else(|| self.typed.failure_v1())
            .or_else(|| self.before.native_failure_v1())
            .or_else(|| self.before.returned_failure_v1())
            .or_else(|| cause(&self.before_readback))
            .or_else(|| self.before_clock.failure())
            .or_else(|| cause(&self.before_sample))
            .or_else(|| cause(&self.before_cutoff))
            .or_else(|| self.assignment.as_ref().and_then(|capture| capture.cause()))
            .or_else(|| cause(&self.assignment_decode))
            .or_else(|| self.claim.as_ref().and_then(|capture| capture.failure()).map(|cause| cause as _))
            .or_else(|| cause(&self.claim_decode))
            .or_else(|| cause(&self.association))
            .or_else(|| self.response.as_ref().and_then(|capture| capture.cause()))
            .or_else(|| cause(&self.verification))
            .or_else(|| cause(&self.primary))
            .or_else(|| self.after.native_failure_v1())
            .or_else(|| self.after.returned_failure_v1())
            .or_else(|| cause(&self.after_readback))
            .or_else(|| self.peer_history.as_ref().and_then(RootCurrentHistoryPostOriginalV1::failure_v1))
            .or_else(|| cause(&self.peer_arm))
            .or_else(|| cause(&self.peer))
            .or_else(|| self.after_clock.failure())
            .or_else(|| cause(&self.after_sample))
            .or_else(|| cause(&self.after_cutoff))
            .or_else(|| cause(&self.interval))
    }
}

fn require_clock(
    open: &RootInitialOpenPreparedOriginalV1,
    source: &RootInitialSourceExchangeOriginalV1,
    sample: &Option<Result<RawPairedClockSample, RootInitialClockErrorV1>>,
) -> Result<(), RootInitialOpenErrorV1> {
    let current = *positive(sample).map_err(|_| RootInitialOpenErrorV1::Boundary)?;
    let body = open.body_v1()?;
    open.clock_original_v1().require_current_v1(current, body.cutoff)?;
    let cutoff = source.original_cutoff_v1().map_err(|_| RootInitialOpenErrorV1::Boundary)?;
    let source = source.fields_v1().map_err(|_| RootInitialOpenErrorV1::Boundary)?;
    if current.boottime_nanoseconds() >= cutoff || current.host_boot_id() != source.boot
        || current.boottime_nanoseconds() < source.boottime_nanoseconds
        || current.wall_seconds() < source.wall_seconds
    {
        return Err(RootInitialOpenErrorV1::Boundary);
    }
    Ok(())
}

fn positive<T, F>(slot: &Option<Result<T, F>>) -> Result<&T, E> {
    slot.as_ref().and_then(|result| result.as_ref().ok()).ok_or(E::Incomplete)
}

fn cause<T, F: Error + 'static>(slot: &Option<Result<T, F>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _)
}

//! Retains Initial Cache proof verification on the same owned Current.
//!
//! The Root signer half starts before invitation19. Controller forwarding uses
//! the same strict subject receiver, while Root retains its independent signer
//! flight and issuer pin. Neither returned proof DATA nor a successful frame
//! constructs Controller, Use, append, released or terminal serving authority.

use std::error::Error;
use std::mem::size_of;

use aos_sandbox_broker::cache_current_signer_exchange::{
    CacheCurrentSignerExchangeClosedV1 as SignerClosed,
    CacheCurrentSignerExchangeOriginalsV1,
};
use aos_sandbox_broker::bounded_stream_io::FixedDeadlineStreamIoV1;
use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as Mechanical;
use aos_sandbox_broker::kernel_clock::RetainedKernelPairedClockAttemptV1;
use aos_sandbox_broker::receiving::{
    RootObservationErrorV1, RootSelectedControllerSubjectSampleV1,
    RootSelectedStartupBorrowV1, RootSubjectReadinessV1, RootUpperMutationGuardV1,
};
use aos_sandbox_model::{RawPairedClockSample, ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::seqpacket::SeqpacketError;
use aos_sandbox_linux::unix_stream::{
    RetainedSubjectStreamReadV1, SubjectStreamReadErrorV1, SubjectStreamReceiveGeometryV1,
};
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    HistoryErrorV1,
    cache_held::current_proof::{
        CacheCurrentProofBodyDataV1, CacheCurrentProofDataErrorV1,
        CacheCurrentProofVerifyCaptureV1,
    },
    ready::{ReadyBundleDataV1, InputsReadyNativeReceiptDataV1},
    root_open::RootHelloDataV1,
    transport::FRAME_HEADER_BYTES,
    use_authorized::CURRENT_PROOFS_PAYLOAD_BYTES_V1,
};

use crate::cache_current_data::{PROOFS_FRAME_BYTES, USE_PROOFS_FRAME_BYTES, received_proofs_v1, received_use_proofs_v1, require_same_reserved_receipt_v1, require_observed_clock};
use crate::native::PolicyNativeJournalErrorV1 as NativeError;
use crate::native::startup::RootCurrentWritersPredecessorV1;

use super::history_post::RootCurrentHistoryPostOriginalV1;
use super::initial_bundle::{RootInitialBundleOwnershipErrorV1, RootInitialBundleOwnershipOriginalV1};
use super::initial_location::RootInitialLocationPairOriginalV1;
use super::initial_open::{RootInitialClockErrorV1, RootInitialOpenErrorV1,
    RootInitialOpenPreparedOriginalV1};
use super::initial_pins::{RootInitialPinsErrorV1, RootInitialPinsOriginalV1};
use super::initial_ready::RootInitialReadyOriginalV1;
use super::initial_receiving::RootInitialStageOriginalV1;
use super::initial_source_exchange::{RootInitialSourceExchangeErrorV1, RootInitialSourceExchangeOriginalV1};
use super::initial_subject::RootInitialSubjectOriginalV1;
use super::owned::RootCurrentAcceptedOriginalsV1;
use super::writers::RootCurrentWritersOriginalV1;
use super::proof_turn::RootCurrentProofTurnV1;

mod frame;
pub use frame::RootInitialCacheProofFrameBorrowV1;

/// Retains refusal of the actual Initial Cache proof exchange.
#[derive(Debug, thiserror::Error)]
pub enum RootInitialCacheProofErrorV1 {
    /// Retains original Open, writer, subject or clock refusal.
    #[error(transparent)]
    Open(#[from] RootInitialOpenErrorV1),
    /// Retains refusal of the actual completed Ownership bundle.
    #[error(transparent)]
    Ownership(#[from] RootInitialBundleOwnershipErrorV1),
    /// Retains refusal of the actual independently captured issuer pins.
    #[error(transparent)]
    Pins(#[from] RootInitialPinsErrorV1),
    /// Retains refusal of the actual Source interval.
    #[error(transparent)]
    Source(#[from] RootInitialSourceExchangeErrorV1),
    /// Retains canonical frame, receipt, packet or clock correlation refusal.
    #[error(transparent)]
    Format(#[from] HistoryErrorV1),
    /// The same receiving, transport, verification or owed post is incomplete.
    #[error("initial Cache proof exchange is incomplete")]
    Incomplete,
}

type E = RootInitialCacheProofErrorV1;
type Clock = RetainedKernelPairedClockAttemptV1<RootInitialClockErrorV1>;
const HELLO_BYTES: usize = 612;
const INVITATION_BYTES: usize = 248;

#[derive(Clone, Copy)]
pub(super) enum CachePrefix<'held> {
    Ownership,
    Refreshed(&'held RootInitialSourceExchangeOriginalV1),
}

pub(super) struct RootInitialCacheProofOriginalV1 {
    stage: RootInitialStageOriginalV1,
    predecessor: Option<RootObservationErrorV1>,
    fixed_configuration: Option<Result<(u32, u32, u32), RootObservationErrorV1>>,
    turn_binding: Option<Result<Option<[u8; 32]>, E>>,
    framing: Option<Result<(), HistoryErrorV1>>,
    configuration: Option<Result<(u32, u32, u32), RootObservationErrorV1>>,
    hello: [u8; HELLO_BYTES],
    hello_copy: Option<Result<(), HistoryErrorV1>>,
    before: RootInitialLocationPairOriginalV1,
    before_readback: Option<Result<(), RootInitialOpenErrorV1>>,
    before_clock: Clock,
    before_sample: Option<Result<RawPairedClockSample, RootInitialClockErrorV1>>,
    before_cutoff: Option<Result<(), RootInitialOpenErrorV1>>,
    transport: CacheCurrentSignerExchangeOriginalsV1,
    begin: Option<Result<(), SignerClosed>>,
    invitation: [u8; INVITATION_BYTES],
    invitation_encoding: Option<Result<(), HistoryErrorV1>>,
    invitation_io: FixedDeadlineStreamIoV1<INVITATION_BYTES>,
    sent: Option<Result<(), HistoryErrorV1>>,
    geometry: Result<SubjectStreamReceiveGeometryV1, SeqpacketError>,
    received_frame: RetainedSubjectStreamReadV1,
    preparation: Option<Result<(), SubjectStreamReadErrorV1>>,
    chunks: RootInitialSubjectOriginalV1,
    prepared: Option<Result<(), E>>,
    received: Option<Result<(), E>>,
    proofs_binding: Option<Result<(), HistoryErrorV1>>,
    finish: Option<Result<(), SignerClosed>>,
    packet: Option<Result<(), SignerClosed>>,
    verification: CacheCurrentProofVerifyCaptureV1,
    verified: Option<Result<(), CacheCurrentProofDataErrorV1>>,
    association: Option<Result<(), HistoryErrorV1>>,
    primary: Option<Result<(), E>>,
    after: RootInitialLocationPairOriginalV1,
    after_readback: Option<Result<(), RootInitialOpenErrorV1>>,
    peer_history: Option<RootCurrentHistoryPostOriginalV1>,
    peer_arm: Option<Result<(), RootObservationErrorV1>>,
    peer: Option<Result<(), RootObservationErrorV1>>,
    after_clock: Clock,
    after_sample: Option<Result<RawPairedClockSample, RootInitialClockErrorV1>>,
    after_cutoff: Option<Result<(), RootInitialOpenErrorV1>>,
    interval: Option<Result<(), aos_sandbox_model::OwnershipLeaseVerificationError>>,
    cross_clock: Option<Result<(), HistoryErrorV1>>,
    body_entered: bool,
    closed: bool,
}

impl RootInitialCacheProofOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            stage: RootInitialStageOriginalV1::new(),
            predecessor: None,
            fixed_configuration: None,
            turn_binding: None,
            framing: None,
            configuration: None,
            hello: [0; HELLO_BYTES],
            hello_copy: None,
            before: RootInitialLocationPairOriginalV1::new(),
            before_readback: None,
            before_clock: Clock::default(),
            before_sample: None,
            before_cutoff: None,
            transport: CacheCurrentSignerExchangeOriginalsV1::new(),
            begin: None,
            invitation: [0; INVITATION_BYTES],
            invitation_encoding: None,
            invitation_io: FixedDeadlineStreamIoV1::default(),
            sent: None,
            geometry: RootSelectedControllerSubjectSampleV1::receive_geometry_v1(),
            received_frame: RetainedSubjectStreamReadV1::new(),
            preparation: None,
            chunks: RootInitialSubjectOriginalV1::new(),
            prepared: None,
            received: None,
            proofs_binding: None,
            finish: None,
            packet: None,
            verification: CacheCurrentProofVerifyCaptureV1::new(),
            verified: None,
            association: None,
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
            cross_clock: None,
            body_entered: false,
            closed: false,
        }
    }

    pub(super) fn entered_v1(&self) -> bool {
        self.stage.entered || self.body_entered
    }

    pub(super) fn claim_fixed_once_v1(&mut self) -> Result<(), RootObservationErrorV1> {
        if self.stage.entered || self.closed {
            self.closed = true;
            return Err(RootObservationErrorV1::Service);
        }
        self.stage.entered = true;
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
        ownership: &RootInitialBundleOwnershipOriginalV1,
        pins: &RootInitialPinsOriginalV1,
        predecessor: RootCurrentWritersPredecessorV1<'_, '_, '_>,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        self.begin_from_prefix_once_v1(open, ownership, pins, CachePrefix::Ownership,
            predecessor, startup, exclusion)
    }

    pub(super) fn begin_reserved_fixed_once_v1(
        &mut self,
        open: &RootInitialOpenPreparedOriginalV1,
        ownership: &RootInitialBundleOwnershipOriginalV1,
        pins: &RootInitialPinsOriginalV1,
        source: &RootInitialSourceExchangeOriginalV1,
        authorization: &super::initial_use_authorized::RootInitialUseAuthorizedOriginalV1,
        reserved: &super::use_tail::reserved::RootUseReservedOriginalV1,
        predecessor: RootCurrentWritersPredecessorV1<'_, '_, '_>,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        source.require_use_complete_for_v1(open, authorization, reserved)
            .map_err(|_| RootObservationErrorV1::Service)?;
        self.begin_from_prefix_once_v1(open, ownership, pins, CachePrefix::Refreshed(source),
            predecessor, startup, exclusion)
    }

    fn begin_from_prefix_once_v1(
        &mut self,
        open: &RootInitialOpenPreparedOriginalV1,
        ownership: &RootInitialBundleOwnershipOriginalV1,
        pins: &RootInitialPinsOriginalV1,
        prefix: CachePrefix<'_>,
        mut predecessor: RootCurrentWritersPredecessorV1<'_, '_, '_>,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        // Configuration comes from the actual completed peer, after the old
        // prerequisite checks and before the same financial receiver mutation.
        ownership.require_complete_v1().map_err(|_| RootObservationErrorV1::Service)?;
        pins.require_complete_v1().map_err(|_| RootObservationErrorV1::Service)?;
        self.fixed_configuration = Some(predecessor.controller_peer_original_v1()
            .current_cache_signer_identity_data_v1());
        let (initial, financial) = predecessor.split_initial_v1();
        if !self.stage.entered || self.stage.permit.is_some() || self.closed {
            self.closed = true;
            initial.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        }
        self.stage.financial = Some(financial.clone());
        self.stage.permit = Some((|| {
            ownership.require_complete_v1().map_err(|_| NativeError::boundary())?;
            pins.require_complete_v1().map_err(|_| NativeError::boundary())?;
            positive(&self.fixed_configuration).map_err(|_| NativeError::boundary())?;
            let body = open.body_v1().map_err(|_| NativeError::boundary())?;
            let enrollment = initial.enrollment_v1().ok_or_else(NativeError::boundary)?;
            if initial.failure().is_some()
                || !matches!(initial.recipient_binding_result_v1(), Some(Ok(())))
                || (body.root_recipient, body.root_producer)
                    != (enrollment.recipient_invocation, enrollment.identity.native_fields().invocation)
                || match prefix {
                    CachePrefix::Ownership => !ownership.same_financial_v1(financial),
                    CachePrefix::Refreshed(source) => !source.same_financial_v1(financial),
                }
                || !startup.same_financial_original_data_v1(financial)
            {
                return Err(NativeError::boundary());
            }
            let (base, additional) = match prefix {
                CachePrefix::Ownership => (
                    ownership.completed_prefix_v1().map_err(|_| NativeError::boundary())?,
                    Self::fixed_demand_v1()?,
                ),
                CachePrefix::Refreshed(source) => (
                    source.completed_prefix_v1().map_err(|_| NativeError::boundary())?,
                    Self::use_fixed_demand_v1()?,
                ),
            };
            let demand = base.checked_add(additional)
                .map_err(|_| NativeError::boundary())?;
            if financial.require_receiving_demand_under_upper_exclusion_v1(exclusion, demand).is_err() {
                return Err(NativeError::Financial(financial.clone()));
            }
            Ok(demand)
        })());
        self.stage.finish_v1(initial, startup, exclusion)
    }

    pub(super) fn observe_native_posts_once_v1(
        &mut self,
        writers: &RootCurrentWritersOriginalV1,
        open: &RootInitialOpenPreparedOriginalV1,
    ) {
        self.observe_native_posts_for_turn_once_v1(writers, open, RootCurrentProofTurnV1::Initial);
    }

    pub(super) fn observe_native_posts_for_turn_once_v1(
        &mut self,
        writers: &RootCurrentWritersOriginalV1,
        open: &RootInitialOpenPreparedOriginalV1,
        turn: RootCurrentProofTurnV1<'_>,
    ) {
        // The old fixed receiving entry establishes this owed post scope.
        // Framing, connection, invitation or verification failure never skips it.
        if self.stage.require_complete_v1().is_err() || self.after_readback.is_some() {
            return;
        }
        match writers.opened_pair_view_v1() {
            Ok((authority, policy)) => {
                self.after.observe_once_v1(authority, policy);
                self.after_readback = Some(turn.readback_v1(open, authority, policy));
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
        if self.stage.require_complete_v1().is_err() || self.after_readback.is_none()
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
        if self.stage.require_complete_v1().is_err() || self.after_readback.is_none()
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
            if let Some(body) = self.verification.body() {
                self.cross_clock = Some(require_observed_clock(body.sample, *before, *after));
            }
        }
    }

    pub(super) fn require_complete_v1(&self) -> Result<(), E> {
        if self.closed || self.failure_v1().is_some() {
            return Err(E::Incomplete);
        }
        self.stage.require_complete_v1()?;
        positive(&self.primary)?;
        self.after.require_complete_v1()?;
        positive(&self.after_readback)?;
        positive(&self.peer_arm)?;
        positive(&self.peer)?;
        positive(&self.after_cutoff)?;
        positive(&self.interval)?;
        positive(&self.cross_clock)?;
        if !self.chunks.disposed_v1() || !self.received_frame.completed_exact()
            || self.verification.body().is_none()
        {
            return Err(E::Incomplete);
        }
        Ok(())
    }

    // Only the completed SAME Cache stage lends the next purpose's prefix.
    pub(super) fn completed_prefix_v1(&self) -> Result<ResourceVector, E> {
        self.require_complete_v1()?;
        self.stage.require_complete_v1().map_err(E::from)
    }

    pub(super) fn same_financial_v1(
        &self,
        financial: &aos_sandbox_broker::receiving::RootJournalFinancialOriginalV1,
    ) -> bool {
        self.stage.financial.as_ref()
            .is_some_and(|original| original.same_original_data_v1(financial))
    }

    pub(super) fn verified_packet_v1(&self) -> Result<&[u8], E> {
        self.require_complete_v1()?;
        self.transport.packet().map(|packet| packet.as_slice()).map_err(|_| E::Incomplete)
    }

    pub(super) fn verified_body_v1(&self) -> Result<&CacheCurrentProofBodyDataV1, E> {
        self.require_complete_v1()?;
        self.verification.body().ok_or(E::Incomplete)
    }

    pub(super) fn controller_receipt_v1(
        &self,
        open: &RootInitialOpenPreparedOriginalV1,
        ready: &RootInitialReadyOriginalV1,
    ) -> Result<InputsReadyNativeReceiptDataV1<'_>, E> {
        self.require_complete_v1()?;
        let body = open.body_v1()?;
        let hello = RootHelloDataV1::decode(&self.hello, body.open)?;
        Ok(received_proofs_v1(self.received_frame.bytes(), hello,
            ready.original_transfer_index_v1()?)?.controller)
    }

    pub(super) fn current_proofs_payload_v1(&self) -> Result<&[u8; CURRENT_PROOFS_PAYLOAD_BYTES_V1], E> {
        self.require_complete_v1()?;
        self.received_frame.bytes().get(FRAME_HEADER_BYTES..)
            .and_then(|bytes| bytes.try_into().ok()).ok_or(E::Incomplete)
    }

    pub(super) fn require_use_complete_for_v1(
        &self,
        open: &RootInitialOpenPreparedOriginalV1,
        authorization: &super::initial_use_authorized::RootInitialUseAuthorizedOriginalV1,
        reserved: &super::use_tail::reserved::RootUseReservedOriginalV1,
    ) -> Result<(), E> {
        self.require_complete_v1()?;
        let expected = RootCurrentProofTurnV1::Reserved { authorization, reserved }
            .authorization_checksum_v1(open)?;
        if expected.is_none() || *positive(&self.turn_binding)? != expected {
            return Err(E::Incomplete);
        }
        Ok(())
    }

    pub(super) fn use_current_proofs_payload_v1(&self)
        -> Result<&[u8; aos_sandbox_protocol::domain_ledger::create_storage_history::use_reserved::USE_CURRENT_PROOFS_BYTES_V1], E>
    {
        self.require_complete_v1()?;
        self.received_frame.bytes().get(FRAME_HEADER_BYTES..)
            .and_then(|bytes| bytes.try_into().ok()).ok_or(E::Incomplete)
    }

    pub(super) fn use_fixed_demand_v1() -> Result<ResourceVector, NativeError> {
        use aos_sandbox_protocol::domain_ledger::create_storage_history::use_reserved::{
            UseCurrentProofsDataV1, UseReservedNativeReceiptDataV1,
        };
        let extra = (USE_PROOFS_FRAME_BYTES - PROOFS_FRAME_BYTES)
            .checked_add(4 * size_of::<UseCurrentProofsDataV1<'static>>())
            .and_then(|bytes| bytes.checked_add(4 * size_of::<UseReservedNativeReceiptDataV1<'static>>()))
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or_else(NativeError::geometry)?;
        Self::fixed_demand_v1()?.checked_add(ResourceVector::ZERO
            .with(D::MemoryBytes, extra)
            .with(D::NetworkBytes, (USE_PROOFS_FRAME_BYTES - PROOFS_FRAME_BYTES) as u64))
            .map_err(|_| NativeError::geometry())
    }

    pub(super) fn fixed_demand_v1() -> Result<ResourceVector, NativeError> {
        let invalid = || NativeError::Mechanical(Mechanical::JournalTooLarge);
        let (transport_bytes, transport_files, transport_cells) =
            CacheCurrentSignerExchangeOriginalsV1::additional_receiving_shape_v1().ok_or_else(invalid)?;
        let verification = CacheCurrentProofVerifyCaptureV1::receiving_additional_inline_bytes_v1()
            .and_then(|bytes| bytes.checked_add(
                CacheCurrentProofVerifyCaptureV1::receiving_additional_heap_bytes_v1()?,
            )).ok_or_else(invalid)?;
        let bytes = size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(transport_bytes))
            .and_then(|bytes| bytes.checked_add(verification))
            .and_then(|bytes| bytes.checked_add(PROOFS_FRAME_BYTES))
            .and_then(|bytes| bytes.checked_add(crate::cache_current_data::fixed_framing_receiving_bytes_v1()?))
            .and_then(|bytes| bytes.checked_add(2 * size_of::<usize>()))
            .and_then(|bytes| bytes.checked_add(super::initial_cache_controls::frame_control_bytes_v1()?))
            .ok_or_else(invalid)?;
        let cells = Some(transport_cells)
            .and_then(|cells| cells.checked_add(CacheCurrentProofVerifyCaptureV1::receiving_metadata_cells_v1()?))
            .and_then(|cells| cells.checked_add(FixedDeadlineStreamIoV1::<INVITATION_BYTES>::receiving_metadata_cells_v1()))
            .ok_or_else(invalid)?;
        let mut demand = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).map_err(|_| invalid())?)
            .with(D::MetadataEntries, u64::try_from(cells).map_err(|_| invalid())?)
            .with(D::OpenFiles, u64::try_from(transport_files).map_err(|_| invalid())?)
            .with(D::NetworkBytes, (INVITATION_BYTES + PROOFS_FRAME_BYTES) as u64);
        let native: Result<ResourceVector, NativeError> = aos_sandbox_broker::root_subject_receiving_demand_v1! {
            sample: RootSelectedControllerSubjectSampleV1,
            readiness: RootSubjectReadinessV1,
            error: NativeError::geometry(),
        };
        let chunk_clock = super::initial_ready_controls::clock_demand_v1()?;
        demand = demand.checked_add(native?)
            .and_then(|demand| demand.checked_add(chunk_clock))
            .map_err(|_| invalid())?;
        demand = demand.checked_add(ReadyBundleDataV1::fixed_framing_receiving_demand_v1().ok_or_else(invalid)?)
            .map_err(|_| invalid())?;
        let names = RootInitialLocationPairOriginalV1::additional_native_demand_v1()?;
        let pair = Clock::dominant_requested_bytes_v1()
            .and_then(|bytes| bytes.checked_sub(size_of::<Clock>()))
            .and_then(|bytes| bytes.checked_mul(2))
            .ok_or_else(invalid)?;
        let posts = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(pair).map_err(|_| invalid())?)
            .with(D::OpenFiles, 2 * Clock::MAXIMUM_RETAINED_FILES_V1 as u64);
        demand = demand.checked_add(names).and_then(|demand| demand.checked_add(names))
            .and_then(|demand| demand.checked_add(posts)).map_err(|_| invalid())?;
        // The old fixed Cache law mirrors complete Memory into Output.
        Ok(demand.with(D::OutputBytes, demand.get(D::MemoryBytes)))
    }

    pub(super) fn failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.predecessor.as_ref().map(|error| error as _)
            .or_else(|| cause(&self.fixed_configuration))
            .or_else(|| self.stage.failure_v1())
            .or_else(|| self.geometry.as_ref().err().map(|error| error as _))
            .or_else(|| cause(&self.turn_binding))
            .or_else(|| cause(&self.framing))
            .or_else(|| cause(&self.configuration))
            .or_else(|| cause(&self.hello_copy))
            .or_else(|| self.before.native_failure_v1())
            .or_else(|| self.before.returned_failure_v1())
            .or_else(|| cause(&self.before_readback))
            .or_else(|| self.before_clock.failure())
            .or_else(|| cause(&self.before_sample))
            .or_else(|| cause(&self.before_cutoff))
            .or_else(|| retained_transport_cause(&self.begin, &self.transport))
            .or_else(|| cause(&self.invitation_encoding))
            .or_else(|| self.invitation_io.failure())
            .or_else(|| cause(&self.sent))
            .or_else(|| if matches!(self.preparation, Some(Err(SubjectStreamReadErrorV1::Retained))) {
                self.received_frame.failure().or_else(|| cause(&self.preparation))
            } else {
                cause(&self.preparation)
            })
            .or_else(|| cause(&self.prepared))
            .or_else(|| self.chunks.failure_v1(&self.received_frame))
            .or_else(|| cause(&self.received))
            .or_else(|| cause(&self.proofs_binding))
            .or_else(|| retained_transport_cause(&self.finish, &self.transport))
            .or_else(|| cause(&self.packet))
            .or_else(|| self.verification.failure())
            .or_else(|| cause(&self.verified))
            .or_else(|| cause(&self.association))
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
            .or_else(|| cause(&self.cross_clock))
    }
}

fn retained_transport_cause<'a>(
    slot: &'a Option<Result<(), SignerClosed>>,
    transport: &'a CacheCurrentSignerExchangeOriginalsV1,
) -> Option<&'a (dyn Error + 'static)> {
    if matches!(slot, Some(Err(_))) {
        transport.failure().or_else(|| cause(slot))
    } else {
        None
    }
}

pub(super) fn require_clock(
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

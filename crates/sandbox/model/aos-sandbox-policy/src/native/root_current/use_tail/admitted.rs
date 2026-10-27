//! Retains Root3, the original unsigned plan transfer and all owed bookends.
//!
//! Genuine refreshed Source and Cache purposes follow the distinct Reserved
//! Controller replay. Their same financial prefix pays this local append;
//! unsigned plan bytes do not adopt a signing or later continuation permission.

use std::collections::TryReserveError;
use std::error::Error;
use std::fs::Metadata;
use std::io;

use aos_sandbox_broker::bounded_stream_io::SliceDeadlineStreamIoV1;
use aos_sandbox_broker::receiving::{RootJournalFinancialOriginalV1, RootObservationErrorV1};
use aos_sandbox_model::ResourceVector;
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    HistoryErrorV1,
    continuation::{
        ContinuationNativeReceiptDataV1, USE_ADMITTED_BODY_BYTES_V1, USE_ADMITTED_RECEIPT_BYTES_V1,
        USE_ADMITTED_RECORD_BYTES_V1, UseAdmittedBodyDataV1,
    },
    readback::HistoryPairReadbackDataV1,
};

use super::super::history_pair::RootCurrentHistoryPairV1;
use super::super::initial_open::RootInitialOpenErrorV1;
use super::super::initial_post::RootInitialOpenPostsOriginalV1;
use super::super::initial_receiving::RootInitialStageOriginalV1;
use super::reserved::RootUseReservedErrorV1;
use crate::native::PolicyNativeJournalErrorV1 as NativeError;
use crate::native::journal::RootPolicyJournalV1;
use crate::native::target::RootPolicyTargetOriginalV1;

mod body;
mod execution;

type Readback = HistoryPairReadbackDataV1<USE_ADMITTED_RECORD_BYTES_V1>;
type Slot<T, F = RootUseAdmittedErrorV1> = Option<Result<T, F>>;

/// Retains actual Root3 admission, transfer and independent post refusal.
#[derive(Debug, thiserror::Error)]
pub enum RootUseAdmittedErrorV1 {
    /// Retains the same native history pair, peer, readback or clock cause.
    #[error(transparent)]
    Open(#[from] RootInitialOpenErrorV1),
    /// Retains the actual same-Initial receiving or arm refusal.
    #[error(transparent)]
    Root(#[from] RootObservationErrorV1),
    /// Retains the actual local financial or geometry cause.
    #[error(transparent)]
    Native(#[from] NativeError),
    /// Retains refusal of the genuine Reserved purpose.
    #[error(transparent)]
    Reserved(#[from] RootUseReservedErrorV1),
    /// Retains actual completed authorization refusal.
    #[error(transparent)]
    Authorization(#[from] super::super::initial_use_authorized::RootInitialUseAuthorizedErrorV1),
    /// Retains actual same-file Controller model or protected plan refusal.
    #[error(transparent)]
    Controller(#[from] super::super::initial_controller::RootInitialControllerReadonlyErrorV1),
    /// Retains the same refreshed Source authentication/currentness refusal.
    #[error(transparent)]
    Source(#[from] super::super::initial_source_exchange::RootInitialSourceExchangeErrorV1),
    /// Retains the same refreshed Cache receipt/currentness refusal.
    #[error(transparent)]
    Cache(#[from] super::super::initial_cache::RootInitialCacheProofErrorV1),
    /// Retains actual compiled/Storage liveness refusal.
    #[error(transparent)]
    Read(#[from] crate::native::readonly::RootReadonlyErrorV1),
    /// Retains canonical body, receipt, framing or deadline IO refusal.
    #[error(transparent)]
    Format(#[from] HistoryErrorV1),
    /// The same actual stage, append, transfer or owed post is incomplete.
    #[error("Root UseAdmitted continuation is incomplete")]
    Incomplete,
}
type E = RootUseAdmittedErrorV1;

pub(in crate::native::root_current) struct RootUseAdmittedOriginalV1 {
    pub(in crate::native::root_current) fixed: RootInitialStageOriginalV1,
    pub(in crate::native::root_current) predecessor: Option<RootObservationErrorV1>,
    quote: Slot<ResourceVector, NativeError>,
    body: Slot<UseAdmittedBodyDataV1>,
    encoded: Slot<[u8; USE_ADMITTED_BODY_BYTES_V1], HistoryErrorV1>,
    pub(in crate::native::root_current) pair:
        RootCurrentHistoryPairV1<USE_ADMITTED_RECORD_BYTES_V1>,
    pub(in crate::native::root_current) primary: Slot<()>,
    pub(in crate::native::root_current) append_posts: RootInitialOpenPostsOriginalV1,
    pub(in crate::native::root_current) append_arm: Slot<(), RootObservationErrorV1>,
    append_live: Slot<()>,
    pub(in crate::native::root_current) crossing_refusal: Option<RootObservationErrorV1>,
    receipt: [u8; USE_ADMITTED_RECEIPT_BYTES_V1],
    frame_length: Slot<usize, HistoryErrorV1>,
    allocation: Slot<(), TryReserveError>,
    frame: Vec<u8>,
    pub(in crate::native::root_current) framing: Slot<(), HistoryErrorV1>,
    send: SliceDeadlineStreamIoV1,
    sent: Slot<(), HistoryErrorV1>,
    pub(in crate::native::root_current) send_posts: RootInitialOpenPostsOriginalV1,
    pub(in crate::native::root_current) send_arm: Slot<(), RootObservationErrorV1>,
    send_readback: Slot<Readback, RootInitialOpenErrorV1>,
    send_metadata: Option<io::Result<Metadata>>,
    send_live: Slot<()>,
    pub(in crate::native::root_current) closed: bool,
    complete: bool,
}

impl RootUseAdmittedOriginalV1 {
    pub(in crate::native::root_current) fn new() -> Self {
        Self {
            fixed: RootInitialStageOriginalV1::new(),
            predecessor: None,
            quote: None,
            body: None,
            encoded: None,
            pair: RootCurrentHistoryPairV1::new(),
            primary: None,
            append_posts: RootInitialOpenPostsOriginalV1::new(),
            append_arm: None,
            append_live: None,
            crossing_refusal: None,
            receipt: [0; USE_ADMITTED_RECEIPT_BYTES_V1],
            frame_length: None,
            allocation: None,
            frame: Vec::new(),
            framing: None,
            send: Default::default(),
            sent: None,
            send_posts: RootInitialOpenPostsOriginalV1::new(),
            send_arm: None,
            send_readback: None,
            send_metadata: None,
            send_live: None,
            closed: false,
            complete: false,
        }
    }

    pub(in crate::native::root_current) fn require_complete_v1(&self) -> Result<(), E> {
        self.fixed.require_complete_v1()?;
        if self.complete && !self.closed && self.failure_v1().is_none() {
            Ok(())
        } else {
            Err(E::Incomplete)
        }
    }

    pub(in crate::native::root_current) fn completed_prefix_v1(&self) -> Result<ResourceVector, E> {
        self.require_complete_v1()?;
        self.fixed.require_complete_v1().map_err(E::from)
    }

    pub(in crate::native::root_current) fn same_financial_v1(
        &self,
        financial: &RootJournalFinancialOriginalV1,
    ) -> bool {
        self.fixed
            .financial
            .as_ref()
            .is_some_and(|same| same.same_original_data_v1(financial))
    }

    pub(in crate::native::root_current) fn completed_receipt_v1(
        &self,
    ) -> Result<ContinuationNativeReceiptDataV1<'_>, E> {
        self.require_complete_v1()?;
        self.receipt_data_v1()
    }

    fn receipt_data_v1(&self) -> Result<ContinuationNativeReceiptDataV1<'_>, E> {
        let observed = positive(&self.pair.readback)?;
        let committed = positive(&self.pair.append)?;
        Ok(ContinuationNativeReceiptDataV1 {
            record: &self.pair.record,
            latest_head: observed.head,
            names: self.append_posts.authority_names_v1()?,
            after_next: observed.next,
            after_end: committed.durable_bytes,
        })
    }

    pub(in crate::native::root_current) fn readback_current_v1(
        &self,
        authority: &RootPolicyJournalV1,
        policy: &RootPolicyTargetOriginalV1,
    ) -> Result<Readback, RootInitialOpenErrorV1> {
        self.require_complete_v1()
            .map_err(|_| RootInitialOpenErrorV1::Boundary)?;
        self.pair.readback_current_v1(authority, policy)
    }

    pub(in crate::native::root_current) fn failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.predecessor
            .as_ref()
            .map(|cause| cause as _)
            .or_else(|| cause(&self.quote))
            .or_else(|| self.fixed.failure_v1())
            .or_else(|| cause(&self.body))
            .or_else(|| cause(&self.encoded))
            .or_else(|| self.pair.failure_v1())
            .or_else(|| self.crossing_refusal.as_ref().map(|cause| cause as _))
            .or_else(|| cause(&self.primary))
            .or_else(|| self.append_posts.failure_v1())
            .or_else(|| cause(&self.append_arm))
            .or_else(|| cause(&self.append_live))
            .or_else(|| cause(&self.frame_length))
            .or_else(|| cause(&self.allocation))
            .or_else(|| cause(&self.framing))
            .or_else(|| self.send.failure())
            .or_else(|| cause(&self.sent))
            .or_else(|| self.send_posts.failure_v1())
            .or_else(|| cause(&self.send_arm))
            .or_else(|| cause(&self.send_readback))
            .or_else(|| cause(&self.send_metadata))
            .or_else(|| cause(&self.send_live))
    }
}

fn positive<T, F>(slot: &Option<Result<T, F>>) -> Result<&T, E> {
    slot.as_ref()
        .and_then(|value| value.as_ref().ok())
        .ok_or(E::Incomplete)
}
fn cause<T, F: Error + 'static>(slot: &Option<Result<T, F>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref()
        .and_then(|value| value.as_ref().err())
        .map(|cause| cause as _)
}

impl RootUseAdmittedOriginalV1 {
    pub(in crate::native::root_current) fn construction_control_bytes_v1() -> Option<usize> {
        use std::mem::size_of;
        type Pair = RootCurrentHistoryPairV1<USE_ADMITTED_RECORD_BYTES_V1>;
        type Names = crate::native::journal::names::RootPolicyNameObservationOriginalV1;
        type Clock = aos_sandbox_broker::kernel_clock::RetainedKernelPairedClockAttemptV1<
            super::super::initial_open::RootInitialClockErrorV1,
        >;

        // These are the nested construction and return values actually made by
        // new(). Their inline residency is separately reflected by the whole owner.
        let constructors = size_of::<Self>()
            .checked_mul(2)?
            .checked_add(size_of::<Pair>().checked_mul(2)?)?
            .checked_add(size_of::<RootInitialStageOriginalV1>().checked_mul(2)?)?
            .checked_add(size_of::<RootInitialOpenPostsOriginalV1>().checked_mul(4)?)?
            .checked_add(
                size_of::<super::super::initial_open::RootInitialOpenCrossingOriginalV1>()
                    .checked_mul(2)?,
            )?
            .checked_add(size_of::<Clock>().checked_mul(6)?)?
            .checked_add(size_of::<SliceDeadlineStreamIoV1>().checked_mul(2)?)?
            .checked_add(size_of::<Vec<u8>>().checked_mul(2)?)?;
        let names = usize::try_from(
            Names::fixed_carrier_demand_v1()?.get(aos_sandbox_model::ResourceDimension::MemoryBytes),
        )
        .ok()?
        .checked_mul(12)?;
        let queries = size_of::<&Self>()
            .checked_mul(18)?
            .checked_add(size_of::<Result<(), E>>().checked_mul(18)?)?
            .checked_add(size_of::<Result<ResourceVector, E>>().checked_mul(3)?)?
            .checked_add(
                size_of::<Result<ContinuationNativeReceiptDataV1<'_>, E>>().checked_mul(6)?,
            )?
            .checked_add(size_of::<(&Self, &RootJournalFinancialOriginalV1)>().checked_mul(3)?)?
            .checked_add(size_of::<bool>().checked_mul(3)?)?;
        // The selector has twenty fallback closures sharing this same owner.
        // Their environments are shared captures, distinct from the returned errors.
        let diagnostics = size_of::<&&Self>()
            .checked_mul(20 * 3)?
            .checked_add(size_of::<Option<&(dyn Error + 'static)>>().checked_mul(25 * 3)?)?;
        let framing = size_of::<Result<usize, HistoryErrorV1>>()
            .checked_mul(3)?
            .checked_add(size_of::<Result<(), TryReserveError>>().checked_mul(3)?)?
            .checked_add(size_of::<Result<(), HistoryErrorV1>>().checked_mul(12)?)?;
        constructors
            .checked_add(names)?
            .checked_add(queries)?
            .checked_add(diagnostics)?
            .checked_add(framing)?
            .checked_add(super::super::initial_open::continuation_control_bytes_v1()?)?
            .checked_add(Pair::control_bytes_v1()?)
    }
}

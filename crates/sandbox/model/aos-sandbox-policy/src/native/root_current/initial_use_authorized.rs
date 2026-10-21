//! Produces Root's second history pair from its completed native Current cut.
//!
//! The local Root Stage pays this append, retained state and its owed posts.
//! The full Create-U calculation is only an unsigned future receiving proposal:
//! Controller independently admits its own real use programme before effects.

use std::error::Error;
use std::fs::Metadata;
use std::io;

use aos_sandbox_broker::bounded_stream_io::{FixedDeadlineStreamIoV1, DeadlineStreamDirectionV1};
use aos_sandbox_broker::receiving::RootObservationErrorV1;
use aos_sandbox_model::{RawPairedClockSample, ResourceVector};
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    HistoryErrorV1,
    use_authorized::{UseAuthorizedBodyDataV1, UseAuthorizedNativeReceiptDataV1,
        USE_AUTHORIZED_BODY_BYTES_V1, USE_AUTHORIZED_RECORD_BYTES_V1,
        USE_AUTHORIZED_FRAME_BYTES_V1},
    readback::HistoryPairReadbackDataV1,
};

use crate::native::PolicyNativeJournalErrorV1;
use crate::native::journal::RootPolicyJournalV1;
use crate::native::target::RootPolicyTargetOriginalV1;

use super::history_pair::RootCurrentHistoryPairV1;
use super::initial_open::RootInitialOpenErrorV1;
use super::initial_post::RootInitialOpenPostsOriginalV1;
use super::initial_receiving::RootInitialStageOriginalV1;

mod prepared;
mod execute;
pub use prepared::{RootInitialUseAuthorizedPreparedBorrowV1, RootInitialUseProspectiveInputsDataV1};

type Readback = HistoryPairReadbackDataV1<USE_AUTHORIZED_RECORD_BYTES_V1>;
type Slot<T, F = RootInitialUseAuthorizedErrorV1> = Option<Result<T, F>>;

/// Retains refusal of the genuine Root UseAuthorized programme.
#[derive(Debug, thiserror::Error)]
pub enum RootInitialUseAuthorizedErrorV1 {
    /// Retains the actual same-pair append, readback, original clock or peer cause.
    #[error(transparent)]
    Open(#[from] RootInitialOpenErrorV1),
    /// Retains the actual same-financial local Root receiving refusal.
    #[error(transparent)]
    Native(#[from] PolicyNativeJournalErrorV1),
    /// Retains the same Root service or separately owed arm refusal.
    #[error(transparent)]
    Root(#[from] RootObservationErrorV1),
    /// Retains canonical record, receipt, frame or standard write refusal.
    #[error(transparent)]
    Format(#[from] HistoryErrorV1),
    /// The actual predecessor, local Stage, body, append or owed post is incomplete.
    #[error("Root UseAuthorized programme is incomplete")]
    Incomplete,
}

type E = RootInitialUseAuthorizedErrorV1;

pub(super) struct RootInitialUseAuthorizedOriginalV1 {
    pub(super) fixed: RootInitialStageOriginalV1,
    pub(super) fixed_quote: Slot<ResourceVector, PolicyNativeJournalErrorV1>,
    pub(super) predecessor: Option<RootObservationErrorV1>,
    pub(super) receiving: Slot<ResourceVector, crate::storage_session_geometry_data::StorageSessionGeometryRefusalV1>,
    pub(super) body: Slot<UseAuthorizedBodyDataV1>,
    pub(super) body_encoding: Slot<[u8; USE_AUTHORIZED_BODY_BYTES_V1], HistoryErrorV1>,
    pub(super) pair: RootCurrentHistoryPairV1<USE_AUTHORIZED_RECORD_BYTES_V1>,
    pub(super) primary: Slot<()>,
    pub(super) crossing_refusal: Option<RootObservationErrorV1>,
    pub(super) body_borrowed: bool,
    pub(super) append_posts: RootInitialOpenPostsOriginalV1,
    pub(super) append_arm: Slot<(), RootObservationErrorV1>,
    pub(super) append_live: Slot<()>,
    pub(super) hello: [u8; 612],
    pub(super) frame: [u8; USE_AUTHORIZED_FRAME_BYTES_V1],
    pub(super) framing: Slot<(), HistoryErrorV1>,
    pub(super) send: FixedDeadlineStreamIoV1<USE_AUTHORIZED_FRAME_BYTES_V1>,
    pub(super) sent: Slot<(), HistoryErrorV1>,
    pub(super) send_posts: RootInitialOpenPostsOriginalV1,
    pub(super) send_arm: Slot<(), RootObservationErrorV1>,
    pub(super) send_readback: Slot<Readback, RootInitialOpenErrorV1>,
    pub(super) send_native_end: Option<io::Result<Metadata>>,
    pub(super) send_live: Slot<()>,
    pub(super) complete: bool,
    pub(super) closed: bool,
}

impl RootInitialUseAuthorizedOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            fixed: RootInitialStageOriginalV1::new(),
            fixed_quote: None,
            predecessor: None,
            receiving: None,
            body: None,
            body_encoding: None,
            pair: RootCurrentHistoryPairV1::new(),
            primary: None,
            crossing_refusal: None,
            body_borrowed: false,
            append_posts: RootInitialOpenPostsOriginalV1::new(),
            append_arm: None,
            append_live: None,
            hello: [0; 612],
            frame: [0; USE_AUTHORIZED_FRAME_BYTES_V1],
            framing: None,
            send: Default::default(),
            sent: None,
            send_posts: RootInitialOpenPostsOriginalV1::new(),
            send_arm: None,
            send_readback: None,
            send_native_end: None,
            send_live: None,
            complete: false,
            closed: false,
        }
    }

    pub(super) fn require_complete_v1(&self) -> Result<(), E> {
        self.fixed.require_complete_v1()?;
        if self.complete && !self.closed && self.failure_v1().is_none() {
            Ok(())
        } else {
            Err(E::Incomplete)
        }
    }

    pub(super) fn completed_body_v1(&self) -> Result<&UseAuthorizedBodyDataV1, E> {
        self.require_complete_v1()?;
        positive(&self.body)
    }

    pub(super) fn completed_receipt_v1(&self) -> Result<UseAuthorizedNativeReceiptDataV1<'_>, E> {
        self.require_complete_v1()?;
        self.receipt_data_v1()
    }

    pub(super) fn receipt_data_v1(&self) -> Result<UseAuthorizedNativeReceiptDataV1<'_>, E> {
        positive(&self.body)?;
        let observed = positive(&self.pair.readback)?;
        let committed = positive(&self.pair.append)?;
        Ok(UseAuthorizedNativeReceiptDataV1 {
            record: &self.pair.record,
            latest_head: observed.head,
            names: self.append_posts.authority_names_v1()?,
            after_next: observed.next,
            after_end: committed.durable_bytes,
        })
    }

    pub(super) fn readback_current_v1(
        &self,
        authority: &RootPolicyJournalV1,
        policy: &RootPolicyTargetOriginalV1,
    ) -> Result<Readback, RootInitialOpenErrorV1> {
        self.require_complete_v1().map_err(|_| RootInitialOpenErrorV1::Boundary)?;
        self.pair.readback_current_v1(authority, policy)
    }

    pub(super) fn completed_prefix_v1(&self) -> Result<ResourceVector, E> {
        self.require_complete_v1()?;
        self.fixed.require_complete_v1().map_err(E::from)
    }

    pub(super) fn same_financial_v1(&self, financial: &aos_sandbox_broker::receiving::RootJournalFinancialOriginalV1)
        -> bool
    {
        self.fixed.financial.as_ref().is_some_and(|same| same.same_original_data_v1(financial))
    }

    pub(super) fn failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.predecessor.as_ref().map(|error| error as _)
            .or_else(|| cause(&self.fixed_quote))
            .or_else(|| self.fixed.failure_v1())
            .or_else(|| cause(&self.receiving))
            .or_else(|| cause(&self.body))
            .or_else(|| cause(&self.body_encoding))
            .or_else(|| self.pair.failure_v1())
            .or_else(|| self.crossing_refusal.as_ref().map(|error| error as _))
            .or_else(|| cause(&self.primary))
            .or_else(|| self.append_posts.arm_failure_v1())
            .or_else(|| cause(&self.append_arm))
            .or_else(|| self.append_posts.failure_v1())
            .or_else(|| cause(&self.append_live))
            .or_else(|| cause(&self.framing))
            .or_else(|| self.send.failure())
            .or_else(|| cause(&self.sent))
            .or_else(|| self.send_posts.arm_failure_v1())
            .or_else(|| cause(&self.send_arm))
            .or_else(|| self.send_posts.failure_v1())
            .or_else(|| cause(&self.send_readback))
            .or_else(|| cause(&self.send_native_end))
            .or_else(|| cause(&self.send_live))
    }
}

pub(super) fn require_live_v1(
    open: &super::initial_open::RootInitialOpenPreparedOriginalV1,
    source: &super::initial_source_exchange::RootInitialSourceExchangeOriginalV1,
    readonly: &super::initial_controller::RootInitialControllerReadonlyOriginalV1,
    sample: RawPairedClockSample,
) -> Result<(), E> {
    let body = open.body_v1()?;
    open.clock_original_v1().require_current_v1(sample, body.cutoff)
        .map_err(RootInitialOpenErrorV1::from)?;
    readonly.require_live_at_v1(sample).map_err(|_| E::Incomplete)?;
    if sample.boottime_nanoseconds() >= source.original_cutoff_v1().map_err(|_| E::Incomplete)? {
        return Err(E::Incomplete);
    }
    Ok(())
}

pub(super) fn positive<T, F>(slot: &Option<Result<T, F>>) -> Result<&T, E> {
    slot.as_ref().and_then(|result| result.as_ref().ok()).ok_or(E::Incomplete)
}

fn cause<T, F: Error + 'static>(slot: &Option<Result<T, F>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _)
}


impl RootInitialUseAuthorizedOriginalV1 {
    pub(super) fn receiving_construction_bytes_v1() -> Option<usize> {
        use std::mem::size_of;
        type Pair = RootCurrentHistoryPairV1<USE_AUTHORIZED_RECORD_BYTES_V1>;
        type Names = crate::native::journal::names::RootPolicyNameObservationOriginalV1;
        type Clock = aos_sandbox_broker::kernel_clock::RetainedKernelPairedClockAttemptV1<
            super::initial_open::RootInitialClockErrorV1>;
        let constructors = size_of::<Self>().checked_mul(2)?
            .checked_add(size_of::<Pair>().checked_mul(2)?)?
            .checked_add(size_of::<RootInitialStageOriginalV1>().checked_mul(2)?)?
            .checked_add(size_of::<RootInitialOpenPostsOriginalV1>().checked_mul(4)?)?
            .checked_add(size_of::<super::initial_open::RootInitialOpenCrossingOriginalV1>().checked_mul(2)?)?
            .checked_add(size_of::<Clock>().checked_mul(6)?)?
            .checked_add(size_of::<FixedDeadlineStreamIoV1<USE_AUTHORIZED_FRAME_BYTES_V1>>().checked_mul(2)?)?;
        let names = usize::try_from(Names::fixed_carrier_demand_v1()?.get(aos_sandbox_model::ResourceDimension::MemoryBytes)).ok()?
            .checked_mul(12)?;
        let queries = size_of::<&Self>().checked_mul(21)?
            .checked_add(size_of::<Result<(), E>>().checked_mul(18)?)?
            .checked_add(size_of::<Result<&UseAuthorizedBodyDataV1, E>>().checked_mul(3)?)?
            .checked_add(size_of::<Result<UseAuthorizedNativeReceiptDataV1<'_>, E>>().checked_mul(6)?)?
            .checked_add(size_of::<Result<ResourceVector, E>>().checked_mul(3)?)?
            .checked_add(size_of::<(&Self, &aos_sandbox_broker::receiving::RootJournalFinancialOriginalV1)>().checked_mul(3)?)?
            .checked_add(size_of::<bool>().checked_mul(3)?)?;
        let proposal = size_of::<RootInitialUseAuthorizedPreparedBorrowV1<'_>>().checked_mul(2)?
            .checked_add(size_of::<&RootInitialUseAuthorizedPreparedBorrowV1<'_>>().checked_mul(6)?)?
            .checked_add(size_of::<RootInitialUseProspectiveInputsDataV1<'_>>().checked_mul(3)?)?
            .checked_add(size_of::<Result<RootInitialUseProspectiveInputsDataV1<'_>, E>>().checked_mul(3)?)?
            .checked_add(size_of::<(&mut RootInitialUseAuthorizedPreparedBorrowV1<'_>,
                Result<ResourceVector, crate::storage_session_geometry_data::StorageSessionGeometryRefusalV1>)>().checked_mul(3)?)?
            .checked_add(size_of::<Result<UseAuthorizedBodyDataV1, E>>().checked_mul(3)?)?;
        let diagnostics = size_of::<&&Self>().checked_mul(25 * 3)?
            .checked_add(size_of::<Option<&(dyn Error + 'static)>>().checked_mul(25 * 3)?)?;
        constructors.checked_add(names)?.checked_add(queries)?.checked_add(proposal)?
            .checked_add(diagnostics)?.checked_add(super::initial_open::continuation_control_bytes_v1()?)?
            .checked_add(RootCurrentHistoryPairV1::<USE_AUTHORIZED_RECORD_BYTES_V1>::control_bytes_v1()?)?
            .checked_add(execute::control_bytes_v1()?)?
            .checked_add(super::initial_geometry::use_authorized_control_bytes_v1()?)?
            .checked_add(super::owned::RootOwnedCurrentOriginalV1::use_authorized_control_bytes_v1()?)
    }
}

//! Retains the genuine Root4 Signed phase and every reached negative original.

use super::super::{
    history_pair::RootCurrentHistoryPairV1,
    initial_controller::{
        RootInitialControllerReadonlyErrorV1, RootInitialControllerReadonlyOriginalV1,
    },
    initial_open::{RootInitialOpenErrorV1, RootInitialOpenPreparedOriginalV1},
    initial_post::RootInitialOpenPostsOriginalV1,
    initial_receiving::RootInitialStageOriginalV1,
    initial_use_authorized::RootInitialUseAuthorizedOriginalV1,
};
use super::signed_input::{RootSignedInputErrorV1, RootSignedInputOriginalV1};
use super::{
    admitted::{RootUseAdmittedErrorV1, RootUseAdmittedOriginalV1},
    reserved::{RootUseReservedErrorV1, RootUseReservedOriginalV1},
};
use crate::native::PolicyNativeJournalErrorV1 as NativeError;
use crate::native::{RootPolicyJournalV1, RootPolicyTargetOriginalV1};
use aos_sandbox_broker::bounded_stream_io::SliceDeadlineStreamIoV1;
use aos_sandbox_broker::receiving::{RootJournalFinancialOriginalV1, RootObservationErrorV1};
use aos_sandbox_model::{RawPairedClockSample, ResourceVector};
use aos_sandbox_protocol::domain_ledger::create_storage_history::continuation::{
    SIGNED_BOUND_BODY_BYTES_V1, SIGNED_BOUND_RECEIPT_BYTES_V1, SIGNED_BOUND_RECORD_BYTES_V1,
    SignedBoundBodyDataV1,
};
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    HistoryErrorV1, KeyV1, OwnerV1, PhaseV1, RecordEnvelopeV1,
    continuation::{ContinuationNativeReceiptDataV1, SignedPreparationBundleDataV1},
    readback::HistoryPairReadbackDataV1,
    transport::{FRAME_HEADER_BYTES, TransferIndexV1},
};
use std::error::Error;
use std::fs::Metadata;
use std::io;
mod execution;
mod geometry;
pub(in crate::native::root_current) mod received;
mod verification;
use received::RootSignedReceivedOriginalV1;
use verification::RootSignedVerificationV1;

/// Retains the actual signed receiving, replay, append or transfer refusal.
#[derive(Debug, thiserror::Error)]
pub enum RootSignedBoundErrorV1 {
    /// Retains the same native Root/Open/currentness cause.
    #[error(transparent)]
    Open(#[from] RootInitialOpenErrorV1),
    /// Retains actual receiving or service refusal.
    #[error(transparent)]
    Root(#[from] RootObservationErrorV1),
    /// Retains the actual financial/geometry cause.
    #[error(transparent)]
    Native(#[from] NativeError),
    /// Retains the actual raw input/frame cause.
    #[error(transparent)]
    Input(#[from] RootSignedInputErrorV1),
    /// Retains the real Reserved Controller refusal.
    #[error(transparent)]
    Reserved(#[from] RootUseReservedErrorV1),
    /// Retains the actual Root3 refusal.
    #[error(transparent)]
    Admitted(#[from] RootUseAdmittedErrorV1),
    /// Retains the actual same-file Controller refusal.
    #[error(transparent)]
    Controller(#[from] RootInitialControllerReadonlyErrorV1),
    /// Retains genuine authorization refusal.
    #[error(transparent)]
    Authorization(#[from] super::super::initial_use_authorized::RootInitialUseAuthorizedErrorV1),
    /// Retains the genuine Ownership response refusal.
    #[error(transparent)]
    Ownership(#[from] super::super::initial_bundle::RootInitialBundleOwnershipErrorV1),
    /// Retains the actual refreshed Source refusal.
    #[error(transparent)]
    Source(#[from] super::super::initial_source_exchange::RootInitialSourceExchangeErrorV1),
    /// Retains actual six-native or model refusal.
    #[error(transparent)]
    Read(#[from] crate::native::readonly::RootReadonlyErrorV1),
    /// Retains actual canonical history/body refusal.
    #[error(transparent)]
    Format(#[from] HistoryErrorV1),
    /// The same actual purpose has not completed or was reentered.
    #[error("signed continuation is incomplete")]
    Incomplete,
}
type E = RootSignedBoundErrorV1;
type Slot<T, F = E> = Option<Result<T, F>>;
type Readback = HistoryPairReadbackDataV1<SIGNED_BOUND_RECORD_BYTES_V1>;
const FRAME_BYTES: usize = FRAME_HEADER_BYTES + SIGNED_BOUND_RECEIPT_BYTES_V1;

pub(in crate::native::root_current) struct RootSignedBoundOriginalV1 {
    pub(in crate::native::root_current) fixed: RootInitialStageOriginalV1,
    pub(in crate::native::root_current) received: RootSignedReceivedOriginalV1,
    pub(in crate::native::root_current) controller_predecessor: Option<RootObservationErrorV1>,
    pub(in crate::native::root_current) controller_stage: Option<RootInitialStageOriginalV1>,
    pub(in crate::native::root_current) controller_quote:
        Option<Result<ResourceVector, super::super::initial_controller::DemandError>>,
    pub(in crate::native::root_current) controller:
        Option<Box<RootInitialControllerReadonlyOriginalV1>>,
    body: Slot<SignedBoundBodyDataV1, HistoryErrorV1>,
    encoded: Slot<[u8; SIGNED_BOUND_BODY_BYTES_V1], HistoryErrorV1>,
    pub(in crate::native::root_current) pair:
        RootCurrentHistoryPairV1<SIGNED_BOUND_RECORD_BYTES_V1>,
    pub(in crate::native::root_current) primary: Slot<()>,
    pub(in crate::native::root_current) append_posts: RootInitialOpenPostsOriginalV1,
    pub(in crate::native::root_current) append_arm: Slot<(), RootObservationErrorV1>,
    append_live: Slot<()>,
    pub(in crate::native::root_current) crossing_refusal: Option<RootObservationErrorV1>,
    frame: [u8; FRAME_BYTES],
    pub(in crate::native::root_current) framing: Slot<(), HistoryErrorV1>,
    send: SliceDeadlineStreamIoV1,
    sent: Slot<(), HistoryErrorV1>,
    pub(in crate::native::root_current) send_posts: RootInitialOpenPostsOriginalV1,
    pub(in crate::native::root_current) send_arm: Slot<(), RootObservationErrorV1>,
    send_readback: Slot<Readback, RootInitialOpenErrorV1>,
    send_metadata: Option<io::Result<Metadata>>,
    send_live: Slot<()>,
    complete: bool,
    pub(in crate::native::root_current) closed: bool,
}

impl RootSignedBoundOriginalV1 {
    pub(in crate::native::root_current) fn new_after_fixed_v1(
        fixed: RootInitialStageOriginalV1,
    ) -> Self {
        Self {
            fixed,
            received: RootSignedReceivedOriginalV1::new(),
            pair: RootCurrentHistoryPairV1::new(),
            append_posts: RootInitialOpenPostsOriginalV1::new(),
            send_posts: RootInitialOpenPostsOriginalV1::new(),
            controller_predecessor: None,
            controller_stage: Some(RootInitialStageOriginalV1::new()),
            controller_quote: None,
            controller: None,
            body: None,
            encoded: None,
            primary: None,
            append_arm: None,
            append_live: None,
            crossing_refusal: None,
            framing: None,
            sent: None,
            send_arm: None,
            send_readback: None,
            send_metadata: None,
            send_live: None,
            frame: [0; FRAME_BYTES],
            send: Default::default(),
            complete: false,
            closed: false,
        }
    }
    pub(in crate::native::root_current) fn require_complete_v1(&self) -> Result<(), E> {
        self.fixed.require_complete_v1()?;
        self.received.require_complete_v1()?;
        self.controller
            .as_ref()
            .ok_or(E::Incomplete)?
            .require_complete_v1()?;
        positive(&self.send_live)?;
        if !self.closed
            && self.complete
            && self.send.completed_exact()
            && self.failure_v1().is_none()
        {
            Ok(())
        } else {
            Err(E::Incomplete)
        }
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
    pub(in crate::native::root_current) fn completed_prefix_v1(&self) -> Result<ResourceVector, E> {
        self.require_complete_v1()?;
        self.controller
            .as_ref()
            .ok_or(E::Incomplete)?
            .completed_prefix_v1()
            .map_err(E::from)
    }
    pub(in crate::native::root_current) fn completed_index_v1(&self) -> Result<TransferIndexV1, E> {
        self.require_complete_v1()?;
        self.received.input.index_data_v1().map_err(E::from)
    }
    pub(in crate::native::root_current) fn completed_bundle_v1(
        &self,
    ) -> Result<SignedPreparationBundleDataV1<'_>, E> {
        self.require_complete_v1()?;
        self.received.input.received_bundle_v1().map_err(E::from)
    }
    pub(in crate::native::root_current) fn completed_controller_v1(
        &self,
    ) -> Result<&RootInitialControllerReadonlyOriginalV1, E> {
        self.require_complete_v1()?;
        self.controller.as_deref().ok_or(E::Incomplete)
    }
    pub(in crate::native::root_current) fn completed_receipt_v1(
        &self,
    ) -> Result<ContinuationNativeReceiptDataV1<'_>, E> {
        self.require_complete_v1()?;
        let readback = positive(&self.pair.readback)?;
        let committed = positive(&self.pair.append)?;
        Ok(ContinuationNativeReceiptDataV1 {
            record: &self.pair.record,
            latest_head: readback.head,
            names: self.append_posts.authority_names_v1()?,
            after_next: readback.next,
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
    pub(in crate::native::root_current) fn require_original_chain_v1(
        &self,
        open: &RootInitialOpenPreparedOriginalV1,
        authorization: &RootInitialUseAuthorizedOriginalV1,
        reserved: &RootUseReservedOriginalV1,
    ) -> Result<(), E> {
        self.require_complete_v1()?;
        authorization.require_complete_v1()?;
        reserved.require_complete_v1()?;
        let financial = self.fixed.financial.as_ref().ok_or(E::Incomplete)?;
        if !authorization.same_financial_v1(financial) || !reserved.same_financial_v1(financial) {
            return Err(E::Incomplete);
        }
        let body = open.body_v1()?;
        let root = RecordEnvelopeV1::decode(
            open.committed_record_v1()?,
            KeyV1::new(body.open.lane, OwnerV1::Root, 1)?,
            PhaseV1::new(OwnerV1::Root, 1)?,
        )?;
        if authorization.completed_body_v1()?.root_open != root.checksum() {
            return Err(E::Incomplete);
        }
        Ok(())
    }
    pub(in crate::native::root_current) fn completed_request_id_v1(&self) -> Result<[u8; 16], E> {
        self.require_complete_v1()?;
        self.received.verification.request_id_v1()
    }
    pub(in crate::native::root_current) fn verified_plan_v1(
        &self,
    ) -> Result<&aos_sandbox_model::VerifiedBrokerPlan, E> {
        self.require_complete_v1()?;
        self.received.verification.verified_plan_v1()
    }
    pub(in crate::native::root_current) fn failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.fixed
            .failure_v1()
            .or_else(|| self.received.failure_v1())
            .or_else(|| self.controller_predecessor.as_ref().map(|cause| cause as _))
            .or_else(|| cause(&self.controller_quote))
            .or_else(|| {
                self.controller_stage
                    .as_ref()
                    .and_then(RootInitialStageOriginalV1::failure_v1)
            })
            .or_else(|| {
                self.controller
                    .as_deref()
                    .and_then(RootInitialControllerReadonlyOriginalV1::failure_v1)
            })
            .or_else(|| cause(&self.body))
            .or_else(|| cause(&self.encoded))
            .or_else(|| self.pair.failure_v1())
            .or_else(|| self.crossing_refusal.as_ref().map(|cause| cause as _))
            .or_else(|| cause(&self.primary))
            .or_else(|| self.append_posts.failure_v1())
            .or_else(|| cause(&self.append_arm))
            .or_else(|| cause(&self.append_live))
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
        .and_then(|v| v.as_ref().ok())
        .ok_or(E::Incomplete)
}
fn cause<T, F: Error + 'static>(slot: &Option<Result<T, F>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref().and_then(|v| v.as_ref().err()).map(|v| v as _)
}

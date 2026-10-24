//! Retains the genuine Root5 Outcome phase and every reached negative original.

use super::super::storage_inventory::RootVerifiedSessionTerminalV1;
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
use super::outcome_input::{RootOutcomeInputErrorV1, RootOutcomeInputOriginalV1};
use super::signed::{RootSignedBoundErrorV1, RootSignedBoundOriginalV1};
use super::{
    admitted::{RootUseAdmittedErrorV1, RootUseAdmittedOriginalV1},
    reserved::{RootUseReservedErrorV1, RootUseReservedOriginalV1},
};
use crate::native::PolicyNativeJournalErrorV1 as NativeError;
use crate::native::readonly::{RootFixedNativeReadOriginalsV1, RootReadonlyErrorV1};
use crate::native::{RootPolicyJournalV1, RootPolicyTargetOriginalV1};
use aos_sandbox_broker::bounded_stream_io::SliceDeadlineStreamIoV1;
use aos_sandbox_broker::receiving::{RootJournalFinancialOriginalV1, RootObservationErrorV1};
use aos_sandbox_model::{RawPairedClockSample, ResourceVector};
use aos_sandbox_protocol::domain_ledger::create_storage_history::outcome::{
    ROOT_OUTCOME_BODY_BYTES_V1, ROOT_OUTCOME_RECEIPT_BYTES_V1, ROOT_OUTCOME_RECORD_BYTES_V1,
    RootOutcomeBodyDataV1,
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

/// Retains the actual outcome receiving, replay, append or transfer refusal.
#[derive(Debug, thiserror::Error)]
pub enum RootUseOutcomeErrorV1 {
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
    Input(#[from] RootOutcomeInputErrorV1),
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
    /// Retains actual six-native or model refusal.
    #[error(transparent)]
    Read(#[from] crate::native::readonly::RootReadonlyErrorV1),
    /// Retains actual canonical history/body refusal.
    #[error(transparent)]
    Format(#[from] HistoryErrorV1),
    /// Retains the genuine completed Signed predecessor refusal.
    #[error(transparent)]
    Signed(#[from] RootSignedBoundErrorV1),
    /// The same actual purpose has not completed or was reentered.
    #[error("outcome continuation is incomplete")]
    Incomplete,
}
type E = RootUseOutcomeErrorV1;
type Slot<T, F = E> = Option<Result<T, F>>;
type Readback = HistoryPairReadbackDataV1<ROOT_OUTCOME_RECORD_BYTES_V1>;
const FRAME_BYTES: usize = FRAME_HEADER_BYTES + ROOT_OUTCOME_RECEIPT_BYTES_V1;

pub(in crate::native::root_current) struct RootUseOutcomeOriginalV1 {
    pub(in crate::native::root_current) fixed: RootInitialStageOriginalV1,
    pub(in crate::native::root_current) variable: RootInitialStageOriginalV1,
    pub(in crate::native::root_current) input: RootOutcomeInputOriginalV1,
    input_before: RootInitialOpenPostsOriginalV1,
    input_after: RootInitialOpenPostsOriginalV1,
    input_before_readback: Slot<(), RootInitialOpenErrorV1>,
    input_before_live: Slot<()>,
    input_after_readback: Slot<(), RootInitialOpenErrorV1>,
    input_after_live: Slot<()>,
    input_interval: Slot<(), aos_sandbox_model::OwnershipLeaseVerificationError>,
    input_result: Slot<()>,
    pub(in crate::native::root_current) controller: RootInitialControllerReadonlyOriginalV1,
    body: Slot<RootOutcomeBodyDataV1, HistoryErrorV1>,
    encoded: Slot<[u8; ROOT_OUTCOME_BODY_BYTES_V1], HistoryErrorV1>,
    pair: RootCurrentHistoryPairV1<ROOT_OUTCOME_RECORD_BYTES_V1>,
    primary: Slot<()>,
    append_posts: RootInitialOpenPostsOriginalV1,
    append_arm: Slot<(), RootObservationErrorV1>,
    append_live: Slot<()>,
    crossing_refusal: Option<RootObservationErrorV1>,
    frame: [u8; FRAME_BYTES],
    framing: Slot<(), HistoryErrorV1>,
    send: SliceDeadlineStreamIoV1,
    sent: Slot<(), HistoryErrorV1>,
    send_posts: RootInitialOpenPostsOriginalV1,
    send_arm: Slot<(), RootObservationErrorV1>,
    send_readback: Slot<Readback, RootInitialOpenErrorV1>,
    send_metadata: Option<io::Result<Metadata>>,
    send_live: Slot<()>,
    complete: bool,
    closed: bool,
    session: RootFixedNativeReadOriginalsV1,
    session_stage: RootInitialStageOriginalV1,
    signature:
        Slot<aos_sandbox_model::model::Signature, aos_sandbox_model::format::CanonicalCborError>,
    verified_plan:
        Slot<aos_sandbox_model::VerifiedBrokerPlan, aos_sandbox_model::BrokerPlanVerificationError>,
    terminal: Slot<RootVerifiedSessionTerminalV1, Box<dyn Error>>,
    session_result: Slot<()>,
    session_after: RootInitialOpenPostsOriginalV1,
    session_after_readback: Slot<(), RootInitialOpenErrorV1>,
    session_after_live: Slot<()>,
    session_interval: Slot<(), aos_sandbox_model::OwnershipLeaseVerificationError>,
    before_sample: Option<RawPairedClockSample>,
    ack_sequence: Option<u64>,
}

impl RootUseOutcomeOriginalV1 {
    pub(in crate::native::root_current) fn new() -> Self {
        Self {
            fixed: RootInitialStageOriginalV1::new(),
            variable: RootInitialStageOriginalV1::new(),
            input: RootOutcomeInputOriginalV1::new(),
            input_before: RootInitialOpenPostsOriginalV1::new(),
            input_after: RootInitialOpenPostsOriginalV1::new(),
            pair: RootCurrentHistoryPairV1::new(),
            append_posts: RootInitialOpenPostsOriginalV1::new(),
            send_posts: RootInitialOpenPostsOriginalV1::new(),
            input_before_readback: None,
            input_before_live: None,
            input_after_readback: None,
            input_after_live: None,
            input_interval: None,
            input_result: None,
            controller: RootInitialControllerReadonlyOriginalV1::new(),
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
            session: RootFixedNativeReadOriginalsV1::default(),
            session_stage: RootInitialStageOriginalV1::new(),
            signature: None,
            verified_plan: None,
            terminal: None,
            session_result: None,
            session_after: RootInitialOpenPostsOriginalV1::new(),
            session_after_readback: None,
            session_after_live: None,
            session_interval: None,
            before_sample: None,
            ack_sequence: None,
        }
    }
    pub(in crate::native::root_current) fn require_complete_v1(&self) -> Result<(), E> {
        self.fixed.require_complete_v1()?;
        self.variable.require_complete_v1()?;
        self.input.require_received_v1()?;
        self.controller.require_complete_v1()?;
        positive(&self.input_result)?;
        positive(&self.input_after_live)?;
        positive(&self.input_interval)?;
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
        self.controller.completed_prefix_v1().map_err(E::from)
    }
    pub(in crate::native::root_current) fn completed_index_v1(&self) -> Result<TransferIndexV1, E> {
        self.require_complete_v1()?;
        self.input.index_data_v1().map_err(E::from)
    }
    pub(in crate::native::root_current) fn completed_bundle_v1(
        &self,
    ) -> Result<
        aos_sandbox_protocol::domain_ledger::create_storage_history::outcome::OutcomeBundleDataV1<
            '_,
        >,
        E,
    > {
        self.require_complete_v1()?;
        self.input.received_bundle_v1().map_err(E::from)
    }
    pub(in crate::native::root_current) fn completed_controller_v1(
        &self,
    ) -> Result<&RootInitialControllerReadonlyOriginalV1, E> {
        self.require_complete_v1()?;
        Ok(&self.controller)
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
        signed: &RootSignedBoundOriginalV1,
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
        signed.require_original_chain_v1(open, authorization, reserved)?;
        if !signed.same_financial_v1(financial) {
            return Err(E::Incomplete);
        }
        Ok(())
    }
    pub(in crate::native::root_current) fn completed_ack_sequence_v1(&self) -> Result<u64, E> {
        self.require_complete_v1()?;
        self.ack_sequence.ok_or(E::Incomplete)
    }
    pub(in crate::native::root_current) fn completed_session_v1(
        &self,
    ) -> Result<&RootVerifiedSessionTerminalV1, E> {
        self.require_complete_v1()?;
        positive(&self.terminal)
    }
    pub(in crate::native::root_current) fn require_live_at_v1(
        &self,
        sample: RawPairedClockSample,
    ) -> Result<(), E> {
        self.completed_controller_v1()?.require_live_at_v1(sample)?;
        self.completed_session_v1()?.require_live_at_v1(sample)?;
        let plan = positive(&self.verified_plan)?;
        if sample.wall_seconds() >= plan.plan().expires_seconds() {
            return Err(E::Incomplete);
        }
        Ok(())
    }
    pub(in crate::native::root_current) fn failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.fixed
            .failure_v1()
            .or_else(|| self.input.geometry_failure_v1())
            .or_else(|| self.input_before.failure_v1())
            .or_else(|| cause(&self.input_before_readback))
            .or_else(|| cause(&self.input_before_live))
            .or_else(|| self.input.before_variable_failure_v1())
            .or_else(|| self.variable.failure_v1())
            .or_else(|| self.input.after_variable_failure_v1())
            .or_else(|| cause(&self.input_result))
            .or_else(|| self.input_after.failure_v1())
            .or_else(|| cause(&self.input_after_readback))
            .or_else(|| cause(&self.input_after_live))
            .or_else(|| cause(&self.input_interval))
            .or_else(|| self.controller.failure_v1())
            .or_else(|| self.session.failure())
            .or_else(|| self.session_stage.failure_v1())
            .or_else(|| cause(&self.signature))
            .or_else(|| cause(&self.verified_plan))
            .or_else(|| {
                self.terminal
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause.as_ref())
            })
            .or_else(|| cause(&self.session_result))
            .or_else(|| self.session.post_failure())
            .or_else(|| self.session_after.failure_v1())
            .or_else(|| cause(&self.session_after_readback))
            .or_else(|| cause(&self.session_after_live))
            .or_else(|| cause(&self.session_interval))
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

//! Measures the initial Source-exchange construction and retained interfaces.
//!
//! These Memory-only controls reach the incoming actual Owned constructor donor.
//! Socket/native-name/clock/message backing remains in the later genuine fixed
//! exchange Stage. Its existing literal transport allowance is not credit for
//! new arguments, closure environments or native-currentness observations.

use std::error::Error;
use std::mem::size_of;

use aos_sandbox_broker::kernel_clock::RetainedKernelPairedClockAttemptV1;
use aos_sandbox_broker::receiving::{
    RootInitialReceivingOriginalV1, RootJournalFinancialOriginalV1,
    RootObservationErrorV1, RootSelectedStartupBorrowV1, RootUpperMutationGuardV1,
};
use aos_sandbox_broker::source_signer_transport::{
    RootSourceSignerTransportOriginalsV1, RootSourceTransportClosedV1,
};
use aos_sandbox_model::{RawPairedClockSample, ResourceVector};
use aos_sandbox_ledger_replay::source_signer_data::PinnedSourceHoldReadbackSignerV1;
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    HistoryErrorV1,
    source_current::{
        SourceCurrentQueryDataV1, SourceCurrentReplyDataV1, SourceCurrentReplyFieldsV1,
        SOURCE_CURRENT_PACKET_BYTES_V1, SOURCE_CURRENT_QUERY_BYTES_V1,
        SOURCE_CURRENT_REPLY_FRAME_BYTES_V1,
    },
};

use crate::native::PolicyNativeJournalErrorV1 as NativeError;
use crate::native::startup::RootCurrentWritersPredecessorV1;

use super::history_post::RootCurrentHistoryPostOriginalV1;
use super::initial_open::{
    RootInitialClockErrorV1, RootInitialOpenErrorV1, RootInitialOpenPreparedOriginalV1,
};
use super::initial_pins::{RootInitialPinsErrorV1, RootInitialPinsOriginalV1};
use super::initial_ready::RootInitialReadyOriginalV1;
use super::initial_receiving::RootInitialStageOriginalV1;
use super::initial_source_exchange::{
    RootInitialSourceExchangeErrorV1 as E, RootInitialSourceExchangeOriginalV1 as Exchange,
};
use super::initial_source_query::{RootInitialSourceQueryErrorV1, RootInitialSourceQueryOriginalV1};
use super::initial_writer_sample::RootInitialWriterSampleOriginalV1;
use super::owned::{RootCurrentAcceptedOriginalsV1, RootOwnedCurrentOriginalV1};
use super::writers::RootCurrentWritersOriginalV1;

type Clock = RetainedKernelPairedClockAttemptV1<RootInitialClockErrorV1>;
type Transport = RootSourceSignerTransportOriginalsV1<
    SOURCE_CURRENT_QUERY_BYTES_V1, SOURCE_CURRENT_REPLY_FRAME_BYTES_V1,
>;

pub(super) fn construction_control_bytes_v1() -> Option<usize> {
    let constructors = size_of::<Exchange>().checked_mul(2)?
        .checked_add(size_of::<RootInitialStageOriginalV1>().checked_mul(2)?)?
        .checked_add(size_of::<Clock>().checked_mul(4)?)?
        .checked_add(size_of::<Transport>().checked_mul(2)?)?
        .checked_add(RootInitialWriterSampleOriginalV1::construction_control_bytes_v1()?
            .checked_mul(2)?)?;
    let delegates = RootJournalFinancialOriginalV1::receiving_stage_under_exclusion_control_bytes_v1()?
        .checked_add(RootSelectedStartupBorrowV1::service_recheck_under_exclusion_control_bytes_v1()?)?
        .checked_add(RootCurrentHistoryPostOriginalV1::construction_control_bytes_v1()?)?;
    let arguments = argument_interfaces_v1()?;
    let results = result_interfaces_v1()?;
    let captures = capture_interfaces_v1()?;
    let queries = query_interfaces_v1()?;

    constructors.checked_add(delegates)?.checked_add(arguments)?
        .checked_add(results)?.checked_add(captures)?.checked_add(queries)?
        .checked_add(size_of::<Option<usize>>().checked_mul(18)?)
}

fn argument_interfaces_v1() -> Option<usize> {
    let upper = size_of::<(&mut RootOwnedCurrentOriginalV1<'_>,
        &mut RootInitialReceivingOriginalV1, &RootSelectedStartupBorrowV1<'_>,
        &RootUpperMutationGuardV1<'_>)>().checked_mul(6)?
        .checked_add(size_of::<(&mut RootOwnedCurrentOriginalV1<'_>, u32, u32)>()
            .checked_mul(3)?)?
        .checked_add(size_of::<&mut RootOwnedCurrentOriginalV1<'_>>().checked_mul(9)?)?
        .checked_add(size_of::<&RootOwnedCurrentOriginalV1<'_>>().checked_mul(12)?)?;
    let receiving = size_of::<(&mut Exchange, &RootInitialOpenPreparedOriginalV1,
        &RootInitialReadyOriginalV1, &RootInitialSourceQueryOriginalV1,
        RootCurrentWritersPredecessorV1<'_, '_, '_>, &RootSelectedStartupBorrowV1<'_>,
        &RootUpperMutationGuardV1<'_>)>().checked_mul(3)?
        .checked_add(size_of::<(&mut Exchange, RootCurrentWritersPredecessorV1<'_, '_, '_>,
            &RootSelectedStartupBorrowV1<'_>, &RootUpperMutationGuardV1<'_>)>()
            .checked_mul(3)?)?
        .checked_add(size_of::<(&RootInitialSourceQueryOriginalV1,
            &RootJournalFinancialOriginalV1)>().checked_mul(3)?)?;
    let body = size_of::<(&mut Exchange, &RootCurrentWritersOriginalV1,
        &RootInitialOpenPreparedOriginalV1, &RootInitialPinsOriginalV1,
        &RootInitialSourceQueryOriginalV1, u32, u32)>().checked_mul(6)?
        .checked_add(size_of::<(&mut Exchange, &RootCurrentWritersOriginalV1,
            &RootInitialOpenPreparedOriginalV1)>().checked_mul(3)?)?
        .checked_add(size_of::<(&mut Exchange, &RootCurrentAcceptedOriginalsV1<'_>,
            &RootInitialOpenPreparedOriginalV1)>().checked_mul(3)?)?
        .checked_add(size_of::<(&RootInitialOpenPreparedOriginalV1,
            &Option<Result<RawPairedClockSample, RootInitialClockErrorV1>>,
            &Option<Result<u64, HistoryErrorV1>>)>().checked_mul(6)?)?
        .checked_add(size_of::<(&mut Transport, u32, u32,
            &[u8; SOURCE_CURRENT_QUERY_BYTES_V1], u64)>().checked_mul(3)?)?
        .checked_add(size_of::<&mut Exchange>().checked_mul(12)?)?
        .checked_add(size_of::<&Exchange>().checked_mul(21)?)?;

    upper.checked_add(receiving)?.checked_add(body)
}

fn result_interfaces_v1() -> Option<usize> {
    size_of::<Result<(), E>>().checked_mul(30)?
        .checked_add(size_of::<Result<(), RootObservationErrorV1>>().checked_mul(15)?)?
        .checked_add(size_of::<Result<(), RootInitialOpenErrorV1>>().checked_mul(18)?)?
        .checked_add(size_of::<Result<(), RootInitialSourceQueryErrorV1>>().checked_mul(9)?)?
        .checked_add(size_of::<Result<(), RootInitialPinsErrorV1>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<(), RootSourceTransportClosedV1>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<(), HistoryErrorV1>>().checked_mul(9)?)?
        .checked_add(size_of::<Result<(), ()>>().checked_mul(6)?)?
        .checked_add(size_of::<Result<Option<[u8; 32]>, E>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<u64, HistoryErrorV1>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<SourceCurrentQueryDataV1<'_>, HistoryErrorV1>>()
            .checked_mul(6)?)?
        .checked_add(size_of::<Result<SourceCurrentReplyDataV1, HistoryErrorV1>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<ResourceVector, NativeError>>().checked_mul(9)?)?
        .checked_add(size_of::<Result<ResourceVector, RootInitialSourceQueryErrorV1>>()
            .checked_mul(3)?)?
        .checked_add(size_of::<Result<RootCurrentWritersPredecessorV1<'_, '_, '_>,
            RootObservationErrorV1>>().checked_mul(6)?)?
        .checked_add(size_of::<Result<RawPairedClockSample, RootInitialClockErrorV1>>()
            .checked_mul(6)?)?
        .checked_add(size_of::<Result<&PinnedSourceHoldReadbackSignerV1, RootInitialPinsErrorV1>>()
            .checked_mul(3)?)?
        .checked_add(size_of::<Result<&[u8; SOURCE_CURRENT_PACKET_BYTES_V1], E>>()
            .checked_mul(6)?)?
        .checked_add(size_of::<Result<SourceCurrentReplyFieldsV1, E>>().checked_mul(6)?)?
        .checked_add(size_of::<Result<u64, E>>().checked_mul(6)?)
}

fn capture_interfaces_v1() -> Option<usize> {
    let stage = size_of::<(&mut Exchange, &mut RootInitialReceivingOriginalV1,
        &RootJournalFinancialOriginalV1, &RootInitialOpenPreparedOriginalV1,
        &RootInitialReadyOriginalV1, &RootInitialSourceQueryOriginalV1,
        &RootSelectedStartupBorrowV1<'_>, &RootUpperMutationGuardV1<'_>)>()
        .checked_mul(3)?;
    let correlation = size_of::<(&SourceCurrentReplyDataV1, &PinnedSourceHoldReadbackSignerV1)>()
        .checked_mul(3)?;
    let diagnostic = size_of::<&Exchange>().checked_mul(75)?;
    let demand = size_of::<ResourceVector>().checked_mul(6)?
        .checked_add(size_of::<&ResourceVector>().checked_mul(6)?)?
        .checked_add(size_of::<usize>().checked_mul(9)?)?
        .checked_add(size_of::<&usize>().checked_mul(9)?)?;

    stage.checked_add(correlation)?.checked_add(diagnostic)?.checked_add(demand)
}

fn query_interfaces_v1() -> Option<usize> {
    size_of::<Option<&(dyn Error + 'static)>>().checked_mul(84)?
        .checked_add(size_of::<Result<&(), E>>().checked_mul(36)?)?
        .checked_add(size_of::<Result<&SourceCurrentReplyDataV1, E>>().checked_mul(9)?)?
        .checked_add(size_of::<Result<&RawPairedClockSample, E>>().checked_mul(6)?)?
        .checked_add(size_of::<Result<&u64, E>>().checked_mul(9)?)?
        .checked_add(size_of::<Result<&Option<[u8; 32]>, E>>().checked_mul(3)?)?
        .checked_add(size_of::<Option<&Result<SourceCurrentReplyDataV1, HistoryErrorV1>>>()
            .checked_mul(3)?)?
        .checked_add(size_of::<bool>().checked_mul(18)?)
}

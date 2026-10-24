//! Measures the new Initial signed-input owner and its concrete interfaces.
//!
//! The incoming INITIAL constructor consumes this Memory-only supplier before
//! constructing the native owner. Actual decoding remains charged by the later
//! genuine cumulative Stage; AFTER names have their separate early native bound.

use std::error::Error;
use std::mem::size_of;

use aos_sandbox_broker::receiving::{RootInitialReceivingOriginalV1,
    RootJournalFinancialOriginalV1, RootObservationErrorV1,
    RootSelectedStartupBorrowV1, RootUpperMutationGuardV1};
use aos_sandbox_model::{RawPairedClockSample, ResourceVector};
use aos_sandbox_protocol::domain_ledger::create_storage_history::readback::HistoryPairReadbackDataV1;
use aos_sandbox_protocol::domain_ledger::readonly::HistoricalLedgerReadViewV1;

use crate::native::journal::RootPolicyJournalV1;
use crate::native::startup::RootCurrentWritersPredecessorV1;
use crate::native::target::RootPolicyTargetOriginalV1;
use crate::native::PolicyNativeJournalErrorV1 as NativeError;
use crate::root_policy_inputs_data::{RootCurrentPolicyInputDataV1, RootPolicyInputErrorV1,
    RootSignedProjectSourcesDataV1, RootSignedSourcesDataErrorV1};
use crate::signed_inputs::PolicyDeploymentInputsV1;

use super::history_post::RootCurrentHistoryPostOriginalV1;
use super::initial_inputs::{RootInitialPolicyInputsErrorV1 as E,
    RootInitialPolicyInputsOriginalV1 as Inputs};
use super::initial_open::{RootInitialClockErrorV1, RootInitialOpenErrorV1,
    RootInitialOpenPreparedOriginalV1, ROOT_RECORD_BYTES};
use super::initial_pins::{RootInitialPinsErrorV1, RootInitialPinsOriginalV1};
use super::initial_receiving::RootInitialStageOriginalV1;
use super::initial_writer_sample::RootInitialWriterSampleOriginalV1;
use super::owned::{RootCurrentAcceptedOriginalsV1, RootOwnedCurrentOriginalV1};
use super::writers::RootCurrentWritersOriginalV1;

type Readback = HistoryPairReadbackDataV1<ROOT_RECORD_BYTES>;

pub(super) fn construction_control_bytes_v1() -> Option<usize> {
    let constructors = size_of::<Inputs>().checked_mul(2)?
        .checked_add(size_of::<RootInitialStageOriginalV1>().checked_mul(2)?)?
        .checked_add(RootInitialWriterSampleOriginalV1::construction_control_bytes_v1()?
            .checked_mul(2)?)?;
    let financial = RootJournalFinancialOriginalV1::receiving_stage_under_exclusion_control_bytes_v1()?
        .checked_add(RootSelectedStartupBorrowV1::service_recheck_under_exclusion_control_bytes_v1()?)?;
    let peer = RootCurrentHistoryPostOriginalV1::construction_control_bytes_v1()?;
    let outer = size_of::<(&mut RootOwnedCurrentOriginalV1<'_>,
        &mut RootInitialReceivingOriginalV1, &RootSelectedStartupBorrowV1<'_>,
        &RootUpperMutationGuardV1<'_>)>().checked_mul(6)?
        .checked_add(size_of::<&mut RootOwnedCurrentOriginalV1<'_>>().checked_mul(15)?)?
        .checked_add(size_of::<&RootOwnedCurrentOriginalV1<'_>>().checked_mul(9)?)?
        .checked_add(size_of::<(&mut RootOwnedCurrentOriginalV1<'_>,
            &RootCurrentPolicyInputDataV1<'_>)>().checked_mul(3)?)?;
    let arguments = size_of::<(&mut Inputs, &RootInitialOpenPreparedOriginalV1,
        &RootInitialPinsOriginalV1, RootCurrentWritersPredecessorV1<'_, '_, '_>,
        &RootSelectedStartupBorrowV1<'_>, &RootUpperMutationGuardV1<'_>)>().checked_mul(3)?
        .checked_add(size_of::<(&mut Inputs, &RootCurrentWritersOriginalV1,
            &RootInitialOpenPreparedOriginalV1, &RootCurrentPolicyInputDataV1<'_>)>()
            .checked_mul(6)?)?
        .checked_add(size_of::<(&mut Inputs, &RootCurrentWritersOriginalV1,
            &RootInitialOpenPreparedOriginalV1)>().checked_mul(3)?)?
        .checked_add(size_of::<(&mut Inputs, RootCurrentWritersPredecessorV1<'_, '_, '_>,
            &RootSelectedStartupBorrowV1<'_>, &RootUpperMutationGuardV1<'_>)>().checked_mul(3)?)?
        .checked_add(size_of::<(&mut Inputs, &RootCurrentAcceptedOriginalsV1<'_>,
            &RootInitialOpenPreparedOriginalV1)>().checked_mul(3)?)?
        .checked_add(size_of::<(&Option<Result<RawPairedClockSample, RootInitialClockErrorV1>>,
            &RootInitialOpenPreparedOriginalV1)>().checked_mul(6)?)?
        .checked_add(size_of::<(&RootInitialPinsOriginalV1, &RootJournalFinancialOriginalV1, bool)>()
            .checked_mul(3)?)?
        .checked_add(size_of::<&mut Inputs>().checked_mul(15)?)?
        .checked_add(size_of::<&Inputs>().checked_mul(15)?)?;
    let results = size_of::<Result<(), E>>().checked_mul(30)?
        .checked_add(size_of::<Result<(), RootInitialPinsErrorV1>>().checked_mul(6)?)?
        .checked_add(size_of::<Result<(), RootObservationErrorV1>>().checked_mul(18)?)?
        .checked_add(size_of::<Result<(), RootInitialOpenErrorV1>>().checked_mul(12)?)?
        .checked_add(size_of::<Result<ResourceVector, NativeError>>().checked_mul(9)?)?
        .checked_add(size_of::<Result<ResourceVector, E>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<ResourceVector, RootInitialPinsErrorV1>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<ResourceVector, RootInitialOpenErrorV1>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<Readback, RootInitialOpenErrorV1>>().checked_mul(6)?)?
        .checked_add(size_of::<Result<RawPairedClockSample, RootInitialClockErrorV1>>().checked_mul(6)?)?
        .checked_add(size_of::<Result<RootCurrentWritersPredecessorV1<'_, '_, '_>,
            RootObservationErrorV1>>().checked_mul(6)?)?
        .checked_add(size_of::<Result<(&RootPolicyJournalV1, &RootPolicyTargetOriginalV1),
            RootObservationErrorV1>>().checked_mul(6)?)?;
    let decoder = size_of::<(&RootCurrentPolicyInputDataV1<'_>,)>().checked_mul(9)?
        .checked_add(size_of::<Result<&[u8], RootPolicyInputErrorV1>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<(), RootPolicyInputErrorV1>>().checked_mul(6)?)?
        .checked_add(size_of::<Result<RootSignedProjectSourcesDataV1,
            RootSignedSourcesDataErrorV1>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<&RootSignedProjectSourcesDataV1, E>>().checked_mul(6)?)?
        .checked_add(size_of::<(HistoricalLedgerReadViewV1<'_>, &[u8],
            &PolicyDeploymentInputsV1<'_>, i64)>().checked_mul(3)?)?
        .checked_add(size_of::<HistoricalLedgerReadViewV1<'_>>().checked_mul(6)?)?
        .checked_add(size_of::<Option<&[u8]>>().checked_mul(3)?)?;
    let views = size_of::<Result<&(), E>>().checked_mul(24)?
        .checked_add(size_of::<Result<&Readback, E>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<&RawPairedClockSample, E>>().checked_mul(3)?)?
        .checked_add(size_of::<Option<&RawPairedClockSample>>().checked_mul(6)?)?
        .checked_add(size_of::<Option<&(dyn Error + 'static)>>().checked_mul(54)?)?
        .checked_add(size_of::<bool>().checked_mul(9)?)?;
    let captures = size_of::<(&mut Inputs, &mut RootInitialReceivingOriginalV1,
        &RootJournalFinancialOriginalV1, &RootInitialOpenPreparedOriginalV1,
        &RootInitialPinsOriginalV1, &RootSelectedStartupBorrowV1<'_>,
        &RootUpperMutationGuardV1<'_>)>().checked_mul(3)?
        .checked_add(size_of::<&Inputs>().checked_mul(45)?)?
        .checked_add(size_of::<&Option<Result<RawPairedClockSample,
            RootInitialClockErrorV1>>>().checked_mul(6)?)?;

    constructors.checked_add(financial)?
        .checked_add(size_of::<&mut RootInitialReceivingOriginalV1>().checked_mul(3)?)?
        .checked_add(size_of::<Result<(), ()>>().checked_mul(6)?)?
        .checked_add(size_of::<(&Result<(), ()>, bool)>().checked_mul(3)?)?
        .checked_add(peer)?
        .checked_add(outer)?
        .checked_add(arguments)?
        .checked_add(results)?
        .checked_add(decoder)?
        .checked_add(views)?
        .checked_add(captures)?
        .checked_add(size_of::<Option<usize>>().checked_mul(12)?)
}

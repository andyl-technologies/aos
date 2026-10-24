//! Measures the initial Source-query constructor and concrete native interfaces.
//!
//! The incoming owned-programme Memory donor pays this before construction.
//! Actual query/framing backing remains in the later genuine cumulative Stage.
//! No request DATA or resource vector replaces that same-original admission.

use std::error::Error;
use std::mem::size_of;

use aos_sandbox_broker::receiving::{
    RootInitialReceivingOriginalV1, RootJournalFinancialOriginalV1,
    RootObservationErrorV1, RootSelectedStartupBorrowV1, RootUpperMutationGuardV1,
};
use aos_sandbox_model::ResourceVector;
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    HistoryErrorV1, ready::ReadyBundleDataV1,
    source_current::{SOURCE_CURRENT_QUERY_BYTES_V1, SourceCurrentQueryDataV1},
};

use crate::native::PolicyNativeJournalErrorV1 as NativeError;
use crate::native::startup::RootCurrentWritersPredecessorV1;

use super::initial_open::{RootInitialOpenErrorV1, RootInitialOpenPreparedOriginalV1};
use super::initial_ready::RootInitialReadyOriginalV1;
use super::initial_receiving::RootInitialStageOriginalV1;
use super::initial_source_query::{
    RootInitialSourceQueryErrorV1 as E, RootInitialSourceQueryOriginalV1 as Query,
};
use super::initial_trust::{RootInitialTrustErrorV1, RootInitialTrustOriginalV1};
use super::owned::RootOwnedCurrentOriginalV1;

pub(super) fn construction_control_bytes_v1() -> Option<usize> {
    let constructors = size_of::<Query>().checked_mul(2)?
        .checked_add(size_of::<RootInitialStageOriginalV1>().checked_mul(2)?)?;
    let delegates = RootJournalFinancialOriginalV1::receiving_stage_under_exclusion_control_bytes_v1()?
        .checked_add(RootSelectedStartupBorrowV1::service_recheck_under_exclusion_control_bytes_v1()?)?;
    let arguments = size_of::<(&mut RootOwnedCurrentOriginalV1<'_>,
        &mut RootInitialReceivingOriginalV1, &RootSelectedStartupBorrowV1<'_>,
        &RootUpperMutationGuardV1<'_>)>().checked_mul(3)?
        .checked_add(size_of::<(&mut Query, &RootInitialOpenPreparedOriginalV1,
            &RootInitialReadyOriginalV1, &RootInitialTrustOriginalV1,
            RootCurrentWritersPredecessorV1<'_, '_, '_>, &RootSelectedStartupBorrowV1<'_>,
            &RootUpperMutationGuardV1<'_>)>().checked_mul(3)?)?
        .checked_add(size_of::<(&mut Query, &RootInitialOpenPreparedOriginalV1,
            &RootInitialReadyOriginalV1)>().checked_mul(6)?)?
        .checked_add(size_of::<(&Query, &RootInitialOpenPreparedOriginalV1,
            &RootInitialReadyOriginalV1)>().checked_mul(3)?)?
        .checked_add(size_of::<&mut RootOwnedCurrentOriginalV1<'_>>().checked_mul(3)?)?
        .checked_add(size_of::<&RootOwnedCurrentOriginalV1<'_>>().checked_mul(6)?)?
        .checked_add(size_of::<&mut Query>().checked_mul(9)?)?
        .checked_add(size_of::<&Query>().checked_mul(12)?)?
        .checked_add(size_of::<(&RootInitialTrustOriginalV1,
            &RootJournalFinancialOriginalV1)>().checked_mul(3)?)?;
    let results = size_of::<Result<(), RootObservationErrorV1>>().checked_mul(12)?
        .checked_add(size_of::<Result<(), E>>().checked_mul(18)?)?
        .checked_add(size_of::<Result<(), RootInitialTrustErrorV1>>().checked_mul(9)?)?
        .checked_add(size_of::<Result<ResourceVector, NativeError>>().checked_mul(6)?)?
        .checked_add(size_of::<Result<ResourceVector, RootInitialTrustErrorV1>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<ResourceVector, RootInitialOpenErrorV1>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<RootCurrentWritersPredecessorV1<'_, '_, '_>,
            RootObservationErrorV1>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<ReadyBundleDataV1<'_>, HistoryErrorV1>>().checked_mul(6)?)?
        .checked_add(size_of::<Result<SourceCurrentQueryDataV1<'_>, HistoryErrorV1>>().checked_mul(9)?)?
        .checked_add(size_of::<Result<[u8; SOURCE_CURRENT_QUERY_BYTES_V1], HistoryErrorV1>>()
            .checked_mul(3)?)?
        .checked_add(size_of::<Result<(), HistoryErrorV1>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<&[u8; SOURCE_CURRENT_QUERY_BYTES_V1], E>>().checked_mul(9)?)?
        .checked_add(size_of::<Result<&[u8], RootInitialOpenErrorV1>>().checked_mul(6)?)?;
    let captures = size_of::<(&mut Query, &mut RootInitialReceivingOriginalV1,
        &RootJournalFinancialOriginalV1, &RootInitialOpenPreparedOriginalV1,
        &RootInitialReadyOriginalV1, &RootInitialTrustOriginalV1,
        &RootSelectedStartupBorrowV1<'_>, &RootUpperMutationGuardV1<'_>)>()
        .checked_mul(3)?
        .checked_add(size_of::<&Query>().checked_mul(12)?)?;
    let views = size_of::<Option<&(dyn Error + 'static)>>().checked_mul(18)?
        .checked_add(size_of::<bool>().checked_mul(12)?)?
        .checked_add(size_of::<Option<&RootObservationErrorV1>>().checked_mul(3)?)?;

    constructors.checked_add(delegates)?.checked_add(arguments)?
        .checked_add(results)?.checked_add(captures)?.checked_add(views)?
        .checked_add(size_of::<Option<usize>>().checked_mul(3)?)
}

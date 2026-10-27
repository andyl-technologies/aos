//! Names the actual second Source/Cache constructor and finite-purpose controls.
//!
//! The incoming constructor pays these typed receiving planes before the new
//! retained owners exist. Their own real Stages pay all native backing before
//! each reached operation. No unsigned proposal or earlier success pays a turn.

use std::mem::size_of;
use std::error::Error;
use aos_sandbox_broker::receiving::{RootInitialReceivingOriginalV1, RootObservationErrorV1,
    RootSelectedStartupBorrowV1, RootUpperMutationGuardV1, RootJournalFinancialOriginalV1};
use aos_sandbox_model::ResourceVector;
use super::owned::RootOwnedCurrentOriginalV1;
use super::proof_turn::RootCurrentProofTurnV1;
use super::initial_open::{RootInitialOpenErrorV1, RootInitialOpenPreparedOriginalV1};
use super::initial_source_query::{RootInitialSourceQueryErrorV1, RootInitialSourceQueryOriginalV1};
use super::initial_source_exchange::{RootInitialSourceExchangeErrorV1, RootInitialSourceExchangeOriginalV1};
use super::initial_cache::{RootInitialCacheProofErrorV1, RootInitialCacheProofOriginalV1,
    RootInitialCacheProofFrameBorrowV1, CachePrefix};
use super::initial_use_authorized::RootInitialUseAuthorizedOriginalV1;
use super::use_tail::reserved::RootUseReservedOriginalV1;

pub(super) fn construction_control_bytes_v1() -> Option<usize> {
    // These second objects execute their own same constructors. Reusing a pure
    // typed quote does not reuse the first object's already-retired call plane.
    let constructors = super::initial_source_query_controls::construction_control_bytes_v1()?
        .checked_add(super::initial_source_exchange_controls::construction_control_bytes_v1()?)?
        .checked_add(super::initial_cache_controls::construction_control_bytes_v1()?)?;
    let stages = size_of::<(&mut RootOwnedCurrentOriginalV1<'_>, &mut RootInitialReceivingOriginalV1,
        &RootSelectedStartupBorrowV1<'_>, &RootUpperMutationGuardV1<'_>)>().checked_mul(15)?
        .checked_add(size_of::<Result<(), RootObservationErrorV1>>().checked_mul(15)?)?;
    let source = size_of::<(&mut RootOwnedCurrentOriginalV1<'_>, u32, u32)>().checked_mul(3)?
        .checked_add(size_of::<&mut RootOwnedCurrentOriginalV1<'_>>().checked_mul(21)?)?
        .checked_add(size_of::<&RootOwnedCurrentOriginalV1<'_>>().checked_mul(21)?)?;
    let turns = turn_control_bytes_v1()?.checked_mul(6)?;
    let cache = size_of::<RootInitialCacheProofFrameBorrowV1<'_, '_>>().checked_mul(2)?
        .checked_add(size_of::<Result<RootInitialCacheProofFrameBorrowV1<'_, '_>, RootInitialCacheProofErrorV1>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<(), RootInitialCacheProofErrorV1>>().checked_mul(12)?)?
        .checked_add(size_of::<CachePrefix<'_>>().checked_mul(3)?)?
        .checked_add(size_of::<&CachePrefix<'_>>().checked_mul(3)?)?;
    let queries = size_of::<(&RootInitialSourceExchangeOriginalV1, &RootInitialOpenPreparedOriginalV1,
        &RootInitialUseAuthorizedOriginalV1, &RootUseReservedOriginalV1)>().checked_mul(3)?
        .checked_add(size_of::<(&RootInitialCacheProofOriginalV1, &RootInitialOpenPreparedOriginalV1,
            &RootInitialUseAuthorizedOriginalV1, &RootUseReservedOriginalV1)>().checked_mul(3)?)?
        .checked_add(size_of::<Result<(), RootInitialSourceExchangeErrorV1>>().checked_mul(12)?)?
        .checked_add(size_of::<Result<(), RootInitialSourceQueryErrorV1>>().checked_mul(9)?)?
        .checked_add(size_of::<Result<ResourceVector, crate::native::PolicyNativeJournalErrorV1>>().checked_mul(6)?)?;
    constructors.checked_add(stages)?.checked_add(source)?.checked_add(turns)?.checked_add(cache)?.checked_add(queries)?
        .checked_add(shared_interface_control_bytes_v1()?)?
        .checked_add(append_interface_control_bytes_v1::<{
            aos_sandbox_protocol::domain_ledger::create_storage_history::use_authorized::USE_AUTHORIZED_RECORD_BYTES_V1
        }>()?)?
        .checked_add(append_interface_control_bytes_v1::<{
            aos_sandbox_protocol::domain_ledger::create_storage_history::continuation::USE_ADMITTED_RECORD_BYTES_V1
        }>()?)
}

pub(super) fn turn_control_bytes_v1() -> Option<usize> {
    let turns = size_of::<RootCurrentProofTurnV1<'_>>().checked_mul(3)?
        .checked_add(size_of::<&RootCurrentProofTurnV1<'_>>().checked_mul(3)?)?;
    let predecessors = size_of::<(&RootInitialUseAuthorizedOriginalV1, &RootUseReservedOriginalV1,
        &RootInitialOpenPreparedOriginalV1)>().checked_mul(3)?
        .checked_add(size_of::<(&RootInitialSourceQueryOriginalV1, &RootJournalFinancialOriginalV1)>().checked_mul(3)?)?;
    let results = size_of::<Result<Option<[u8; 32]>, RootInitialOpenErrorV1>>().checked_mul(3)?
        .checked_add(size_of::<Result<(), RootInitialOpenErrorV1>>().checked_mul(6)?)?
        .checked_add(size_of::<Result<ResourceVector, RootInitialOpenErrorV1>>().checked_mul(3)?)?
        .checked_add(size_of::<Option<&(dyn Error + 'static)>>().checked_mul(3)?)?;
    turns.checked_add(predecessors)?.checked_add(results)
}

fn shared_interface_control_bytes_v1() -> Option<usize> {
    use super::initial_ready::RootInitialReadyOriginalV1;
    use super::initial_trust::RootInitialTrustOriginalV1;
    use super::initial_pins::RootInitialPinsOriginalV1;
    use super::initial_bundle::RootInitialBundleOwnershipOriginalV1;
    use super::writers::RootCurrentWritersOriginalV1;
    use super::owned::RootCurrentAcceptedOriginalsV1;
    use super::initial_cache::CachePrefix;
    use crate::native::startup::RootCurrentWritersPredecessorV1;
    use std::os::unix::net::UnixStream;

    let query = size_of::<(&mut RootInitialSourceQueryOriginalV1, &RootInitialOpenPreparedOriginalV1,
        &RootInitialReadyOriginalV1, &RootInitialTrustOriginalV1, RootCurrentProofTurnV1<'_>,
        RootCurrentWritersPredecessorV1<'_, '_, '_>, &RootSelectedStartupBorrowV1<'_>,
        &RootUpperMutationGuardV1<'_>)>().checked_mul(6)?;
    let exchange = size_of::<(&mut RootInitialSourceExchangeOriginalV1, &RootCurrentWritersOriginalV1,
        &RootInitialOpenPreparedOriginalV1, &RootInitialPinsOriginalV1, &RootInitialSourceQueryOriginalV1,
        u32, u32, RootCurrentProofTurnV1<'_>)>().checked_mul(12)?
        .checked_add(size_of::<(&mut RootInitialSourceExchangeOriginalV1, &RootCurrentWritersOriginalV1,
            &RootInitialOpenPreparedOriginalV1, RootCurrentProofTurnV1<'_>)>().checked_mul(6)?)?;
    let cache = size_of::<(&mut RootInitialCacheProofOriginalV1, &RootInitialOpenPreparedOriginalV1,
        &RootInitialBundleOwnershipOriginalV1, &RootInitialPinsOriginalV1, CachePrefix<'_>,
        RootCurrentWritersPredecessorV1<'_, '_, '_>, &RootSelectedStartupBorrowV1<'_>,
        &RootUpperMutationGuardV1<'_>)>().checked_mul(6)?;
    let frame = size_of::<(&mut RootInitialCacheProofOriginalV1, &RootCurrentWritersOriginalV1,
        &RootInitialOpenPreparedOriginalV1, &RootInitialReadyOriginalV1, &RootInitialSourceExchangeOriginalV1,
        &RootInitialPinsOriginalV1, &RootInitialBundleOwnershipOriginalV1,
        &mut RootCurrentAcceptedOriginalsV1<'_>, &UnixStream, RootCurrentProofTurnV1<'_>)>().checked_mul(6)?
        .checked_add(size_of::<(&mut RootInitialCacheProofOriginalV1, &RootCurrentWritersOriginalV1,
            &RootInitialOpenPreparedOriginalV1, &RootInitialReadyOriginalV1, &RootInitialSourceExchangeOriginalV1,
            &RootInitialBundleOwnershipOriginalV1, &RootCurrentAcceptedOriginalsV1<'_>,
            &UnixStream, RootCurrentProofTurnV1<'_>)>().checked_mul(6)?)?;
    let captures = size_of::<&RootCurrentProofTurnV1<'_>>().checked_mul(12)?
        .checked_add(size_of::<&CachePrefix<'_>>().checked_mul(6)?)?
        .checked_add(size_of::<(&RootCurrentProofTurnV1<'_>, &RootInitialCacheProofOriginalV1)>().checked_mul(6)?)?;
    query.checked_add(exchange)?.checked_add(cache)?.checked_add(frame)?.checked_add(captures)
}


fn append_interface_control_bytes_v1<const RECORD: usize>() -> Option<usize> {
    use std::os::fd::BorrowedFd;
    use super::initial_open::RootHistoryAppendPurposeV1;
    use super::history_pair::RootCurrentHistoryPairV1;
    use super::owned::RootCurrentAcceptedOriginalsV1;
    use super::preopen_geometry::ProtectedJournalPreopenReplayExtentV1;
    use crate::native::journal::RootPolicyJournalV1;
    use crate::native::target::RootPolicyTargetOriginalV1;
    use crate::native::PolicyNativeJournalErrorV1;

    let append = size_of::<(&mut RootCurrentHistoryPairV1<RECORD>, &mut RootPolicyJournalV1,
        &RootPolicyTargetOriginalV1, &RootInitialOpenPreparedOriginalV1,
        RootHistoryAppendPurposeV1<'_>, &RootCurrentAcceptedOriginalsV1<'_>,
        BorrowedFd<'_>)>().checked_mul(3)?;
    let admitted = size_of::<(&mut RootCurrentHistoryPairV1<RECORD>, &mut RootPolicyJournalV1,
        &RootPolicyTargetOriginalV1, &RootInitialOpenPreparedOriginalV1,
        &RootInitialUseAuthorizedOriginalV1, &RootUseReservedOriginalV1,
        &RootInitialSourceExchangeOriginalV1, &RootInitialCacheProofOriginalV1,
        &RootCurrentAcceptedOriginalsV1<'_>, BorrowedFd<'_>)>().checked_mul(3)?;
    let cut = size_of::<(&mut RootCurrentHistoryPairV1<RECORD>, &RootInitialOpenPreparedOriginalV1)>()
        .checked_mul(3)?;
    let quote = size_of::<(&ProtectedJournalPreopenReplayExtentV1, ResourceVector, usize, usize, usize)>()
        .checked_mul(3)?;
    let results = size_of::<Result<(), RootInitialOpenErrorV1>>().checked_mul(9)?
        .checked_add(size_of::<Result<ResourceVector, PolicyNativeJournalErrorV1>>().checked_mul(3)?)?;
    append.checked_add(admitted)?.checked_add(cut)?.checked_add(quote)?.checked_add(results)
}

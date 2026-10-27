//! Quotes concrete Initial issuer constructors and same-owner interfaces.
//!
//! The genuine incoming INITIAL payer consumes this Memory-only supplier before
//! constructing the owned programme. Native owed names remain a separate vector
//! forecast; neither this quote nor public verifier DATA supplies role authority.

use std::error::Error;
use std::mem::size_of;

use aos_sandbox_broker::receiving::{RootInitialReceivingOriginalV1,
    RootJournalFinancialOriginalV1, RootObservationErrorV1,
    RootSelectedStartupBorrowV1, RootUpperMutationGuardV1};
use aos_sandbox_broker::systemd_credentials::RootCurrentIssuerCredentialCustodyV1;
use aos_sandbox_model::{RawPairedClockSample, ResourceVector};
use aos_sandbox_ledger_replay::source_signer_data::PinnedSourceHoldReadbackSignerV1;
use aos_sandbox_protocol::cache_owner_readback::{CacheOwnerReadbackDataErrorV1,
    PinnedCacheOwnerReadbackSignerV1};
use aos_sandbox_protocol::domain_ledger::create_storage_history::readback::HistoryPairReadbackDataV1;
use aos_sandbox_protocol::domain_ledger::readonly::HistoricalLedgerReadViewV1;

use crate::native::journal::RootPolicyJournalV1;
use crate::native::startup::RootCurrentWritersPredecessorV1;
use crate::native::target::RootPolicyTargetOriginalV1;
use crate::native::PolicyNativeJournalErrorV1 as NativeError;
use crate::root_role_pins_data::{RootRolePinsDataErrorV1, RootRolePinsDataV1};

use super::history_post::RootCurrentHistoryPostOriginalV1;
use super::initial_open::{RootInitialClockErrorV1, RootInitialOpenErrorV1,
    RootInitialOpenPreparedOriginalV1, ROOT_RECORD_BYTES};
use super::initial_pins::{RootInitialPinsErrorV1 as E, RootInitialPinsOriginalV1 as Pins};
use super::initial_ready::RootInitialReadyOriginalV1;
use super::initial_receiving::RootInitialStageOriginalV1;
use super::initial_writer_sample::RootInitialWriterSampleOriginalV1;
use super::owned::{RootCurrentAcceptedOriginalsV1, RootInitialPinsBorrowV1,
    RootOwnedCurrentOriginalV1};
use super::writers::RootCurrentWritersOriginalV1;

type Readback = HistoryPairReadbackDataV1<ROOT_RECORD_BYTES>;

pub(super) fn construction_control_bytes_v1() -> Option<usize> {
    let constructors = size_of::<Pins>().checked_mul(2)?
        .checked_add(size_of::<RootInitialStageOriginalV1>().checked_mul(2)?)?
        .checked_add(size_of::<RootCurrentIssuerCredentialCustodyV1>().checked_mul(2)?)?
        .checked_add(RootInitialWriterSampleOriginalV1::construction_control_bytes_v1()?
            .checked_mul(2)?)?;
    let stage = RootJournalFinancialOriginalV1::receiving_stage_under_exclusion_control_bytes_v1()?
        .checked_add(RootSelectedStartupBorrowV1::service_recheck_under_exclusion_control_bytes_v1()?)?;
    let peer = RootCurrentHistoryPostOriginalV1::construction_control_bytes_v1()?;
    let external = size_of::<(&mut RootOwnedCurrentOriginalV1<'_>,
        &mut RootInitialReceivingOriginalV1, &RootSelectedStartupBorrowV1<'_>,
        &RootUpperMutationGuardV1<'_>)>().checked_mul(6)?
        .checked_add(size_of::<&mut RootOwnedCurrentOriginalV1<'_>>().checked_mul(18)?)?
        .checked_add(size_of::<&RootOwnedCurrentOriginalV1<'_>>().checked_mul(15)?)?
        .checked_add(size_of::<RootInitialPinsBorrowV1<'_, '_>>().checked_mul(2)?)?
        .checked_add(size_of::<Result<RootInitialPinsBorrowV1<'_, '_>, E>>().checked_mul(3)?)?
        .checked_add(size_of::<&RootInitialPinsBorrowV1<'_, '_>>().checked_mul(18)?)?;
    let arguments = size_of::<(&mut Pins, &RootInitialOpenPreparedOriginalV1,
        &RootInitialReadyOriginalV1, RootCurrentWritersPredecessorV1<'_, '_, '_>,
        &RootSelectedStartupBorrowV1<'_>, &RootUpperMutationGuardV1<'_>)>().checked_mul(3)?
        .checked_add(size_of::<(&mut Pins, &RootCurrentWritersOriginalV1,
            &RootInitialOpenPreparedOriginalV1)>().checked_mul(9)?)?
        .checked_add(size_of::<(&mut Pins, RootCurrentWritersPredecessorV1<'_, '_, '_>,
            &RootSelectedStartupBorrowV1<'_>, &RootUpperMutationGuardV1<'_>)>().checked_mul(3)?)?
        .checked_add(size_of::<(&mut Pins, &RootCurrentAcceptedOriginalsV1<'_>,
            &RootInitialOpenPreparedOriginalV1)>().checked_mul(3)?)?
        .checked_add(size_of::<(&Pins, &RootPolicyTargetOriginalV1)>().checked_mul(9)?)?
        .checked_add(size_of::<&mut Pins>().checked_mul(15)?)?
        .checked_add(size_of::<&Pins>().checked_mul(21)?)?;
    let results = size_of::<Result<(), E>>().checked_mul(36)?
        .checked_add(size_of::<Result<(), RootObservationErrorV1>>().checked_mul(18)?)?
        .checked_add(size_of::<Result<(), ()>>().checked_mul(6)?)?
        .checked_add(size_of::<Result<ResourceVector, E>>().checked_mul(6)?)?
        .checked_add(size_of::<Result<ResourceVector, RootInitialOpenErrorV1>>().checked_mul(9)?)?
        .checked_add(size_of::<Result<ResourceVector, NativeError>>().checked_mul(9)?)?
        .checked_add(size_of::<Result<u64, RootInitialOpenErrorV1>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<Readback, RootInitialOpenErrorV1>>().checked_mul(6)?)?
        .checked_add(size_of::<Result<RawPairedClockSample, RootInitialClockErrorV1>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<RootCurrentWritersPredecessorV1<'_, '_, '_>,
            RootObservationErrorV1>>().checked_mul(6)?)?
        .checked_add(size_of::<Result<(&RootPolicyJournalV1, &RootPolicyTargetOriginalV1),
            RootObservationErrorV1>>().checked_mul(9)?)?
        .checked_add(size_of::<Result<(&RootPolicyJournalV1, &RootPolicyTargetOriginalV1), E>>()
            .checked_mul(3)?)?;
    let role_data = size_of::<Result<RootRolePinsDataV1, RootRolePinsDataErrorV1>>().checked_mul(3)?
        .checked_add(size_of::<Result<RootRolePinsDataV1, E>>().checked_mul(9)?)?
        .checked_add(size_of::<Result<[u8; 80], E>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<PinnedCacheOwnerReadbackSignerV1, CacheOwnerReadbackDataErrorV1>>()
            .checked_mul(3)?)?
        .checked_add(size_of::<Result<&PinnedCacheOwnerReadbackSignerV1, E>>().checked_mul(6)?)?
        .checked_add(size_of::<Result<&PinnedSourceHoldReadbackSignerV1, E>>().checked_mul(6)?)?
        .checked_add(size_of::<Result<&[u8; 488], E>>().checked_mul(6)?)?
        .checked_add(size_of::<HistoricalLedgerReadViewV1<'_>>().checked_mul(6)?)?
        .checked_add(size_of::<Option<&[u8]>>().checked_mul(6)?)?
        .checked_add(size_of::<Option<[&[u8]; 2]>>().checked_mul(6)?)?
        .checked_add(size_of::<(HistoricalLedgerReadViewV1<'_>, &[u8], &[u8])>().checked_mul(9)?)?;
    let positive_views = size_of::<Result<&ResourceVector, E>>().checked_mul(3)?
        .checked_add(size_of::<Result<&(), E>>().checked_mul(21)?)?
        .checked_add(size_of::<Result<&Readback, E>>().checked_mul(6)?)?
        .checked_add(size_of::<Result<&RootRolePinsDataV1, E>>().checked_mul(9)?)?
        .checked_add(size_of::<Result<&[u8; 80], E>>().checked_mul(6)?)?
        .checked_add(size_of::<Result<&PinnedCacheOwnerReadbackSignerV1, E>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<&RawPairedClockSample, E>>().checked_mul(3)?)?
        .checked_add(size_of::<Option<&(dyn Error + 'static)>>().checked_mul(54)?)?
        .checked_add(size_of::<bool>().checked_mul(9)?)?;
    // These are actual closure environments, separate from resident owner bytes.
    let captures = size_of::<(&mut Pins, &mut RootInitialReceivingOriginalV1,
        &RootJournalFinancialOriginalV1, &RootInitialOpenPreparedOriginalV1,
        &RootInitialReadyOriginalV1, &RootSelectedStartupBorrowV1<'_>,
        &RootUpperMutationGuardV1<'_>)>().checked_mul(3)?
        .checked_add(size_of::<(&mut Pins, &RootInitialOpenPreparedOriginalV1)>().checked_mul(3)?)?
        .checked_add(size_of::<&Pins>().checked_mul(45)?)?
        .checked_add(size_of::<(&Result<(), RootObservationErrorV1>,)>().checked_mul(3)?)?;

    constructors.checked_add(stage)?
        .checked_add(size_of::<&mut RootInitialReceivingOriginalV1>().checked_mul(3)?)?
        .checked_add(size_of::<Result<(), ()>>().checked_mul(6)?)?
        .checked_add(size_of::<(&Result<(), ()>, bool)>().checked_mul(3)?)?
        .checked_add(peer)?
        .checked_add(external)?
        .checked_add(arguments)?
        .checked_add(results)?
        .checked_add(role_data)?
        .checked_add(positive_views)?
        .checked_add(captures)?
        .checked_add(size_of::<Option<usize>>().checked_mul(12)?)
}

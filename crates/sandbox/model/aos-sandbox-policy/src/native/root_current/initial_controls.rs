//! Quotes the concrete new INITIAL constructor and forwarding interfaces.
//!
//! The real incoming Create branch consumes these controls before constructing
//! its owned programme. Actual native names/files/clock/history backing remains
//! in the separately checked Open Stage; these scalar controls grant no role.

use std::error::Error;
use std::mem::size_of;
use std::os::fd::BorrowedFd;

use aos_sandbox_broker::receiving::{
    RootAcceptedHistoryBorrowerV1, RootInitialReceivingOriginalV1, RootJournalFinancialOriginalV1,
    RootObservationErrorV1, RootOpenClockOriginalV1, RootOpenPhysicalBorrowerV1,
    RootSelectedStartupBorrowV1, RootUpperMutationGuardV1,
};
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_linux_descriptors::unix_stream::RetainedUnixStream;
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    root_open::RootOpenBodyDataV1, transport::OpenQueryV1,
};
use aos_sandbox_protocol::domain_ledger::protected_names::ProtectedJournalNamesV1;

use crate::native::journal::{RootPolicyJournalV1, names::{
    RootFixedNameRoleV1, RootFixedNameRecipeV1, RootPolicyNameObservationOriginalV1,
}};
use crate::native::startup::{RootCurrentWritersPredecessorV1, RootStartupControllerPeerOriginalV1};
use crate::native::target::RootPolicyTargetOriginalV1;
use crate::native::PolicyNativeJournalErrorV1;

use super::history_post::RootCurrentHistoryPostOriginalV1;
use super::initial_open::{
    RootInitialOpenAppendGateV1, RootInitialOpenCrossingOriginalV1,
    RootInitialOpenErrorV1 as E, RootInitialOpenPreparedOriginalV1,
    RootInitialOpenProgrammeOriginalV1,
};
use super::initial_post::RootInitialOpenPostsOriginalV1;
use super::initial_provision::{RootInitialOpenProvisionOriginalV1, RootInitialOpenReceivingDataV1};
use super::owned::RootOwnedCurrentOriginalV1;
use super::writers::RootCurrentWritersOriginalV1;

pub(super) fn construction_control_bytes_v1() -> Option<usize> {
    // Resident fields are contained in RootOwnedCurrentOriginal. These are the
    // distinct nested constructor/return planes, not padding or optimizer credit.
    let constructors = size_of::<RootInitialOpenProgrammeOriginalV1>()
        .checked_add(size_of::<RootInitialOpenPreparedOriginalV1>())?
        .checked_add(size_of::<RootInitialOpenCrossingOriginalV1>())?
        .checked_add(size_of::<RootInitialOpenPostsOriginalV1>())?
        .checked_add(size_of::<RootInitialOpenProvisionOriginalV1>())?
        .checked_mul(2)?;
    let names = RootPolicyNameObservationOriginalV1::fixed_carrier_demand_v1()?
        .get(D::MemoryBytes).checked_mul(10)?;
    let names = usize::try_from(names).ok()?;
    let history = RootCurrentHistoryPostOriginalV1::construction_control_bytes_v1()?.checked_mul(2)?;
    let clocks = RootOpenClockOriginalV1::additional_control_bytes_v1()?
        .checked_add(RootAcceptedHistoryBorrowerV1::root_open_clock_binding_control_bytes_v1()?)?
        .checked_add(RootOpenPhysicalBorrowerV1::peer_association_control_bytes_v1()?)?;
    let provision = RootJournalFinancialOriginalV1::receiving_stage_under_exclusion_control_bytes_v1()?
        .checked_add(RootSelectedStartupBorrowV1::service_recheck_under_exclusion_control_bytes_v1()?)?;

    let post_queries = size_of::<&RootInitialOpenPostsOriginalV1>().checked_mul(6)?
        .checked_add(size_of::<Result<aos_sandbox_model::RawPairedClockSample, E>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<aos_sandbox_protocol::domain_ledger::protected_names::ProtectedJournalNamesV1,
            E>>().checked_mul(3)?)?;

    constructors.checked_add(names)?.checked_add(post_queries)?
        .checked_add(size_of::<(&Option<RootCurrentHistoryPostOriginalV1>, bool)>()
            .checked_mul(3)?)?
        .checked_add(history)?
        .checked_add(clocks)?
        .checked_add(provision)?
        .checked_add(super::initial_geometry::control_bytes_v1()?)?
        // Actual upper/native staged entry interfaces, including whole-gate and
        // borrowed producer/stream/clock owners. Each is a real typed call lane.
        .checked_add(size_of::<(&mut RootOwnedCurrentOriginalV1<'_>,
            &mut RootInitialReceivingOriginalV1, &RootSelectedStartupBorrowV1<'_>,
            &RootUpperMutationGuardV1<'_>)>().checked_mul(9)?)?
        .checked_add(size_of::<(&mut RootOwnedCurrentOriginalV1<'_>, OpenQueryV1)>().checked_mul(3)?)?
        .checked_add(size_of::<&mut RootOwnedCurrentOriginalV1<'_>>().checked_mul(3)?)?
        .checked_add(size_of::<&mut RootOwnedCurrentOriginalV1<'_>>().checked_mul(3)?)?
        .checked_add(size_of::<(&mut RootInitialOpenPreparedOriginalV1,
            &mut RootCurrentWritersOriginalV1, &RootAcceptedHistoryBorrowerV1<'_, '_>, OpenQueryV1)>()
            .checked_mul(6)?)?
        .checked_add(size_of::<(&mut RootInitialOpenPreparedOriginalV1,
            &mut RootCurrentWritersOriginalV1, &mut RootInitialOpenCrossingOriginalV1,
            &mut RootCurrentHistoryPostOriginalV1, &RootStartupControllerPeerOriginalV1<'_>,
            &RetainedUnixStream, BorrowedFd<'_>)>().checked_mul(3)?)?
        .checked_add(size_of::<(&mut RootInitialOpenPostsOriginalV1,
            RootCurrentWritersPredecessorV1<'_, '_, '_>, &RootSelectedStartupBorrowV1<'_>,
            &RootUpperMutationGuardV1<'_>)>().checked_mul(3)?)?
        .checked_add(size_of::<(&mut RootInitialOpenPostsOriginalV1,
            &mut RootCurrentWritersOriginalV1, &RootInitialOpenPreparedOriginalV1,
            &RootStartupControllerPeerOriginalV1<'_>, &RetainedUnixStream)>().checked_mul(3)?)?
        .checked_add(size_of::<(&mut RootInitialOpenProvisionOriginalV1,
            &RootCurrentWritersOriginalV1, RootCurrentWritersPredecessorV1<'_, '_, '_>,
            &RootSelectedStartupBorrowV1<'_>, &RootUpperMutationGuardV1<'_>)>().checked_mul(3)?)?
        .checked_add(size_of::<(&RootInitialOpenProvisionOriginalV1,
            &RootCurrentWritersOriginalV1, &RootJournalFinancialOriginalV1,
            &RootSelectedStartupBorrowV1<'_>, &RootUpperMutationGuardV1<'_>)>().checked_mul(3)?)?
        .checked_add(size_of::<RootInitialOpenAppendGateV1<'_, '_>>().checked_mul(3)?)?
        .checked_add(size_of::<(&mut RootInitialOpenAppendGateV1<'_, '_>,
            &RootPolicyJournalV1, &aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction)>()
            .checked_mul(3)?)?
        .checked_add(size_of::<(&RootInitialOpenAppendGateV1<'_, '_>,
            &RootPolicyJournalV1)>().checked_mul(6)?)?
        .checked_add(size_of::<(&RootPolicyJournalV1, RootFixedNameRoleV1,
            RootFixedNameRecipeV1, &mut RootPolicyNameObservationOriginalV1)>().checked_mul(15)?)?
        .checked_add(size_of::<(&RootPolicyTargetOriginalV1,
            &mut RootPolicyNameObservationOriginalV1)>().checked_mul(15)?)?
        .checked_add(size_of::<Result<ProtectedJournalNamesV1, E>>().checked_mul(18)?)?
        .checked_add(size_of::<Result<ProtectedJournalNamesV1, ()>>().checked_mul(18)?)?
        .checked_add(size_of::<Result<(), E>>().checked_mul(12)?)?
        .checked_add(size_of::<Result<(), ()>>().checked_mul(12)?)?
        .checked_add(size_of::<Result<RootInitialOpenReceivingDataV1<'_>, RootObservationErrorV1>>()
            .checked_mul(3)?)?
        .checked_add(size_of::<Result<ResourceVector, PolicyNativeJournalErrorV1>>().checked_mul(12)?)?
        .checked_add(size_of::<Result<(), RootObservationErrorV1>>().checked_mul(24)?)?
        .checked_add(size_of::<Result<(), E>>().checked_mul(30)?)?
        .checked_add(size_of::<Result<RootOpenBodyDataV1, E>>().checked_mul(12)?)?
        .checked_add(size_of::<Result<[u8; aos_sandbox_protocol::domain_ledger::create_storage_history::root_open::ROOT_OPEN_BODY_BYTES_V1],
            aos_sandbox_protocol::domain_ledger::create_storage_history::HistoryErrorV1>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<[u8; 32], aos_sandbox_protocol::domain_ledger::create_storage_history::HistoryErrorV1>>()
            .checked_mul(3)?)?
        .checked_add(size_of::<Result<aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction, E>>()
            .checked_mul(3)?)?
        .checked_add(size_of::<Result<aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction,
            aos_sandbox_protocol::domain_ledger::create_storage_history::HistoryPairPreparationErrorV1>>()
            .checked_mul(3)?)?
        .checked_add(size_of::<Result<aos_sandbox_broker::canonical_journal::CommitResult,
            PolicyNativeJournalErrorV1>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<aos_sandbox_protocol::domain_ledger::create_storage_history::readback::HistoryPairReadbackBytesDataV1<'_>, E>>()
            .checked_mul(3)?)?
        .checked_add(size_of::<Result<aos_sandbox_protocol::domain_ledger::create_storage_history::readback::HistoryPairReadbackDataV1<
            { super::initial_open::ROOT_RECORD_BYTES }>, E>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<[u8; super::initial_open::ROOT_RECORD_BYTES], std::array::TryFromSliceError>>()
            .checked_mul(3)?)?
        .checked_add(size_of::<(&RootInitialOpenPreparedOriginalV1, &RootPolicyJournalV1,
            &RootPolicyTargetOriginalV1, OpenQueryV1)>().checked_mul(3)?)?
        .checked_add(size_of::<(&RootInitialOpenPreparedOriginalV1, &RootPolicyJournalV1,
            &RootPolicyTargetOriginalV1, &aos_sandbox_broker::canonical_journal::CommitResult)>().checked_mul(3)?)?
        // The diagnostic chains construct concrete borrowed closure environments
        // while querying the same retained owners, with no additional IO.
        .checked_add(size_of::<(&RootInitialOpenPreparedOriginalV1,
            Option<&(dyn Error + 'static)>)>().checked_mul(54)?)?
        .checked_add(size_of::<(&RootInitialOpenCrossingOriginalV1,
            Option<&RootCurrentHistoryPostOriginalV1>, Option<&(dyn Error + 'static)>)>()
            .checked_mul(54)?)?
        .checked_add(size_of::<(&RootInitialOpenPostsOriginalV1,
            Option<&(dyn Error + 'static)>)>().checked_mul(45)?)?
        .checked_add(size_of::<Option<usize>>().checked_mul(12)?)?
        .checked_add(size_of::<Option<ResourceVector>>().checked_mul(6)?)?
        .checked_add(size_of::<bool>().checked_mul(30)?)
}

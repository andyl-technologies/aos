//! Measures new Initial Ready constructor and concrete staged interfaces.
//!
//! The actual incoming Create payer consumes these Memory controls before native
//! programme construction. Ready's fixed/variable stages retain their own native
//! resource geometry; these passive controls confer no phase or completion.

use std::error::Error;
use std::mem::size_of;
use std::os::unix::net::UnixStream;

use aos_sandbox_broker::kernel_clock::RetainedKernelPairedClockAttemptV1;
use aos_sandbox_broker::receiving::{
    RootInitialReceivingOriginalV1, RootJournalFinancialOriginalV1,
    RootObservationErrorV1, RootSelectedStartupBorrowV1, RootUpperMutationGuardV1,
};
use aos_sandbox_model::{RawPairedClockSample, ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::unix_stream::{RetainedSubjectStreamReadV1,
    SubjectStreamReadErrorV1, SubjectStreamReceiveGeometryV1};
use aos_sandbox_protocol::domain_ledger::create_storage_history::{HistoryErrorV1,
    indexed_transfer::IndexedTransferPurposeDataV1, root_open::RootOpenBodyDataV1,
    transport::TransferIndexV1};

use crate::native::startup::RootCurrentWritersPredecessorV1;
use crate::native::PolicyNativeJournalErrorV1 as NativeError;

use super::history_post::RootCurrentHistoryPostOriginalV1;
use super::initial_open::{RootInitialClockErrorV1, RootInitialOpenErrorV1 as E,
    RootInitialOpenPreparedOriginalV1};
use super::initial_ready::RootInitialReadyOriginalV1;
use super::initial_receiving::RootInitialStageOriginalV1 as ReadyStageV1;
use super::initial_subject::{RootInitialSubjectFrameBorrowV1, RootInitialSubjectOriginalV1};
use super::owned::{RootCurrentAcceptedOriginalsV1, RootOwnedCurrentOriginalV1};

pub(super) fn clock_demand_v1() -> Result<ResourceVector, NativeError> {
    type Clock = RetainedKernelPairedClockAttemptV1<RootInitialClockErrorV1>;
    let bytes = Clock::dominant_requested_bytes_v1().ok_or_else(NativeError::geometry)?;
    let cells = Clock::receiving_metadata_cells_v1().ok_or_else(NativeError::geometry)?;
    Ok(ResourceVector::ZERO
        .with(D::MemoryBytes, u64::try_from(bytes).map_err(|_| NativeError::geometry())?)
        .with(D::MetadataEntries, u64::try_from(cells).map_err(|_| NativeError::geometry())?)
        .with(D::OpenFiles, Clock::MAXIMUM_RETAINED_FILES_V1 as u64))
}

pub(super) fn construction_control_bytes_v1() -> Option<usize> {
    let constructors = size_of::<RootInitialReadyOriginalV1>().checked_mul(2)?
        .checked_add(size_of::<ReadyStageV1>().checked_mul(4)?)?
        .checked_add(size_of::<RootInitialSubjectOriginalV1>().checked_mul(2)?)?
        .checked_add(size_of::<RetainedSubjectStreamReadV1>().checked_mul(4)?)?;
    let names = super::initial_writer_sample::RootInitialWriterSampleOriginalV1::construction_control_bytes_v1()?;
    let arms = RootCurrentHistoryPostOriginalV1::construction_control_bytes_v1()?;
    let stage = RootJournalFinancialOriginalV1::receiving_stage_under_exclusion_control_bytes_v1()?
        .checked_add(RootSelectedStartupBorrowV1::service_recheck_under_exclusion_control_bytes_v1()?)?;

    constructors.checked_add(names)?
        .checked_add(size_of::<&mut RootInitialReceivingOriginalV1>().checked_mul(9)?)?
        .checked_add(size_of::<Result<(), ()>>().checked_mul(6)?)?
        .checked_add(size_of::<(&Result<(), ()>, bool)>().checked_mul(3)?)?
        .checked_add(size_of::<&mut RootOwnedCurrentOriginalV1<'_>>().checked_mul(3)?)?
        .checked_add(size_of::<&mut RootInitialReadyOriginalV1>().checked_mul(3)?)?
        .checked_add(size_of::<Result<(), E>>().checked_mul(3)?)?
        .checked_add(size_of::<bool>().checked_mul(3)?)?
        .checked_add(size_of::<(&RootInitialSubjectFrameBorrowV1<'_, '_>,
            Option<&(dyn Error + 'static)>)>().checked_mul(3)?)?
        .checked_add(size_of::<&mut RootInitialSubjectFrameBorrowV1<'_, '_>>().checked_mul(3)?)?
        .checked_add(size_of::<&mut RootOwnedCurrentOriginalV1<'_>>().checked_mul(3)?)?
        .checked_add(size_of::<&mut RootInitialReadyOriginalV1>().checked_mul(3)?)?
        .checked_add(size_of::<Option<Result<(), RootObservationErrorV1>>>().checked_mul(9)?)?
        .checked_add(size_of::<bool>().checked_mul(9)?)?
        .checked_add(arms)?
        .checked_add(stage)?
        // External programme and its opaque frame-stage argument/return planes.
        .checked_add(size_of::<(&mut RootOwnedCurrentOriginalV1<'_>,
            &mut RootInitialReceivingOriginalV1, &RootSelectedStartupBorrowV1<'_>,
            &RootUpperMutationGuardV1<'_>)>().checked_mul(9)?)?
        .checked_add(size_of::<&mut RootOwnedCurrentOriginalV1<'_>>().checked_mul(39)?)?
        .checked_add(size_of::<&RootOwnedCurrentOriginalV1<'_>>().checked_mul(9)?)?
        .checked_add(size_of::<Result<RootInitialSubjectFrameBorrowV1<'_, '_>, E>>().checked_mul(6)?)?
        .checked_add(size_of::<RootInitialSubjectFrameBorrowV1<'_, '_>>().checked_mul(2)?)?
        .checked_add(size_of::<(&mut RootInitialSubjectOriginalV1, &mut RetainedSubjectStreamReadV1,
            &mut RootCurrentAcceptedOriginalsV1<'_>, &RootInitialOpenPreparedOriginalV1,
            SubjectStreamReceiveGeometryV1)>().checked_mul(3)?)?
        .checked_add(size_of::<(&mut RootInitialSubjectFrameBorrowV1<'_, '_>,
            &mut RootInitialReceivingOriginalV1, &RootSelectedStartupBorrowV1<'_>,
            &RootUpperMutationGuardV1<'_>)>().checked_mul(6)?)?
        .checked_add(size_of::<&mut RootInitialSubjectFrameBorrowV1<'_, '_>>().checked_mul(18)?)?
        .checked_add(size_of::<&RootInitialSubjectFrameBorrowV1<'_, '_>>().checked_mul(9)?)?
        // Private fixed/variable stages derive actual totals internally.
        .checked_add(size_of::<(&mut RootInitialReadyOriginalV1, &RootInitialOpenPreparedOriginalV1,
            &super::initial_provision::RootInitialOpenProvisionOriginalV1,
            RootCurrentWritersPredecessorV1<'_, '_, '_>, &RootSelectedStartupBorrowV1<'_>,
            &RootUpperMutationGuardV1<'_>)>().checked_mul(3)?)?
        .checked_add(size_of::<(&mut RootInitialReadyOriginalV1,
            RootCurrentWritersPredecessorV1<'_, '_, '_>, &RootSelectedStartupBorrowV1<'_>,
            &RootUpperMutationGuardV1<'_>)>().checked_mul(6)?)?
        .checked_add(size_of::<(&mut ReadyStageV1, &mut RootInitialReceivingOriginalV1,
            &RootSelectedStartupBorrowV1<'_>, &RootUpperMutationGuardV1<'_>)>().checked_mul(6)?)?
        .checked_add(size_of::<(&mut RootInitialReadyOriginalV1,
            &mut RootCurrentAcceptedOriginalsV1<'_>, &UnixStream,
            &RootInitialOpenPreparedOriginalV1)>().checked_mul(3)?)?
        .checked_add(size_of::<(&mut RootInitialReadyOriginalV1, &UnixStream, &[u8])>().checked_mul(3)?)?
        .checked_add(size_of::<(&mut RootInitialReadyOriginalV1,
            &RootInitialOpenPreparedOriginalV1)>().checked_mul(9)?)?
        .checked_add(size_of::<(&mut RootInitialReadyOriginalV1,
            &mut RootCurrentAcceptedOriginalsV1<'_>, &RootInitialOpenPreparedOriginalV1)>().checked_mul(6)?)?
        .checked_add(size_of::<(&mut RootInitialReadyOriginalV1,
            &super::writers::RootCurrentWritersOriginalV1, &RootInitialOpenPreparedOriginalV1)>()
            .checked_mul(3)?)?
        .checked_add(size_of::<(&mut RootInitialReadyOriginalV1,
            &RootCurrentAcceptedOriginalsV1<'_>, &RootInitialOpenPreparedOriginalV1)>().checked_mul(3)?)?
        .checked_add(size_of::<&mut RootInitialReadyOriginalV1>().checked_mul(15)?)?
        .checked_add(size_of::<&RootInitialReadyOriginalV1>().checked_mul(18)?)?
        // Exact conversion/Result interfaces, including private retained marker resolution.
        .checked_add(size_of::<Result<ResourceVector, NativeError>>().checked_mul(12)?)?
        .checked_add(size_of::<Result<ResourceVector, E>>().checked_mul(12)?)?
        .checked_add(size_of::<Result<(), E>>().checked_mul(54)?)?
        .checked_add(size_of::<Result<(), RootObservationErrorV1>>().checked_mul(24)?)?
        .checked_add(size_of::<Result<(), SubjectStreamReadErrorV1>>().checked_mul(9)?)?
        .checked_add(size_of::<Result<bool, E>>().checked_mul(6)?)?
        .checked_add(size_of::<Result<usize, E>>().checked_mul(9)?)?
        .checked_add(size_of::<Result<&[u8], E>>().checked_mul(6)?)?
        .checked_add(size_of::<Result<&[u8; super::initial_open::ROOT_RECORD_BYTES], E>>().checked_mul(6)?)?
        .checked_add(size_of::<Result<TransferIndexV1, HistoryErrorV1>>().checked_mul(6)?)?
        .checked_add(size_of::<Result<RootOpenBodyDataV1, E>>().checked_mul(15)?)?
        .checked_add(size_of::<Result<RawPairedClockSample, RootInitialClockErrorV1>>().checked_mul(6)?)?
        .checked_add(size_of::<(&super::initial_provision::RootInitialOpenProvisionOriginalV1,
            &RootJournalFinancialOriginalV1, bool)>().checked_mul(3)?)?
        .checked_add(size_of::<(&RootInitialOpenPreparedOriginalV1,
            &crate::native::journal::RootPolicyJournalV1,
            &crate::native::target::RootPolicyTargetOriginalV1)>().checked_mul(3)?)?
        .checked_add(size_of::<Result<aos_sandbox_protocol::domain_ledger::create_storage_history::readback::
            HistoryPairReadbackDataV1<{super::initial_open::ROOT_RECORD_BYTES}>, E>>().checked_mul(6)?)?
        .checked_add(size_of::<(&Option<Result<(), SubjectStreamReadErrorV1>>,
            &RetainedSubjectStreamReadV1, Option<&(dyn Error + 'static)>)>().checked_mul(6)?)?
        .checked_add(size_of::<(Option<&mut RootCurrentHistoryPostOriginalV1>,
            &RootCurrentAcceptedOriginalsV1<'_>)>().checked_mul(3)?)?
        // Fixed quote arithmetic and the actual canonical Ready-only recipe locals.
        .checked_add(size_of::<(TransferIndexV1, IndexedTransferPurposeDataV1, u64, usize)>().checked_mul(3)?)?
        .checked_add(size_of::<Option<usize>>().checked_mul(12)?)?
        .checked_add(size_of::<Option<u64>>().checked_mul(12)?)?
        .checked_add(size_of::<ResourceVector>().checked_mul(9)?)?
        .checked_add(size_of::<([
            (crate::native::journal::names::RootFixedNameRoleV1,
             crate::native::journal::names::RootFixedNameRecipeV1); 4],
            std::array::IntoIter<(crate::native::journal::names::RootFixedNameRoleV1,
                crate::native::journal::names::RootFixedNameRecipeV1), 4>,
            Option<(crate::native::journal::names::RootFixedNameRoleV1,
                crate::native::journal::names::RootFixedNameRecipeV1)>)>().checked_mul(3)?)?
        // New immediate closure environments are quoted independently of Self.
        .checked_add(size_of::<(&mut RootInitialReadyOriginalV1, &mut RootInitialReceivingOriginalV1,
            &RootJournalFinancialOriginalV1, &RootInitialOpenPreparedOriginalV1,
            &super::initial_provision::RootInitialOpenProvisionOriginalV1,
            &RootSelectedStartupBorrowV1<'_>, &RootUpperMutationGuardV1<'_>)>().checked_mul(3)?)?
        .checked_add(size_of::<(&mut RootInitialReadyOriginalV1, &RootJournalFinancialOriginalV1,
            &RootSelectedStartupBorrowV1<'_>, &RootUpperMutationGuardV1<'_>)>().checked_mul(3)?)?
        .checked_add(size_of::<(&RootInitialReadyOriginalV1, &RootInitialOpenPreparedOriginalV1)>().checked_mul(12)?)
}

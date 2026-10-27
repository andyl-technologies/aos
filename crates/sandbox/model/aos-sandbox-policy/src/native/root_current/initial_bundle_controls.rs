//! Measures native Ownership bundle construction and scoped-frame interfaces.
//!
//! The incoming Owned Memory donor pays the new fixed-calculator interfaces
//! before those calculators run. The later real Bundle fixed Stage pays the
//! concrete parsed frame before constructing/parsing it; typed capsule backing
//! remains in the separately derived actual typed Stage.

use std::error::Error;
use std::mem::size_of;

use aos_sandbox_broker::kernel_clock::RetainedKernelPairedClockAttemptV1;
use aos_sandbox_broker::receiving::{
    RootInitialReceivingOriginalV1, RootJournalFinancialOriginalV1,
    RootObservationErrorV1, RootSelectedStartupBorrowV1, RootUpperMutationGuardV1,
};
use aos_sandbox_model::{CanonicalAssignmentManifestV1, CanonicalCborError, DecodeLimits, RawPairedClockSample, ResourceVector};
use aos_sandbox_model::format::assignment_capture::CanonicalAssignmentDecodeCaptureV1;
use aos_sandbox_ownership_protocol::{
    OwnershipAuthorityVerifier, OwnershipClaimV1, OwnershipClaimError, OwnershipLeaseAcquisitionError,
    response_verification::{OwnershipClaimDecodeCaptureV1, OwnershipResponseVerifyCaptureV1},
};
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    HistoryErrorV1, assignment_planned::AssignmentPlannedBodyDataV1,
    ready::ReadyBundleDataV1,
};
use aos_sandbox_protocol::domain_ledger::create_storage_history::readback::HistoryPairReadbackDataV1;

use crate::native::journal::names::RootPolicyNameObservationOriginalV1;
use crate::native::startup::RootCurrentWritersPredecessorV1;
use crate::native::PolicyNativeJournalErrorV1 as NativeError;

use super::history_post::RootCurrentHistoryPostOriginalV1;
use super::initial_bundle::{
    RootInitialBundleOwnershipErrorV1 as E,
    RootInitialBundleOwnershipFrameBorrowV1 as Frame,
    RootInitialBundleOwnershipOriginalV1 as Bundle,
};
use super::initial_location::RootInitialLocationPairOriginalV1;
use super::initial_open::{
    RootInitialClockErrorV1, RootInitialOpenErrorV1, RootInitialOpenPreparedOriginalV1,
    ROOT_RECORD_BYTES,
};
use super::initial_ready::RootInitialReadyOriginalV1;
use super::initial_receiving::RootInitialStageOriginalV1;
use super::initial_source_exchange::{RootInitialSourceExchangeErrorV1, RootInitialSourceExchangeOriginalV1};
use super::initial_trust::{RootInitialTrustErrorV1, RootInitialTrustOriginalV1};
use super::owned::{RootCurrentAcceptedOriginalsV1, RootOwnedCurrentOriginalV1};
use super::writers::RootCurrentWritersOriginalV1;

type Clock = RetainedKernelPairedClockAttemptV1<RootInitialClockErrorV1>;
type Readback = HistoryPairReadbackDataV1<ROOT_RECORD_BYTES>;

pub(super) fn construction_control_bytes_v1() -> Option<usize> {
    let constructors = size_of::<Bundle>().checked_mul(2)?
        .checked_add(size_of::<RootInitialStageOriginalV1>().checked_mul(4)?)?
        .checked_add(size_of::<RootInitialLocationPairOriginalV1>().checked_mul(4)?)?
        .checked_add(size_of::<RootPolicyNameObservationOriginalV1>().checked_mul(8)?)?
        .checked_add(size_of::<Clock>().checked_mul(4)?)?;
    let suppliers = crate::bundle_ownership_data::fixed_interface_control_bytes_v1::<NativeError>()?;
    let held = RootJournalFinancialOriginalV1::receiving_stage_under_exclusion_control_bytes_v1()?
        .checked_add(RootSelectedStartupBorrowV1::service_recheck_under_exclusion_control_bytes_v1()?)?
        .checked_add(RootCurrentHistoryPostOriginalV1::construction_control_bytes_v1()?)?;
    let receiving = size_of::<(&mut RootOwnedCurrentOriginalV1<'_>,
        &mut RootInitialReceivingOriginalV1, &RootSelectedStartupBorrowV1<'_>,
        &RootUpperMutationGuardV1<'_>)>().checked_mul(6)?
        .checked_add(size_of::<(&mut Bundle, &RootInitialOpenPreparedOriginalV1,
            &RootInitialSourceExchangeOriginalV1, &RootInitialTrustOriginalV1,
            RootCurrentWritersPredecessorV1<'_, '_, '_>, &RootSelectedStartupBorrowV1<'_>,
            &RootUpperMutationGuardV1<'_>)>().checked_mul(3)?)?
        .checked_add(size_of::<(&mut Bundle, RootCurrentWritersPredecessorV1<'_, '_, '_>,
            &RootSelectedStartupBorrowV1<'_>, &RootUpperMutationGuardV1<'_>)>()
            .checked_mul(3)?)?
        .checked_add(size_of::<Result<RootCurrentWritersPredecessorV1<'_, '_, '_>,
            RootObservationErrorV1>>().checked_mul(6)?)?
        .checked_add(size_of::<Result<ResourceVector, NativeError>>().checked_mul(9)?)?
        .checked_add(size_of::<Result<ResourceVector, RootInitialSourceExchangeErrorV1>>()
            .checked_mul(3)?)?;
    let stages = stage_and_post_interfaces_v1()?;
    let captures = native_capture_interfaces_v1()?;

    constructors.checked_add(suppliers)?.checked_add(held)?.checked_add(receiving)?
        .checked_add(stages)?.checked_add(captures)?
        .checked_add(size_of::<Option<usize>>().checked_mul(18)?)
}

pub(super) fn frame_control_bytes_v1() -> Option<usize> {
    // All three actual native factory returns retain the concrete same frame.
    // This is separate from the capsule boxes allocated after typed admission.
    let construction = size_of::<Frame<'_, '_>>().checked_mul(2)?
        .checked_add(size_of::<Result<Frame<'_, '_>, E>>().checked_mul(9)?)?;
    let factories = size_of::<(&mut Bundle, &RootCurrentWritersOriginalV1,
        &RootInitialOpenPreparedOriginalV1, &RootInitialReadyOriginalV1,
        &RootInitialSourceExchangeOriginalV1, &RootInitialTrustOriginalV1,
        &RootCurrentAcceptedOriginalsV1<'_>)>().checked_mul(6)?
        .checked_add(size_of::<&mut RootOwnedCurrentOriginalV1<'_>>().checked_mul(3)?)?;
    let operations = size_of::<(&mut Frame<'_, '_>, &mut RootInitialReceivingOriginalV1,
        &RootSelectedStartupBorrowV1<'_>, &RootUpperMutationGuardV1<'_>)>()
        .checked_mul(3)?
        .checked_add(size_of::<&mut Frame<'_, '_>>().checked_mul(6)?)?
        .checked_add(size_of::<&Frame<'_, '_>>().checked_mul(3)?)?
        .checked_add(size_of::<(&Frame<'_, '_>, &CanonicalAssignmentManifestV1,
            &OwnershipClaimV1)>().checked_mul(3)?)?;
    let capsule_arguments = size_of::<(&mut CanonicalAssignmentDecodeCaptureV1, &[u8], DecodeLimits)>()
        .checked_mul(3)?
        .checked_add(size_of::<(&mut OwnershipClaimDecodeCaptureV1, &[u8])>().checked_mul(3)?)?
        .checked_add(size_of::<(&OwnershipAuthorityVerifier, &OwnershipClaimV1,
            &[u8], &[u8], &[u8], &[u8], &RawPairedClockSample,
            &mut OwnershipResponseVerifyCaptureV1)>().checked_mul(3)?)?;
    let results = size_of::<Result<(), E>>().checked_mul(12)?
        .checked_add(size_of::<Result<(), HistoryErrorV1>>().checked_mul(6)?)?
        .checked_add(size_of::<Result<(), CanonicalCborError>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<(), OwnershipClaimError>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<(), OwnershipLeaseAcquisitionError>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<&OwnershipAuthorityVerifier, RootInitialTrustErrorV1>>()
            .checked_mul(3)?)?
        .checked_add(size_of::<Result<(), RootObservationErrorV1>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<ReadyBundleDataV1<'_>, HistoryErrorV1>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<AssignmentPlannedBodyDataV1<'_>, HistoryErrorV1>>()
            .checked_mul(3)?)?
        .checked_add(size_of::<Option<&(dyn Error + 'static)>>().checked_mul(3)?)?;
    let local_views = size_of::<ReadyBundleDataV1<'_>>().checked_mul(6)?
        .checked_add(size_of::<AssignmentPlannedBodyDataV1<'_>>().checked_mul(6)?)?
        .checked_add(size_of::<&CanonicalAssignmentManifestV1>().checked_mul(3)?)?
        .checked_add(size_of::<&OwnershipClaimV1>().checked_mul(3)?)?
        .checked_add(size_of::<&OwnershipAuthorityVerifier>().checked_mul(3)?)?;

    construction.checked_add(factories)?.checked_add(operations)?
        .checked_add(capsule_arguments)?.checked_add(results)?.checked_add(local_views)?
        .checked_add(size_of::<Option<usize>>().checked_mul(3)?)
}

fn stage_and_post_interfaces_v1() -> Option<usize> {
    let posts = size_of::<(&mut Bundle, &RootCurrentWritersOriginalV1,
        &RootInitialOpenPreparedOriginalV1)>().checked_mul(3)?
        .checked_add(size_of::<(&mut Bundle, &RootCurrentAcceptedOriginalsV1<'_>,
            &RootInitialOpenPreparedOriginalV1, &RootInitialSourceExchangeOriginalV1)>()
            .checked_mul(3)?)?
        .checked_add(size_of::<(&RootInitialOpenPreparedOriginalV1,
            &RootInitialSourceExchangeOriginalV1,
            &Option<Result<RawPairedClockSample, RootInitialClockErrorV1>>)>()
            .checked_mul(6)?)?
        .checked_add(size_of::<&mut RootOwnedCurrentOriginalV1<'_>>().checked_mul(9)?)?
        .checked_add(size_of::<&RootOwnedCurrentOriginalV1<'_>>().checked_mul(9)?)?
        .checked_add(size_of::<&Bundle>().checked_mul(15)?)?
        .checked_add(size_of::<&mut Bundle>().checked_mul(9)?)?;
    let returns = size_of::<Result<(), E>>().checked_mul(18)?
        .checked_add(size_of::<Result<(), RootInitialOpenErrorV1>>().checked_mul(12)?)?
        .checked_add(size_of::<Result<(), RootObservationErrorV1>>().checked_mul(9)?)?
        .checked_add(size_of::<Result<(), ()>>().checked_mul(6)?)?
        .checked_add(size_of::<Result<Readback, RootInitialOpenErrorV1>>().checked_mul(6)?)?
        .checked_add(size_of::<Result<RawPairedClockSample, RootInitialClockErrorV1>>()
            .checked_mul(6)?)?
        .checked_add(size_of::<Result<&CanonicalAssignmentManifestV1, E>>().checked_mul(6)?)?
        .checked_add(size_of::<Result<&OwnershipResponseVerifyCaptureV1, E>>().checked_mul(6)?)?
        .checked_add(size_of::<Option<&(dyn Error + 'static)>>().checked_mul(102)?)?;
    let selected_order = size_of::<&RootInitialLocationPairOriginalV1>().checked_mul(12)?
        .checked_add(size_of::<Option<&(dyn Error + 'static)>>().checked_mul(12)?)?;

    posts.checked_add(returns)?.checked_add(selected_order)
}

fn native_capture_interfaces_v1() -> Option<usize> {
    let fixed = size_of::<(&mut Bundle, &mut RootInitialReceivingOriginalV1,
        &RootJournalFinancialOriginalV1, &RootInitialOpenPreparedOriginalV1,
        &RootInitialSourceExchangeOriginalV1, &RootInitialTrustOriginalV1,
        &RootSelectedStartupBorrowV1<'_>, &RootUpperMutationGuardV1<'_>)>()
        .checked_mul(3)?;
    let typed = size_of::<(&mut Frame<'_, '_>, &mut RootInitialReceivingOriginalV1,
        &RootJournalFinancialOriginalV1, &RootSelectedStartupBorrowV1<'_>,
        &RootUpperMutationGuardV1<'_>)>().checked_mul(3)?;
    let geometry = size_of::<(&RootInitialTrustOriginalV1, &ReadyBundleDataV1<'_>,
        &AssignmentPlannedBodyDataV1<'_>)>().checked_mul(3)?;
    let selectors = size_of::<&Bundle>().checked_mul(90)?
        .checked_add(size_of::<&RootJournalFinancialOriginalV1>().checked_mul(3)?)?
        .checked_add(size_of::<&ResourceVector>().checked_mul(6)?)?
        .checked_add(size_of::<&usize>().checked_mul(12)?)?;

    fixed.checked_add(typed)?.checked_add(geometry)?.checked_add(selectors)
}

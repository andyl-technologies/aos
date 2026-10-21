//! Measures the new native trust interfaces before their actual construction.
//!
//! The incoming owned-Current constructor consumes these Memory-only controls.
//! The later genuine fixed Stage separately pays the boxed trust owner, native
//! credentials, four location observations and retained clock. The typed Stage
//! separately pays actual captured-byte cloning and decoder backing.

use std::error::Error;
use std::mem::size_of;

use aos_sandbox_broker::kernel_clock::RetainedKernelPairedClockAttemptV1;
use aos_sandbox_broker::receiving::{
    RootInitialReceivingOriginalV1, RootJournalFinancialOriginalV1,
    RootObservationErrorV1, RootSelectedStartupBorrowV1, RootUpperMutationGuardV1,
};
use aos_sandbox_broker::systemd_credentials::RootCurrentOwnershipCredentialCustodyV1;
use aos_sandbox_model::{DecodeLimits, RawPairedClockSample, ResourceVector};
use aos_sandbox_ownership_protocol::OwnershipAuthorityVerifier;
use aos_sandbox_ownership_protocol::trusted_policy::{
    OwnershipTrustConfigurationCaptureV1, OwnershipTrustConfigurationClosedV1,
};
use aos_sandbox_protocol::domain_ledger::create_storage_history::readback::HistoryPairReadbackDataV1;

use crate::native::journal::{RootPolicyJournalV1,
    names::RootPolicyNameObservationOriginalV1};
use crate::native::startup::RootCurrentWritersPredecessorV1;
use crate::native::target::RootPolicyTargetOriginalV1;
use crate::native::PolicyNativeJournalErrorV1 as NativeError;

use super::history_post::RootCurrentHistoryPostOriginalV1;
use super::initial_location::RootInitialLocationPairOriginalV1;
use super::initial_open::{
    RootInitialClockErrorV1, RootInitialOpenErrorV1,
    RootInitialOpenPreparedOriginalV1, ROOT_RECORD_BYTES,
};
use super::initial_receiving::RootInitialStageOriginalV1;
use super::initial_trust::{RootInitialTrustErrorV1 as E, RootInitialTrustOriginalV1 as Trust};
use super::owned::{RootCurrentAcceptedOriginalsV1, RootOwnedCurrentOriginalV1};
use super::writers::RootCurrentWritersOriginalV1;

type Readback = HistoryPairReadbackDataV1<ROOT_RECORD_BYTES>;
type Clock = RetainedKernelPairedClockAttemptV1<RootInitialClockErrorV1>;

pub(super) fn construction_control_bytes_v1() -> Option<usize> {
    let constructors = constructor_interfaces_v1()?;
    let arguments = argument_interfaces_v1()?;
    let results = result_interfaces_v1()?;
    let captures = capture_interfaces_v1()?;
    let queries = query_interfaces_v1()?;
    let delegates = RootJournalFinancialOriginalV1::receiving_stage_under_exclusion_control_bytes_v1()?
        .checked_add(RootSelectedStartupBorrowV1::service_recheck_under_exclusion_control_bytes_v1()?)?
        .checked_add(RootCurrentHistoryPostOriginalV1::construction_control_bytes_v1()?)?;

    constructors.checked_add(arguments)?
        .checked_add(results)?
        .checked_add(captures)?
        .checked_add(queries)?
        .checked_add(delegates)?
        // Six private scalar supplier returns each keep their three Result-like
        // Option planes; they are separate from the interfaces they measure.
        .checked_add(size_of::<Option<usize>>().checked_mul(18)?)
}

fn constructor_interfaces_v1() -> Option<usize> {
    // The fixed demand owns Trust's actual resident/return planes. These are
    // distinct nested constructors, including both location pairs and all four
    // concrete native name originals; none substitutes for native backing.
    size_of::<RootInitialStageOriginalV1>().checked_mul(4)?
        .checked_add(size_of::<RootInitialLocationPairOriginalV1>().checked_mul(4)?)?
        .checked_add(size_of::<RootPolicyNameObservationOriginalV1>().checked_mul(8)?)?
        .checked_add(size_of::<RootCurrentOwnershipCredentialCustodyV1>().checked_mul(2)?)?
        .checked_add(size_of::<OwnershipTrustConfigurationCaptureV1>().checked_mul(2)?)?
        .checked_add(size_of::<Clock>().checked_mul(2)?)?
        .checked_add(size_of::<Box<Trust>>().checked_mul(2)?)?
        .checked_add(size_of::<Option<Box<Trust>>>().checked_mul(2)?)
}

fn argument_interfaces_v1() -> Option<usize> {
    let upper = size_of::<(&mut RootOwnedCurrentOriginalV1<'_>,
        &mut RootInitialReceivingOriginalV1, &RootSelectedStartupBorrowV1<'_>,
        &RootUpperMutationGuardV1<'_>)>().checked_mul(12)?
        .checked_add(size_of::<&mut RootOwnedCurrentOriginalV1<'_>>().checked_mul(24)?)?
        .checked_add(size_of::<&RootOwnedCurrentOriginalV1<'_>>().checked_mul(6)?)?;
    let receiving = size_of::<(&mut Trust, &RootInitialStageOriginalV1,
        RootCurrentWritersPredecessorV1<'_, '_, '_>, &RootSelectedStartupBorrowV1<'_>)>()
        .checked_mul(3)?
        .checked_add(size_of::<(&mut Trust, &RootInitialStageOriginalV1,
            RootCurrentWritersPredecessorV1<'_, '_, '_>, &RootSelectedStartupBorrowV1<'_>,
            &RootUpperMutationGuardV1<'_>)>().checked_mul(3)?)?
        .checked_add(size_of::<(&mut Trust, RootCurrentWritersPredecessorV1<'_, '_, '_>,
            &RootSelectedStartupBorrowV1<'_>, &RootUpperMutationGuardV1<'_>)>()
            .checked_mul(3)?)?;
    let observations = size_of::<(&mut Trust, &RootCurrentWritersOriginalV1,
        &RootInitialOpenPreparedOriginalV1)>().checked_mul(6)?
        .checked_add(size_of::<(&mut Trust, &RootCurrentAcceptedOriginalsV1<'_>,
            &RootInitialOpenPreparedOriginalV1)>().checked_mul(3)?)?
        .checked_add(size_of::<(&mut RootInitialLocationPairOriginalV1,
            &RootPolicyJournalV1, &RootPolicyTargetOriginalV1)>().checked_mul(6)?)?
        .checked_add(size_of::<&mut Trust>().checked_mul(18)?)?
        .checked_add(size_of::<&Trust>().checked_mul(15)?)?
        .checked_add(size_of::<&RootInitialLocationPairOriginalV1>().checked_mul(12)?)?;
    let decoder = size_of::<(Vec<u8>, [u8; 32], DecodeLimits,
        &mut OwnershipTrustConfigurationCaptureV1)>().checked_mul(3)?
        .checked_add(size_of::<(&[u8], &[u8])>().checked_mul(6)?)?
        .checked_add(size_of::<&[u8]>().checked_mul(6)?)?;

    upper.checked_add(receiving)?.checked_add(observations)?.checked_add(decoder)
}

fn result_interfaces_v1() -> Option<usize> {
    size_of::<Result<(), E>>().checked_mul(36)?
        .checked_add(size_of::<Result<(), RootObservationErrorV1>>().checked_mul(21)?)?
        .checked_add(size_of::<Result<(), RootInitialOpenErrorV1>>().checked_mul(24)?)?
        .checked_add(size_of::<Result<(), ()>>().checked_mul(12)?)?
        .checked_add(size_of::<Result<(), OwnershipTrustConfigurationClosedV1>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<[u8; 32], RootInitialOpenErrorV1>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<ResourceVector, NativeError>>().checked_mul(15)?)?
        .checked_add(size_of::<Result<ResourceVector, RootInitialOpenErrorV1>>().checked_mul(9)?)?
        .checked_add(size_of::<Result<ResourceVector, E>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<Readback, RootInitialOpenErrorV1>>().checked_mul(6)?)?
        .checked_add(size_of::<Result<RawPairedClockSample, RootInitialClockErrorV1>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<RootCurrentWritersPredecessorV1<'_, '_, '_>,
            RootObservationErrorV1>>().checked_mul(12)?)?
        .checked_add(size_of::<Result<(&RootPolicyJournalV1, &RootPolicyTargetOriginalV1),
            RootObservationErrorV1>>().checked_mul(6)?)?
        .checked_add(size_of::<Result<&OwnershipAuthorityVerifier, E>>().checked_mul(6)?)
}

fn capture_interfaces_v1() -> Option<usize> {
    // These are source-reached closure environments, separately from their
    // callable argument and returned Result planes. Counts include construction,
    // call and retained diagnostic traversal; no optimizer credit is taken.
    let fixed = size_of::<(&mut RootOwnedCurrentOriginalV1<'_>,
        &mut RootInitialReceivingOriginalV1, &RootJournalFinancialOriginalV1,
        &RootSelectedStartupBorrowV1<'_>, &RootUpperMutationGuardV1<'_>)>()
        .checked_mul(3)?;
    let capture = size_of::<(&mut Trust, &RootCurrentWritersOriginalV1,
        &RootInitialOpenPreparedOriginalV1)>().checked_mul(3)?;
    let typed = size_of::<(&mut Trust, &RootInitialStageOriginalV1,
        &RootJournalFinancialOriginalV1, &RootSelectedStartupBorrowV1<'_>,
        &RootUpperMutationGuardV1<'_>)>().checked_mul(3)?;
    let cutoff = size_of::<(&Trust, &RootInitialOpenPreparedOriginalV1)>().checked_mul(3)?;
    let diagnostics = size_of::<&Trust>().checked_mul(57)?
        .checked_add(size_of::<&RootInitialLocationPairOriginalV1>().checked_mul(9)?)?;
    let affinity = size_of::<&RootJournalFinancialOriginalV1>().checked_mul(6)?;
    let pure = size_of::<ResourceVector>().checked_mul(6)?
        .checked_add(size_of::<&ResourceVector>().checked_mul(6)?)?
        .checked_add(size_of::<&u64>().checked_mul(3)?)?
        .checked_add(size_of::<usize>().checked_mul(6)?)?
        .checked_add(size_of::<Option<usize>>().checked_mul(6)?)?;

    fixed.checked_add(capture)?.checked_add(typed)?.checked_add(cutoff)?
        .checked_add(diagnostics)?.checked_add(affinity)?.checked_add(pure)
}

fn query_interfaces_v1() -> Option<usize> {
    size_of::<Result<&(), E>>().checked_mul(30)?
        .checked_add(size_of::<Result<&Readback, E>>().checked_mul(6)?)?
        .checked_add(size_of::<Result<&[u8; 32], E>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<&RawPairedClockSample, E>>().checked_mul(3)?)?
        .checked_add(size_of::<Option<(&[u8], &[u8])>>().checked_mul(6)?)?
        .checked_add(size_of::<Option<&OwnershipAuthorityVerifier>>().checked_mul(3)?)?
        .checked_add(size_of::<Option<&(dyn Error + 'static)>>().checked_mul(69)?)?
        .checked_add(size_of::<Option<&Box<Trust>>>().checked_mul(6)?)?
        .checked_add(size_of::<Option<&mut Box<Trust>>>().checked_mul(24)?)?
        .checked_add(size_of::<bool>().checked_mul(15)?)
}

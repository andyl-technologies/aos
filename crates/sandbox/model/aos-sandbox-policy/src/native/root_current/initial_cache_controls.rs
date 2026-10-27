//! Measures Initial Cache constructors and concrete scoped-frame interfaces.
//!
//! Incoming Owned Memory pays the added fixed-calculator and shared deadline
//! controls before those calls. The real Cache fixed Stage separately pays its
//! parsed frame and decoder/native backing before constructing or observing it.
//! These source-derived rosters remain subject to quantity/overlap qualification.

use std::error::Error;
use std::mem::size_of;
use std::os::unix::net::UnixStream;

use aos_sandbox_broker::bounded_stream_io::{DeadlineStreamDirectionV1, FixedDeadlineStreamIoV1};
use aos_sandbox_broker::cache_current_signer_exchange::{
    CacheCurrentSignerExchangeClosedV1, CacheCurrentSignerExchangeOriginalsV1,
};
use aos_sandbox_broker::kernel_clock::RetainedKernelPairedClockAttemptV1;
use aos_sandbox_broker::receiving::{
    RootInitialReceivingOriginalV1, RootJournalFinancialOriginalV1,
    RootObservationErrorV1, RootSelectedControllerPeerOriginalV1,
    RootSelectedStartupBorrowV1, RootUpperMutationGuardV1,
};
use aos_sandbox_model::{RawPairedClockSample, ResourceVector};
use aos_sandbox_linux::unix_stream::{
    RetainedSubjectStreamReadV1, SubjectStreamReadErrorV1, SubjectStreamReceiveGeometryV1,
};
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    HistoryErrorV1,
    cache_held::{CACHE_HELD_RECEIPT_BYTES_V1, CacheHeldReceiptDataV1,
        current_proof::{CacheCurrentProofBodyDataV1, CacheCurrentProofDataErrorV1,
            CacheCurrentProofVerifyCaptureV1}},
    current_proofs::{CurrentProofsChallengeDataV1, CurrentProofsDataV1},
    ready::{ReadyBundleDataV1, InputsReadyNativeReceiptDataV1},
    root_open::RootHelloDataV1,
    transport::TransferIndexV1,
};

use crate::native::startup::RootCurrentWritersPredecessorV1;
use crate::native::PolicyNativeJournalErrorV1 as NativeError;

use super::history_post::RootCurrentHistoryPostOriginalV1;
use super::initial_bundle::RootInitialBundleOwnershipOriginalV1;
use super::initial_cache::{RootInitialCacheProofErrorV1 as E,
    RootInitialCacheProofFrameBorrowV1 as Frame, RootInitialCacheProofOriginalV1 as Cache};
use super::initial_location::RootInitialLocationPairOriginalV1;
use super::initial_open::{RootInitialClockErrorV1, RootInitialOpenErrorV1,
    RootInitialOpenPreparedOriginalV1, ROOT_RECORD_BYTES};
use super::initial_pins::RootInitialPinsOriginalV1;
use super::initial_ready::RootInitialReadyOriginalV1;
use super::initial_receiving::RootInitialStageOriginalV1;
use super::initial_source_exchange::{RootInitialSourceExchangeErrorV1,
    RootInitialSourceExchangeOriginalV1};
use super::initial_subject::{RootInitialSubjectFrameBorrowV1, RootInitialSubjectOriginalV1};
use super::owned::{RootCurrentAcceptedOriginalsV1, RootOwnedCurrentOriginalV1};
use super::writers::RootCurrentWritersOriginalV1;

type Clock = RetainedKernelPairedClockAttemptV1<RootInitialClockErrorV1>;
type Prepared<'a, 'b> = (ReadyBundleDataV1<'a>, &'a [u8], RootHelloDataV1<'b>, TransferIndexV1);

pub(super) fn construction_control_bytes_v1() -> Option<usize> {
    // This constant is paid before the later framing quote helper is invoked.
    let framing = crate::cache_current_data::FRAMING_INTERFACE_CONTROL_BYTES_V1;
    // Exactly the fixed precheck and native body read this actual peer profile.
    let identity = RootSelectedControllerPeerOriginalV1::current_cache_signer_identity_control_bytes_v1()?
        .checked_mul(2)?;
    let constructors = size_of::<Cache>().checked_mul(2)?
        .checked_add(size_of::<RootInitialStageOriginalV1>().checked_mul(2)?)?
        .checked_add(size_of::<RootInitialLocationPairOriginalV1>().checked_mul(4)?)?
        .checked_add(size_of::<Clock>().checked_mul(4)?)?
        .checked_add(size_of::<CacheCurrentSignerExchangeOriginalsV1>().checked_mul(2)?)?
        .checked_add(size_of::<CacheCurrentProofVerifyCaptureV1>().checked_mul(2)?)?
        .checked_add(size_of::<FixedDeadlineStreamIoV1<248>>().checked_mul(2)?)?
        .checked_add(size_of::<RootInitialSubjectOriginalV1>().checked_mul(2)?)?
        .checked_add(size_of::<RetainedSubjectStreamReadV1>().checked_mul(2)?)?;
    let stages = RootJournalFinancialOriginalV1::receiving_stage_under_exclusion_control_bytes_v1()?
        .checked_add(RootSelectedStartupBorrowV1::service_recheck_under_exclusion_control_bytes_v1()?)?
        .checked_add(RootCurrentHistoryPostOriginalV1::construction_control_bytes_v1()?)?;
    let fixed_arguments = size_of::<(&mut RootOwnedCurrentOriginalV1<'_>,
        &mut RootInitialReceivingOriginalV1, &RootSelectedStartupBorrowV1<'_>,
        &RootUpperMutationGuardV1<'_>)>().checked_mul(6)?
        .checked_add(size_of::<(&mut Cache, &RootInitialOpenPreparedOriginalV1,
            &RootInitialBundleOwnershipOriginalV1, &RootInitialPinsOriginalV1,
            RootCurrentWritersPredecessorV1<'_, '_, '_>, &RootSelectedStartupBorrowV1<'_>,
            &RootUpperMutationGuardV1<'_>)>().checked_mul(3)?)?
        .checked_add(size_of::<(&mut Cache, RootCurrentWritersPredecessorV1<'_, '_, '_>,
            &RootSelectedStartupBorrowV1<'_>, &RootUpperMutationGuardV1<'_>)>().checked_mul(3)?)?;
    // The fixed immediate closure retains these actual locals/references; its
    // FnOnce environment is separate from the outer method argument tuple.
    let fixed_capture = size_of::<(&mut Cache, &mut RootInitialReceivingOriginalV1,
        &RootJournalFinancialOriginalV1, &RootInitialOpenPreparedOriginalV1,
        &RootInitialBundleOwnershipOriginalV1, &RootInitialPinsOriginalV1,
        &RootSelectedStartupBorrowV1<'_>, &RootUpperMutationGuardV1<'_>)>().checked_mul(3)?;
    let returns = size_of::<Result<RootCurrentWritersPredecessorV1<'_, '_, '_>,
        RootObservationErrorV1>>().checked_mul(6)?
        .checked_add(size_of::<Result<ResourceVector, NativeError>>().checked_mul(12)?)?
        .checked_add(size_of::<Result<(), RootObservationErrorV1>>().checked_mul(12)?)?
        .checked_add(size_of::<Result<(), ()>>().checked_mul(6)?)?
        .checked_add(size_of::<Result<(u32, u32, u32), RootObservationErrorV1>>().checked_mul(6)?)?;
    let calculators = size_of::<(usize, usize)>().checked_mul(21)?
        .checked_add(size_of::<Option<usize>>().checked_mul(54)?)?
        .checked_add(size_of::<ResourceVector>().checked_mul(18)?)?
        .checked_add(size_of::<(&usize, &usize, &usize)>().checked_mul(9)?)?
        .checked_add(size_of::<(&ResourceVector, &ResourceVector)>().checked_mul(12)?)?;

    framing.checked_add(identity)?.checked_add(constructors)?.checked_add(stages)?
        .checked_add(fixed_arguments)?.checked_add(fixed_capture)?.checked_add(returns)?
        .checked_add(calculators)?.checked_add(shared_deadline_control_bytes_v1()?)?
        .checked_add(post_and_query_control_bytes_v1()?)
}

pub(super) fn frame_control_bytes_v1() -> Option<usize> {
    let factory = size_of::<Frame<'_, '_>>().checked_mul(2)?
        .checked_add(size_of::<Result<Frame<'_, '_>, E>>().checked_mul(6)?)?
        .checked_add(size_of::<Prepared<'_, '_>>().checked_mul(2)?)?
        .checked_add(size_of::<Result<Prepared<'_, '_>, E>>().checked_mul(3)?)?;
    let arguments = size_of::<(&mut Cache, &RootCurrentWritersOriginalV1,
        &RootInitialOpenPreparedOriginalV1, &RootInitialReadyOriginalV1,
        &RootInitialSourceExchangeOriginalV1, &RootInitialPinsOriginalV1,
        &RootInitialBundleOwnershipOriginalV1, &mut RootCurrentAcceptedOriginalsV1<'_>,
        &UnixStream)>().checked_mul(3)?
        .checked_add(size_of::<(&mut Cache, &RootCurrentWritersOriginalV1,
            &RootInitialOpenPreparedOriginalV1, &RootInitialReadyOriginalV1,
            &RootInitialSourceExchangeOriginalV1, &RootInitialBundleOwnershipOriginalV1,
            &RootCurrentAcceptedOriginalsV1<'_>, &UnixStream)>().checked_mul(3)?)?
        .checked_add(size_of::<&mut RootOwnedCurrentOriginalV1<'_>>().checked_mul(3)?)?
        .checked_add(size_of::<&mut Frame<'_, '_>>().checked_mul(12)?)?
        .checked_add(size_of::<&Frame<'_, '_>>().checked_mul(3)?)?;
    let codecs = size_of::<ReadyBundleDataV1<'_>>().checked_mul(3)?
        .checked_add(size_of::<RootHelloDataV1<'_>>().checked_mul(6)?)?
        .checked_add(size_of::<CurrentProofsDataV1<'_>>().checked_mul(6)?)?
        .checked_add(size_of::<CurrentProofsChallengeDataV1>().checked_mul(3)?)?
        .checked_add(size_of::<CacheHeldReceiptDataV1<'_>>().checked_mul(3)?)?
        .checked_add(size_of::<(&[u8], RootHelloDataV1<'_>, TransferIndexV1)>().checked_mul(6)?)?
        .checked_add(size_of::<(&RootInitialReadyOriginalV1,
            &RootInitialOpenPreparedOriginalV1, &mut [u8; 612])>().checked_mul(3)?)?
        .checked_add(size_of::<(&[u8], aos_sandbox_protocol::domain_ledger::create_storage_history::transport::OpenQueryV1)>()
            .checked_mul(6)?)?;
    let native = size_of::<(&mut CacheCurrentSignerExchangeOriginalsV1,
        &[u8; 612], &[u8; CACHE_HELD_RECEIPT_BYTES_V1], u32, u32, u32, u64)>().checked_mul(3)?
        .checked_add(size_of::<(&mut FixedDeadlineStreamIoV1<248>, &mut &UnixStream,
            &mut [u8; 248], u64, DeadlineStreamDirectionV1)>().checked_mul(3)?)?
        .checked_add(size_of::<(&[u8], &ed25519_dalek::VerifyingKey, u64,
            &mut CacheCurrentProofVerifyCaptureV1)>().checked_mul(3)?)?
        .checked_add(size_of::<&mut [u8; 248]>().checked_mul(3)?)?;
    let returns = size_of::<Result<(), E>>().checked_mul(24)?
        .checked_add(size_of::<Result<(), HistoryErrorV1>>().checked_mul(30)?)?
        .checked_add(size_of::<Result<ReadyBundleDataV1<'_>, HistoryErrorV1>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<RootHelloDataV1<'_>, HistoryErrorV1>>().checked_mul(6)?)?
        .checked_add(size_of::<Result<TransferIndexV1, RootInitialOpenErrorV1>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<(), CacheCurrentSignerExchangeClosedV1>>().checked_mul(6)?)?
        .checked_add(size_of::<Result<&[u8; 1064], CacheCurrentSignerExchangeClosedV1>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<(), CacheCurrentProofDataErrorV1>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<(), SubjectStreamReadErrorV1>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<RootInitialSubjectFrameBorrowV1<'_, '_>, RootInitialOpenErrorV1>>()
            .checked_mul(6)?)?;
    // The two immediate comparison closures retain concrete source views;
    // neither supplied DATA nor their return may construct a native owner.
    let captures = size_of::<(&Cache, RootHelloDataV1<'_>, TransferIndexV1, &[u8])>().checked_mul(3)?
        .checked_add(size_of::<(&Cache, RootHelloDataV1<'_>, TransferIndexV1,
            &[u8; CACHE_HELD_RECEIPT_BYTES_V1], &[u8; 1064])>().checked_mul(3)?)?;

    factory.checked_add(arguments)?.checked_add(codecs)?.checked_add(native)?
        .checked_add(returns)?.checked_add(captures)?
        .checked_add(size_of::<Option<&(dyn Error + 'static)>>().checked_mul(6)?)
}

fn shared_deadline_control_bytes_v1() -> Option<usize> {
    // Ready's frame uses the same original Open cutoff. Only the private Cache
    // factory binds the genuine Source minimum; no public scalar setter exists.
    size_of::<u64>().checked_mul(6)?
        .checked_add(size_of::<(&mut RootInitialSubjectOriginalV1,
            &mut RetainedSubjectStreamReadV1, &mut RootCurrentAcceptedOriginalsV1<'_>,
            &RootInitialOpenPreparedOriginalV1, &RootInitialSourceExchangeOriginalV1,
            SubjectStreamReceiveGeometryV1)>().checked_mul(3)?)?
        .checked_add(size_of::<Result<u64, RootInitialSourceExchangeErrorV1>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<RootInitialSubjectFrameBorrowV1<'_, '_>, RootInitialOpenErrorV1>>()
            .checked_mul(3)?)?
        .checked_add(size_of::<&RootInitialSourceExchangeOriginalV1>().checked_mul(3)?)
}

fn post_and_query_control_bytes_v1() -> Option<usize> {
    let arguments = size_of::<(&mut Cache, &RootCurrentWritersOriginalV1,
        &RootInitialOpenPreparedOriginalV1)>().checked_mul(3)?
        .checked_add(size_of::<(&mut Cache, &RootCurrentAcceptedOriginalsV1<'_>,
            &RootInitialOpenPreparedOriginalV1, &RootInitialSourceExchangeOriginalV1)>()
            .checked_mul(3)?)?
        .checked_add(size_of::<(&RootInitialOpenPreparedOriginalV1,
            &RootInitialSourceExchangeOriginalV1,
            &Option<Result<RawPairedClockSample, RootInitialClockErrorV1>>)>().checked_mul(6)?)?
        .checked_add(size_of::<&mut RootOwnedCurrentOriginalV1<'_>>().checked_mul(9)?)?
        .checked_add(size_of::<&RootOwnedCurrentOriginalV1<'_>>().checked_mul(15)?)?
        .checked_add(size_of::<&Cache>().checked_mul(108)?)?
        .checked_add(size_of::<&mut Cache>().checked_mul(9)?)?;
    let returns = size_of::<Result<(), E>>().checked_mul(30)?
        .checked_add(size_of::<Result<(), RootInitialOpenErrorV1>>().checked_mul(18)?)?
        .checked_add(size_of::<Result<RawPairedClockSample, RootInitialClockErrorV1>>().checked_mul(6)?)?
        .checked_add(size_of::<Result<&[u8], E>>().checked_mul(6)?)?
        .checked_add(size_of::<Result<&CacheCurrentProofBodyDataV1, E>>().checked_mul(6)?)?
        .checked_add(size_of::<Result<InputsReadyNativeReceiptDataV1<'_>, E>>().checked_mul(6)?)?
        .checked_add(size_of::<Option<&(dyn Error + 'static)>>().checked_mul(132)?)?
        .checked_add(size_of::<Result<&[u8; ROOT_RECORD_BYTES], RootInitialOpenErrorV1>>()
            .checked_mul(9)?)?;

    arguments.checked_add(returns)
}

//! Prices the actual native readonly opening, semantic and model owners.
//!
//! The common scalar recipe retains its full pending/frame/checkpoint and
//! all-family semantic bounds. Concrete native types replace the old Domain
//! owners; writable extent DATA cannot authenticate a captured prefix, select a
//! Current receiving context or admit growth. The enclosing real R owns that
//! association and every independent native/service/model post.

use std::{fs, io, mem::size_of};

use aos_sandbox_broker::canonical_journal::{
    CanonicalJournalMechanicalErrorV1, CanonicalOrdinaryReadonlyOpeningV1,
    CanonicalRereadWireWorkDataV1, ordinary_reread_wire_work_data_v1,
};
use aos_sandbox_broker::canonical_journal::coordinator::indexed_replay::
    CanonicalIndexedReplayErrorV1;
use aos_sandbox_model::{RecordNamespace, ResourceDimension as D, ResourceVector};
use aos_sandbox_journal::framing::{Frame, FrameError, HEADER_BYTES};
use aos_sandbox_journal::geometry::NativeGeometryBounds;
use aos_sandbox_journal::protected_storage::ReadOnlyJournalNameWitness;
use aos_sandbox_journal::transaction::NativePendingTransaction;
use aos_sandbox_ledger_replay::cold::{ColdReplayClosedV1, ColdReplayRemainderDataV1};
use aos_sandbox_ledger_replay::replay::challenge::SourceOriginalChallengeCheckpointV5;
use aos_sandbox_ledger_replay::replay::source_original::cache::SourceOriginalReplayDataV5;
use aos_sandbox_protocol::domain_ledger::transaction::{JournalLimits, JournalRecord};

use super::audit::RootControllerReadonlyGeometryAuditV1;
use super::completed::RootFixedCompletedReadDataV2;
use super::error::RootReadonlyErrorV1 as JournalError;
use super::model::{RootReadonlyModelInputsV1, RootReadonlyModelOriginalsV1};
use super::role_replay::RootReadonlySemanticOriginalV1;
use super::RootFixedNativeReadOriginalsV1;

// The pending tuple is the same canonical Journal record/pending representation
// used by the original native parser. The semantic enum retains its actual
// Common or Current driver; Current's outer error differs from its fixed
// canonical Source E/H/R. Completed DATA and model inputs are real alternative
// handoffs, not a fictitious successful return of the native model owner.
aos_sandbox_ledger_replay::define_protected_preopen_geometry_data_v1! {
    replay_before_control = [
        ColdReplayRemainderDataV1,
        (Vec<JournalRecord>, NativePendingTransaction),
    ],
    replay_control = RootReadonlySemanticOriginalV1::receiving_construction_bytes_v1,
    replay_after_control = [RootFixedCompletedReadDataV2, RootReadonlyModelInputsV1],
    source_checkpoint = SourceOriginalChallengeCheckpointV5,
    source_cache = SourceOriginalReplayDataV5<()>,
    native_owner = RootFixedNativeReadOriginalsV1,
    native_first = Result<(), JournalError>,
    native_before_fixed = [
        CanonicalOrdinaryReadonlyOpeningV1<JournalError>,
        RootReadonlySemanticOriginalV1,
        RootControllerReadonlyGeometryAuditV1,
        RootReadonlyModelOriginalsV1,
        RootReadonlyModelInputsV1,
        Result<RootFixedCompletedReadDataV2, RootFixedNativeReadOriginalsV1>,
        Result<(), ColdReplayClosedV1>,
        Result<(), CanonicalIndexedReplayErrorV1>,
        Result<ProtectedJournalPreopenReplayExtentV1, JournalError>,
        Option<(u64, u64)>,
        ReadOnlyJournalNameWitness,
        Frame,
        std::cell::Cell<bool>,
    ],
    native_after_fixed = [Result<fs::Metadata, io::Error>],
}

fn validate_limits(limits: JournalLimits) -> Result<(), JournalError> {
    aos_sandbox_journal::geometry::validate_native_bounds(limits.into())
        .map_err(CanonicalJournalMechanicalErrorV1::from)
        .map_err(JournalError::from)
}

fn native_release_replay_work_v1(
    physical: usize,
    limits: JournalLimits,
) -> Result<CanonicalRereadWireWorkDataV1, JournalError> {
    ordinary_reread_wire_work_data_v1(physical, limits)
        .ok_or(JournalError::LimitExceeded("original Release replay copy"))
}

// Full initial semantic rows remain distinct from CanonicalReplayExtent's key
// index. This supplement names actual native owners and never unconditionally
// allocates Source families: their same canonical E/H/R fixed backing remains
// in the real reached-state audit/admission. Common fixed/model quotes already
// include these headers; this pure bound conservatively overlaps them and
// establishes no refund, cap change or claim that the complete service fits.
pub(super) fn semantic_representation_demand_v1(
    encoded: usize,
    rows: usize,
) -> Result<ResourceVector, JournalError> {
    let semantic = aos_sandbox_ledger_replay::geometry::semantic_rows::
        semantic_representation_demand_v1(encoded, rows).map_err(JournalError::from)?;
    let controls = RootReadonlySemanticOriginalV1::receiving_construction_bytes_v1()
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(JournalError::LimitExceeded("native history observer controls"))?;
    let history = ResourceVector::ZERO.with(D::MemoryBytes, controls)
        .checked_add(RootControllerReadonlyGeometryAuditV1::fixed_demand_v1()?)
        .map_err(|_| JournalError::LimitExceeded("native history observer controls"))?;
    semantic.checked_add(history)
        .map_err(|_| JournalError::LimitExceeded("native history observer representation"))
}

/// Quotes new native preopen forwarding controls for the real fixed invoice.
///
/// The caller consumes this once before constructing/using the native opening.
/// It is separate from native/parser/model backing and from the generic Source
/// boxed-footprint helper's new Option tuple interfaces. No Metadata or FD
/// identity is created by these scalar argument/result planes.
pub(crate) fn additional_control_bytes_v1() -> Option<usize> {
    // Preopen arguments; validation's converted bounds; wire-work arguments;
    // two semantic interfaces; and both extent method self arguments.
    let arguments = size_of::<(JournalLimits, u64)>()
        .checked_mul(2)?
        .checked_add(size_of::<JournalLimits>())?
        .checked_add(size_of::<NativeGeometryBounds>().checked_mul(2)?)?
        .checked_add(size_of::<(usize, JournalLimits)>().checked_mul(2)?)?
        .checked_add(size_of::<(usize, usize)>().checked_mul(3)?)?
        .checked_add(size_of::<(ResourceVector, ResourceVector)>().checked_mul(2)?)?
        .checked_add(size_of::<&ProtectedJournalPreopenReplayExtentV1>().checked_mul(4)?)?;

    // Two extent methods, semantic projection and actual audit-fixed interface
    // retain their returned/caller vectors. Native error causes stay typed.
    let results = size_of::<Result<ProtectedJournalPreopenReplayExtentV1, JournalError>>()
        .checked_mul(2)?
        .checked_add(size_of::<Result<ResourceVector, JournalError>>().checked_mul(8)?)?
        .checked_add(size_of::<Result<ResourceVector, CanonicalJournalMechanicalErrorV1>>()
            .checked_mul(2)?)?
        .checked_add(size_of::<Result<ResourceVector, aos_sandbox_model::AccountingError>>()
            .checked_mul(4)?)?
        .checked_add(size_of::<Result<CanonicalRereadWireWorkDataV1, JournalError>>()
            .checked_mul(2)?)?
        .checked_add(size_of::<Option<CanonicalRereadWireWorkDataV1>>().checked_mul(2)?)?
        .checked_add(size_of::<Result<(), FrameError>>().checked_mul(2)?)?
        .checked_add(size_of::<Result<usize, FrameError>>().checked_mul(2)?)?
        .checked_add(size_of::<Result<usize, JournalError>>().checked_mul(8)?)?
        .checked_add(size_of::<Result<u64, JournalError>>().checked_mul(4)?)?
        .checked_add(size_of::<Result<usize, std::num::TryFromIntError>>().checked_mul(6)?)?
        .checked_add(size_of::<Result<(), CanonicalJournalMechanicalErrorV1>>()
            .checked_mul(2)?)?
        .checked_add(size_of::<Result<(), JournalError>>().checked_mul(2)?)?
        .checked_add(size_of::<Result<u64, std::num::TryFromIntError>>().checked_mul(6)?)?
        .checked_add(size_of::<Option<u64>>().checked_mul(2)?)?
        // Supplied ok_or errors and the two checked-add error projections.
        .checked_add(size_of::<JournalError>().checked_mul(4)?)?
        // Two enum quote calls and this supplier return/pass an Option.
        .checked_add(size_of::<Option<usize>>().checked_mul(6)?)?;
    arguments.checked_add(results)
}

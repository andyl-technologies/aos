//! Binds full protected preopen geometry to the actual Current native writers.
//!
//! Authority and Policy use the same retained writable opening and Cold recipe.
//! Each genuine receiving stage captures its own physical prefix, constructs
//! this comparison DATA, and admits the native, full semantic and index terms
//! before its parser. These scalar functions neither adopt storage nor select
//! an ordinary fallback, receiving original or successful Current role.

use std::{fs, io, mem::size_of};

use aos_sandbox_broker::canonical_journal::{
    CanonicalJournalMechanicalErrorV1 as JournalError, CanonicalReplayExtentDataV1,
    CanonicalReplayOriginalV1, CanonicalRereadWireWorkDataV1, CanonicalWriterOpeningOriginalsV1,
    ordinary_reread_wire_work_data_v1,
};
use aos_sandbox_broker::canonical_journal::coordinator::indexed_replay::{
    CanonicalIndexedReplayErrorV1, CanonicalReplayIndexOriginalsV1,
};
use aos_sandbox_broker::receiving::{
    RootCoordinatorWriterV1, RootWriterErrorV1, RootWriterOpeningOriginalV1, RootWriterReplayV1,
};
use aos_sandbox_model::{RecordNamespace, ResourceDimension as D, ResourceVector};
use aos_sandbox_journal::framing::{Frame, FrameError, HEADER_BYTES};
use aos_sandbox_journal::geometry::NativeGeometryBounds;
use aos_sandbox_ledger_replay::cold::{ColdReplayOriginalV1, ColdReplayRemainderDataV1};
use aos_sandbox_ledger_replay::replay::challenge::SourceOriginalChallengeCheckpointV5;
use aos_sandbox_ledger_replay::replay::source_original::cache::SourceOriginalReplayDataV5;
use aos_sandbox_protocol::domain_ledger::transaction::{JournalLimits, JournalRecord};

use crate::native::journal::{RootPolicyJournalConstructionOriginalV1, RootPolicyJournalV1};
use crate::native::target::{RootPolicyTargetConstructionOriginalV1, RootPolicyTargetOriginalV1};
use crate::native::PolicyNativeJournalErrorV1;

// Each binding lists only owners reached by that actual writer. The sole
// lower macro retains all scalar algorithms; this local macro shares only the
// concrete native roster. Policy's extra Target is never charged to Authority.
macro_rules! define_writable_binding {
    ($module:ident, $owner:ty, [$($policy_owner:ty),* $(,)?]) => {
        mod $module {
            use super::*;

            aos_sandbox_ledger_replay::define_protected_preopen_geometry_data_v1! {
                replay_before_control = [
                    ColdReplayRemainderDataV1,
                    CanonicalReplayOriginalV1,
                ],
                replay_control = ColdReplayOriginalV1::<RootWriterErrorV1>::receiving_construction_bytes_v1,
                replay_after_control = [RootCoordinatorWriterV1<()>],
                source_checkpoint = SourceOriginalChallengeCheckpointV5,
                source_cache = SourceOriginalReplayDataV5<()>,
                native_owner = $owner,
                native_first = Result<RootWriterOpeningOriginalV1, RootWriterErrorV1>,
                native_before_fixed = [
                    RootWriterOpeningOriginalV1,
                    CanonicalWriterOpeningOriginalsV1,
                    CanonicalReplayIndexOriginalsV1,
                    ColdReplayOriginalV1<RootWriterErrorV1>,
                    RootWriterReplayV1<'_, '_>,
                    RootCoordinatorWriterV1<()>,
                    RootPolicyJournalV1,
                    Result<RootCoordinatorWriterV1<()>, RootWriterErrorV1>,
                    Option<RootPolicyJournalV1>,
                    Result<(), RootWriterErrorV1>,
                    Result<(), CanonicalIndexedReplayErrorV1>,
                    Result<CanonicalReplayExtentDataV1, aos_sandbox_broker::canonical_journal::NativeJournalDataErrorV1>,
                    Result<ProtectedJournalPreopenReplayExtentV1, JournalError>,
                    $($policy_owner,)*
                    Frame,
                ],
                native_after_fixed = [Result<fs::Metadata, io::Error>],
            }

            pub(super) fn additional_control_bytes_v1() -> Option<usize> {
                common_control_bytes_v1()?
                    .checked_add(size_of::<&ProtectedJournalPreopenReplayExtentV1>().checked_mul(4)?)?
                    .checked_add(size_of::<Result<ProtectedJournalPreopenReplayExtentV1, JournalError>>()
                        .checked_mul(3)?)?
                    // The actual nested payload enters the variant and the
                    // wrapper's returned/caller value; it is not a Target size.
                    .checked_add(size_of::<ProtectedJournalPreopenReplayExtentV1>()
                        .checked_mul(3)?)?
                    .checked_add(size_of::<Option<usize>>().checked_mul(2)?)
            }
        }
    };
}

define_writable_binding!(authority, RootPolicyJournalConstructionOriginalV1, []);
define_writable_binding!(policy, RootPolicyTargetConstructionOriginalV1, [
    RootPolicyTargetOriginalV1,
    Option<RootPolicyTargetOriginalV1>,
]);

/// Retains the full scalar extent produced for one concrete Current writer.
///
/// Both variants are comparison DATA. Their private factories receive only
/// limits and captured bytes; the actual receiving owner retains the physical
/// association and authenticates every native or role transition separately.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ProtectedJournalPreopenReplayExtentV1 {
    Authority(authority::ProtectedJournalPreopenReplayExtentV1),
    Policy(policy::ProtectedJournalPreopenReplayExtentV1),
}

/// Computes the actual Authority writer's full scalar preopen representation.
///
/// # Errors
/// Preserves invalid limits, an excessive captured prefix or checked overflow.
pub(super) fn protected_authority_preopen_replay_extent_for_prefix_v1(
    limits: JournalLimits,
    native_prefix_bytes: u64,
) -> Result<ProtectedJournalPreopenReplayExtentV1, JournalError> {
    match authority::protected_journal_preopen_replay_extent_for_prefix_v1(limits, native_prefix_bytes) {
        Ok(extent) => Ok(ProtectedJournalPreopenReplayExtentV1::Authority(extent)),
        Err(cause) => Err(cause),
    }
}

/// Computes the actual Policy writer's full scalar preopen representation.
///
/// # Errors
/// Preserves invalid limits, an excessive captured prefix or checked overflow.
pub(super) fn protected_policy_preopen_replay_extent_for_prefix_v1(
    limits: JournalLimits,
    native_prefix_bytes: u64,
) -> Result<ProtectedJournalPreopenReplayExtentV1, JournalError> {
    match policy::protected_journal_preopen_replay_extent_for_prefix_v1(limits, native_prefix_bytes) {
        Ok(extent) => Ok(ProtectedJournalPreopenReplayExtentV1::Policy(extent)),
        Err(cause) => Err(cause),
    }
}

impl ProtectedJournalPreopenReplayExtentV1 {
    /// Copies the actual writer's original limits as passive scalar DATA.
    #[must_use]
    pub(super) fn limits_v1(&self) -> JournalLimits {
        match self {
            Self::Authority(extent) => extent.limits,
            Self::Policy(extent) => extent.limits,
        }
    }

    /// Prices the same writer's full native and checkpoint/cache representation.
    ///
    /// # Errors
    /// Preserves the actual scalar extent's consistency or overflow refusal.
    pub(super) fn dominant_native_receiving_demand_v1(
        &self,
    ) -> Result<ResourceVector, JournalError> {
        match self {
            Self::Authority(extent) => extent.dominant_native_receiving_demand_v1(),
            Self::Policy(extent) => extent.dominant_native_receiving_demand_v1(),
        }
    }

    /// Prices the sole complete all-family semantic recipe for this prefix.
    ///
    /// # Errors
    /// Preserves the actual scalar extent's consistency or overflow refusal.
    pub(super) fn dominant_semantic_receiving_demand_v1(
        &self,
    ) -> Result<ResourceVector, JournalError> {
        match self {
            Self::Authority(extent) => extent.dominant_semantic_receiving_demand_v1(),
            Self::Policy(extent) => extent.dominant_semantic_receiving_demand_v1(),
        }
    }
}

/// Measures the actual Authority binding's new scalar forwarding controls.
#[must_use]
pub(super) fn authority_control_bytes_v1() -> Option<usize> {
    authority::additional_control_bytes_v1()
}

/// Measures the actual Policy binding's new scalar forwarding controls.
#[must_use]
pub(super) fn policy_control_bytes_v1() -> Option<usize> {
    policy::additional_control_bytes_v1()
}

fn validate_limits(limits: JournalLimits) -> Result<(), JournalError> {
    aos_sandbox_journal::geometry::validate_native_bounds(limits.into()).map_err(JournalError::from)
}

fn native_release_replay_work_v1(
    physical: usize,
    limits: JournalLimits,
) -> Result<CanonicalRereadWireWorkDataV1, JournalError> {
    ordinary_reread_wire_work_data_v1(physical, limits)
        .ok_or(JournalError::LimitExceeded("original Release replay copy"))
}

// This is the sole full all-family LedgerReplay recipe. Current adds its old
// independently compiled supplement only after this succeeds, and prices its
// held index afterwards. CanonicalReplayExtent's key index is not this term.
fn semantic_representation_demand_v1(
    encoded: usize,
    rows: usize,
) -> Result<ResourceVector, JournalError> {
    aos_sandbox_ledger_replay::geometry::semantic_rows::semantic_representation_demand_v1(
        encoded, rows,
    )
}

// Measures the controls common to either actual typed binding.
// The real Current fixed admission consumes the distinct Authority and Policy
// supplier once each. This function prices no native backing, cells or FDs.
fn common_control_bytes_v1() -> Option<usize> {
    // Actual extent constructor, validation conversion, native-work wrapper,
    // full semantic wrapper, and both extent methods retain these interfaces.
    let arguments = size_of::<(JournalLimits, u64)>()
        .checked_mul(4)?
        .checked_add(size_of::<JournalLimits>())?
        .checked_add(size_of::<NativeGeometryBounds>().checked_mul(2)?)?
        .checked_add(size_of::<(usize, JournalLimits)>().checked_mul(2)?)?
        .checked_add(size_of::<(usize, usize)>().checked_mul(2)?)?
        .checked_add(size_of::<&ProtectedJournalPreopenReplayExtentV1>().checked_mul(4)?)?;

    // Constructor/return/caller interfaces for the actual nested scalar calls.
    // Error objects stay their canonical owning types; no supplied byte shape
    // or widened result enum is used to imitate an unrelated old Domain lane.
    let results = size_of::<Result<ProtectedJournalPreopenReplayExtentV1, JournalError>>()
        .checked_mul(3)?
        // Six actually reached Result interfaces per writer: outer and inner
        // native method; outer and inner semantic method; shared semantic
        // wrapper; canonical full Ledger rows. Each names construction/return/
        // caller planes. None is a future unexecuted writer or Source family.
        .checked_add(size_of::<Result<ResourceVector, JournalError>>().checked_mul(18)?)?
        .checked_add(
            size_of::<Result<CanonicalRereadWireWorkDataV1, JournalError>>().checked_mul(2)?,
        )?
        .checked_add(size_of::<Option<CanonicalRereadWireWorkDataV1>>().checked_mul(2)?)?
        .checked_add(size_of::<Result<(), FrameError>>().checked_mul(2)?)?
        .checked_add(size_of::<Result<usize, FrameError>>().checked_mul(2)?)?
        .checked_add(size_of::<Result<usize, JournalError>>().checked_mul(8)?)?
        .checked_add(size_of::<Result<u64, JournalError>>().checked_mul(4)?)?
        .checked_add(size_of::<Result<usize, std::num::TryFromIntError>>().checked_mul(6)?)?
        .checked_add(size_of::<Result<(), JournalError>>().checked_mul(2)?)?
        .checked_add(size_of::<Result<u64, std::num::TryFromIntError>>().checked_mul(6)?)?
        .checked_add(size_of::<Option<u64>>().checked_mul(2)?)?
        .checked_add(size_of::<JournalError>().checked_mul(2)?)?
        // Two Cold quote interfaces and this supplier's checked return/caller.
        .checked_add(size_of::<Option<usize>>().checked_mul(12)?)?
        .checked_add(
            size_of::<Result<ProtectedJournalPreopenReplayExtentV1, PolicyNativeJournalErrorV1>>()
                .checked_mul(2)?,
        )?
        .checked_add(size_of::<PolicyNativeJournalErrorV1>().checked_mul(2)?)?
        // Explicit factory Err transfer keeps the canonical owning cause.
        .checked_add(size_of::<JournalError>().checked_mul(3)?)?;
    // The newly exposed Cold subset names its semantic and outer-header
    // scalar locals in addition to the Option return/caller planes above.
    arguments
        .checked_add(results)?
        .checked_add(size_of::<usize>().checked_mul(2)?)
}


// The real incoming Current constructor pays this new scalar query interface.
// It retains no native IO owner or receiving/role permission.
pub(super) const EXTENT_QUERY_CONTROL_BYTES_V1: usize =
    3 * std::mem::size_of::<&ProtectedJournalPreopenReplayExtentV1>()
    + 3 * std::mem::size_of::<JournalLimits>();

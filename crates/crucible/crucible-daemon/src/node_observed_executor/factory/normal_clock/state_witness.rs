//! Borrows real retired and continued Clock owners for the normal runner.
//!
//! No decoder or public constructor can create this view. Fresh snapshots are
//! read from the actual retained worlds while their owning programme is borrowed
//! exclusively; the returned immutable loan prevents concurrent mutation.

use crucible_engine::node_contract::{RuntimeSnapshot, SavedRuntimeActivation};
use crucible_engine::node_state::NativeWorldFactory;
use serde::Serialize;

use super::*;

pub(super) const MAXIMUM_STATE_BYTES: usize = 128 * 1024;

/// Borrows actual original Clock retirement and both independent fresh owners.
///
/// This view grants no mutable runtime, class policy or activation. Its original
/// native archive records and inaccessible retired runtime remain retained by
/// the service actor throughout the installed-source callback.
pub struct OriginalClockStateWitness<'a> {
    pub(super) programme: &'a OriginalClockStateProgramme,
    pub(super) original: &'a OriginalClockQualificationRun,
    pub(super) fresh: [RuntimeSnapshot; 2],
}

/// Borrows complete actual state observations, independently of class authority.
#[derive(Serialize)]
pub struct ClockStateObservationData<'a> {
    /// Names the original complete state witness format.
    pub schema: &'static str,
    /// Binds the unchanged complete source-selected world.
    pub source_world: &'a crucible_node_format::WorldBinding,
    /// Retains actual native admission refusals under the same original owners.
    pub admission: super::admission_cases::ClockAdmissionObservationData<'a>,
    /// Binds the actual typed archive read after original retirement.
    pub source_artifact: &'a ContentRef,
    /// Retains the complete original signed runtime and ACK ledger.
    pub original: &'a RuntimeSnapshot,
    /// Retains both independently published owners' complete current ledgers.
    pub fresh: &'a [RuntimeSnapshot; 2],
    /// Binds independently captured real native suffix states and their history.
    pub future_artifacts: [&'a ContentRef; 2],
}

impl OriginalClockStateWitness<'_> {
    /// Authenticates the same real original and both live continuation owners.
    ///
    /// Every call rechecks original origin/source, authentic resource retirement,
    /// actual complete current runtime snapshots and source-native archive
    /// records. Matching report bytes alone do not establish these properties.
    ///
    /// # Errors
    /// Refuses missing originals, changed state/lineage/source, partial retirement,
    /// an unacknowledged suffix, differing actual world or native ledger.
    pub fn authenticate_current(&self) -> Result<(), NodeObservedError> {
        let state = self.programme;
        state.origin.current()?;
        self.original.current()?;
        if !state.compared
            || state.failed
            || !state.reopened
            || !self.original.failed
            || !self.original.retirement_attempted
            || !self.original.admission_cases.complete()
            || self.original.runtime.is_some()
        {
            return Err(refused("original Clock state owners no longer current"));
        }
        let original_record = self
            .original
            .captured
            .as_ref()
            .ok_or_else(|| refused("original captured Clock absent"))?;
        let source = state
            .original
            .as_ref()
            .ok_or_else(|| refused("retired Clock ledger absent"))?;
        if original_record
            .runtime_snapshot()
            .map_err(super::super::native)?
            != *source
            || state.record.as_ref().map(|record| record.artifact())
                != Some(original_record.artifact())
            || state.artifact.as_ref() != Some(original_record.artifact())
        {
            return Err(refused("Clock original source ledger or artifact changed"));
        }
        self.original
            .retired
            .as_ref()
            .ok_or_else(|| refused("actual original retirement absent"))?
            .authenticate_retired_ledger(
                source,
                state_programme::limits().state.maximum_record_bytes,
            )?;
        for (index, branch) in state.branches.iter().enumerate() {
            let graph = branch
                .graph
                .as_ref()
                .ok_or_else(|| refused("actual Clock continuation graph absent"))?;
            let world = branch
                .world
                .as_ref()
                .ok_or_else(|| refused("actual Clock continuation owner absent"))?;
            let future = branch
                .future
                .as_ref()
                .ok_or_else(|| refused("actual Clock continuation capture absent"))?;
            let factory = branch
                .catalog
                .installed_normal_clock_state_factory(&state.profile)?;
            let admitted = future
                .admit(graph, state_programme::requirements()?, factory.as_ref())
                .map_err(super::super::native)?;
            let actual = &self.fresh[index];
            if future.runtime_snapshot().map_err(super::super::native)? != *actual
                || actual.source_activation
                    != SavedRuntimeActivation::from(world.activation().record())
                || actual.capture_cut
                    != Position::new(
                        U64::new(state_programme::SUFFIX_PS),
                        0.into(),
                        Phase::BoundaryControl,
                    )
                || actual.capture_ordinal != U64::new(state_programme::CAPTURE_ORDINAL + 1)
            {
                return Err(refused(
                    "Clock current fresh world differs from original native capture",
                ));
            }
            let owner = admitted
                .manifest()
                .owners
                .first()
                .ok_or_else(|| refused("actual fresh Clock owner absent"))?;
            let opaque = future
                .authenticated_source(&owner.capture_owner_id, actual, admitted.content())
                .map_err(super::super::native)?;
            factory
                .authenticate_source(graph, owner, &opaque)
                .map_err(super::super::native)?;
            let case = branch
                .expected
                .as_ref()
                .ok_or_else(|| refused("original Clock suffix programme absent"))?;
            if !case.acknowledged {
                return Err(refused("actual Clock suffix ACK absent"));
            }
            case.expected.authenticate_objects(
                case.objects
                    .as_deref()
                    .ok_or_else(|| refused("original suffix bodies absent"))?,
            )?;
        }
        state.origin.current()
    }

    /// Borrows the actual complete records after authenticating their real owners.
    ///
    /// # Errors
    /// Refuses any currentness, native state, actual retirement or owner mismatch.
    pub fn observation_data(&self) -> Result<ClockStateObservationData<'_>, NodeObservedError> {
        self.authenticate_current()?;
        let state = self.programme;
        let artifact = state
            .artifact
            .as_ref()
            .ok_or_else(|| refused("Clock source artifact absent"))?;
        let original = state
            .original
            .as_ref()
            .ok_or_else(|| refused("Clock original history absent"))?;
        let left = state.branches[0]
            .future
            .as_ref()
            .ok_or_else(|| refused("left native source absent"))?;
        let right = state.branches[1]
            .future
            .as_ref()
            .ok_or_else(|| refused("right native source absent"))?;
        Ok(ClockStateObservationData {
            schema: "crucible.original-clock-state/2",
            admission: self.original.admission_cases.observation()?,
            source_world: &state.profile.scenario.world,
            source_artifact: artifact,
            original,
            fresh: &self.fresh,
            future_artifacts: [left.artifact(), right.artifact()],
        })
    }
}

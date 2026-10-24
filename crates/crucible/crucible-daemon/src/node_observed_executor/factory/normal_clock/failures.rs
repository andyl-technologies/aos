//! Retains actual failed publication and signed-archive challenge experiments.
//!
//! All native owners come from the same installed Clock constructor. Ref faults
//! surround real durable root placement; archive challenges alter the actual
//! signed index and restore its original bytes before subsequent experiments.
//! Separate malformed-manifest probes invoke the actual Core pre-staging
//! schema/source/owner guards; they cannot supply native provenance or staging.
//! A seal refusal is not evidence of a validly signed incompatible native codec.

use std::rc::Rc;

use super::*;
use crucible_engine::node_contract::{
    Lifecycle, PhysicalState, PublicationStatus, RuntimeError, RuntimePollFailure,
};

mod damage;
mod publication;
mod storage;
mod witness;

pub use witness::OriginalClockFailureWitness;

pub(super) const BEFORE: &str = "clock/failed-publication-before-commit";
pub(super) const AFTER: &str = "clock/failed-publication-after-commit";
pub(super) const DAMAGED: &str = "clock/damaged-restoration-refusals";
pub(super) const MAXIMUM_REPORT_BYTES: u64 = 128 * 1024;

type Status = (Lifecycle, PhysicalState, Option<Position>);

pub(super) struct OriginalClockFailureProgramme {
    origin: ClockOrigin,
    executions: [ExecutionId; 2],
    publications: [publication::PublicationFailure; 2],
    damage: damage::DamagedArchive,
}

impl OriginalClockFailureProgramme {
    pub(super) fn new(
        catalog: &InstalledNodeCatalog,
        aggregate: &OriginalClockAggregateResources,
        executions: [ExecutionId; 2],
    ) -> Result<Self, NodeObservedError> {
        aggregate
            .authenticate_current()
            .map_err(super::super::native)?;
        if executions[0] == executions[1] {
            return Err(refused(
                "Clock publication experiments require independent executions",
            ));
        }
        let root = aggregate
            .publication_path_data()
            .map_err(super::super::native)?;
        Ok(Self {
            origin: ClockOrigin {
                source: catalog.host_identity.clone(),
                source_path: catalog.host_executable.clone(),
                process: std::process::id(),
                thread: std::thread::current().id(),
            },
            executions,
            publications: [
                publication::PublicationFailure::new(catalog, &root, executions[0], false)?,
                publication::PublicationFailure::new(catalog, &root, executions[1], true)?,
            ],
            damage: damage::DamagedArchive::new(
                aggregate
                    .archive_path_data()
                    .map_err(super::super::native)?,
            )?,
        })
    }

    pub(super) fn execute_publication(
        &mut self,
        index: usize,
        profile: &InstalledNormalClockProfile,
        original: &OriginalClockQualificationRun,
        aggregate: &OriginalClockAggregateResources,
    ) -> Result<(), NodeObservedError> {
        self.origin.current()?;
        aggregate
            .authenticate_current()
            .map_err(super::super::native)?;
        self.publications
            .get_mut(index)
            .ok_or_else(|| refused("Clock publication experiment index"))?
            .execute(profile, original)?;
        aggregate
            .authenticate_current()
            .map_err(super::super::native)?;
        self.origin.current()
    }

    pub(super) fn execute_damage(
        &mut self,
        state: &OriginalClockStateProgramme,
        original: &OriginalClockQualificationRun,
        aggregate: &OriginalClockAggregateResources,
    ) -> Result<(), NodeObservedError> {
        self.origin.current()?;
        aggregate
            .authenticate_current()
            .map_err(super::super::native)?;
        self.damage.execute(state, original, aggregate)?;
        aggregate
            .authenticate_current()
            .map_err(super::super::native)?;
        self.origin.current()
    }

    pub(super) fn witness<'a>(
        &'a mut self,
        case: &'static str,
        original: &'a OriginalClockQualificationRun,
        state: &'a OriginalClockStateProgramme,
    ) -> Result<OriginalClockFailureWitness<'a>, NodeObservedError> {
        OriginalClockFailureWitness::new(self, case, original, state)
    }
}

fn status(runtime: &mut NodeRuntime, node: &Id) -> Result<Status, NodeObservedError> {
    let actual = runtime.status(node).map_err(super::super::native)?;
    Ok((actual.lifecycle, actual.physical, actual.boundary))
}

fn disposition(status: PublicationStatus) -> &'static str {
    match status {
        PublicationStatus::Committed => "committed",
        PublicationStatus::NotCommitted => "not-committed",
        PublicationStatus::Unknown => "unknown",
    }
}

fn report(value: &impl serde::Serialize) -> Result<InputPayload, NodeObservedError> {
    struct Bound(usize);
    impl std::io::Write for Bound {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_sub(bytes.len())
                .ok_or_else(|| std::io::Error::other("Clock failure report ceiling"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(&mut Bound(MAXIMUM_REPORT_BYTES as usize), value)?;
    let bytes = canonical::canonical_json(&serde_json::to_value(value)?)?;
    if bytes.len() > MAXIMUM_REPORT_BYTES as usize {
        return Err(refused("Clock failure canonical report ceiling"));
    }
    Ok(InputPayload {
        reference: canonical::content_ref(&bytes, "application/json")?,
        bytes,
    })
}

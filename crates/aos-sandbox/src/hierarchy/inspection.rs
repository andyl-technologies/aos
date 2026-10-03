//! Explicit live and stable descendant-inspection identities.
//!
//! Construction consumes opaque evidence minted by trusted in-crate adapters
//! and a complete export closure. Request scalars cannot become inspection
//! authority through this module.

use std::collections::{BTreeMap, BTreeSet};

use aos_sandbox_core::{DesiredGeneration, ObjectDigest, ProjectId, SandboxId};

use super::evidence::{
    CurrentAssignmentEvidenceV1, CurrentLiveInspectionObservationV1, InspectionGrantModeV1,
    VerifiedInspectionGrantV1,
};
use super::exports::{ExportSourceV1, MAXIMUM_EXPORT_DEFINITIONS, SubtreeExportClosureV1};
use super::graph::SandboxTreeV1;
use super::recovery::CommittedHierarchySnapshotV1;

/// Selects retained immutable state or an authenticated current live namespace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InspectionSourceEvidenceV1 {
    /// Carries a verified immutable snapshot manifest and retention proof.
    Stable(Box<CommittedHierarchySnapshotV1>),
    /// Carries current observer and descendant observations with kernel coupling.
    LiveKernelCoupled(Box<LiveInspectionEvidenceV1>),
}

/// Joins current observer assignment with a current live descendant observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiveInspectionEvidenceV1 {
    observer: CurrentAssignmentEvidenceV1,
    live_sources: Vec<CurrentLiveInspectionObservationV1>,
}

impl LiveInspectionEvidenceV1 {
    /// Joins observations only after a trusted adapter verifies one current set.
    ///
    /// # Errors
    ///
    /// Returns [`InspectionError::LiveObservationsNotCanonical`] when the set
    /// is oversized, duplicated, or not ordered by sandbox identity.
    pub(crate) fn from_verified_parts(
        observer: CurrentAssignmentEvidenceV1,
        live_sources: Vec<CurrentLiveInspectionObservationV1>,
    ) -> Result<Self, InspectionError> {
        if live_sources.len() > MAXIMUM_EXPORT_DEFINITIONS
            || !live_sources
                .windows(2)
                .all(|pair| pair[0].sandbox() < pair[1].sandbox())
        {
            return Err(InspectionError::LiveObservationsNotCanonical);
        }

        Ok(Self {
            observer,
            live_sources,
        })
    }

    /// Returns the current observer assignment evidence.
    #[must_use]
    pub const fn observer(&self) -> &CurrentAssignmentEvidenceV1 {
        &self.observer
    }

    /// Returns exact current observations for every required live source.
    #[must_use]
    pub fn live_sources(&self) -> &[CurrentLiveInspectionObservationV1] {
        &self.live_sources
    }
}

/// Stores one complete descendant-inspection identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DescendantInspectionV1 {
    project: ProjectId,
    observer: SandboxId,
    observer_generation: DesiredGeneration,
    descendant: SandboxId,
    grant: VerifiedInspectionGrantV1,
    source: InspectionSourceEvidenceV1,
    export_closure: SubtreeExportClosureV1,
}

impl DescendantInspectionV1 {
    /// Constructs one inspection from current opaque evidence.
    ///
    /// The grant must bind the exact observer, descendant, and observer
    /// generation. Live evidence must match the descendant's current tree
    /// incarnation and generation, and the observer and descendant must share
    /// one node and authenticated observation set. Stable evidence may capture
    /// an older generation, but must retain the exact export-closure commitment.
    ///
    /// # Errors
    ///
    /// Returns [`InspectionError`] for a stale evidence join, non-descendant
    /// target, or snapshot/export commitment mismatch.
    pub fn new(
        tree: &SandboxTreeV1,
        grant: VerifiedInspectionGrantV1,
        source: InspectionSourceEvidenceV1,
        export_closure: SubtreeExportClosureV1,
        export_closure_commitment: ObjectDigest,
    ) -> Result<Self, InspectionError> {
        if export_closure_commitment.as_bytes() == &[0; 32] {
            return Err(InspectionError::UnspecifiedIdentity);
        }
        if grant.grant_commitment().as_bytes() == &[0; 32]
            || grant.revocation_generation().get() == 0
        {
            return Err(InspectionError::UnspecifiedIdentity);
        }
        if tree.project() != grant.project() {
            return Err(InspectionError::ProjectMismatch);
        }
        let observer = tree
            .record(grant.observer())
            .ok_or(InspectionError::UnknownSandbox)?;
        let descendant = tree
            .record(grant.descendant())
            .ok_or(InspectionError::UnknownSandbox)?;
        if observer.desired_generation() != grant.observer_generation() {
            return Err(InspectionError::StaleGrant);
        }
        if observer.sandbox() == descendant.sandbox()
            || !tree.contains_in_subtree(observer.sandbox(), descendant.sandbox())
        {
            return Err(InspectionError::NotDescendant);
        }
        if export_closure.project() != tree.project()
            || export_closure.root() != descendant.sandbox()
            || export_closure.commitment() != export_closure_commitment
        {
            return Err(InspectionError::ExportClosureMismatch);
        }

        match &source {
            InspectionSourceEvidenceV1::Stable(snapshot) => {
                if grant.mode() != InspectionGrantModeV1::Stable {
                    return Err(InspectionError::GrantModeMismatch);
                }
                let manifest = snapshot.retained();
                if manifest.project() != tree.project()
                    || manifest.sandbox() != descendant.sandbox()
                    || manifest.snapshot().as_bytes() == &[0; 16]
                    || manifest.captured_generation().get() == 0
                    || manifest.export_closure_commitment() != export_closure_commitment
                    || manifest.manifest().encoded_size() == 0
                    || manifest.manifest().digest().as_bytes() == &[0; 32]
                    || manifest.retention_proof_commitment().as_bytes() == &[0; 32]
                    || snapshot.commit_commitment().as_bytes() == &[0; 32]
                {
                    return Err(InspectionError::SnapshotEvidenceMismatch);
                }
            }
            InspectionSourceEvidenceV1::LiveKernelCoupled(evidence) => {
                if grant.mode() != InspectionGrantModeV1::LiveKernelCoupled {
                    return Err(InspectionError::GrantModeMismatch);
                }
                let observer_assignment = evidence.observer();
                if export_closure.project() != tree.project()
                    || export_closure.tree_generation() != tree.tree_generation()
                    || observer_assignment.project() != tree.project()
                    || observer_assignment.sandbox() != observer.sandbox()
                    || observer_assignment.desired_generation() != observer.desired_generation()
                    || observer.incarnation() != Some(observer_assignment.incarnation())
                    || observer_assignment.node().as_bytes() == &[0; 16]
                    || observer_assignment.namespace_generation().get() == 0
                    || observer_assignment.assignment_epoch().get() == 0
                    || observer_assignment.observation_set_commitment().as_bytes() == &[0; 32]
                    || observer_assignment.assignment_commitment().as_bytes() == &[0; 32]
                {
                    return Err(InspectionError::StaleLiveObservation);
                }

                let mut required_sources = BTreeSet::new();
                required_sources.insert(descendant.sandbox());
                for definition in export_closure.reachable_definitions() {
                    if matches!(
                        definition.source(),
                        ExportSourceV1::LiveKernelCoupled { .. }
                    ) {
                        required_sources.insert(definition.sandbox());
                    }
                }
                let observed_sources: BTreeSet<_> = evidence
                    .live_sources()
                    .iter()
                    .map(CurrentLiveInspectionObservationV1::sandbox)
                    .collect();
                if required_sources != observed_sources {
                    return Err(InspectionError::IncompleteLiveObservations);
                }

                let observations: BTreeMap<_, _> = evidence
                    .live_sources()
                    .iter()
                    .map(|observation| (observation.sandbox(), observation))
                    .collect();
                for observation in observations.values() {
                    let record = tree
                        .record(observation.sandbox())
                        .ok_or(InspectionError::UnknownSandbox)?;
                    if observation.project() != tree.project()
                        || observation.desired_generation() != record.desired_generation()
                        || record.incarnation() != Some(observation.incarnation())
                        || observation.node() != observer_assignment.node()
                        || observation.observation_set_commitment()
                            != observer_assignment.observation_set_commitment()
                        || observation.namespace_generation().get() == 0
                        || observation.assignment_epoch().get() == 0
                        || observation.observation_commitment().as_bytes() == &[0; 32]
                    {
                        return Err(InspectionError::StaleLiveObservation);
                    }
                }
                for definition in export_closure.reachable_definitions() {
                    let ExportSourceV1::LiveKernelCoupled {
                        incarnation,
                        generation,
                        ..
                    } = definition.source()
                    else {
                        continue;
                    };
                    let observation = observations
                        .get(&definition.sandbox())
                        .ok_or(InspectionError::IncompleteLiveObservations)?;
                    if observation.incarnation() != incarnation
                        || observation.desired_generation() != generation
                    {
                        return Err(InspectionError::StaleLiveObservation);
                    }
                }
            }
        }

        Ok(Self {
            project: tree.project(),
            observer: observer.sandbox(),
            observer_generation: observer.desired_generation(),
            descendant: descendant.sandbox(),
            grant,
            source,
            export_closure,
        })
    }

    /// Returns the project authority domain.
    #[must_use]
    pub const fn project(&self) -> ProjectId {
        self.project
    }

    /// Returns the inspecting ancestor.
    #[must_use]
    pub const fn observer(&self) -> SandboxId {
        self.observer
    }

    /// Returns the observer generation checked during construction.
    #[must_use]
    pub const fn observer_generation(&self) -> DesiredGeneration {
        self.observer_generation
    }

    /// Returns the inspected strict descendant.
    #[must_use]
    pub const fn descendant(&self) -> SandboxId {
        self.descendant
    }

    /// Returns retained verified grant evidence.
    #[must_use]
    pub const fn grant(&self) -> &VerifiedInspectionGrantV1 {
        &self.grant
    }

    /// Returns the explicit stable or live source evidence.
    #[must_use]
    pub const fn source(&self) -> &InspectionSourceEvidenceV1 {
        &self.source
    }

    /// Returns the complete reachable export closure.
    #[must_use]
    pub const fn export_closure(&self) -> &SubtreeExportClosureV1 {
        &self.export_closure
    }
}

/// Reports a conflicting or stale inspection evidence join.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InspectionError {
    /// A required commitment uses its zero sentinel.
    #[error("inspection contains an unspecified commitment")]
    UnspecifiedIdentity,
    /// Grant evidence belongs to another project.
    #[error("inspection evidence belongs to another project")]
    ProjectMismatch,
    /// The observer or descendant is absent.
    #[error("inspection evidence names an unknown sandbox")]
    UnknownSandbox,
    /// Grant evidence does not bind the current observer generation.
    #[error("inspection grant is stale")]
    StaleGrant,
    /// The grant authorizes different stable or live semantics.
    #[error("inspection grant mode does not match the requested source")]
    GrantModeMismatch,
    /// The target is not a strict descendant of the observer.
    #[error("inspection target is not a descendant")]
    NotDescendant,
    /// The supplied export closure is not exact for the target.
    #[error("inspection export closure does not match the descendant")]
    ExportClosureMismatch,
    /// Stable manifest or retention evidence conflicts with the closure.
    #[error("inspection snapshot evidence is incomplete or conflicting")]
    SnapshotEvidenceMismatch,
    /// Live evidence is not current for the descendant assignment.
    #[error("live inspection observation is stale")]
    StaleLiveObservation,
    /// The live source set is oversized, duplicated, or unordered.
    #[error("live inspection observations are not canonical")]
    LiveObservationsNotCanonical,
    /// Current evidence does not exactly cover every reachable live source.
    #[error("live inspection evidence does not cover every live source")]
    IncompleteLiveObservations,
}

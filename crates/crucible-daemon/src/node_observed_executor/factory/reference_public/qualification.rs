//! Invokes the installed source candidate and retains its partial qualification.
//!
//! This entry point runs the fixed source-owned qualification mechanism. It
//! never supplies an ordinary node factory or a Ready token. The returned report
//! records missing review and preserves the exact original native population.

use std::{path::PathBuf, sync::mpsc};

use crucible_cas::content_store::ContentId;
use crucible_node_contract::ContentRef;

use super::{
    harness, issuer::SourceIssuedQualification, package::InstalledPublicReferencePackage,
    run_error::QualificationRunError,
};

/// Retains the fixed installed implementation and its qualification invocation.
pub struct InstalledReferenceQualifier {
    implementation: ContentRef,
}

/// Receives the durable original result from the owning installation actor.
pub struct ReferenceQualificationRun {
    receiver: mpsc::Receiver<Result<harness::CandidateHarnessResult, QualificationRunError>>,
}

/// Retains original native roots and a complete unresolved behavioral report.
pub struct ReferenceQualificationObservation {
    implementation: ContentRef,
    original: ContentId,
    retirement: ContentId,
    population: ContentId,
    issued: SourceIssuedQualification,
}

impl InstalledReferenceQualifier {
    /// Measures the source package pinned into this executable at compilation.
    ///
    /// # Errors
    /// Refuses absent installation, changed original artifact bytes or an
    /// unsupported package scope. Descriptor validation grants no qualification.
    pub fn built_in() -> Result<Self, QualificationRunError> {
        let package = InstalledPublicReferencePackage::built_in()?;
        Ok(Self {
            implementation: package.identity().clone(),
        })
    }

    /// Starts the fixed original population in a fresh private output directory.
    ///
    /// Only one qualification actor may be reserved per host process. The
    /// actor retains native cleanup and evidence publication when this handle
    /// or its receiver is dropped. Storage failures never initiate another run.
    ///
    /// # Errors
    /// Refuses a changed installation, exhausted actor reservation, invalid
    /// thread resources or a directory that cannot be created privately.
    pub fn start(
        &self,
        directory: PathBuf,
    ) -> Result<ReferenceQualificationRun, QualificationRunError> {
        let package = InstalledPublicReferencePackage::built_in()?;
        if package.identity() != &self.implementation {
            return Err(QualificationRunError::Refused(
                "installed qualification implementation changed",
            ));
        }
        let receiver = harness::start(directory)?;
        Ok(ReferenceQualificationRun { receiver })
    }
}

impl ReferenceQualificationRun {
    /// Waits for original native reclamation and durable population publication.
    ///
    /// # Errors
    /// Reports the original setup failure or unavailable actor result. Missing
    /// source-inspection evidence is represented inside the report, not hidden
    /// by changing the native case or its original verdict.
    pub fn wait(self) -> Result<ReferenceQualificationObservation, QualificationRunError> {
        let original = self.receiver.recv()??;
        let (_, criteria) =
            original
                .qualification_context()
                .ok_or(QualificationRunError::Refused(
                    "original predeclared qualification context unavailable",
                ))?;
        let implementation = criteria.plan.unit.implementation.clone();
        let original_root = original.original_result();
        let retirement = original.retirement_result();
        let population = original
            .population_result()
            .ok_or(QualificationRunError::Refused(
                "original qualification population is not durable",
            ))?;
        let issued = SourceIssuedQualification::issue(original)?;
        Ok(ReferenceQualificationObservation {
            implementation,
            original: original_root,
            retirement,
            population,
            issued,
        })
    }
}

impl ReferenceQualificationObservation {
    /// Returns the measured immutable implementation-unit identity.
    pub fn implementation(&self) -> &ContentRef {
        &self.implementation
    }

    /// Returns the original complete native observation root.
    pub fn original(&self) -> ContentId {
        self.original
    }

    /// Returns original positively reclaimed process and world custody facts.
    pub fn retirement(&self) -> ContentId {
        self.retirement
    }

    /// Returns the complete persistent population manifest, including failures.
    pub fn population(&self) -> ContentId {
        self.population
    }

    /// Returns complete original claim bytes without conferring acceptance.
    pub fn report_bytes(&self) -> &[u8] {
        self.issued.report().bytes()
    }

    /// Returns the original report identity without upgrading missing criteria.
    pub fn report_reference(&self) -> &ContentRef {
        self.issued.report().reference()
    }

    /// Rechecks the concrete installed authority's ordinary qualification gate.
    ///
    /// This diagnostic does not grant native readiness or execution. No caller
    /// accepted-token or permissive authority can replace this source authority.
    ///
    /// # Errors
    /// Refuses unresolved original review, missing artifacts or changed scope.
    pub fn require_complete_qualification(&self) -> Result<(), QualificationRunError> {
        self.issued
            .admit_current()
            .map(|_| ())
            .map_err(QualificationRunError::from)
    }
}

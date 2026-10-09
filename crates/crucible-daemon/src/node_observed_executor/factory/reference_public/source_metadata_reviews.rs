//! Binds four completed source inspections to their immutable native predecessor.
//!
//! The predecessor contains only the original native cases and omissions. These
//! source reviews never refer to the report that credits them, avoiding a report
//! identity cycle. Their private collector performs actual metadata and source
//! artifact checks; authentication repeats those checks against the same actor.

use std::collections::BTreeMap;

use crucible_node_contract::{Bytes, ContentRef, canonical};
use serde_json::json;

use super::harness::CandidateHarnessResult;
use crate::node_qualification::{CaseVerdict, IssuedQualification, QualificationError};

const MAXIMUM_REVIEW_BYTES: usize = 128 * 1024 * 1024;

/// Lists the four complete metadata clauses, independently of behavioral classes.
pub(super) const REVIEW_IDS: [&str; 4] =
    ["CN-TEST-001", "CN-TEST-002", "CN-TEST-004", "CN-TEST-005"];

/// Retains inspector-issued original review bytes without a public constructor.
pub(super) struct SourceMetadataReviews {
    predecessor: ContentRef,
    predecessor_bytes: Vec<u8>,
    predecessor_objects: Vec<(ContentRef, Bytes)>,
    aggregate: ContentRef,
    aggregate_bytes: Vec<u8>,
    results: BTreeMap<String, (ContentRef, Vec<u8>)>,
    failure: Option<OriginalInspectionFailure>,
}

/// Retains the two successful original observation bodies for storage retries.
pub(super) struct SourceInspectionBytes {
    /// Contains the exact original metadata inspector body.
    pub(super) metadata: Vec<u8>,
    /// Contains the exact original real-file measurement control body.
    pub(super) artifacts: Vec<u8>,
}

/// Retains the first inspection failure instead of retrying its measurements.
#[derive(Clone)]
struct OriginalInspectionFailure {
    diagnostic: String,
    unwound: bool,
    prior: Option<Box<PriorSourceInspection>>,
}

#[derive(Clone)]
struct PriorSourceInspection {
    reference: ContentRef,
    bytes: Vec<u8>,
    objects: Vec<(ContentRef, Vec<u8>)>,
}

impl SourceMetadataReviews {
    /// Collects exactly once and retains error or unwind as original failed cases.
    ///
    /// # Errors
    /// Refuses failure-record encoding when original context is unavailable or
    /// the bounded immutable diagnostic itself cannot be represented.
    pub(super) fn collect_once(
        original: &CandidateHarnessResult,
        predecessor: &IssuedQualification,
    ) -> Result<Self, QualificationError> {
        match original_attempt(|| Self::collect(original, predecessor)) {
            Ok(reviews) => Ok(reviews),
            Err(failure) => Self::failure_objects(original, predecessor, failure),
        }
    }

    /// Retains issuance refusal without retrying the original source inspection.
    ///
    /// # Errors
    /// Refuses absent original context or malformed bounded failure objects.
    pub(super) fn failed(
        original: &CandidateHarnessResult,
        predecessor: &IssuedQualification,
        diagnostic: &str,
        unwound: bool,
        prior: Option<&Self>,
    ) -> Result<Self, QualificationError> {
        let mut failure = failure_diagnostic(diagnostic, unwound);
        failure.prior = prior.filter(|prior| prior.failure.is_none()).map(|prior| {
            Box::new(PriorSourceInspection {
                reference: prior.aggregate.clone(),
                bytes: prior.aggregate_bytes.clone(),
                objects: prior
                    .objects()
                    .map(|(reference, bytes)| (reference.clone(), bytes.to_vec()))
                    .collect(),
            })
        });
        Self::failure_objects(original, predecessor, failure)
    }

    fn failure_objects(
        original: &CandidateHarnessResult,
        predecessor: &IssuedQualification,
        failure: OriginalInspectionFailure,
    ) -> Result<Self, QualificationError> {
        let (unit, criteria) = original
            .qualification_context()
            .ok_or(refused("original source review failure context absent"))?;
        let aggregate_bytes = canonical::canonical_json(&json!({
            "schema":"crucible.reference.original-source-review-failure.v1",
            "unit":unit.identity,"plan":criteria.reference,
            "native_predecessor":predecessor.reference(),
            "source_inspector":unit.identity.harness,
            "requirements":REVIEW_IDS,"case_kind":"source_inspection",
            "verdict":"failed","diagnostic":failure.diagnostic,"unknown":failure.unwound,
            "prior_completed_inspection":failure.prior.as_ref().map(|prior|json!({
                "reference":prior.reference,"bytes":Bytes::new(prior.bytes.clone()),
                "scope":"retained original successful collection; later authentication failed, so no passing criterion",
            })),
            "retry_policy":"only these same immutable nonpassing bytes may retry storage; no measurement retry",
        }))?;
        let aggregate = canonical::content_ref(&aggregate_bytes, "application/json")?;
        let mut results = BTreeMap::new();
        for id in REVIEW_IDS {
            let clause = criteria
                .clauses
                .get(id)
                .ok_or(refused("original failure normative clause absent"))?;
            let clause_bytes = canonical::canonical_json(
                &serde_json::to_value(clause)
                    .map_err(crucible_node_contract::ContractError::from)?,
            )?;
            let bytes = canonical::canonical_json(&json!({
                "schema":"crucible.reference.original-source-metadata-review.v1",
                "requirement":id,"clause":canonical::content_ref(&clause_bytes,"application/json")?,
                "source_reviews":aggregate,"unit":unit.identity,"plan":criteria.reference,
                "native_predecessor":predecessor.reference(),"case_kind":"source_inspection",
                "verdict":"failed","scope":"original inspection did not complete its oracle; no later retry replaces its failure",
            }))?;
            results.insert(
                format!("reference/review/{id}"),
                (canonical::content_ref(&bytes, "application/json")?, bytes),
            );
        }
        Ok(Self {
            predecessor: predecessor.reference().clone(),
            predecessor_bytes: predecessor.bytes().to_vec(),
            predecessor_objects: predecessor.objects().to_vec(),
            aggregate,
            aggregate_bytes,
            results,
            failure: Some(failure),
        })
    }

    /// Performs the predeclared inspections on the exact original actor report.
    ///
    /// # Errors
    /// Refuses absent original context, a changed fixture or source package,
    /// failed metadata/negative predicates, changed actual artifact bytes, or
    /// any review object outside the independent encoding ceiling.
    pub(super) fn collect(
        original: &CandidateHarnessResult,
        predecessor: &IssuedQualification,
    ) -> Result<Self, QualificationError> {
        let (unit, criteria) = original
            .qualification_context()
            .ok_or(refused("original review context absent"))?;
        let inspection = super::metadata_inspection::inspect(original, predecessor)?;
        let package = super::package::InstalledPublicReferencePackage::built_in()
            .map_err(|_| refused("source review package remeasurement refused"))?;
        let artifact_plan = package
            .artifact_measurement_plan()
            .map_err(|_| refused("source review artifact plan unavailable"))?;
        let fixtures = unit
            .objects
            .get(&unit.identity.fixtures)
            .ok_or(refused("original source review fixture missing"))?;
        let fixtures = canonical::parse_json(fixtures, 16 * 1024 * 1024)?;
        if fixtures["artifact_integrity_plan"] != artifact_plan.fixture()
            || fixtures["source_metadata_reviews"] != fixture()
        {
            return Err(refused("original source review plan changed"));
        }
        let artifact_controls = artifact_plan
            .inspect(&package)
            .map_err(|_| refused("source review actual artifact controls failed"))?;
        let aggregate_bytes = canonical::canonical_json(&json!({
            "schema":"crucible.reference.source-metadata-reviews.v1",
            "unit":unit.identity,"plan":criteria.reference,
            "native_predecessor":predecessor.reference(),
            "native_predecessor_bytes":Bytes::new(predecessor.bytes().to_vec()),
            "metadata_inspection":inspection,"artifact_controls":artifact_controls,
            "source_inspector":unit.identity.harness,
            "review_scope":"four exact metadata clauses only; source inspection rather than native behavioral acceptance",
            "requirements":REVIEW_IDS,
        }))?;
        if aggregate_bytes.len() > MAXIMUM_REVIEW_BYTES {
            return Err(refused("source review aggregate byte ceiling"));
        }
        let aggregate = canonical::content_ref(&aggregate_bytes, "application/json")?;
        let mut results = BTreeMap::new();
        for id in REVIEW_IDS {
            let clause = criteria
                .clauses
                .get(id)
                .ok_or(refused("source review normative clause absent"))?;
            let clause_bytes = canonical::canonical_json(
                &serde_json::to_value(clause)
                    .map_err(crucible_node_contract::ContractError::from)?,
            )?;
            let clause_ref = canonical::content_ref(&clause_bytes, "application/json")?;
            let bytes = canonical::canonical_json(&json!({
                "schema":"crucible.reference.original-source-metadata-review.v1",
                "requirement":id,"clause":clause_ref,"source_reviews":aggregate,
                "unit":unit.identity,"plan":criteria.reference,
                "native_predecessor":predecessor.reference(),
                "case_kind":"source_inspection",
                "scope":"the exact metadata sentence, independently checked against original source-bound facts; no remaining behavioral class or Ready claim",
            }))?;
            let reference = canonical::content_ref(&bytes, "application/json")?;
            results.insert(format!("reference/review/{id}"), (reference, bytes));
        }
        Ok(Self {
            predecessor: predecessor.reference().clone(),
            predecessor_bytes: predecessor.bytes().to_vec(),
            predecessor_objects: predecessor.objects().to_vec(),
            aggregate,
            aggregate_bytes,
            results,
            failure: None,
        })
    }

    /// Repeats the concrete inspections rather than trusting a passing flag.
    ///
    /// # Errors
    /// Refuses changed predecessor, actor/unit/fixture, inspector body, adverse
    /// population, actual source table or original per-clause result bytes.
    pub(super) fn authenticate(
        &self,
        original: &CandidateHarnessResult,
        predecessor: &IssuedQualification,
    ) -> Result<(), QualificationError> {
        let recomputed = match &self.failure {
            Some(failure) => Self::failure_objects(original, predecessor, failure.clone())?,
            None => Self::collect(original, predecessor)?,
        };
        if self.predecessor != recomputed.predecessor
            || self.predecessor_bytes != recomputed.predecessor_bytes
            || self.predecessor_objects != recomputed.predecessor_objects
            || self.aggregate != recomputed.aggregate
            || self.aggregate_bytes != recomputed.aggregate_bytes
            || self.results != recomputed.results
        {
            return Err(refused("original source metadata review witness changed"));
        }
        Ok(())
    }

    pub(super) fn verdict(&self) -> CaseVerdict {
        if self.failure.is_some() {
            CaseVerdict::Failed
        } else {
            CaseVerdict::Passed
        }
    }

    /// Returns already-collected original observations without re-executing them.
    ///
    /// # Errors
    /// Refuses malformed original aggregate encodings or observation bodies.
    pub(super) fn inspection_bytes(
        &self,
    ) -> Result<Option<SourceInspectionBytes>, QualificationError> {
        if self.failure.is_some() {
            return Ok(None);
        }
        let value = canonical::parse_json(&self.aggregate_bytes, MAXIMUM_REVIEW_BYTES)?;
        Ok(Some(SourceInspectionBytes {
            metadata: canonical::canonical_json(&value["metadata_inspection"])?,
            artifacts: canonical::canonical_json(&value["artifact_controls"])?,
        }))
    }

    pub(super) fn result(&self, case: &str) -> Option<(&ContentRef, &[u8])> {
        self.results
            .get(case)
            .map(|(reference, bytes)| (reference, bytes.as_slice()))
    }

    pub(super) fn objects(&self) -> impl Iterator<Item = (&ContentRef, &[u8])> {
        [
            (&self.predecessor, self.predecessor_bytes.as_slice()),
            (&self.aggregate, self.aggregate_bytes.as_slice()),
        ]
        .into_iter()
        .chain(
            self.predecessor_objects
                .iter()
                .map(|(reference, bytes)| (reference, bytes.as_slice())),
        )
        .chain(
            self.results
                .values()
                .map(|(reference, bytes)| (reference, bytes.as_slice())),
        )
        .chain(
            self.failure
                .iter()
                .filter_map(|failure| failure.prior.as_ref())
                .flat_map(|prior| {
                    prior
                        .objects
                        .iter()
                        .map(|(reference, bytes)| (reference, bytes.as_slice()))
                }),
        )
    }
}

/// Declares exact source reviews and their refusal population before any Child.
pub(super) fn fixture() -> serde_json::Value {
    json!({
        "schema":"crucible.reference.source-metadata-review-fixture.v1",
        "requirements":REVIEW_IDS,
        "maximum_review_bytes":MAXIMUM_REVIEW_BYTES,
        "predecessor":"the same original actor's immutable native-only report; never the report that credits these reviews",
        "authentication":"recompute exact source inspector, source unit, plan, fourteen original inert negative predicates and complete304 actual-file measurement table",
        "case_kind":"source_inspection",
        "collection":"exactly one original inspection attempt; error or unwind retained Failed; storage retries reuse identical bytes",
        "maximum_failure_diagnostic_bytes":4096,
        "prior_observations":"retained unchanged even if later issuer authentication fails or unwinds",
        "unavailable_issuance":"original actor/journals/context remain fenced; no inspection retry",
        "authentication_negatives":["inspector","report","unit","negative-population","artifact-table","plan","case-kind"],
        "remaining_requirements":"368 remain NotExecuted; ten exact conditional exclusions remain scoped NA; ordinary admission refused",
    })
}

fn original_attempt<T>(
    attempt: impl FnOnce() -> Result<T, QualificationError>,
) -> Result<T, OriginalInspectionFailure> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(attempt)) {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(failure_diagnostic(&error.to_string(), false)),
        Err(_) => Err(failure_diagnostic(
            "original source inspection unwound; outcome unknown",
            true,
        )),
    }
}

fn failure_diagnostic(diagnostic: &str, unwound: bool) -> OriginalInspectionFailure {
    OriginalInspectionFailure {
        diagnostic: if diagnostic.len() <= 4096 {
            diagnostic.to_owned()
        } else {
            "original source inspection failed; diagnostic exceeded predeclared byte ceiling"
                .to_owned()
        },
        unwound,
        prior: None,
    }
}

fn refused(reason: &'static str) -> QualificationError {
    QualificationError::Refused(reason)
}

#[cfg(test)]
#[path = "source_metadata_review_tests.rs"]
pub(super) mod adversarial_tests;

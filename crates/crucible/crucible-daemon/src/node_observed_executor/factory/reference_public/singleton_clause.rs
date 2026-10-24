//! Verifies the complete singleton clause population against compiled originals.
//!
//! This verifier checks full clauses, source units, and planned dependencies. It
//! never substitutes those checks or positive native subsets for an independent
//! behavioral review. Each unresolved review remains explicit in the output.

use std::collections::BTreeMap;

use crucible_node_format::{ContentRef, canonical};
use serde_json::{Value, json};

use crate::node_qualification::{QualificationError, WitnessCriterion};

use super::{
    criteria::NormativeClause, singleton_criteria::SingletonQualificationCriteria,
    singleton_unit::SingletonQualificationUnit,
};

pub(super) struct SingletonClauseVerifier {
    originals: BTreeMap<String, NormativeClause>,
    criteria: ContentRef,
    plan: crate::node_qualification::WitnessPlan,
}

impl SingletonClauseVerifier {
    /// Authenticates every complete clause and dependency before native effects.
    ///
    /// # Errors
    /// Refuses missing, modified, foreign-unit or additional clauses and cases.
    pub(super) fn prepare(
        unit: &SingletonQualificationUnit,
        criteria: &SingletonQualificationCriteria,
    ) -> Result<Self, QualificationError> {
        let expected = SingletonQualificationCriteria::build(unit)?;
        if expected.plan != criteria.plan
            || expected.reference != criteria.reference
            || expected.bytes != criteria.bytes
            || expected.objects != criteria.objects
            || expected.clauses != criteria.clauses
        {
            return Err(QualificationError::Refused(
                "singleton complete clause population differs",
            ));
        }
        Ok(Self {
            originals: expected.clauses,
            criteria: criteria.reference.clone(),
            plan: expected.plan,
        })
    }

    /// Rechecks one full published clause, including chapter and location.
    ///
    /// # Errors
    /// Refuses unknown requirements, paraphrases, missing sentences or retagged source.
    pub(super) fn verify_original_clause(
        &self,
        supplied: &NormativeClause,
    ) -> Result<ContentRef, QualificationError> {
        let expected =
            self.originals
                .get(&supplied.requirement)
                .ok_or(QualificationError::Refused(
                    "singleton review names an unknown clause",
                ))?;
        if supplied != expected {
            return Err(QualificationError::Refused(
                "singleton review changed the complete original clause",
            ));
        }
        let bytes = canonical::canonical_json(
            &serde_json::to_value(expected).map_err(crucible_node_format::ContractError::from)?,
        )?;
        Ok(canonical::content_ref(&bytes, "application/json")?)
    }

    /// Retains all original reviews and precise conditional decisions separately.
    ///
    /// No supplied native JSON can grant review completion. The owning actor's
    /// subset artifact is carried as original data alongside unresolved reviews.
    ///
    /// # Errors
    /// Refuses a changed complete plan, clause or missing dependency assignment.
    pub(super) fn population(
        &self,
        criteria: &SingletonQualificationCriteria,
        native_subsets: &Value,
    ) -> Result<Value, QualificationError> {
        if criteria.reference != self.criteria
            || criteria.clauses != self.originals
            || criteria.plan != self.plan
        {
            return Err(QualificationError::Refused(
                "singleton review plan changed after native effects",
            ));
        }
        let mut rows = Vec::with_capacity(self.originals.len());
        for (id, original) in &self.originals {
            let clause = self.verify_original_clause(original)?;
            let assignment =
                criteria
                    .plan
                    .requirements
                    .get(id)
                    .ok_or(QualificationError::Refused(
                        "singleton review lacks a complete clause assignment",
                    ))?;
            let review = match assignment {
                WitnessCriterion::Applicable { cases, criterion } => json!({
                    "status":"NotExecuted","case":format!("reference/singleton/review/{id}"),
                    "required_original_cases":cases,"criterion":criterion,
                    "rule":"all complete sentence semantics and required adverse branches need their independent source-authenticated original reviews"
                }),
                WitnessCriterion::NotApplicable { reason, criterion } => json!({
                    "status":"DeclaredConditionalExclusion","reason":reason,"criterion":criterion,
                    "rule":"only this exact source-bound condition; universal refusal and lifecycle duties remain applicable"
                }),
            };
            rows.push(json!({"requirement":id,"complete_clause":clause,"original":original,"review":review}));
        }
        Ok(json!({
            "schema":"crucible.reference.singleton-complete-clause-population.v1",
            "unit":criteria.plan.unit,"criteria":self.criteria,"clauses":rows,
            "original_native_subsets":native_subsets,"qualification_accepted":false
        }))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn verifier() -> (SingletonClauseVerifier, NormativeClause) {
        let source = canonical::content_ref(b"compiled full source", "text/plain").unwrap();
        let clause = NormativeClause {
            schema: "fixture.original-clause.v1".into(),
            requirement: "CN-TEST-010".into(),
            specification: source.clone(),
            chapter: "08-conformance.md".into(),
            chapter_reference: source.clone(),
            line: 154,
            text: "Refuse incompatible identities before activation. No mutation may escape."
                .into(),
        };
        (
            SingletonClauseVerifier {
                originals: BTreeMap::from([(clause.requirement.clone(), clause.clone())]),
                criteria: source.clone(),
                plan: crate::node_qualification::WitnessPlan {
                    schema: "fixture.plan.v1".into(),
                    unit: crate::node_qualification::QualificationUnit {
                        implementation: source.clone(),
                        realization: source.clone(),
                        descriptors: source.clone(),
                        contracts: source.clone(),
                        port_profiles: source.clone(),
                        environment: source.clone(),
                        harness: source.clone(),
                        fixtures: source.clone(),
                        specification: source.clone(),
                    },
                    classes: Default::default(),
                    requirements: Default::default(),
                    cases: vec![],
                    limitations: source,
                },
            },
            clause,
        )
    }

    #[test]
    fn full_clause_verifier_rejects_paraphrases_locations_and_foreign_source() {
        let (verifier, original) = verifier();
        assert!(verifier.verify_original_clause(&original).is_ok());
        let mut changed = original.clone();
        changed.text = "Refuse incompatible identities before activation.".into();
        assert!(verifier.verify_original_clause(&changed).is_err());
        changed = original.clone();
        changed.line += 1;
        assert!(verifier.verify_original_clause(&changed).is_err());
        changed = original.clone();
        changed.chapter = "another-chapter.md".into();
        assert!(verifier.verify_original_clause(&changed).is_err());
        changed = original.clone();
        changed.requirement = "CN-TEST-037".into();
        assert!(verifier.verify_original_clause(&changed).is_err());
        changed = original;
        changed.chapter_reference =
            canonical::content_ref(b"foreign source", "text/plain").unwrap();
        assert!(verifier.verify_original_clause(&changed).is_err());
    }
}

//! Predeclares the complete ordinary singleton obligation population.
//!
//! Native cases cover only their named original effects. Every other clause
//! retains its own independent review; absent reviews stay unexecuted.

use std::collections::{BTreeMap, BTreeSet};

use crucible_node_format::{ContentRef, canonical};
use serde_json::json;

use super::{
    criteria::{NormativeClause, extract_clauses, insert, put},
    singleton_unit::SingletonQualificationUnit,
};
use crate::node_qualification::{
    CaseKind, PlannedWitnessCase, QualificationClass, QualificationError, WitnessCriterion,
    WitnessPlan, normative_specification, requirement_catalog,
};

pub(super) const WORLD_CASE: &str = "reference/singleton/original-world-and-windows";
pub(super) const RETIREMENT_CASE: &str = "reference/singleton/original-semantic-retirement";
pub(super) const ADVERSE_CASE: &str = "reference/singleton/original-adverse-controls";

pub(super) struct SingletonQualificationCriteria {
    pub(super) plan: WitnessPlan,
    pub(super) reference: ContentRef,
    pub(super) bytes: Vec<u8>,
    pub(super) objects: BTreeMap<ContentRef, Vec<u8>>,
    pub(super) clauses: BTreeMap<String, NormativeClause>,
}

impl SingletonQualificationCriteria {
    /// Retains all compiled obligations and exact unsupported-class conditions.
    ///
    /// # Errors
    /// Refuses foreign ordinary classes or specification, changed complete
    /// clause inventory, and unrepresentable bounded policy objects.
    pub(super) fn build(unit: &SingletonQualificationUnit) -> Result<Self, QualificationError> {
        let expected = BTreeSet::from([
            QualificationClass::BaseProvider,
            QualificationClass::QuantizedTiming,
            QualificationClass::RoleProfile,
        ]);
        let (specification, specification_bytes) = normative_specification()?;
        if unit.classes != expected || unit.identity.specification != specification {
            return Err(QualificationError::Refused(
                "ordinary singleton source/class scope differs",
            ));
        }
        let (catalog, ids) = requirement_catalog()?;
        let mut objects = BTreeMap::new();
        insert(
            &mut objects,
            specification.clone(),
            specification_bytes.clone(),
        )?;
        insert(
            &mut objects,
            catalog,
            format!("{}\n", ids.join("\n")).into_bytes(),
        )?;
        let clauses = extract_clauses(&specification, &specification_bytes, &mut objects)?;
        if clauses.len() != ids.len() || !clauses.keys().map(String::as_str).eq(ids.iter().copied())
        {
            return Err(QualificationError::Refused(
                "singleton complete obligation inventory differs",
            ));
        }

        let mut cases = Vec::new();
        for (id, property) in [
            (
                WORLD_CASE,
                "actual complete one-owner world activation followed by three original empty-cut commitments, quantized windows, complete source-owned checksum output, publication acknowledgement and original close receipts",
            ),
            (
                RETIREMENT_CASE,
                "actual owning runtime/controller journals establish terminal semantic disposition; original native reclamation and same-attempt durable original capsule archive complete before queue transfer; process exit alone never resolves semantic custody",
            ),
            (
                ADVERSE_CASE,
                "actual installed provider is realized under each selected class; original stale identity, conflicting grant, unsupported ingress/capture, budget and lost/uncertain effect cases retain first outcomes and custody",
            ),
        ] {
            let oracle = put(
                &mut objects,
                &json!({
                    "schema": "crucible.reference.singleton-native-oracle.v1",
                    "unit": unit.identity,
                    "case": id,
                    "required_original_property": property,
                    "scope": "one ordinary closed-ingress source-owned node, one native execution owner, zero connections; no checksum pair, replacement peer or model substitutes for this original",
                    "failure_rule": "original Failed/Unknown/NotExecuted remains immutable; successful later attempts cannot replace it",
                }),
            )?;
            cases.push(PlannedWitnessCase {
                id: id.into(),
                kind: CaseKind::RealizedProvider,
                classes: unit.classes.clone(),
                oracle,
            });
        }

        let mut requirements = BTreeMap::new();
        for (id, clause) in &clauses {
            let clause_reference = put(
                &mut objects,
                &serde_json::to_value(clause).map_err(crucible_node_format::ContractError::from)?,
            )?;
            if let Some((condition, reason)) = excluded_class(id) {
                let criterion = put(
                    &mut objects,
                    &json!({
                        "schema": "crucible.reference.singleton-conditional-exclusion.v1",
                        "unit": unit.identity,
                        "clause": clause_reference,
                        "condition": condition,
                        "reason": reason,
                        "source_authentication": "regenerate the exact ordinary installed profile and its advertised class axes; universal lifecycle, unsupported-operation refusal, ownership and state-declaration duties remain applicable",
                    }),
                )?;
                requirements.insert(
                    id.clone(),
                    WitnessCriterion::NotApplicable {
                        reason: reason.into(),
                        criterion,
                    },
                );
                continue;
            }
            let review = format!("reference/singleton/review/{id}");
            let criterion = put(
                &mut objects,
                &json!({
                    "schema": "crucible.reference.singleton-full-clause.v1",
                    "unit": unit.identity,
                    "clause": clause_reference,
                    "original_review": review,
                    "required_review": "independent review of every complete sentence against exact original installed source/profile and native observations for all applicable behavioral branches",
                    "adverse_rule": "required malformed, stale, loss, resource, uncertainty and lifetime conditions must have matching original native observations; general positive windows or package/model passes do not cover them",
                    "missing_rule": "NotExecuted until the exact original complete clause review is authenticated",
                }),
            )?;
            cases.push(PlannedWitnessCase {
                id: review.clone(),
                kind: CaseKind::SourceInspection,
                classes: unit.classes.clone(),
                oracle: criterion.clone(),
            });
            // Every clause review is mandatory beside all three native classes.
            // A passed native case can never erase an unexecuted clause review.
            let mut selected = vec![
                review,
                WORLD_CASE.into(),
                RETIREMENT_CASE.into(),
                ADVERSE_CASE.into(),
            ];
            selected.sort();
            requirements.insert(
                id.clone(),
                WitnessCriterion::Applicable {
                    cases: selected,
                    criterion,
                },
            );
        }
        cases.sort_by(|left, right| left.id.cmp(&right.id));
        let limitations = put(
            &mut objects,
            &json!({
                "schema": "crucible.reference.singleton-limitations.v1",
                "fixed_scope": "one source-installed ordinary closed-ingress checksum node; no connections or external live inputs",
                "classes": unit.classes,
                "unsupported": ["exact-timing", "repeatability", "capture", "restoration", "branch-isolation", "conditional-replay", "physical-pause", "CPU-device-parity", "mixed-native-preservation"],
                "acceptance": "this plan assigns no verdict; every applicable original native and complete clause case remains mandatory",
            }),
        )?;
        let plan = WitnessPlan {
            schema: "crucible.node-witness-plan.v1".into(),
            unit: unit.identity.clone(),
            classes: unit.classes.clone(),
            requirements,
            cases,
            limitations,
        };
        let bytes = canonical::canonical_json(
            &serde_json::to_value(&plan).map_err(crucible_node_format::ContractError::from)?,
        )?;
        let reference = canonical::content_ref(&bytes, "application/json")?;
        insert(&mut objects, reference.clone(), bytes.clone())?;
        Ok(Self {
            plan,
            reference,
            bytes,
            objects,
            clauses,
        })
    }
}

fn excluded_class(id: &str) -> Option<(&'static str, &'static str)> {
    Some(match id {
        "CN-TEST-011" | "CN-TEST-012" | "CN-TEST-035" => (
            "exact timing qualification is claimed",
            "The exact ordinary profile advertises quantized timing only; this clause explicitly conditions its qualification tests on exact timing.",
        ),
        "CN-TEST-013" => (
            "mixed exact-world qualification is claimed",
            "This exact source selection contains one quantized owner and no connections; no mixed exact-world class is advertised.",
        ),
        "CN-TEST-017" => (
            "repeatability qualification is claimed",
            "The exact ordinary profile declares nondeterministic execution and no repeatability qualification.",
        ),
        "CN-TEST-018" => (
            "conditional replay qualification is claimed",
            "The exact ordinary profile exposes no transcript replay and no conditional-replay class.",
        ),
        "CN-TEST-020" | "CN-TEST-021" => (
            "complete modeled-state qualification is claimed",
            "The exact ordinary profile declares capture None and no complete modeled-state continuation qualification.",
        ),
        "CN-TEST-023" => (
            "branch qualification is claimed",
            "The exact ordinary profile exposes no branch/live-fork operation and no branch class.",
        ),
        "CN-TEST-024" => (
            "capture qualification is claimed",
            "The exact ordinary profile exposes no capture operation and no capture class.",
        ),
        _ => return None,
    })
}

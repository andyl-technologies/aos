//! Defines the source-owned complete obligation plan for the fixed public pair.
//!
//! Every applicable clause retains an unexecuted independent review case. The
//! two native cases cover explicit subsets only; their success cannot erase the
//! remaining review. Conditional exclusions are exact class-scoped rules, not
//! exclusions inferred from missing evidence or requirement-name prefixes.

use std::collections::{BTreeMap, BTreeSet};

use crucible_node_contract::{ContentRef, Validate, canonical};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::node_qualification::{
    CaseKind, PlannedWitnessCase, QualificationClass, QualificationError, QualificationUnit,
    WitnessCriterion, WitnessPlan, normative_specification, requirement_catalog,
};

const MAXIMUM_OBJECT_BYTES: usize = 1024 * 1024;
const MAXIMUM_TOTAL_BYTES: usize = 8 * 1024 * 1024;
const MAXIMUM_OBJECTS: usize = 2048;
const WORLD_CASE: &str = "reference/native-complete-world-and-windows";
const RETIREMENT_CASE: &str = "reference/native-original-custody-retirement";

/// Retains the exact published clause rather than a paraphrased obligation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NormativeClause {
    pub(super) schema: String,
    pub(super) requirement: String,
    pub(super) specification: ContentRef,
    pub(super) chapter: String,
    pub(super) chapter_reference: ContentRef,
    pub(super) line: usize,
    pub(super) text: String,
}

/// Retains a bounded policy plan without assigning any behavioral verdict.
pub(super) struct ReferenceQualificationCriteria {
    pub(super) plan: WitnessPlan,
    pub(super) reference: ContentRef,
    pub(super) bytes: Vec<u8>,
    pub(super) objects: BTreeMap<ContentRef, Vec<u8>>,
    pub(super) clauses: BTreeMap<String, NormativeClause>,
}

impl ReferenceQualificationCriteria {
    /// Builds the complete immutable plan for the independently measured unit.
    ///
    /// The concrete installed issuer must authenticate the regenerated fixed
    /// profile, unit and exclusions before installing this plan. A supplied unit
    /// or a correctly hashed policy object does not authenticate native behavior.
    ///
    /// # Errors
    /// Refuses another specification, changed obligation inventory, malformed
    /// compiled clauses, or unrepresentable bounded canonical policy objects.
    pub(super) fn build(unit: QualificationUnit) -> Result<Self, QualificationError> {
        let (specification, specification_bytes) = normative_specification()?;
        if unit.specification != specification {
            return Err(refused(
                "qualification criteria require exact compiled specification",
            ));
        }
        for reference in [
            &unit.implementation,
            &unit.realization,
            &unit.descriptors,
            &unit.contracts,
            &unit.port_profiles,
            &unit.environment,
            &unit.harness,
            &unit.fixtures,
            &unit.specification,
        ] {
            reference.validate()?;
        }
        let (catalog, ids) = requirement_catalog()?;
        let mut objects = BTreeMap::new();
        insert(
            &mut objects,
            specification.clone(),
            specification_bytes.clone(),
        )?;
        let catalog_bytes = format!("{}\n", ids.join("\n")).into_bytes();
        insert(&mut objects, catalog, catalog_bytes)?;
        let clauses = extract_clauses(&specification, &specification_bytes, &mut objects)?;
        if clauses.len() != ids.len() || !clauses.keys().map(String::as_str).eq(ids.iter().copied())
        {
            return Err(refused(
                "compiled clause population differs from complete catalog",
            ));
        }

        let classes = supported_classes();
        let world_oracle = put(&mut objects, &world_oracle(&unit))?;
        let retirement_oracle = put(&mut objects, &retirement_oracle(&unit))?;
        let mut cases = vec![
            PlannedWitnessCase {
                id: WORLD_CASE.into(),
                kind: CaseKind::RealizedProvider,
                classes: classes.clone(),
                oracle: world_oracle,
            },
            PlannedWitnessCase {
                id: RETIREMENT_CASE.into(),
                kind: CaseKind::RealizedProvider,
                classes: BTreeSet::from([QualificationClass::BaseProvider]),
                oracle: retirement_oracle,
            },
        ];
        let mut requirements = BTreeMap::new();
        for (id, clause) in &clauses {
            let clause_reference = put(
                &mut objects,
                &serde_json::to_value(clause).map_err(contract_error)?,
            )?;
            if let Some(exclusion) = conditional_exclusion(id) {
                let criterion = put(
                    &mut objects,
                    &json!({
                        "schema": "crucible.reference.conditional-exclusion.v1",
                        "clause": clause_reference,
                        "unit": unit,
                        "selected_classes": classes,
                        "condition": exclusion.condition,
                        "reason": exclusion.reason,
                        "required_source_authentication": "regenerate exact installed public profiles and verify that this conditional qualification class is neither selected nor advertised",
                        "unsupported_request_rule": "universal refusal, ownership, error, state-declaration and lifecycle obligations remain applicable"
                    }),
                )?;
                requirements.insert(
                    id.clone(),
                    WitnessCriterion::NotApplicable {
                        reason: exclusion.reason.into(),
                        criterion,
                    },
                );
                continue;
            }

            let review_id = format!("reference/review/{id}");
            let native = native_subset(id);
            let criterion = put(
                &mut objects,
                &json!({
                    "schema": "crucible.reference.full-obligation-criterion.v1",
                    "clause": clause_reference,
                    "unit": unit,
                    "selected_classes": classes,
                    "required_review_case": review_id,
                    "review": {
                        "required_property": "independently inspect each complete normative sentence and its conditional applicability against original installed source and declared profile; behavioral branches require actual original native/adverse observations",
                        "negative_controls": "exercise each refusal, boundary, stale identity, loss, resource, effect-uncertainty and lifetime condition required by this exact clause; retain original failures and blocked cases",
                        "missing_evidence": "NotExecuted; a positive native window, protocol-only report, syntactic validity or claim-author pass flag cannot satisfy the remaining obligation"
                    },
                    "native_subset": native.as_ref().map(|subset| json!({"case":subset.case,"observed_property":subset.property})),
                    "whole_clause_rule": "every predeclared case remains mandatory; the native subset never substitutes for complete independent review"
                }),
            )?;
            cases.push(PlannedWitnessCase {
                id: review_id.clone(),
                kind: CaseKind::SourceInspection,
                classes: classes.clone(),
                oracle: criterion.clone(),
            });
            let mut selected = vec![review_id];
            if let Some(subset) = native {
                selected.push(subset.case.into());
            }
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
                "schema": "crucible.reference.criteria-limitations.v1",
                "fixed_scope": "two source-installed public byte-linked checksum nodes; one closed source, one open consumer; phase-zero equal quantum, fixed zero-latency boundary-sampled one-way connection",
                "classes": classes,
                "unsupported": ["exact-timing","repeatability","capture","restoration","branch-isolation","conditional-replay","physical-pause","CPU-device-parity","arbitrary-topology","external-live-ingress"],
                "required_effect_accounting": "actual physical execution remains nondeterministic; original Unknown/failed/unexecuted cases are retained and cannot be replaced by a passing retry",
                "native_evidence_scope": "complete initial world, three windows per node, independent checksum and retained publication/consumption lineage, original process-group reclamation only",
                "acceptance": "no behavioral verdict is assigned by this plan; complete independently authenticated applicable evidence remains required"
            }),
        )?;
        let plan = WitnessPlan {
            schema: "crucible.node-witness-plan.v1".into(),
            unit,
            classes,
            requirements,
            cases,
            limitations,
        };
        let bytes =
            canonical::canonical_json(&serde_json::to_value(&plan).map_err(contract_error)?)?;
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

fn supported_classes() -> BTreeSet<QualificationClass> {
    BTreeSet::from([
        QualificationClass::BaseProvider,
        QualificationClass::QuantizedTiming,
        QualificationClass::RoleProfile,
    ])
}

struct Exclusion {
    condition: &'static str,
    reason: &'static str,
}

fn conditional_exclusion(id: &str) -> Option<Exclusion> {
    let (condition, reason) = match id {
        "CN-TEST-011" | "CN-TEST-012" | "CN-TEST-035" => (
            "exact timing qualification is claimed",
            "This fixed source-owned public profile selects only quantized timing and advertises no exact-timing capability; the clause expressly requires an exact timing qualification.",
        ),
        "CN-TEST-013" => (
            "a mixed exact-world qualification is claimed",
            "This fixed direct world contains only two quantized checksum nodes and makes no mixed exact-world claim; this clause expressly conditions its tests on that claim.",
        ),
        "CN-TEST-017" => (
            "repeatability qualification is claimed",
            "This fixed profile explicitly declares nondeterministic execution and selects no repeatability class; this clause expressly requires a repeatability qualification.",
        ),
        "CN-TEST-018" => (
            "conditional replay qualification is claimed",
            "This fixed native profile exposes no transcript replay mode and selects no conditional-replay class; this clause expressly requires a conditional replay qualification.",
        ),
        "CN-TEST-020" | "CN-TEST-021" => (
            "complete modeled-state qualification is claimed",
            "This fixed profile offers no capture or continuation and selects no complete modeled-state class; this clause expressly requires complete modeled-state qualification.",
        ),
        "CN-TEST-023" => (
            "branch qualification is claimed",
            "This fixed profile offers no branch or live-fork operation and selects no branch-isolation class; this clause expressly requires branch qualification.",
        ),
        "CN-TEST-024" => (
            "capture qualification is claimed",
            "This fixed profile offers no capture operation and selects no capture class; this clause expressly requires capture qualification.",
        ),
        _ => return None,
    };
    Some(Exclusion { condition, reason })
}

struct NativeSubset {
    case: &'static str,
    property: &'static str,
}

fn native_subset(id: &str) -> Option<NativeSubset> {
    let property = match id {
        "CN-MODEL-10" => {
            "original control and window receipts retain actual owner/incarnation, original operation and realization scope in this executed fixed world"
        }
        "CN-NODE-11" | "CN-NODE-54" | "CN-IPC-29" => {
            "actual all-owner prepared readiness and complete initial coordinator are durably published before original runtime grants; genuine WorldActivate manifest and later original Begin controls retain that generation"
        }
        "CN-NODE-12" | "CN-NODE-23" | "CN-NODE-24" => {
            "original staged input ACK and publication-consumption bodies retain exact delivered bytes, producer event lineage and committed prefix for the executed windows"
        }
        "CN-NODE-19" | "CN-NODE-52" => {
            "actual original Begin and Close responses bind retained grant, window and native stop/observation inventory rather than a replacement operation"
        }
        "CN-QUANT-1" => {
            "three executed phase-zero windows per node bind original equal positive grids and checked half-open logical intervals"
        }
        "CN-QUANT-2" | "CN-QUANT-19" => {
            "actual native elapsed budget measurements remain distinct from authorized logical intervals and publication boundaries; application park is not physical suspension"
        }
        "CN-QUANT-3" | "CN-QUANT-8" => {
            "original complete start batches and authentic staging ACKs precede each dependent executed window in the fixed direct world"
        }
        "CN-QUANT-4" | "CN-QUANT-5" | "CN-QUANT-6" => {
            "retained native checksum output publishes at its declared logical boundary and its exact original octets enter the sampled next consumer batch; independent limb checksum verifies delivery-order bytes"
        }
        "CN-QUANT-7" => {
            "executed original grants bind actual node/owner generation, grid/index, closed input batch and operational budget"
        }
        "CN-QUANT-10" | "CN-QUANT-11" => {
            "original closed output inventory and authenticated native stop/observation records precede semantic publication; exact original Retire-Consumed and PublicationConsumption retain completion lineage"
        }
        "CN-TIME-11" | "CN-TIME-34" => {
            "original receipt and pending publication are validated before scheduling ACK; retained publication and destination delivery coordinates are checked independently in the fixed direct route"
        }
        "CN-TEST-014" => {
            "three actual windows per node retain authorized input and output boundary assignments under authentic original coordinator grants"
        }
        "CN-TEST-029" => {
            "actual advertised fixed opaque-byte checksum role yields independently verified cumulative outputs for the original staged input bytes; no CPU or other-device parity is inferred"
        }
        "CN-NODE-13" | "CN-NODE-39" | "CN-SEC-4" => {
            return Some(NativeSubset {
                case: RETIREMENT_CASE,
                property: "original complete runtime and peer capsules survive borrower release until both genuine provider/companion process groups are reclaimed; original supervision scopes and admitted native limits are retained",
            });
        }
        _ => return None,
    };
    Some(NativeSubset {
        case: WORLD_CASE,
        property,
    })
}

fn world_oracle(unit: &QualificationUnit) -> Value {
    json!({
        "schema":"crucible.reference.native-world-window-oracle.v1", "unit":unit,
        "required_originals":["genuine committed WorldActivation", "Directory world/coordinator durable roots", "complete ActivationManifest, original readiness and coordinator bytes", "origin-labelled canonical original request frames and latest authentic responses", "original Begin/Close DeviceReceipt, stop and observation objects", "original staged input bytes and input custody", "original Retire-Consumed and PublicationConsumption lineage"],
        "checksum_oracle":"independent byte-limb arithmetic: initial0; for each exact delivered octet b in canonical delivery order, state=(257*state+b) mod2^64; compare complete output bytes and cumulative checksum",
        "boundaries":"original phase-zero equal quantum/index, exclusive start cut, output boundary and conversion remain distinct from measured host elapsed time",
        "budgets":"independently match original physical budget scope and authenticated measurement; no exact physical pause claim",
        "case_population":"three original windows per node in fixed producer/consumer world; original missing/Unknown/failed case is not replaced by a retry",
        "not_proven":"general malformed protocol, stale/conflicting grants, overflow, cancellation races, arbitrary topology, missed deadlines, storage/CPU parity and other unexercised conditions"
    })
}

fn retirement_oracle(unit: &QualificationUnit) -> Value {
    json!({
        "schema":"crucible.reference.native-retirement-oracle.v1", "unit":unit,
        "required_originals":["pre-reserved complete world custody", "both pre-reserved provider/companion peer capsules", "original private supervision scopes and retained control journals", "actual independent original PID/starttick/group census", "positive authentic world and peer reclamation", "immutable original result and retirement records"],
        "secrets":"private launch, Hello and resume material is never emitted into content evidence",
        "release":"both original process groups must be absent under authoritative census before original native ownership is discharged",
        "not_proven":"failed-reap, cancellation, unwind and publication-uncertainty adverse populations unless independently executed"
    })
}

fn extract_clauses(
    specification: &ContentRef,
    bytes: &[u8],
    objects: &mut BTreeMap<ContentRef, Vec<u8>>,
) -> Result<BTreeMap<String, NormativeClause>, QualificationError> {
    specification.verify(bytes)?;
    let source = canonical::parse_json(bytes, MAXIMUM_OBJECT_BYTES)?;
    let sources = source
        .get("sources")
        .and_then(Value::as_array)
        .ok_or_else(|| refused("compiled specification source inventory missing"))?;
    let mut clauses = BTreeMap::new();
    for pair in sources {
        let pair = pair
            .as_array()
            .filter(|pair| pair.len() == 2)
            .ok_or_else(|| refused("compiled specification source pair malformed"))?;
        let chapter = pair[0]
            .as_str()
            .ok_or_else(|| refused("compiled chapter name missing"))?;
        let text = pair[1]
            .as_str()
            .ok_or_else(|| refused("compiled chapter bytes missing"))?;
        if !text.contains("**[CN-") {
            continue;
        }
        let chapter_reference = canonical::content_ref(text.as_bytes(), "text/markdown")?;
        insert(objects, chapter_reference.clone(), text.as_bytes().to_vec())?;
        let lines = text.lines().collect::<Vec<_>>();
        for (index, line) in lines.iter().enumerate() {
            let Some(marker) = line.find("**[CN-") else {
                continue;
            };
            let first = &line[marker..];
            let (marked_id, _) = first
                .split_once("]**")
                .ok_or_else(|| refused("compiled requirement marker malformed"))?;
            let id = marked_id
                .strip_prefix("**[")
                .ok_or_else(|| refused("compiled requirement identifier malformed"))?;
            let mut clause = first.to_owned();
            for continuation in &lines[index + 1..] {
                if continuation.trim().is_empty() || continuation.contains("**[CN-") {
                    break;
                }
                clause.push('\n');
                clause.push_str(continuation);
            }
            if id.len() > 64 || clause.len() > 16_384 || clauses.len() >= 4096 {
                return Err(refused("compiled normative clause geometry"));
            }
            let row = NormativeClause {
                schema: "crucible.reference.normative-clause.v1".into(),
                requirement: id.into(),
                specification: specification.clone(),
                chapter: chapter.into(),
                chapter_reference: chapter_reference.clone(),
                line: index + 1,
                text: clause,
            };
            if clauses.insert(id.into(), row).is_some() {
                return Err(refused("duplicate compiled normative clause"));
            }
        }
    }
    Ok(clauses)
}

fn put(
    objects: &mut BTreeMap<ContentRef, Vec<u8>>,
    value: &Value,
) -> Result<ContentRef, QualificationError> {
    let bytes = canonical::canonical_json(value)?;
    let reference = canonical::content_ref(&bytes, "application/json")?;
    insert(objects, reference.clone(), bytes)?;
    Ok(reference)
}

fn insert(
    objects: &mut BTreeMap<ContentRef, Vec<u8>>,
    reference: ContentRef,
    bytes: Vec<u8>,
) -> Result<(), QualificationError> {
    reference.verify(&bytes)?;
    if bytes.len() > MAXIMUM_OBJECT_BYTES {
        return Err(refused("criteria object byte ceiling"));
    }
    if let Some(original) = objects.get(&reference) {
        if original != &bytes {
            return Err(refused("criteria object identity collision"));
        }
        return Ok(());
    }
    let total = objects
        .values()
        .try_fold(bytes.len(), |total, body| total.checked_add(body.len()))
        .filter(|total| *total <= MAXIMUM_TOTAL_BYTES)
        .ok_or_else(|| refused("criteria aggregate byte ceiling"))?;
    if objects.len() >= MAXIMUM_OBJECTS || total > MAXIMUM_TOTAL_BYTES {
        return Err(refused("criteria aggregate geometry"));
    }
    objects.insert(reference, bytes);
    Ok(())
}

fn contract_error(error: serde_json::Error) -> QualificationError {
    crucible_node_contract::ContractError::from(error).into()
}

fn refused(reason: &'static str) -> QualificationError {
    QualificationError::Refused(reason)
}

#[cfg(test)]
#[path = "criteria_tests.rs"]
mod tests;
